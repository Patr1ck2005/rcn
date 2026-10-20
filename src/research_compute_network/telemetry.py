"""Windows telemetry sampling and the bounded machine-agent client."""

from __future__ import annotations

import csv
import ctypes
import json
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol
from urllib.request import Request, urlopen

from .models import GpuMetric, MachineHeartbeat, MachineMetrics


class MetricsSampler(Protocol):
    def sample(self) -> MachineMetrics: ...


def _keyboard_idle_seconds() -> int:
    if not hasattr(ctypes, "windll"):
        return 0

    class LastInputInfo(ctypes.Structure):
        _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint)]

    info = LastInputInfo()
    info.cbSize = ctypes.sizeof(LastInputInfo)
    if not ctypes.windll.user32.GetLastInputInfo(ctypes.byref(info)):
        return 0
    elapsed_ms = ctypes.windll.kernel32.GetTickCount() - info.dwTime
    return max(0, int(elapsed_ms / 1000))


def _gpu_metrics() -> list[GpuMetric]:
    command = [
        "nvidia-smi",
        "--query-gpu=index,name,utilization.gpu,memory.total,memory.used,temperature.gpu",
        "--format=csv,noheader,nounits",
    ]
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=2)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    if completed.returncode != 0:
        return []
    result: list[GpuMetric] = []
    for row in csv.reader(line for line in completed.stdout.splitlines() if line.strip()):
        if len(row) != 6:
            continue
        try:
            result.append(GpuMetric(
                index=int(row[0].strip()),
                name=row[1].strip(),
                utilization_percent=float(row[2].strip()),
                memory_total_mb=int(float(row[3].strip())),
                memory_used_mb=int(float(row[4].strip())),
                temperature_c=float(row[5].strip()),
            ))
        except ValueError:
            continue
    return result


class WindowsMetricsSampler:
    """Collect bounded host metrics without inspecting project files or processes."""

    def sample(self) -> MachineMetrics:
        try:
            import psutil
        except ImportError as exc:  # pragma: no cover - installation is tested through packaging
            raise RuntimeError("install the pilot telemetry extra (psutil) before starting an agent") from exc
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        cpu_percent = float(psutil.cpu_percent(interval=None))
        return MachineMetrics(
            cpu_total_percent=cpu_percent,
            non_pool_cpu_percent=cpu_percent,
            keyboard_idle_s=_keyboard_idle_seconds(),
            memory_used_mb=int(memory.used / (1024 * 1024)),
            total_memory_mb=int(memory.total / (1024 * 1024)),
            available_memory_mb=int(memory.available / (1024 * 1024)),
            disk_used_mb=int(disk.used / (1024 * 1024)),
            total_disk_mb=int(disk.total / (1024 * 1024)),
            free_disk_mb=int(disk.free / (1024 * 1024)),
            gpu=_gpu_metrics(),
            observed_at=datetime.now(timezone.utc),
        )


@dataclass
class MachineAgent:
    machine_id: str
    token: str
    base_url: str
    sampler: MetricsSampler

    def report_once(self) -> MachineMetrics:
        metrics = self.sampler.sample()
        heartbeat = MachineHeartbeat(machine_id=self.machine_id, metrics=metrics)
        payload = json.dumps(heartbeat.model_dump(mode="json")).encode("utf-8")
        request = Request(
            f"{self.base_url.rstrip('/')}/v1/machines/{self.machine_id}/heartbeat",
            data=payload,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urlopen(request, timeout=8) as response:
            if response.status >= 300:
                raise RuntimeError(f"heartbeat rejected with HTTP {response.status}")
        return metrics

    def run_forever(self, *, interval_s: float = 5.0) -> None:
        while True:
            try:
                self.report_once()
            except OSError:
                # The next bounded retry keeps the agent recoverable during coordinator restarts.
                pass
            time.sleep(max(1.0, interval_s))
