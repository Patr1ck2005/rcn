"""Optional Windows telemetry for the file-spool supervisor.

The supervisor remains deployable without installing packages: psutil is
loaded when present and failures are represented explicitly instead of as
zero-valued measurements.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import time
from collections import deque
from datetime import datetime, timezone

try:
    from .remote_pressure import ExternalPressureSnapshot, PressureTracker
except ImportError:  # Standalone versioned runtime executes this directory directly.
    from remote_pressure import ExternalPressureSnapshot, PressureTracker


def _iso_now():
    return datetime.now(timezone.utc).isoformat()


def _windowless_run(*args, **kwargs):
    """subprocess.run that never opens a console window for telemetry helpers.

    GPU machines invoke nvidia-smi on every sample tick (utilization
    attribution plus the NVML fallback path). A bare subprocess.run opens a
    visible console per spawn, which produced the flickering-black-box report
    on desktop machines where the supervisor runs in the interactive session.
    """
    if os.name == "nt":
        kwargs.setdefault("creationflags", getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return subprocess.run(*args, **kwargs)


def windows_idle_seconds():
    if os.name != "nt":
        raise RuntimeError("Windows idle-time sampling is unavailable on this platform")

    class LASTINPUTINFO(ctypes.Structure):
        _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint)]

    info = LASTINPUTINFO()
    info.cbSize = ctypes.sizeof(info)
    if not ctypes.windll.user32.GetLastInputInfo(ctypes.byref(info)):
        raise OSError("GetLastInputInfo failed")
    elapsed_ms = (ctypes.windll.kernel32.GetTickCount() - info.dwTime) & 0xFFFFFFFF
    return int(elapsed_ms / 1000)


class RemoteMetricSampler:
    def __init__(
        self,
        root,
        psutil_module=None,
        runner=None,
        idle_reader=None,
        telemetry_policy=None,
        nvml_module=None,
    ):
        self.root = str(root)
        if psutil_module is None:
            try:
                import psutil as psutil_module  # type: ignore
            except ImportError:
                psutil_module = None
        self.psutil = psutil_module
        self.runner = runner or _windowless_run
        self.idle_reader = idle_reader or windows_idle_seconds
        self.telemetry_policy = dict(telemetry_policy or {})
        self._processes = {}
        self._last_attribution_quality = "unavailable"
        self._cpu_history = deque()
        self._external_cpu_history = deque()
        self._gpu_history = {}
        self._pressure_tracker = PressureTracker()
        self._external_process_set_hash = hashlib.sha256(b"").hexdigest()
        self._external_process_count = 0
        self._gpu_history_path = Path(self.root) / "logs" / "gpu-samples.jsonl"
        self._load_gpu_history()
        if nvml_module is None:
            try:
                import pynvml as nvml_module  # type: ignore

                nvml_module.nvmlInit()
            except Exception:
                nvml_module = None
        self.nvml = nvml_module

    def _load_gpu_history(self):
        """Restore only recent samples so a Supervisor restart preserves windows."""
        now_wall = time.time()
        now_monotonic = time.monotonic()
        try:
            records = self._gpu_history_path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return
        for line in records[-7200:]:
            try:
                item = json.loads(line)
                observed = datetime.fromisoformat(str(item["observed_at"]).replace("Z", "+00:00")).timestamp()
                age = now_wall - observed
                if age < 0 or age > 300:
                    continue
                index = int(item["index"])
                value = float(item["utilization_percent"])
                memory = int(item.get("memory_used_mb") or 0)
            except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                continue
            self._gpu_history.setdefault(index, deque()).append(
                (now_monotonic - age, value, memory)
            )

    def _persist_gpu_samples(self, observed_at, gpu):
        if not gpu:
            return
        try:
            self._gpu_history_path.parent.mkdir(parents=True, exist_ok=True)
            with self._gpu_history_path.open("a", encoding="utf-8", newline="\n") as handle:
                for metric in gpu:
                    if metric.get("available") and metric.get("utilization_percent") is not None:
                        handle.write(json.dumps({
                            "observed_at": observed_at.isoformat(),
                            "index": int(metric["index"]),
                            "utilization_percent": float(metric["utilization_percent"]),
                            "memory_used_mb": int(metric.get("memory_used_mb") or 0),
                        }, separators=(",", ":")) + "\n")
            if self._gpu_history_path.stat().st_size > 2 * 1024 * 1024:
                lines = self._gpu_history_path.read_text(encoding="utf-8").splitlines()[-7200:]
                temporary = self._gpu_history_path.with_suffix(".tmp")
                temporary.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
                os.replace(temporary, self._gpu_history_path)
        except OSError:
            # Telemetry must remain available even when the retained log is
            # temporarily read-only or out of space.
            return

    @staticmethod
    def _launched_process(entry):
        return entry.get("process") if isinstance(entry, dict) else entry

    @staticmethod
    def _process_guard(entry):
        return entry.get("guard") if isinstance(entry, dict) else None

    def _external_load_snapshot(
        self,
        active_processes,
        *,
        gpu_metrics,
        observed_at,
        system_cpu_percent=None,
        network_cpu_percent=None,
    ):
        """Aggregate all process-tree-external load without retaining identity."""
        if self.psutil is None:
            return ExternalPressureSnapshot(
                attribution_quality="unavailable",
                reason_codes=["telemetry_attribution_degraded"],
                observed_at=observed_at,
            )
        own_pids = {os.getpid()}
        for entry in active_processes:
            launched = self._launched_process(entry)
            try:
                root = self.psutil.Process(launched.pid)
                own_pids.add(root.pid)
                own_pids.update(child.pid for child in root.children(recursive=True))
            except (self.psutil.Error, OSError, AttributeError):
                continue
        count = 0
        cpu = 0.0
        memory_mb = 0
        external_pids = set()
        external_identities = []
        attribution_quality = "complete"
        try:
            processes = self.psutil.process_iter(["name", "cpu_percent", "memory_info"])
        except (self.psutil.Error, OSError, AttributeError):
            processes = []
            attribution_quality = "unavailable"
        logical_cpus = max(1, int(self.psutil.cpu_count() or 1))
        for process in processes:
            try:
                name = (process.info.get("name") or "").strip().lower()
                # On Windows PID 0 is System Idle Process. Its reported CPU
                # is idle time, so including it in external load inverts the
                # signal and makes an idle machine look nearly 100% busy.
                if process.pid == 0 or name in {"system idle process", "idle"}:
                    continue
                if process.pid in own_pids:
                    continue
                external_pids.add(process.pid)
                try:
                    created = process.create_time()
                except (self.psutil.Error, OSError, AttributeError):
                    created = 0
                # Names are only hashed diagnostic evidence; command lines,
                # users, and paths never leave the node.
                external_identities.append("%s|%s|%s" % (process.pid, created, name))
                count += 1
                cpu += max(0.0, float(process.info.get("cpu_percent") or 0.0)) / logical_cpus
                info = process.info.get("memory_info")
                memory_mb += int(getattr(info, "rss", 0) / 1024**2)
            except (self.psutil.Error, OSError, TypeError, ValueError):
                continue
        gpu_util = self._external_gpu_utilization(external_pids)
        self._external_process_count = count
        self._external_process_set_hash = hashlib.sha256(
            "\n".join(sorted(external_identities)).encode("utf-8")
        ).hexdigest()
        if system_cpu_percent is not None and network_cpu_percent is not None:
            cpu = max(0.0, float(system_cpu_percent) - float(network_cpu_percent))
        sample = ExternalPressureSnapshot(
            external_process_count=count,
            external_cpu_percent=min(100.0, cpu),
            external_memory_mb=max(0, memory_mb),
            external_gpu_utilization_percent=min(100.0, gpu_util),
            process_set_hash=self._external_process_set_hash,
            attribution_quality=attribution_quality,
            reason_codes=([] if attribution_quality == "complete" else ["telemetry_attribution_degraded"]),
            observed_at=observed_at,
        )
        return self._pressure_tracker.update(sample, now=observed_at)

    def _external_comsol_pressure(self, active_processes, *, gpu_metrics, observed_at):
        """Compatibility alias for older supervisor call sites."""
        return self._external_load_snapshot(
            active_processes, gpu_metrics=gpu_metrics, observed_at=observed_at
        )

    def _external_gpu_utilization(self, external_pids):
        """Aggregate GPU SM use for external PIDs without returning identity."""
        if not external_pids:
            return 0.0
        executable = shutil.which("nvidia-smi")
        if executable is None:
            return 0.0
        command = [executable, "pmon", "-c", "1", "-s", "u"]
        try:
            completed = self.runner(
                command, check=False, capture_output=True, text=True,
                timeout=float(self.telemetry_policy.get("sample_timeout_s", 8)),
            )
        except (OSError, subprocess.TimeoutExpired):
            return 0.0
        if completed.returncode != 0:
            return 0.0
        utilization = 0.0
        for line in completed.stdout.splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 4:
                continue
            try:
                pid = int(parts[1])
                sm_percent = float(parts[3])
            except (TypeError, ValueError):
                continue
            if pid in external_pids:
                utilization += max(0.0, sm_percent)
        return min(100.0, utilization)

    def _job_object_cpu_totals(self, active_processes):
        """Read cumulative CPU seconds for every guarded Network process tree."""

        totals = {}
        guarded = 0
        for entry in active_processes:
            guard = self._process_guard(entry)
            if guard is None or not hasattr(guard, "accounting_snapshot"):
                continue
            guarded += 1
            try:
                snapshot = guard.accounting_snapshot()
            except (OSError, RuntimeError):
                snapshot = None
            if snapshot:
                totals[id(guard)] = float(snapshot["cpu_seconds"])
        return totals, guarded

    def _pool_cpu_percent(
        self,
        active_processes,
        *,
        aligned_start=None,
        aligned_end=None,
        aligned_elapsed_s=None,
        guarded_start=0,
        guarded_end=0,
    ):
        if self.psutil is None:
            self._last_attribution_quality = "unavailable"
            return None
        logical_cpus = max(1, int(self.psutil.cpu_count() or 1))
        if (
            aligned_start is not None
            and aligned_end is not None
            and aligned_elapsed_s is not None
            and aligned_elapsed_s > 0
            and guarded_start == guarded_end == len(active_processes)
            and len(aligned_start) == len(aligned_end) == len(active_processes)
            and set(aligned_start) == set(aligned_end)
        ):
            job_cpu_seconds = sum(
                max(0.0, aligned_end[key] - aligned_start[key])
                for key in aligned_start
            )
            self._last_attribution_quality = "job_object"
            return min(
                100.0,
                max(
                    0.0,
                    job_cpu_seconds / aligned_elapsed_s * 100.0 / logical_cpus,
                ),
            )

        active_pids = set()
        total = 0.0
        sampled = 0
        live_identities = set()
        for entry in active_processes:
            launched = self._launched_process(entry)
            try:
                root = self.psutil.Process(launched.pid)
                processes = [root, *root.children(recursive=True)]
                for process in processes:
                    active_pids.add(process.pid)
                    try:
                        created_at = float(process.create_time())
                    except (self.psutil.Error, OSError, AttributeError):
                        created_at = 0.0
                    identity = (process.pid, created_at)
                    live_identities.add(identity)
                    cached = self._processes.get(identity)
                    if cached is None:
                        cached = process
                        cached.cpu_percent(None)
                        self._processes[identity] = cached
                    total += max(0.0, float(cached.cpu_percent(None))) / logical_cpus
                    sampled += 1
            except (self.psutil.Error, OSError):
                continue
        for identity in list(self._processes):
            if identity not in live_identities:
                self._processes.pop(identity, None)
        if active_processes and sampled == 0:
            self._last_attribution_quality = "unavailable"
            return None
        self._last_attribution_quality = "process_tree" if sampled else "degraded"
        return min(100.0, total)

    def _nvml_gpu_metrics(self):
        if self.nvml is None:
            return None
        try:
            result = []
            for index in range(int(self.nvml.nvmlDeviceGetCount())):
                handle = self.nvml.nvmlDeviceGetHandleByIndex(index)
                utilization = self.nvml.nvmlDeviceGetUtilizationRates(handle)
                memory = self.nvml.nvmlDeviceGetMemoryInfo(handle)
                name = self.nvml.nvmlDeviceGetName(handle)
                if isinstance(name, bytes):
                    name = name.decode("utf-8", errors="replace")
                result.append({
                    "index": index,
                    "name": str(name),
                    "utilization_percent": float(utilization.gpu),
                    "memory_used_mb": int(memory.used / 1024**2),
                    "memory_total_mb": int(memory.total / 1024**2),
                    "temperature_c": float(
                        self.nvml.nvmlDeviceGetTemperature(
                            handle, self.nvml.NVML_TEMPERATURE_GPU
                        )
                    ),
                    "available": True,
                    "sampling_quality": "nvml",
                })
            return result, "live", ""
        except Exception as exc:
            return [], "unavailable", str(exc)[:240]

    def _gpu_metrics(self):
        nvml = self._nvml_gpu_metrics()
        if nvml is not None and nvml[0]:
            return nvml
        executable = shutil.which("nvidia-smi")
        if executable is None:
            return [], "not_detected", ""
        command = [
            executable,
            "--query-gpu=index,name,utilization.gpu,memory.used,memory.total,temperature.gpu",
            "--format=csv,noheader,nounits",
        ]
        try:
            completed = self.runner(
                command, check=False, capture_output=True, text=True,
                timeout=float(self.telemetry_policy.get("sample_timeout_s", 8)),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return [], "unavailable", str(exc)
        if completed.returncode != 0:
            return [], "unavailable", (completed.stderr or completed.stdout).strip()[:240]
        metrics = []
        try:
            for line in completed.stdout.splitlines():
                if not line.strip():
                    continue
                parts = [part.strip() for part in line.split(",")]
                if len(parts) != 6:
                    raise ValueError("unexpected nvidia-smi column count")
                metrics.append({
                    "index": int(parts[0]),
                    "name": parts[1],
                    "utilization_percent": float(parts[2]),
                    "memory_used_mb": int(float(parts[3])),
                    "memory_total_mb": int(float(parts[4])),
                    "temperature_c": float(parts[5]),
                    "available": True,
                    "sampling_quality": "degraded",
                })
        except (TypeError, ValueError) as exc:
            return [], "unavailable", str(exc)
        return metrics, "live", ""

    @staticmethod
    def _time_weighted_average(history, *, now, window_s):
        selected = [item for item in history if now - item[0] <= window_s]
        if not selected:
            return None
        if len(selected) == 1:
            return selected[0][1]
        total = 0.0
        duration = 0.0
        for current, following in zip(selected, selected[1:]):
            interval = max(0.0, following[0] - current[0])
            total += current[1] * interval
            duration += interval
        tail = max(0.0, now - selected[-1][0])
        total += selected[-1][1] * tail
        duration += tail
        return total / duration if duration > 0 else selected[-1][1]

    def sample(self, active_processes):
        active_processes = list(active_processes)
        reasons = []
        if self.psutil is None:
            return {
                "available": False,
                "unavailable_reasons": ["psutil is not installed"],
                "source": "ssh-supervisor",
                "observed_at": _iso_now(),
                "gpu": [],
                "gpu_status": "unavailable",
            }
        try:
            # Bracket psutil's system CPU window with Job Object counters. This
            # makes system and Network CPU directly comparable; cross-cycle
            # deltas can otherwise make Network CPU exceed total host CPU and
            # create false external-load pressure.
            job_cpu_start, guarded_start = self._job_object_cpu_totals(active_processes)
            cpu_window_started = time.monotonic()
            cpu_total = float(self.psutil.cpu_percent(
                interval=min(1.0, max(0.05, float(self.telemetry_policy.get("cpu_sample_window_s", 15)) / 100.0))
            ))
            cpu_window_elapsed = max(0.0, time.monotonic() - cpu_window_started)
            job_cpu_end, guarded_end = self._job_object_cpu_totals(active_processes)
            memory = self.psutil.virtual_memory()
            disk = self.psutil.disk_usage(self.root)
        except (self.psutil.Error, OSError, ValueError) as exc:
            return {
                "available": False,
                "unavailable_reasons": [f"system metrics failed: {exc}"],
                "source": "ssh-supervisor",
                "observed_at": _iso_now(),
                "gpu": [],
                "gpu_status": "unavailable",
            }
        try:
            idle_seconds = int(self.idle_reader())
        except (OSError, RuntimeError, AttributeError) as exc:
            idle_seconds = None
            reasons.append(f"keyboard idle failed: {exc}")
        pool_cpu = self._pool_cpu_percent(
            active_processes,
            aligned_start=job_cpu_start,
            aligned_end=job_cpu_end,
            aligned_elapsed_s=cpu_window_elapsed,
            guarded_start=guarded_start,
            guarded_end=guarded_end,
        )
        if pool_cpu is not None:
            # Minor boundary skew is still possible while reading several Job
            # Objects. Preserve the physical invariant used by capacity policy.
            pool_cpu = min(cpu_total, pool_cpu)
        gpu, gpu_status, gpu_error = self._gpu_metrics()
        observed_at = datetime.now(timezone.utc)
        self._persist_gpu_samples(observed_at, gpu)
        external_pressure = self._external_load_snapshot(
            active_processes,
            gpu_metrics=gpu,
            observed_at=observed_at,
            system_cpu_percent=cpu_total,
            network_cpu_percent=pool_cpu,
        )
        if gpu_error:
            reasons.append(f"GPU metrics failed: {gpu_error}")
        available = idle_seconds is not None and pool_cpu is not None
        now_monotonic = time.monotonic()
        peak_window = max(1.0, float(self.telemetry_policy.get("peak_window_s", 300)))
        history_window = max(300.0, peak_window)
        average_window = max(1.0, float(self.telemetry_policy.get("cpu_sample_window_s", 15)))
        self._cpu_history.append((now_monotonic, cpu_total))
        self._external_cpu_history.append((now_monotonic, external_pressure.external_cpu_percent))
        while self._cpu_history and now_monotonic - self._cpu_history[0][0] > peak_window:
            self._cpu_history.popleft()
        while self._external_cpu_history and now_monotonic - self._external_cpu_history[0][0] > peak_window:
            self._external_cpu_history.popleft()
        for metric in gpu:
            if metric.get("available") and metric.get("utilization_percent") is not None:
                history = self._gpu_history.setdefault(metric["index"], deque())
                history.append((
                    now_monotonic,
                    float(metric["utilization_percent"]),
                    int(metric.get("memory_used_mb") or 0),
                ))
                while history and now_monotonic - history[0][0] > history_window:
                    history.popleft()
                peak_values = [value for _, value, _ in history]
                sixty_average = self._time_weighted_average(
                    history, now=now_monotonic, window_s=60.0
                )
                five_minute_average = self._time_weighted_average(
                    history, now=now_monotonic, window_s=300.0
                )
                ordered = sorted(peak_values)
                p95_index = max(0, math.ceil(0.95 * len(ordered)) - 1)
                metric["utilization_average_percent"] = sixty_average
                metric["utilization_5m_average_percent"] = five_minute_average
                metric["utilization_peak_percent"] = max(peak_values)
                metric["utilization_p95_percent"] = ordered[p95_index]
                metric["busy_duty_cycle_percent"] = (
                    sum(value > 5.0 for value in peak_values) / len(peak_values) * 100.0
                )
                metric["sample_count"] = len(peak_values)
                metric["memory_peak_mb"] = max(value for _, _, value in history)
        attempt_resource_usage = []
        for entry in active_processes:
            if not isinstance(entry, dict):
                continue
            request = entry.get("request") or {}
            work_unit_id = request.get("work_unit_id")
            if not work_unit_id:
                continue
            guard = self._process_guard(entry)
            try:
                accounting = guard.accounting_snapshot() if guard is not None else None
            except (OSError, RuntimeError, AttributeError):
                accounting = None
            run_dir = entry.get("run_dir")
            output_bytes = 0
            try:
                output = run_dir / "output"
                output_bytes = sum(path.stat().st_size for path in output.rglob("*") if path.is_file())
            except (OSError, AttributeError, TypeError):
                output_bytes = 0
            attempt_resource_usage.append({
                "work_unit_id": str(work_unit_id),
                "peak_memory_mb": int((accounting or {}).get("peak_memory_bytes", 0) / 1024**2),
                "output_bytes": max(0, output_bytes),
                "active_processes": int((accounting or {}).get("active_processes", 0)),
            })
        cpu_values = [
            value for observed, value in self._cpu_history
            if now_monotonic - observed <= average_window
        ]
        cpu_peak_values = [value for _, value in self._cpu_history]
        external_cpu_values = [value for _, value in self._external_cpu_history]
        return {
            "cpu_total_percent": cpu_total,
            "cpu_current_percent": cpu_total,
            "cpu_average_percent": sum(cpu_values) / len(cpu_values),
            "cpu_peak_percent": max(cpu_peak_values),
            "network_cpu_percent": pool_cpu,
            "external_cpu_percent": external_pressure.external_cpu_percent,
            "cpu_attribution_quality": self._last_attribution_quality,
            "keyboard_idle_s": idle_seconds,
            "non_pool_cpu_percent": max(0.0, cpu_total - (pool_cpu or 0.0)),
            "memory_used_mb": int(memory.used / 1024**2),
            "total_memory_mb": int(memory.total / 1024**2),
            "available_memory_mb": int(memory.available / 1024**2),
            "disk_used_mb": int(disk.used / 1024**2),
            "total_disk_mb": int(disk.total / 1024**2),
            "free_disk_mb": int(disk.free / 1024**2),
            "running_units": len(active_processes),
            "gpu": gpu,
            "gpu_status": gpu_status,
            "available": available,
            "unavailable_reasons": reasons,
            "source": "ssh-supervisor",
            "observed_at": observed_at.isoformat(),
            "external_load": external_pressure.model_dump(mode="json"),
            "external_pressure": external_pressure.model_dump(mode="json"),
            "external_process_set_hash": self._external_process_set_hash,
            "external_process_count": self._external_process_count,
            "external_comsol_process_set_hash": self._external_process_set_hash,
            "external_comsol_process_count": self._external_process_count,
            "attempt_resource_usage": attempt_resource_usage,
        }
