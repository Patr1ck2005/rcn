"""Deterministic multi-machine simulator used for UI acceptance only."""

from __future__ import annotations

import math
from datetime import datetime, timezone

from .models import (
    ApprovalRecord,
    ApprovalScope,
    JobEnvelope,
    MachineExecutionConfig,
    MachineHeartbeat,
    MachineMetrics,
    MachineMode,
    MachineOperationalStatus,
    MachinePolicy,
    MachineState,
    ProjectGrant,
    ResourceRequest,
    TimeWindow,
    SupervisorState,
    TelemetryState,
    TransportState,
    UserAccount,
    WorkUnit,
    WorkUnitStatus,
)
from .profiles import WORKBENCH_COMSOL_SCAN_V1
from .service import NetworkService


class DemoSimulator:
    """Six synthetic Windows machines; it never starts a real process."""

    def __init__(self, service: NetworkService) -> None:
        self.service = service
        self.tick_count = 0

    def bootstrap(self) -> None:
        self.service.create_user(
            user=self.service.repository.get_user("demo-member")
            or UserAccount(
                user_id="demo-member",
                display_name="Demo Member",
            ),
            actor_id="demo-simulator",
        )
        self.service.register_project(ProjectGrant(
            project_id="demo-simulator-project",
            owner_user_id="demo-member",
            approved=True,
            allowed_profiles={WORKBENCH_COMSOL_SCAN_V1.profile_id},
            trusted_machine_labels={"demo"},
            max_running_units=12,
        ), actor_id="demo-simulator")
        now = datetime.now(timezone.utc)
        for index in range(1, 7):
            machine_id = f"sim-worker-{index:02d}"
            if self.service.repository.get_machine(machine_id) is None:
                machine = MachineState(
                    machine_id=machine_id,
                    owner_user_id="demo-member",
                    hostname=f"SIM-WIN-{index:02d}",
                    labels={"demo", "group-trusted"},
                    capabilities={"comsol-6.4", "python-mph"},
                    total_cpus=8 + index * 2,
                    total_memory_mb=32768 + index * 8192,
                    total_gpus=1 if index in {2, 4, 6} else 0,
                    metrics=MachineMetrics(observed_at=now),
                    last_heartbeat_at=now,
                )
                policy = MachinePolicy(
                    machine_id=machine_id,
                    owner_user_id="demo-member",
                    weekly_windows={day: [TimeWindow(start="00:00", end="00:00")] for day in range(7)},
                    owner_mode=MachineMode.OPEN,
                    max_cpus=machine.total_cpus,
                    max_memory_mb=machine.total_memory_mb - 4096,
                    max_gpus=machine.total_gpus,
                    max_concurrent_units=2,
                )
                self.service.register_machine(machine, policy, actor_id="demo-simulator")
                self.service.approve(ApprovalRecord(
                    machine_id=machine_id,
                    scope=ApprovalScope.PROJECT,
                    subject_id="demo-simulator-project",
                    approved_by="demo-member",
                ), actor_id="demo-member")
            if self.service.repository.get_machine_execution_config(machine_id) is None:
                self.service.repository.put_machine_execution_config(MachineExecutionConfig(
                    machine_id=machine_id,
                    max_concurrent_units=2,
                    target_concurrent_units=2,
                    accepted_hard_capacity_units=2,
                    enabled=True,
                    operational_execution="passed",
                    conditional_production="enabled",
                    startup_after_reboot="passed",
                    numeric_equivalence="passed",
                    root_uuid=f"demo-root-{index:02d}",
                    runtime_version="demo-runtime-v1",
                ))
            self.service.update_operational_status(
                MachineOperationalStatus(
                    machine_id=machine_id,
                    transport_state=TransportState.CONNECTED,
                    supervisor_state=SupervisorState.ONLINE,
                    telemetry_state=TelemetryState.LIVE,
                    last_checked_at=now,
                    last_supervisor_heartbeat_at=now,
                    last_metric_at=now,
                    telemetry_source="simulator",
                    consecutive_successes=1,
                ),
                actor_id="demo-simulator",
            )
        for job_index in range(3):
            units = [
                WorkUnit(
                    work_unit_id=f"sim-unit-{job_index}-{unit_index}",
                    ordinal=unit_index,
                    payload={"kind": "simulated", "step": unit_index},
                    expected_duration_s=90,
                    resources=ResourceRequest(cpus=2, memory_mb=2048, disk_mb=1024),
                    required_capabilities={"comsol-6.4", "python-mph"},
                )
                for unit_index in range(6)
            ]
            self.service.submit(JobEnvelope(
                job_id=f"sim-job-{job_index}",
                origin_submitter_id="demo-simulator",
                user_id="demo-member",
                project_id="demo-simulator-project",
                execution_profile_id=WORKBENCH_COMSOL_SCAN_V1.profile_id,
                request_hash=f"{job_index + 100:064x}",
                work_units=units,
            ), actor_id="demo-simulator")

    def tick(self) -> None:
        self.tick_count += 1
        now = datetime.now(timezone.utc)
        for index, machine in enumerate(self.service.repository.list_machines(), start=1):
            if not machine.machine_id.startswith("sim-worker-"):
                continue
            policy = self.service.repository.get_policy(machine.machine_id)
            phase = self.tick_count / 3 + index
            cpu = max(2.0, min(96.0, 42 + 32 * math.sin(phase)))
            memory_used = int(machine.total_memory_mb * (0.28 + 0.22 * (1 + math.sin(phase / 2)) / 2))
            disk_used = int(240000 * (0.15 + index * 0.02))
            gpu = []
            if machine.total_gpus:
                from .models import GpuMetric
                gpu = [GpuMetric(
                    index=0,
                    name="Simulated RTX",
                    utilization_percent=max(0.0, min(100.0, 55 + 35 * math.sin(phase * 1.3))),
                    memory_total_mb=8192,
                    memory_used_mb=int(3000 + 2500 * (1 + math.sin(phase)) / 2),
                    temperature_c=55 + 12 * math.sin(phase),
                )]
            metrics = MachineMetrics(
                cpu_total_percent=cpu,
                # The scheduler respects non-pool activity rather than total
                # utilization.  Synthetic work accounts for the difference so
                # the demo pool can visibly run work while the UI still shows
                # a changing total CPU load.
                non_pool_cpu_percent=5.0 + 4.0 * (1 + math.sin(phase / 2)) / 2,
                keyboard_idle_s=1800 + (index * 120),
                memory_used_mb=memory_used,
                total_memory_mb=machine.total_memory_mb,
                available_memory_mb=machine.total_memory_mb - memory_used,
                disk_used_mb=disk_used,
                total_disk_mb=240000,
                free_disk_mb=240000 - disk_used,
                gpu=gpu,
                source="simulator",
                observed_at=now,
            )
            self.service.record_heartbeat(
                MachineHeartbeat(machine_id=machine.machine_id, metrics=metrics),
                actor_id="demo-simulator",
            )
            if policy and policy.effective_mode() == MachineMode.EMERGENCY_STOP:
                self.service.stop_simulated_units(machine.machine_id, actor_id="demo-simulator")

        for _ in range(6):
            self.service.schedule_once(actor_id="demo-simulator")
        for listed_job in self.service.repository.list_jobs():
            if not listed_job.job_id.startswith("sim-job-"):
                continue
            job = self.service.repository.get_job(listed_job.job_id)
            if job is None:
                continue
            for unit in job.work_units:
                if unit.status == WorkUnitStatus.ASSIGNED:
                    self.service.mark_unit_started(job.job_id, unit.work_unit_id, actor_id="demo-simulator")
                    break
                elif unit.status == WorkUnitStatus.RUNNING:
                    unit.progress_percent = min(100.0, unit.progress_percent + 14.0)
                    self.service.repository.put_job(job)
                    if unit.progress_percent >= 100:
                        self.service.mark_unit_completed(
                            job.job_id,
                            unit.work_unit_id,
                            duration_s=90.0,
                            actor_id="demo-simulator",
                        )
                    break
