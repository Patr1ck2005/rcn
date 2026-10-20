"""Controlled real-SSH retry and migration acceptance for the pilot."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from importlib.resources import files
from pathlib import Path
from typing import Callable
from uuid import uuid4

from .hashing import sha256_file, sha256_value
from .models import (
    ApprovalRecord,
    ApprovalScope,
    ArtifactManifest,
    Assignment,
    FileRecord,
    JobEnvelope,
    MachineHeartbeat,
    MachineMode,
    ProjectGrant,
    RemoteRunRecord,
    RemoteRunState,
    ResourceRequest,
    TimeWindow,
    WorkUnit,
)
from .profiles import PROJECT_WORKER_V1
from .repository import MetadataRepository
from .schedulers.ssh import OpenSshTransport, SshSchedulerAdapter
from .service import NetworkService
from .ssh_bundle import build_project_worker_unit_bundle


ExecutionResult = dict[str, object]
Executor = Callable[[NetworkService, JobEnvelope, Assignment, Path], ExecutionResult]
PACKAGE_ACCEPTANCE_FIXTURES = Path(
    str(files("research_compute_network.acceptance_fixtures"))
)


class RetryMigrationAuditor:
    """Run one deterministic two-attempt migration with an unaffected control."""

    def __init__(
        self,
        formal_service: NetworkService,
        *,
        project_root: Path,
        source_machine_id: str,
        target_machine_id: str,
        state_root: Path | None = None,
        executor: Executor | None = None,
    ) -> None:
        if source_machine_id == target_machine_id:
            raise ValueError("retry migration requires two different machines")
        self.formal_service = formal_service
        self.formal_repository = formal_service.repository
        self.project_root = Path(project_root)
        self.source_machine_id = source_machine_id
        self.target_machine_id = target_machine_id
        self.run_id = f"retry-migration-{uuid4().hex}"
        self.state_root = state_root or self.project_root / ".state" / "retry-migration" / self.run_id
        self.executor = executor or self._execute_real

    def _audit_service(self) -> NetworkService:
        self.state_root.mkdir(parents=True, exist_ok=True)
        service = NetworkService(
            MetadataRepository(f"sqlite:///{(self.state_root / 'audit.db').as_posix()}")
        )
        service.initialize()
        return service

    def _register_machine(self, service: NetworkService, machine_id: str) -> None:
        machine = self.formal_repository.get_machine(machine_id)
        policy = self.formal_repository.get_policy(machine_id)
        if machine is None or policy is None:
            raise KeyError(f"machine or policy not found: {machine_id}")
        now = datetime.now(timezone.utc)
        machine = machine.model_copy(deep=True)
        machine.capabilities.add("python-project-worker")
        machine.last_heartbeat_at = now
        machine.metrics.observed_at = now
        machine.metrics.keyboard_idle_s = max(machine.metrics.keyboard_idle_s, 10)
        machine.metrics.running_units = 0
        machine.metrics.available = True
        machine.metrics.unavailable_reasons = []
        policy = policy.model_copy(deep=True)
        policy.owner_mode = MachineMode.OPEN
        policy.admin_mode_override = None
        policy.keyboard_idle_min_s = 10
        policy.max_concurrent_units = 1
        policy.weekly_windows = {
            day: [TimeWindow(start="00:00", end="00:00")] for day in range(7)
        }
        service.register_machine(machine, policy, actor_id="retry-migration-auditor")
        service.record_heartbeat(
            MachineHeartbeat(machine_id=machine_id, metrics=machine.metrics),
            actor_id="retry-migration-auditor",
        )
        service.approve(
            ApprovalRecord(
                machine_id=machine_id,
                scope=ApprovalScope.PROJECT,
                subject_id="compute-network-pilot",
                approved_by="retry-migration-auditor",
            ),
            actor_id="retry-migration-auditor",
        )

    def _execute_real(
        self,
        service: NetworkService,
        job: JobEnvelope,
        assignment: Assignment,
        destination: Path,
    ) -> ExecutionResult:
        config = self.formal_repository.get_machine_execution_config(assignment.machine_id)
        if config is None or not config.runtime_version:
            raise RuntimeError(f"deployed runtime config is unavailable: {assignment.machine_id}")
        config = config.model_copy(update={"enabled": True})
        transport = OpenSshTransport(
            config,
            state_root=self.project_root / ".state" / "ssh",
        )
        external_run_id = SshSchedulerAdapter.external_id(job, assignment)
        unit = next(item for item in job.work_units if item.work_unit_id == assignment.work_unit_id)
        arguments = dict(unit.payload["arguments"])
        bundle = build_project_worker_unit_bundle(
            project_root=PACKAGE_ACCEPTANCE_FIXTURES,
            entrypoint="project_worker_smoke.py",
            project_files=[],
            arguments=arguments,
            job=job,
            assignment=assignment,
            external_run_id=external_run_id,
            config=config,
            runtime_version=config.runtime_version,
            output_zip=self.state_root / "bundles" / f"{external_run_id}.zip",
        )
        transport.stage_bundle(external_run_id, bundle)
        service.put_remote_run(
            RemoteRunRecord(
                external_run_id=external_run_id,
                machine_id=assignment.machine_id,
                job_id=job.job_id,
                work_unit_id=assignment.work_unit_id,
                request_hash=sha256_value({"external_run_id": external_run_id}),
                state=RemoteRunState.STAGED,
                remote_relative_path="",
            ),
            actor_id="retry-migration-auditor",
        )
        deadline = time.monotonic() + 180
        status: dict = {}
        observed_states: list[str] = []
        while time.monotonic() < deadline:
            status = transport.read_status(external_run_id)
            state = str(status.get("state", "staged"))
            if not observed_states or observed_states[-1] != state:
                observed_states.append(state)
            if state in {"completed", "failed", "cancelled", "interrupted"}:
                break
            time.sleep(1)
        if status.get("state") != "completed":
            raise RuntimeError(f"controlled project worker did not complete: {status.get('state')}")
        transport.download_outputs(external_run_id, destination)
        manifest_path = next(iter(destination.rglob("project-worker-manifest.json")), None)
        if manifest_path is None:
            raise RuntimeError("project-worker manifest was not returned")
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        files: list[FileRecord] = []
        for item in payload.get("files", []):
            relative_path = str(item["relative_path"])
            artifact_path = next(iter(destination.rglob(relative_path)), None)
            if artifact_path is None or sha256_file(artifact_path) != item["sha256"]:
                raise RuntimeError(f"artifact SHA-256 verification failed: {relative_path}")
            files.append(FileRecord(
                relative_path=relative_path,
                size_bytes=artifact_path.stat().st_size,
                sha256=item["sha256"],
                media_type="application/json",
            ))
        service.put_remote_run(
            RemoteRunRecord(
                external_run_id=external_run_id,
                machine_id=assignment.machine_id,
                job_id=job.job_id,
                work_unit_id=assignment.work_unit_id,
                request_hash=str(status.get("request_hash", "0" * 64)),
                state=RemoteRunState.COMPLETED,
                remote_relative_path=str(status.get("remote_relative_path", "")),
                progress_percent=100,
                message=str(status.get("message", "")),
                artifacts_available=True,
            ),
            actor_id="retry-migration-auditor",
        )
        return {
            "external_run_id": external_run_id,
            "files": files,
            "hashes": {item.relative_path: item.sha256 for item in files},
            "observed_states": observed_states,
        }

    @staticmethod
    def _artifact_manifest(job: JobEnvelope, assignment: Assignment, result: ExecutionResult) -> ArtifactManifest:
        return ArtifactManifest(
            job_id=job.job_id,
            work_unit_id=assignment.work_unit_id,
            files=list(result["files"]),
            output_schema=PROJECT_WORKER_V1.output_schema,
            producer={
                "machine_id": assignment.machine_id,
                "external_run_id": str(result["external_run_id"]),
            },
        )

    def run(self) -> dict:
        service = self._audit_service()
        actor = "retry-migration-auditor"
        service.register_project(
            ProjectGrant(
                project_id="compute-network-pilot",
                owner_user_id=actor,
                approved=True,
                allowed_profiles={PROJECT_WORKER_V1.profile_id},
                trusted_machine_labels={"group-trusted"},
            ),
            actor_id=actor,
        )
        self._register_machine(service, self.source_machine_id)
        request_hash = sha256_value({"run_id": self.run_id, "profile": PROJECT_WORKER_V1.profile_id})
        common_payload = {
            "kind": PROJECT_WORKER_V1.profile_id,
            "entrypoint": "project_worker_smoke.py",
        }
        fault_unit = WorkUnit(
            work_unit_id=f"unit-{request_hash[:12]}-fault",
            ordinal=0,
            payload={**common_payload, "arguments": {"acceptance_nonce": self.run_id, "value": 7}},
            expected_duration_s=30,
            resources=ResourceRequest(cpus=1, memory_mb=256, disk_mb=16),
            required_capabilities={"python-project-worker"},
            max_attempts=3,
        )
        control_unit = WorkUnit(
            work_unit_id=f"unit-{request_hash[:12]}-control",
            ordinal=1,
            payload={**common_payload, "arguments": {"acceptance_nonce": f"{self.run_id}-control", "value": 11}},
            expected_duration_s=30,
            resources=ResourceRequest(cpus=1, memory_mb=256, disk_mb=16),
            required_capabilities={"python-project-worker"},
            max_attempts=3,
        )
        job = service.submit(
            JobEnvelope(
                job_id=self.run_id,
                origin_submitter_id=actor,
                user_id=actor,
                project_id="compute-network-pilot",
                execution_profile_id=PROJECT_WORKER_V1.profile_id,
                record_class="acceptance",
                request_hash=request_hash,
                work_units=[fault_unit, control_unit],
            ),
            actor_id=actor,
        )
        first = service.schedule_once(actor_id=actor)
        if first is None or first.work_unit_id != fault_unit.work_unit_id:
            raise RuntimeError("source fault unit was not assigned")
        service.mark_unit_started(job.job_id, first.work_unit_id, actor_id=actor)
        first_result = self.executor(service, job, first, self.state_root / "attempt-1")
        self._register_machine(service, self.target_machine_id)
        control = service.schedule_once(actor_id=actor)
        if control is None or control.work_unit_id != control_unit.work_unit_id:
            raise RuntimeError("unrelated control unit was not assigned")
        service.mark_unit_started(job.job_id, control.work_unit_id, actor_id=actor)
        control_result = self.executor(service, job, control, self.state_root / "control")
        service.complete_unit(
            job.job_id,
            control.work_unit_id,
            manifest=self._artifact_manifest(job, control, control_result),
            duration_s=1,
            actor_id=actor,
        )
        service.fail_unit(
            job.job_id,
            first.work_unit_id,
            error="controlled post-execution artifact-transfer fault",
            retryable=True,
            actor_id=actor,
        )
        source_policy = service.repository.get_policy(self.source_machine_id)
        source_policy.owner_mode = MachineMode.PAUSED
        service.repository.put_policy(source_policy)
        service._event(
            "machine.controlled_fault_isolated",
            actor,
            "machine",
            self.source_machine_id,
            job_id=job.job_id,
            work_unit_id=first.work_unit_id,
        )
        control_before_retry = next(
            item for item in service.repository.get_job(job.job_id).work_units
            if item.work_unit_id == control.work_unit_id
        ).model_dump(mode="json")
        service.retry_unit(job.job_id, first.work_unit_id, actor_id=actor)
        second = service.schedule_once(actor_id=actor)
        if second is None or second.work_unit_id != first.work_unit_id:
            raise RuntimeError("failed work unit was not reassigned")
        service.mark_unit_started(job.job_id, second.work_unit_id, actor_id=actor)
        second_result = self.executor(service, job, second, self.state_root / "attempt-2")
        service.complete_unit(
            job.job_id,
            second.work_unit_id,
            manifest=self._artifact_manifest(job, second, second_result),
            duration_s=1,
            actor_id=actor,
        )
        stored = service.repository.get_job(job.job_id)
        fault = next(item for item in stored.work_units if item.work_unit_id == fault_unit.work_unit_id)
        control_after_retry = next(
            item for item in stored.work_units if item.work_unit_id == control.work_unit_id
        ).model_dump(mode="json")
        hashes_equal = first_result["hashes"] == second_result["hashes"]
        control_unchanged = control_before_retry == control_after_retry
        passed = (
            stored.status.value == "completed"
            and fault.attempt_count == 2
            and len(fault.attempts) == 2
            and fault.attempts[0].failure_reason == "controlled post-execution artifact-transfer fault"
            and fault.attempts[1].migrated
            and hashes_equal
            and control_unchanged
        )
        events = [
            event.model_dump(mode="json") for event in service.repository.list_events(limit=200)
            if event.subject_id in {job.job_id, fault_unit.work_unit_id, control_unit.work_unit_id, self.source_machine_id}
        ]
        report = {
            "run_id": self.run_id,
            "status": "passed" if passed else "failed",
            "source_machine_id": self.source_machine_id,
            "target_machine_id": self.target_machine_id,
            "max_attempts": fault.max_attempts,
            "attempt_count": fault.attempt_count,
            "attempt_ledger": [item.model_dump(mode="json") for item in fault.attempts],
            "manifest_hashes_before_retry": first_result["hashes"],
            "manifest_hashes_after_retry": second_result["hashes"],
            "manifest_hashes_equal": hashes_equal,
            "control_unit_unchanged": control_unchanged,
            "audit_event_types": sorted({event["event_type"] for event in events}),
            "audit_event_count": len(events),
            "database": str(self.state_root / "audit.db"),
        }
        (self.state_root / "report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        if not passed:
            raise RuntimeError("retry/migration audit did not satisfy all gates")
        return report
