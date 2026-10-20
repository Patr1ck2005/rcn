"""SSH/COMSOL acceptance harness for registered Windows workers.

Operational checks use a registered execution configuration. Scientific probes
require origin-owned acceptance inputs; no project or reference data is selected
implicitly.
"""

from __future__ import annotations

import base64
import json
import re
import shutil
import socket
import time
import zipfile
from datetime import datetime, timezone
from importlib.resources import files
from pathlib import Path, PureWindowsPath
from subprocess import TimeoutExpired
from uuid import uuid4

from .hashing import sha256_file, sha256_value
from .models import (
    AcceptanceCheck,
    AcceptanceStatus,
    Assignment,
    JobEnvelope,
    MachineExecutionConfig,
    RemoteRunRecord,
    RemoteRunState,
    ResourceRequest,
    SshAcceptanceRun,
    SolverVariant,
    WorkUnit,
)
from .profiles import PROJECT_WORKER_V1, SAFE_FAKE_TASK_V1
from .integrations import (
    load_workbench_runtime_source,
    load_workbench_scan_planner,
    materialize_workbench_probe_job,
    workbench_unit_item_count,
)
from .remote_storage import RemoteLayout, validate_remote_root_path
from .schedulers.ssh import OpenSshTransport
from .service import NetworkService, STABLE_RUNTIME_VERSION
from .ssh_bundle import (
    build_comsol_unit_bundle,
    build_project_worker_unit_bundle,
    build_runtime_package,
    build_safe_fake_unit_bundle,
    merge_chunk_outputs,
)


PACKAGE_ACCEPTANCE_FIXTURES = Path(
    str(files("research_compute_network.acceptance_fixtures"))
)
REQUIRED_CHECK_IDS = {
    "ssh_transport",
    "worker_environment",
    "root_initialized",
    "runtime_deployed",
    "safe_fake_task",
    "project_worker_task",
    "concurrency_1",
    "concurrency_2",
    "concurrency_3",
    "cancel_python_start",
    "cancel_comsol_start",
    "cancel_solve",
    "cancel_transfer",
    "tunnel_recovery",
    "no_residual_processes",
}

# Task Scheduler's restart count is a per-task failure window.  Three retries
# may be exhausted by external interruptions, leaving a healthy machine
# without a heartbeat. Keep the retry window bounded but
# long enough to cover transient logon/session interruptions, and expose the
# policy through the read-only startup-status command.
SUPERVISOR_RESTART_COUNT = 5
SUPERVISOR_RESTART_INTERVAL_MINUTES = 1
SUPERVISOR_WATCHDOG_INTERVAL_MINUTES = 5
SUPERVISOR_TASK_SETTINGS = (
    "New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries "
    "-DontStopIfGoingOnBatteries -StartWhenAvailable "
    "-MultipleInstances IgnoreNew "
    f"-RestartCount {SUPERVISOR_RESTART_COUNT} "
    f"-RestartInterval (New-TimeSpan -Minutes {SUPERVISOR_RESTART_INTERVAL_MINUTES}) "
    "-ExecutionTimeLimit ([TimeSpan]::Zero)"
)


def _operational_numeric_status(
    operational_passed: bool,
    numerical_passed: bool,
) -> AcceptanceStatus:
    if not operational_passed:
        return AcceptanceStatus.FAILED
    return AcceptanceStatus.PASSED if numerical_passed else AcceptanceStatus.WARNING


class SshAcceptanceHarness:
    def __init__(
        self,
        service: NetworkService,
        *,
        project_root: Path,
        workspace_root: Path,
        machine_config: MachineExecutionConfig,
        transport: OpenSshTransport | None = None,
        acceptance_inputs=None,
    ) -> None:
        self.service = service
        self.project_root = project_root
        self.workspace_root = workspace_root
        self.machine_config = machine_config
        self.acceptance_inputs = acceptance_inputs
        self.transport = transport or OpenSshTransport(
            machine_config,
            state_root=project_root / ".state" / "ssh",
        )

    @property
    def state_root(self) -> Path:
        return self.project_root / ".state" / "ssh-acceptance"

    @property
    def supervisor_config_path(self) -> PureWindowsPath:
        """Return the per-account supervisor config location on Windows.

        SSH accounts in this pilot map to their normal Windows profile.  The
        path is derived locally and never accepted from a task payload.
        """
        from .supervisor_paths import supervisor_config_path
        return supervisor_config_path(self.machine_config)

    def _require_remote_supervisor_pythonw(
        self,
        python_executable: str | PureWindowsPath | None = None,
    ) -> PureWindowsPath:
        """Resolve and verify the console-free interpreter before any restart."""
        configured = PureWindowsPath(
            python_executable or self.machine_config.python_executable
        )
        pythonw = configured.with_name("pythonw.exe")
        pythonw_text = str(pythonw).replace("'", "''")
        completed = self.transport._powershell(
            f"""
$ErrorActionPreference='Stop'
$pythonw='{pythonw_text}'
if (-not (Test-Path -LiteralPath $pythonw -PathType Leaf)) {{
  Write-Error 'managed pythonw.exe is required for windowless supervisor startup'
  exit 75
}}
[PSCustomObject]@{{available=$true;executable=$pythonw}} | ConvertTo-Json -Compress
""",
            timeout=30,
        )
        self.transport._require_success(
            completed,
            "verify windowless supervisor interpreter",
        )
        return pythonw

    @property
    def expected_hostname(self) -> str | None:
        return self.machine_config.expected_hostname

    @property
    def legacy_worker_path(self) -> str:
        return self.machine_config.legacy_worker_path or fr"C:\Users\{self.machine_config.ssh_user}\comsol_worker"

    def create_run(self, *, actor_id: str, concurrency: int | None = None) -> SshAcceptanceRun:
        if concurrency is not None and concurrency not in (1, 2, 3):
            raise ValueError("acceptance concurrency must be 1, 2 or 3")
        run = SshAcceptanceRun(
            status=AcceptanceStatus.RUNNING,
            coordinator_hostname=socket.gethostname(),
            worker_id=self.machine_config.machine_id,
            worker_hostname=self.machine_config.expected_hostname or "",
            remote_root=self.machine_config.remote_root,
            concurrency_levels=list(range(1, (concurrency or self.machine_config.target_concurrent_units) + 1)),
        )
        self.state_root.mkdir(parents=True, exist_ok=True)
        return self.service.put_ssh_acceptance_run(run, actor_id=actor_id)

    def _save(self, run: SshAcceptanceRun, actor_id: str) -> None:
        self.service.put_ssh_acceptance_run(run, actor_id=actor_id)

    def _refresh_status(self, run: SshAcceptanceRun) -> None:
        checks = {item.check_id: item.status for item in run.checks}
        required = set(REQUIRED_CHECK_IDS)
        required.difference_update({"concurrency_1", "concurrency_2", "concurrency_3"})
        required.update(f"concurrency_{level}" for level in run.concurrency_levels)
        if any(status == AcceptanceStatus.FAILED for status in checks.values()):
            run.status = AcceptanceStatus.FAILED
        elif all(
            checks.get(check_id) in {AcceptanceStatus.PASSED, AcceptanceStatus.WARNING}
            for check_id in required
        ):
            run.status = AcceptanceStatus.PASSED
        else:
            run.status = AcceptanceStatus.RUNNING

    def _check(self, run, check_id, label, status, message, *, actor_id, evidence=None):
        found = next((item for item in run.checks if item.check_id == check_id), None)
        check = found or AcceptanceCheck(check_id=check_id, label=label)
        check.status = status
        check.message = message
        check.evidence = evidence or {}
        check.updated_at = datetime.now(timezone.utc)
        if found is None:
            run.checks.append(check)
        self._refresh_status(run)
        self._save(run, actor_id)

    def preflight(self, run: SshAcceptanceRun, *, actor_id: str) -> SshAcceptanceRun:
        validate_remote_root_path(self.machine_config.remote_root)
        probe = self.transport.probe()
        self._check(
            run,
            "ssh_transport",
            "Pinned SSH transport",
            AcceptanceStatus.PASSED if probe.available else AcceptanceStatus.FAILED,
            "pinned SSH connection is available" if probe.available else "SSH connection failed",
            actor_id=actor_id,
            evidence=probe.model_dump(mode="json"),
        )
        script = f"""
$ProgressPreference='SilentlyContinue'
$python='{self.machine_config.python_executable}'
$info=& $python -c "import json,sys,importlib.util; print(json.dumps({{'version':sys.version,'mph':bool(importlib.util.find_spec('mph')),'jpype':bool(importlib.util.find_spec('jpype')),'yaml':bool(importlib.util.find_spec('yaml'))}}))" 2>&1
$drive=Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='{self.machine_config.remote_root[:2]}'"
$active=@(Get-CimInstance Win32_Process | Where-Object {{
  $_.Name -match '^(python|pythonw|comsol|comsolmphserver)\\.exe$' -and
  $_.CommandLine -notlike '*ResearchComputeNetwork*remote-agent*supervisor.py*'
}} | Select-Object ProcessId,Name,CommandLine)
$old=Get-Item -LiteralPath '{self.legacy_worker_path}' -ErrorAction SilentlyContinue
[PSCustomObject]@{{
 hostname=$env:COMPUTERNAME
 python_info=($info -join "`n")
 comsol=(Test-Path -LiteralPath '{self.machine_config.comsol_root}')
 free_bytes=[int64]$drive.FreeSpace
 active_compute=$active.Count
 root_exists=(Test-Path -LiteralPath '{self.machine_config.remote_root}')
 old_worker_exists=[bool]$old
 old_worker_last_write=if($old){{$old.LastWriteTimeUtc.ToString('o')}}else{{$null}}
}} | ConvertTo-Json -Compress
"""
        completed = self.transport._powershell(script, timeout=45)
        evidence = {}
        try:
            evidence = next(
                json.loads(line.strip())
                for line in completed.stdout.splitlines()
                if line.strip().startswith("{") and line.strip().endswith("}")
            )
            python_info = json.loads(evidence.get("python_info", "{}"))
            allow_member_compute = (
                self.machine_config.execution_provenance.get(
                    "onboarding_exception"
                )
                == "owner-approved-active-compute-coexistence-20260905"
            )
            active_compute = int(evidence.get("active_compute", 1))
            evidence["member_compute_coexistence_allowed"] = allow_member_compute
            ready = (
                completed.returncode == 0
                and (not self.expected_hostname or evidence.get("hostname", "").upper() == self.expected_hostname.upper())
                and python_info.get("mph") is True
                and python_info.get("jpype") is True
                and python_info.get("yaml") is True
                and evidence.get("comsol") is True
                and int(evidence.get("free_bytes", 0)) >= self.machine_config.disk_reserve_gib * 1024**3
                and (active_compute == 0 or allow_member_compute)
            )
        except (StopIteration, ValueError, json.JSONDecodeError) as exc:
            evidence = {"error": str(exc), "returncode": completed.returncode}
            ready = False
        self._check(
            run,
            "worker_environment",
            f"{self.machine_config.machine_id} COMSOL environment and idle state",
            AcceptanceStatus.PASSED if ready else AcceptanceStatus.FAILED,
            (
                f"{self.machine_config.machine_id} is ready with owner-approved member compute coexistence"
                if ready and evidence.get("active_compute", 0)
                else f"{self.machine_config.machine_id} is idle and ready"
                if ready
                else "worker preflight requirements are not satisfied"
            ),
            actor_id=actor_id,
            evidence=evidence,
        )
        run.status = AcceptanceStatus.RUNNING if all(c.status == AcceptanceStatus.PASSED for c in run.checks) else AcceptanceStatus.FAILED
        self._save(run, actor_id)
        return run

    def initialize_root(self, run: SshAcceptanceRun, *, actor_id: str) -> MachineExecutionConfig:
        from .root_initialization import IDENTITY, build_root_initialization
        from .member_worker_root_contract import canonical_root

        current = self.service.repository.get_machine_execution_config(self.machine_config.machine_id)
        if self.machine_config.enabled or (current is not None and current.enabled):
            raise RuntimeError('enabled execution requires the maintenance gate, not root initialization')
        if current is not None and (canonical_root(current.remote_root) != canonical_root(self.machine_config.remote_root)
                or (current.root_uuid is not None and current.root_uuid != self.machine_config.root_uuid)):
            raise RuntimeError('existing execution root identity differs; explicit migration required')
        script = build_root_initialization(self.machine_config)
        completed = self.transport._powershell(script, timeout=60)
        self.transport._require_success(completed, 'initialize marked root')
        try:
            verified = json.loads(completed.stdout.strip().lstrip('\ufeff'))
            root_uuid = verified['root_uuid']
            if (type(verified.get('schema_version')) is not int or verified['schema_version'] != 1
                    or verified.get('machine_id') != self.machine_config.machine_id
                    or verified.get('remote_root') != canonical_root(self.machine_config.remote_root)
                    or not isinstance(root_uuid, str) or not IDENTITY.fullmatch(root_uuid)
                    or type(verified.get('marker_created')) is not bool
                    or (self.machine_config.root_uuid is not None and root_uuid != self.machine_config.root_uuid)):
                raise ValueError('root readback identity mismatch')
        except (ValueError, KeyError, TypeError):
            raise RuntimeError('root initialization did not return verified identity') from None
        latest = self.service.repository.get_machine_execution_config(self.machine_config.machine_id)
        if latest is not None and (latest.enabled or current is None or latest != current):
            raise RuntimeError('execution configuration changed during root initialization')
        self.machine_config.root_uuid = root_uuid
        self.machine_config.enabled = False
        self.service.put_machine_execution_config(self.machine_config, actor_id=actor_id)
        self._check(
            run,
            'root_initialized',
            'Isolated marked remote root',
            AcceptanceStatus.PASSED,
            f'{self.machine_config.remote_root} identity verified and preserved without touching the legacy worker',
            actor_id=actor_id,
            evidence={'remote_root': self.machine_config.remote_root, 'root_uuid': root_uuid},
        )
        return self.machine_config

    def deploy_managed_python(
        self,
        run: SshAcceptanceRun,
        *,
        wheel_root: Path,
        actor_id: str,
    ) -> dict:
        """Deploy a self-contained CPython 3.11 runtime and pinned wheels.

        Wheels are expanded into the managed runtime's private site-packages;
        no system or user Python installation is modified.
        """
        if not self.machine_config.root_uuid:
            raise RuntimeError("remote root must be initialized before managed Python deployment")
        wheel_root = Path(wheel_root)
        python_archive = wheel_root / "python-3.11.9-embed-amd64.zip"
        wheel_names = [
            "numpy-2.4.6-cp311-cp311-win_amd64.whl",
            "scipy-1.17.1-cp311-cp311-win_amd64.whl",
            "h5py-3.16.0-cp311-cp311-win_amd64.whl",
            "jpype1-1.7.1-cp311-cp311-win_amd64.whl",
            "mph-1.3.1-py3-none-any.whl",
            "pyyaml-6.0.3-cp311-cp311-win_amd64.whl",
            "psutil-7.2.2-cp37-abi3-win_amd64.whl",
        ]
        sources = [python_archive, *(wheel_root / name for name in wheel_names)]
        missing = [str(path) for path in sources if not path.is_file()]
        if missing:
            raise FileNotFoundError("managed runtime artifacts are missing: " + ", ".join(missing))
        uploaded = {}
        for source in sources:
            digest = sha256_file(source)
            uploaded[source.name] = {
                "sha256": digest,
                "remote_path": str(self.transport.upload_cache_object(source, digest)),
            }
        root = PureWindowsPath(self.machine_config.remote_root)
        python_root = root / "agent" / "python" / "3.11.9"
        python_executable = python_root / "python.exe"
        site_packages = python_root / "site-packages"
        marker = python_root / "managed-runtime.json"
        archive_path = uploaded[python_archive.name]["remote_path"]
        marker_payload = json.dumps(
            {
                "schema_version": 1,
                "python_version": "3.11.9",
                "artifacts": {name: value["sha256"] for name, value in uploaded.items()},
            },
            separators=(",", ":"),
        ).replace("'", "''")
        marker_check = self.transport._powershell(
            f"if (Test-Path -LiteralPath '{marker}') {{ exit 0 }} else {{ exit 1 }}",
            timeout=30,
        )
        already_deployed = marker_check.returncode == 0
        prepare_script = f"""
$ErrorActionPreference='Stop'
$pythonRoot='{python_root}'
$pythonExe='{python_executable}'
$site='{site_packages}'
if (-not (Test-Path -LiteralPath $pythonExe)) {{
  New-Item -ItemType Directory -Force -Path $pythonRoot | Out-Null
  Expand-Archive -LiteralPath '{archive_path}' -DestinationPath $pythonRoot -Force
}}
New-Item -ItemType Directory -Force -Path $site | Out-Null
@('python311.zip','.','site-packages') | Set-Content -LiteralPath (Join-Path $pythonRoot 'python311._pth') -Encoding ASCII
"""
        if not already_deployed:
            prepared = self.transport._powershell(prepare_script, timeout=180)
            self.transport._require_success(prepared, "prepare managed Python runtime")
            for name in wheel_names:
                remote_wheel = uploaded[name]["remote_path"].replace("'", "''")
                extract = self.transport._powershell(
                    f"& '{python_executable}' -c \"import zipfile; zipfile.ZipFile(r'{remote_wheel}').extractall(r'{site_packages}')\"; "
                    "if ($LASTEXITCODE -ne 0) { exit 82 }",
                    timeout=180,
                )
                self.transport._require_success(extract, f"expand managed wheel {name}")
        validation_result = self.transport._powershell(
            f"$validation=& '{python_executable}' -c \"import json,sys,mph,jpype,numpy,scipy,h5py,yaml,psutil; print(json.dumps({{'version':sys.version.split()[0],'mph':getattr(mph,'__version__','unknown'),'jpype':jpype.__version__,'numpy':numpy.__version__,'scipy':scipy.__version__,'h5py':h5py.__version__,'yaml':yaml.__version__,'psutil':psutil.__version__}}))\"; "
            "if ($LASTEXITCODE -ne 0) { exit 83 }; "
            f"Set-Content -LiteralPath '{marker}' -Value '{marker_payload}' -Encoding UTF8; $validation",
            timeout=180,
        )
        self.transport._require_success(validation_result, "validate managed Python runtime")
        validation = next(
            json.loads(line.strip())
            for line in validation_result.stdout.splitlines()
            if line.strip().startswith("{") and line.strip().endswith("}")
        )
        if validation.get("version") != "3.11.9":
            raise RuntimeError("managed Python validation returned an unexpected version")
        self.machine_config.python_executable = str(python_executable)
        self.service.put_machine_execution_config(self.machine_config, actor_id=actor_id)
        self._check(
            run,
            "managed_python",
            "Versioned managed Python runtime",
            AcceptanceStatus.PASSED,
            "isolated CPython 3.11 and fixed scientific wheels were verified",
            actor_id=actor_id,
            evidence={
                "python_executable": str(python_executable),
                "versions": validation,
                "artifact_hashes": {name: value["sha256"] for name, value in uploaded.items()},
            },
        )
        return {"python_executable": str(python_executable), "versions": validation}

    def deploy(self, run: SshAcceptanceRun, *, actor_id: str) -> dict:
        from .member_release_catalog import RuntimeNotConfigured
        # Public workers only install an explicitly approved external archive.
        raise RuntimeNotConfigured()

    def deploy_sealed_runtime(
        self,
        archive: Path,
        runtime_version: str,
        *,
        actor_id: str,
    ) -> dict:
        """Deploy only a verified sealed runtime to an idle enrolled worker.

        A runtime update must never select, copy, or alter a project
        template. Templates arrive later in authorized fixed-recipe bundles.
        """
        archive = Path(archive).resolve()
        if not re.fullmatch(r"[0-9a-f]{24}", runtime_version):
            raise ValueError("sealed runtime version must be a 24-character lowercase fingerprint")
        if not archive.is_file():
            raise FileNotFoundError(archive)
        from .member_release_catalog import release_for_runtime
        from .member_runtime import approved_runtime
        release = release_for_runtime(runtime_version).require_configured()
        approved_runtime(archive, release_descriptor=release)

        formal = self.service.repository.get_machine_execution_config(self.machine_config.machine_id)
        if formal is None or not formal.enabled:
            raise RuntimeError("sealed runtime deployment requires an enabled enrolled machine")
        supervisor = self.supervisor_status()
        if supervisor.get("running") and supervisor.get("active_run_ids"):
            raise RuntimeError("cannot deploy a sealed runtime while work units are active")

        previous = formal.model_copy(deep=True)
        provenance = dict(formal.execution_provenance)
        provenance["previous_runtime_version"] = str(formal.runtime_version or "")
        candidate = formal.model_copy(
            deep=True,
            update={
                "runtime_version": runtime_version,
                "execution_provenance": provenance,
            },
        )
        self.machine_config = candidate
        config_dir = self.state_root / "runtime-deployments" / runtime_version
        config_dir.mkdir(parents=True, exist_ok=True)
        candidate_config = config_dir / f"{candidate.machine_id}.json"
        candidate_config.write_text(json.dumps(candidate.model_dump(mode="json"), indent=2), encoding="utf-8")
        try:
            self.transport.upload_runtime(archive, runtime_version)
            self._lock_managed_python_workbench_path(runtime_version)
            self.transport.upload_supervisor_config(candidate_config, self.supervisor_config_path)
            restart = self.restart_supervisor(actor_id=actor_id)
        except Exception:
            # Restore only the preceding sealed supervisor configuration.
            # No COMSOL process is inspected or terminated here.
            self.machine_config = previous
            rollback_config = config_dir / f"{previous.machine_id}.rollback.json"
            rollback_config.write_text(json.dumps(previous.model_dump(mode="json"), indent=2), encoding="utf-8")
            try:
                self.transport.upload_supervisor_config(rollback_config, self.supervisor_config_path)
                self._lock_managed_python_workbench_path(str(previous.runtime_version or ""))
                self.restart_supervisor(actor_id=f"{actor_id}-rollback")
            except Exception:
                pass
            raise

        self.service.put_machine_execution_config(candidate, actor_id=actor_id)
        self.service._event(
            "machine.sealed_runtime_deployed",
            actor_id,
            "machine",
            candidate.machine_id,
            previous_runtime_version=previous.runtime_version,
            runtime_version=runtime_version,
            supervisor_pid=restart["supervisor"].get("pid"),
        )
        return {
            "machine_id": candidate.machine_id,
            "previous_runtime_version": previous.runtime_version,
            "runtime_version": runtime_version,
            "supervisor": restart["supervisor"],
        }

    def _lock_managed_python_workbench_path(self, runtime_version: str) -> None:
        python_path = PureWindowsPath(self.machine_config.python_executable)
        managed_python_root = (
            PureWindowsPath(self.machine_config.remote_root) / "agent" / "python"
        )
        try:
            python_path.relative_to(managed_python_root)
        except ValueError:
            return
        pth = python_path.parent / "python311._pth"
        workbench_source = (
            PureWindowsPath(self.machine_config.remote_root)
            / "agent"
            / "versions"
            / runtime_version
            / "workbench-src"
        )
        pth_script = (
            f"@('python311.zip','.', 'site-packages', '{workbench_source}') | "
            f"Set-Content -LiteralPath '{pth}' -Encoding ASCII"
        )
        pth_result = self.transport._powershell(pth_script, timeout=30)
        self.transport._require_success(pth_result, "lock managed Python Workbench path")

    def supervisor_status(self) -> dict:
        status = RemoteLayout.from_string(self.machine_config.remote_root).agent / "status.json"
        expected_fragment = str(
            PureWindowsPath(self.machine_config.remote_root) / "agent" / "versions"
        ).replace("'", "''")
        completed = self.transport._powershell(
            f"""
if (-not (Test-Path -LiteralPath '{status}')) {{ exit 44 }}
$status=Get-Content -LiteralPath '{status}' -Raw | ConvertFrom-Json
$process=Get-CimInstance Win32_Process -Filter "ProcessId=$($status.pid)" -ErrorAction SilentlyContinue
$running=[bool]($process -and $process.CommandLine -like '*{expected_fragment}*remote-agent*supervisor.py*')
$status | Add-Member -NotePropertyName running -NotePropertyValue $running -Force
$status | ConvertTo-Json -Compress -Depth 8
"""
        )
        if completed.returncode == 44:
            return {"running": False}
        self.transport._require_success(completed, "read supervisor status")
        payload = next(
            json.loads(line.strip())
            for line in completed.stdout.splitlines()
            if line.strip().startswith("{") and line.strip().endswith("}")
        )
        return payload

    @property
    def supervisor_task_name(self) -> str:
        from .supervisor_paths import LOCATION_KEY, MANAGED_LOCATION
        if (self.machine_config.execution_provenance.get(LOCATION_KEY) == MANAGED_LOCATION
                and self.machine_config.root_uuid):
            return f"RCN-Member-{self.machine_config.root_uuid}-Supervisor"
        return f"ResearchComputeNetwork-{self.machine_config.machine_id}"

    def _boot_identity(self) -> str:
        completed = self.transport._powershell(
            "$b=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime; "+
            "[PSCustomObject]@{boot_id=$b.ToUniversalTime().ToString('o')}|ConvertTo-Json -Compress",
            timeout=20,
        )
        self.transport._require_success(completed, "read Windows boot identity")
        try:
            value = next(json.loads(line.strip()) for line in completed.stdout.splitlines()
                         if line.strip().startswith("{") and line.strip().endswith("}"))
            at = datetime.fromisoformat(value["boot_id"].replace("Z", "+00:00"))
            if at.tzinfo is None or at > datetime.now(timezone.utc):
                raise ValueError("invalid boot time")
            return at.astimezone(timezone.utc).isoformat()
        except (StopIteration, ValueError, TypeError, KeyError, json.JSONDecodeError):
            raise RuntimeError("Windows boot identity was not verified") from None

    def supervisor_startup_status(self) -> dict:
        task_name = self.supervisor_task_name
        completed = self.transport._powershell(f"""
$task=Get-ScheduledTask -TaskName '{task_name}' -ErrorAction SilentlyContinue
if (-not $task) {{
  [PSCustomObject]@{{task_name='{task_name}';installed=$false}} | ConvertTo-Json -Compress
  exit 0
}}
$info=Get-ScheduledTaskInfo -TaskName '{task_name}'
$restartInterval=[System.Xml.XmlConvert]::ToTimeSpan([string]$task.Settings.RestartInterval)
$watchdog=$task.Triggers | Where-Object {{ $_.Repetition.Interval }} | Select-Object -First 1
$watchdogInterval=if ($watchdog) {{ [System.Xml.XmlConvert]::ToTimeSpan([string]$watchdog.Repetition.Interval) }} else {{ [TimeSpan]::Zero }}
[PSCustomObject]@{{
  task_name=$task.TaskName
  installed=$true
  enabled=[bool]$task.Settings.Enabled
  state=$task.State.ToString()
  last_task_result=$info.LastTaskResult
  last_run_time=$info.LastRunTime
  next_run_time=$info.NextRunTime
  principal_user=$task.Principal.UserId
  logon_type=$task.Principal.LogonType.ToString()
  execute=$task.Actions[0].Execute
  arguments=$task.Actions[0].Arguments
  working_directory=$task.Actions[0].WorkingDirectory
  restart_count=$task.Settings.RestartCount
  restart_interval_seconds=[int]$restartInterval.TotalSeconds
  watchdog_interval_seconds=[int]$watchdogInterval.TotalSeconds
  trigger_count=@($task.Triggers).Count
  restart_policy_healthy=([int]$task.Settings.RestartCount -ge {SUPERVISOR_RESTART_COUNT} -and [int]$restartInterval.TotalSeconds -le {SUPERVISOR_RESTART_INTERVAL_MINUTES * 60} -and [int]$watchdogInterval.TotalSeconds -gt 0 -and [int]$watchdogInterval.TotalSeconds -le {SUPERVISOR_WATCHDOG_INTERVAL_MINUTES * 60})
  last_task_result_hex=('0x{{0:X8}}' -f [uint32]$info.LastTaskResult)
  multiple_instances=$task.Settings.MultipleInstances.ToString()
}} | ConvertTo-Json -Compress
""")
        self.transport._require_success(completed, "read supervisor startup task")
        return next(
            json.loads(line.strip())
            for line in completed.stdout.splitlines()
            if line.strip().startswith("{") and line.strip().endswith("}")
        )

    def arm_startup_after_reboot(self, run: SshAcceptanceRun, *, actor_id: str) -> dict:
        existing = next((c for c in run.checks if c.check_id == "startup_after_reboot"), None)
        if existing is not None and existing.status == AcceptanceStatus.PASSED:
            return existing.evidence
        supervisor = self.supervisor_status()
        startup = self.supervisor_startup_status()
        try:
            observed = datetime.fromisoformat(str(supervisor["updated_at"]).replace("Z", "+00:00"))
        except (ValueError, TypeError, KeyError):
            raise RuntimeError("fresh idle supervisor with verified startup task required before reboot acceptance") from None
        if (observed.tzinfo is None or not 0 <= (datetime.now(timezone.utc)-observed).total_seconds() <= 60
                or not supervisor.get("running") or supervisor.get("active_run_ids")
                or supervisor.get("runtime_version") != self.machine_config.runtime_version
                or not startup.get("installed") or startup.get("enabled") is not True
                or startup.get("task_name") != self.supervisor_task_name
                or startup.get("restart_policy_healthy") is not True):
            raise RuntimeError("fresh idle supervisor with verified startup task required before reboot acceptance")
        boot = self._boot_identity()
        if existing is not None:
            if existing.status != AcceptanceStatus.RUNNING or existing.evidence.get("armed_boot_id") != boot:
                raise RuntimeError("startup-after-reboot acceptance is already armed for another boot")
            return existing.evidence
        evidence = {"armed_boot_id": boot, "task_name": self.supervisor_task_name,
                    "runtime_version": self.machine_config.runtime_version, "root_uuid": self.machine_config.root_uuid,
                    "armed_at": datetime.now(timezone.utc).isoformat()}
        self._check(run, "startup_after_reboot", "Supervisor recovery after real Windows reboot",
                    AcceptanceStatus.RUNNING, "reboot acceptance armed; reboot the member and verify the same run",
                    actor_id=actor_id, evidence=evidence)
        return evidence

    def verify_startup_after_reboot(self, run: SshAcceptanceRun, *, actor_id: str) -> dict:
        check = next((c for c in run.checks if c.check_id == "startup_after_reboot"), None)
        if check is None:
            raise RuntimeError("startup-after-reboot acceptance must be armed first")
        if check.status == AcceptanceStatus.PASSED:
            return check.evidence
        if check.status != AcceptanceStatus.RUNNING:
            raise RuntimeError("startup-after-reboot acceptance is not resumable")
        previous = check.evidence
        boot = self._boot_identity()
        if boot == previous.get("armed_boot_id"):
            raise RuntimeError("Windows has not rebooted since startup acceptance was armed")
        startup = self.supervisor_startup_status()
        supervisor = self.supervisor_status()
        try:
            observed = datetime.fromisoformat(str(supervisor["updated_at"]).replace("Z", "+00:00"))
        except (ValueError, TypeError, KeyError):
            raise RuntimeError("supervisor heartbeat after reboot is invalid") from None
        if (observed.tzinfo is None or not 0 <= (datetime.now(timezone.utc)-observed).total_seconds() <= 60
                or not supervisor.get("running") or supervisor.get("active_run_ids")
                or supervisor.get("runtime_version") != previous.get("runtime_version")
                or not startup.get("installed") or startup.get("enabled") is not True
                or startup.get("task_name") != previous.get("task_name")
                or startup.get("restart_policy_healthy") is not True):
            raise RuntimeError("supervisor did not independently recover after reboot")
        evidence = {**previous, "verified_boot_id": boot, "verified_at": datetime.now(timezone.utc).isoformat(),
                    "supervisor_observed_at": observed.astimezone(timezone.utc).isoformat()}
        self._check(run, "startup_after_reboot", "Supervisor recovery after real Windows reboot",
                    AcceptanceStatus.PASSED, "verified new Windows boot and fresh automatically recovered supervisor",
                    actor_id=actor_id, evidence=evidence)
        return evidence

    def restart_supervisor(self, *, actor_id: str = "admin") -> dict:
        """Switch the manually/logon-started supervisor to the sealed runtime.

        Only the exact supervisor PID and command rooted in the configured RCN
        directory are eligible for termination; no process-name cleanup is
        used.
        """
        if not self.machine_config.runtime_version:
            raise RuntimeError("runtime is not deployed")
        current = self.supervisor_status()
        old_pid = int(current.get("pid", 0) or 0)
        old_updated_at = current.get("updated_at")
        runtime = PureWindowsPath(self.machine_config.remote_root) / "agent" / "versions" / self.machine_config.runtime_version / "remote-agent" / "supervisor.py"
        old_fragment = str(PureWindowsPath(self.machine_config.remote_root) / "agent" / "versions").replace("'", "''")
        runtime_text = str(runtime).replace("'", "''")
        pythonw_text = str(self._require_remote_supervisor_pythonw()).replace("'", "''")
        config_text = str(self.supervisor_config_path).replace("'", "''")
        from .supervisor_paths import LOCATION_KEY, MANAGED_LOCATION
        managed = (self.machine_config.execution_provenance.get(LOCATION_KEY) == MANAGED_LOCATION
                   and bool(self.machine_config.root_uuid))
        preflight_script = ""
        managed_process_check = ""
        if self.machine_config.supervisor_startup == "logon" and managed:
            previous = str(current.get("runtime_version") or "")
            if (not re.fullmatch(r"[0-9a-f]{24}", previous)
                    or not isinstance(current.get("active_run_ids"), list) or current["active_run_ids"]):
                raise RuntimeError("managed supervisor update requires its exact idle previous runtime")
            previous_script = str(PureWindowsPath(self.machine_config.remote_root) / "agent" / "versions"
                                  / previous / "remote-agent" / "supervisor.py").replace("'", "''")
            root_text = str(PureWindowsPath(self.machine_config.remote_root)).replace("'", "''")
            task_name = self.supervisor_task_name.replace("'", "''")
            account = self.machine_config.ssh_user.replace("'", "''")
            # Validate ownership/action before stopping even the old supervisor.
            # Password-logon dedicated tasks retain their existing stored
            # credential; no account/password/principal is passed to Set.
            preflight_script = f"""
$ErrorActionPreference='Stop'
$taskName='{task_name}'
$managedTask=Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
if (-not $managedTask -or @($managedTask.Actions).Count -ne 1) {{ throw 'Managed supervisor task missing or ambiguous' }}
$expectedSid=([Security.Principal.NTAccount]::new('{account}')).Translate([Security.Principal.SecurityIdentifier]).Value
$principalUser=[string]$managedTask.Principal.UserId
$principalSid=if($principalUser -like 'S-1-*'){{$principalUser}}else{{([Security.Principal.NTAccount]::new($principalUser)).Translate([Security.Principal.SecurityIdentifier]).Value}}
if ($principalSid -cne $expectedSid -or [string]$managedTask.Principal.LogonType -notin @('Password','Interactive','InteractiveToken') -or [string]$managedTask.Principal.RunLevel -notin @('Limited','LeastPrivilege')) {{ throw 'Managed supervisor principal changed' }}
$oldRuntime='{previous_script}';$managedConfig='{config_text}';$managedRoot='{root_text}';$managedPythonw='{pythonw_text}'
$oldArgs=@(('"'+$oldRuntime+'" --config "'+$managedConfig+'" run'),('-B "'+$oldRuntime+'" --config "'+$managedConfig+'" run'))
$oldAction=$managedTask.Actions[0]
if ([IO.Path]::GetFullPath([string]$oldAction.Execute) -ine [IO.Path]::GetFullPath($managedPythonw) -or [string]$oldAction.Arguments -cnotin $oldArgs -or [IO.Path]::GetFullPath([string]$oldAction.WorkingDirectory).TrimEnd('\\') -ine $managedRoot.TrimEnd('\\')) {{ throw 'Managed supervisor action changed' }}
$oldCommands=@();foreach($a in $oldArgs){{$oldCommands+=('"'+$managedPythonw+'" '+$a);$oldCommands+=($managedPythonw+' '+$a)}}
$managedProcessBinding=$null
if ({old_pid} -gt 0) {{
 $ownedProcess=Get-CimInstance Win32_Process -Filter 'ProcessId={old_pid}' -ErrorAction SilentlyContinue
 if ($ownedProcess) {{
  $processOwner=Invoke-CimMethod -InputObject $ownedProcess -MethodName GetOwnerSid -ErrorAction Stop
  if ($processOwner.ReturnValue -ne 0 -or $processOwner.Sid -cne $expectedSid -or [IO.Path]::GetFullPath([string]$ownedProcess.ExecutablePath) -ine [IO.Path]::GetFullPath($managedPythonw) -or [string]$ownedProcess.CommandLine -cnotin $oldCommands) {{ throw 'Managed supervisor process ownership changed' }}
  $managedProcessBinding=@{{exe=[string]$ownedProcess.ExecutablePath;command=[string]$ownedProcess.CommandLine;birth=$ownedProcess.CreationDate.ToUniversalTime().ToString('o')}}
 }}
}}
$beforeTaskXml=[xml](Export-ScheduledTask -TaskName $taskName -ErrorAction Stop)
$savedPrincipal=$beforeTaskXml.Task.Principals.OuterXml;$savedTriggers=$beforeTaskXml.Task.Triggers.OuterXml;$savedSettings=$beforeTaskXml.Task.Settings.OuterXml
"""
            managed_process_check = """
    if ($null -eq $managedProcessBinding -or [string]$process.ExecutablePath -cne $managedProcessBinding.exe -or [string]$process.CommandLine -cne $managedProcessBinding.command -or $process.CreationDate.ToUniversalTime().ToString('o') -cne $managedProcessBinding.birth) { throw 'Managed supervisor PID identity changed before stop' }
"""
            launch_script = f"""
Stop-ScheduledTask -TaskName $taskName -ErrorAction Stop
$deadline=(Get-Date).AddSeconds(20)
do {{
 Start-Sleep -Milliseconds 250
 $managedTask=Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
}} while ($managedTask.State -eq 'Running' -and (Get-Date) -lt $deadline)
if ($managedTask.State -eq 'Running') {{ exit 74 }}
$arguments='-B "{runtime_text}" --config "{config_text}" run'
$action=New-ScheduledTaskAction -Execute '{pythonw_text}' -Argument $arguments -WorkingDirectory '{root_text}'
Set-ScheduledTask -TaskName $taskName -Action $action -ErrorAction Stop | Out-Null
$afterTaskXml=[xml](Export-ScheduledTask -TaskName $taskName -ErrorAction Stop)
$updatedTask=Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
if ($afterTaskXml.Task.Principals.OuterXml -cne $savedPrincipal -or $afterTaskXml.Task.Triggers.OuterXml -cne $savedTriggers -or $afterTaskXml.Task.Settings.OuterXml -cne $savedSettings -or @($updatedTask.Actions).Count -ne 1 -or [string]$updatedTask.Actions[0].Execute -ine '{pythonw_text}' -or [string]$updatedTask.Actions[0].Arguments -cne $arguments -or [string]$updatedTask.Actions[0].WorkingDirectory -ine '{root_text}') {{ throw 'Managed supervisor task readback changed' }}
Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
[PSCustomObject]@{{launch='scheduled_task';task_name=$taskName;runtime='{runtime_text}';existing_principal_triggers_settings_preserved=$true}} | ConvertTo-Json -Compress
"""
        elif self.machine_config.supervisor_startup == "logon":
            launch_script = f"""
$taskName='{self.supervisor_task_name}'
$user=[System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$existingTask=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existingTask) {{
  Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
  $deadline=(Get-Date).AddSeconds(20)
  do {{
    Start-Sleep -Milliseconds 250
    $existingTask=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
  }} while ($existingTask -and $existingTask.State -eq 'Running' -and (Get-Date) -lt $deadline)
  if ($existingTask -and $existingTask.State -eq 'Running') {{ exit 74 }}
}}
$arguments='-B "{runtime_text}" --config "{config_text}" run'
$action=New-ScheduledTaskAction -Execute '{pythonw_text}' -Argument $arguments -WorkingDirectory '{self.machine_config.remote_root}'
$logonTrigger=New-ScheduledTaskTrigger -AtLogOn -User $user
$watchdogTrigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes({SUPERVISOR_WATCHDOG_INTERVAL_MINUTES}) -RepetitionInterval (New-TimeSpan -Minutes {SUPERVISOR_WATCHDOG_INTERVAL_MINUTES})
$principal=New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
$settings={SUPERVISOR_TASK_SETTINGS}
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger @($logonTrigger,$watchdogTrigger) -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $taskName
[PSCustomObject]@{{launch='scheduled_task';task_name=$taskName;runtime='{runtime_text}'}} | ConvertTo-Json -Compress
"""
        else:
            command_line = f'"{pythonw_text}" -B "{runtime_text}" --config "{config_text}" run'.replace("'", "''")
            launch_script = f"""
$created=Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{{CommandLine='{command_line}'}}
if ($created.ReturnValue -ne 0) {{ exit 73 }}
[PSCustomObject]@{{launch='manual_process';pid=$created.ProcessId;runtime='{runtime_text}'}} | ConvertTo-Json -Compress
"""
        script = f"""
{preflight_script}
$ErrorActionPreference='Stop'
$oldPid={old_pid}
if ($oldPid -gt 0) {{
  $process=Get-CimInstance Win32_Process -Filter "ProcessId=$oldPid" -ErrorAction SilentlyContinue
  if ($process) {{
{managed_process_check}
    if ($process.CommandLine -notlike '*{old_fragment}*remote-agent*supervisor.py*') {{ exit 72 }}
    Stop-Process -Id $oldPid -Force -ErrorAction Stop
    Wait-Process -Id $oldPid -Timeout 20 -ErrorAction SilentlyContinue
  }}
}}
{launch_script}
"""
        completed = self.transport._powershell(script, timeout=60)
        self.transport._require_success(completed, "restart exact supervisor")
        evidence = next(
            json.loads(line.strip())
            for line in completed.stdout.splitlines()
            if line.strip().startswith("{") and line.strip().endswith("}")
        )
        deadline = time.monotonic() + 60
        status = {}
        while time.monotonic() < deadline:
            time.sleep(2)
            status = self.supervisor_status()
            if (
                status.get("running")
                and status.get("runtime_version") == self.machine_config.runtime_version
                and int(status.get("pid", 0) or 0) != old_pid
                and status.get("updated_at") != old_updated_at
            ):
                break
        if not (
            status.get("running")
            and status.get("runtime_version") == self.machine_config.runtime_version
            and int(status.get("pid", 0) or 0) != old_pid
            and status.get("updated_at") != old_updated_at
        ):
            raise RuntimeError("restarted supervisor did not publish a fresh running process")
        self.service._event(
            "machine.supervisor_runtime_restarted",
            actor_id,
            "machine",
            self.machine_config.machine_id,
            old_pid=old_pid,
            new_pid=status.get("pid"),
            runtime_version=self.machine_config.runtime_version,
        )
        return {"old_pid": old_pid, "start": evidence, "supervisor": status}

    def promote_running_runtime(self, *, actor_id: str = "admin") -> dict:
        """Promote only a verified sealed runtime on an accepted live machine."""
        formal = self.service.repository.get_machine_execution_config(
            self.machine_config.machine_id
        )
        if formal is None or not formal.enabled:
            raise RuntimeError("runtime promotion requires an enabled accepted machine")
        status = self.supervisor_status()
        if not status.get("running") or status.get("active_run_ids"):
            raise RuntimeError("runtime promotion requires an idle live supervisor")
        if status.get("runtime_version") != STABLE_RUNTIME_VERSION:
            raise RuntimeError("running supervisor does not match the stable runtime fingerprint")
        startup = self.supervisor_startup_status()
        expected = str(
            PureWindowsPath(formal.remote_root)
            / "agent"
            / "versions"
            / STABLE_RUNTIME_VERSION
            / "remote-agent"
            / "supervisor.py"
        ).lower()
        if (
            not startup.get("installed")
            or startup.get("state") != "Running"
            or expected not in str(startup.get("arguments", "")).lower()
        ):
            raise RuntimeError("fixed startup task does not reference the running stable runtime")
        provenance = dict(formal.execution_provenance)
        provenance["previous_runtime_version"] = str(formal.runtime_version or "")
        promoted = formal.model_copy(
            deep=True,
            update={
                "runtime_version": STABLE_RUNTIME_VERSION,
                "execution_provenance": provenance,
            },
        )
        self.service.put_machine_execution_config(promoted, actor_id=actor_id)
        self.machine_config = promoted
        self.service._event(
            "machine.runtime_promoted",
            actor_id,
            "machine",
            promoted.machine_id,
            previous_runtime_version=formal.runtime_version,
            runtime_version=STABLE_RUNTIME_VERSION,
            supervisor_pid=status.get("pid"),
        )
        return {
            "machine_id": promoted.machine_id,
            "previous_runtime_version": formal.runtime_version,
            "runtime_version": promoted.runtime_version,
            "supervisor_pid": status.get("pid"),
            "max_concurrent_units": promoted.max_concurrent_units,
        }

    def runtime_control_snapshot(self, action: str) -> dict:
        """Return sanitized, read-only evidence for runtime preview/confirm."""
        if action not in {"promote_runtime", "rollback_runtime"}:
            raise ValueError("unsupported runtime control action")
        formal = self.service.repository.get_machine_execution_config(
            self.machine_config.machine_id
        )
        if formal is None or not formal.enabled:
            raise RuntimeError("runtime control requires an enabled accepted machine")
        status = self.supervisor_status()
        startup = self.supervisor_startup_status()
        running_version = str(status.get("runtime_version") or "")
        if not status.get("running") or not running_version:
            raise RuntimeError("runtime control requires a live versioned supervisor")
        if status.get("active_run_ids"):
            raise RuntimeError("runtime control requires an idle supervisor")
        target_version = (
            running_version
            if action == "promote_runtime"
            else str(formal.execution_provenance.get("previous_runtime_version") or "")
        )
        target_available = False
        if target_version:
            marker = (
                PureWindowsPath(formal.remote_root)
                / "agent"
                / "versions"
                / target_version
                / "runtime-manifest.json"
            )
            supervisor = marker.parent / "remote-agent" / "supervisor.py"
            checked = self.transport._powershell(
                f"if ((Test-Path -LiteralPath '{marker}') -and "
                f"(Test-Path -LiteralPath '{supervisor}')) {{ exit 0 }} else {{ exit 44 }}"
            )
            target_available = checked.returncode == 0
        snapshot = {
            "machine_id": formal.machine_id,
            "running_runtime_version": running_version,
            "formal_runtime_version": str(formal.runtime_version or ""),
            "target_runtime_version": target_version,
            "target_runtime_available": target_available,
            "active_run_ids": sorted(status.get("active_run_ids") or []),
            "supervisor_instance_fingerprint": sha256_value({
                "pid": int(status.get("pid", 0) or 0),
                "started_at": status.get("started_at"),
                "runtime_version": running_version,
            }),
            "startup_fingerprint": sha256_value({
                "installed": bool(startup.get("installed")),
                "state": startup.get("state"),
                "execute": startup.get("execute"),
                "arguments": startup.get("arguments"),
                "working_directory": startup.get("working_directory"),
            }),
        }
        if action == "promote_runtime":
            if running_version == formal.runtime_version:
                raise RuntimeError("no running candidate runtime is available for promotion")
            if running_version != STABLE_RUNTIME_VERSION or not target_available:
                raise RuntimeError("running candidate does not match the sealed stable runtime")
        else:
            if not target_version or target_version == running_version:
                raise RuntimeError("no previous runtime is available for rollback")
            if formal.runtime_version != running_version:
                raise RuntimeError("rollback requires the formal and running runtime to match")
            if not target_available:
                raise RuntimeError("previous sealed runtime is unavailable on the machine")
        return snapshot

    def rollback_running_runtime(
        self,
        target_runtime_version: str,
        *,
        actor_id: str = "admin",
    ) -> dict:
        """Rollback an idle supervisor to one previously sealed runtime."""
        formal = self.service.repository.get_machine_execution_config(
            self.machine_config.machine_id
        )
        if formal is None or not formal.enabled:
            raise RuntimeError("runtime rollback requires an enabled accepted machine")
        snapshot = self.runtime_control_snapshot("rollback_runtime")
        if target_runtime_version != snapshot["target_runtime_version"]:
            raise RuntimeError("rollback target changed after preview")
        provenance = dict(formal.execution_provenance)
        provenance["previous_runtime_version"] = str(formal.runtime_version or "")
        rolled_back = formal.model_copy(
            deep=True,
            update={
                "runtime_version": target_runtime_version,
                "execution_provenance": provenance,
            },
        )
        control_dir = self.state_root / "runtime-control"
        control_dir.mkdir(parents=True, exist_ok=True)

        def upload(config: MachineExecutionConfig, suffix: str) -> None:
            local = control_dir / f"{config.machine_id}-{uuid4().hex}-{suffix}.json"
            local.write_text(
                json.dumps(config.model_dump(mode="json"), indent=2),
                encoding="utf-8",
            )
            self.transport.upload_supervisor_config(local, self.supervisor_config_path)

        upload(rolled_back, "rollback")
        self.machine_config = rolled_back
        self._lock_managed_python_workbench_path(target_runtime_version)
        try:
            evidence = self.restart_supervisor(actor_id=actor_id)
        except Exception:
            upload(formal, "recovery")
            self.machine_config = formal
            self._lock_managed_python_workbench_path(str(formal.runtime_version or ""))
            try:
                self.restart_supervisor(actor_id=f"{actor_id}-rollback-recovery")
            except Exception:
                pass
            raise
        self.service.put_machine_execution_config(rolled_back, actor_id=actor_id)
        self.service._event(
            "machine.runtime_rolled_back",
            actor_id,
            "machine",
            rolled_back.machine_id,
            previous_runtime_version=formal.runtime_version,
            runtime_version=target_runtime_version,
        )
        return {
            "machine_id": rolled_back.machine_id,
            "previous_runtime_version": formal.runtime_version,
            "runtime_version": target_runtime_version,
            "restart_completed": bool(evidence.get("supervisor")),
        }

    def enable_after_acceptance(self, run: SshAcceptanceRun, *, actor_id: str) -> dict:
        self._refresh_status(run)
        if run.status != AcceptanceStatus.PASSED:
            raise RuntimeError("SSH production execution requires a passed acceptance run")
        old_status = self.supervisor_status()
        if old_status.get("active_run_ids"):
            raise RuntimeError("cannot upgrade the supervisor while work units are active")
        old_pid = int(old_status.get("pid", 0) or 0)
        deployment = self.deploy(run, actor_id=actor_id)
        pythonw_text = str(self._require_remote_supervisor_pythonw()).replace("'", "''")
        self.machine_config.max_concurrent_units = self.machine_config.target_concurrent_units
        self.machine_config.enabled = True
        self.machine_config.supervisor_startup = "logon"
        local_config = self.state_root / run.run_id / "machine-enabled.json"
        local_config.write_text(
            json.dumps(self.machine_config.model_dump(mode="json"), indent=2),
            encoding="utf-8",
        )
        supervisor_config = self.supervisor_config_path
        self.transport.upload_supervisor_config(local_config, supervisor_config)
        runtime = (
            PureWindowsPath(self.machine_config.remote_root)
            / "agent"
            / "versions"
            / str(self.machine_config.runtime_version)
            / "remote-agent"
            / "supervisor.py"
        )
        task_name = f"ResearchComputeNetwork-{self.machine_config.machine_id}"
        arguments = f'"{runtime}" --config "{supervisor_config}" run'
        escaped_arguments = arguments.replace("'", "''")
        expected_command_fragment = str(runtime).replace("'", "''")
        stop_script = f"""
$ErrorActionPreference='Stop'
$taskName='{task_name}'
$oldPid={old_pid}
$existing=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existing) {{ Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue }}
if ($oldPid -gt 0) {{
  $process=Get-CimInstance Win32_Process -Filter "ProcessId=$oldPid" -ErrorAction SilentlyContinue
  if ($process) {{
    if ($process.CommandLine -notlike '*{expected_command_fragment}*' -and $process.CommandLine -notlike '*ResearchComputeNetwork*remote-agent*supervisor.py*') {{ exit 72 }}
    Stop-Process -Id $oldPid -Force -ErrorAction Stop
    Wait-Process -Id $oldPid -Timeout 20 -ErrorAction SilentlyContinue
  }}
}}
"""
        stopped = self.transport._powershell(stop_script, timeout=60)
        self.transport._require_success(stopped, "stop exact previous supervisor")
        script = f"""
$ErrorActionPreference='Stop'
$taskName='{task_name}'
$user=[System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$action=New-ScheduledTaskAction -Execute '{pythonw_text}' -Argument '{escaped_arguments}' -WorkingDirectory '{self.machine_config.remote_root}'
$logonTrigger=New-ScheduledTaskTrigger -AtLogOn -User $user
$watchdogTrigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes({SUPERVISOR_WATCHDOG_INTERVAL_MINUTES}) -RepetitionInterval (New-TimeSpan -Minutes {SUPERVISOR_WATCHDOG_INTERVAL_MINUTES})
$principal=New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
$settings={SUPERVISOR_TASK_SETTINGS}
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger @($logonTrigger,$watchdogTrigger) -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $taskName
$task=Get-ScheduledTask -TaskName $taskName
[PSCustomObject]@{{task_name=$task.TaskName;state=$task.State.ToString();user=$user;logon_type=$task.Principal.LogonType.ToString()}} | ConvertTo-Json -Compress
"""
        completed = self.transport._powershell(script, timeout=120)
        self.transport._require_success(completed, "register supervisor logon task")
        task_evidence = next(
            json.loads(line.strip())
            for line in completed.stdout.splitlines()
            if line.strip().startswith("{") and line.strip().endswith("}")
        )
        supervisor_evidence = None
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            time.sleep(2)
            candidate = self.supervisor_status()
            if (
                candidate.get("running")
                and int(candidate.get("schema_version", 0)) >= 2
                and candidate.get("runtime_version") == self.machine_config.runtime_version
                and int(candidate.get("pid", 0)) != old_pid
            ):
                supervisor_evidence = candidate
                break
        if supervisor_evidence is None:
            raise RuntimeError("new supervisor did not publish its versioned heartbeat within 60 seconds")
        self.service.put_machine_execution_config(self.machine_config, actor_id=actor_id)
        self.service._event(
            "machine.supervisor_startup_configured",
            actor_id,
            "machine",
            self.machine_config.machine_id,
            startup="logon",
            task_name=task_name,
            runtime_version=self.machine_config.runtime_version,
        )
        return {
            "enabled": True,
            "max_concurrent_units": self.machine_config.max_concurrent_units,
            "runtime_version": deployment["runtime_version"],
            "scheduled_task": task_evidence,
            "supervisor": supervisor_evidence,
        }

    def install_supervisor_startup(self, run: SshAcceptanceRun, *, actor_id: str) -> dict:
        """Install the fixed logon task without opening production scheduling."""
        self._refresh_status(run)
        if run.status != AcceptanceStatus.PASSED:
            raise RuntimeError("supervisor startup requires a passed operational acceptance run")
        old_status = self.supervisor_status()
        if old_status.get("active_run_ids"):
            raise RuntimeError("cannot replace supervisor startup while work units are active")
        old_pid = int(old_status.get("pid", 0) or 0)
        config = self.machine_config.model_copy(
            update={"supervisor_startup": "logon"},
        )
        pythonw_text = str(
            self._require_remote_supervisor_pythonw(config.python_executable)
        ).replace("'", "''")
        local_config = self.state_root / run.run_id / "machine-startup.json"
        local_config.parent.mkdir(parents=True, exist_ok=True)
        local_config.write_text(
            json.dumps(config.model_dump(mode="json"), indent=2),
            encoding="utf-8",
        )
        self.transport.upload_supervisor_config(local_config, self.supervisor_config_path)
        runtime = (
            PureWindowsPath(config.remote_root)
            / "agent"
            / "versions"
            / str(config.runtime_version)
            / "remote-agent"
            / "supervisor.py"
        )
        task_name = f"ResearchComputeNetwork-{config.machine_id}"
        arguments = f'"{runtime}" --config "{self.supervisor_config_path}" run'
        escaped_arguments = arguments.replace("'", "''")
        expected_command_fragment = str(runtime).replace("'", "''")
        script = f"""
$ErrorActionPreference='Stop'
$taskName='{task_name}'
$oldPid={old_pid}
$action=New-ScheduledTaskAction -Execute '{pythonw_text}' -Argument '{escaped_arguments}' -WorkingDirectory '{config.remote_root}'
$logonTrigger=New-ScheduledTaskTrigger -AtLogOn -User ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
$watchdogTrigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes({SUPERVISOR_WATCHDOG_INTERVAL_MINUTES}) -RepetitionInterval (New-TimeSpan -Minutes {SUPERVISOR_WATCHDOG_INTERVAL_MINUTES})
$user=[System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$principal=New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
$settings={SUPERVISOR_TASK_SETTINGS}
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger @($logonTrigger,$watchdogTrigger) -Principal $principal -Settings $settings -Force | Out-Null
if ($oldPid -gt 0) {{
  $process=Get-CimInstance Win32_Process -Filter "ProcessId=$oldPid" -ErrorAction SilentlyContinue
  if ($process) {{
    if ($process.CommandLine -notlike '*{expected_command_fragment}*' -and $process.CommandLine -notlike '*ResearchComputeNetwork*remote-agent*supervisor.py*') {{ exit 72 }}
    Stop-Process -Id $oldPid -Force -ErrorAction Stop
    Wait-Process -Id $oldPid -Timeout 20 -ErrorAction SilentlyContinue
  }}
}}
Start-ScheduledTask -TaskName $taskName
$task=Get-ScheduledTask -TaskName $taskName
[PSCustomObject]@{{
  task_name=$task.TaskName
  state=$task.State.ToString()
  user=$task.Principal.UserId
  logon_type=$task.Principal.LogonType.ToString()
  triggers=@($task.Triggers).Count
  execute=$task.Actions[0].Execute
  arguments=$task.Actions[0].Arguments
  restart_count=$task.Settings.RestartCount
  restart_interval=$task.Settings.RestartInterval
  restart_interval_seconds=[int]$task.Settings.RestartInterval.TotalSeconds
  restart_policy_healthy=([int]$task.Settings.RestartCount -ge {SUPERVISOR_RESTART_COUNT} -and [int]$task.Settings.RestartInterval.TotalSeconds -le {SUPERVISOR_RESTART_INTERVAL_MINUTES * 60})
  multiple_instances=$task.Settings.MultipleInstances.ToString()
}} | ConvertTo-Json -Compress
"""
        completed = self.transport._powershell(script, timeout=120)
        self.transport._require_success(completed, "register supervisor logon task")
        task_evidence = next(
            json.loads(line.strip())
            for line in completed.stdout.splitlines()
            if line.strip().startswith("{") and line.strip().endswith("}")
        )
        replacement = None
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            time.sleep(2)
            candidate = self.supervisor_status()
            if (
                candidate.get("running")
                and candidate.get("runtime_version") == config.runtime_version
                and int(candidate.get("pid", 0) or 0) != old_pid
            ):
                replacement = candidate
                break
        if replacement is None:
            raise RuntimeError("scheduled supervisor did not publish a replacement heartbeat")
        repeated = self.transport._powershell(
            f"Start-ScheduledTask -TaskName '{task_name}'; Start-Sleep -Seconds 3",
            timeout=20,
        )
        self.transport._require_success(repeated, "repeat supervisor task start")
        repeated_status = self.supervisor_status()
        if int(repeated_status.get("pid", 0) or 0) != int(replacement.get("pid", 0) or 0):
            raise RuntimeError("repeated task start created a second supervisor")
        self.machine_config = config
        self.service.put_machine_execution_config(config, actor_id=actor_id)
        self.service._event(
            "machine.supervisor_startup_configured",
            actor_id,
            "machine",
            config.machine_id,
            startup="logon",
            task_name=task_name,
            duplicate_start_guard=True,
            production_enabled=config.enabled,
        )
        return {
            "machine_id": config.machine_id,
            "production_enabled": config.enabled,
            "scheduled_task": task_evidence,
            "supervisor": repeated_status,
            "duplicate_start_guard": True,
        }

    def _acceptance_template_path(self, project_yaml: Path) -> Path:
        if self.acceptance_inputs is not None:
            return self.acceptance_inputs.template
        return self.resolve_template_path(project_yaml)

    def _acceptance_references(self) -> dict[str, Path]:
        if self.acceptance_inputs is not None:
            return self.acceptance_inputs.references
        from .member_release_catalog import RuntimeNotConfigured
        raise RuntimeNotConfigured()

    def verify_installed_runtime(self, run: SshAcceptanceRun, *, actor_id: str) -> dict:
        """Verify the installed sealed version and stage only the fixed template cache."""
        from .ssh_acceptance_inputs import PackagedAcceptanceInputs
        inputs = self.acceptance_inputs or PackagedAcceptanceInputs(self.project_root)
        if run.worker_id != self.machine_config.machine_id or run.remote_root != self.machine_config.remote_root:
            raise ValueError("acceptance run does not match the configured machine/root")
        try:
            evidence = inputs.verify_runtime(self.machine_config, self.transport)
            live = self.supervisor_status()
            if (not live.get("running") or live.get("machine_id") != self.machine_config.machine_id
                    or live.get("root_uuid") != self.machine_config.root_uuid
                    or live.get("runtime_version") != self.machine_config.runtime_version
                    or live.get("active_run_ids")):
                raise RuntimeError("installed supervisor must be live, correctly bound and idle for acceptance")
            template = inputs.template
            template_hash = sha256_file(template)
            self.transport.upload_cache_object(template, template_hash)
        except Exception:
            self._check(run, "runtime_deployed", "Existing sealed runtime and fixed template",
                AcceptanceStatus.FAILED, "installed runtime verification or template staging failed",
                actor_id=actor_id, evidence={"runtime_changed": False, "supervisor_restarted": False})
            raise
        evidence = {**evidence, "template_sha256": template_hash,
                    "runtime_changed": False, "supervisor_restarted": False}
        self._check(run, "runtime_deployed", "Existing sealed runtime and fixed template",
            AcceptanceStatus.PASSED, "existing sealed bytes verified; fixed template cache available",
            actor_id=actor_id, evidence=evidence)
        return evidence

    def build_acceptance_job(self, run: SshAcceptanceRun, concurrency: int, attempt: int):
        if self.acceptance_inputs is not None:
            return self.acceptance_inputs.build_job(run, self.machine_config,
                self.service.repository.get_policy(self.machine_config.machine_id),
                self.service.repository.get_machine(self.machine_config.machine_id), concurrency, attempt)
        from .member_release_catalog import RuntimeNotConfigured
        raise RuntimeNotConfigured()

    @staticmethod
    def resolve_template_path(project_yaml: Path) -> Path:
        import yaml

        project_config = yaml.safe_load(project_yaml.read_text(encoding="utf-8"))
        template_value = project_config.get("comsol", {}).get("template_mph")
        if not template_value:
            raise FileNotFoundError("COMSOL template is unavailable")
        template = (project_yaml.parent / template_value).resolve()
        if not template.is_file():
            raise FileNotFoundError("COMSOL template is unavailable")
        return template

    def _upload_machine_config_snapshot(
        self,
        run: SshAcceptanceRun,
        config: MachineExecutionConfig,
        filename: str,
    ) -> None:
        local_config = self.state_root / run.run_id / filename
        local_config.parent.mkdir(parents=True, exist_ok=True)
        local_config.write_text(
            json.dumps(config.model_dump(mode="json"), indent=2),
            encoding="utf-8",
        )
        self.transport.upload_supervisor_config(local_config, self.supervisor_config_path)

    def _config_for_running_runtime(self) -> MachineExecutionConfig:
        status = self.supervisor_status()
        runtime_version = str(status.get("runtime_version") or "")
        if not status.get("running") or not runtime_version:
            raise RuntimeError("a live versioned supervisor is required")
        return self.machine_config.model_copy(
            deep=True,
            update={"runtime_version": runtime_version},
        )

    @staticmethod
    def _authorize_concurrency_extension(run: SshAcceptanceRun, concurrency: int) -> bool:
        if concurrency in run.concurrency_levels:
            return False
        highest = max(run.concurrency_levels, default=0)
        if run.status != AcceptanceStatus.PASSED or concurrency != highest + 1:
            raise ValueError(
                "acceptance concurrency must be an existing level or the next level of a passed run"
            )
        run.concurrency_levels.append(concurrency)
        run.concurrency_levels.sort()
        run.status = AcceptanceStatus.RUNNING
        return True

    @staticmethod
    def _solver_canary_approval_reference(
        run: SshAcceptanceRun,
        solver_variant: SolverVariant,
    ) -> str | None:
        if solver_variant != SolverVariant.CUDSS:
            return None
        return f"solver-canary-{run.run_id}"

    def build_safe_fake_job(self, run: SshAcceptanceRun) -> JobEnvelope:
        nonce = f"{run.run_id}-{uuid4().hex[:8]}"
        fingerprint = {
            "profile_id": SAFE_FAKE_TASK_V1.profile_id,
            "acceptance_run_id": run.run_id,
            "acceptance_nonce": nonce,
        }
        request_hash = sha256_value(fingerprint)
        return JobEnvelope(
            origin_submitter_id=f"ssh-safe-fake-{run.run_id}",
            user_id="admin",
            project_id="compute-network-pilot",
            execution_profile_id=SAFE_FAKE_TASK_V1.profile_id,
            request_hash=request_hash,
            work_units=[WorkUnit(
                work_unit_id=f"unit-{request_hash[:16]}-0000",
                ordinal=0,
                payload={"kind": "rcn_safe_fake_task", "acceptance_nonce": nonce},
                expected_duration_s=10,
                resources=ResourceRequest(cpus=1, memory_mb=256, disk_mb=16),
            )],
        )

    def run_safe_fake_task(
        self,
        run: SshAcceptanceRun,
        *,
        actor_id: str,
        timeout_s: float = 120,
    ) -> dict:
        """Validate staging, fixed execution, status and artifact collection."""
        if not self.machine_config.runtime_version:
            raise RuntimeError("runtime must be deployed before the safe fake task")
        job = self.build_safe_fake_job(run)
        unit = job.work_units[0]
        external = f"ssh-{self.machine_config.machine_id}-safe-{uuid4().hex[:12]}"
        assignment = Assignment(
            job_id=job.job_id,
            work_unit_id=unit.work_unit_id,
            machine_id=self.machine_config.machine_id,
            scheduler="ssh",
        )
        bundle = build_safe_fake_unit_bundle(
            job=job,
            assignment=assignment,
            external_run_id=external,
            config=self.machine_config,
            runtime_version=self.machine_config.runtime_version,
            output_zip=self.state_root / run.run_id / "safe-fake" / f"{external}.zip",
        )
        request = json.loads(zip_read(bundle, "request.json"))
        self.transport.stage_bundle(external, bundle)
        self.service.put_remote_run(
            RemoteRunRecord(
                external_run_id=external,
                machine_id=self.machine_config.machine_id,
                job_id=job.job_id,
                work_unit_id=unit.work_unit_id,
                request_hash=request["request_hash"],
                state=RemoteRunState.STAGED,
                remote_relative_path="",
            ),
            actor_id=actor_id,
        )
        run.external_run_ids.append(external)
        self._save(run, actor_id)

        deadline = time.monotonic() + timeout_s
        observed_states = []
        status = {}
        while time.monotonic() < deadline:
            status = self.transport.read_status(external)
            state = status.get("state", "staged")
            if not observed_states or observed_states[-1] != state:
                observed_states.append(state)
            if state in {"completed", "failed", "cancelled", "interrupted"}:
                break
            time.sleep(1)

        destination = self.state_root / run.run_id / "safe-fake" / "collected" / external
        result = {}
        artifact_manifest = {}
        if status.get("state") == "completed":
            self.transport.download_outputs(external, destination)
            result_paths = list(destination.rglob("safe-fake-result.json"))
            manifest_paths = list(destination.rglob("artifact-manifest.json"))
            if len(result_paths) == 1:
                result = json.loads(result_paths[0].read_text(encoding="utf-8"))
            if len(manifest_paths) == 1:
                artifact_manifest = json.loads(manifest_paths[0].read_text(encoding="utf-8"))
        result_files = {
            item.get("relative_path"): item.get("sha256")
            for item in artifact_manifest.get("files", [])
        }
        result_path = next(iter(destination.rglob("safe-fake-result.json")), None)
        passed = (
            status.get("state") == "completed"
            and result.get("profile_id") == SAFE_FAKE_TASK_V1.profile_id
            and result.get("acceptance_nonce") == unit.payload["acceptance_nonce"]
            and result.get("message") == "fixed safe fake task completed; no user command was executed"
            and result_path is not None
            and result_files.get("safe-fake-result.json") == sha256_file(result_path)
        )
        evidence = {
            "external_run_id": external,
            "observed_states": observed_states,
            "terminal_state": status.get("state"),
            "artifact_count": len(result_files),
            "result_hash_verified": bool(result_path) and result_files.get("safe-fake-result.json") == sha256_file(result_path),
            "fixed_profile": result.get("profile_id"),
        }
        self.service.put_remote_run(
            RemoteRunRecord(
                external_run_id=external,
                machine_id=status.get("machine_id", self.machine_config.machine_id),
                job_id=status.get("job_id", job.job_id),
                work_unit_id=status.get("work_unit_id", unit.work_unit_id),
                request_hash=status.get("request_hash", request["request_hash"]),
                state=RemoteRunState(status.get("state", "interrupted")),
                remote_relative_path=status.get("remote_relative_path", ""),
                progress_percent=status.get("progress_percent", 0),
                message=status.get("message", ""),
                artifacts_available=status.get("artifacts_available", False),
            ),
            actor_id=actor_id,
        )
        self._check(
            run,
            "safe_fake_task",
            "Fixed safe SSH task",
            AcceptanceStatus.PASSED if passed else AcceptanceStatus.FAILED,
            "sealed task ran and its artifact hash was verified" if passed else "safe fake task validation failed",
            actor_id=actor_id,
            evidence=evidence,
        )
        if not passed:
            raise RuntimeError("safe fake task validation failed")
        return evidence

    def run_project_worker_task(
        self,
        run: SshAcceptanceRun,
        *,
        actor_id: str,
        timeout_s: float = 120,
    ) -> dict:
        """Execute the fixed project-worker smoke task without a remote shell."""
        if not self.machine_config.runtime_version:
            raise RuntimeError("runtime must be deployed before the project worker task")
        nonce = f"{run.run_id}-{uuid4().hex[:8]}"
        request_hash = sha256_value({
            "profile_id": PROJECT_WORKER_V1.profile_id,
            "acceptance_run_id": run.run_id,
            "acceptance_nonce": nonce,
        })
        unit = WorkUnit(
            work_unit_id=f"unit-{request_hash[:16]}-0000",
            ordinal=0,
            payload={
                "kind": PROJECT_WORKER_V1.profile_id,
                "entrypoint": "project_worker_smoke.py",
            },
            expected_duration_s=30,
            resources=ResourceRequest(cpus=1, memory_mb=256, disk_mb=16),
        )
        job = JobEnvelope(
            origin_submitter_id=f"ssh-project-worker-{run.run_id}",
            user_id="admin",
            project_id="compute-network-pilot",
            execution_profile_id=PROJECT_WORKER_V1.profile_id,
            request_hash=request_hash,
            work_units=[unit],
        )
        external = f"ssh-{self.machine_config.machine_id}-project-{uuid4().hex[:12]}"
        assignment = Assignment(
            job_id=job.job_id,
            work_unit_id=unit.work_unit_id,
            machine_id=self.machine_config.machine_id,
            scheduler="ssh",
        )
        bundle = build_project_worker_unit_bundle(
            project_root=PACKAGE_ACCEPTANCE_FIXTURES,
            entrypoint="project_worker_smoke.py",
            project_files=[],
            arguments={"acceptance_nonce": nonce, "value": 7},
            job=job,
            assignment=assignment,
            external_run_id=external,
            config=self.machine_config,
            runtime_version=self.machine_config.runtime_version,
            output_zip=self.state_root / run.run_id / "project-worker" / f"{external}.zip",
        )
        request = json.loads(zip_read(bundle, "request.json"))
        self.transport.stage_bundle(external, bundle)
        self.service.put_remote_run(
            RemoteRunRecord(
                external_run_id=external,
                machine_id=self.machine_config.machine_id,
                job_id=job.job_id,
                work_unit_id=unit.work_unit_id,
                request_hash=request["request_hash"],
                state=RemoteRunState.STAGED,
                remote_relative_path="",
            ),
            actor_id=actor_id,
        )
        run.external_run_ids.append(external)
        self._save(run, actor_id)

        deadline = time.monotonic() + timeout_s
        observed_states = []
        status = {}
        while time.monotonic() < deadline:
            status = self.transport.read_status(external)
            state = status.get("state", "staged")
            if not observed_states or observed_states[-1] != state:
                observed_states.append(state)
            if state in {"completed", "failed", "cancelled", "interrupted"}:
                break
            time.sleep(1)

        destination = self.state_root / run.run_id / "project-worker" / "collected" / external
        result = {}
        manifest = {}
        result_path = None
        if status.get("state") == "completed":
            self.transport.download_outputs(external, destination)
            result_path = next(iter(destination.rglob("result.json")), None)
            manifest_path = next(iter(destination.rglob("project-worker-manifest.json")), None)
            if result_path is not None:
                result = json.loads(result_path.read_text(encoding="utf-8"))
            if manifest_path is not None:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        file_hashes = {
            item.get("relative_path"): item.get("sha256")
            for item in manifest.get("files", [])
        }
        hash_verified = (
            result_path is not None
            and file_hashes.get("result.json") == sha256_file(result_path)
        )
        passed = (
            status.get("state") == "completed"
            and result.get("acceptance_nonce") == nonce
            and result.get("value") == 7
            and result.get("message") == "project worker executed without a shell"
            and hash_verified
        )
        evidence = {
            "external_run_id": external,
            "observed_states": observed_states,
            "terminal_state": status.get("state"),
            "runtime_version": self.machine_config.runtime_version,
            "artifact_count": len(file_hashes),
            "result_hash_verified": hash_verified,
            "fixed_profile": PROJECT_WORKER_V1.profile_id,
        }
        self.service.put_remote_run(
            RemoteRunRecord(
                external_run_id=external,
                machine_id=status.get("machine_id", self.machine_config.machine_id),
                job_id=status.get("job_id", job.job_id),
                work_unit_id=status.get("work_unit_id", unit.work_unit_id),
                request_hash=status.get("request_hash", request["request_hash"]),
                state=RemoteRunState(status.get("state", "interrupted")),
                remote_relative_path=status.get("remote_relative_path", ""),
                progress_percent=status.get("progress_percent", 0),
                message=status.get("message", ""),
                artifacts_available=status.get("artifacts_available", False),
            ),
            actor_id=actor_id,
        )
        self._check(
            run,
            "project_worker_task",
            "Bounded project-worker execution",
            AcceptanceStatus.PASSED if passed else AcceptanceStatus.FAILED,
            "project worker executed and returned a hash-verified artifact"
            if passed
            else "project worker validation failed",
            actor_id=actor_id,
            evidence=evidence,
        )
        if not passed:
            raise RuntimeError("project worker validation failed")
        return evidence

    def submit_concurrency(
        self,
        run: SshAcceptanceRun,
        concurrency: int,
        *,
        solver_variant: SolverVariant = SolverVariant.MUMPS,
        actor_id: str,
    ) -> list[str]:
        extended = self._authorize_concurrency_extension(run, concurrency)
        if extended:
            self._save(run, actor_id)
        runtime_config = self._config_for_running_runtime()
        acceptance_config = runtime_config.model_copy(
            update={"max_concurrent_units": concurrency, "target_concurrent_units": concurrency,
                    "profile_concurrency_limits": {key: min(value, concurrency)
                        for key, value in runtime_config.profile_concurrency_limits.items()}}
        )
        restore_config = runtime_config.model_copy(
            update={
                "max_concurrent_units": self.machine_config.max_concurrent_units,
                "target_concurrent_units": self.machine_config.target_concurrent_units,
            }
        )
        self._upload_machine_config_snapshot(
            run,
            acceptance_config,
            f"machine-c{concurrency}.json",
        )
        self.service._event(
            "machine.acceptance_capacity_staged",
            actor_id,
            "machine",
            self.machine_config.machine_id,
            acceptance_concurrency=concurrency,
            production_concurrency=self.machine_config.max_concurrent_units,
        )
        attempt = 1 + len(run.external_run_ids) // 3
        project_yaml, scan_spec, job = self.build_acceptance_job(run, concurrency, attempt)
        canary_approval_reference = self._solver_canary_approval_reference(
            run,
            solver_variant,
        )
        if canary_approval_reference:
            job.solver_approval_id = canary_approval_reference
        external_ids = []
        bundle_dir = self.state_root / run.run_id / f"concurrency-{concurrency}" / "bundles"
        try:
            for unit in job.work_units:
                assignment = Assignment(
                    job_id=job.job_id,
                    work_unit_id=unit.work_unit_id,
                    machine_id=self.machine_config.machine_id,
                    scheduler="ssh",
                    solver_variant=solver_variant,
                )
                external = f"ssh-{self.machine_config.machine_id}-{unit.work_unit_id}"
                bundle = build_comsol_unit_bundle(
                    project_yaml=project_yaml,
                    scan_spec=scan_spec,
                    template_path=self._acceptance_template_path(project_yaml),
                    job=job,
                    assignment=assignment,
                    external_run_id=external,
                    config=acceptance_config,
                    runtime_version=runtime_config.runtime_version,
                    output_zip=bundle_dir / f"{external}.zip",
                )
                self.transport.stage_bundle(external, bundle)
                request = json.loads(zip_read(bundle, "request.json"))
                record = RemoteRunRecord(
                    external_run_id=external,
                    machine_id=self.machine_config.machine_id,
                    job_id=job.job_id,
                    work_unit_id=unit.work_unit_id,
                    request_hash=request["request_hash"],
                    state=RemoteRunState.STAGED,
                    remote_relative_path="",
                    solver_variant=solver_variant,
                )
                self.service.put_remote_run(record, actor_id=actor_id)
                run.external_run_ids.append(external)
                external_ids.append(external)
        except Exception:
            self._upload_machine_config_snapshot(
                run,
                restore_config,
                "machine-production-restored.json",
            )
            raise
        self._save(run, actor_id)
        self.service._event(
            "machine.solver_canary_submitted",
            actor_id,
            "machine",
            self.machine_config.machine_id,
            acceptance_run_id=run.run_id,
            solver_variant=solver_variant.value,
            solver_approval_reference=canary_approval_reference,
            concurrency=concurrency,
            external_run_ids=external_ids,
        )
        return external_ids

    def wait_and_collect(self, run: SshAcceptanceRun, concurrency: int, external_ids: list[str], *, actor_id: str, timeout_s: float = 7200) -> Path:
        runtime_config = self._config_for_running_runtime()
        restore_config = runtime_config.model_copy(
            update={
                "max_concurrent_units": self.machine_config.max_concurrent_units,
                "target_concurrent_units": self.machine_config.target_concurrent_units,
            }
        )

        def restore_production_capacity() -> None:
            self._upload_machine_config_snapshot(
                run,
                restore_config,
                "machine-production-restored.json",
            )

        deadline = time.monotonic() + timeout_s
        terminal = {RemoteRunState.COMPLETED, RemoteRunState.FAILED, RemoteRunState.CANCELLED, RemoteRunState.INTERRUPTED}
        records = {}
        read_errors = {}
        while time.monotonic() < deadline:
            for external in external_ids:
                try:
                    payload = self.transport.read_status(external)
                    read_errors.pop(external, None)
                except (OSError, RuntimeError, TimeoutExpired, json.JSONDecodeError, ValueError) as exc:
                    read_errors[external] = str(exc)[:500]
                    continue
                state = RemoteRunState(payload.get("state", "staged"))
                record = RemoteRunRecord(
                    external_run_id=external,
                    machine_id=payload.get("machine_id", self.machine_config.machine_id),
                    job_id=payload.get("job_id", "unknown"),
                    work_unit_id=payload.get("work_unit_id", "unknown"),
                    request_hash=payload.get("request_hash", "0" * 64),
                    state=state,
                    remote_relative_path=payload.get("remote_relative_path", ""),
                    progress_percent=payload.get("progress_percent", 0),
                    message=payload.get("message", ""),
                    artifacts_available=payload.get("artifacts_available", False),
                )
                records[external] = record
                self.service.put_remote_run(record, actor_id=actor_id)
            if len(records) == len(external_ids) and all(record.state in terminal for record in records.values()):
                break
            time.sleep(self.machine_config.poll_interval_s)
        if len(records) != len(external_ids) or any(record.state != RemoteRunState.COMPLETED for record in records.values()):
            restore_production_capacity()
            detail = f"; transient read errors: {read_errors}" if read_errors else ""
            raise RuntimeError("not all SSH COMSOL units completed successfully" + detail)
        try:
            collected = self.state_root / run.run_id / f"concurrency-{concurrency}" / "collected"
            roots = []
            for external in external_ids:
                destination = collected / external
                self.transport.download_outputs(external, destination)
                roots.append(destination)
            merged = self.state_root / run.run_id / f"concurrency-{concurrency}" / "merged"
            _, candidate_manifest = merge_chunk_outputs(roots, merged)
            comparisons = {label: compare_three_point_manifests(reference, candidate_manifest)
                           for label, reference in self._acceptance_references().items()}
        except Exception:
            restore_production_capacity()
            raise
        passed = all(result["passed"] for result in comparisons.values())
        self._check(
            run,
            f"concurrency_{concurrency}",
            f"Three-point COMSOL scan at concurrency {concurrency}",
            _operational_numeric_status(True, passed),
            (
                "three work units completed and matched both references"
                if passed
                else "operational execution passed; cross-machine numerical baseline requires review"
            ),
            actor_id=actor_id,
            evidence={
                "operational_execution_passed": True,
                "numerical_baseline_passed": passed,
                "comparisons": comparisons,
            },
        )
        promoted = runtime_config.model_copy(update={
            "max_concurrent_units": max(self.machine_config.max_concurrent_units, concurrency),
            "target_concurrent_units": max(self.machine_config.target_concurrent_units, concurrency),
        })
        self.service.put_machine_execution_config(promoted, actor_id=actor_id)
        self.machine_config = promoted
        return merged

    def request_cancel(self, external_run_id: str) -> None:
        self.transport.request_cancel(external_run_id)

    def _upload_concurrency_limit(self, run: SshAcceptanceRun, concurrency: int) -> None:
        self.machine_config.max_concurrent_units = concurrency
        self.machine_config.target_concurrent_units = concurrency
        self.machine_config.profile_concurrency_limits = {key: min(value, concurrency)
            for key, value in self.machine_config.profile_concurrency_limits.items()}
        local_config = self.state_root / run.run_id / f"machine-c{concurrency}.json"
        local_config.parent.mkdir(parents=True, exist_ok=True)
        local_config.write_text(
            json.dumps(self.machine_config.model_dump(mode="json"), indent=2),
            encoding="utf-8",
        )
        self.transport.upload_supervisor_config(local_config, self.supervisor_config_path)

    def _stage_single_cancel_unit(
        self,
        run: SshAcceptanceRun,
        stage: str,
        *,
        actor_id: str,
    ) -> str:
        self._upload_concurrency_limit(run, 1)
        project_yaml, scan_spec, job = self.build_acceptance_job(
            run,
            1,
            len(run.external_run_ids) + 1,
        )
        unit = job.work_units[0]
        external = (
            f"ssh-{self.machine_config.machine_id}-cancel-{stage}-"
            f"{uuid4().hex[:8]}-{unit.work_unit_id}"
        )
        assignment = Assignment(
            job_id=job.job_id,
            work_unit_id=unit.work_unit_id,
            machine_id=self.machine_config.machine_id,
            scheduler="ssh",
        )
        bundle = build_comsol_unit_bundle(
            project_yaml=project_yaml,
            scan_spec=scan_spec,
            template_path=self._acceptance_template_path(project_yaml),
            job=job,
            assignment=assignment,
            external_run_id=external,
            config=self.machine_config,
            runtime_version=self.machine_config.runtime_version or "",
            output_zip=self.state_root / run.run_id / "cancellation" / stage / f"{external}.zip",
        )
        self.transport.stage_bundle(external, bundle)
        request = json.loads(zip_read(bundle, "request.json"))
        self.service.put_remote_run(
            RemoteRunRecord(
                external_run_id=external,
                machine_id=self.machine_config.machine_id,
                job_id=job.job_id,
                work_unit_id=unit.work_unit_id,
                request_hash=request["request_hash"],
                state=RemoteRunState.STAGED,
                remote_relative_path="",
            ),
            actor_id=actor_id,
        )
        run.external_run_ids.append(external)
        self._save(run, actor_id)
        return external

    def _remote_scoped_processes(self) -> list[dict]:
        needle = f"{self.machine_config.remote_root}\\runs\\active".replace("'", "''")
        script = f"""
$all=@(Get-CimInstance Win32_Process)
$ids=New-Object 'System.Collections.Generic.HashSet[int]'
$all | Where-Object {{ $_.CommandLine -like '*{needle}*' }} | ForEach-Object {{ [void]$ids.Add([int]$_.ProcessId) }}
do {{
  $before=$ids.Count
  $all | Where-Object {{ $ids.Contains([int]$_.ParentProcessId) }} | ForEach-Object {{ [void]$ids.Add([int]$_.ProcessId) }}
}} while ($ids.Count -gt $before)
@($all | Where-Object {{ $ids.Contains([int]$_.ProcessId) }} | Select-Object ProcessId,ParentProcessId,Name) | ConvertTo-Json -Compress
"""
        completed = self.transport._powershell(script, timeout=45)
        self.transport._require_success(completed, "inspect scoped process tree")
        for line in completed.stdout.splitlines():
            line = line.strip()
            if line.startswith("[") or line.startswith("{"):
                payload = json.loads(line)
                return payload if isinstance(payload, list) else [payload]
        return []

    def run_cancel_test(
        self,
        run: SshAcceptanceRun,
        stage: str,
        *,
        actor_id: str,
        timeout_s: float = 180,
    ) -> dict:
        check_ids = {
            "python_start": "cancel_python_start",
            "comsol_start": "cancel_comsol_start",
            "solve": "cancel_solve",
        }
        if stage not in check_ids:
            raise ValueError("cancellation stage must be python_start, comsol_start or solve")
        external = self._stage_single_cancel_unit(run, stage, actor_id=actor_id)
        observed = []
        deadline = time.monotonic() + timeout_s
        if stage != "python_start":
            while time.monotonic() < deadline:
                status = self.transport.read_status(external)
                if status.get("state") == "running":
                    observed = self._remote_scoped_processes()
                    names = {str(item.get("Name", "")).lower() for item in observed}
                    if stage == "comsol_start" and "python.exe" in names:
                        break
                    if stage == "solve" and any("comsol" in name for name in names):
                        time.sleep(8)
                        if self.transport.read_status(external).get("state") == "running":
                            observed = self._remote_scoped_processes()
                            break
                time.sleep(1)
            else:
                raise TimeoutError(f"did not reach cancellation stage {stage}")
        started_cancel = time.monotonic()
        self.transport.request_cancel(external)
        final = {}
        while time.monotonic() < deadline:
            final = self.transport.read_status(external)
            if final.get("state") in {"cancelled", "failed"}:
                break
            time.sleep(1)
        residual = self._remote_scoped_processes()
        elapsed = time.monotonic() - started_cancel
        passed = final.get("state") == "cancelled" and not residual and elapsed <= 180
        evidence = {
            "external_run_id": external,
            "terminal_state": final.get("state"),
            "cleanup_seconds": round(elapsed, 3),
            "observed_process_names": sorted({str(item.get("Name", "")) for item in observed}),
            "residual_scoped_processes": residual,
        }
        self._check(
            run,
            check_ids[stage],
            f"Exact process-tree cancellation during {stage}",
            AcceptanceStatus.PASSED if passed else AcceptanceStatus.FAILED,
            "test process tree was cancelled and cleaned" if passed else "cancellation cleanup failed",
            actor_id=actor_id,
            evidence=evidence,
        )
        return evidence

    def run_transfer_cancel_test(
        self,
        run: SshAcceptanceRun,
        external_run_id: str,
        *,
        actor_id: str,
    ) -> dict:
        root = self.state_root / run.run_id / "transfer-cancel" / external_run_id
        partial = root / "partial"
        recovered = root / "recovered"
        if partial.exists():
            shutil.rmtree(partial)
        if recovered.exists():
            shutil.rmtree(recovered)
        self.transport.download_outputs(external_run_id, partial)
        first = {
            str(path.relative_to(partial)).replace("\\", "/"): sha256_file(path)
            for path in partial.rglob("*")
            if path.is_file()
        }
        # Cancelling collection before atomic activation must never remove the
        # completed remote output.  A later collection is a clean retry.
        shutil.rmtree(partial)
        status_after_cancel = self.transport.read_status(external_run_id)
        self.transport.download_outputs(external_run_id, recovered)
        second = {
            str(path.relative_to(recovered)).replace("\\", "/"): sha256_file(path)
            for path in recovered.rglob("*")
            if path.is_file()
        }
        passed = bool(first) and first == second and status_after_cancel.get("state") == "completed"
        evidence = {
            "external_run_id": external_run_id,
            "files_verified": len(second),
            "remote_state_after_cancel": status_after_cancel.get("state"),
            "hashes_equal_after_retry": first == second,
        }
        self._check(
            run,
            "cancel_transfer",
            "Cancel and retry artifact collection",
            AcceptanceStatus.PASSED if passed else AcceptanceStatus.FAILED,
            "partial collection was discarded and recovered by hash" if passed else "transfer recovery failed",
            actor_id=actor_id,
            evidence=evidence,
        )
        return evidence

    def prepare_tunnel_recovery_test(
        self,
        run: SshAcceptanceRun,
        *,
        actor_id: str,
    ) -> list[str]:
        if not self.machine_config.runtime_version:
            raise RuntimeError("runtime must be deployed before tunnel recovery test")
        self._upload_concurrency_limit(run, 1)
        project_yaml, scan_spec, job = self.build_acceptance_job(
            run,
            1,
            len(run.external_run_ids) + 1,
        )
        test_nonce = uuid4().hex[:8]
        bundle_dir = self.state_root / run.run_id / "tunnel-recovery" / "bundles"
        external_ids = []
        for unit in job.work_units:
            external = (
                f"ssh-{self.machine_config.machine_id}-tunnel-{test_nonce}-"
                f"{unit.work_unit_id}"
            )
            assignment = Assignment(
                job_id=job.job_id,
                work_unit_id=unit.work_unit_id,
                machine_id=self.machine_config.machine_id,
                scheduler="ssh",
            )
            bundle = build_comsol_unit_bundle(
                project_yaml=project_yaml,
                scan_spec=scan_spec,
                template_path=self._acceptance_template_path(project_yaml),
                job=job,
                assignment=assignment,
                external_run_id=external,
                config=self.machine_config,
                runtime_version=self.machine_config.runtime_version,
                output_zip=bundle_dir / f"{external}.zip",
            )
            self.transport.stage_bundle(external, bundle)
            request = json.loads(zip_read(bundle, "request.json"))
            self.service.put_remote_run(
                RemoteRunRecord(
                    external_run_id=external,
                    machine_id=self.machine_config.machine_id,
                    job_id=job.job_id,
                    work_unit_id=unit.work_unit_id,
                    request_hash=request["request_hash"],
                    state=RemoteRunState.STAGED,
                    remote_relative_path="",
                ),
                actor_id=actor_id,
            )
            run.external_run_ids.append(external)
            external_ids.append(external)
        self._check(
            run,
            "tunnel_recovery",
            "Reverse-tunnel interruption and idempotent recovery",
            AcceptanceStatus.RUNNING,
            "three sequential units are staged; manual tunnel interruption is pending",
            actor_id=actor_id,
            evidence={"external_run_ids": external_ids, "max_concurrent_units": 1},
        )
        return external_ids

    def schedule_tunnel_outage(
        self,
        *,
        actor_id: str,
        outage_seconds: int = 30,
    ) -> dict:
        """Schedule one exact, self-recovering reverse-tunnel interruption."""
        if outage_seconds < 5 or outage_seconds > 120:
            raise ValueError("tunnel outage must be between 5 and 120 seconds")
        root = PureWindowsPath(self.machine_config.remote_root)
        probe_task = f"ResearchComputeNetwork-TunnelRecovery-{self.machine_config.machine_id}"
        probe_path = root / "agent" / "tunnel" / "tunnel-recovery-probe.ps1"
        log_path = root / "logs" / "tunnel-recovery-probe.log"
        process_pattern = (
            f"*-R {self.machine_config.reverse_forward_port}:"
            f"{self.machine_config.reverse_forward_host}:22*"
        )
        body = f"""$ErrorActionPreference='Continue'
function Log([string]$m) {{ Add-Content -LiteralPath '{log_path}' -Value ((Get-Date).ToUniversalTime().ToString('o') + ' ' + $m) -Encoding UTF8 }}
Start-Sleep -Seconds 5
Log 'outage-start'
Stop-ScheduledTask -TaskName '{self.machine_config.tunnel_task_name}' -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process | Where-Object {{
  $_.Name -eq 'ssh.exe' -and
  $_.CommandLine -like '{process_pattern}' -and
  $_.CommandLine -like '*{self.machine_config.coordinator_host}*'
}} | ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }}
Start-Sleep -Seconds {outage_seconds}
Log 'outage-end'
Start-ScheduledTask -TaskName '{self.machine_config.tunnel_task_name}'
Start-Sleep -Seconds 3
Unregister-ScheduledTask -TaskName '{probe_task}' -Confirm:$false -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force -ErrorAction SilentlyContinue
"""
        payload = base64.b64encode(body.encode("utf-8")).decode("ascii")
        script = f"""
$probePath='{probe_path}'
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $probePath) | Out-Null
[IO.File]::WriteAllBytes($probePath,[Convert]::FromBase64String('{payload}'))
$action=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $probePath + '"')
$principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -StartWhenAvailable
Register-ScheduledTask -TaskName '{probe_task}' -Action $action -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName '{probe_task}'
[ordered]@{{scheduled=$true;task_name='{probe_task}';outage_seconds={outage_seconds}}} | ConvertTo-Json -Compress
"""
        completed = self.transport._powershell(script, timeout=30)
        self.transport._require_success(completed, "schedule exact tunnel outage")
        evidence = next(
            json.loads(line.strip())
            for line in completed.stdout.splitlines()
            if line.strip().startswith("{") and line.strip().endswith("}")
        )
        self.service._event(
            "machine.tunnel_outage_scheduled",
            actor_id,
            "machine",
            self.machine_config.machine_id,
            outage_seconds=outage_seconds,
            task_name=probe_task,
        )
        return evidence

    def verify_tunnel_recovery_test(
        self,
        run: SshAcceptanceRun,
        external_ids: list[str],
        *,
        actor_id: str,
        outage_seconds: float,
        timeout_s: float = 600,
    ) -> dict:
        deadline = time.monotonic() + timeout_s
        statuses = {}
        read_errors = {}
        while time.monotonic() < deadline:
            for external in external_ids:
                try:
                    statuses[external] = self.transport.read_status(external)
                    read_errors.pop(external, None)
                except (OSError, RuntimeError, TimeoutExpired) as exc:
                    read_errors[external] = str(exc)[:500]
            if (
                len(statuses) == len(external_ids)
                and all(
                    payload.get("state") in {"completed", "failed", "cancelled"}
                    for payload in statuses.values()
                )
            ):
                break
            time.sleep(self.machine_config.poll_interval_s)
        collected = self.state_root / run.run_id / "tunnel-recovery" / "collected"
        roots = []
        launch_counts = {}
        for external, status in statuses.items():
            if status.get("state") != "completed":
                continue
            destination = collected / external
            self.transport.download_outputs(external, destination)
            roots.append(destination)
            relative = str(status["remote_relative_path"]).replace("/", "\\").replace("'", "''")
            stdout_path = PureWindowsPath(self.machine_config.remote_root) / PureWindowsPath(relative) / "stdout.txt"
            completed = self.transport._powershell(
                f"if (Test-Path -LiteralPath '{stdout_path}') {{ "
                f"(Select-String -LiteralPath '{stdout_path}' -Pattern 'setting parameters').Count "
                f"}} else {{ 0 }}"
            )
            self.transport._require_success(completed, "inspect tunnel-test launch count")
            counts = [int(line.strip()) for line in completed.stdout.splitlines() if line.strip().isdigit()]
            launch_counts[external] = counts[-1] if counts else 0
        comparisons = {}
        if len(roots) == 3:
            merged = self.state_root / run.run_id / "tunnel-recovery" / "merged"
            _, candidate_manifest = merge_chunk_outputs(roots, merged)
            references = self._acceptance_references()
            comparisons = {
                label: compare_three_point_manifests(reference, candidate_manifest)
                for label, reference in references.items()
            }
        operational_passed = (
            outage_seconds > 0
            and len(roots) == 3
            and len(statuses) == len(external_ids)
            and all(payload.get("state") == "completed" for payload in statuses.values())
            and all(count == 1 for count in launch_counts.values())
        )
        numerical_passed = bool(comparisons) and all(
            item["passed"] for item in comparisons.values()
        )
        status = _operational_numeric_status(operational_passed, numerical_passed)
        evidence = {
            "manual_tunnel_outage_seconds": outage_seconds,
            "operational_recovery_passed": operational_passed,
            "numerical_baseline_passed": numerical_passed,
            "terminal_states": {key: value.get("state") for key, value in statuses.items()},
            "launch_counts": launch_counts,
            "numerical_comparisons": comparisons,
            "transient_read_errors": read_errors,
        }
        self._check(
            run,
            "tunnel_recovery",
            "Reverse-tunnel interruption and idempotent recovery",
            status,
            (
                "tasks continued locally and recovered without relaunch"
                if status == AcceptanceStatus.PASSED
                else "tunnel recovery passed; cross-machine numerical baseline requires review"
                if status == AcceptanceStatus.WARNING
                else "tunnel recovery failed"
            ),
            actor_id=actor_id,
            evidence=evidence,
        )
        return evidence

    def verify_no_residual_processes(self, run: SshAcceptanceRun, *, actor_id: str) -> dict:
        residual = self._remote_scoped_processes()
        evidence = {"residual_scoped_processes": residual}
        self._check(
            run,
            "no_residual_processes",
            "No residual pilot Python or COMSOL processes",
            AcceptanceStatus.PASSED if not residual else AcceptanceStatus.FAILED,
            "no pilot-scoped process remains" if not residual else "pilot-scoped processes remain",
            actor_id=actor_id,
            evidence=evidence,
        )
        return evidence

    def cleanup_preview(self) -> list[dict]:
        if not self.machine_config.runtime_version:
            return []
        supervisor = (
            PureWindowsPath(self.machine_config.remote_root)
            / "agent"
            / "versions"
            / self.machine_config.runtime_version
            / "remote-agent"
            / "supervisor.py"
        )
        completed = self.transport._powershell(
            f"& '{self.machine_config.python_executable}' '{supervisor}' --config '{self.supervisor_config_path}' cleanup-preview",
            timeout=120,
        )
        self.transport._require_success(completed, "preview cleanup")
        for line in completed.stdout.splitlines():
            line = line.strip()
            if line.startswith("[") and line.endswith("]"):
                return json.loads(line)
        return []

    def cleanup_confirm(self, relative_path: str, root_uuid: str) -> dict:
        if not self.machine_config.runtime_version:
            raise RuntimeError("runtime is not deployed")
        if root_uuid != self.machine_config.root_uuid:
            raise ValueError("cleanup root UUID does not match machine configuration")
        supervisor = (
            PureWindowsPath(self.machine_config.remote_root)
            / "agent"
            / "versions"
            / self.machine_config.runtime_version
            / "remote-agent"
            / "supervisor.py"
        )
        completed = self.transport._powershell(
            f"& '{self.machine_config.python_executable}' '{supervisor}' --config '{self.supervisor_config_path}' cleanup-confirm "
            f"--relative-path '{relative_path}' --root-uuid '{root_uuid}'",
            timeout=180,
        )
        self.transport._require_success(completed, "confirm cleanup")
        for line in completed.stdout.splitlines():
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                return json.loads(line)
        raise ValueError("cleanup command did not return JSON")

    def write_report(self, run: SshAcceptanceRun, *, actor_id: str) -> Path:
        self._refresh_status(run)
        report = self.state_root / run.run_id / "acceptance-report.json"
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(run.model_dump_json(indent=2), encoding="utf-8")
        run.report_path = str(report.relative_to(self.project_root)).replace("\\", "/")
        self._save(run, actor_id)
        return report


def zip_read(path: Path, member: str) -> str:
    import zipfile
    with zipfile.ZipFile(path) as bundle:
        return bundle.read(member).decode("utf-8")


def compare_three_point_manifests(reference_path: Path, candidate_path: Path) -> dict:
    import numpy as np
    from scipy.optimize import linear_sum_assignment

    reference = json.loads(reference_path.read_text(encoding="utf-8"))
    candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
    result = {"passed": True, "k_points": []}
    scalar_keys = ("fake_factor", "Pu", "Pd", "up_S1", "up_S2", "up_S3", "down_S1", "down_S2", "down_S3")
    for k_idx in range(3):
        left = [row for row in reference.get("files", []) if row.get("k_idx") == k_idx]
        right = [row for row in candidate.get("files", []) if row.get("k_idx") == k_idx]
        if len(left) != 21 or len(right) != 21:
            result["passed"] = False
            result["k_points"].append({"k_idx": k_idx, "passed": False, "error": "expected 21 modes"})
            continue
        left_complex = np.array([complex(row["f_thz"], -row["f_thz"] / (2 * row["Q"])) for row in left])
        right_complex = np.array([complex(row["f_thz"], -row["f_thz"] / (2 * row["Q"])) for row in right])
        rows, cols = linear_sum_assignment(np.abs(left_complex[:, None] - right_complex[None, :]))
        complex_delta = max(abs(left_complex[i] - right_complex[j]) for i, j in zip(rows, cols))
        q_relative = max(abs(left[i]["Q"] - right[j]["Q"]) / max(abs(left[i]["Q"]), 1e-12) for i, j in zip(rows, cols))
        scalar_delta = max(
            abs(float(left[i][key]) - float(right[j][key]))
            for i, j in zip(rows, cols)
            for key in scalar_keys
        )
        # COMSOL eigenvectors have an arbitrary global complex scale and
        # phase.  The raw Jones components are therefore not observables and
        # can differ by O(1e-1) even when their normalized polarization is
        # identical.  Compare unit-norm, phase-aligned vectors instead.  The
        # Stokes fields above remain an independent observable check.
        normalized_complex_delta = 0.0
        for i, j in zip(rows, cols):
            for key in ("up", "down"):
                ref_vector = np.array(
                    [complex(*left[i][f"{key}_cx"]), complex(*left[i][f"{key}_cy"])],
                    dtype=complex,
                )
                candidate_vector = np.array(
                    [complex(*right[j][f"{key}_cx"]), complex(*right[j][f"{key}_cy"])],
                    dtype=complex,
                )
                ref_norm = np.linalg.norm(ref_vector)
                candidate_norm = np.linalg.norm(candidate_vector)
                if ref_norm <= 1e-15 or candidate_norm <= 1e-15:
                    normalized_complex_delta = max(
                        normalized_complex_delta,
                        float(np.linalg.norm(ref_vector - candidate_vector)),
                    )
                    continue
                ref_vector = ref_vector / ref_norm
                candidate_vector = candidate_vector / candidate_norm
                overlap = np.vdot(candidate_vector, ref_vector)
                if abs(overlap) > 1e-15:
                    candidate_vector *= overlap / abs(overlap)
                normalized_complex_delta = max(
                    normalized_complex_delta,
                    float(np.max(np.abs(ref_vector - candidate_vector))),
                )
        physical_equal = bool(all(left[i].get("is_physical") == right[j].get("is_physical") for i, j in zip(rows, cols)))
        passed = bool(
            complex_delta <= 1e-8
            and q_relative <= 1e-4
            and scalar_delta <= 1e-7
            and normalized_complex_delta <= 1e-7
            and physical_equal
        )
        result["passed"] = result["passed"] and passed
        result["k_points"].append({
            "k_idx": k_idx,
            "max_complex_frequency_delta_thz": float(complex_delta),
            "max_q_relative_delta": float(q_relative),
            "max_scalar_absolute_delta": float(scalar_delta),
            "max_normalized_complex_amplitude_delta": float(normalized_complex_delta),
            "physical_classification_equal": physical_equal,
            "passed": passed,
        })
    return result
