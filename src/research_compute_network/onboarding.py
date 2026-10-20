"""Configuration-driven, read-only SSH onboarding for planned Windows workers."""

from __future__ import annotations

import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .models import (
    AcceptanceCheck,
    AcceptanceStatus,
    DeploymentReadiness,
    MachineExecutionConfig,
    MachineMode,
    MachineOnboardingProfile,
    MachinePolicy,
    MachinePreflightRun,
    MachineState,
    OnboardingStage,
    TimeWindow,
)
from .schedulers.ssh import OpenSshTransport
from .service import NetworkService


BUILTIN_ONBOARDING_PROFILES: dict[str, MachineOnboardingProfile] = {}
ONBOARDING_PROFILES_FILE = "profiles.json"


def _validated_profiles(payload) -> dict[str, MachineOnboardingProfile]:
    entries = payload.get("profiles", []) if isinstance(payload, dict) else payload
    if not isinstance(entries, list):
        raise ValueError("onboarding profile document must contain a profiles list")
    profiles = [MachineOnboardingProfile.model_validate(entry) for entry in entries]
    result = {profile.machine_id: profile for profile in profiles}
    if len(result) != len(profiles):
        raise ValueError("onboarding profile machine IDs must be unique")
    orders = [profile.order for profile in profiles]
    if len(set(orders)) != len(orders):
        raise ValueError("onboarding profile order values must be unique")
    return result


def _run(command: list[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout)


class MachineOnboardingManager:
    """Persist sanitized preflight evidence without registering a worker."""

    def __init__(
        self,
        service: NetworkService,
        *,
        state_root: str | Path,
        runner: Callable[..., subprocess.CompletedProcess[str]] = _run,
        transport_factory=None,
        profiles: dict[str, MachineOnboardingProfile] | None = None,
    ) -> None:
        self.service = service
        self.state_root = Path(state_root)
        self.runner = runner
        self.transport_factory = transport_factory
        self.profiles_path = self.state_root / ONBOARDING_PROFILES_FILE
        if profiles is not None:
            self.profiles = dict(profiles)
        elif self.profiles_path.is_file():
            self.profiles = _validated_profiles(json.loads(self.profiles_path.read_text(encoding="utf-8")))
        else:
            self.profiles = dict(BUILTIN_ONBOARDING_PROFILES)

    @property
    def key_root(self) -> Path:
        return self.state_root / "known_hosts"

    def profile(self, machine_id: str) -> MachineOnboardingProfile:
        try:
            return self.profiles[machine_id]
        except KeyError as exc:
            raise KeyError(f"unknown onboarding machine: {machine_id}") from exc

    def import_profiles(self, source: str | Path) -> dict:
        profiles = _validated_profiles(json.loads(Path(source).read_text(encoding="utf-8-sig")))
        payload = {
            "schema_version": 1,
            "profiles": [
                profile.model_dump(mode="json")
                for profile in sorted(profiles.values(), key=lambda item: item.order)
            ],
        }
        self.profiles_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.profiles_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        temporary.replace(self.profiles_path)
        self.profiles = profiles
        return {"profile_count": len(profiles), "machine_ids": list(profiles)}

    def host_key_path(self, machine_id: str) -> Path:
        self.profile(machine_id)
        return self.key_root / f"{machine_id}.known_hosts"

    def _fingerprint(self, path: Path) -> str:
        if shutil.which("ssh-keygen") is None:
            raise RuntimeError("ssh-keygen is unavailable")
        completed = self.runner(["ssh-keygen", "-lf", str(path), "-E", "sha256"], timeout=20)
        if completed.returncode != 0:
            raise ValueError(f"host key fingerprint failed: {(completed.stderr or completed.stdout).strip()}")
        for token in completed.stdout.split():
            if token.startswith("SHA256:"):
                return token
        raise ValueError("ssh-keygen output did not contain a SHA-256 fingerprint")

    def import_verified_host_key(
        self,
        machine_id: str,
        source: str | Path,
        expected_fingerprint: str,
    ) -> dict:
        profile = self.profile(machine_id)
        source_path = Path(source)
        lines = [
            line.strip()
            for line in source_path.read_text(encoding="utf-8-sig").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        if len(lines) != 1 or "PRIVATE KEY" in lines[0]:
            raise ValueError("host-key file must contain exactly one public known-hosts line")
        if not any(kind in lines[0] for kind in ("ssh-ed25519", "ecdsa-sha2-", "ssh-rsa")):
            raise ValueError("host-key line has no supported public key type")
        expected_host = f"[localhost]:{profile.ssh_port}"
        if not lines[0].startswith(expected_host + " "):
            raise ValueError(f"host-key line must be scoped to {expected_host}")
        actual = self._fingerprint(source_path)
        if actual != expected_fingerprint:
            raise ValueError("host-key fingerprint does not match the ToDesk-confirmed value")
        destination = self.host_key_path(machine_id)
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_suffix(".tmp")
        temporary.write_text(lines[0] + "\n", encoding="utf-8")
        temporary.replace(destination)
        return {
            "machine_id": machine_id,
            "fingerprint": actual,
            "verified": True,
            "key_path": str(destination),
        }

    def profile_statuses(self) -> list[dict]:
        runs = self.service.repository.list_machine_preflight_runs()
        latest = {}
        for run in runs:
            latest.setdefault(run.machine_id, run)
        result = []
        for profile in sorted(self.profiles.values(), key=lambda item: item.order):
            key_path = self.host_key_path(profile.machine_id)
            result.append({
                "profile": profile.model_dump(mode="json"),
                "host_key_ready": key_path.is_file(),
                "host_key_fingerprint": self._fingerprint(key_path) if key_path.is_file() else None,
                "latest_run": latest.get(profile.machine_id).model_dump(mode="json") if latest.get(profile.machine_id) else None,
            })
        return result

    def _transport(self, profile: MachineOnboardingProfile):
        key_path = self.host_key_path(profile.machine_id)
        if not key_path.is_file():
            raise RuntimeError("ToDesk-verified host key has not been imported")
        key_line = key_path.read_text(encoding="utf-8-sig").strip()
        config = MachineExecutionConfig(
            machine_id=profile.machine_id,
            ssh_host=profile.ssh_host,
            ssh_port=profile.ssh_port,
            ssh_user=profile.ssh_user,
            pinned_host_key=key_line,
            remote_root=profile.proposed_root,
            disk_reserve_gib=profile.disk_reserve_gib,
            max_concurrent_units=1,
            target_concurrent_units=profile.target_concurrent_units,
            expected_hostname=profile.expected_hostname,
            python_executable=profile.python_executable or "python.exe",
            comsol_root=profile.comsol_root or "",
            legacy_worker_path=profile.legacy_worker_path,
            enabled=False,
        )
        if self.transport_factory is not None:
            return self.transport_factory(config)
        return OpenSshTransport(config, state_root=self.state_root / "transport")

    def approve_for_deployment(self, machine_id: str, *, actor_id: str) -> dict:
        """Register one preflight-approved worker in paused deployment mode.

        This is the explicit phase boundary between read-only discovery and
        remote initialization.  It stores only non-secret configuration; the
        pinned public host key remains in the ignored state directory.
        """
        profile = self.profile(machine_id)
        runs = self.service.repository.list_machine_preflight_runs(machine_id)
        if not runs:
            raise RuntimeError("machine has no preflight evidence")
        preflight = runs[0]
        if preflight.status != AcceptanceStatus.PASSED or preflight.stage != OnboardingStage.AWAITING_APPROVAL:
            raise RuntimeError("latest machine preflight is not approved for deployment")
        facts = preflight.facts
        if str(facts.get("hostname", "")).upper() != profile.expected_hostname.upper():
            raise RuntimeError("preflight hostname no longer matches onboarding profile")
        key_path = self.host_key_path(machine_id)
        if not key_path.is_file():
            raise RuntimeError("verified host key is unavailable")
        pinned_host_key = key_path.read_text(encoding="utf-8-sig").strip()
        total_memory_mb = max(256, int(facts.get("memory_bytes", 0)) // 1024**2)
        total_cpus = max(1, int(facts.get("logical_cpus", profile.max_cpus)))
        existing_machine = self.service.repository.get_machine(machine_id)
        if existing_machine is None:
            machine = MachineState(
                machine_id=machine_id,
                owner_user_id=profile.owner_user_id,
                hostname=profile.expected_hostname,
                labels={"group-trusted", machine_id.lower()},
                capabilities={"comsol-6.4", "python-mph"},
                total_cpus=total_cpus,
                total_memory_mb=total_memory_mb,
                total_gpus=0,
            )
            policy = MachinePolicy(
                machine_id=machine_id,
                owner_user_id=profile.owner_user_id,
                weekly_windows={day: [TimeWindow(start="00:00", end="00:00")] for day in range(7)},
                owner_mode=MachineMode.PAUSED,
                keyboard_idle_min_s=1200,
                non_pool_cpu_max_percent=15,
                cpu_window_s=600,
                memory_reserve_mb=profile.memory_reserve_mb,
                max_cpus=profile.max_cpus,
                max_memory_mb=profile.max_memory_mb,
                max_gpus=profile.max_gpus,
                max_concurrent_units=1,
            )
            self.service.register_machine(machine, policy, actor_id=actor_id)
        config = self.service.repository.get_machine_execution_config(machine_id) or MachineExecutionConfig(
            machine_id=machine_id,
            ssh_host=profile.ssh_host,
            ssh_port=profile.ssh_port,
            ssh_user=profile.ssh_user,
            pinned_host_key=pinned_host_key,
            remote_root=profile.proposed_root,
            python_executable=profile.python_executable or r"python.exe",
            comsol_root=profile.comsol_root or "",
            disk_reserve_gib=profile.disk_reserve_gib,
            max_concurrent_units=1,
            target_concurrent_units=profile.target_concurrent_units,
            enabled=False,
            tunnel_startup="boot",
            reverse_forward_port=profile.ssh_port,
            expected_hostname=profile.expected_hostname,
            legacy_worker_path=profile.legacy_worker_path,
        )
        # Preserve deployed versions/root UUID on an idempotent re-approval,
        # while refreshing reviewed non-secret connection metadata.
        config.ssh_host = profile.ssh_host
        config.ssh_port = profile.ssh_port
        config.ssh_user = profile.ssh_user
        config.pinned_host_key = pinned_host_key
        config.expected_hostname = profile.expected_hostname
        config.legacy_worker_path = profile.legacy_worker_path
        config.target_concurrent_units = profile.target_concurrent_units
        config.tunnel_startup = "boot"
        config.reverse_forward_port = profile.ssh_port
        config.enabled = False
        self.service.put_machine_execution_config(config, actor_id=actor_id)
        self.service._event(
            "machine.onboarding_deployment_approved",
            actor_id,
            "machine",
            machine_id,
            preflight_run_id=preflight.run_id,
            remote_root=profile.proposed_root,
        )
        return {
            "machine_id": machine_id,
            "preflight_run_id": preflight.run_id,
            "owner_mode": "paused",
            "execution_enabled": False,
            "remote_root": profile.proposed_root,
            "python_executable": config.python_executable,
            "target_concurrent_units": profile.target_concurrent_units,
        }

    @staticmethod
    def _check(check_id: str, label: str, passed: bool, message: str, evidence=None) -> AcceptanceCheck:
        return AcceptanceCheck(
            check_id=check_id,
            label=label,
            status=AcceptanceStatus.PASSED if passed else AcceptanceStatus.BLOCKED,
            message=message,
            evidence=evidence or {},
        )

    @staticmethod
    def _parse_json(stdout: str) -> dict:
        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                value = json.loads(line)
                if isinstance(value, dict):
                    return value
        raise ValueError("read-only preflight did not return JSON")

    def _script(self, profile: MachineOnboardingProfile) -> str:
        root = profile.proposed_root.replace("'", "''")
        return rf"""
$ErrorActionPreference='Stop'
$root='{root}'
$os=Get-CimInstance Win32_OperatingSystem
$cpu=Get-CimInstance Win32_Processor | Select-Object -First 1
$disks=@(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3'|%{{[PSCustomObject]@{{drive=$_.DeviceID;total_bytes=[int64]$_.Size;free_bytes=[int64]$_.FreeSpace}}}})
$firewall=@(Get-NetFirewallProfile|%{{[PSCustomObject]@{{name=[string]$_.Name;enabled=[bool]$_.Enabled}}}})
$active=@(Get-CimInstance Win32_Process|?{{$_.Name -match '^(python|pythonw|comsol|comsolmphserver|ComsolUI)\.exe$'}}|%{{[PSCustomObject]@{{name=$_.Name;pid=[int]$_.ProcessId;command_line=[string]$_.CommandLine}}}})
$video=@(Get-CimInstance Win32_VideoController|%{{$_.Name}})
$comsol=@()
foreach($exe in @('C:\Program Files\COMSOL\COMSOL64\Multiphysics\bin\win64\comsol.exe','D:\Program Files\COMSOL\COMSOL64\Multiphysics\bin\win64\comsol.exe','D:\Program Files\COMSOL64\Multiphysics\bin\win64\comsol.exe','E:\Program Files\COMSOL\COMSOL64\Multiphysics\bin\win64\comsol.exe','F:\Program Files\COMSOL\COMSOL64\Multiphysics\bin\win64\comsol.exe')){{
  if(Test-Path -LiteralPath $exe){{$comsol+=[PSCustomObject]@{{display_name='COMSOL Multiphysics 6.4';version='6.4';root=($exe -replace '\\Multiphysics\\bin\\win64\\comsol\.exe$','');executable_exists=$true}}}}
}}
$python=@()
foreach($path in @(Get-Command python.exe -All|%{{$_.Source}}|select -Unique)){{
  if(Test-Path -LiteralPath $path){{try{{$i=& $path -c "import json,sys,importlib.util as u;print(json.dumps(dict(version=sys.version.split()[0],mph=bool(u.find_spec('mph')),jpype=bool(u.find_spec('jpype')),numpy=bool(u.find_spec('numpy')),scipy=bool(u.find_spec('scipy')),h5py=bool(u.find_spec('h5py')),yaml=bool(u.find_spec('yaml')))))"|select -Last 1;$j=$i|ConvertFrom-Json;$python+=[PSCustomObject]@{{path=$path;version=$j.version;mph=[bool]$j.mph;jpype=[bool]$j.jpype;numpy=[bool]$j.numpy;scipy=[bool]$j.scipy;h5py=[bool]$j.h5py;yaml=[bool]$j.yaml}}}}catch{{}}}}
}}
$legacy=Join-Path $env:USERPROFILE 'comsol_worker'
$rootExists=Test-Path -LiteralPath $root
$rootCount=if($rootExists){{@(Get-ChildItem -LiteralPath $root -Force).Count}}else{{0}}
$rootMarked=if($rootExists){{Test-Path -LiteralPath (Join-Path $root '.rcn-root.json')}}else{{$false}}
[PSCustomObject]@{{
  hostname=$env:COMPUTERNAME
  os_caption=[string]$os.Caption
  os_version=[string]$os.Version
  cpu_name=[string]$cpu.Name
  logical_cpus=[int]$cpu.NumberOfLogicalProcessors
  memory_bytes=[int64]$os.TotalVisibleMemorySize*1024
  disks=$disks
  firewall=$firewall
  active_compute=$active
  video=$video
  python=$python
  comsol=$comsol
  license_launch_test='not_run_read_only_preflight'
  legacy_worker_exists=[bool](Test-Path -LiteralPath $legacy)
  legacy_worker_last_write=if(Test-Path -LiteralPath $legacy){{(Get-Item -LiteralPath $legacy).LastWriteTimeUtc.ToString('o')}}else{{$null}}
  proposed_root_exists=[bool]$rootExists
  proposed_root_item_count=[int]$rootCount
  proposed_root_marked=[bool]$rootMarked
}} | ConvertTo-Json -Compress -Depth 8
"""

    def run_preflight(self, machine_id: str, *, actor_id: str, run_id: str | None = None) -> MachinePreflightRun:
        profile = self.profile(machine_id)
        key_path = self.host_key_path(machine_id)
        run = MachinePreflightRun(
            **({'run_id': run_id} if run_id is not None else {}),
            machine_id=machine_id,
            stage=OnboardingStage.PREFLIGHT_RUNNING,
            status=AcceptanceStatus.RUNNING,
            expected_hostname=profile.expected_hostname,
            proposed_root=profile.proposed_root,
            host_key_fingerprint=self._fingerprint(key_path) if key_path.is_file() else None,
            warnings=list(profile.persistent_warnings),
        )
        self.service.put_machine_preflight_run(run, actor_id=actor_id)
        try:
            transport = self._transport(profile)
            probe = transport.probe()
            run.checks.append(self._check(
                "ssh_transport",
                "Pinned SSH transport",
                probe.available,
                "pinned SSH transport connected" if probe.available else "pinned SSH transport unavailable",
                {"host": profile.ssh_host, "port": profile.ssh_port, "errors": probe.errors},
            ))
            if not probe.available:
                raise RuntimeError("pinned SSH transport unavailable")
            completed = transport._powershell(self._script(profile), timeout=90)
            transport._require_success(completed, "run read-only onboarding preflight")
            facts = self._parse_json(completed.stdout)
            run.facts = facts
            run.observed_hostname = facts.get("hostname")

            hostname_ok = str(facts.get("hostname", "")).upper() == profile.expected_hostname.upper()
            run.checks.append(self._check("hostname", "Expected machine identity", hostname_ok, "hostname matched" if hostname_ok else "hostname mismatch", {"observed": facts.get("hostname")}))
            drive = profile.proposed_root[:2].upper()
            disk = next((item for item in facts.get("disks", []) if str(item.get("drive", "")).upper() == drive), None)
            disk_ok = bool(disk) and int(disk.get("free_bytes", 0)) >= profile.disk_reserve_gib * 1024**3
            run.checks.append(self._check("disk", "Proposed root disk reserve", disk_ok, "disk reserve satisfied" if disk_ok else "proposed root drive lacks the required reserve", {"drive": drive, "free_bytes": disk.get("free_bytes") if disk else None, "reserve_gib": profile.disk_reserve_gib}))
            comsol = facts.get("comsol", [])
            comsol64 = [item for item in comsol if str(item.get("version", "")).startswith("6.4") or "6.4" in str(item.get("display_name", ""))]
            comsol_ok = any(item.get("executable_exists") for item in comsol64)
            run.checks.append(self._check("comsol_64", "COMSOL 6.4 executable", comsol_ok, "COMSOL 6.4 executable discovered" if comsol_ok else "COMSOL 6.4 executable not discovered", {"candidates": comsol64}))
            active = facts.get("active_compute", [])
            idle_ok = len(active) == 0
            run.checks.append(self._check("idle", "No active Python or COMSOL compute", idle_ok, "machine is idle" if idle_ok else "active compute processes were observed", {"processes": active}))
            root_safe = not facts.get("proposed_root_exists") or facts.get("proposed_root_marked") or int(facts.get("proposed_root_item_count", 0)) == 0
            run.checks.append(self._check("root", "Proposed isolated root", root_safe, "root is absent, empty, or already marked" if root_safe else "proposed root is non-empty and unmarked", {"exists": facts.get("proposed_root_exists"), "item_count": facts.get("proposed_root_item_count"), "marked": facts.get("proposed_root_marked")}))
            python_ready = any(all(item.get(name) for name in ("mph", "jpype", "numpy", "scipy", "h5py", "yaml")) for item in facts.get("python", []))
            run.checks.append(self._check("python", "Python scientific runtime", True, "existing runtime is ready" if python_ready else "versioned managed Python is required", {"existing_runtime_ready": python_ready, "candidates": facts.get("python", [])}))
            disabled_firewall = [item.get("name") for item in facts.get("firewall", []) if not item.get("enabled")]
            if disabled_firewall:
                run.warnings.append("disabled Windows firewall profiles: " + ", ".join(disabled_firewall))
            if facts.get("legacy_worker_exists"):
                run.warnings.append("legacy comsol_worker exists and must remain untouched")
            if not python_ready:
                run.warnings.append("managed Python package is required before deployment")
            run.warnings.append("COMSOL license launch was intentionally not tested during read-only preflight")

            hard_ok = all(check.status == AcceptanceStatus.PASSED for check in run.checks if check.check_id != "python")
            run.status = AcceptanceStatus.PASSED if hard_ok else AcceptanceStatus.BLOCKED
            run.readiness = (
                DeploymentReadiness.BLOCKED
                if not hard_ok
                else DeploymentReadiness.READY if python_ready else DeploymentReadiness.NEEDS_MANAGED_PYTHON
            )
            run.stage = OnboardingStage.AWAITING_APPROVAL
        except Exception as exc:
            run.status = AcceptanceStatus.BLOCKED
            run.readiness = DeploymentReadiness.BLOCKED
            run.stage = OnboardingStage.AWAITING_APPROVAL
            run.warnings.append(f"preflight blocked: {type(exc).__name__}: {exc}")
        return self.service.put_machine_preflight_run(run, actor_id=actor_id)

    def write_matrix_report(self) -> Path:
        report_root = self.state_root / "reports"
        report_root.mkdir(parents=True, exist_ok=True)
        runs = self.service.repository.list_machine_preflight_runs()
        latest = {}
        for run in runs:
            latest.setdefault(run.machine_id, run)
        payload = {
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "order": [profile.machine_id for profile in sorted(self.profiles.values(), key=lambda item: item.order)],
            "machines": {
                machine_id: run.model_dump(mode="json") if (run := latest.get(machine_id)) else None
                for machine_id in self.profiles
            },
            "remote_mutations_performed": False,
        }
        destination = report_root / "preflight-matrix.json"
        destination.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        return destination
