"""Admin-only local transport for the existing sealed-runtime deployment harness.

No shell API, root initialization, scientific inputs, admission or policy changes.
The command is useful only on the registered worker's own Windows computer.
"""
from __future__ import annotations

import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import inspect
import io
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
from uuid import uuid4
import zipfile

from .hashing import sha256_value
from .models import (FailureClass, JobStatus, MachineExecutionConfig, MachineMode,
    RemoteRunState, UserRole, WorkUnitStatus)
from .remote_storage import ROOT_MARKER, safe_component, validate_remote_root_path
from .ssh_acceptance import SshAcceptanceHarness
from .supervisor_paths import LOCATION_KEY, supervisor_config_path


def _windows_identity() -> str:
    if os.name != 'nt' or not ctypes.windll.shell32.IsUserAnAdmin():
        raise RuntimeError('local_worker_requires_elevated_windows_administrator')
    size = ctypes.c_ulong(256)
    buffer = ctypes.create_unicode_buffer(size.value)
    if not ctypes.windll.advapi32.GetUserNameW(buffer, ctypes.byref(size)):
        raise RuntimeError('local_worker_identity_unavailable')
    return buffer.value


def _powershell_executable() -> Path:
    buffer = ctypes.create_unicode_buffer(32768)
    size = ctypes.windll.kernel32.GetSystemDirectoryW(buffer, len(buffer))
    if not 0 < size < len(buffer):
        raise RuntimeError('local_worker_windows_system_directory_unavailable')
    return Path(buffer.value)/'WindowsPowerShell/v1.0/powershell.exe'


def _unlinked(path: Path) -> Path:
    path = path.absolute()
    for item in (path, *path.parents):
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise RuntimeError('local_worker_linked_path')
    return path


def _read(path: Path, maximum: int = 262144) -> bytes:
    _unlinked(path)
    with path.open('rb') as stream:
        value = stream.read(maximum + 1)
    if len(value) > maximum:
        raise RuntimeError('local_worker_oversized_evidence')
    return value


def _json(path: Path) -> dict:
    value = json.loads(_read(path).decode('utf-8-sig'))
    if not isinstance(value, dict):
        raise RuntimeError('local_worker_invalid_evidence')
    return value


def _authority(value: dict) -> dict:
    """Ignore only a validated bookkeeping timestamp, retaining every other key."""
    if not isinstance(value, dict) or 'updated_at' not in value:
        raise RuntimeError('local_worker_configuration_collision')
    MachineExecutionConfig.model_validate(value)
    return {key: item for key, item in value.items() if key != 'updated_at'}


def _walk_unavailable(error: OSError):
    raise RuntimeError('local_worker_directory_evidence_unavailable') from error


def runtime_files(archive: Path, version: str, runtime_lock: Path) -> dict[str, bytes]:
    """Validate the registered whole archive and its original source fingerprint."""
    if not re.fullmatch(r'[a-f0-9]{24}', version):
        raise ValueError('local_worker_invalid_runtime_version')
    lock = _json(runtime_lock)
    if version == lock.get('runtime_version'):
        expected = lock.get('archive_sha256')
    else:
        entry = lock.get('candidate_runtimes', {}).get(version, {})
        expected = entry.get('archive_sha256') if entry.get('promotion_state') == 'candidate' else None
    if not isinstance(expected, str) or not re.fullmatch(r'[a-f0-9]{64}', expected):
        raise ValueError('local_worker_runtime_not_registered')
    raw = _read(archive, 8 * 1024 * 1024)
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('local_worker_archive_hash_mismatch')
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as bundle:
            infos = bundle.infolist()
            if not 1 <= len(infos) <= 2048 or sum(i.file_size for i in infos) > 32 * 1024 * 1024:
                raise ValueError('archive bounds')
            contents = {}
            folded = set()
            for item in infos:
                name = item.orig_filename
                parts = name.split('/')
                mode = (item.external_attr >> 16) & 0o170000
                if (item.is_dir() or item.file_size > 262144 or mode not in {0, 0o100000}
                        or item.flag_bits & 1 or name != item.filename or '\\' in name
                        or any(not p or p in {'.', '..'} or p.endswith((' ', '.'))
                            or re.search(r'[<>:"|?*\x00-\x1f]', p)
                            or re.fullmatch(r'(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?', p, re.I)
                            for p in parts) or name.casefold() in folded):
                    raise ValueError('unsafe archive member')
                if name != 'runtime-manifest.json' and not name.startswith(
                        ('remote-agent/', 'workbench-src/research_agent_workbench/')):
                    raise ValueError('archive outside runtime scope')
                folded.add(name.casefold())
                contents[name] = bundle.read(item)
        manifest = json.loads(contents['runtime-manifest.json'])
        fingerprint = manifest['files']
        if (type(manifest.get('schema_version')) is not int or manifest['schema_version'] != 1
                or manifest.get('version') != version or not isinstance(fingerprint, dict)
                or fingerprint.get('__runtime_layout_version__') != '2'
                or sha256_value(fingerprint)[:24] != version):
            raise ValueError('runtime fingerprint mismatch')
        expected_sources = set()
        for name, digest in fingerprint.items():
            if name == '__runtime_layout_version__':
                continue
            target = ('workbench-src/research_agent_workbench/'+name[10:]
                      if name.startswith('workbench/') else name)
            if (not name.startswith(('workbench/', 'remote-agent/')) or not target.endswith('.py')
                    or not isinstance(digest, str) or not re.fullmatch(r'[a-f0-9]{64}', digest)
                    or target in expected_sources or target not in contents
                    or hashlib.sha256(contents[target]).hexdigest() != digest):
                raise ValueError('runtime source mismatch')
            expected_sources.add(target)
        if (not {'remote-agent/supervisor.py', 'remote-agent/comsol_recipe_worker.py',
                 'remote-agent/comsol_recipe_contracts.py'}.issubset(expected_sources)
                or not any(n.startswith('workbench-src/') for n in expected_sources)
                or any(n.lower().endswith(('.py', '.pyw', '.pyc', '.pyo'))
                       for n in set(contents)-expected_sources-{'runtime-manifest.json'})):
            raise ValueError('runtime source inventory mismatch')
        return contents
    except (KeyError, TypeError, zipfile.BadZipFile, RuntimeError) as exc:
        raise ValueError('local_worker_archive_invalid') from exc


class NativeTransport:
    """Private adapter; only the four fixed deployment-harness scripts can execute."""
    def __init__(self, service, config: MachineExecutionConfig, *, actor_id: str, runtime_lock: Path):
        self.service, self.config, self.actor_id = service, config.model_copy(deep=True), actor_id
        self.runtime_lock = Path(runtime_lock)
        self.root = _unlinked(Path(str(validate_remote_root_path(config.remote_root))))
        self.config_path = _unlinked(Path(str(supervisor_config_path(config))))
        self.harness = None
        self.candidate = None
        self.backups = []
        marker = _json(self.root/ROOT_MARKER)
        self.root_uuid = marker.get('root_uuid')
        self.guard()

    def guard(self):
        username = _windows_identity()
        repo = self.service.repository
        actor = repo.get_user(self.actor_id)
        machine = repo.get_machine(self.config.machine_id)
        policy = repo.get_policy(self.config.machine_id)
        current = repo.get_machine_execution_config(self.config.machine_id)
        if actor is None or not actor.active or UserRole.ADMIN not in actor.roles:
            raise RuntimeError('local_worker_actor_requires_admin')
        if (machine is None or policy is None or current is None or not current.enabled
                or policy.effective_mode() != MachineMode.DRAIN or machine.metrics.running_units != 0):
            raise RuntimeError('local_worker_requires_registered_idle_drain')
        if (not self.config.expected_hostname or self.config.expected_hostname.casefold() != socket.gethostname().casefold()
                or machine.hostname.casefold() != socket.gethostname().casefold()
                or self.config.ssh_host.casefold() not in {'localhost', '127.0.0.1', '::1'}
                or username.casefold() != self.config.ssh_user.casefold()
                or self.config.execution_provenance.get(LOCATION_KEY) is not None
                or self.config.supervisor_startup not in {'logon', 'manual'}):
            raise RuntimeError('local_worker_host_or_account_scope_mismatch')
        for value in (self.config.remote_root, self.config.python_executable,
                      str(self.config_path), self.config.machine_id):
            if any(ch in value for ch in "'\r\n\x00"):
                raise RuntimeError('local_worker_unsafe_script_identity')
        marker = _json(self.root/ROOT_MARKER)
        if (type(marker.get('schema_version')) is not int or marker['schema_version'] != 1
                or marker.get('machine_id') != self.config.machine_id
                or not isinstance(self.root_uuid, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,159}', self.root_uuid)
                or marker.get('root_uuid') != self.root_uuid
                or (self.config.root_uuid is not None and self.config.root_uuid != self.root_uuid)):
            raise RuntimeError('local_worker_root_identity_mismatch')
        allowed = [self.config, self.candidate] if self.candidate else [self.config]
        if not any(current.model_dump(mode='json', exclude={'updated_at'}) == c.model_dump(mode='json', exclude={'updated_at'}) for c in allowed):
            raise RuntimeError('local_worker_formal_configuration_changed')
        self._check_work()
        _unlinked(self.config_path)

    def _check_work(self):
        """RemoteRun is a polling cache, not the authority for current work."""
        repo, machine_id = self.service.repository, self.config.machine_id
        reservations = repo.list_dispatch_reservations(machine_id=machine_id)
        if any(r.active_key is not None or r.state in {'preparing', 'prepared', 'activating'} for r in reservations):
            raise RuntimeError('local_worker_pending_remote_work')
        jobs = {job.job_id: job for job in repo.list_operational_jobs()}
        end_jobs = {JobStatus.COMPLETED, JobStatus.FAILED_TERMINAL, JobStatus.CANCELLED}
        active_units = {WorkUnitStatus.ASSIGNED, WorkUnitStatus.RUNNING,
            WorkUnitStatus.RECONCILE_PENDING, WorkUnitStatus.COLLECTING}
        end_attempts = {'completed', 'failed', 'cancelled'}
        for job in jobs.values():
            for unit in job.work_units:
                # A terminal Job may retain the previous machine attribution
                # and failed_retriable Unit. Those fields do not reserve a slot.
                if (job.status not in end_jobs and unit.assigned_machine_id == machine_id
                        and unit.status in active_units):
                    raise RuntimeError('local_worker_pending_remote_work')
                for attempt in unit.attempts:
                    # Match the Dispatcher's actual uncertain recovery contract.
                    # UNKNOWN describes a failure cause, not a live process.
                    uncertain = (unit.status not in {WorkUnitStatus.COMPLETED, WorkUnitStatus.CANCELLED}
                        and attempt is unit.attempts[-1] and attempt.state == 'failed'
                        and attempt.failure_class == FailureClass.INFRASTRUCTURE
                        and attempt.external_run_id and not attempt.execution_completed
                        and (attempt.failure_reason or unit.failure_reason or '').startswith('remote state remained uncertain:'))
                    if attempt.machine_id == machine_id and (attempt.state not in end_attempts
                            or uncertain):
                        raise RuntimeError('local_worker_pending_remote_work')
        # A prepared request is absent from supervisor.active, but survives a
        # restart. Preserve it by refusing any incoming or activation material.
        for relative in ('spool/incoming', 'spool/activations'):
            directory = _unlinked(self.root/relative)
            if directory.exists() and any(directory.iterdir()):
                raise RuntimeError('local_worker_pending_remote_work')
        terminal = {RemoteRunState.COMPLETED, RemoteRunState.FAILED, RemoteRunState.CANCELLED, RemoteRunState.INTERRUPTED}
        for run in repo.list_remote_runs(machine_id):
            if run.state in terminal:
                continue
            if run.state not in {RemoteRunState.STAGED, RemoteRunState.PREPARED, RemoteRunState.RUNNING}:
                raise RuntimeError('local_worker_pending_remote_work')
            external = safe_component(getattr(run, 'external_run_id', ''), label='external_run_id')
            path = _unlinked(self.root/'spool/status'/(external+'.json'))
            if not path.is_file():
                raise RuntimeError('local_worker_pending_remote_work')
            status = _json(path)
            if (status.get('state') not in terminal or status.get('machine_id') != machine_id
                    or status.get('external_run_id') != external
                    or not isinstance(status.get('request_hash'), str)
                    or not re.fullmatch(r'[a-f0-9]{64}', status['request_hash'])
                    or status['request_hash'] == '0'*64):
                raise RuntimeError('local_worker_pending_remote_work')
            fallback = (run.state == RemoteRunState.STAGED and run.job_id == run.work_unit_id == 'unknown'
                and run.request_hash == '0'*64 and run.remote_relative_path == '')
            if not fallback and any(status.get(k) != getattr(run, k) for k in ('job_id', 'work_unit_id', 'request_hash')):
                raise RuntimeError('local_worker_pending_remote_work')
            job = jobs.get(status.get('job_id'))
            unit = next((u for u in job.work_units if u.work_unit_id == status.get('work_unit_id')), None) if job else None
            # The submission Job hash and resolved dispatch-bundle hash name
            # different contracts. Only compare dispatch hashes for this exact
            # external ID; known cache identity was checked above. A fallback
            # must bind the published identity to the original typed Attempt.
            if job is None or unit is None:
                raise RuntimeError('local_worker_pending_remote_work')
            matches = [a for a in unit.attempts if a.external_run_id == external]
            retired_reservation = any(r.external_run_id == external and r.job_id == job.job_id
                and r.work_unit_id == unit.work_unit_id and r.active_key is None
                and r.state in {'cancelled', 'expired'} for r in reservations)
            if ((fallback and not matches) or (not matches and not retired_reservation)
                    or any(a.machine_id != machine_id or a.state not in end_attempts for a in matches)
                    or (not matches and job.status not in end_jobs)):
                raise RuntimeError('local_worker_pending_remote_work')
            active = self.root/'runs/active'/safe_component(job.project_id, label='project_id')/safe_component(job.job_id, label='job_id')/safe_component(unit.work_unit_id, label='work_unit_id')
            if _unlinked(active).exists():
                raise RuntimeError('local_worker_pending_remote_work')
        # Even an uncached prepared/queued run must not be started by a restart.
        active = _unlinked(self.root/'runs/active')
        if active.exists():
            for base, directories, names in os.walk(active, followlinks=False, onerror=_walk_unavailable):
                current = _unlinked(Path(base))
                for name in directories:
                    _unlinked(current/name)
                if names or len(current.relative_to(active).parts) >= 3:
                    raise RuntimeError('local_worker_pending_remote_work')

    def idle(self, *, live: bool):
        self.guard()
        value = self.harness.supervisor_status()
        try:
            observed = datetime.fromisoformat(value['updated_at'].replace('Z', '+00:00'))
            if (value.get('machine_id') != self.config.machine_id or value.get('active_run_ids') != []
                    or observed.tzinfo is None or not -5 <= (datetime.now(timezone.utc)-observed).total_seconds() <= 60
                    or (live and value.get('running') is not True)
                    or value.get('runtime_version') not in {self.config.runtime_version, self.candidate.runtime_version if self.candidate else self.config.runtime_version}
                    or (value.get('root_uuid') is not None and value['root_uuid'] != self.root_uuid)
                    or (self.config.root_uuid is not None and value.get('root_uuid') != self.root_uuid)):
                raise ValueError('idle evidence mismatch')
        except (KeyError, TypeError, ValueError):
            raise RuntimeError('local_worker_fresh_idle_not_proven') from None
        return value

    def _powershell(self, script: str, *, timeout: int = 45):
        frame = inspect.currentframe().f_back
        names = ('supervisor_status', '_require_remote_supervisor_pythonw',
                 '_lock_managed_python_workbench_path', 'restart_supervisor')
        if (self.harness is None or frame.f_locals.get('self') is not self.harness
                or not any(frame.f_code is getattr(SshAcceptanceHarness, n).__code__ for n in names)):
            raise RuntimeError('local_worker_fixed_harness_scripts_only')
        self.guard()
        # stdin avoids both cmd.exe limits and loopback SSH's stuck close channel.
        environment = dict(os.environ)
        environment.pop('PSModulePath', None)
        executable = _powershell_executable()
        wrapped = ("try {\n$ErrorActionPreference='Stop'\n$ProgressPreference='SilentlyContinue'\n"
            + script + "\nif (-not $?) { throw 'fixed script failed' }\nexit 0\n"
            + "} catch { [Console]::Error.WriteLine('local_worker_fixed_script_error'); exit 1 }\n\n")
        return subprocess.run([str(executable), '-NoProfile', '-NonInteractive', '-Command', '-'],
            input=wrapped, capture_output=True, text=True,
            timeout=timeout, check=False, env=environment, creationflags=subprocess.CREATE_NO_WINDOW)

    @staticmethod
    def _require_success(completed, action):
        if completed.returncode:
            raise RuntimeError(f'local_worker_fixed_script_failed:{action}:exit={completed.returncode}')

    def _verify_tree(self, destination: Path, contents: dict[str, bytes]):
        _unlinked(destination)
        seen = set()
        for base, directories, names in os.walk(destination, followlinks=False, onerror=_walk_unavailable):
            for name in directories:
                _unlinked(Path(base)/name)
            for name in names:
                path = _unlinked(Path(base)/name)
                relative = path.relative_to(destination).as_posix()
                if relative not in contents or _read(path) != contents[relative]:
                    raise RuntimeError('local_worker_runtime_directory_collision')
                seen.add(relative)
        if seen != set(contents):
            raise RuntimeError('local_worker_runtime_directory_collision')

    def upload_runtime(self, archive: Path, version: str):
        self.idle(live=True)
        contents = runtime_files(Path(archive), version, self.runtime_lock)
        versions = _unlinked(self.root/'agent/versions')
        if not versions.is_dir():
            raise RuntimeError('local_worker_runtime_parent_missing')
        destination = versions/version
        if destination.exists():
            self._verify_tree(destination, contents)
            return destination
        stage = versions/('.local-worker-stage-'+uuid4().hex)
        stage.mkdir()
        for name, raw in contents.items():
            target = stage.joinpath(*name.split('/'))
            target.parent.mkdir(parents=True, exist_ok=True)
            with _unlinked(target).open('xb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        self._verify_tree(stage, contents)
        self.idle(live=True)
        _unlinked(destination)
        # Windows rename refuses a destination collision; failed staging is retained.
        stage.rename(destination)
        self._verify_tree(destination, contents)
        return destination

    def upload_supervisor_config(self, local_config: Path, remote_config):
        self.guard()
        if Path(str(remote_config)).absolute() != self.config_path:
            raise RuntimeError('local_worker_config_destination_outside_scope')
        raw = _read(Path(local_config))
        value = json.loads(raw.decode('utf-8-sig'))
        allowed = [_authority(self.config.model_dump(mode='json'))]
        if self.candidate:
            allowed.append(_authority(self.candidate.model_dump(mode='json')))
        authority = _authority(value)
        if authority not in allowed or _authority(_json(self.config_path)) not in allowed:
            raise RuntimeError('local_worker_configuration_collision')
        # An original-config rollback must work after a failed start has left
        # no live heartbeat. guard() still proves identity, DRAIN and no work.
        if authority != allowed[0]:
            self.idle(live=True)
        temporary = self.config_path.with_name(self.config_path.name+'.local-partial-'+uuid4().hex)
        backup = self.config_path.with_name(self.config_path.name+'.local-backup-'+uuid4().hex)
        with _unlinked(temporary).open('xb') as stream:
            stream.write(raw);stream.flush();os.fsync(stream.fileno())
        # ReplaceFile preserves the original DACL and atomically retains old bytes.
        if not ctypes.windll.kernel32.ReplaceFileW(str(self.config_path), str(temporary), str(backup), 0, None, None):
            raise RuntimeError('local_worker_atomic_config_replace_failed')
        self.backups.append(str(backup))
        if _json(self.config_path) != value:
            raise RuntimeError('local_worker_configuration_readback_failed')


def deploy(service, machine_id: str, archive: Path, version: str, *, actor_id: str,
           state_root: Path, runtime_lock: Path) -> dict:
    _windows_identity()
    config = service.repository.get_machine_execution_config(machine_id)
    if config is None:
        raise RuntimeError('local_worker_registered_configuration_required')
    # Validate immutable bytes before invoking the harness or creating intent files.
    runtime_files(Path(archive), version, Path(runtime_lock))
    transport = NativeTransport(service, config, actor_id=actor_id, runtime_lock=runtime_lock)
    harness = SshAcceptanceHarness(service, project_root=Path(state_root), workspace_root=Path(state_root),
        machine_config=config, transport=transport)
    transport.harness = harness
    transport.candidate = config.model_copy(deep=True, update={'runtime_version':version,
        'execution_provenance':{**config.execution_provenance, 'previous_runtime_version':str(config.runtime_version or '')}})
    transport.idle(live=True)
    try:
        result = harness.deploy_sealed_runtime(Path(archive), version, actor_id=actor_id)
    except Exception:
        # The harness owns rollback. Its swallowed rollback exception is not
        # proof of recovery: independently require both config and fresh PID.
        recovered = False
        try:
            old = _authority(config.model_dump(mode='json'))
            formal = service.repository.get_machine_execution_config(machine_id)
            status = transport.idle(live=True)
            recovered = (_authority(_json(transport.config_path)) == old
                and formal is not None and _authority(formal.model_dump(mode='json')) == old
                and status.get('runtime_version') == config.runtime_version)
        except Exception:
            pass
        raise RuntimeError('local_worker_deploy_failed:rollback_verified='+str(recovered).lower()) from None
    transport.idle(live=True)
    supervisor = result['supervisor']
    return {k:result[k] for k in ('machine_id', 'previous_runtime_version', 'runtime_version')} | {
        'transport':'native-local-admin', 'root_marker_uuid':transport.root_uuid,
        'supervisor':{k:supervisor.get(k) for k in ('pid','updated_at','runtime_version','running')},
        'config_backup_paths':transport.backups}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('machine_id');parser.add_argument('archive', type=Path);parser.add_argument('runtime_version')
    parser.add_argument('--actor', required=True);parser.add_argument('--runtime-lock', type=Path, required=True)
    parser.add_argument('--database-url');parser.add_argument('--state-root', type=Path)
    args = parser.parse_args(argv)
    _windows_identity()
    from .paths import ControlPlanePaths, database_url
    from .repository import MetadataRepository
    from .runtime_policy import RuntimePolicy, STABLE_RUNTIME_VERSION
    from .service import NetworkService
    runtime_files(args.archive, args.runtime_version, args.runtime_lock)
    policy = RuntimePolicy.with_candidates([] if args.runtime_version == STABLE_RUNTIME_VERSION else [args.runtime_version])
    service = NetworkService(MetadataRepository(database_url(args.database_url)), runtime_policy=policy)
    result = deploy(service, args.machine_id, args.archive, args.runtime_version, actor_id=args.actor,
        runtime_lock=args.runtime_lock, state_root=args.state_root or ControlPlanePaths.from_root().root)
    print(json.dumps(result, ensure_ascii=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
