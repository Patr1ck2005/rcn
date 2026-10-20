"""Fixed, fingerprinted process control for the production Dispatcher."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil

from .models import AuditEvent, DispatcherControlAction, DispatcherPhase
from .paths import ControlPlanePaths
from .repository import MetadataRepository
from .runtime_policy import DEFAULT_RUNTIME_POLICY, RuntimePolicy


def _command_hash(command: list[str]) -> str:
    return hashlib.sha256(json.dumps(command, separators=(",", ":")).encode("utf-8")).hexdigest()


def _normalized_command(command: list[str]) -> list[str]:
    """Ignore the Python launcher path, but retain every execution argument."""
    if not command:
        return []
    return [str(value) for value in command[1:]]


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


class DispatcherProcessController:
    """Control one known Dispatcher command without accepting user paths."""

    def __init__(
        self,
        repository: MetadataRepository,
        *,
        database_url: str,
        paths: ControlPlanePaths,
        runtime_policy: RuntimePolicy | None = None,
    ) -> None:
        self.repository = repository
        self.database_url = database_url
        self.paths = paths
        self.runtime_policy = runtime_policy or DEFAULT_RUNTIME_POLICY
        self.control_root = paths.root / "dispatcher" / "control"
        self.control_root.mkdir(parents=True, exist_ok=True)
        self.process_record = self.control_root / "process.json"
        self.stop_file = self.control_root / "stop.requested"
        self.drain_file = self.control_root / "drain.requested"
        self.wake_file = self.control_root / "wake.requested"
        self.stdout_path = self.control_root / "dispatcher.stdout.log"
        self.stderr_path = self.control_root / "dispatcher.stderr.log"

    def _command(self, *, once: bool = False, reconcile_only: bool = False) -> list[str]:
        command = [
            sys.executable,
            "-m",
            "research_compute_network.cli",
            "--database-url",
            self.database_url,
            "dispatch",
            "--owner-id",
            "dispatcher-web-control",
            "--origin-root",
            str(self.paths.origin_spool),
        ]
        for version in sorted(self.runtime_policy.candidate_runtime_versions):
            command.extend(["--canary-runtime-version", version])
        if once:
            command.append("--once")
        if reconcile_only:
            command.extend(["--reconcile-only", "--max-assignments-per-cycle", "0"])
        return command

    def _read_record(self) -> dict | None:
        if not self.process_record.is_file():
            return None
        try:
            return json.loads(self.process_record.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def _verified_process(self) -> psutil.Process | None:
        record = self._read_record()
        if not record:
            return None
        expected_command = record.get("command")
        if expected_command:
            created = float(record.get("created_at_epoch") or 0.0)
            try:
                process = psutil.Process(int(record["pid"]))
                if (
                    abs(process.create_time() - created) <= 1.0
                    and _normalized_command(process.cmdline()) == _normalized_command(expected_command)
                    and process.is_running()
                ):
                    return process
            except (KeyError, ValueError, psutil.Error):
                pass

            # ``Scripts\\python.exe`` is a short-lived launcher on Windows.
            # Match the actual interpreter by the complete argument contract
            # and reject any process that predates the recorded launch.
            for candidate in psutil.process_iter(["pid", "create_time", "cmdline"]):
                try:
                    if not candidate.is_running() or candidate.create_time() + 1.0 < created:
                        continue
                    if _normalized_command(candidate.cmdline()) != _normalized_command(expected_command):
                        continue
                    return candidate
                except (psutil.Error, OSError):
                    continue
            return None
        try:
            process = psutil.Process(int(record["pid"]))
            created = float(record["created_at_epoch"])
            if abs(process.create_time() - created) > 1.0:
                return None
            if _command_hash(process.cmdline()) != record["command_hash"]:
                return None
            return process if process.is_running() else None
        except (KeyError, ValueError, psutil.Error):
            return None

    def snapshot(self) -> dict:
        status = self.repository.get_dispatcher_status()
        lease = self.repository.get_dispatcher_lease()
        process = self._verified_process()
        payload = {
            "running": process is not None,
            "pid_verified": process is not None,
            "phase": status.phase.value,
            "accepting_assignments": status.accepting_assignments,
            "control_mode": status.control_mode,
            "desired_state": status.desired_state,
            "stop_reason": status.stop_reason,
            "blocked_reason": status.blocked_reason,
            "auto_resume_allowed": status.auto_resume_allowed,
            "last_recovered_at": (
                status.last_recovered_at.isoformat() if status.last_recovered_at else None
            ),
            "heartbeat_at": status.heartbeat_at.isoformat() if status.heartbeat_at else None,
            "lease_owner": lease.owner_id if lease else None,
            "lease_expires_at": lease.expires_at.isoformat() if lease else None,
            "pending_reconciliation": status.pending_reconciliation,
        }
        # Heartbeats and lease expiry move continuously while a healthy
        # Dispatcher is running.  They remain visible in the preview, but a
        # control ticket must only bind the safety-relevant process and
        # scheduling state; otherwise preview/confirm races every heartbeat.
        fingerprint_payload = {
            key: value
            for key, value in payload.items()
            if key not in {"heartbeat_at", "lease_expires_at"}
        }
        canonical = json.dumps(fingerprint_payload, sort_keys=True, separators=(",", ":"))
        payload["fingerprint"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return payload

    def reconcile(self) -> dict:
        completed = subprocess.run(
            self._command(once=True, reconcile_only=True),
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError((completed.stderr or completed.stdout or "dispatcher reconcile failed")[-1000:])
        return self.snapshot()

    def _launch_environment(self) -> dict[str, str]:
        env = os.environ.copy()
        if "RCN_SSH_IDENTITY_FILE" not in env:
            config_path = self.paths.root / "startup" / "supervision.json"
            try:
                config_path.lstat()
            except FileNotFoundError:
                pass  # Unmanaged/demo roots retain OpenSSH's legacy selection.
            else:
                from .coordinator_supervision import CoordinatorGuard
                from .origin_transfer import managed_path

                # Reuse the service's fixed configuration and runtime checks;
                # never infer an identity from another account's SSH directory.
                # These reads do not start, stop, or update the coordinator.
                config_path = managed_path(self.paths.root, "startup/supervision.json")
                _command, _runtime, service_env = CoordinatorGuard(config_path).launch_contract()
                env["RCN_SSH_IDENTITY_FILE"] = service_env["RCN_SSH_IDENTITY_FILE"]
        env["RCN_DISPATCHER_STOP_FILE"] = str(self.stop_file)
        env["RCN_DISPATCHER_DRAIN_FILE"] = str(self.drain_file)
        env["RCN_DISPATCHER_WAKE_FILE"] = str(self.wake_file)
        return env

    def start(self, *, reason: str = "", set_desired: bool = True) -> dict:
        if self._verified_process() is not None:
            if set_desired:
                self.drain_file.unlink(missing_ok=True)
                self.stop_file.unlink(missing_ok=True)
                status = self.repository.get_dispatcher_status()
                status.accepting_assignments = True
                status.control_mode = "open"
                status.desired_state = "open"
                status.stop_reason = ""
                status.blocked_reason = ""
                status.auto_resume_allowed = True
                self.repository.put_dispatcher_status(status)
            snapshot = self.snapshot()
            snapshot["outcome"] = "already_running"
            return snapshot
        lease = self.repository.get_dispatcher_lease()
        now = datetime.now(timezone.utc)
        if lease is not None and _aware(lease.expires_at) > now:
            raise RuntimeError("a live Dispatcher lease already exists")
        # Reject an invalid declared coordinator before changing stop intent
        # or persisting a starting state for a process that cannot be launched.
        env = self._launch_environment()
        # The normal lease-owning worker reconciles before dispatch, then on
        # every cycle. Remote reads must never be a prerequisite to starting
        # the API or spawning that worker (outage regression 2026-09-29).
        pending_reconciliation = self.repository.get_dispatcher_status().pending_reconciliation
        self.stop_file.unlink(missing_ok=True)
        status = self.repository.get_dispatcher_status()
        # An execution-started Attempt remains bound to its original machine
        # while unavailable. That machine-local quarantine prevents duplicate
        # science without draining unrelated healthy machines.
        status.accepting_assignments = True
        status.control_mode = "open"
        status.phase = DispatcherPhase.STARTING
        if set_desired:
            status.desired_state = "open"
        status.stop_reason = ""
        status.blocked_reason = (
            "quarantined_reconciliation" if pending_reconciliation else ""
        )
        self.drain_file.unlink(missing_ok=True)
        status.auto_resume_allowed = True
        status.last_recovered_at = datetime.now(timezone.utc)
        self.repository.put_dispatcher_status(status)
        command = self._command()
        creationflags = 0
        if os.name == "nt":
            # DETACHED_PROCESS can still be handed to the user's configured
            # Windows Terminal when redirected handles are present.  The
            # explicit no-window flag keeps the long-lived Dispatcher in the
            # Control Plane's background process tree without a visible tab.
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
        with self.stdout_path.open("a", encoding="utf-8") as stdout, self.stderr_path.open("a", encoding="utf-8") as stderr:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                env=env,
                creationflags=creationflags,
                close_fds=True,
            )
        ps_process = psutil.Process(process.pid)
        record = {
            "pid": process.pid,
            "created_at_epoch": ps_process.create_time(),
            "command_hash": _command_hash(command),
            "command": command,
            "started_at": datetime.now(timezone.utc).isoformat(),
        }
        temporary_record = self.process_record.with_suffix(".json.tmp")
        temporary_record.write_text(json.dumps(record, sort_keys=True, indent=2), encoding="utf-8")
        temporary_record.replace(self.process_record)
        snapshot = self.snapshot()
        snapshot["outcome"] = "started"
        snapshot["reason"] = reason
        snapshot["reconciliation_deferred"] = True
        snapshot["recovery_mode"] = pending_reconciliation > 0
        snapshot["recovery_scope"] = (
            "machine_local_quarantine" if pending_reconciliation else "none"
        )
        return snapshot

    def wake(self, *, reason: str = "event") -> None:
        """Request one prompt reconciliation through the fixed control root."""
        safe_reason = str(reason).replace("\r", " ").replace("\n", " ")[:160]
        self.wake_file.write_text(
            f"{datetime.now(timezone.utc).isoformat()} {safe_reason}\n",
            encoding="utf-8",
        )

    def drain(self, *, reason: str = "manual maintenance drain") -> dict:
        self.drain_file.write_text(datetime.now(timezone.utc).isoformat(), encoding="ascii")
        status = self.repository.get_dispatcher_status()
        status.accepting_assignments = False
        status.control_mode = "drain"
        status.desired_state = "drain"
        status.stop_reason = reason
        status.blocked_reason = "maintenance_drain"
        self.repository.put_dispatcher_status(status)
        return self.snapshot()

    def stop(self, *, timeout_s: float = 180, reason: str = "manual stop") -> dict:
        process = self._verified_process()
        if process is None:
            # Absence is not permission to kill a reused PID, fabricate a
            # process record or release another controller's active lease.
            self._require_stopped_evidence()
        requested_at = datetime.now(timezone.utc).isoformat()
        self.drain_file.write_text(requested_at, encoding="ascii")
        self.stop_file.write_text(requested_at, encoding="ascii")
        if process is not None:
            try:
                process.wait(timeout=timeout_s)
            except psutil.NoSuchProcess:
                pass  # The exact fingerprinted process exited before wait.
            except psutil.TimeoutExpired as exc:
                raise TimeoutError(f"Dispatcher did not stop cooperatively within {timeout_s:g} seconds") from exc
        else:
            self._require_stopped_evidence()
        self.process_record.unlink(missing_ok=True)
        status = self.repository.get_dispatcher_status()
        status.phase = DispatcherPhase.STOPPED
        status.accepting_assignments = False
        status.control_mode = "drain"
        status.desired_state = "stopped"
        status.stop_reason = reason
        status.blocked_reason = "manual_stop"
        self.repository.put_dispatcher_status(status)
        return self.snapshot() | {"outcome": "stopped" if process is not None else "already_stopped"}

    def _require_stopped_evidence(self) -> None:
        """Prove no lease or untracked exact command exists; never guess a PID."""
        lease = self.repository.get_dispatcher_lease()
        if lease is not None and _aware(lease.expires_at) > datetime.now(timezone.utc):
            raise RuntimeError("a live Dispatcher lease exists without a fingerprinted process")
        record = self._read_record()
        if self.process_record.exists() and (not isinstance(record, dict) or
                not isinstance(record.get("pid"), int) or not record.get("created_at_epoch")):
            raise RuntimeError("unverified Dispatcher process record; inspect before stopping")
        expected = _normalized_command(self._command())
        for candidate in psutil.process_iter(["pid", "name", "cmdline"]):
            info = candidate.info
            command = info.get("cmdline")
            if command and _normalized_command(command) == expected:
                raise RuntimeError("unverified Dispatcher process is still running; preserve its identity")
            if command is None and str(info.get("name", "")).lower() in {"python", "python3", "python.exe", "pythonw.exe"}:
                raise RuntimeError("unverified Dispatcher process observation; command access denied")

    def force_stop(self) -> dict:
        process = self._verified_process()
        if process is None:
            raise RuntimeError("Dispatcher PID, creation time, or command fingerprint does not match")
        process.kill()
        process.wait(timeout=30)
        self.drain_file.write_text(datetime.now(timezone.utc).isoformat(), encoding="ascii")
        self.repository.release_dispatcher_lease("dispatcher-web-control")
        status = self.repository.get_dispatcher_status()
        status.phase = DispatcherPhase.STOPPED
        status.accepting_assignments = False
        status.control_mode = "drain"
        status.desired_state = "stopped"
        status.stop_reason = "forced stop"
        status.blocked_reason = "forced_stop"
        status.auto_resume_allowed = False
        self.repository.put_dispatcher_status(status)
        self.process_record.unlink(missing_ok=True)
        return self.snapshot()

    def ensure_running(self, *, actor_id: str = "control-plane") -> dict:
        """Idempotently honor a previously approved open desired state."""
        status = self.repository.get_dispatcher_status()
        if status.desired_state != "open":
            raise RuntimeError(f"Dispatcher desired state is {status.desired_state}: {status.stop_reason or 'operator control'}")
        if not status.auto_resume_allowed:
            raise RuntimeError(f"Dispatcher automatic recovery is disabled: {status.blocked_reason or 'operator review required'}")
        if status.blocked_reason and status.blocked_reason not in {
            "pending_reconciliation",
            "quarantined_reconciliation",
        }:
            raise RuntimeError(f"Dispatcher is blocked: {status.blocked_reason}")
        result = self.start(reason=f"ensure-running:{actor_id}", set_desired=False)
        self.repository.append_event(
            AuditEvent(
                event_type="dispatcher.ensure_running",
                actor_id=actor_id,
                subject_type="dispatcher",
                subject_id="dispatcher",
                details={"outcome": result.get("outcome", "unknown")},
            )
        )
        return result

    def recover_desired_state(self) -> dict:
        status = self.repository.get_dispatcher_status()
        if status.desired_state != "open":
            return self.snapshot() | {"outcome": "desired_state_not_open"}
        return self.ensure_running(actor_id="control-plane-startup")

    def execute(self, action: DispatcherControlAction) -> dict:
        if action == DispatcherControlAction.START:
            return self.start(reason="admin start")
        if action == DispatcherControlAction.DRAIN:
            return self.drain()
        if action == DispatcherControlAction.STOP:
            return self.stop()
        if action == DispatcherControlAction.RESTART:
            self.stop(reason="admin restart")
            return self.start(reason="admin restart")
        if action == DispatcherControlAction.FORCE_STOP:
            return self.force_stop()
        if action == DispatcherControlAction.RECONCILE:
            return self.reconcile()
        raise ValueError(f"unsupported Dispatcher control action: {action.value}")
