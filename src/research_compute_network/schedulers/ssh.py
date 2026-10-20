"""Locked SSH transport and scheduler adapter for Windows workers."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import json
import os
import queue
import re
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
import zipfile
from pathlib import Path, PureWindowsPath
from typing import Callable, Protocol

from ..models import (
    Assignment,
    JobEnvelope,
    MachineExecutionConfig,
    RemoteRunRecord,
    RemoteRunState,
)
from ..hashing import sha256_file
from ..failure_diagnostics import safe_failure_reason, timeout_evidence, is_ssh_transport_failure
from ..remote_storage import RemoteLayout
from ..ssh_disk_probe import supervisor_status_with_disk_probe
from ..volume_budget import VolumeBudget, VolumeBudgetError, VolumeCapacityUnavailable, VolumeHolderBusy
from ..storage_roots import StorageRootError
from .base import PreLaunchSubmissionError, SubmissionUncertainError, SchedulerAdapter, SchedulerProbe


class SshTransportUnavailableError(RuntimeError):
    """SSH/SCP connection evidence: the machine transport itself failed.

    Subclasses :class:`RuntimeError` so every existing ``except Exception``
    boundary keeps working; the type only adds a machine-scoped signal for
    collection-failure handling in the Dispatcher.
    """

    reason_code = "ssh_transport_unavailable"


@dataclass(frozen=True)
class BundlePublicationAck:
    """A successful fresh .partial -> .ready reply, not a worker-start claim."""

    external_run_id: str
    bundle_sha256: str


class CollectionCapacityUnavailable(RuntimeError):
    """Known local storage pressure; retry collection of the same remote run."""

    def __init__(self, *, required_bytes: int, free_bytes: int | None, reserved_bytes: int | None,
                 reserve_bytes: int, reason_code: str = "storage_capacity_unavailable") -> None:
        super().__init__("center collection storage capacity is unavailable")
        self.required_bytes = required_bytes
        self.free_bytes = free_bytes
        self.reserved_bytes = reserved_bytes
        self.reserve_bytes = reserve_bytes
        self.reason_code = reason_code


_COLLECTION_RESERVE_BYTES = 10 * 1024**3
_COLLECTION_CAPACITY_LOCK = threading.Lock()
_COLLECTION_CAPACITY_RESERVATIONS: dict[int, dict[str, int]] = {}


def _reserve_collection_capacity(destination: Path, required_bytes: int) -> tuple[int, str]:
    ancestor = destination.absolute()
    while not ancestor.exists():
        ancestor = ancestor.parent
    volume = ancestor.stat().st_dev
    token = uuid.uuid4().hex
    with _COLLECTION_CAPACITY_LOCK:
        claims = _COLLECTION_CAPACITY_RESERVATIONS.get(volume, {})
        reserved = sum(claims.values())
        free = shutil.disk_usage(ancestor).free
        # Conservative: current free already reflects bytes written so far,
        # while claims retain each transfer's entire size until it finishes.
        if free < required_bytes + reserved + _COLLECTION_RESERVE_BYTES:
            raise CollectionCapacityUnavailable(required_bytes=required_bytes, free_bytes=free,
                reserved_bytes=reserved, reserve_bytes=_COLLECTION_RESERVE_BYTES)
        _COLLECTION_CAPACITY_RESERVATIONS.setdefault(volume, {})[token] = required_bytes
    return volume, token


def _release_collection_capacity(claim: tuple[int, str]) -> None:
    volume, token = claim
    with _COLLECTION_CAPACITY_LOCK:
        claims = _COLLECTION_CAPACITY_RESERVATIONS.get(volume, {})
        claims.pop(token, None)
        if not claims:
            _COLLECTION_CAPACITY_RESERVATIONS.pop(volume, None)


def _prelaunch_error(
    action: str,
    error: BaseException,
    *,
    default_timeout_s: float | None = None,
) -> PreLaunchSubmissionError:
    if isinstance(error, PreLaunchSubmissionError):
        return error
    if isinstance(error, (StorageRootError, VolumeBudgetError)):
        return PreLaunchSubmissionError(str(error), reason_code=error.reason_code,
                                       error_type=type(error).__name__)
    timeout = timeout_evidence(error)
    return PreLaunchSubmissionError(
        safe_failure_reason(
            error,
            action=action,
            default_timeout_s=default_timeout_s,
        ),
        reason_code="prelaunch_timeout" if timeout is not None else "prelaunch_failure",
        error_type=timeout[0] if timeout is not None else type(error).__name__,
        timeout_s=timeout[1] if timeout is not None else None,
    )


class CommandRunner(Protocol):
    def __call__(self, command: list[str], *, timeout: float) -> subprocess.CompletedProcess[str]: ...


class PreparedActivationChannel(Protocol):
    def activate(self, encoded_payload: str, external_run_id: str, *, timeout: float) -> bool: ...
    def close(self) -> None: ...


def stoppable_runner(stop_event: threading.Event):
    """Bound only this dispatcher's local SSH/SCP child for cooperative stop.

    No process lookup, port kill, remote termination or retry is performed.
    Publication-stage callers retain unknown delivery when interrupted.
    """
    def run(command: list[str], *, timeout: float):
        if stop_event.is_set():
            error = SshTransportUnavailableError("dispatcher transport stopping")
            error._rcn_writer_stopped = True
            raise error
        start = time.monotonic()
        try:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace",
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except OSError as exc:
            exc._rcn_writer_stopped = True  # Popen did not create a local writer.
            raise
        import psutil
        owned_children = {}
        def remember_children():
            if process.poll() is not None:
                return
            try:
                for child in psutil.Process(process.pid).children(recursive=True):
                    owned_children[(child.pid, child.create_time())] = child
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        failure = None
        result = None
        partial_stdout = partial_stderr = None
        try:
            while True:
                remember_children()
                if stop_event.is_set():
                    raise SshTransportUnavailableError("dispatcher transport interrupted for cooperative stop")
                remaining = timeout - (time.monotonic() - start)
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, timeout,
                        output=partial_stdout, stderr=partial_stderr)
                try:
                    stdout, stderr = process.communicate(timeout=min(.25, remaining))
                    result = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
                    return result
                except subprocess.TimeoutExpired as pending:
                    # communicate() reports the complete accumulated buffers,
                    # not a delta. Preserve them on the eventual timeout; only
                    # identity-bound read callers may consume a full receipt.
                    if pending.output is not None:
                        partial_stdout = pending.output
                    if pending.stderr is not None:
                        partial_stderr = pending.stderr
                    continue
        except BaseException as exc:
            failure = exc
            raise
        finally:
            remember_children()
            # SCP may own an SSH child which inherits its output pipe. Killing
            # only the SCP parent can leave communicate() blocked forever.
            # These Process objects were observed below our own Popen child and
            # psutil rechecks creation identity; never search by executable/port.
            for child in reversed(list(owned_children.values())):
                try:
                    if child.is_running():
                        child.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            if process.poll() is None:
                process.kill()
            try:
                process.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                for stream in (process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()
            # A durable capacity claim cannot be freed on an interruption unless
            # this exact local writer and all observed children really exited.
            stopped = process.poll() is not None
            for child in owned_children.values():
                try:
                    child.wait(timeout=2)
                except psutil.NoSuchProcess:
                    pass
                except (psutil.TimeoutExpired, psutil.AccessDenied):
                    stopped = False
            if failure is not None and stopped:
                failure._rcn_writer_stopped = True
            if result is not None:
                result._rcn_writer_stopped = stopped
    run._rcn_stop_event = stop_event
    return run


def _run(command: list[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
    # Windows workers can emit localized PowerShell/SSH diagnostics (often in
    # the system GBK code page) alongside the UTF-8 JSON payload we consume.
    # Explicit replacement decoding keeps a diagnostic byte from killing the
    # reader thread and leaving a remote run stuck in ``running``.
    # The Dispatcher makes frequent, bounded SSH status calls.  On Windows a
    # background Python service otherwise lets each child create a transient
    # console window, which is both distracting and unrelated to its results.
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        creationflags=creationflags,
    )


_ANSI_ESCAPE_RE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
_ACTIVATION_FRAME_RE = re.compile(
    r"(RCN-ACTIVATE (?:READY|OK [A-Za-z0-9_.-]+|ERR [A-Za-z0-9_.-]+))\s*$"
)


def _activation_protocol_frame(value: str) -> str | None:
    """Extract a protocol frame from noisy OpenSSH pseudo-terminal output."""

    normalized = _ANSI_ESCAPE_RE.sub("", value).replace("\r", "").strip()
    match = _ACTIVATION_FRAME_RE.search(normalized)
    return match.group(1) if match is not None else None


class _OpenSshPreparedActivationChannel:
    """Preconnected one-shot channel that hides SSH setup before slot release."""

    def __init__(self, command: list[str], external_run_id: str, *, ready_timeout: float = 15,
                 stop_event: threading.Event | None = None) -> None:
        self.stop_event = stop_event
        if stop_event is not None and stop_event.is_set():
            raise SshTransportUnavailableError("activation channel stopping before connection")
        self.external_run_id = external_run_id
        self._responses: queue.Queue[str] = queue.Queue()
        self._stderr: list[str] = []
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        self.process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            creationflags=creationflags,
        )
        threading.Thread(target=self._read_stdout, daemon=True).start()
        threading.Thread(target=self._read_stderr, daemon=True).start()
        try:
            deadline = time.monotonic() + ready_timeout
            while True:
                if self.stop_event is not None and self.stop_event.is_set():
                    self.close()
                    raise SshTransportUnavailableError("activation readiness interrupted for cooperative stop")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise queue.Empty
                try:
                    response = self._responses.get(timeout=min(.25, remaining))
                except queue.Empty:
                    continue
                if response == "RCN-ACTIVATE READY":
                    break
        except queue.Empty as exc:
            self.close()
            detail = "; ".join(self._stderr[-3:]) or "no readiness acknowledgement"
            raise TimeoutError(f"prepared activation channel did not become ready: {detail}") from exc

    def _read_stdout(self) -> None:
        if self.process.stdout is None:
            return
        for line in self.process.stdout:
            frame = _activation_protocol_frame(line)
            if frame is not None:
                self._responses.put(frame)

    def _read_stderr(self) -> None:
        if self.process.stderr is None:
            return
        for line in self.process.stderr:
            value = line.strip()
            if value:
                self._stderr.append(value[:500])
                del self._stderr[:-8]

    def activate(self, encoded_payload: str, external_run_id: str, *, timeout: float) -> bool:
        if self.stop_event is not None and self.stop_event.is_set():
            self.close()
            return False
        if external_run_id != self.external_run_id or self.process.poll() is not None:
            return False
        if self.process.stdin is None:
            return False
        try:
            self.process.stdin.write(encoded_payload + "\n")
            self.process.stdin.flush()
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                remaining = max(0.01, deadline - time.monotonic())
                response = self._responses.get(timeout=remaining)
                if response == f"RCN-ACTIVATE OK {external_run_id}":
                    return True
                if response.startswith("RCN-ACTIVATE ERR "):
                    return False
        except (BrokenPipeError, OSError, queue.Empty):
            return False
        return False

    def close(self) -> None:
        if self.process.stdin is not None:
            try:
                self.process.stdin.close()
            except OSError:
                pass
        if self.process.poll() is None:
            try:
                self.process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                try:
                    self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=2)


_PREPARED_ACTIVATION_CHANNELS: dict[tuple[str, str], PreparedActivationChannel] = {}
_PREPARED_ACTIVATION_CHANNELS_LOCK = threading.Lock()


def close_owned_activation_channels(stop_event: threading.Event) -> int:
    """Close only warm channels owned by this exact Dispatcher stop identity."""
    with _PREPARED_ACTIVATION_CHANNELS_LOCK:
        keys = [key for key, channel in _PREPARED_ACTIVATION_CHANNELS.items()
                if getattr(channel, "stop_event", None) is stop_event]
        channels = [_PREPARED_ACTIVATION_CHANNELS.pop(key) for key in keys]
    for channel in channels:
        channel.close()
    return len(channels)


class SshTransport(Protocol):
    def probe(self) -> SchedulerProbe: ...
    def stage_bundle(self, external_run_id: str, bundle_zip: Path) -> BundlePublicationAck | None: ...
    def read_status(self, external_run_id: str) -> dict: ...
    def read_supervisor_status(self) -> dict: ...
    def request_cancel(self, external_run_id: str) -> None: ...
    def activate_prepared(self, external_run_id: str) -> None: ...
    def download_outputs(self, external_run_id: str, destination: Path) -> list[str]: ...

    def install_tunnel_task(self, script: str, task_xml: str, *, task_name: str) -> dict: ...

    def bootstrap_tunnel_identity(self) -> dict: ...


def _safe_external_id(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", value):
        raise ValueError("external run ID contains unsafe characters")
    return value


class OpenSshTransport:
    """OpenSSH implementation with a dedicated pinned known-hosts file."""

    def __init__(
        self,
        config: MachineExecutionConfig,
        *,
        state_root: str | Path,
        runner: CommandRunner = _run,
        activation_channel_factory: Callable[[list[str], str], PreparedActivationChannel] | None = None,
        identity_file: str | Path | None = None,
        budget_database: str | Path | None = None,
        collection_storage_validator: Callable[[], Path] | None = None,
    ) -> None:
        self.config = config
        self.layout = RemoteLayout.from_string(config.remote_root)
        self.state_root = Path(state_root)
        self.runner = runner
        self.volume_budget = VolumeBudget(budget_database) if budget_database is not None else None
        self.collection_storage_validator = collection_storage_validator
        # Service-local operator identity, never a key value in machine metadata.
        # Keep legacy selection unchanged unless an operator explicitly selects it.
        selected_identity = identity_file if identity_file is not None else os.environ.get("RCN_SSH_IDENTITY_FILE")
        self.identity_file: Path | None = None
        if selected_identity is not None:
            if not str(selected_identity).strip():
                raise ValueError("configured SSH identity path must not be empty")
            selected_path = Path(selected_identity).expanduser()
            if not selected_path.is_absolute():
                raise ValueError("configured SSH identity path must be absolute")
            if not selected_path.is_file():
                raise ValueError("configured SSH identity file is unavailable")
            self.identity_file = selected_path.resolve()
        self.activation_channel_factory = activation_channel_factory
        stop_event = getattr(runner, "_rcn_stop_event", None)
        if activation_channel_factory is None and (runner is _run or stop_event is not None):
            self.activation_channel_factory = (
                lambda command, external: _OpenSshPreparedActivationChannel(command, external, stop_event=stop_event)
            )
        self.known_hosts = self.state_root / "known_hosts" / f"{config.machine_id}.known_hosts"

    def _activation_channel_key(self, external_run_id: str) -> tuple[str, str]:
        return self.config.machine_id, external_run_id

    def _drop_activation_channel(self, external_run_id: str) -> PreparedActivationChannel | None:
        key = self._activation_channel_key(external_run_id)
        with _PREPARED_ACTIVATION_CHANNELS_LOCK:
            return _PREPARED_ACTIVATION_CHANNELS.pop(key, None)

    def prepare_activation_channel(self, external_run_id: str) -> bool:
        external = _safe_external_id(external_run_id)
        if self.activation_channel_factory is None:
            return False
        activation_dir = self.layout.root / "spool" / "activations"
        script = f"""
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$activationDir='{activation_dir}'
New-Item -ItemType Directory -Force -Path $activationDir | Out-Null
[Console]::Out.WriteLine('RCN-ACTIVATE READY')
[Console]::Out.Flush()
try {{
  $line=[Console]::In.ReadLine()
  if ($null -eq $line) {{ throw 'activation channel closed before authorization' }}
  $bytes=[Convert]::FromBase64String($line)
  $payload=[Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
  $external=[string]$payload.external_run_id
  if ($external -notmatch '^[A-Za-z0-9_.-]+$') {{ throw 'unsafe external run ID' }}
  $partial=Join-Path $activationDir ($external + '.partial')
  $ready=Join-Path $activationDir ($external + '.ready')
  if (-not (Test-Path -LiteralPath $ready)) {{
    [IO.File]::WriteAllBytes($partial,$bytes)
    Move-Item -LiteralPath $partial -Destination $ready -Force -ErrorAction Stop
  }}
  [Console]::Out.WriteLine('RCN-ACTIVATE OK ' + $external)
  [Console]::Out.Flush()
}} catch {{
  [Console]::Out.WriteLine('RCN-ACTIVATE ERR ' + $_.Exception.GetType().Name)
  [Console]::Out.Flush()
  exit 3
}}
"""
        encoded_script = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        bootstrap = (
            "$script=[Text.Encoding]::Unicode.GetString("
            f"[Convert]::FromBase64String('{encoded_script}')); "
            "Invoke-Expression $script"
        )
        # Windows OpenSSH does not reliably forward delayed stdin to a remote
        # PowerShell process without a pseudo-terminal.  The prepared channel
        # carries only a small, one-shot activation frame, so a PTY is safe;
        # its input echo and terminal control sequences are filtered by the
        # protocol reader above.
        ssh_base = self._ssh_base()
        command = [
            *ssh_base[:-1],
            "-tt",
            ssh_base[-1],
            "powershell",
            "-NoProfile",
            "-Command",
            bootstrap,
        ]
        try:
            channel = self.activation_channel_factory(command, external)
        except (OSError, RuntimeError, TimeoutError):
            return False
        key = self._activation_channel_key(external)
        with _PREPARED_ACTIVATION_CHANNELS_LOCK:
            previous = _PREPARED_ACTIVATION_CHANNELS.pop(key, None)
            _PREPARED_ACTIVATION_CHANNELS[key] = channel
        if previous is not None:
            previous.close()
        return True

    def prepare_known_hosts(self) -> Path:
        line = self.config.pinned_host_key.strip()
        if not line:
            raise ValueError("a pinned SSH host key is required")
        if not any(kind in line for kind in ("ssh-ed25519", "ecdsa-sha2-", "ssh-rsa")):
            raise ValueError("pinned SSH host key must contain a supported public-key type")
        self.known_hosts.parent.mkdir(parents=True, exist_ok=True)
        expected = line + "\n"
        # Concurrent connections to one machine share this per-machine file,
        # and the pinned key for a machine never varies within a process. An
        # in-place rewrite opens a truncated window that a concurrent ssh
        # reader observes as "No ED25519 host key is known ... strict
        # checking" (production incident 2026-09-01). So: skip the write when
        # the content already matches, and otherwise publish atomically via a
        # unique temp file plus replace, retrying while a reader holds the
        # target open. Never truncate the live file in place.
        try:
            if self.known_hosts.read_text(encoding="utf-8") == expected:
                return self.known_hosts
        except OSError:
            pass
        temp_path = self.known_hosts.with_name(
            "%s.%s.%s.tmp" % (self.known_hosts.name, os.getpid(), threading.get_ident())
        )
        try:
            temp_path.write_text(expected, encoding="utf-8")
            last_error: PermissionError | None = None
            for attempt in range(10):
                try:
                    os.replace(temp_path, self.known_hosts)
                    return self.known_hosts
                except PermissionError as exc:
                    # A concurrent reader still holds the target open (Windows
                    # denies replace without FILE_SHARE_DELETE). Real ssh
                    # clients release it within milliseconds.
                    last_error = exc
                    time.sleep(0.005 * (attempt + 1))
            assert last_error is not None
            raise last_error
        finally:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass

    @property
    def tunnel_identity_path(self) -> PureWindowsPath:
        return self.layout.root / "agent" / "tunnel" / "coordinator_boot_ed25519"

    @property
    def tunnel_known_hosts_path(self) -> PureWindowsPath:
        return self.layout.root / "agent" / "tunnel" / "coordinator_known_hosts"

    def _ssh_base(self) -> list[str]:
        self.prepare_known_hosts()
        return [
            "ssh",
            *self._operator_identity_options(),
            "-p",
            str(self.config.ssh_port),
            "-o",
            "BatchMode=yes",
            "-o",
            f"ConnectTimeout={self.config.ssh_connect_timeout_s or 5}",
            "-o",
            "ConnectionAttempts=1",
            "-o",
            "ServerAliveInterval=5",
            "-o",
            "ServerAliveCountMax=2",
            "-o",
            "TCPKeepAlive=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={self.known_hosts}",
            f"{self.config.ssh_user}@{self.config.ssh_host}",
        ]

    def _scp_base(self) -> list[str]:
        self.prepare_known_hosts()
        return [
            "scp",
            *self._operator_identity_options(),
            "-P",
            str(self.config.ssh_port),
            "-o",
            "BatchMode=yes",
            "-o",
            f"ConnectTimeout={self.config.ssh_connect_timeout_s or 5}",
            "-o",
            "ConnectionAttempts=1",
            "-o",
            "ServerAliveInterval=5",
            "-o",
            "ServerAliveCountMax=2",
            "-o",
            "TCPKeepAlive=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={self.known_hosts}",
        ]

    def _operator_identity_options(self) -> list[str]:
        if self.identity_file is None:
            return []
        return ["-i", str(self.identity_file), "-o", "IdentitiesOnly=yes"]

    def _powershell(self, script: str, *, timeout: float = 45) -> subprocess.CompletedProcess[str]:
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        completed = self.runner(
            [*self._ssh_base(), "powershell", "-NoProfile", "-EncodedCommand", encoded],
            timeout=timeout,
        )
        return completed

    @staticmethod
    def _require_success(completed: subprocess.CompletedProcess[str], action: str) -> None:
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()
            message = safe_failure_reason(detail, action=f"SSH {action}")
            # Exit 255 can also originate from the remote command. Never
            # downgrade integrity/unknown failures merely because of this code.
            if is_ssh_transport_failure(message):
                raise SshTransportUnavailableError(message)
            raise RuntimeError(message)

    def probe(self) -> SchedulerProbe:
        if shutil.which("ssh") is None or shutil.which("scp") is None:
            return SchedulerProbe(adapter="ssh", available=False, errors=["OpenSSH client tools are unavailable"])
        script = "$PSVersionTable.PSVersion.ToString(); $env:COMPUTERNAME"
        try:
            completed = self._powershell(script, timeout=20)
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            return SchedulerProbe(
                adapter="ssh",
                available=False,
                errors=[safe_failure_reason(exc, action="SSH probe", default_timeout_s=20)],
            )
        lines = [line.strip() for line in completed.stdout.splitlines() if line.strip() and not line.startswith("#<")]
        return SchedulerProbe(
            adapter="ssh",
            available=completed.returncode == 0,
            version=lines[0] if lines else None,
            details={"host": self.config.ssh_host, "port": self.config.ssh_port, "machine": lines[-1] if lines else None},
            errors=(
                []
                if completed.returncode == 0
                else [
                    safe_failure_reason(
                        completed.stderr or completed.stdout,
                        action="SSH probe",
                    )
                ]
            ),
        )

    @staticmethod
    def _scp_remote(path: PureWindowsPath) -> str:
        return str(path).replace("\\", "/")

    def stage_bundle(self, external_run_id: str, bundle_zip: Path) -> BundlePublicationAck | None:
        external = _safe_external_id(external_run_id)
        if not bundle_zip.is_file():
            raise FileNotFoundError(bundle_zip)
        incoming = self.layout.incoming
        partial = incoming / f"{external}.partial"
        ready = incoming / f"{external}.ready"
        try:
            prepare = self._powershell(
                f"$p='{incoming}'; New-Item -ItemType Directory -Force -Path $p | Out-Null; "
                f"if (Test-Path -LiteralPath '{ready}') {{ exit 23 }}; "
                f"if (Test-Path -LiteralPath '{partial}') {{ Remove-Item -LiteralPath '{partial}' -Force }}"
            )
        except Exception as exc:
            raise _prelaunch_error("SSH prepare incoming bundle", exc, default_timeout_s=45) from exc
        if prepare.returncode == 23:
            return
        try:
            self._require_success(prepare, "prepare incoming bundle")
        except Exception as exc:
            raise _prelaunch_error("SSH prepare incoming bundle", exc) from exc
        remote = f"{self.config.ssh_user}@{self.config.ssh_host}:{self._scp_remote(partial)}"
        try:
            uploaded = self.runner([*self._scp_base(), str(bundle_zip), remote], timeout=300)
        except Exception as exc:
            raise _prelaunch_error("SSH upload bundle", exc, default_timeout_s=300) from exc
        try:
            self._require_success(uploaded, "upload bundle")
        except Exception as exc:
            raise _prelaunch_error("SSH upload bundle", exc) from exc
        # From this call onward the server may have published .ready even if
        # the response is lost. Do not let the adapter reclassify it as safe
        # pre-launch and release its original durable execution identity.
        try:
            activated = self._powershell(
                f"Move-Item -LiteralPath '{partial}' -Destination '{ready}' -ErrorAction Stop"
            )
            self._require_success(activated, "activate bundle")
        except Exception as exc:
            raise SubmissionUncertainError(
                safe_failure_reason(exc, action="SSH publication acknowledgement"),
                external_run_id=external,
            ) from exc
        return BundlePublicationAck(external, sha256_file(bundle_zip))

    def upload_cache_object(self, source: Path, sha256: str) -> PureWindowsPath:
        if not re.fullmatch(r"[0-9a-f]{64}", sha256):
            raise ValueError("cache object hash must be lowercase SHA-256")
        destination_dir = self.layout.root / "cache" / "objects" / sha256
        destination = destination_dir / source.name
        # Preparation runs concurrently. A shared ``<name>.partial`` lets two
        # uploads of the same immutable object overwrite or move each other's
        # staging file. Give each publisher its own path and accept a matching
        # destination when another publisher wins the race.
        partial = destination.with_name(
            f"{destination.name}.{uuid.uuid4().hex}.partial"
        )
        verified = destination.with_suffix(destination.suffix + ".sha256")
        check = self._powershell(
            f"if (Test-Path -LiteralPath '{destination}') {{ "
            f"if (Test-Path -LiteralPath '{verified}') {{ "
            f"try {{ $v=(Get-Content -LiteralPath '{verified}' -Raw -ErrorAction Stop).Trim().ToLower() }} "
            f"catch {{ $v='' }}; if ($v -eq '{sha256}') {{ exit 0 }} }}; "
            f"try {{ $h=(Get-FileHash -Algorithm SHA256 -LiteralPath '{destination}' -ErrorAction Stop).Hash.ToLower() }} "
            f"catch {{ exit 27 }}; "
            f"if ($h -eq '{sha256}') {{ Set-Content -LiteralPath '{verified}' -Value '{sha256}' -Encoding ASCII; exit 0 }} "
            f"else {{ exit 24 }} }}; "
            f"New-Item -ItemType Directory -Force -Path '{destination_dir}' | Out-Null; exit 25"
        )
        if check.returncode == 0:
            return destination
        if check.returncode == 24:
            observed = self._powershell(
                f"$h=(Get-FileHash -Algorithm SHA256 -LiteralPath '{destination}').Hash.ToLower(); "
                f"[pscustomobject]@{{path='{destination}'; expected='{sha256}'; actual=$h}} "
                "| ConvertTo-Json -Compress",
                timeout=60,
            )
            detail = ""
            for line in observed.stdout.splitlines():
                line = line.strip()
                if line.startswith("{") and line.endswith("}"):
                    detail = line
                    break
            raise RuntimeError(
                "remote cache object exists with a different hash: "
                f"{detail or destination}"
            )
        if check.returncode == 27:
            raise RuntimeError(
                "remote cache object is busy and could not be hashed; retry later: "
                f"{destination}"
            )
        if check.returncode != 25:
            self._require_success(check, "inspect cache object")
        remote = f"{self.config.ssh_user}@{self.config.ssh_host}:{self._scp_remote(partial)}"
        uploaded = self.runner([*self._scp_base(), str(source), remote], timeout=1200)
        self._require_success(uploaded, "upload cache object")
        activated = self._powershell(
            f"$partial='{partial}'; $destination='{destination}'; $verified='{verified}'; "
            f"$expected='{sha256}'; "
            "$h=(Get-FileHash -Algorithm SHA256 -LiteralPath $partial -ErrorAction Stop).Hash.ToLower(); "
            "if ($h -ne $expected) { Remove-Item -LiteralPath $partial -Force -ErrorAction SilentlyContinue; exit 26 }; "
            "if (Test-Path -LiteralPath $destination) { "
            "$existing=(Get-FileHash -Algorithm SHA256 -LiteralPath $destination -ErrorAction Stop).Hash.ToLower(); "
            "if ($existing -ne $expected) { Remove-Item -LiteralPath $partial -Force -ErrorAction SilentlyContinue; exit 24 }; "
            "Remove-Item -LiteralPath $partial -Force -ErrorAction SilentlyContinue "
            "} else { "
            "try { Move-Item -LiteralPath $partial -Destination $destination -ErrorAction Stop } "
            "catch { "
            "if (-not (Test-Path -LiteralPath $destination)) { throw }; "
            "$existing=(Get-FileHash -Algorithm SHA256 -LiteralPath $destination -ErrorAction Stop).Hash.ToLower(); "
            "if ($existing -ne $expected) { throw }; "
            "Remove-Item -LiteralPath $partial -Force -ErrorAction SilentlyContinue "
            "} }; "
            "try { Set-Content -LiteralPath $verified -Value $expected -Encoding ASCII -ErrorAction Stop } "
            "catch { "
            "$v=(Get-Content -LiteralPath $verified -Raw -ErrorAction Stop).Trim().ToLower(); "
            "if ($v -ne $expected) { throw } "
            "}",
            timeout=300,
        )
        self._require_success(activated, "verify cache object")
        return destination

    def upload_runtime(self, archive: Path, version: str) -> PureWindowsPath:
        version = _safe_external_id(version)
        destination = self.layout.root / "agent" / "versions" / version
        marker = destination / "runtime-manifest.json"
        check = self._powershell(f"if (Test-Path -LiteralPath '{marker}') {{ exit 0 }} else {{ exit 25 }}")
        if check.returncode == 0:
            return destination
        if check.returncode != 25:
            self._require_success(check, "inspect runtime")
        versions = destination.parent
        remote_archive = versions / f"{version}.partial.zip"
        prepared = self._powershell(f"New-Item -ItemType Directory -Force -Path '{versions}' | Out-Null")
        self._require_success(prepared, "prepare runtime directory")
        remote = f"{self.config.ssh_user}@{self.config.ssh_host}:{self._scp_remote(remote_archive)}"
        uploaded = self.runner([*self._scp_base(), str(archive), remote], timeout=1200)
        self._require_success(uploaded, "upload runtime")
        expanded = self._powershell(
            f"if (Test-Path -LiteralPath '{destination}') {{ Remove-Item -LiteralPath '{destination}' -Recurse -Force }}; "
            f"Expand-Archive -LiteralPath '{remote_archive}' -DestinationPath '{destination}' -Force; "
            f"Remove-Item -LiteralPath '{remote_archive}' -Force; "
            f"if (-not (Test-Path -LiteralPath '{marker}')) {{ exit 27 }}",
            timeout=600,
        )
        self._require_success(expanded, "activate runtime")
        return destination

    def upload_supervisor_config(self, local_config: Path, remote_config: PureWindowsPath) -> None:
        partial = remote_config.with_suffix(remote_config.suffix + ".partial")
        prepared = self._powershell(
            f"New-Item -ItemType Directory -Force -Path '{remote_config.parent}' | Out-Null"
        )
        self._require_success(prepared, "prepare supervisor configuration")
        remote = f"{self.config.ssh_user}@{self.config.ssh_host}:{self._scp_remote(partial)}"
        uploaded = self.runner([*self._scp_base(), str(local_config), remote], timeout=60)
        self._require_success(uploaded, "upload supervisor configuration")
        activated = self._powershell(
            f"Move-Item -LiteralPath '{partial}' -Destination '{remote_config}' -Force -ErrorAction Stop"
        )
        self._require_success(activated, "activate supervisor configuration")

    def install_tunnel_task(self, script: str, task_xml: str, *, task_name: str) -> dict:
        """Install and run the fixed reverse-SSH task on the worker.

        The only remote paths used here are under the configured RCN root;
        callers cannot supply a command, a remote path, or a credential.  The
        task XML is generated locally and is transferred as UTF-16 because
        Windows Task Scheduler rejects XML whose declaration and encoding do
        not agree.
        """
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", task_name):
            raise ValueError("unsafe task name")
        tunnel_dir = self.layout.root / "agent" / "tunnel"
        script_path = tunnel_dir / "reverse-ssh.ps1"
        xml_path = tunnel_dir / "task.xml"
        with tempfile.TemporaryDirectory(prefix="rcn-tunnel-") as tmp:
            local_script = Path(tmp) / "reverse-ssh.ps1"
            local_xml = Path(tmp) / "task.xml"
            local_script.write_text(script, encoding="utf-8")
            local_xml.write_text(task_xml, encoding="utf-16")
            prepared = self._powershell(f"New-Item -ItemType Directory -Force -Path '{tunnel_dir}' | Out-Null")
            self._require_success(prepared, "prepare tunnel task directory")
            for source, destination in ((local_script, script_path), (local_xml, xml_path)):
                partial = destination.with_suffix(destination.suffix + ".partial")
                remote = f"{self.config.ssh_user}@{self.config.ssh_host}:{self._scp_remote(partial)}"
                uploaded = self.runner([*self._scp_base(), str(source), remote], timeout=60)
                self._require_success(uploaded, "upload tunnel task file")
                activated = self._powershell(
                    f"Move-Item -LiteralPath '{partial}' -Destination '{destination}' -Force -ErrorAction Stop"
                )
                self._require_success(activated, "activate tunnel task file")
        command = (
            f"schtasks.exe /Create /TN '{task_name}' /XML '{xml_path}' /F; "
            f"if ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}; "
            f"schtasks.exe /Run /TN '{task_name}'"
        )
        registered = self._powershell(command, timeout=60)
        self._require_success(registered, "register reverse-SSH task")
        return {"task_name": task_name, "script_path": str(script_path), "task_xml_path": str(xml_path)}

    def bootstrap_tunnel_identity(self) -> dict:
        """Create and authorize the fixed machine-level tunnel identity.

        The private key is generated on the worker and never crosses SSH.  The
        currently authenticated worker account is used exactly once to append
        the generated public key to the coordinator administrator key file.
        The coordinator host key must already exist in the worker user's
        known-hosts file; this method never performs trust-on-first-use.
        """
        tunnel_dir = self.layout.root / "agent" / "tunnel"
        identity = self.tunnel_identity_path
        public_key = PureWindowsPath(str(identity) + ".pub")
        pinned_hosts = self.tunnel_known_hosts_path
        coordinator_host = self.config.coordinator_host.replace("'", "''")
        coordinator_user = self.config.coordinator_user.replace("'", "''")
        prepare_script = f"""
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$tunnelDir='{tunnel_dir}'
$identity='{identity}'
$publicKey='{public_key}'
$pinnedHosts='{pinned_hosts}'
$coordinatorHost='{coordinator_host}'
$sshKeygen=Join-Path $env:SystemRoot 'System32\\OpenSSH\\ssh-keygen.exe'
if (-not (Test-Path -LiteralPath $sshKeygen)) {{ $sshKeygen=(Get-Command ssh-keygen.exe -ErrorAction Stop).Source }}
New-Item -ItemType Directory -Force -Path $tunnelDir | Out-Null
$identityCreated=$false
if (-not (Test-Path -LiteralPath $identity)) {{
  & $sshKeygen -q -t ed25519 -N '""' -C ('rcn-tunnel-' + $env:COMPUTERNAME) -f $identity
  if ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}
  $identityCreated=$true
}}
if (-not (Test-Path -LiteralPath $publicKey)) {{ throw 'RCN tunnel public key is unavailable' }}
$userKnownHosts=Join-Path $env:USERPROFILE '.ssh\\known_hosts'
if (-not (Test-Path -LiteralPath $userKnownHosts)) {{ throw 'existing coordinator known-hosts file is unavailable' }}
$hostLines=@(& $sshKeygen -F $coordinatorHost -f $userKnownHosts 2>$null | Where-Object {{ $_ -and -not $_.StartsWith('#') }})
if (-not $hostLines) {{ throw 'coordinator host key is not already pinned for the worker account' }}
$hostsCreated=$false
if (-not (Test-Path -LiteralPath $pinnedHosts)) {{
  Set-Content -LiteralPath $pinnedHosts -Value $hostLines -Encoding ascii
  $hostsCreated=$true
}}
$pub=(Get-Content -LiteralPath $publicKey -Raw).Trim()
if ($pub -notmatch '^ssh-ed25519 [A-Za-z0-9+/=]+(?: .*)?$') {{ throw 'generated tunnel public key is invalid' }}
if ($identityCreated -or $hostsCreated) {{
  & icacls.exe $tunnelDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
  & icacls.exe $publicKey /inheritance:r /grant:r '*S-1-5-18:R' '*S-1-5-32-544:F' | Out-Null
  & icacls.exe $pinnedHosts /inheritance:r /grant:r '*S-1-5-18:R' '*S-1-5-32-544:F' | Out-Null
  $systemSid=New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
  $privateAcl=New-Object System.Security.AccessControl.FileSecurity
  $privateAcl.SetOwner($systemSid)
  $privateAcl.SetAccessRuleProtection($true,$false)
  $privateAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($systemSid,'FullControl','Allow')))
  Set-Acl -LiteralPath $identity -AclObject $privateAcl
}}
$fingerprint=(& $sshKeygen -lf $publicKey -E sha256 | Select-Object -First 1)
[pscustomobject]@{{public_key=$pub;fingerprint=$fingerprint}} | ConvertTo-Json -Compress
"""
        prepared = self._powershell(prepare_script, timeout=60)
        self._require_success(prepared, "prepare reverse-SSH identity")
        prepared_payload = next(
            (
                json.loads(line.strip())
                for line in prepared.stdout.splitlines()
                if line.strip().startswith("{") and line.strip().endswith("}")
            ),
            None,
        )
        if prepared_payload is None:
            raise ValueError("tunnel identity preparation did not return JSON")
        public_value = str(prepared_payload.get("public_key", ""))
        if not re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/=]+(?: .*)?", public_value):
            raise ValueError("remote tunnel public key is invalid")
        escaped_public = public_value.replace("'", "''")
        authorize_script = f"""
$ErrorActionPreference='Stop'
$ssh=Join-Path $env:SystemRoot 'System32\\OpenSSH\\ssh.exe'
if (-not (Test-Path -LiteralPath $ssh)) {{ $ssh=(Get-Command ssh.exe -ErrorAction Stop).Source }}
$pinnedHosts='{pinned_hosts}'
$escapedPub='{escaped_public}'
$authorizeScript=@"
`$ErrorActionPreference='Stop'
`$path='C:\\ProgramData\\ssh\\administrators_authorized_keys'
`$pub='$escapedPub'
if (-not (Test-Path -LiteralPath `$path)) {{ New-Item -ItemType File -Force -Path `$path | Out-Null }}
`$existing=@(Get-Content -LiteralPath `$path -ErrorAction SilentlyContinue)
`$added=`$false
if (`$existing -notcontains `$pub) {{ Add-Content -LiteralPath `$path -Value `$pub -Encoding ascii; `$added=`$true }}
[pscustomobject]@{{added=`$added}} | ConvertTo-Json -Compress
"@
$encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($authorizeScript))
$stdout=Join-Path $env:TEMP 'rcn-tunnel-authorize.stdout'
$stderr=Join-Path $env:TEMP 'rcn-tunnel-authorize.stderr'
Remove-Item -LiteralPath $stdout,$stderr -Force -ErrorAction SilentlyContinue
$arguments=@('-n','-o','BatchMode=yes','-o','ConnectTimeout=10','-o','StrictHostKeyChecking=yes','-o',('UserKnownHostsFile=' + $pinnedHosts),'{coordinator_user}@{coordinator_host}','powershell.exe','-NoLogo','-NoProfile','-NonInteractive','-OutputFormat','Text','-EncodedCommand',$encoded)
$process=Start-Process -FilePath $ssh -ArgumentList $arguments -NoNewWindow -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
if (-not $process.WaitForExit(20000)) {{ $process.Kill(); throw 'coordinator public-key authorization timed out' }}
$process.WaitForExit()
$authorizeOutput=(Get-Content -LiteralPath $stdout -Raw -ErrorAction SilentlyContinue)
$authorizeError=(Get-Content -LiteralPath $stderr -Raw -ErrorAction SilentlyContinue)
if ($authorizeOutput -notmatch '\{{"added":(true|false)\}}') {{ throw ('coordinator public-key authorization failed: ' + $authorizeError + $authorizeOutput) }}
Remove-Item -LiteralPath $stdout,$stderr -Force -ErrorAction SilentlyContinue
[pscustomobject]@{{coordinator_authorized=$true}} | ConvertTo-Json -Compress
"""
        authorized = self._powershell(authorize_script, timeout=45)
        self._require_success(authorized, "authorize reverse-SSH identity")
        for line in authorized.stdout.splitlines():
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                payload = json.loads(line)
                return {
                    "identity_path": str(identity),
                    "known_hosts_path": str(pinned_hosts),
                    "fingerprint": prepared_payload.get("fingerprint"),
                    "coordinator_authorized": bool(payload.get("coordinator_authorized")),
                }
        raise ValueError("tunnel identity authorization did not return JSON")

    def _validate_read_identity(self, payload: dict, *, external_run_id: str | None = None,
                                supervisor: bool = False, complete_receipt: bool = False) -> None:
        if not isinstance(payload, dict):
            raise ValueError('remote read receipt must be a JSON object')
        expected = {'machine_id': self.config.machine_id, 'root_uuid': self.config.root_uuid}
        if external_run_id is not None:
            expected['external_run_id'] = external_run_id
            if complete_receipt and (payload.get('external_run_id') != external_run_id
                    or payload.get('state') not in {state.value for state in RemoteRunState}):
                raise ValueError('remote status receipt lacks its expected run identity or state')
            if complete_receipt:
                required = {'schema_version', 'external_run_id', 'machine_id', 'job_id',
                    'work_unit_id', 'request_hash', 'state', 'message', 'progress_percent',
                    'remote_relative_path', 'artifacts_available', 'updated_at'}
                if (not required.issubset(payload) or type(payload['schema_version']) is not int
                        or payload['schema_version'] != 1 or type(payload['artifacts_available']) is not bool
                        or not payload['job_id'] or not payload['work_unit_id']):
                    raise ValueError('remote status receipt lacks complete published status fields')
                RemoteRunRecord.model_validate(payload)
                if 'runtime_version' in payload and (not isinstance(payload['runtime_version'], str)
                        or not re.fullmatch(r'[A-Za-z0-9_.-]+', payload['runtime_version'])):
                    raise ValueError('remote status receipt runtime version is invalid')
        if supervisor:
            expected['runtime_version'] = self.config.runtime_version
            if complete_receipt and (not isinstance(payload.get('updated_at'), str)
                    or type(payload.get('pid')) is not int or payload['pid'] <= 0
                    or not isinstance(payload.get('metrics'), dict)):
                raise ValueError('remote supervisor receipt lacks complete published status fields')
        for field, value in expected.items():
            required = complete_receipt and supervisor
            if required and (not value or payload.get(field) != value):
                raise ValueError(f'remote supervisor receipt {field} does not match configured identity')
            if value and field in payload and payload[field] != value:
                raise ValueError(f'remote read receipt {field} does not match configured identity')

    def _readonly_timeout_receipt(self, error: subprocess.TimeoutExpired, *,
                                  external_run_id: str | None = None, supervisor: bool = False,
                                  remote_output: PureWindowsPath | None = None) -> dict:
        """Consume one complete, identity-bound read frame without repeating SSH.

        Transport evidence is kept outside the remote payload, whose existing
        schema remains unchanged. Mutating calls still propagate this exception.
        """
        try:
            output = error.stdout or b''
            stderr = error.stderr or b''
            if isinstance(output, bytes):
                output = output.decode('utf-8-sig')
            if isinstance(stderr, bytes):
                stderr = stderr.decode('utf-8-sig')
            if re.search(r'(?i)\b(?:error|exception|CategoryInfo|FullyQualifiedErrorId)\b', stderr):
                raise ValueError('remote read reported an error')
            lines = [line.strip() for line in output.splitlines()
                     if line.strip() and line.strip() != '#< CLIXML']
            if len(lines) != 1:
                raise ValueError('remote read did not emit exactly one complete receipt')
            def unique_object(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError('remote read JSON has duplicate fields')
                    result[key] = value
                return result
            def invalid_constant(value):
                raise ValueError('remote read JSON has a nonfinite constant')
            text = lines[0] if remote_output is not None else base64.b64decode(lines[0], validate=True).decode('utf-8-sig')
            payload = json.loads(text,
                                 object_pairs_hook=unique_object, parse_constant=invalid_constant)
            if remote_output is not None:
                self._validate_output_measurement(payload, remote_output, complete_receipt=True)
            else:
                self._validate_read_identity(payload, external_run_id=external_run_id,
                                             supervisor=supervisor, complete_receipt=True)
        except (ValueError, TypeError, UnicodeDecodeError) as invalid:
            raise error from invalid
        self.last_read_transport_receipt = {
            'action': 'measure_completed_output' if remote_output is not None else (
                'read_supervisor_status' if supervisor else 'read_status'),
            'external_run_id': external_run_id, 'transport_closed_normally': False,
            'complete_receipt_consumed': True, 'timeout_s': error.timeout,
        }
        if remote_output is not None:
            self.last_read_transport_receipt['remote_output'] = str(remote_output)
        return payload

    def read_status(self, external_run_id: str, *, timeout_s: float | None = None) -> dict:
        external = _safe_external_id(external_run_id)
        self.last_read_transport_receipt = None
        status_path = self.layout.status / f"{external}.json"
        last_error: Exception | None = None
        deadline = time.monotonic() + timeout_s if timeout_s is not None else None
        for attempt in range(3):
            script = (
                f"if (-not (Test-Path -LiteralPath '{status_path}')) {{ exit 44 }}; "
                # Do not put a worker-written UTF-8 JSON document through
                # Windows PowerShell's text decoder and JSON reserializer.
                # PowerShell 5 treats BOM-less UTF-8 as an ANSI code page and
                # can corrupt localized COMSOL errors before ``ConvertFrom-Json``
                # sees them.  The status path is fixed by the assignment, and
                # the base64 payload is decoded and validated locally.
                f"[Convert]::ToBase64String([IO.File]::ReadAllBytes('{status_path}'))"
            )
            try:
                if deadline is None:
                    completed = self._powershell(script)
                else:
                    remaining = deadline - time.monotonic()
                    if remaining < 0.25:
                        raise TimeoutError("first-status read budget expired")
                    completed = self._powershell(script, timeout=remaining)
            except subprocess.TimeoutExpired as exc:
                return self._readonly_timeout_receipt(exc, external_run_id=external)
            if completed.returncode == 44:
                return {"external_run_id": external, "state": "staged", "message": "status not published yet"}
            self._require_success(completed, "read status")
            for line in completed.stdout.splitlines():
                line = line.strip()
                if not line or line.startswith("#<"):
                    continue
                try:
                    payload = json.loads(base64.b64decode(line, validate=True).decode("utf-8-sig"))
                except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                    last_error = exc
                    break
                self._validate_read_identity(payload, external_run_id=external)
                return payload
            else:
                last_error = ValueError("remote status did not contain a base64 JSON payload")
            if attempt < 2:
                remaining = deadline - time.monotonic() if deadline is not None else 0.1
                if remaining <= 0:
                    raise TimeoutError("first-status read budget expired")
                time.sleep(min(0.1, remaining))
        raise ValueError(f"remote status JSON remained invalid after retries: {last_error}")

    def read_supervisor_status(self) -> dict:
        """Read the one fixed supervisor heartbeat; never accept a remote path."""
        self.last_read_transport_receipt = None
        status_path = self.layout.root / "agent" / "status.json"
        try:
            completed = self._powershell(
                supervisor_status_with_disk_probe(status_path),
                timeout=self.config.ssh_status_timeout_s or 20,
            )
        except subprocess.TimeoutExpired as exc:
            return self._readonly_timeout_receipt(exc, supervisor=True)
        if completed.returncode == 44:
            raise FileNotFoundError("remote supervisor status is unavailable")
        self._require_success(completed, "read supervisor status")
        for line in completed.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("#<"):
                continue
            try:
                payload = json.loads(base64.b64decode(line, validate=True).decode("utf-8-sig"))
            except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError("remote supervisor status did not contain valid base64 JSON") from exc
            self._validate_read_identity(payload, supervisor=True)
            return payload
        raise ValueError("remote supervisor status did not contain a base64 JSON payload")

    def request_cancel(self, external_run_id: str) -> None:
        external = _safe_external_id(external_run_id)
        channel = self._drop_activation_channel(external)
        if channel is not None:
            channel.close()
        payload = json.dumps({"schema_version": 1, "external_run_id": external}, separators=(",", ":"))
        with tempfile.TemporaryDirectory(prefix="rcn-cancel-") as tmp:
            source = Path(tmp) / f"{external}.json"
            source.write_text(payload, encoding="utf-8")
            cancel_dir = self.layout.cancel
            partial = cancel_dir / f"{external}.partial"
            final = cancel_dir / f"{external}.json"
            prepared = self._powershell(f"New-Item -ItemType Directory -Force -Path '{cancel_dir}' | Out-Null")
            self._require_success(prepared, "prepare cancellation")
            remote = f"{self.config.ssh_user}@{self.config.ssh_host}:{self._scp_remote(partial)}"
            uploaded = self.runner([*self._scp_base(), str(source), remote], timeout=60)
            self._require_success(uploaded, "upload cancellation")
            activated = self._powershell(
                f"Move-Item -LiteralPath '{partial}' -Destination '{final}' -Force -ErrorAction Stop"
            )
            self._require_success(activated, "activate cancellation")

    def activate_prepared(self, external_run_id: str) -> None:
        external = _safe_external_id(external_run_id)
        payload = json.dumps(
            {"schema_version": 1, "external_run_id": external},
            separators=(",", ":"),
        ).encode("utf-8")
        encoded_payload = base64.b64encode(payload).decode("ascii")
        channel = self._drop_activation_channel(external)
        if channel is not None:
            try:
                if channel.activate(encoded_payload, external, timeout=1.5):
                    return
            finally:
                channel.close()
        activation_dir = self.layout.root / "spool" / "activations"
        partial = activation_dir / f"{external}.partial"
        ready = activation_dir / f"{external}.ready"
        activated = self._powershell(
            "$ErrorActionPreference='Stop'; "
            f"$activationDir='{activation_dir}'; $partial='{partial}'; $ready='{ready}'; "
            "New-Item -ItemType Directory -Force -Path $activationDir | Out-Null; "
            "if (-not (Test-Path -LiteralPath $ready)) { "
            f"[IO.File]::WriteAllBytes($partial,[Convert]::FromBase64String('{encoded_payload}')); "
            "Move-Item -LiteralPath $partial -Destination $ready -Force -ErrorAction Stop "
            "}"
        )
        self._require_success(activated, "activate standby request")

    def submit_machine_command(self, command: dict) -> None:
        """Upload one allowlisted supervisor command through the fixed inbox."""
        command_id = _safe_external_id(str(command.get("command_id", "")))
        if command.get("machine_id") != self.config.machine_id:
            raise ValueError("machine command targets a different machine")
        payload = json.dumps(command, sort_keys=True, separators=(",", ":"))
        with tempfile.TemporaryDirectory(prefix="rcn-command-") as tmp:
            source = Path(tmp) / f"{command_id}.json"
            source.write_text(payload, encoding="utf-8")
            incoming = self.layout.root / "spool" / "commands" / "incoming"
            result_path = self.layout.root / "spool" / "commands" / "results" / f"{command_id}.json"
            partial = incoming / f"{command_id}.partial"
            ready = incoming / f"{command_id}.ready"
            encoded = base64.b64encode(payload.encode("utf-8")).decode("ascii")
            nonce_check = ""
            if command.get("nonce"):
                nonce = _safe_external_id(str(command["nonce"]))
                nonce_path = self.layout.root / "spool" / "commands" / "nonces" / f"{nonce}.used"
                nonce_check = f"if (Test-Path -LiteralPath '{nonce_path}') {{ exit 26 }}; "
            prepared = self._powershell(
                f"New-Item -ItemType Directory -Force -Path '{incoming}' | Out-Null; "
                f"if (Test-Path -LiteralPath '{result_path}') {{ exit 24 }}; "
                f"if (Test-Path -LiteralPath '{ready}') {{ "
                f"if ([Convert]::ToBase64String([IO.File]::ReadAllBytes('{ready}')) -cne '{encoded}') {{ exit 25 }}; exit 23 }}; "
                + nonce_check
            )
            if prepared.returncode in {23, 24}:
                return
            if prepared.returncode == 25:
                raise ValueError("machine command inbox payload differs from the original command")
            if prepared.returncode == 26:
                raise RuntimeError("reconciliation_required: original command nonce was consumed without a result")
            self._require_success(prepared, "prepare machine command inbox")
            remote = f"{self.config.ssh_user}@{self.config.ssh_host}:{self._scp_remote(partial)}"
            uploaded = self.runner([*self._scp_base(), str(source), remote], timeout=60)
            self._require_success(uploaded, "upload machine command")
            activated = self._powershell(
                f"Move-Item -LiteralPath '{partial}' -Destination '{ready}' -ErrorAction Stop"
            )
            self._require_success(activated, "activate machine command")
            # Verify the command actually landed in the watched inbox. During
            # a tunnel flap the scp/move steps have been observed to return
            # success while the file never appears, leaving the operation
            # pending forever with no result file. Fail loudly instead.
            verify = self._powershell(
                f"if ((Test-Path -LiteralPath '{ready}') -or (Test-Path -LiteralPath '{result_path}')) {{ 'landed' }} else {{ 'missing' }}",
                timeout=30,
            )
            if "landed" not in verify.stdout:
                raise RuntimeError(
                    "machine command did not land in the supervisor inbox "
                    f"after a successful upload sequence ({command_id}); "
                    "retry the command when the machine connection is stable"
                )

    def read_machine_command_result(self, command_id: str) -> dict | None:
        command_id = _safe_external_id(command_id)
        result_path = self.layout.root / "spool" / "commands" / "results" / f"{command_id}.json"
        completed = self._powershell(
            f"if (-not (Test-Path -LiteralPath '{result_path}')) {{ exit 44 }}; "
            f"[Convert]::ToBase64String([IO.File]::ReadAllBytes('{result_path}'))",
            timeout=20,
        )
        if completed.returncode == 44:
            return None
        self._require_success(completed, "read machine command result")
        for line in completed.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("#<"):
                continue
            try:
                return json.loads(base64.b64decode(line, validate=True).decode("utf-8-sig"))
            except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError("remote machine command result did not contain valid base64 JSON") from exc
        raise ValueError("remote machine command result did not contain a base64 JSON payload")

    def _validate_output_measurement(self, payload: dict, remote_output: PureWindowsPath, *,
                                     complete_receipt: bool = False) -> int:
        if not isinstance(payload, dict):
            raise ValueError('completed output size metadata must be a JSON object')
        size, count = payload.get('total_bytes'), payload.get('file_count')
        if type(size) is not int or size <= 0 or type(count) is not int or count <= 0:
            raise ValueError('completed output size is unknown or invalid')
        expected = {'machine_id': self.config.machine_id, 'root_uuid': self.config.root_uuid,
                    'remote_output': str(remote_output)}
        for field, value in expected.items():
            observed = payload.get(field)
            matches = observed == value
            if field == 'remote_output' and isinstance(observed, str):
                matches = PureWindowsPath(observed) == PureWindowsPath(value)
            if complete_receipt and (not value or not matches):
                raise ValueError(f'completed output measurement {field} does not match configured identity')
            if field in payload and value and not matches:
                raise ValueError(f'completed output measurement {field} does not match configured identity')
        if complete_receipt and (not remote_output.is_absolute()
                or '..' in remote_output.parts or not remote_output.is_relative_to(self.layout.root)):
            raise ValueError('completed output measurement escaped the configured remote root')
        return size

    def _output_size_bytes(self, remote_output: PureWindowsPath) -> int:
        # The fixed completed-run output can include the transport manifest
        # and other metadata beyond its registered scientific file records.
        path = str(remote_output).replace("'", "''")
        self.last_read_transport_receipt = None
        binding_script = ''
        if self.config.root_uuid:
            marker = str(self.layout.root / '.rcn-root.json').replace("'", "''")
            # Existing workers accept UTF-8 root markers with or without a
            # BOM (supervisor.load_json uses utf-8-sig). ConvertFrom-Json does
            # not accept that prefix, so remove it once before parsing.
            binding_script = (
                f"$identityJson = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes('{marker}')); "
                "if ($identityJson.Length -gt 0 -and $identityJson[0] -eq [char]0xFEFF) { "
                "$identityJson = $identityJson.Substring(1) }; "
                "$identity = $identityJson | ConvertFrom-Json; "
                "$metadata.machine_id = $identity.machine_id; $metadata.root_uuid = $identity.root_uuid; "
                "$metadata.remote_output = $output.FullName; "
            )
        script = (
            "$ErrorActionPreference='Stop'; "
            f"$output = Get-Item -LiteralPath '{path}' -ErrorAction Stop; "
            "if ($output.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'output reparse point' }; "
            f"if (-not (Test-Path -LiteralPath '{path}\\artifact-manifest.json' -PathType Leaf)) {{ exit 44 }}; "
            f"$items = @(Get-ChildItem -LiteralPath '{path}' -Recurse -Force -ErrorAction Stop); "
            "$bytes = [long]0; $count = 0; foreach ($item in $items) { "
            "if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'output reparse point' }; "
            "if (-not $item.PSIsContainer) { $bytes += [long]$item.Length; $count++ } }; "
            "$metadata = @{ total_bytes = $bytes; file_count = $count }; "
            + binding_script + "$metadata | ConvertTo-Json -Compress"
        )
        try:
            completed = self._powershell(script)
        except subprocess.TimeoutExpired as exc:
            payload = self._readonly_timeout_receipt(exc, remote_output=remote_output)
            return payload['total_bytes']
        self._require_success(completed, "measure completed output")
        for line in completed.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            payload = json.loads(line)
            return self._validate_output_measurement(payload, remote_output)
        raise ValueError("completed output size metadata is unavailable")

    def _guard_collection_storage(self, destination: Path, required_bytes: int) -> None:
        if self.collection_storage_validator is None:
            return
        try:
            root = Path(self.collection_storage_validator()).absolute()
            if not destination.absolute().is_relative_to(root):
                raise StorageRootError("storage_binding_changed", "collection destination is outside its registered root")
        except StorageRootError as exc:
            raise CollectionCapacityUnavailable(required_bytes=required_bytes, free_bytes=None,
                reserved_bytes=None, reserve_bytes=_COLLECTION_RESERVE_BYTES, reason_code=exc.reason_code) from exc

    def download_outputs(self, external_run_id: str, destination: Path) -> list[str]:
        status = self.read_status(external_run_id)
        if status.get("state") != "completed" or not status.get("remote_relative_path"):
            raise RuntimeError("remote outputs are not ready")
        relative = PureWindowsPath(str(status["remote_relative_path"]).replace("/", "\\"))
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("remote status contains an unsafe output path")
        remote_output = self.layout.root / relative / "output"
        required_bytes = self._output_size_bytes(remote_output)
        self._guard_collection_storage(destination, required_bytes)
        if self.volume_budget is None:
            claim = _reserve_collection_capacity(destination, required_bytes)
        else:
            try:
                claim = self.volume_budget.reserve(destination, required_bytes,
                    holder_kind="scp-collection", holder_key=f"{self.config.machine_id}/{external_run_id}/{destination.absolute()}")
            except VolumeCapacityUnavailable as exc:
                raise CollectionCapacityUnavailable(required_bytes=exc.required_bytes, free_bytes=exc.free_bytes,
                    reserved_bytes=exc.reserved_bytes, reserve_bytes=exc.reserve_bytes) from exc
            except VolumeHolderBusy as exc:
                raise CollectionCapacityUnavailable(required_bytes=exc.required_bytes, free_bytes=exc.free_bytes,
                    reserved_bytes=exc.reserved_bytes, reserve_bytes=exc.reserve_bytes,
                    reason_code=exc.reason_code) from exc
        writer_stopped = True  # No transport writer has been launched yet.
        try:
            self._guard_collection_storage(destination, required_bytes)
            destination.mkdir(parents=True, exist_ok=True)
            remote = f"{self.config.ssh_user}@{self.config.ssh_host}:{self._scp_remote(remote_output)}"
            command = [*self._scp_base(), "-r", remote, str(destination)]
            self._guard_collection_storage(destination, required_bytes)
            writer_stopped = False
            try:
                completed = self.runner(command, timeout=600)
            except BaseException as exc:
                # subprocess.run kills/waits its own timed-out child. The
                # cooperative runner attaches proof only after its exact tree
                # exits. An arbitrary custom runner provides no such evidence.
                writer_stopped = bool(getattr(exc, "_rcn_writer_stopped", False)) or (
                    self.runner is _run and isinstance(exc, (subprocess.TimeoutExpired, OSError))
                )
                raise
            else:
                writer_stopped = bool(getattr(completed, "_rcn_writer_stopped", True))
            self._guard_collection_storage(destination, required_bytes)
            self._require_success(completed, "download outputs")
            # ``scp -r <directory> <destination>`` creates a nested directory
            # named after the remote source.  The origin contract, however,
            # validates manifest paths relative to the attempt destination.  Move
            # the downloaded output contents up one level before returning so the
            # manifest's relative paths remain stable across transports.
            nested_output = destination / remote_output.name
            if nested_output.is_dir():
                for child in nested_output.iterdir():
                    target = destination / child.name
                    if target.exists():
                        if not child.is_file() or not target.is_file():
                            raise RuntimeError(f"download output path collision: {target.name}")
                        if child.stat().st_size != target.stat().st_size or sha256_file(child) != sha256_file(target):
                            raise RuntimeError(f"download output content conflict: {target.name}")
                        # Collection may be replayed after the bytes reached origin
                        # staging but before the attempt state was committed.  An
                        # identical file is the same immutable artifact, so reuse
                        # it and remove only the fresh nested download.
                        child.unlink()
                        continue
                    child.replace(target)
                nested_output.rmdir()
            self._guard_collection_storage(destination, required_bytes)
            return [str(path) for path in destination.rglob("*") if path.is_file()]
        finally:
            if self.volume_budget is None:
                _release_collection_capacity(claim)
            elif writer_stopped:
                self.volume_budget.release(claim, writer_stopped=True,
                    evidence="owned synchronous SCP writer ended; local postprocessing stopped")


BundleBuilder = Callable[[JobEnvelope, Assignment, str], Path]


class SshSchedulerAdapter(SchedulerAdapter):
    def __init__(
        self,
        config: MachineExecutionConfig,
        transport: SshTransport,
        bundle_builder: BundleBuilder,
    ) -> None:
        self.config = config
        self.transport = transport
        self.bundle_builder = bundle_builder

    @staticmethod
    def external_id(job: JobEnvelope, assignment: Assignment) -> str:
        suffix = assignment.attempt_id or assignment.work_unit_id
        return f"ssh-{assignment.machine_id}-{suffix}"

    def probe(self) -> SchedulerProbe:
        return self.transport.probe()

    def submit(self, job: JobEnvelope, assignment: Assignment) -> str:
        if not self.config.enabled:
            raise RuntimeError("SSH production execution remains locked until acceptance passes")
        if assignment.machine_id != self.config.machine_id:
            raise ValueError("assignment does not target this SSH machine")
        external = self.external_id(job, assignment)
        try:
            bundle = self.bundle_builder(job, assignment, external)
        except Exception as exc:
            raise _prelaunch_error("bundle construction", exc, default_timeout_s=45) from exc
        try:
            acknowledgement = self.transport.stage_bundle(external, bundle)
            if isinstance(acknowledgement, BundlePublicationAck):
                if (acknowledgement.external_run_id != external
                        or acknowledgement.bundle_sha256 != sha256_file(bundle)):
                    raise ValueError("publication acknowledgement identity/hash mismatch")
                with zipfile.ZipFile(bundle) as archive:
                    if archive.getinfo("request.json").file_size > 262_144:
                        raise ValueError("published request exceeds metadata limit")
                    request = json.loads(archive.read("request.json"))
                expected = dict(external_run_id=external, machine_id=assignment.machine_id,
                                job_id=job.job_id, work_unit_id=assignment.work_unit_id)
                if (any(request.get(key) != value for key, value in expected.items())
                        or not re.fullmatch(r"[0-9a-f]{64}", request.get("request_hash", ""))
                        or request.get("attempt_id", assignment.attempt_id) != assignment.attempt_id):
                    raise ValueError("published request does not bind the original assignment")
                expected["request_hash"] = request["request_hash"]
                self._await_first_status(external, expected)
        except (PreLaunchSubmissionError, SubmissionUncertainError):
            raise
        except Exception as exc:
            # A third-party transport error supplies no pre-publication proof.
            raise SubmissionUncertainError(
                safe_failure_reason(exc, action="bundle publication"), external_run_id=external,
            ) from exc
        return external

    def _await_first_status(self, external: str, expected: dict) -> None:
        """Use the existing 45s control-I/O boundary for a real first status.

        Fresh publication remains the only opt-in. A tail shorter than 0.25s
        waits out the budget without opening another SSH probe. No status,
        Attempt state or start time is invented on expiry or cooperative stop.
        """
        budget_s = 45.0
        deadline = time.monotonic() + budget_s
        stop = getattr(getattr(self.transport, "runner", None), "_rcn_stop_event", None)
        accepted = {"queued", "running", "completed", "failed", "cancelled", "interrupted", "collecting"}
        while True:
            remaining = deadline - time.monotonic()
            if stop is not None and stop.is_set():
                raise SshTransportUnavailableError("first-status wait interrupted for cooperative stop")
            if remaining < 0.25:
                if remaining > 0:
                    if stop is not None:
                        stop.wait(remaining)
                    else:
                        time.sleep(remaining)
                    if stop is not None and stop.is_set():
                        raise SshTransportUnavailableError("first-status wait interrupted for cooperative stop")
                raise subprocess.TimeoutExpired("first-status publication budget", budget_s)
            try:
                status = self.transport.read_status(external, timeout_s=remaining)
            except (TimeoutError, subprocess.TimeoutExpired):
                if deadline - time.monotonic() < 0.25:
                    continue  # Report the whole publication budget, not its last tiny probe.
                raise
            if time.monotonic() > deadline:
                raise subprocess.TimeoutExpired("first-status publication budget", budget_s)
            if status.get("state") == "staged" and status.get("message") == "status not published yet":
                delay = min(0.1, max(0.0, deadline - time.monotonic()))
                if stop is not None:
                    stop.wait(delay)
                else:
                    time.sleep(delay)
                continue
            if (any(status.get(key) != value for key, value in expected.items())
                    or status.get("state") not in accepted):
                raise ValueError("first remote status identity/hash/lifecycle mismatch")
            return

    def prepare(self, job: JobEnvelope, assignment: Assignment, external_job_id: str) -> str:
        return self.prepare_with_receipt(job, assignment, external_job_id)

    def prepare_with_receipt(
        self,
        job: JobEnvelope,
        assignment: Assignment,
        external_job_id: str,
        *,
        before_publication: Callable[[dict], None] | None = None,
    ) -> str:
        if not self.config.enabled:
            raise RuntimeError("SSH production execution remains locked until acceptance passes")
        if assignment.machine_id != self.config.machine_id:
            raise ValueError("assignment does not target this SSH machine")
        external = _safe_external_id(external_job_id)
        try:
            bundle = self.bundle_builder(job, assignment, external)
            if before_publication is not None:
                with zipfile.ZipFile(bundle) as archive:
                    if archive.getinfo("request.json").file_size > 262_144:
                        raise ValueError("standby request exceeds metadata limit")
                    request = json.loads(archive.read("request.json"))
                if not isinstance(request, dict):
                    raise ValueError("standby request must be an object")
                before_publication(request)
        except Exception as exc:
            raise _prelaunch_error("bundle construction", exc, default_timeout_s=45) from exc
        try:
            self.transport.stage_bundle(external, bundle)
        except (PreLaunchSubmissionError, SubmissionUncertainError):
            raise
        except Exception as exc:
            raise SubmissionUncertainError(
                safe_failure_reason(exc, action="standby publication"), external_run_id=external,
            ) from exc
        prepare_channel = getattr(self.transport, "prepare_activation_channel", None)
        if prepare_channel is not None:
            prepare_channel(external)
        return external

    def activate(self, external_job_id: str) -> None:
        self.transport.activate_prepared(external_job_id)

    def cancel(self, external_job_id: str) -> None:
        self.transport.request_cancel(external_job_id)

    def poll(self, external_job_id: str) -> RemoteRunRecord:
        payload = self.transport.read_status(external_job_id)
        return RemoteRunRecord(
            external_run_id=external_job_id,
            machine_id=payload.get("machine_id", self.config.machine_id),
            job_id=payload.get("job_id", "unknown"),
            work_unit_id=payload.get("work_unit_id", "unknown"),
            request_hash=payload.get("request_hash", "0" * 64),
            state=RemoteRunState(payload.get("state", "staged")),
            remote_relative_path=payload.get("remote_relative_path", ""),
            progress_percent=float(payload.get("progress_percent", 0)),
            completed_items=payload.get("completed_items"),
            total_items=payload.get("total_items"),
            eta_s=payload.get("eta_s"),
            solver_variant=payload.get("solver_variant"),
            message=payload.get("message", ""),
            artifacts_available=bool(payload.get("artifacts_available", False)),
            failure_class=payload.get("failure_class"),
        )

    def collect_artifacts(self, external_job_id: str, destination: str) -> list[str]:
        return self.transport.download_outputs(external_job_id, Path(destination))
