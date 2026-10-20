"""Allowlisted, file-spool based Windows supervisor for the SSH pilot.

This module intentionally uses only the Python standard library so it can run
under an operator-provided Python interpreter without installing packages.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import traceback
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse
from urllib.request import Request, urlopen

# The embeddable CPython runtime uses a locked ``python311._pth`` file, so
# Python does not automatically add the directory containing this script.
# Add only this versioned, sealed remote-agent directory before importing its
# sibling modules; no user-controlled path is accepted here.
_REMOTE_AGENT_DIR = str(Path(__file__).resolve().parent)
if _REMOTE_AGENT_DIR not in sys.path:
    sys.path.insert(0, _REMOTE_AGENT_DIR)

try:
    from .remote_metrics import RemoteMetricSampler
    from .windows_job import ProcessTreeGuard
    from .worker_storage import (prepare_scratch, scratch_environment, cleanup_scratch,
        scratch_reserve_gib, allow_worker_start, record_tree_exit, has_tree_exit_proof, SCRATCH_MARKER)
except ImportError:  # direct script execution on the worker
    from remote_metrics import RemoteMetricSampler
    from windows_job import ProcessTreeGuard
    from worker_storage import (prepare_scratch, scratch_environment, cleanup_scratch,
        scratch_reserve_gib, allow_worker_start, record_tree_exit, has_tree_exit_proof, SCRATCH_MARKER)


ROOT_MARKER = ".rcn-root.json"
RUN_MARKER = ".rcn-run.json"
COMSOL_PROFILES = {
    "workbench-comsol-template-build-v1",
    "workbench-comsol-saved-readout-v1",
    "workbench-comsol-scan-v1",
    "workbench-comsol-eigen-v2",
    "workbench-comsol-eigen-v3",
    "workbench-comsol-eigen-v4",
    "workbench-comsol-frequency-v1",
    "workbench-comsol-frequency-v2",
    "workbench-comsol-study-v1",
    "workbench-comsol-study-v2",
}
# These Profiles all use the schema-v2 fixed Recipe bundle.  The historical
# scan Profile deliberately retains the legacy batch-worker job contract.
FIXED_RECIPE_PROFILES = {
    "workbench-comsol-template-build-v1",
    "workbench-comsol-saved-readout-v1",
    "workbench-comsol-eigen-v2",
    "workbench-comsol-eigen-v3",
    "workbench-comsol-eigen-v4",
    "workbench-comsol-frequency-v1",
    "workbench-comsol-frequency-v2",
    "workbench-comsol-study-v1",
    "workbench-comsol-study-v2",
}
ALLOWED_PROFILES = COMSOL_PROFILES | {"rcn-safe-fake-v1", "project-worker-v1"}
ALLOWED_CONTROL_ACTIONS = {
    "set_target_capacity",
    "set_hard_capacity",
    "health_probe",
    "graceful_stop",
    "emergency_stop_network",
    "emergency_stop_host",
    "restart_supervisor",
    "force_restart_supervisor",
}

DEFAULT_TELEMETRY_POLICY = {
    "sample_interval_s": 1,
    "cpu_sample_window_s": 60,
    "peak_window_s": 300,
    "sample_timeout_s": 8,
    "stale_after_s": 45,
    "external_process_names": ["comsol", "mphserver", "comsol server"],
}


def validated_telemetry_policy(value):
    """Validate the small live-reload policy without importing control-plane code."""
    if value is None or value == {}:
        value = DEFAULT_TELEMETRY_POLICY
    if not isinstance(value, dict):
        raise ValueError("telemetry policy must be an object")
    integer_fields = {
        "sample_interval_s": (1, 60),
        "cpu_sample_window_s": (1, 300),
        "peak_window_s": (1, 900),
        "sample_timeout_s": (1, 30),
        "stale_after_s": (5, 3600),
    }
    normalized = {}
    if set(value) != set(integer_fields) | {"external_process_names"}:
        raise ValueError("telemetry policy fields are invalid")
    for field, (minimum, maximum) in integer_fields.items():
        raw = value.get(field)
        if isinstance(raw, bool) or not isinstance(raw, int) or not minimum <= raw <= maximum:
            raise ValueError("telemetry policy %s is outside the supported range" % field)
        normalized[field] = raw
    names = value.get("external_process_names")
    if not isinstance(names, list) or not 1 <= len(names) <= 32:
        raise ValueError("telemetry policy process names are invalid")
    normalized_names = []
    for raw_name in names:
        if not isinstance(raw_name, str):
            raise ValueError("telemetry policy process names must be strings")
        name = raw_name.strip().lower()
        if not name or len(name) > 128 or any(character in name for character in "\r\n\0"):
            raise ValueError("telemetry policy process name is invalid")
        normalized_names.append(name)
    if len(normalized_names) != len(set(normalized_names)):
        raise ValueError("telemetry policy process names must be unique")
    normalized["external_process_names"] = normalized_names
    return normalized


def telemetry_policy_sha256(value):
    normalized = validated_telemetry_policy(value)
    canonical = json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class SingleInstanceLock:
    """Keep one supervisor per configured root without a Windows service."""

    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = None
        try:
            self.handle = self.path.open("a+b")
            self.handle.seek(0)
            if self.handle.read(1) == b"":
                self.handle.seek(0)
                self.handle.write(b"0")
                self.handle.flush()
            self.handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, IOError, PermissionError):
            if self.handle is not None:
                self.handle.close()
            self.handle = None
            raise RuntimeError("another supervisor already owns this root")

    def close(self):
        if self.handle is None:
            return
        self.handle.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(self.handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
        self.handle.close()
        self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.close()


def utc_now():
    return datetime.now(timezone.utc)


def iso_now():
    return utc_now().isoformat()


def record_supervisor_event(config, event, **details):
    """Best-effort lifecycle evidence that must never mask supervisor work."""
    try:
        root = Path(config["remote_root"])
        payload = {
            "schema_version": 1,
            "event": event,
            "machine_id": config.get("machine_id", ""),
            "runtime_version": config.get("runtime_version", ""),
            "pid": os.getpid(),
            "observed_at": iso_now(),
        }
        payload.update(details)
        log_path = root / "logs" / "supervisor-events.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        if event in {"crashed", "instance_rejected", "stopped"}:
            write_json_atomic(root / "agent" / "supervisor-last-exit.json", payload)
    except Exception:
        # Lifecycle evidence is deliberately best-effort.  A full disk or a
        # transient log handle must not become a second supervisor failure.
        pass


def load_json(path):
    # Windows PowerShell 5's ``Set-Content -Encoding UTF8`` writes a BOM.
    # ``utf-8-sig`` accepts both BOM and normal UTF-8 JSON.
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def write_json_atomic(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(
        "%s.tmp-%s-%s" % (path.name, os.getpid(), threading.get_ident())
    )
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2))
            handle.flush()
            os.fsync(handle.fileno())
        replace_with_retry(
            temporary,
            path,
            timeout_s=5.0,
            transient_winerrors={5, 32},
        )
    finally:
        temporary.unlink(missing_ok=True)


def replace_with_retry(
    source,
    destination,
    *,
    timeout_s=60.0,
    transient_winerrors=None,
):
    """Move a completed unit after Windows child handles have drained.

    COMSOL, antivirus, or an indexer can retain a directory handle after the
    worker exits. Treat only Windows access-denied and sharing violations as
    transient; all other filesystem errors remain explicit failures.
    """
    transient_winerrors = transient_winerrors or {5, 32}
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            os.replace(str(source), str(destination))
            return
        except OSError as exc:
            if (
                getattr(exc, "winerror", None) not in transient_winerrors
                or time.monotonic() >= deadline
            ):
                raise
            time.sleep(0.25)


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while True:
            block = handle.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def safe_name(value, label):
    if not value or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-" for ch in value):
        raise ValueError("unsafe %s" % label)
    if value in (".", ".."):
        raise ValueError("unsafe %s" % label)
    return value


def safe_extract(archive, destination):
    destination = Path(destination).resolve()
    with zipfile.ZipFile(archive) as bundle:
        for member in bundle.infolist():
            path = PurePosixPath(member.filename)
            if path.is_absolute() or ".." in path.parts or not path.parts:
                raise ValueError("bundle contains unsafe path")
            target = (destination / Path(*path.parts)).resolve()
            try:
                target.relative_to(destination)
            except ValueError:
                raise ValueError("bundle escapes extraction directory")
        bundle.extractall(destination)


class OutboundHeartbeatReporter:
    """Machine-token authenticated heartbeat independent of reverse SSH."""

    def __init__(self, root, machine_id, config):
        self.root = Path(root).resolve()
        self.machine_id = machine_id
        self.base_url = str(
            config.get("control_plane_heartbeat_url")
            or os.environ.get("RCN_CONTROL_PLANE_URL")
            or ""
        ).rstrip("/")
        token_value = str(
            config.get("machine_token_file")
            or os.environ.get("RCN_MACHINE_TOKEN_FILE")
            or ""
        )
        self.token_file = Path(token_value).resolve() if token_value else None
        if self.token_file is not None:
            self.token_file.relative_to(self.root)
        if self.base_url:
            parsed = urlparse(self.base_url)
            if parsed.scheme != "https" and parsed.hostname not in {"127.0.0.1", "localhost"}:
                raise ValueError("outbound heartbeat requires HTTPS outside loopback")
        self.heartbeat_base_url = (
            self.base_url if self.base_url.endswith("/v1") else self.base_url + "/v1"
        ) if self.base_url else ""

    @property
    def enabled(self):
        return bool(self.base_url and self.token_file)

    def report(
        self,
        *,
        metrics,
        running_work_unit_ids,
        runtime_version,
        supervisor_reported_concurrent_units=None,
        applied_telemetry_policy=None,
    ):
        if not self.enabled:
            return None
        token = self.token_file.read_text(encoding="utf-8-sig").strip()
        if not token:
            raise ValueError("machine heartbeat token file is empty")
        payload = json.dumps({
            "schema_version": 1,
            "machine_id": self.machine_id,
            "metrics": metrics,
            "running_work_unit_ids": running_work_unit_ids,
            "runtime_version": runtime_version,
            "supervisor_reported_concurrent_units": supervisor_reported_concurrent_units,
            "applied_telemetry_policy": applied_telemetry_policy,
            "applied_telemetry_policy_sha256": telemetry_policy_sha256(
                applied_telemetry_policy
            ),
        }, ensure_ascii=False).encode("utf-8")
        request = Request(
            "%s/machines/%s/heartbeat" % (self.heartbeat_base_url, self.machine_id),
            data=payload,
            headers={
                "Authorization": "Bearer " + token,
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urlopen(request, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))


def worker_failure_summary(stderr_path, return_code):
    """Return a short, path-free worker failure explanation for status polling."""
    try:
        text = Path(stderr_path).read_text(encoding="utf-8", errors="replace")[-32768:]
    except OSError:
        text = ""
    # Python tracebacks place the useful exception on the final matching line.
    matches = re.findall(r"(?m)^([A-Za-z_][A-Za-z0-9_.]*(?:Error|Exception)): (.+)$", text)
    if not matches:
        return "worker exit code %s (diagnostic unavailable)" % return_code
    error_type, detail = matches[-1]
    # The remote result contract never exposes filesystem layout or command
    # details. Keep only the classified exception text, with path-like values
    # redacted before it can reach the control plane.
    detail = re.sub(r"(?i)(?:[a-z]:)?[\\/][^\\s'\"`]+", "<path>", detail)
    detail = " ".join(detail.split())[:220]
    if not detail:
        return "worker failed: %s" % error_type
    return "worker failed: %s: %s" % (error_type, detail)


class Supervisor:
    def __init__(self, config, config_path=None):
        self.config = config
        self.config_path = Path(config_path) if config_path else None
        self.root = Path(config["remote_root"])
        self.machine_id = config["machine_id"]
        self.root_uuid = config["root_uuid"]
        self.validated_hard_cap = int(config.get("max_concurrent_units", 1))
        self.max_concurrent = min(
            self.validated_hard_cap,
            int(config.get("target_concurrent_units", self.validated_hard_cap)),
        )
        self.python = Path(config["python_executable"])
        # Dependencies are installed into the immutable RCN runtime version,
        # never into the worker's system or user Python environment.
        self.runtime_version = str(config.get("runtime_version") or "")
        version_root = (self.root / "agent" / "versions").resolve()
        try:
            source_relative = Path(__file__).resolve().relative_to(version_root)
        except ValueError:
            source_relative = None
        if source_relative is not None and len(source_relative.parts) >= 3:
            source_version = source_relative.parts[0]
            if source_version != self.runtime_version:
                raise RuntimeError(
                    "configured runtime version does not match the supervisor source path"
                )
        if self.runtime_version:
            runtime_site = self.root / "agent" / "versions" / self.runtime_version / "site-packages"
            if runtime_site.is_dir():
                sys.path.insert(0, str(runtime_site))
        self.active = {}
        self.stop_requested = False
        self._verify_root()
        self._ensure_dirs()
        self.metric_sampler = RemoteMetricSampler(
            self.root,
            telemetry_policy=config.get("telemetry_policy") or {},
        )
        self._metric_lock = threading.Lock()
        self._metric_thread = None
        self._latest_metrics = {
            "available": False,
            "unavailable_reasons": ["telemetry sampling has not completed"],
            "source": "ssh-supervisor",
            "observed_at": iso_now(),
            "gpu": [],
            "gpu_status": "unavailable",
        }
        self._metric_sampler_status = {
            "state": "idle",
            "started_at": None,
            "finished_at": None,
            "error": "",
        }
        self._metric_started_monotonic = None
        self._metric_last_started_monotonic = None
        self.outbound_heartbeat = OutboundHeartbeatReporter(
            self.root, self.machine_id, config
        )
        self._outbound_thread = None
        self._outbound_lock = threading.Lock()
        self._model_retirement_thread = None
        self._model_retirement_lock = threading.Lock()
        self._model_retirement_last_started = None
        self._tunnel_unreachable_observations = 0
        self._recover_completed_finalizations()
        self._recover_interrupted_runs()

    def _validated_completed_manifest(self, request, run_dir):
        manifest_path = run_dir / "output" / "artifact-manifest.json"
        if not manifest_path.is_file():
            raise FileNotFoundError(manifest_path)
        manifest = load_json(manifest_path)
        for key in ("external_run_id", "job_id", "work_unit_id", "runtime_version",
                    "solver_variant", "solver_approval_id"):
            if manifest.get(key) != request.get(key):
                raise ValueError("completed artifact manifest identity changed")
        records = manifest.get("files")
        if not isinstance(records, list) or not records:
            raise ValueError("completed artifact manifest files are invalid")
        output = (run_dir / "output").resolve()
        seen = set()
        for record in records:
            relative = PurePosixPath(record["relative_path"])
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError("completed artifact manifest path is unsafe")
            candidate = (output / Path(*relative.parts)).resolve()
            candidate.relative_to(output)
            if candidate in seen or candidate == manifest_path.resolve():
                raise ValueError("completed artifact manifest repeats a file")
            seen.add(candidate)
            if (
                not candidate.is_file()
                or candidate.stat().st_size != int(record["size_bytes"])
                or sha256_file(candidate) != record["sha256"]
            ):
                raise ValueError("completed artifact manifest file changed")
        if seen != {path.resolve() for path in output.rglob("*")
                    if path.is_file() and path != manifest_path}:
            raise ValueError("completed artifact manifest file coverage changed")
        if manifest.get("item_provenance", []) != self._item_provenance(request, run_dir):
            raise ValueError("completed artifact manifest provenance changed")
        return manifest

    def _validate_run_binding(self, request, run_dir):
        """Bind mutable-status recovery to the original immutable run identity."""
        self._validate_request(dict(request))
        if not re.fullmatch(r"[0-9a-f]{64}", request["request_hash"]):
            raise ValueError("run request hash is invalid")
        marker = load_json(run_dir / RUN_MARKER)
        if marker.get("root_uuid") != self.root_uuid:
            raise ValueError("run marker root identity changed")
        for key in ("external_run_id", "request_hash"):
            if marker.get(key) != request[key]:
                raise ValueError("run marker request identity changed")
        relative = run_dir.resolve().relative_to(self.root.resolve())
        active = ("runs", "active", request["project_id"], request["job_id"], request["work_unit_id"])
        retained = ("runs", "retained", "success", *active[2:])
        if relative.parts not in (active, retained):
            raise ValueError("run path differs from immutable request")
        if relative.parts == retained and marker.get("outcome") != "success":
            raise ValueError("retained run lacks successful finalization identity")

    def _recover_run_status(self, request, run_dir):
        """Repair status only; unknown execution never becomes launchable."""
        self._validate_run_binding(request, run_dir)
        external = request["external_run_id"]
        entry = self.active.get(external)
        state = "reconcile_pending"
        message = "mutable status unavailable; original execution ownership is unknown"
        if entry is not None:
            if entry["request"] == request and Path(entry["run_dir"]).resolve() == run_dir.resolve():
                if entry["process"].poll() is None:
                    state = "running"
                    message = "mutable status recovered from current supervisor process ownership"
        else:
            try:
                self._validated_completed_manifest(request, run_dir)
            except (OSError, KeyError, TypeError, ValueError):
                pass
            else:
                try:
                    self._validate_recovery_destination(request, run_dir)
                except (OSError, KeyError, TypeError, ValueError):
                    message = "mutable status unavailable; completed recovery destination needs reconciliation"
                else:
                    destination = self._retain(request, run_dir, "success")
                    self.publish(request, "completed", "outputs recovered after finalization retry",
                                 100, str(destination.relative_to(self.root)), True)
                    return load_json(self.status_path(external))
        self.publish(request, state, message, relative_path=str(run_dir.relative_to(self.root)))
        return load_json(self.status_path(external))

    def _validate_recovery_destination(self, request, run_dir):
        destination = self.root / "runs" / "retained" / "success" / request["project_id"] / request["job_id"] / request["work_unit_id"]
        if destination.exists() and destination.resolve() != run_dir.resolve():
            if load_json(destination / "request.json") != request:
                raise ValueError("completed recovery destination belongs to another attempt")
            self._validate_run_binding(request, destination)
            self._validated_completed_manifest(request, destination)

    def _load_run_status(self, request, run_dir):
        try:
            status = load_json(self.status_path(request["external_run_id"]))
            if not isinstance(status, dict) or not isinstance(status.get("state"), str):
                raise ValueError("mutable run status is invalid")
            return status
        except (OSError, ValueError):
            return self._recover_run_status(request, run_dir)

    def _recover_completed_finalizations(self):
        """Finish a validated successful run after a transient move failure."""
        active_root = self.root / "runs" / "active"
        retained_root = self.root / "runs" / "retained" / "success"
        markers = list(active_root.glob("*/*/*/" + RUN_MARKER)) + list(retained_root.glob("*/*/*/" + RUN_MARKER))
        for marker_path in sorted(markers):
            run_dir = marker_path.parent
            binding_valid = False
            try:
                request = load_json(run_dir / "request.json")
                self._validate_run_binding(request, run_dir)
                binding_valid = True
                external = request["external_run_id"]
                status = self._load_run_status(request, run_dir)
                if external in self.active or not run_dir.exists() or status.get("state") == "completed":
                    continue
                message = str(status.get("message") or "")
                pending_finalization = status.get("state") in {"failed", "reconcile_pending"} and (
                    message.startswith("worker finalization failed:")
                    or message.startswith("worker finalization pending:")
                )
                retained_publication = run_dir.is_relative_to(retained_root) and status.get("state") in {
                    "queued", "prepared", "running", "reconcile_pending",
                }
                if not pending_finalization and not retained_publication:
                    continue
                self._validated_completed_manifest(request, run_dir)
                self._validate_recovery_destination(request, run_dir)
                destination = self._retain(request, run_dir, "success")
                self.publish(
                    request,
                    "completed",
                    "outputs recovered after finalization retry",
                    100,
                    str(destination.relative_to(self.root)),
                    True,
                )
            except (OSError, RuntimeError) as exc:
                if not binding_valid:
                    continue
                try:
                    self.publish(
                        request,
                        "reconcile_pending",
                        "worker finalization pending: %s" % str(exc)[:500],
                        100,
                        str(run_dir.relative_to(self.root)),
                        False,
                    )
                except Exception:
                    pass
            except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                continue

    def _recover_interrupted_runs(self):
        """Quarantine unfinished units left by a supervisor process restart.

        A restarted supervisor has no safe handle to a prior Job Object.  All
        non-terminal active/queued units with readable status are therefore
        marked interrupted and retained as failed evidence. Missing/damaged
        status stays reconciliation-pending without assuming the prior process
        stopped or launching it a second time.
        """
        active_root = self.root / "runs" / "active"
        terminal = {"completed", "failed", "cancelled", "interrupted"}
        for marker_path in sorted(active_root.glob("*/*/*/" + RUN_MARKER)):
            run_dir = marker_path.parent
            try:
                request = load_json(run_dir / "request.json")
                status = self._load_run_status(request, run_dir)
                if not run_dir.exists() or status.get("state") == "reconcile_pending":
                    continue
                if status.get("state") in terminal:
                    continue
                destination = self._retain(request, run_dir, "failed")
                self.publish(
                    request,
                    "interrupted",
                    "supervisor restarted before unit completion",
                    100,
                    str(destination.relative_to(self.root)),
                    False,
                )
            except (OSError, KeyError, ValueError, json.JSONDecodeError):
                # Leave malformed material for the normal quarantine/cleanup
                # path; startup must not broaden its authority.
                continue

    def reload_config(self):
        if self.config_path is None:
            return
        latest = load_json(self.config_path)
        if latest.get("root_uuid") != self.root_uuid or latest.get("remote_root") != str(self.root):
            raise RuntimeError("live configuration attempted to switch the active root")
        # Runtime identity belongs to the running executable, not a mutable
        # config file.  A newly deployed config is consumed only after an exact
        # supervisor restart.
        latest["runtime_version"] = self.runtime_version
        self.config = latest
        self.validated_hard_cap = int(latest.get("max_concurrent_units", 1))
        self.max_concurrent = min(
            self.validated_hard_cap,
            int(latest.get("target_concurrent_units", self.validated_hard_cap)),
        )
        if hasattr(self, "metric_sampler"):
            self.metric_sampler.telemetry_policy = dict(latest.get("telemetry_policy") or {})

    def _verify_root(self):
        marker_path = self.root / ROOT_MARKER
        marker = load_json(marker_path)
        if marker.get("root_uuid") != self.root_uuid or marker.get("machine_id") != self.machine_id:
            raise RuntimeError("root marker does not match supervisor configuration")

    def _ensure_dirs(self):
        for relative in (
            "spool/incoming", "spool/ready", "spool/cancel", "spool/status",
            "spool/activations",
            "spool/commands/incoming", "spool/commands/results", "spool/commands/archive",
            "spool/commands/nonces",
            "runs/active", "runs/retained/success", "runs/retained/failed",
            "agent", "logs", "quarantine", "cache/objects",
        ):
            (self.root / relative).mkdir(parents=True, exist_ok=True)

    def _comsol_process_snapshot(self):
        """Return internal process identities plus a privacy-preserving hash."""
        if os.name != "nt":
            return [], hashlib.sha256(b"").hexdigest()
        script = r"""
$items = Get-CimInstance Win32_Process | Where-Object {
  $_.Name -match '^(comsol|comsolbatch|mphserver|comsolmphserver)\.exe$' -and
  $_.Name -notmatch '^(lmgrd|lmadmin)\.exe$'
} | ForEach-Object {
  [PSCustomObject]@{
    pid=[int]$_.ProcessId
    parent_pid=[int]$_.ParentProcessId
    name=[string]$_.Name
    created=[string]$_.CreationDate
  }
}
@($items) | ConvertTo-Json -Compress
"""
        # creationflags is Windows-only; passing even 0 on POSIX raises.
        windowless = (
            {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)}
            if os.name == "nt"
            else {}
        )
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
            **windowless,
        )
        if completed.returncode != 0:
            raise RuntimeError("COMSOL process inventory is unavailable")
        raw = completed.stdout.strip() or "[]"
        parsed = json.loads(raw)
        processes = parsed if isinstance(parsed, list) else [parsed]
        identities = sorted(
            "%s|%s|%s" % (item.get("pid"), item.get("created"), item.get("name"))
            for item in processes
        )
        return processes, hashlib.sha256("\n".join(identities).encode("utf-8")).hexdigest()

    def _terminate_host_comsol(self, expected_hash):
        processes, process_hash = self._comsol_process_snapshot()
        if process_hash != expected_hash:
            raise RuntimeError("COMSOL process set changed before termination")
        for item in processes:
            pid = int(item["pid"])
            completed = subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                **(
                    {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)}
                    if os.name == "nt"
                    else {}
                ),
            )
            if completed.returncode not in {0, 128}:
                raise RuntimeError("one or more COMSOL process trees could not be terminated")
        return len(processes), process_hash

    def _validate_machine_command(self, command):
        required = {
            "command_id", "machine_id", "action", "root_uuid", "runtime_version",
            "nonce", "created_at", "expires_at",
        }
        missing = sorted(required - set(command))
        if missing:
            raise ValueError("machine command missing fields: %s" % ", ".join(missing))
        safe_name(str(command["command_id"]), "command_id")
        safe_name(str(command["nonce"]), "nonce")
        if command["machine_id"] != self.machine_id:
            raise ValueError("machine command targets a different machine")
        if command["root_uuid"] != self.root_uuid:
            raise ValueError("machine command root UUID mismatch")
        if command["runtime_version"] != self.runtime_version:
            raise ValueError("machine command runtime mismatch")
        if command["action"] not in ALLOWED_CONTROL_ACTIONS:
            raise ValueError("machine command action is not allowlisted")
        expires = datetime.fromisoformat(str(command["expires_at"]).replace("Z", "+00:00"))
        if expires <= utc_now():
            raise ValueError("machine command expired")
        nonce_path = self.root / "spool" / "commands" / "nonces" / (command["nonce"] + ".used")
        try:
            with nonce_path.open("x", encoding="ascii") as handle:
                handle.write(command["command_id"])
        except FileExistsError:
            raise ValueError("machine command nonce was already used")

    def _machine_command_result(self, command, state, message, **details):
        payload = {
            "schema_version": 1,
            "command_id": command.get("command_id", "unknown"),
            "machine_id": self.machine_id,
            "action": command.get("action", "health_probe"),
            "state": state,
            "affected_network_runs": int(details.get("affected_network_runs", 0)),
            "affected_comsol_processes": int(details.get("affected_comsol_processes", 0)),
            "process_set_hash": details.get("process_set_hash"),
            "message": message,
            "created_at": command.get("created_at", iso_now()),
            "completed_at": iso_now(),
        }
        result_path = self.root / "spool" / "commands" / "results" / (payload["command_id"] + ".json")
        write_json_atomic(result_path, payload)
        return payload

    def process_machine_commands(self):
        incoming = self.root / "spool" / "commands" / "incoming"
        archive = self.root / "spool" / "commands" / "archive"
        for command_path in sorted(incoming.glob("*.ready")):
            command = {"command_id": command_path.stem, "action": "health_probe"}
            result_path = self.root / "spool" / "commands" / "results" / (command_path.stem + ".json")
            if result_path.exists():
                command_path.replace(archive / command_path.name)
                continue
            try:
                command = load_json(command_path)
                self._validate_machine_command(command)
                action = command["action"]
                if action == "health_probe":
                    processes, process_hash = self._comsol_process_snapshot()
                    self._machine_command_result(
                        command,
                        "completed",
                        "supervisor health probe completed",
                        affected_network_runs=len(self.active),
                        affected_comsol_processes=len(processes),
                        process_set_hash=process_hash,
                    )
                elif action == "set_target_capacity":
                    target = int(command.get("target_concurrent_units"))
                    if target < 0 or target > self.validated_hard_cap:
                        raise ValueError("target capacity exceeds the validated hard cap")
                    self.config["target_concurrent_units"] = target
                    self.max_concurrent = target
                    if self.config_path is not None:
                        write_json_atomic(self.config_path, self.config)
                    self._machine_command_result(command, "completed", "target capacity synchronized")
                elif action == "set_hard_capacity":
                    hard_cap = int(command.get("hard_capacity_units"))
                    if hard_cap < 1 or hard_cap > 64:
                        raise ValueError("hard capacity is outside the supported range")
                    self.validated_hard_cap = hard_cap
                    self.config["max_concurrent_units"] = hard_cap
                    self.config["target_concurrent_units"] = min(
                        int(self.config.get("target_concurrent_units", hard_cap)), hard_cap
                    )
                    self.max_concurrent = min(
                        self.validated_hard_cap,
                        int(self.config["target_concurrent_units"]),
                    )
                    if self.config_path is not None:
                        write_json_atomic(self.config_path, self.config)
                    self._machine_command_result(command, "completed", "hard capacity synchronized")
                elif action == "graceful_stop":
                    for entry in self.active.values():
                        entry["cancelled"] = True
                        entry["process"].terminate()
                    self._machine_command_result(
                        command,
                        "completed",
                        "graceful cancellation requested; no force escalation will occur",
                        affected_network_runs=len(self.active),
                    )
                elif action == "emergency_stop_network":
                    count = len(self.active)
                    for entry in self.active.values():
                        entry["cancelled"] = True
                        entry["guard"].terminate(130)
                    self._machine_command_result(
                        command,
                        "completed",
                        "Network-owned process trees terminated",
                        affected_network_runs=count,
                    )
                elif action == "emergency_stop_host":
                    count, process_hash = self._terminate_host_comsol(
                        command.get("expected_process_set_hash")
                    )
                    self._machine_command_result(
                        command,
                        "completed",
                        "host COMSOL process trees terminated",
                        affected_comsol_processes=count,
                        process_set_hash=process_hash,
                    )
                elif action in {"restart_supervisor", "force_restart_supervisor"}:
                    if self.active and action == "restart_supervisor":
                        raise RuntimeError("supervisor restart is blocked while work is active")
                    self._machine_command_result(
                        command,
                        "completed",
                        "supervisor cooperative restart requested",
                        affected_network_runs=len(self.active),
                    )
                    self.stop_requested = True
                else:
                    raise ValueError("unsupported machine command")
            except Exception as exc:
                self._machine_command_result(
                    command,
                    "failed",
                    "%s: %s" % (type(exc).__name__, str(exc)[:500]),
                )
            finally:
                destination = archive / command_path.name
                if command_path.exists():
                    command_path.replace(destination)

    def status_path(self, external_id):
        return self.root / "spool" / "status" / (external_id + ".json")

    def publish(
        self,
        request,
        state,
        message="",
        progress=0.0,
        relative_path="",
        artifacts=False,
        progress_data=None,
    ):
        progress_data = progress_data or {}
        payload = {
            "schema_version": 1,
            "external_run_id": request["external_run_id"],
            "machine_id": self.machine_id,
            "job_id": request["job_id"],
            "work_unit_id": request["work_unit_id"],
            "request_hash": request["request_hash"],
            "state": state,
            "message": message,
            "progress_percent": progress,
            "completed_items": progress_data.get("completed_items"),
            "total_items": progress_data.get("total_items"),
            "eta_s": progress_data.get("eta_s"),
            "solver_variant": request.get("solver_variant"),
            "remote_relative_path": relative_path.replace("\\", "/"),
            "artifacts_available": bool(artifacts),
            "updated_at": iso_now(),
        }
        write_json_atomic(self.status_path(request["external_run_id"]), payload)

    def _validate_request(self, request):
        for key in ("external_run_id", "machine_id", "project_id", "job_id", "work_unit_id", "request_hash", "profile_id", "runtime_version"):
            if key not in request:
                raise ValueError("request missing %s" % key)
        for key in ("external_run_id", "machine_id", "project_id", "job_id", "work_unit_id", "runtime_version"):
            safe_name(str(request[key]), key)
        if request["machine_id"] != self.machine_id:
            raise ValueError("bundle targets a different machine")
        if request["profile_id"] not in ALLOWED_PROFILES:
            raise ValueError("execution profile is not allowlisted")
        dispatch_state = request.get("dispatch_state", "queued")
        if dispatch_state not in ("queued", "prepared"):
            raise ValueError("bundle has an invalid dispatch state")
        if dispatch_state == "prepared" and not request.get("dispatch_reservation_id"):
            raise ValueError("prepared bundle is missing its dispatch reservation")
        if request["profile_id"] in COMSOL_PROFILES:
            solver_variant = request.get("solver_variant", "mumps")
            if request["profile_id"] in {"workbench-comsol-template-build-v1", "workbench-comsol-saved-readout-v1"} and (
                solver_variant != "mumps" or not request.get("solver_approval_id")
            ):
                raise ValueError("template construction requires its reviewed runtime approval")
            if solver_variant not in ("mumps", "cudss"):
                raise ValueError("COMSOL request has an unsupported solver variant")
            if solver_variant == "cudss" and not request.get("solver_approval_id"):
                raise ValueError("cuDSS request is missing its manual approval reference")
            request["solver_variant"] = solver_variant
            resolved = request.get("resolved_resources")
            resources = resolved.get("resources") if isinstance(resolved, dict) else None
            cpus = resources.get("cpus") if isinstance(resources, dict) else None
            if cpus is not None:
                if not isinstance(cpus, int) or isinstance(cpus, bool) or cpus < 1:
                    raise ValueError("resolved COMSOL CPU count is invalid")
                if cpus > max(1, int(os.cpu_count() or 1)):
                    raise ValueError("resolved COMSOL CPU count exceeds the worker host")
        if len(request["request_hash"]) != 64:
            raise ValueError("invalid request hash")

    def _verify_manifest(self, extracted, request):
        for record in request.get("files", []):
            relative = PurePosixPath(record["path"])
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError("unsafe manifest path")
            candidate = extracted / Path(*relative.parts)
            if not candidate.is_file():
                raise ValueError("missing bundle file: %s" % record["path"])
            if candidate.stat().st_size != int(record["size_bytes"]):
                raise ValueError("bundle size mismatch: %s" % record["path"])
            if sha256_file(candidate) != record["sha256"]:
                raise ValueError("bundle hash mismatch: %s" % record["path"])

    def process_incoming(self):
        incoming = self.root / "spool" / "incoming"
        for archive in sorted(incoming.glob("*.ready")):
            external = archive.stem
            unpack = incoming / (external + ".unpack")
            try:
                if unpack.exists():
                    shutil.rmtree(unpack)
                unpack.mkdir()
                safe_extract(archive, unpack)
                request = load_json(unpack / "request.json")
                self._validate_request(request)
                if request["external_run_id"] != external:
                    raise ValueError("archive name does not match external run ID")
                self._verify_manifest(unpack, request)
                run_dir = self.root / "runs" / "active" / request["project_id"] / request["job_id"] / request["work_unit_id"]
                if run_dir.exists():
                    existing = load_json(run_dir / RUN_MARKER)
                    if existing.get("request_hash") != request["request_hash"]:
                        raise ValueError("idempotency conflict for existing run")
                    shutil.rmtree(unpack)
                else:
                    run_dir.parent.mkdir(parents=True, exist_ok=True)
                    os.replace(str(unpack), str(run_dir))
                    write_json_atomic(run_dir / RUN_MARKER, {
                        "schema_version": 1,
                        "root_uuid": self.root_uuid,
                        "external_run_id": external,
                        "request_hash": request["request_hash"],
                        "created_at": iso_now(),
                    })
                archive.unlink()
                self.publish(
                    request,
                    request.get("dispatch_state", "queued"),
                    "standby bundle prepared" if request.get("dispatch_state") == "prepared" else "",
                    relative_path=str(run_dir.relative_to(self.root)),
                )
            except Exception as exc:
                quarantine = self.root / "quarantine" / (external + "-" + str(int(time.time())))
                quarantine.parent.mkdir(parents=True, exist_ok=True)
                if unpack.exists():
                    os.replace(str(unpack), str(quarantine))
                if archive.exists():
                    archive.rename(quarantine.with_suffix(".ready"))
                write_json_atomic(self.status_path(external), {
                    "schema_version": 1,
                    "external_run_id": external,
                    "machine_id": self.machine_id,
                    "job_id": "unknown",
                    "work_unit_id": "unknown",
                    "request_hash": "0" * 64,
                    "state": "failed",
                    "message": "bundle rejected: %s" % exc,
                    "progress_percent": 0,
                    "remote_relative_path": "",
                    "artifacts_available": False,
                    "updated_at": iso_now(),
                })

    def process_activations(self):
        activation_dir = self.root / "spool" / "activations"
        for activation_path in sorted(activation_dir.glob("*.ready")):
            try:
                payload = load_json(activation_path)
                external = safe_name(str(payload.get("external_run_id", "")), "external_run_id")
                if external != activation_path.stem:
                    raise ValueError("activation filename does not match external run ID")
                status_path = self.status_path(external)
                if not status_path.exists():
                    raise FileNotFoundError("prepared status is unavailable")
                status = load_json(status_path)
                if status.get("state") in ("queued", "running", "completed"):
                    activation_path.unlink(missing_ok=True)
                    continue
                if status.get("state") != "prepared":
                    raise ValueError("remote run is not prepared")
                relative = PurePosixPath(str(status.get("remote_relative_path", "")))
                if relative.is_absolute() or ".." in relative.parts:
                    raise ValueError("prepared status contains an unsafe run path")
                run_dir = self.root / Path(*relative.parts)
                request = load_json(run_dir / "request.json")
                if request.get("external_run_id") != external:
                    raise ValueError("prepared request identity mismatch")
                self.publish(
                    request,
                    "queued",
                    "standby activated after slot release",
                    relative_path=str(run_dir.relative_to(self.root)),
                )
                activation_path.unlink(missing_ok=True)
            except Exception as exc:
                record_supervisor_event(
                    self.config,
                    "standby_activation_failed",
                    activation_file=activation_path.name,
                    error_type=type(exc).__name__,
                    error_message=str(exc)[:500],
                )

    def _quarantine_malformed_active_run(self, run_dir, error):
        """Isolate one malformed run without taking down the supervisor."""

        active_root = (self.root / "runs" / "active").resolve()
        resolved = Path(run_dir).resolve()
        relative = resolved.relative_to(active_root)
        if len(relative.parts) != 3:
            raise ValueError("malformed active run is outside the expected project/job/unit layout")
        marker = {}
        try:
            marker = load_json(resolved / RUN_MARKER)
        except (OSError, ValueError, json.JSONDecodeError):
            pass
        identity = hashlib.sha256(str(relative).encode("utf-8")).hexdigest()[:16]
        destination = self.root / "quarantine" / (
            "malformed-active-run-%s-%s" % (int(time.time()), identity)
        )
        suffix = 0
        while destination.exists():
            suffix += 1
            destination = destination.with_name(destination.name + "-" + str(suffix))
        destination.parent.mkdir(parents=True, exist_ok=True)
        os.replace(str(resolved), str(destination))

        external = str(marker.get("external_run_id") or "")
        if external:
            try:
                external = safe_name(external, "external_run_id")
                status_path = self.status_path(external)
                status = load_json(status_path) if status_path.exists() else {
                    "schema_version": 1,
                    "external_run_id": external,
                    "machine_id": self.machine_id,
                    "job_id": relative.parts[1],
                    "work_unit_id": relative.parts[2],
                    "request_hash": str(marker.get("request_hash") or "0" * 64),
                    "progress_percent": 0,
                    "artifacts_available": False,
                }
                if status.get("state") not in {"completed", "failed", "cancelled", "interrupted"}:
                    status.update({
                        "state": "failed",
                        "message": "malformed active run quarantined: %s" % str(error)[:500],
                        "remote_relative_path": str(destination.relative_to(self.root)),
                        "updated_at": iso_now(),
                    })
                    write_json_atomic(status_path, status)
            except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
                pass
        record_supervisor_event(
            self.config,
            "malformed_active_run_quarantined",
            source_relative_path=str(Path("runs") / "active" / relative),
            quarantine_relative_path=str(destination.relative_to(self.root)),
            error_type=type(error).__name__,
            error_message=str(error)[:500],
        )
        return destination

    def _queued_runs(self):
        active_root = self.root / "runs" / "active"
        for marker_path in sorted(active_root.glob("*/*/*/" + RUN_MARKER)):
            run_dir = marker_path.parent
            try:
                request = load_json(run_dir / "request.json")
                external = request["external_run_id"]
            except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                self._quarantine_malformed_active_run(run_dir, exc)
                continue
            try:
                status = self._load_run_status(request, run_dir)
                if external not in self.active and run_dir.exists() and status.get("state") == "queued":
                    yield request, run_dir
            except (OSError, KeyError, TypeError, ValueError):
                # Mutable status damage does not authorize moving a live run.
                continue

    def _validate_job_paths(self, job, run_dir):
        root = self.root.resolve()
        output = (run_dir / "output").resolve()
        cache = (root / "cache" / "objects").resolve()
        if job.get("profile_id") == "rcn-safe-fake-v1":
            Path(job["out_manifest"]).resolve().relative_to(output)
            return
        if job.get("profile_id") == "project-worker-v1":
            project_root = (run_dir / "input" / "project").resolve()
            entrypoint = PurePosixPath(str(job.get("entrypoint", "")))
            if entrypoint.is_absolute() or ".." in entrypoint.parts or not entrypoint.parts:
                raise ValueError("project worker entrypoint must be relative")
            entry = (project_root / Path(*entrypoint.parts)).resolve()
            entry.relative_to(project_root)
            if not entry.is_file() or entry.suffix.lower() != ".py":
                raise ValueError("project worker entrypoint is unavailable")
            (run_dir / Path(job.get("out_manifest", "output/project-worker-manifest.json"))).resolve().relative_to(run_dir.resolve())
            if not isinstance(job.get("arguments", {}), dict):
                raise ValueError("project worker arguments must be an object")
            return
        template = Path(job["template_path"]).resolve()
        progress_path = Path(job.get("progress_path", run_dir / "progress.json")).resolve()
        template.relative_to(cache)
        progress_path.relative_to(run_dir.resolve())
        if job.get("schema_version") == 2:
            Path(job["output_path"]).resolve().relative_to(output)
        else:
            Path(job["out_csv"]).resolve().relative_to(output)
            Path(job["out_manifest"]).resolve().relative_to(output)

    def _member_launch_permission(self):
        try:
            from .member_session_gate import launch_permission
        except ImportError:
            from member_session_gate import launch_permission
        return launch_permission(self.config, required=False)

    def launch_ready(self):
        if not self._member_launch_permission()['allowed']:
            return
        while len(self.active) < self.max_concurrent:
            if not self._member_launch_permission()['allowed']:
                return
            queued = next(iter(self._queued_runs()), None)
            if queued is None:
                return
            request, run_dir = queued
            external = request["external_run_id"]
            stdout = None
            stderr = None
            process = None
            guard = None
            scratch_prepared = False
            try:
                try:
                    from .member_session_gate import rollback_prelaunch_scratch
                except ImportError:
                    from member_session_gate import rollback_prelaunch_scratch
                if (run_dir / '.rcn-member-prelaunch.json').exists():
                    if not rollback_prelaunch_scratch(self.root, self.config['root_uuid'], run_dir, request):
                        return
                runtime_root = self.root / "agent" / "versions" / request["runtime_version"]
                runtime = runtime_root / "workbench-src"
                if not runtime.is_dir() and request["profile_id"] != "project-worker-v1":
                    raise RuntimeError("requested runtime version is unavailable")
                job_path = run_dir / "input" / "job.json"
                job = load_json(job_path)
                request_resources = request.get("resolved_resources")
                job_resources = job.get("resolved_resources")
                if request["profile_id"] in {"workbench-comsol-template-build-v1", "workbench-comsol-saved-readout-v1"} and (
                    job.get("profile_id") != request["profile_id"]
                    or job.get("solver_approval_id") != request.get("solver_approval_id")
                    or job.get("runtime_version") != request["runtime_version"]
                    or job.get("template_sha256") != request.get("template_sha256")
                ):
                    raise ValueError("template construction job differs from its sealed supervisor request")
                if request["profile_id"] in FIXED_RECIPE_PROFILES:
                    resources_declared = request_resources is not None or job_resources is not None
                    if resources_declared and (
                        not isinstance(request_resources, dict)
                        or not isinstance(job_resources, dict)
                        or job_resources != request_resources
                    ):
                        raise ValueError("sealed job resources do not match the supervisor request")
                self._validate_job_paths(job, run_dir)
                (run_dir / "output").mkdir(parents=True, exist_ok=True)
                stdout = (run_dir / "stdout.txt").open("w", encoding="utf-8")
                stderr = (run_dir / "stderr.txt").open("w", encoding="utf-8")
                env = dict(os.environ)
                site = runtime_root / "site-packages"
                env["PYTHONPATH"] = os.pathsep.join(
                    str(path)
                    # The sealed workers are launched as standalone scripts.
                    # Include their versioned directory explicitly so sibling
                    # contract modules remain importable on every Python build.
                    for path in (site, runtime, runtime_root / "remote-agent")
                    if path.is_dir()
                )
                env["PYTHONIOENCODING"] = "utf-8"
                if request["profile_id"] in COMSOL_PROFILES:
                    scratch = prepare_scratch(
                        self.root, self.config["root_uuid"], run_dir, request,
                        reserve_gib=scratch_reserve_gib(self.root, self.config),
                    )
                    env.update(scratch_environment(scratch))
                    scratch_prepared = True
                flags = (
                    subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
                    if os.name == "nt" else 0
                )
                if request["profile_id"] == "rcn-safe-fake-v1":
                    command = [str(self.python), str(runtime_root / "remote-agent" / "fake_worker.py"), "--job", str(job_path)]
                elif request["profile_id"] == "project-worker-v1":
                    command = [str(self.python), str(runtime_root / "remote-agent" / "project_worker.py"), "--job", str(job_path)]
                else:
                    command = [str(self.python), str(runtime_root / "remote-agent" / "comsol_worker_bootstrap.py"), "--job", str(job_path)]
                if not self._member_launch_permission()['allowed']:
                    for handle in (stdout, stderr):
                        if handle is not None:
                            handle.close()
                    if scratch_prepared:
                        rollback_prelaunch_scratch(self.root, self.config['root_uuid'], run_dir, request, known_not_launched=True)
                    return
                if self._member_launch_permission()['reason'] != 'legacy-runtime':
                    try:
                        from .member_session_gate import authorize_execution_intent
                    except ImportError:
                        from member_session_gate import authorize_execution_intent
                    if not authorize_execution_intent(self, request, run_dir):
                        for handle in (stdout, stderr):
                            if handle is not None:
                                handle.close()
                        if scratch_prepared:
                            rollback_prelaunch_scratch(self.root, self.config['root_uuid'], run_dir, request, known_not_launched=True)
                        return
                process = subprocess.Popen(
                    command,
                    cwd=str(run_dir),
                    stdout=stdout,
                    stderr=stderr,
                    env=env,
                    creationflags=flags,
                    start_new_session=os.name != "nt",
                )
                guard = ProcessTreeGuard(process)
                self.active[external] = {
                    "request": request,
                    "run_dir": run_dir,
                    "process": process,
                    "guard": guard,
                    "stdout": stdout,
                    "stderr": stderr,
                    "started": time.time(),
                    "cancelled": False,
                }
                self.publish(
                    request,
                    "running",
                    "safe fake worker started"
                    if request["profile_id"] == "rcn-safe-fake-v1"
                    else "project worker started"
                    if request["profile_id"] == "project-worker-v1"
                    else "COMSOL worker started",
                    0 if request["profile_id"] in COMSOL_PROFILES else 5,
                    str(run_dir.relative_to(self.root)),
                )
                if request["profile_id"] in COMSOL_PROFILES:
                    allow_worker_start(self.root, self.config["root_uuid"], run_dir, request)
            except Exception as exc:
                tree_stopped = process is None and scratch_prepared
                if guard is not None:
                    try:
                        guard.terminate(1)
                        process.wait(timeout=5)
                        tree_stopped = guard.finish()
                    except Exception:
                        pass
                    guard.close()
                elif process is not None and process.poll() is None:
                    try:
                        process.terminate()
                        process.wait(timeout=5)
                    except Exception:
                        try:
                            process.kill()
                        except Exception:
                            pass
                for handle in (stdout, stderr):
                    if handle is not None:
                        try:
                            handle.close()
                        except Exception:
                            pass
                detail = "launch failed: %s: %s" % (type(exc).__name__, str(exc)[:500])
                self.active.pop(external, None)
                self._cleanup_finished_scratch(request, run_dir, tree_stopped)
                try:
                    self._finish_failed(request, run_dir, detail, cancelled=False)
                except Exception as finish_exc:
                    record_supervisor_event(
                        self.config,
                        "unit_launch_finalization_failed",
                        external_run_id=external,
                        error_type=type(finish_exc).__name__,
                        error_message=str(finish_exc)[:500],
                        launch_error=detail,
                    )
                    try:
                        relative = str(run_dir.relative_to(self.root)) if run_dir.exists() else ""
                        self.publish(request, "failed", detail, 100, relative, False)
                    except Exception:
                        pass

    def process_cancellations(self):
        cancel_dir = self.root / "spool" / "cancel"
        for cancel_path in sorted(cancel_dir.glob("*.json")):
            external = cancel_path.stem
            try:
                safe_name(external, "external_run_id")
                entry = self.active.get(external)
                if entry:
                    entry["cancelled"] = True
                    self.publish(entry["request"], "cancel_pending", "terminating exact task process tree", 0, str(entry["run_dir"].relative_to(self.root)))
                    entry["guard"].terminate(130)
                else:
                    status_path = self.status_path(external)
                    if status_path.exists():
                        status = load_json(status_path)
                        if status.get("state") in ("prepared", "queued"):
                            run_dir = self.root / Path(status["remote_relative_path"])
                            try:
                                run_dir.resolve().relative_to(
                                    (self.root / "runs" / "active").resolve()
                                )
                                request = load_json(run_dir / "request.json")
                            except (
                                OSError,
                                KeyError,
                                TypeError,
                                ValueError,
                                json.JSONDecodeError,
                            ) as exc:
                                destination = None
                                if run_dir.exists():
                                    try:
                                        destination = self._quarantine_malformed_active_run(
                                            run_dir,
                                            exc,
                                        )
                                    except (OSError, TypeError, ValueError):
                                        destination = None
                                status.update({
                                    "state": "cancelled",
                                    "message": "cancelled before launch; run metadata unavailable",
                                    "progress_percent": 100,
                                    "eta_s": 0,
                                    "artifacts_available": False,
                                    "updated_at": iso_now(),
                                })
                                if destination is not None:
                                    status["remote_relative_path"] = str(
                                        destination.relative_to(self.root)
                                    ).replace("\\", "/")
                                write_json_atomic(status_path, status)
                                record_supervisor_event(
                                    self.config,
                                    "orphaned_prelaunch_cancellation_finalized",
                                    external_run_id=external,
                                    error_type=type(exc).__name__,
                                    error_message=str(exc)[:500],
                                    quarantine_relative_path=(
                                        str(destination.relative_to(self.root))
                                        if destination is not None
                                        else None
                                    ),
                                )
                            else:
                                self._finish_failed(
                                    request,
                                    run_dir,
                                    "cancelled before launch",
                                    cancelled=True,
                                )
                cancel_path.unlink(missing_ok=True)
            except Exception as exc:
                record_supervisor_event(
                    self.config,
                    "cancellation_processing_deferred",
                    external_run_id=external,
                    error_type=type(exc).__name__,
                    error_message=str(exc)[:500],
                )

    def _item_provenance(self, request, run_dir):
        if request.get("profile_id") not in FIXED_RECIPE_PROFILES:
            return []
        job = load_json(run_dir / "input" / "job.json")
        result_path = Path(job["output_path"]).resolve()
        try:
            result_path.relative_to((run_dir / "output").resolve())
        except ValueError:
            # Retention moves the sealed input unchanged, including its old
            # absolute output path. Resolve only that exact original path.
            run_dir.resolve().relative_to((self.root / "runs" / "retained" / "success").resolve())
            original_output = self.root / "runs" / "active" / request["project_id"] / request["job_id"] / request["work_unit_id"] / "output"
            relative = result_path.relative_to(original_output.resolve())
            result_path = run_dir / "output" / relative
        result = load_json(result_path)
        expected = job.get("items")
        actual = result.get("items")
        if not isinstance(expected, list) or not isinstance(actual, list) or len(actual) != len(expected):
            raise ValueError("fixed recipe result item coverage is incomplete")
        if request.get("profile_id") == "workbench-comsol-saved-readout-v1":
            try:
                from .saved_readout_contracts import (
                    SAVED_READOUT_PROFILE_ID, PX1050_SAVED_READOUT_DIAGNOSTIC,
                    saved_readout_contract, validate_saved_readout_items,
                )
            except ImportError:
                from saved_readout_contracts import (
                    SAVED_READOUT_PROFILE_ID, PX1050_SAVED_READOUT_DIAGNOSTIC,
                    saved_readout_contract, validate_saved_readout_items,
                )
            validate_saved_readout_items(solver_variant=job.get("solver_variant"), items=expected)
            diagnostic_name = expected[0]["payload"]["diagnostic"]["name"]
            registered = saved_readout_contract(diagnostic_name)
            if (diagnostic_name == PX1050_SAVED_READOUT_DIAGNOSTIC
                    and result.get("diagnostic") != diagnostic_name):
                raise ValueError("saved readout result changed its fixed diagnostic")
            for counter in ("study_calls", "geometry_calls", "mesh_calls", "solver_calls"):
                if type(result.get(counter)) is not int or result[counter] != 0:
                    raise ValueError("saved readout result must attest zero geometry, mesh, Study and solver calls")
            if (result.get("output_schema") != SAVED_READOUT_PROFILE_ID
                    or result.get("saved_output_mph") is not False
                    or result.get("source_template_unchanged") is not True
                    or result.get("template_role") != registered["template_role"]
                    or result.get("template_sha256") != registered["template_sha256"]
                    or result.get("output_contract_sha256") != registered["output_contract_sha256"]
                    or result.get("setup_fingerprint") != expected[0].get("setup_fingerprint")):
                raise ValueError("saved readout result changed its immutable source or output contract")
            for field in ("runtime_version", "solver_approval_id", "machine_id", "attempt_id"):
                if not job.get(field) or result.get(field) != job[field]:
                    raise ValueError("saved readout result changed its approved execution identity")
            for expected_item, actual_item in zip(expected, actual, strict=True):
                if (actual_item.get("item_id") != expected_item.get("item_id")
                        or type(actual_item.get("ordinal")) is not int
                        or actual_item["ordinal"] != expected_item.get("ordinal")
                        or "actual_solver" not in actual_item
                        or actual_item["actual_solver"] is not None
                        or type(actual_item.get("native_readout_complete")) is not bool):
                    raise ValueError("saved readout result cannot claim solver execution or change item identity")
                for key, filename in (("diagnostic_audit", "saved_readout_audit.json"),
                                      ("diagnostic_data", "saved_field_readout.json")):
                    record = actual_item.get(key)
                    path = result_path.parent / filename
                    if (not isinstance(record, dict)
                            or record.get("relative_path") != filename
                            or type(record.get("size_bytes")) is not int
                            or record["size_bytes"] < 0 or not path.is_file()
                            or path.stat().st_size != record["size_bytes"]
                            or sha256_file(path) != record.get("sha256")):
                        raise ValueError("saved readout result lacks its fixed hash-verified diagnostic artifact")
                audit = load_json(result_path.parent / "saved_readout_audit.json")
                if (diagnostic_name == PX1050_SAVED_READOUT_DIAGNOSTIC
                        and audit.get("diagnostic") != diagnostic_name):
                    raise ValueError("saved readout audit changed its fixed diagnostic")
                for counter in ("study_calls", "geometry_calls", "mesh_calls", "solver_calls"):
                    if type(audit.get(counter)) is not int or audit[counter] != result[counter]:
                        raise ValueError("saved readout audit contradicts its zero-run result")
                if (audit.get("saved_output_mph") is not False
                        or audit.get("source_template_unchanged") is not True
                        or "actual_solver" not in audit or audit["actual_solver"] is not None
                        or audit.get("source_template_sha256") != result["template_sha256"]
                        or audit.get("source_template_role") != result["template_role"]
                        or audit.get("output_contract_sha256") != result["output_contract_sha256"]
                        or audit.get("runtime_version") != result["runtime_version"]
                        or audit.get("native_readout_complete") is not actual_item["native_readout_complete"]):
                    raise ValueError("saved readout audit changed its source, runtime or native completeness")
            if any(path.is_file() and path.suffix.lower() == ".mph"
                   for path in result_path.parent.rglob("*")):
                raise ValueError("saved readout cannot publish a saved output MPH")
            # Partial native evidence remains collectable. No actual solver
            # provenance is fabricated for a saved-solution readout.
            return []
        if request.get("profile_id") == "workbench-comsol-template-build-v1":
            if type(result.get("study_calls")) is not int or result["study_calls"] != 0:
                raise ValueError("template construction result must attest zero Study calls")
            if result.get("output_schema") != "workbench-comsol-template-build-v1":
                raise ValueError("template construction result output schema is invalid")
            for expected_item, actual_item in zip(expected, actual, strict=True):
                if (actual_item.get("item_id") != expected_item.get("item_id")
                        or actual_item.get("ordinal") != expected_item.get("ordinal")
                        or actual_item.get("actual_solver") is not None):
                    raise ValueError("template construction result cannot claim solver execution")
            # An actual solver was not executed. Do not fabricate solver
            # provenance merely to reuse the normal artifact-transfer path.
            return []
        provenance = []
        for expected_item, actual_item in zip(expected, actual, strict=True):
            if (
                actual_item.get("item_id") != expected_item.get("item_id")
                or actual_item.get("ordinal") != expected_item.get("ordinal")
            ):
                raise ValueError("fixed recipe result item identity changed")
            solver = actual_item.get("actual_solver")
            if solver not in {"mumps", "cudss"}:
                raise ValueError("fixed recipe result lacks actual solver provenance")
            duration = actual_item.get("duration_s")
            if duration is not None and (
                isinstance(duration, bool) or not isinstance(duration, (int, float)) or duration < 0
            ):
                raise ValueError("fixed recipe result duration is invalid")
            provenance.append({
                "item_id": actual_item["item_id"],
                "ordinal": actual_item["ordinal"],
                "solver_variant": solver,
                "duration_s": duration,
            })
        return provenance

    def _artifact_manifest(self, request, run_dir):
        files = []
        output = run_dir / "output"
        for path in sorted(output.rglob("*")):
            if path.is_file():
                files.append({
                    "relative_path": str(path.relative_to(output)).replace("\\", "/"),
                    "size_bytes": path.stat().st_size,
                    "sha256": sha256_file(path),
                })
        manifest = {
            "schema_version": 1,
            "external_run_id": request["external_run_id"],
            "job_id": request["job_id"],
            "work_unit_id": request["work_unit_id"],
            "runtime_version": request["runtime_version"],
            "solver_variant": request.get("solver_variant"),
            "solver_approval_id": request.get("solver_approval_id"),
            "files": files,
            "item_provenance": self._item_provenance(request, run_dir),
            "created_at": iso_now(),
        }
        write_json_atomic(output / "artifact-manifest.json", manifest)
        return manifest

    def _retain(self, request, run_dir, outcome):
        destination = self.root / "runs" / "retained" / outcome / request["project_id"] / request["job_id"] / request["work_unit_id"]
        destination.parent.mkdir(parents=True, exist_ok=True)

        def retained_hash(path):
            """Read immutable identity from marker, or recover a missing marker."""
            marker = {}
            try:
                marker = load_json(path / RUN_MARKER)
            except (OSError, ValueError, json.JSONDecodeError):
                marker = {}
            if isinstance(marker, dict) and marker.get("request_hash"):
                return str(marker["request_hash"]), marker
            # A move can succeed before the marker write, or an older
            # supervisor can leave request.json without the retained marker.
            # request.json is part of the sealed run identity and is safe to
            # use for idempotent recovery; it is never used to overwrite a
            # directory with a different hash.
            try:
                identity = load_json(path / "request.json")
            except (OSError, ValueError, json.JSONDecodeError):
                identity = {}
            if isinstance(identity, dict) and identity.get("request_hash"):
                return str(identity["request_hash"]), marker
            return None, marker

        def restore_marker(path, marker):
            restored = dict(marker) if isinstance(marker, dict) else {}
            for key in ("schema_version", "request_hash", "external_run_id", "job_id", "work_unit_id", "project_id", "root_uuid", "created_at"):
                if key not in restored and key in request:
                    restored[key] = request[key]
            restored["request_hash"] = request.get("request_hash")
            restored["outcome"] = outcome
            restored["retained_at"] = restored.get("retained_at") or iso_now()
            write_json_atomic(path / RUN_MARKER, restored)

        if destination.exists():
            # Recovery and cancellation can race after a supervisor restart.
            # Reuse an existing directory only when its immutable request hash
            # matches; otherwise preserve both attempts under a deterministic
            # evidence suffix instead of overwriting either result.
            existing_hash, existing_marker = retained_hash(destination)
            if existing_hash == request.get("request_hash"):
                if run_dir.exists() and run_dir.resolve() != destination.resolve():
                    shutil.rmtree(run_dir)
                restore_marker(destination, existing_marker)
                return destination
            suffix = hashlib.sha256(str(request.get("request_hash", "")).encode("utf-8")).hexdigest()[:12]
            base_destination = destination.with_name(destination.name + "-conflict-" + suffix)
            destination = base_destination
            collision_index = 0
            while destination.exists():
                conflict_hash, conflict_marker = retained_hash(destination)
                if conflict_hash == request.get("request_hash"):
                    if run_dir.exists() and run_dir.resolve() != destination.resolve():
                        shutil.rmtree(run_dir)
                    restore_marker(destination, conflict_marker)
                    return destination
                collision_index += 1
                destination = base_destination.with_name(
                    base_destination.name + "-" + str(collision_index)
                )
        replace_with_retry(run_dir, destination)
        marker = load_json(destination / RUN_MARKER)
        restore_marker(destination, marker)
        return destination

    def _finish_failed(self, request, run_dir, message, cancelled):
        destination = self._retain(request, run_dir, "failed")
        self.publish(
            request,
            "cancelled" if cancelled else "failed",
            message,
            100,
            str(destination.relative_to(self.root)),
            False,
        )

    def reap(self):
        self._recover_completed_finalizations()
        for external, entry in list(self.active.items()):
            process = entry["process"]
            return_code = process.poll()
            if return_code is None:
                request = entry["request"]
                progress_data = {}
                if request["profile_id"] in COMSOL_PROFILES:
                    progress_path = entry["run_dir"] / "progress.json"
                    if progress_path.is_file():
                        try:
                            progress_data = load_json(progress_path)
                        except (OSError, ValueError):
                            progress_data = {}
                    completed = int(progress_data.get("completed_items", 0))
                    total = int(progress_data.get("total_items", 0))
                    progress = (100.0 * completed / total) if total else 0.0
                    message = progress_data.get("message") or (
                        "solving first parameter point"
                        if completed == 0
                        else "solving parameter point %s/%s" % (min(completed + 1, total), total)
                    )
                elif request["profile_id"] == "rcn-safe-fake-v1":
                    elapsed = max(1.0, time.time() - entry["started"])
                    progress = min(90.0, 5.0 + elapsed / 60.0)
                    message = "safe fake worker running"
                else:
                    progress = 0.0
                    message = "project worker running"
                self.publish(
                    request,
                    "running",
                    message,
                    progress,
                    str(entry["run_dir"].relative_to(self.root)),
                    progress_data=progress_data,
                )
                continue
            entry["stdout"].close()
            entry["stderr"].close()
            tree_stopped = False
            try:
                finish = getattr(entry["guard"], "finish", None)
                if finish is not None:
                    tree_stopped = finish()
                else:
                    entry["guard"].close()
            except Exception:
                # A cleanup barrier failure must not lose a completed result.
                entry["guard"].close()
            request = entry["request"]
            run_dir = entry["run_dir"]
            try:
                if return_code == 0 and not entry["cancelled"]:
                    self._artifact_manifest(request, run_dir)
                    self._cleanup_finished_scratch(request, run_dir, tree_stopped)
                    destination = self._retain(request, run_dir, "success")
                    self.publish(request, "completed", "outputs ready", 100, str(destination.relative_to(self.root)), True)
                else:
                    self._cleanup_finished_scratch(request, run_dir, tree_stopped)
                    self._finish_failed(
                        request,
                        run_dir,
                        worker_failure_summary(run_dir / "stderr.txt", return_code),
                        entry["cancelled"],
                    )
            except Exception as exc:
                # Finalization must never take down the supervisor.  A worker
                # can finish successfully while manifest creation, retention,
                # or status publication encounters a transient filesystem
                # problem (for example, a delayed Windows file handle close).
                # Keep the exact unit auditable and reconciliation-pending so
                # the validated completed output can be finalized later
                # without creating a duplicate scientific attempt.
                detail = "worker finalization failed: %s" % str(exc)[:500]
                try:
                    relative = str(run_dir.relative_to(self.root)) if run_dir.exists() else ""
                    self.publish(request, "reconcile_pending", detail, 100, relative, False)
                except Exception:
                    # If retention already moved the directory or status
                    # publication itself failed, the supervisor must still
                    # continue serving other work units.  Recovery on the
                    # next restart will quarantine any non-terminal marker.
                    pass
            finally:
                self.active.pop(external, None)

    def _cleanup_finished_scratch(self, request, run_dir, tree_stopped):
        if request.get("profile_id") not in COMSOL_PROFILES:
            return
        try:
            if tree_stopped and (run_dir / SCRATCH_MARKER).is_file():
                record_tree_exit(self.root, self.config.get("root_uuid"), run_dir, request)
            result = cleanup_scratch(
                self.root, self.config.get("root_uuid"), run_dir, request,
                tree_stopped=tree_stopped,
            )
        except Exception as exc:
            result = {"state": "pending_cleanup", "error_type": type(exc).__name__}
        try:
            write_json_atomic(run_dir / "scratch-cleanup.json", result)
            record_supervisor_event(
                self.config, "unit_scratch_cleanup",
                external_run_id=request["external_run_id"], **result,
            )
        except OSError:
            pass  # Disk evidence failure must not turn valid science into failure.

    def _retry_scratch_cleanup(self):
        """Bounded retry of new marked scratch, never of retained results.

        Persisted exact-tree exit proof survives retention/restart. Without
        it, interrupted runs remain untouched for explicit reconciliation.
        """
        now = time.monotonic()
        if now < getattr(self, "_scratch_retry_after", 0):
            return
        self._scratch_retry_after = now + 60
        if getattr(self, "_scratch_retry_iterator", None) is None:
            self._scratch_retry_iterator = (
                self.root / "runs" / "retained"
            ).glob("*/*/*/*/" + SCRATCH_MARKER)
        for _ in range(16):
            marker = next(self._scratch_retry_iterator, None)
            if marker is None:
                self._scratch_retry_iterator = None
                break
            run_dir = marker.parent
            try:
                if not (run_dir / "scratch").exists():
                    continue
                request = load_json(run_dir / "request.json")
                if request["external_run_id"] in self.active:
                    continue
                if has_tree_exit_proof(self.root, self.config.get("root_uuid"), run_dir, request):
                    self._cleanup_finished_scratch(request, run_dir, True)
            except (OSError, ValueError, KeyError, TypeError):
                continue  # Malformed/unknown ownership never widens deletion.

    def _sample_metrics(self, active_processes):
        try:
            metrics = self.metric_sampler.sample(active_processes)
        except Exception as exc:
            with self._metric_lock:
                self._metric_sampler_status = {
                    "state": "failed",
                    "started_at": self._metric_sampler_status.get("started_at"),
                    "finished_at": iso_now(),
                    "error": "%s: %s" % (type(exc).__name__, str(exc)[:240]),
                }
            return
        with self._metric_lock:
            self._latest_metrics = metrics
            self._metric_sampler_status = {
                "state": "ready",
                "started_at": self._metric_sampler_status.get("started_at"),
                "finished_at": iso_now(),
                "error": "",
            }

    def _start_metric_sample_if_idle(self):
        with self._metric_lock:
            if self._metric_thread is not None and self._metric_thread.is_alive():
                return
            now_monotonic = time.monotonic()
            telemetry_policy = getattr(self.metric_sampler, "telemetry_policy", {})
            sample_interval_s = max(
                1.0,
                float(telemetry_policy.get("sample_interval_s", 5)),
            )
            last_started = getattr(self, "_metric_last_started_monotonic", None)
            if last_started is not None and now_monotonic - last_started < sample_interval_s:
                return
            started_at = iso_now()
            self._metric_started_monotonic = now_monotonic
            self._metric_last_started_monotonic = now_monotonic
            self._metric_sampler_status = {
                "state": "sampling",
                "started_at": started_at,
                "finished_at": self._metric_sampler_status.get("finished_at"),
                "error": "",
            }
            # Preserve the Job Object guard so telemetry can account for the
            # entire COMSOL descendant tree, including short-lived children.
            active_processes = [
                {
                    "process": entry["process"],
                    "guard": entry.get("guard"),
                    "request": entry.get("request"),
                    "run_dir": entry.get("run_dir"),
                }
                for entry in self.active.values()
            ]
            self._metric_thread = threading.Thread(
                target=self._sample_metrics,
                args=(active_processes,),
                name="rcn-metric-sampler",
                daemon=True,
            )
            self._metric_thread.start()

    def _metric_snapshot(self):
        with self._metric_lock:
            metrics = dict(self._latest_metrics)
            sampler_status = dict(self._metric_sampler_status)
            thread_running = self._metric_thread is not None and self._metric_thread.is_alive()
            started = self._metric_started_monotonic
        telemetry_policy = getattr(self.metric_sampler, "telemetry_policy", {})
        timeout_s = max(
            1.0,
            float(telemetry_policy.get("sample_timeout_s", 8)),
        )
        if thread_running and started is not None and time.monotonic() - started >= timeout_s:
            sampler_status["state"] = "stalled"
        return metrics, sampler_status

    def _restart_tunnel_task(self):
        if os.name != "nt":
            return
        task_name = str(self.config.get("tunnel_task_name") or "")
        if not task_name or any(character in task_name for character in "\r\n\0"):
            raise ValueError("configured tunnel task name is invalid")
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        subprocess.run(
            ["schtasks.exe", "/End", "/TN", task_name],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=flags,
        )
        completed = subprocess.run(
            ["schtasks.exe", "/Run", "/TN", task_name],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=flags,
        )
        if completed.returncode != 0:
            raise RuntimeError("fixed reverse-SSH task restart failed")

    def _report_outbound_heartbeat(self, metrics, running_work_unit_ids):
        try:
            reported_capacity = int(getattr(
                self,
                "max_concurrent",
                self.config.get(
                    "target_concurrent_units",
                    self.config.get("max_concurrent_units", 1),
                ),
            ))
            response = self.outbound_heartbeat.report(
                metrics=metrics,
                running_work_unit_ids=running_work_unit_ids,
                runtime_version=self.runtime_version,
                supervisor_reported_concurrent_units=reported_capacity,
                applied_telemetry_policy=validated_telemetry_policy(
                    self.config.get("telemetry_policy")
                ),
            )
            observation = (
                response.get("control_plane_observation", {})
                if isinstance(response, dict)
                else {}
            )
            desired_policy = response.get("desired_telemetry_policy") if isinstance(response, dict) else None
            desired_hash = (
                str(response.get("desired_telemetry_policy_sha256") or "")
                if isinstance(response, dict)
                else ""
            )
            if desired_policy is not None:
                normalized_policy = validated_telemetry_policy(desired_policy)
                if telemetry_policy_sha256(normalized_policy) != desired_hash:
                    raise ValueError("control-plane telemetry policy hash mismatch")
                current_policy = validated_telemetry_policy(
                    self.config.get("telemetry_policy") or normalized_policy
                )
                if current_policy != normalized_policy:
                    self.config["telemetry_policy"] = normalized_policy
                    self.metric_sampler.telemetry_policy = dict(normalized_policy)
                    if self.config_path is not None:
                        write_json_atomic(self.config_path, self.config)
                    record_supervisor_event(
                        self.config,
                        "telemetry_policy_applied",
                        telemetry_policy_sha256=desired_hash,
                    )
            transport = observation.get("transport_state", "unknown")
            if transport == "disconnected":
                self._tunnel_unreachable_observations += 1
            elif transport == "connected":
                self._tunnel_unreachable_observations = 0
            if self._tunnel_unreachable_observations >= 2:
                self._restart_tunnel_task()
                self._tunnel_unreachable_observations = 0
            write_json_atomic(self.root / "agent" / "control-plane-observation.json", {
                "schema_version": 1,
                "transport_state": transport,
                "control_state": observation.get("control_state", "unknown"),
                "observed_at": observation.get("observed_at") or iso_now(),
            })
        except Exception as exc:
            record_supervisor_event(
                self.config,
                "outbound_heartbeat_failed",
                error_type=type(exc).__name__,
                error_message=str(exc)[:240],
            )

    def _start_outbound_heartbeat_if_idle(self, metrics, running_work_unit_ids):
        reporter = getattr(self, "outbound_heartbeat", None)
        if reporter is None or not reporter.enabled:
            return
        lock = getattr(self, "_outbound_lock", None)
        if lock is None:
            return
        with lock:
            thread = getattr(self, "_outbound_thread", None)
            if thread is not None and thread.is_alive():
                return
            self._outbound_thread = threading.Thread(
                target=self._report_outbound_heartbeat,
                args=(dict(metrics), list(running_work_unit_ids)),
                name="rcn-outbound-heartbeat",
                daemon=True,
            )
            self._outbound_thread.start()

    def _run_model_retirement_batch(self):
        try:
            try:
                from .model_retirement import WorkerModelRetirement
            except ImportError:  # sealed standalone worker script
                from model_retirement import WorkerModelRetirement
            result = WorkerModelRetirement(
                self.root, self.machine_id, self.root_uuid, self.outbound_heartbeat,
                enabled=lambda: self.config.get("scientific_model_retirement_enabled") is True
                    and not self.stop_requested,
            ).run_batch()
            if result["files_checked"] or result["failures"]:
                record_supervisor_event(self.config, "scientific_model_retirement_batch",
                    units_checked=result["units_checked"], files_checked=result["files_checked"],
                    deleted_bytes=result["deleted_bytes"], failures=result["failures"])
        except Exception as exc:
            # Local paths and machine tokens never enter the telemetry event.
            record_supervisor_event(self.config, "scientific_model_retirement_failed",
                error_type=type(exc).__name__)

    def _start_model_retirement_if_idle(self):
        reporter = getattr(self, "outbound_heartbeat", None)
        if (self.config.get("scientific_model_retirement_enabled") is not True
            or self.stop_requested or reporter is None or not reporter.enabled):
            return
        lock = getattr(self, "_model_retirement_lock", None)
        if lock is None:
            return
        with lock:
            thread = self._model_retirement_thread
            if thread is not None and thread.is_alive():
                return
            now = time.monotonic()
            if self._model_retirement_last_started is not None and now - self._model_retirement_last_started < 30:
                return
            self._model_retirement_last_started = now
            self._model_retirement_thread = threading.Thread(
                target=self._run_model_retirement_batch,
                name="rcn-scientific-model-retirement", daemon=True,
            )
            self._model_retirement_thread.start()

    def heartbeat(self):
        self._start_metric_sample_if_idle()
        metrics, sampler_status = self._metric_snapshot()
        running_work_unit_ids = sorted(
            entry["request"]["work_unit_id"] for entry in self.active.values()
        )
        write_json_atomic(self.root / "agent" / "status.json", {
            "schema_version": 2,
            "machine_id": self.machine_id,
            "root_uuid": self.root_uuid,
            "runtime_version": self.runtime_version,
            "pid": os.getpid(),
            "max_concurrent_units": self.max_concurrent,
            "active_run_ids": sorted(self.active),
            "metrics": metrics,
            "applied_telemetry_policy": validated_telemetry_policy(
                self.config.get("telemetry_policy") or {}
            ),
            "applied_telemetry_policy_sha256": telemetry_policy_sha256(
                self.config.get("telemetry_policy") or {}
            ),
            "telemetry_sampler": sampler_status,
            "updated_at": iso_now(),
        })
        self._start_outbound_heartbeat_if_idle(metrics, running_work_unit_ids)

    def run(self):
        last_heartbeat = 0.0
        while not self.stop_requested:
            self.member_launch_gate = self._member_launch_permission()
            self.process_incoming()
            self.process_activations()
            self.process_cancellations()
            self.process_machine_commands()
            self.reap()
            self._retry_scratch_cleanup()
            try:
                from .member_session_gate import reconcile_retirement
            except ImportError:
                from member_session_gate import reconcile_retirement
            reconcile_retirement(self)
            self.launch_ready()
            self._start_model_retirement_if_idle()
            sample_interval_s = max(
                1.0,
                float((self.config.get("telemetry_policy") or {}).get("sample_interval_s", 5)),
            )
            if time.time() - last_heartbeat >= min(5.0, sample_interval_s):
                self.reload_config()
                self.heartbeat()
                last_heartbeat = time.time()
            time.sleep(1)


def cleanup_preview(config):
    root = Path(config["remote_root"])
    root_marker = load_json(root / ROOT_MARKER)
    if root_marker.get("root_uuid") != config["root_uuid"]:
        raise RuntimeError("root marker mismatch")
    now = utc_now()
    result = []
    for outcome, days in (("success", int(config.get("success_retention_days", 3))), ("failed", int(config.get("failure_retention_days", 7)))):
        base = root / "runs" / "retained" / outcome
        for marker_path in base.glob("*/*/*/" + RUN_MARKER):
            marker = load_json(marker_path)
            retained = datetime.fromisoformat(marker["retained_at"])
            eligible = retained + timedelta(days=days)
            if eligible <= now:
                size = sum(path.stat().st_size for path in marker_path.parent.rglob("*") if path.is_file())
                result.append({
                    "relative_path": str(marker_path.parent.relative_to(root)).replace("\\", "/"),
                    "outcome": outcome,
                    "eligible_at": eligible.isoformat(),
                    "size_bytes": size,
                    "root_uuid": marker.get("root_uuid", ""),
                    "run_marker_valid": marker.get("root_uuid") == config["root_uuid"],
                })
    return result


def cleanup_confirm(config, relative_path, expected_root_uuid):
    root = Path(config["remote_root"]).resolve()
    if expected_root_uuid != config["root_uuid"]:
        raise ValueError("cleanup root UUID confirmation mismatch")
    candidate = (root / Path(relative_path)).resolve()
    candidate.relative_to(root / "runs" / "retained")
    marker = load_json(candidate / RUN_MARKER)
    if marker.get("root_uuid") != expected_root_uuid:
        raise ValueError("run marker does not authorize deletion")
    eligible = {item["relative_path"] for item in cleanup_preview(config)}
    normalized = str(candidate.relative_to(root)).replace("\\", "/")
    if normalized not in eligible:
        raise ValueError("candidate is not eligible for cleanup")
    shutil.rmtree(candidate)
    return {"deleted": normalized}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("run")
    sub.add_parser("status")
    sub.add_parser("cleanup-preview")
    clean = sub.add_parser("cleanup-confirm")
    clean.add_argument("--relative-path", required=True)
    clean.add_argument("--root-uuid", required=True)
    args = parser.parse_args(argv)
    config = load_json(args.config)
    if args.command == "run":
        lock_path = Path(config["remote_root"]) / "agent" / "supervisor.lock"
        supervisor = None
        record_supervisor_event(config, "starting")
        try:
            with SingleInstanceLock(lock_path):
                record_supervisor_event(config, "lock_acquired")
                supervisor = Supervisor(config, args.config)
                supervisor.run()
        except RuntimeError as exc:
            if supervisor is None and str(exc) == "another supervisor already owns this root":
                record_supervisor_event(
                    config,
                    "instance_rejected",
                    outcome="duplicate_instance",
                    error_type=type(exc).__name__,
                    error_message=str(exc),
                )
            else:
                record_supervisor_event(
                    config,
                    "crashed",
                    outcome="unhandled_exception",
                    error_type=type(exc).__name__,
                    error_message=str(exc)[:1000],
                    active_run_ids=sorted(supervisor.active) if supervisor is not None else [],
                    traceback="".join(traceback.format_exception(type(exc), exc, exc.__traceback__))[-12000:],
                )
            raise
        except BaseException as exc:
            record_supervisor_event(
                config,
                "crashed",
                outcome="unhandled_exception",
                error_type=type(exc).__name__,
                error_message=str(exc)[:1000],
                active_run_ids=sorted(supervisor.active) if supervisor is not None else [],
                traceback="".join(traceback.format_exception(type(exc), exc, exc.__traceback__))[-12000:],
            )
            raise
        else:
            record_supervisor_event(config, "stopped", outcome="clean_exit", active_run_ids=[])
    elif args.command == "status":
        print(json.dumps(load_json(Path(config["remote_root"]) / "agent" / "status.json"), separators=(",", ":")))
    elif args.command == "cleanup-preview":
        print(json.dumps(cleanup_preview(config), separators=(",", ":")))
    else:
        print(json.dumps(cleanup_confirm(config, args.relative_path, args.root_uuid), separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
