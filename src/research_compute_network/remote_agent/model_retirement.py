"""Machine-authenticated retirement of explicit worker recovery models only.

This sealed standalone module never selects files by age. The control plane
owns scientific gates/permits; this process owns only exact local syscalls and
their fsync recovery journals. Scientific output and input are never targets.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import stat
import tempfile
from contextlib import ExitStack
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

try:
    from .worker_storage import _plain_path, has_tree_exit_proof
except ImportError:  # sealed standalone worker script
    from worker_storage import _plain_path, has_tree_exit_proof


MAX_UNITS = 4
MAX_FILES = 16
_DIGEST = re.compile(r"[0-9a-f]{64}")
_MODEL = re.compile(r"(?:atom|unit)_[0-9]{8}_result\.mph")


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _identity(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,191}", value):
        raise ValueError("invalid model retirement identity")
    return value


def _parts(value):
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError("invalid model retirement path")
    parts = value.split("/")
    for part in parts:
        if (not part or part in {".", ".."} or part.endswith((".", " "))
            or any(ord(c) < 32 or c in '<>:"|?*' for c in part)
            or re.fullmatch(r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", part, re.I)):
            raise ValueError("invalid model retirement path")
    return parts


def _record(raw):
    if not isinstance(raw, dict):
        raise ValueError("invalid recovery file descriptor")
    path, size, digest = raw.get("relative_path"), raw.get("size_bytes"), raw.get("sha256")
    _parts(path)
    if type(size) is not int or size < 0 or not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
        raise ValueError("invalid recovery file descriptor")
    return {"relative_path": path, "size_bytes": size, "sha256": digest}


def _inventory(records):
    if not isinstance(records, list) or not records:
        raise ValueError("empty model retirement inventory")
    normalized = [_record(record) for record in records]
    names = [record["relative_path"].casefold() for record in normalized]
    if len(set(names)) != len(names):
        raise ValueError("ambiguous model retirement inventory")
    return sorted(normalized, key=lambda record: record["relative_path"])


def _read(path, *, limit=2 * 1024**2):
    with path.open("rb") as stream:
        raw = stream.read() if limit is None else stream.read(limit + 1)
    if limit is not None and len(raw) > limit:
        raise ValueError("model retirement metadata exceeds limit")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("model retirement metadata must be an object")
    return value


def _source_identity(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise ValueError("recovery source is not a plain file")
    return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def _verify_file(path, record):
    before = _source_identity(path)
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    if before[2] != record["size_bytes"] or digest.hexdigest() != record["sha256"]:
        raise ValueError("recovery file size or SHA mismatch")
    if _source_identity(path) != before:
        raise ValueError("recovery file changed during full SHA read")
    return before


class _ModelDisposalGuard:
    """Keep the full-SHA source exclusive through its Windows delete syscall.

    This module is also shipped alone in sealed workers. Only the standard
    library is used; scientific packages and Workbench are not dependencies.
    """
    def __init__(self, path, record):
        self.path, self.handle = path, None
        self.identity = _source_identity(path)
        if os.name != "nt":
            self.identity = _verify_file(path, record)
            return
        import ctypes
        from ctypes import wintypes
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        self.kernel.CreateFileW.restype = wintypes.HANDLE
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel.CloseHandle.restype = wintypes.BOOL
        # READ | DELETE, share=0. Active readers, writers, or replacements
        # conflict before any central authorization can be requested.
        handle = self.kernel.CreateFileW(str(path), 0x80010000, 0, None, 3, 0x200000, None)
        if handle in (None, ctypes.c_void_p(-1).value):
            raise ctypes.WinError(ctypes.get_last_error())
        self.handle = handle
        try:
            self.check()
            self.kernel.GetCurrentProcess.restype = wintypes.HANDLE
            self.kernel.DuplicateHandle.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.HANDLE,
                ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            self.kernel.DuplicateHandle.restype = wintypes.BOOL
            process, duplicate = self.kernel.GetCurrentProcess(), wintypes.HANDLE()
            if not self.kernel.DuplicateHandle(process, handle, process, ctypes.byref(duplicate), 0, False, 2):
                raise ctypes.WinError(ctypes.get_last_error())
            import msvcrt
            try:
                descriptor = msvcrt.open_osfhandle(duplicate.value, os.O_RDONLY | os.O_BINARY)
            except BaseException:
                self.kernel.CloseHandle(duplicate)
                raise
            digest = hashlib.sha256()
            with os.fdopen(descriptor, "rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            self.check()
            if self.identity[2] != record["size_bytes"] or digest.hexdigest() != record["sha256"]:
                raise ValueError("protected recovery file size or SHA mismatch")
        except BaseException:
            self.close()
            raise

    def check(self):
        if _source_identity(self.path) != self.identity:
            raise ValueError("protected recovery source identity changed")
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes
            class HandleInfo(ctypes.Structure):
                _fields_ = [("attributes", wintypes.DWORD), ("creation", wintypes.FILETIME),
                    ("access", wintypes.FILETIME), ("write", wintypes.FILETIME),
                    ("volume", wintypes.DWORD), ("size_high", wintypes.DWORD),
                    ("size_low", wintypes.DWORD), ("links", wintypes.DWORD),
                    ("index_high", wintypes.DWORD), ("index_low", wintypes.DWORD)]
            self.kernel.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.POINTER(HandleInfo)]
            self.kernel.GetFileInformationByHandle.restype = wintypes.BOOL
            info = HandleInfo()
            if not self.kernel.GetFileInformationByHandle(self.handle, ctypes.byref(info)):
                raise ctypes.WinError(ctypes.get_last_error())
            if (info.attributes & 0x400 or (info.index_high << 32) | info.index_low != self.identity[1]
                or (info.size_high << 32) | info.size_low != self.identity[2]):
                raise ValueError("protected recovery handle differs from its exact source")
        return self.identity

    def delete(self):
        self.check()
        if os.name != "nt":
            self.path.unlink()
            return
        import ctypes
        from ctypes import wintypes
        self.kernel.SetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_int,
            ctypes.c_void_p, wintypes.DWORD]
        self.kernel.SetFileInformationByHandle.restype = wintypes.BOOL
        disposition = ctypes.c_ubyte(1)
        if not self.kernel.SetFileInformationByHandle(self.handle, 4, ctypes.byref(disposition), 1):
            raise ctypes.WinError(ctypes.get_last_error())
        self.close()  # Finish unlink before fsync of the durable result/ACK.

    def close(self):
        if self.handle is not None:
            if not self.kernel.CloseHandle(self.handle):
                import ctypes
                raise ctypes.WinError(ctypes.get_last_error())
            self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def _sync_directory(path):
    if os.name != "nt":
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _windows_process_start(pid):
    """Return the Windows kernel creation timestamp without new dependencies."""
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE, *([ctypes.POINTER(wintypes.FILETIME)] * 4)]
    kernel.GetProcessTimes.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        if ctypes.get_last_error() == 87:  # ERROR_INVALID_PARAMETER: PID absent
            raise ProcessLookupError(pid)
        raise PermissionError("process creation time is unavailable")
    try:
        creation, exit_time, kernel_time, user_time = (wintypes.FILETIME() for _ in range(4))
        if not kernel.GetProcessTimes(handle, ctypes.byref(creation), ctypes.byref(exit_time),
                                      ctypes.byref(kernel_time), ctypes.byref(user_time)):
            raise PermissionError("process creation time is unavailable")
        if exit_time.dwHighDateTime or exit_time.dwLowDateTime:
            # An exited Windows process object can remain queryable while an
            # existing Popen/kernel handle is open. Its positive exit timestamp
            # still proves that this exact creation identity cannot run again.
            raise ProcessLookupError(pid)
        ticks = (creation.dwHighDateTime << 32) + creation.dwLowDateTime
        return ticks / 10000000 - 11644473600
    finally:
        kernel.CloseHandle(handle)


def _process_start(pid, clock=None):
    if clock in {None, "psutil"}:
        try:
            import psutil
        except ImportError:
            if clock == "psutil":
                raise PermissionError("original process clock is unavailable")
        else:
            try:
                return psutil.Process(pid).create_time(), "psutil"
            except psutil.NoSuchProcess as exc:
                raise ProcessLookupError(pid) from exc
            except psutil.AccessDenied as exc:
                raise PermissionError("process creation time is unavailable") from exc
    if os.name == "nt" and clock in {None, "win32_filetime"}:
        return _windows_process_start(pid), "win32_filetime"
    raise PermissionError("exact process identity is unavailable")


def _exact_process_exited(process, clock):
    try:
        started, _ = _process_start(process["process_id"], clock)
        return started != process["process_started"]
    except ProcessLookupError:
        return True
    except (PermissionError, OSError, ValueError):
        return False


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("model retirement redirects are forbidden")


class WorkerModelRetirement:
    def __init__(self, root, machine_id, root_uuid, reporter, *, enabled=False, request=None):
        self.root = Path(root).absolute()
        self.machine_id, self.root_uuid = _identity(machine_id), str(root_uuid)
        self.reporter, self.enabled = reporter, enabled
        self._transport = request
        self.prefix = f"/v1/machines/{self.machine_id}/model-retirements"

    def _is_enabled(self):
        return (self.enabled() if callable(self.enabled) else self.enabled) is True

    def _check_root(self):
        marker = _read(_plain_path(self.root / ".rcn-root.json", self.root))
        if marker.get("root_uuid") != self.root_uuid or marker.get("machine_id") != self.machine_id:
            raise ValueError("model retirement root binding changed")
        return self.root

    def _path(self, directory, relative):
        return _plain_path(Path(directory).joinpath(*_parts(relative)), self.root)

    def _request(self, method, path, payload=None):
        self._check_root()
        if self._transport is not None:
            return self._transport(method, path, payload)
        if self.reporter is None or not self.reporter.enabled:
            raise ValueError("machine model retirement transport is unavailable")
        base = str(self.reporter.base_url).rstrip("/")
        parsed = urlsplit(base)
        try:
            loopback = parsed.hostname == "localhost" or ipaddress.ip_address(parsed.hostname or "").is_loopback
        except ValueError:
            loopback = False
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or (parsed.scheme == "http" and not loopback)):
            raise ValueError("model retirement requires verified HTTPS or loopback")
        token_path = _plain_path(Path(self.reporter.token_file).absolute(), self.root)
        token = token_path.read_text(encoding="utf-8-sig").strip()
        if not token:
            raise ValueError("machine model retirement token is empty")
        # OutboundHeartbeatReporter accepts a base ending with /v1.
        base = base[:-3] if base.endswith("/v1") else base
        raw = None if payload is None else _canonical(payload)
        headers = {"Authorization": "Bearer " + token}
        if raw is not None:
            headers.update({"Content-Type": "application/json", "Content-Length": str(len(raw))})
        opener = build_opener(ProxyHandler({}), _NoRedirect())
        with opener.open(Request(base + path, data=raw, headers=headers, method=method), timeout=5) as response:
            encoded = response.read(2 * 1024**2 + 1)
        if len(encoded) > 2 * 1024**2:
            raise ValueError("model retirement response exceeds metadata limit")
        result = json.loads(encoded)
        if not isinstance(result, dict):
            raise ValueError("model retirement response must be an object")
        return result

    def _write_journal(self, path, payload):
        self._check_root()
        path = _plain_path(path, self.root)
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, name = tempfile.mkstemp(prefix=".worker-model-retirement-", suffix=".partial", dir=path.parent)
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(_canonical(payload))
                stream.flush()
                os.fsync(stream.fileno())
            self._check_root()
            _plain_path(path, self.root)
            temporary.replace(path)
            current = path.parent
            while True:
                _sync_directory(current)
                if current == self.root:
                    break
                current = current.parent
        finally:
            try:
                self._check_root()
                _plain_path(temporary, self.root).unlink(missing_ok=True)
            except (OSError, ValueError):
                pass

    def _validate_local(self, candidate):
        if not self._is_enabled():
            raise ValueError("worker model retirement is disabled")
        self._check_root()
        for key in ("acceptance_id", "job_id", "work_unit_id", "producer_attempt_id"):
            _identity(candidate.get(key))
        for key in ("request_hash", "job_request_hash", "manifest_sha256"):
            if not isinstance(candidate.get(key), str) or not _DIGEST.fullmatch(candidate[key]):
                raise ValueError("worker model retirement digest binding is missing")
        if candidate.get("root_uuid") != self.root_uuid:
            raise ValueError("worker model retirement root UUID mismatch")
        parts = _parts(candidate.get("directory_relative_path"))
        if len(parts) != 6 or parts[:3] != ["runs", "retained", "success"]:
            raise ValueError("worker model retirement requires successful retained run")
        directory = self._path(self.root, candidate["directory_relative_path"])
        request = _read(self._path(directory, "request.json"))
        if parts[3:] != [request.get(key) for key in ("project_id", "job_id", "work_unit_id")]:
            raise ValueError("worker model retirement run layout mismatch")
        marker = _read(self._path(directory, ".rcn-run.json"))
        if marker.get("root_uuid") != self.root_uuid or marker.get("outcome") != "success":
            raise ValueError("worker model retirement run marker mismatch")
        for key, expected in (("job_id", candidate["job_id"]), ("work_unit_id", candidate["work_unit_id"]),
                              ("attempt_id", candidate["producer_attempt_id"]), ("machine_id", self.machine_id),
                              ("external_run_id", candidate.get("producer_external_id")),
                              ("request_hash", candidate["request_hash"])):
            if request.get(key) != expected or expected is None:
                raise ValueError("worker model retirement original request mismatch")
        if any(marker.get(key) != request[key] for key in ("external_run_id", "request_hash")):
            raise ValueError("worker model retirement marker request mismatch")
        if not has_tree_exit_proof(self.root, self.root_uuid, directory, request):
            raise ValueError("worker model retirement process tree has not exited")
        output = self._path(directory, "output")
        transport = _read(self._path(output, "artifact-manifest.json"))
        for key in ("job_id", "work_unit_id", "external_run_id", "runtime_version"):
            if transport.get(key) != request.get(key):
                raise ValueError("worker model retirement transport producer mismatch")
        originals = _inventory(candidate.get("original_files"))
        if _inventory(transport.get("files")) != originals:
            raise ValueError("worker model retirement original inventory changed")
        inventory_file = _record(candidate.get("temporary_inventory_file"))
        if inventory_file not in originals:
            raise ValueError("worker recovery descriptor is not in original inventory")
        result_path = self._path(output, inventory_file["relative_path"])
        _verify_file(result_path, inventory_file)
        # Scientific scalar exports can exceed the API metadata limit. This
        # local file was fully hashed against the original producer inventory.
        result = _read(result_path, limit=None)
        # A coarsened unit can contain many complete per-item contracts. Its
        # frozen local job is not an unbounded remote API response.
        job = _read(self._path(directory, "input/job.json"), limit=None)
        # Frozen absolute output paths keep their old active-run location after retention.
        declared_output = Path(job.get("output_path", ""))
        active_output = self.root / "runs/active" / request["project_id"] / request["job_id"] / request["work_unit_id"] / "output"
        try:
            relative_output = declared_output.relative_to(active_output)
        except ValueError:
            relative_output = declared_output.relative_to(output)
        if not declared_output.is_absolute() or relative_output.as_posix() != inventory_file["relative_path"]:
            raise ValueError("worker recovery result file binding mismatch")
        for key in ("attempt_id", "machine_id", "runtime_version"):
            if job.get(key) != request.get(key) or result.get(key) != request.get(key):
                raise ValueError("worker recovery result producer mismatch")
        items = job.get("items")
        if not isinstance(items, list) or not items:
            raise ValueError("worker recovery has no declared atomic items")
        contract = items[0].get("payload", {}).get("output_contract_sha256")
        if not isinstance(contract, str) or not _DIGEST.fullmatch(contract) or result.get("output_contract_sha256") != contract:
            raise ValueError("worker recovery output contract mismatch")
        for item in items:
            declared = item.get("payload", {})
            if (declared.get("output_contract_sha256") != contract
                or declared.get("output_request", {}).get("temporary_solution_retention") != "recovery"
                or _digest(declared["output_request"]) != contract):
                raise ValueError("worker recovery storage was not explicitly declared")
        if result.get("output_request") != items[0]["payload"]["output_request"]:
            raise ValueError("worker recovery result output request mismatch")
        descriptors = result.get("temporary_model_inventory")
        normalized = _inventory(descriptors)
        for descriptor in descriptors:
            path_parts = _parts(descriptor["relative_path"])
            if (len(path_parts) != 2 or path_parts[0] != "recovery" or not _MODEL.fullmatch(path_parts[1])
                or descriptor.get("storage_kind") != "worker_recovery"
                or descriptor.get("output_contract_sha256") != contract):
                raise ValueError("worker recovery descriptor is not a temporary model")
        files = _inventory(candidate.get("files"))
        if any(record not in normalized for record in files):
            raise ValueError("worker recovery candidates differ from hashed descriptor")
        if {record["relative_path"].casefold() for record in files} & {
                record["relative_path"].casefold() for record in originals}:
            raise ValueError("worker recovery overlaps scientific inventory")
        return directory, files

    def _validate_intent(self, candidate, intent):
        _identity(intent.get("intent_id"))
        bound = intent.get("candidate")
        if not isinstance(bound, dict) or not isinstance(intent.get("files"), dict) or not isinstance(intent.get("writer_permits"), dict):
            raise ValueError("worker retirement intent is incomplete")
        for key in ("acceptance_id", "job_id", "work_unit_id", "producer_attempt_id", "producer_external_id",
                    "request_hash", "job_request_hash", "directory_relative_path", "root_uuid", "manifest_sha256"):
            if bound.get(key) != candidate.get(key):
                raise ValueError("worker retirement intent binding mismatch")
        target = bound.get("target", {})
        if (_record(bound.get("temporary_inventory_file")) != _record(candidate.get("temporary_inventory_file"))
            or _inventory(bound.get("original_files")) != _inventory(candidate.get("original_files"))
            or _inventory(bound.get("files")) != _inventory(candidate.get("files"))
            or target.get("host_id") != self.machine_id or target.get("store_id") != "worker-recovery"
            or target.get("generation") != self.root_uuid
            or target.get("physical_device_id") != "worker-root:" + self.machine_id + ":" + self.root_uuid
            or Path(target.get("volume_id", "")).absolute() != self.root):
            raise ValueError("worker retirement intent physical inventory mismatch")
        return bound

    def _run_candidate(self, candidate, budget):
        directory, files = self._validate_local(candidate)
        key = "worker-model-" + _digest({"acceptance_id": candidate["acceptance_id"],
            "machine_id": self.machine_id, "root_uuid": self.root_uuid,
            "directory": candidate["directory_relative_path"]})[:32]
        pending_id = candidate.get("intent_id")
        if pending_id is not None:
            _identity(pending_id)
        else:
            created = self._request("POST", self.prefix, {"acceptance_id": candidate["acceptance_id"], "idempotency_key": key})
            pending_id = _identity(created.get("intent_id"))
        # The create acknowledgement need not include writer_permits. GET is
        # the immutable operation plus its current durable permit snapshot.
        intent = self._request("GET", self.prefix + "/" + pending_id)
        if intent.get("intent_id") != pending_id:
            raise ValueError("worker pending intent acknowledgement mismatch")
        bound = self._validate_intent(candidate, intent)
        intent_id = intent["intent_id"]
        prefix = self.prefix + "/" + intent_id
        fingerprint = _digest(bound)
        transaction = self._path(self.root, "agent/model-retirement-journals/" + intent_id)
        operation_path = self._path(transaction, "operation.json")
        operation = {"intent_id": intent_id, "candidate_sha256": fingerprint}
        previous = _read(operation_path) if operation_path.exists() else None
        if previous is not None and previous != operation:
            raise ValueError("worker retirement local operation binding changed")
        if previous is None:
            self._write_journal(operation_path, operation)
        started, clock = _process_start(os.getpid())
        process = {"host_id": self.machine_id, "process_id": os.getpid(), "process_started": started}
        completed = []
        for record in files:
            state = intent["files"].get(record["relative_path"])
            if state in {"deleted", "already_absent"}:
                continue
            if state != "pending":
                raise ValueError("worker retirement file has no pending ledger entry")
            if budget["remaining"] <= 0:
                break
            budget["remaining"] -= 1
            budget["files_checked"] += 1
            path = self._path(directory, record["relative_path"])
            journal_path = self._path(transaction, _digest(record["relative_path"]) + ".json")
            journal = _read(journal_path) if journal_path.exists() else None
            contract = {**operation, "file": record}
            if journal and any(journal.get(field) != value for field, value in contract.items()):
                raise ValueError("worker retirement file journal binding changed")
            permit = intent["writer_permits"].get(record["relative_path"])
            released_permit = False
            if journal and not journal.get("owner_token") and permit:
                if permit.get("process") != journal.get("process"):
                    raise ValueError("worker pending permit differs from durable preauthorization")
                journal["owner_token"] = permit.get("owner_token")
                self._write_journal(journal_path, journal)
            if journal and journal.get("owner_token"):
                if permit and (permit.get("owner_token"), permit.get("process")) != (journal["owner_token"], journal.get("process")):
                    raise ValueError("worker durable permit is not active at control plane")
                released_permit = permit is None
            elif permit:
                raise ValueError("worker central permit has no matching durable journal")
            if journal and journal.get("process") != process:
                if (journal.get("process", {}).get("host_id") != self.machine_id
                    or not _exact_process_exited(journal["process"], journal.get("process_clock"))):
                    raise ValueError("worker retirement previous process has not demonstrably exited")
                if not journal.get("owner_token"):
                    journal = None
            with ExitStack() as handles:
                disposal = handles.enter_context(_ModelDisposalGuard(path, record)) if path.exists() else None
                identity = list(disposal.identity) if disposal else None
                if released_permit:
                    # A reconcile/abort ACK can be lost after the server released
                    # ownership. Only an unchanged, still-present source allows a
                    # fresh transaction. Absence never inherits a released token.
                    if identity is None or journal.get("result") is not None or identity != journal.get("source_identity"):
                        raise ValueError("released worker permit cannot acknowledge a missing or changed source")
                    journal = None
                if identity is None and (not journal or not journal.get("owner_token")):
                    raise ValueError("missing worker recovery source has no durable authorization")
                self._validate_local(candidate)
                if journal and journal.get("owner_token") and journal["process"] != process and identity is not None:
                    if identity != journal.get("source_identity"):
                        raise ValueError("worker recovery source changed after previous authorization")
                    acknowledgement = self._request("POST", prefix + "/reconcile", {
                        "relative_path": record["relative_path"], "owner_token": journal["owner_token"],
                        "previous_process": journal["process"], "exact_process_exited": True})
                    if acknowledgement.get("reconciled") is not True:
                        raise ValueError("worker permit reconciliation acknowledgement mismatch")
                    journal = None
                if not journal or not journal.get("owner_token"):
                    if identity is None:
                        raise ValueError("missing worker model cannot be newly authorized")
                    journal = {**contract, "source_identity": identity, "process": process, "process_clock": clock}
                    self._write_journal(journal_path, journal)
                    grant = self._request("POST", prefix + "/authorize", {
                        "file": record, "source_identity": identity, "process": process,
                        "actual_sha256_verified": True, "target_binding_verified": True, "formal_copy_verified": True})
                    if (grant.get("state") != "authorized" or grant.get("intent_id") != intent_id
                        or grant.get("relative_path") != record["relative_path"] or grant.get("process") != process
                        or not isinstance(grant.get("owner_token"), str) or not grant["owner_token"]):
                        raise ValueError("worker model authorization acknowledgement mismatch")
                    journal["owner_token"] = grant["owner_token"]
                    self._write_journal(journal_path, journal)
                result = journal.get("result")
                if identity is not None:
                    if result is not None or identity != journal.get("source_identity"):
                        raise ValueError("worker recovery source changed after durable permit")
                    try:
                        self._validate_local(candidate)
                        self._path(directory, record["relative_path"])
                        if _source_identity(path) != journal["source_identity"]:
                            raise ValueError("worker recovery source changed before unlink")
                        # A persisted permit records syscall ownership, not a
                        # perpetual policy approval. Recheck all science gates at
                        # every actual unlink; same-process authorization is stable.
                        fresh = self._request("POST", prefix + "/authorize", {
                            "file": record, "source_identity": identity, "process": process,
                            "actual_sha256_verified": True, "target_binding_verified": True, "formal_copy_verified": True})
                        if (fresh.get("state") != "authorized" or fresh.get("intent_id") != intent_id
                            or fresh.get("relative_path") != record["relative_path"] or fresh.get("process") != process
                            or fresh.get("owner_token") != journal["owner_token"]):
                            raise ValueError("worker fresh model authorization acknowledgement mismatch")
                        # The network round trip may coincide with a local root or
                        # file change. The exact syscall still has its own gate.
                        self._validate_local(candidate)
                        if _source_identity(self._path(directory, record["relative_path"])) != journal["source_identity"]:
                            raise ValueError("worker recovery source changed at syscall gate")
                    except Exception:
                        aborted = self._request("POST", prefix + "/abort", {
                            "relative_path": record["relative_path"], "owner_token": journal["owner_token"],
                            "process": journal["process"], "reason": "local_pre_unlink_validation_failed"})
                        if aborted.get("aborted") is True:
                            journal.pop("owner_token")
                            journal["aborted_before_unlink"] = True
                            self._write_journal(journal_path, journal)
                        raise
                    disposal.delete()
                    budget["deleted_bytes"] += record["size_bytes"]
                    _sync_directory(path.parent)
                    result = "deleted"
                elif result is None:
                    result = "already_absent"
                journal["result"] = result
                self._write_journal(journal_path, journal)
                acknowledgement = self._request("POST", prefix + "/complete", {
                    "relative_path": record["relative_path"], "owner_token": journal["owner_token"],
                    "process": journal["process"], "result": result, "target_binding_verified": True})
                if (acknowledgement.get("intent_id") != intent_id
                    or acknowledgement.get("files", {}).get(record["relative_path"]) != result):
                    raise ValueError("worker model completion acknowledgement mismatch")
                completed.append({"relative_path": record["relative_path"], "result": result})
        return {"intent_id": intent_id, "completed": completed}

    def run_batch(self):
        if not self._is_enabled():
            return {"enabled": False, "units_checked": 0, "files_checked": 0, "deleted_bytes": 0,
                    "completed": [], "failures": []}
        response = self._request("GET", self.prefix)
        candidates = response.get("candidates")
        if not isinstance(candidates, list):
            raise ValueError("worker model retirement candidate response is invalid")
        budget = {"remaining": MAX_FILES, "files_checked": 0, "deleted_bytes": 0}
        results, failures, checked = [], [], 0
        for candidate in candidates[:MAX_UNITS]:
            if budget["remaining"] <= 0 or not self._is_enabled():
                break
            checked += 1
            try:
                results.append(self._run_candidate(candidate, budget))
            except Exception as exc:
                failures.append({"acceptance_id": candidate.get("acceptance_id") if isinstance(candidate, dict) else None,
                                 "error_type": type(exc).__name__})
        return {"enabled": True, "units_checked": checked, "files_checked": budget["files_checked"],
                "deleted_bytes": budget["deleted_bytes"], "completed": results, "failures": failures}
