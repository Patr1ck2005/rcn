"""Authenticated Job-scoped streaming transfer, disabled until provisioned."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
import shutil
import stat
from secrets import token_hex
import tempfile
import threading
import traceback
import zipfile
import zlib
from functools import wraps
from contextlib import nullcontext
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from starlette.responses import Response
from pydantic import BaseModel, ConfigDict, Field
from fastapi.routing import APIRoute
from starlette.requests import ClientDisconnect

from .auth import AuthContext
from .hashing import sha256_file, sha256_value
from .models import AuditEvent
from .origin import MAX_BUNDLE_BYTES, OriginSpool
from .origin_transfer import CHUNK_BYTES, TRANSFER_PROTOCOL, identifier, managed_path, publish_new_file, verify_file
from .origin_assets import TransferAssetValidationCache, asset_path, declared_asset, verify_asset
from .origin_transfer_diagnostics import OriginTransferDiagnostics
from .spool_relocation import SpoolRelocationRegistry
from .storage_roots import StorageRootError
from .storage_lifecycle import StorageMetadataBusy
from .storage_io import io_priority, BackgroundBudget, BackgroundDeferred, BACKGROUND_CHUNK_BYTES
from .volume_budget import HARD_RESERVE_BYTES, VolumeBudget, VolumeBudgetError, VolumeCapacityUnavailable
from .result_preparations import (PreparationCancelled, ResultPreparations,
                                  TransferActivity, VERIFY_CHUNK_BYTES, verification_slots)


class PinnedFileResponse(FileResponse):
    """Keep an exact persistent reader pin through streaming and cancellation."""

    def __init__(self, *args, reader_pin=None, opened_file=None, storage_validator=None, diagnostics=None,
                 transfer_activity=None, background_budget=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.reader_pin = reader_pin
        self.opened_file = opened_file
        self.storage_validator = storage_validator
        self.diagnostics = diagnostics
        self.transfer_activity = transfer_activity
        self.background_budget = background_budget
        if background_budget is not None:
            self.chunk_size = BACKGROUND_CHUNK_BYTES

    async def __call__(self, scope, receive, send):
        accepted_bytes = 0
        response_status = None
        outcome, error_type = "body_complete", None
        activity = io_priority.foreground() if self.background_budget is None else nullcontext()
        activity.__enter__()

        async def observed_send(message):
            nonlocal accepted_bytes, response_status
            await send(message)
            if message["type"] == "http.response.body":
                accepted_bytes += len(message.get("body", b""))
            elif message["type"] == "http.response.start":
                response_status = message.get("status")

        try:
            try:
                if self.background_budget is not None:
                    await joined_io(self.background_budget.checkpoint)
                if self.storage_validator is not None:
                    try:
                        await joined_io(self.storage_validator)
                    except StorageRootError as exc:
                        raise HTTPException(409, {"reason_code": exc.reason_code}) from exc
                # Do not hand the path to a server extension that could return
                # before its independent sendfile reader has closed the handle.
                scope = {**scope, "extensions": {key: value for key, value in scope.get("extensions", {}).items()
                         if key != "http.response.pathsend"}}
                await super().__call__(scope, receive, observed_send)
            finally:
                if self.opened_file is not None:
                    await joined_io(self.opened_file.close)
                if self.reader_pin is not None:
                    await joined_io(self.reader_pin.release)
                if self.transfer_activity is not None:
                    await joined_io(self.transfer_activity.release)
        except BaseException as exc:
            outcome, error_type = "body_error", type(exc).__name__
            if isinstance(exc, BackgroundDeferred) and response_status is None:
                raise HTTPException(503, {"reason_code": exc.reason_code}, headers={"Retry-After": "2"}) from exc
            raise
        finally:
            activity.__exit__(None, None, None)
            if self.diagnostics is not None:
                self.diagnostics.finish(outcome, asgi_accepted_body_bytes=accepted_bytes,
                                        response_status=response_status, error_type=error_type)

    async def _body(self, send, start, end, *, multipart=False):
        await joined_io(self.opened_file.seek, start)
        while start < end:
            if self.background_budget is not None:
                await joined_io(self.background_budget.checkpoint)
            chunk = await joined_io(self.opened_file.read, min(self.chunk_size, end - start))
            if not chunk:
                raise OSError("verified result handle ended before its declared size")
            start += len(chunk)
            await send({"type": "http.response.body", "body": chunk,
                        "more_body": multipart or start < end})

    async def _handle_simple(self, send, send_header_only, send_pathsend):
        if self.opened_file is None:
            return await super()._handle_simple(send, send_header_only, False)
        await send({"type": "http.response.start", "status": self.status_code, "headers": self.raw_headers})
        if send_header_only or self.stat_result.st_size == 0:
            await send({"type": "http.response.body", "body": b"", "more_body": False})
        else:
            await self._body(send, 0, self.stat_result.st_size)

    async def _handle_single_range(self, send, start, end, file_size, send_header_only):
        if self.opened_file is None:
            return await super()._handle_single_range(send, start, end, file_size, send_header_only)
        self.headers["content-range"] = f"bytes {start}-{end - 1}/{file_size}"
        self.headers["content-length"] = str(end - start)
        await send({"type": "http.response.start", "status": 206, "headers": self.raw_headers})
        if send_header_only or start == end:
            await send({"type": "http.response.body", "body": b"", "more_body": False})
        else:
            await self._body(send, start, end)

    async def _handle_multiple_ranges(self, send, ranges, file_size, send_header_only):
        if self.opened_file is None:
            return await super()._handle_multiple_ranges(send, ranges, file_size, send_header_only)
        boundary = token_hex(13)
        length, header = self.generate_multipart(ranges, boundary, file_size, self.headers["content-type"])
        self.headers["content-range"] = f"multipart/byteranges; boundary={boundary}"
        self.headers["content-length"] = str(length)
        await send({"type": "http.response.start", "status": 206, "headers": self.raw_headers})
        if send_header_only:
            await send({"type": "http.response.body", "body": b"", "more_body": False})
            return
        for start, end in ranges:
            await send({"type": "http.response.body", "body": header(start, end), "more_body": True})
            await self._body(send, start, end, multipart=True)
            await send({"type": "http.response.body", "body": b"\n", "more_body": True})
        await send({"type": "http.response.body", "body": f"\n--{boundary}--\n".encode("latin-1"), "more_body": False})


def open_verified_result(path, size_bytes, expected_sha256, *, progress=None, cancelled=lambda: False, background_budget=None):
    """Verify once and stream that same handle; NTFS denies concurrent mutation."""
    volume = os.stat(path.parent).st_dev
    cancelled = cancelled or (lambda: False)
    def check_cancelled():
        if background_budget is not None:
            background_budget.checkpoint()
        return cancelled()
    # Foreground demand is visible while waiting for a volume slot, so an
    # archive already holding it yields at its next chunk and releases it.
    with (io_priority.foreground() if background_budget is None else nullcontext()):
        verification_slots.acquire(volume, check_cancelled)
        try:
            return _open_verified_result(path, size_bytes, expected_sha256, progress=progress,
                                         cancelled=check_cancelled, background_budget=background_budget)
        finally:
            verification_slots.release(volume)


def _open_verified_result(path, size_bytes, expected_sha256, *, progress, cancelled, background_budget=None):
    if cancelled():
        raise PreparationCancelled()
    if os.name == "nt":
        import ctypes
        import msvcrt
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        handle = kernel.CreateFileW(str(path), 0x80000000, 1, None, 3, 0x08000000, None)
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
        except BaseException:
            kernel.CloseHandle(handle)
            raise
        stream = os.fdopen(descriptor, "rb")
    else:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        stream = os.fdopen(descriptor, "rb")
    try:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size != size_bytes:
            raise ValueError("result handle does not match manifest size")
        checksum, checked = hashlib.sha256(), 0
        if progress is not None:
            progress(0, size_bytes)
        while True:
            if cancelled():
                raise PreparationCancelled()
            chunk = stream.read(BACKGROUND_CHUNK_BYTES if background_budget is not None else VERIFY_CHUNK_BYTES)
            if not chunk:
                break
            checksum.update(chunk)
            checked += len(chunk)
            if progress is not None:
                progress(checked, size_bytes)
        if cancelled():
            raise PreparationCancelled()
        digest = checksum.hexdigest()
        after = os.fstat(stream.fileno())
        if digest != expected_sha256 or (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError("result handle does not match manifest SHA256")
        stream.seek(0)
        return stream, after
    except BaseException:
        stream.close()
        raise


class ResultPreparationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    operation_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")
    work_unit_id: str = Field(min_length=1, max_length=256)
    attempt_id: str = Field(min_length=1, max_length=256)
    file: str = Field(min_length=1, max_length=4096)
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


def single_result_range(raw, size):
    if raw is None:
        return 0, size, 200
    match = re.fullmatch(r"bytes=(\d{0,20})-(\d{0,20})", raw)
    if match is not None and any(match.groups()) and size:
        first, last = match.groups()
        if not first:
            suffix = int(last)
            if suffix:
                return max(0, size - suffix), size, 206
        else:
            start = int(first)
            end = min(size, int(last) + 1) if last else size
            if 0 <= start < end:
                return start, end, 206
    raise HTTPException(416, {"reason_code": "invalid_result_range"}, headers={"Content-Range": f"bytes */{size}"})


class PreparedContentResponse(Response):
    """A single body borrower; the ticket retains the same verified handle."""

    def __init__(self, manager, ticket, start, end, status, validator):
        document = ticket.document
        headers = {"Content-Length": str(end - start), "Accept-Ranges": "bytes",
                   "ETag": '"' + document["sha256"] + '"', "X-RCN-SHA256": document["sha256"],
                   "Cache-Control": "no-store"}
        if status == 206:
            headers["Content-Range"] = f"bytes {start}-{end - 1}/{document['size_bytes']}"
        super().__init__(status_code=status, media_type="application/octet-stream", headers=headers)
        self.manager, self.ticket = manager, ticket
        self.start, self.end, self.validator = start, end, validator

    async def __call__(self, scope, receive, send):
        resource = self.ticket.resource
        background = getattr(resource, "background_budget", None)
        activity = io_priority.foreground() if background is None else nullcontext()
        activity.__enter__()
        started = False
        try:
            if background is not None:
                await joined_io(background.checkpoint)
            await joined_io(self.validator)
            if resource.storage_validator is not None:
                await joined_io(resource.storage_validator)
            current = await joined_io(os.fstat, resource.opened_file.fileno())
            original = resource.stat_result
            if (current.st_ino, current.st_size, current.st_mtime_ns) != (original.st_ino, original.st_size, original.st_mtime_ns):
                await joined_io(self.manager.cancel_ticket, self.ticket.document["ticket_id"],
                                self.ticket.document["actor_id"], self.ticket.document["job_id"])
                raise HTTPException(409, {"reason_code": "result_handle_changed"})
            await joined_io(resource.opened_file.seek, self.start)
            await send({"type": "http.response.start", "status": self.status_code, "headers": self.raw_headers})
            started = True
            position = self.start
            if position == self.end:
                await send({"type": "http.response.body", "body": b"", "more_body": False})
            while position < self.end:
                if self.ticket.cancel.is_set():
                    raise PreparationCancelled()
                if background is not None:
                    await joined_io(background.checkpoint)
                chunk = await joined_io(resource.opened_file.read, min(
                    BACKGROUND_CHUNK_BYTES if background is not None else VERIFY_CHUNK_BYTES, self.end - position))
                if self.ticket.cancel.is_set():
                    raise PreparationCancelled()
                if not chunk:
                    raise OSError("verified result handle ended before its declared size")
                position += len(chunk)
                await send({"type": "http.response.body", "body": chunk, "more_body": position < self.end})
        except BackgroundDeferred as exc:
            await joined_io(self.manager.defer_body, self.ticket)
            if not started:
                raise HTTPException(503, {"reason_code": exc.reason_code}, headers={"Retry-After": "2"}) from exc
            raise ConnectionAbortedError("archive yielded; resume original Range") from exc
        except HTTPException as exc:
            if background is not None and isinstance(exc.detail, dict) and exc.detail.get("reason_code") == "restore_source_unavailable":
                await joined_io(self.manager.defer_body, self.ticket, "restore_source_unavailable")
            raise
        except OSError as exc:
            from .restore_sources import source_unavailable
            if background is not None and source_unavailable(exc):
                await joined_io(self.manager.defer_body, self.ticket, "restore_source_unavailable")
                if not started:
                    raise HTTPException(503, {"reason_code":"restore_source_unavailable"}, headers={"Retry-After":"2"}) from exc
            raise
        finally:
            try:
                await joined_io(self.manager.end_body, self.ticket)
            finally:
                activity.__exit__(None, None, None)


async def joined_io(operation, *args, on_cancelled_result=None, **kwargs):
    """Cancellation waits for the owned IO before closing handles or budgets."""
    work = asyncio.create_task(asyncio.to_thread(operation, *args, **kwargs))
    try:
        return await asyncio.shield(work)
    except asyncio.CancelledError:
        while not work.done():
            try:
                await asyncio.shield(work)
            except asyncio.CancelledError:
                continue
            except Exception:
                break
        if work.done() and not work.cancelled():
            try:
                result = work.result()
            except Exception:
                pass
            else:
                if on_cancelled_result is not None:
                    await joined_io(on_cancelled_result, result)
        raise


def discard_temporary(result):
    descriptor, name = result
    try:
        os.close(descriptor)
    finally:
        Path(name).unlink(missing_ok=True)


class OriginTransferRoute(APIRoute):
    """Keep unexpected failures diagnosable without logging input or credentials."""

    def get_route_handler(self):
        handler = super().get_route_handler()

        async def checked(request):
            try:
                return await handler(request)
            except StorageRootError as exc:
                raise HTTPException(409, {"reason_code": exc.reason_code, "message": "managed storage is unavailable"}) from exc
            except StorageMetadataBusy as exc:
                raise HTTPException(503, {"reason_code": exc.reason_code,
                    "operation": exc.operation}, headers={"Retry-After": "1"}) from exc
            except HTTPException:
                raise
            except Exception as exc:
                # Exception strings/SQL parameters may contain secrets or paths.
                # Record only code identity, never request headers/body or locals.
                frames = ";".join(
                    f"{Path(frame.filename).name}:{frame.lineno}:{frame.name}"
                    for frame in traceback.extract_tb(exc.__traceback__)
                )
                logging.getLogger(__name__).error(
                    "origin_transfer.unexpected_error route=%s type=%s frames=%s",
                    self.name, type(exc).__name__, frames,
                )
                raise

        return checked


class OriginTransferStore:
    def __init__(self, root: Path, *, max_bytes: int = MAX_BUNDLE_BYTES,
                 reserve_bytes: int = HARD_RESERVE_BYTES, budget_database: str | Path | None = None,
                 validate_root=None, validate_write=None):
        self.root = root.absolute()
        self.max_bytes = max_bytes
        self.reserve_bytes = reserve_bytes
        self._lock = threading.Lock()
        self._reservations: dict[str, int] = {}
        self._claims = {}
        self.volume_budget = VolumeBudget(budget_database) if budget_database is not None else None
        self._root_validator = validate_root
        self._write_validator = validate_write
        self._asset_cache = TransferAssetValidationCache()

    def check_root(self):
        if self._root_validator is not None:
            selected = self._root_validator()
            if selected is not None and Path(selected).absolute() != self.root:
                raise StorageRootError("storage_binding_changed", "root validator returned a different storage path")
        return self.root

    def spool(self):
        self.check_root()
        managed_path(self.root, ".transfer-check")
        self.root.mkdir(parents=True, exist_ok=True)
        return OriginSpool(self.root, transfer_asset_cache=self._asset_cache,
                           storage_validator=self.check_root)

    def check_write(self):
        self.check_root()
        if self._write_validator is not None:
            selected = self._write_validator()
            if selected is not None and Path(selected).absolute() != self.root:
                raise StorageRootError("storage_binding_changed", "write guard returned a different root")

    def outgoing(self, job, unit):
        self.check_root()
        return managed_path(self.root, identifier(job.origin_submitter_id), "outgoing",
                            identifier(job.job_id), identifier(unit.work_unit_id) + ".zip")

    def incoming(self, job, unit_id, attempt_id):
        self.check_root()
        return managed_path(self.root, identifier(job.origin_submitter_id), "incoming",
                            identifier(job.job_id), identifier(unit_id), identifier(attempt_id))

    def create_temporary(self, target, prefix):
        self.check_write()
        target.parent.mkdir(parents=True, exist_ok=True)
        return tempfile.mkstemp(prefix=prefix, suffix=".partial", dir=target.parent)

    def reserve(self, key: str, size: int):
        self.check_write()
        self.spool()
        with self._lock:
            if key in self._reservations or len(self._reservations) >= 4:
                raise HTTPException(429, "transfer busy; retry the same Job", headers={"Retry-After": "5"})
            if self.volume_budget is not None:
                try:
                    claim = self.volume_budget.reserve(self.root, size, holder_kind="http-upload",
                                                       holder_key=key, max_kind_claims=4)
                except VolumeCapacityUnavailable as exc:
                    raise HTTPException(507, {"reason_code": exc.reason_code,
                        "required_bytes": exc.required_bytes, "free_bytes": exc.free_bytes,
                        "reserved_bytes": exc.reserved_bytes, "reserve_bytes": exc.reserve_bytes}) from exc
                except VolumeBudgetError as exc:
                    raise HTTPException(429 if exc.reason_code == "storage_holder_busy" else 507,
                                        {"reason_code": exc.reason_code}, headers={"Retry-After": "5"}) from exc
                self._claims[key] = claim
            else:
                # Legacy direct stores retain their in-process fixture contract.
                if shutil.disk_usage(self.root).free < size + sum(self._reservations.values()) + self.reserve_bytes:
                    raise HTTPException(507, "managed staging has insufficient free space")
            self._reservations[key] = size

    def release(self, key):
        with self._lock:
            claim = self._claims.get(key)
            if claim is not None:
                self.volume_budget.release(claim, writer_stopped=True,
                    evidence="owned HTTP upload stream and file handles ended")
                self._claims.pop(key, None)
            self._reservations.pop(key, None)

    def publish(self, job, unit, temporary):
        self.check_write()
        spool = self.spool()
        descriptor = spool._validate_archive(job, unit, temporary)
        target = self.outgoing(job, unit)
        try:
            publish_new_file(temporary, target)
            repeated = False
        except FileExistsError:
            current = spool.validate(job, unit)
            # Dispatcher may have legitimately re-sealed the runtime since
            # the first upload; never replace its current archive on retry.
            left, right = descriptor.hash_payload(), current.hash_payload()
            left.pop("runtime_version", None)
            right.pop("runtime_version", None)
            if left != right:
                raise HTTPException(409, "a different sealed bundle already exists")
            repeated = True
        return {"job_id": job.job_id, "work_unit_id": unit.work_unit_id,
                "ready": True, "already_present": repeated,
                "size_bytes": target.stat().st_size, "sha256": sha256_file(target)}


def build_origin_transfer_router(*, repository, auth, root, require_owner, enabled=False,
                                 validate_root=None, validate_write=None, budget_database=None, lifecycle=None,
                                 control_root=None, transfer_gate=None, restore_sources=None):
    router = APIRouter(route_class=OriginTransferRoute)
    if budget_database is None:
        url = repository.engine.url
        if url.get_backend_name() == "sqlite" and url.database not in {None, "", ":memory:"}:
            budget_database = url.database
    store = OriginTransferStore(root, budget_database=budget_database, validate_root=validate_root, validate_write=validate_write)
    relocations = SpoolRelocationRegistry(control_root) if control_root is not None else None
    if transfer_gate is None and control_root is not None:
        from .release_maintenance import get_transfer_gate
        transfer_gate = get_transfer_gate(control_root)
    preparations = ResultPreparations(control_root, gate=transfer_gate)
    router.result_preparations = preparations
    if restore_sources is None and lifecycle is not None:
        from .restore_sources import RegisteredResultSources
        restore_sources = RegisteredResultSources(lifecycle)
    router.restore_sources = restore_sources
    router.add_event_handler("shutdown", preparations.close)

    def admitted_transfer(function):
        @wraps(function)
        async def admitted(*args, **kwargs):
            activity = await joined_io(TransferActivity, transfer_gate,
                on_cancelled_result=lambda claim: claim.release()) if transfer_gate is not None else None
            handed_off = False
            try:
                response = await function(*args, **kwargs)
                if isinstance(response, PinnedFileResponse):
                    response.transfer_activity = activity
                    handed_off = True
                return response
            finally:
                if activity is not None and not handed_off:
                    await joined_io(activity.release)
        return admitted

    def result_paths(job, unit, attempt, manifest, records):
        directory = store.incoming(job, unit.work_unit_id, attempt.attempt_id)
        if relocations is None:
            return [managed_path(directory, record.relative_path) for record in records], None
        return relocations.resolve_files(job=job, unit=unit, attempt=attempt, manifest=manifest,
                                         source_directory=directory, records=records)

    def owned_job(job_id, context, unit_id=None, *, all_units=False):
        if not enabled:
            raise HTTPException(503, "origin byte transfer is not enabled")
        try:
            identifier(job_id)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        job = (repository.get_job(job_id, hydrate_blobs=False) if all_units
               else repository.get_origin_transfer_job(job_id, unit_id))
        if job is None:
            raise HTTPException(404, "job not found")
        # Stricter than metadata visibility: machine ownership alone never
        # permits downloading a project's artifacts or replacing its input.
        require_owner(job, context)
        return job

    def unit_for(job, unit_id):
        try:
            identifier(unit_id)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        unit = next((unit for unit in job.work_units if unit.work_unit_id == unit_id), None)
        if unit is None:
            raise HTTPException(404, "work unit not found")
        return unit

    def checked_manifest(manifest):
        if manifest is None:
            raise HTTPException(409, "verified result manifest is not available")
        names = [f.relative_path.casefold() for f in manifest.files]
        if len(names) != len(set(names)):
            raise HTTPException(409, "ambiguous result manifest")
        return manifest

    def manifest_for(job_id, unit_id):
        return checked_manifest(next((m for m in repository.list_artifact_manifests(job_id)
                                      if m.work_unit_id == unit_id), None))

    @router.get("/v1/origin-transfer")
    def capabilities(_context: AuthContext = Depends(auth.actor)):
        return {"protocol": TRANSFER_PROTOCOL, "enabled": enabled,
                "max_bundle_bytes": store.max_bytes, "artifact_ownership": "origin_submitter",
                "bundle_status": True, "bundle_source_receipts": True, "max_parallel_uploads": 4,
                "content_addressed_inputs": 1, "asset_encoding": "gzip",
                "result_preparations": True, "result_range_resume": True,
                "registered_archive_restore": restore_sources is not None,
                "result_preparation_idle_seconds": 120, "max_ready_result_tickets": 8,
                "max_actor_ready_result_tickets": 2, "max_result_verifications": 2,
                "max_volume_result_verifications": 1}

    @router.get("/v1/jobs/{job_id}/origin-assets/{digest}")
    def asset_status(job_id: str, digest: str, context: AuthContext = Depends(auth.actor)):
        job = owned_job(job_id, context)
        store.check_root()
        try:
            record = declared_asset(job, digest)
            target = asset_path(store.root, job, digest)
            ready = target.exists()
            if ready:
                verify_asset(store.root, job, record)
            return {"job_id": job_id, "sha256": digest, "size_bytes": record.size_bytes, "ready": ready}
        except (OSError, ValueError) as exc:
            raise HTTPException(409, "asset missing authorization or failed integrity verification") from exc

    @router.put("/v1/jobs/{job_id}/origin-assets/{digest}")
    @admitted_transfer
    async def upload_asset(job_id: str, digest: str, request: Request, context: AuthContext = Depends(auth.actor)):
        job = await joined_io(owned_job, job_id, context)
        await joined_io(store.check_root)
        try:
            record = declared_asset(job, digest)
            target = asset_path(store.root, job, digest)
        except ValueError as exc:
            raise HTTPException(409, "asset is not declared by Job") from exc
        raw_length = request.headers.get("content-length", "")
        encoded_hash = request.headers.get("x-rcn-sha256", "")
        if (request.headers.get("content-encoding") != "gzip"
            or not re.fullmatch(r"[0-9]{1,12}", raw_length)
            or not re.fullmatch(r"[0-9a-f]{64}", encoded_hash)):
            raise HTTPException(400, "gzip, exact length and encoded SHA256 required")
        length = int(raw_length)
        if not 0 < length <= store.max_bytes or not 0 <= record.size_bytes <= store.max_bytes:
            raise HTTPException(413, "asset exceeds transfer size limit")
        key = f"asset/{job.origin_submitter_id}/{job.project_id}/{digest}"
        await joined_io(store.reserve, key, record.size_bytes + length,
                        on_cancelled_result=lambda _: store.release(key))
        temporary = None
        try:
            fd, name = await joined_io(store.create_temporary, target, ".asset-upload-",
                                       on_cancelled_result=discard_temporary)
            temporary = Path(name)
            decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
            encoded_sum, raw_sum = hashlib.sha256(), hashlib.sha256()
            received = written = 0
            with os.fdopen(fd, "wb") as output:
                async for chunk in request.stream():
                    received += len(chunk)
                    if received > length:
                        raise HTTPException(413, "asset exceeds declared transfer length")
                    encoded_sum.update(chunk)
                    pending = chunk
                    while pending:
                        raw = decoder.decompress(pending, min(CHUNK_BYTES, record.size_bytes - written + 1))
                        pending = decoder.unconsumed_tail
                        written += len(raw)
                        if written > record.size_bytes or decoder.unused_data:
                            raise HTTPException(422, "asset expanded beyond declared content")
                        raw_sum.update(raw)
                        await joined_io(output.write, raw)
                if (received != length or encoded_sum.hexdigest() != encoded_hash
                    or not decoder.eof or written != record.size_bytes or raw_sum.hexdigest() != digest):
                    raise HTTPException(422, "asset length or SHA256 mismatch")
                await joined_io(output.flush)
                await joined_io(os.fsync, output.fileno())
            job = await joined_io(owned_job, job_id, context)
            current_record = declared_asset(job, digest)
            if current_record.size_bytes != written:
                raise HTTPException(409, "Job asset binding changed")
            target = asset_path(store.root, job, digest)
            await joined_io(store.check_write)
            try:
                await joined_io(publish_new_file, temporary, target)
            except FileExistsError:
                await joined_io(verify_asset, store.root, job, current_record)
            await joined_io(repository.append_event, AuditEvent(
                event_type="origin_transfer.asset_published", actor_id=context.actor_id,
                subject_type="job", subject_id=job_id,
                details={"sha256": digest, "size_bytes": written, "transfer_bytes": received}))
            return {"job_id": job_id, "sha256": digest, "size_bytes": written, "ready": True}
        except ClientDisconnect as exc:
            raise HTTPException(400, "asset transfer interrupted; retry the same Job") from exc
        except StorageRootError as exc:
            raise HTTPException(409, {"reason_code": exc.reason_code}) from exc
        except (ValueError, zlib.error) as exc:
            raise HTTPException(422, "invalid asset encoding or binding") from exc
        except OSError as exc:
            raise HTTPException(507, "managed asset I/O failed") from exc
        finally:
            try:
                if temporary is not None:
                    await joined_io(temporary.unlink, missing_ok=True)
            finally:
                await joined_io(store.release, key)

    @router.get("/v1/jobs/{job_id}/origin-bundles/{unit_id}")
    def bundle_status(job_id: str, unit_id: str, expected_sha256: str | None = None,
                      expected_size: int | None = None, context: AuthContext = Depends(auth.actor)):
        job = owned_job(job_id, context, unit_id)
        unit = unit_for(job, unit_id)
        if (expected_sha256 is not None or expected_size is not None) and (
            not re.fullmatch(r"[0-9a-f]{64}", expected_sha256 or "")
            or expected_size is None or not 0 < expected_size <= store.max_bytes
        ):
            raise HTTPException(400, "exact source size and SHA256 are required")
        try:
            target = store.outgoing(job, unit)
            if not target.exists():
                return {"job_id": job_id, "work_unit_id": unit_id, "ready": False}
            spool = store.spool()
            current = spool.validate(job, unit)
            # A receipt is current evidence, not a stale remembered acknowledgement.
            result = {"job_id": job_id, "work_unit_id": unit_id, "ready": True,
                      "already_present": True, "size_bytes": target.stat().st_size,
                      "sha256": sha256_file(target)}
            if expected_sha256 and (result["sha256"], result["size_bytes"]) != (expected_sha256, expected_size):
                # Audited runtime resealing retains the exact source archive.
                # Verify those bytes and current scientific equivalence before
                # allowing the client to skip; identity alone is never enough.
                retained = managed_path(store.root, ".retained", "runtime-migrations",
                                        identifier(job.origin_submitter_id), identifier(job.job_id), identifier(unit_id))
                if retained.is_dir():
                    for name in sorted(p.name for p in retained.iterdir() if p.name.endswith("-" + expected_sha256 + ".zip")):
                        source = managed_path(retained, name)
                        verify_file(source, expected_size, expected_sha256)
                        descriptor = spool._validate_archive(job, unit, source)
                        left, right = descriptor.hash_payload(), current.hash_payload()
                        left.pop("runtime_version", None)
                        right.pop("runtime_version", None)
                        if left == right:
                            result.update(accepted_source_sha256=expected_sha256, accepted_source_size_bytes=expected_size)
                            break
            return result
        except (OSError, ValueError, zipfile.BadZipFile) as exc:
            raise HTTPException(409, "existing bundle failed integrity verification") from exc

    @router.put("/v1/jobs/{job_id}/origin-bundles/{unit_id}")
    @admitted_transfer
    async def upload(job_id: str, unit_id: str, request: Request, context: AuthContext = Depends(auth.actor)):
        job = await joined_io(owned_job, job_id, context, unit_id)
        unit = unit_for(job, unit_id)
        digest = request.headers.get("x-rcn-sha256", "")
        raw_length = request.headers.get("content-length", "")
        if not re.fullmatch(r"[0-9a-f]{64}", digest) or not re.fullmatch(r"[0-9]{1,12}", raw_length):
            raise HTTPException(400, "exact Content-Length and X-RCN-SHA256 are required")
        length = int(raw_length)
        if not 0 < length <= store.max_bytes:
            raise HTTPException(413, "bundle exceeds transfer size limit")
        key = job_id + "/" + unit_id
        try:
            await joined_io(store.reserve, key, length,
                            on_cancelled_result=lambda _: store.release(key))
        except StorageRootError as exc:
            raise HTTPException(409, {"reason_code": exc.reason_code}) from exc
        except (OSError, ValueError) as exc:
            raise HTTPException(507, "managed staging is unavailable") from exc
        temporary = None
        try:
            target = await joined_io(store.outgoing, job, unit)
            fd, name = await joined_io(store.create_temporary, target, ".upload-",
                                       on_cancelled_result=discard_temporary)
            temporary = Path(name)
            checksum, received = hashlib.sha256(), 0
            with os.fdopen(fd, "wb") as output:
                async for chunk in request.stream():
                    received += len(chunk)
                    if received > length:
                        raise HTTPException(413, "upload exceeds declared size")
                    checksum.update(chunk)
                    await joined_io(output.write, chunk)
                await joined_io(output.flush)
                await joined_io(os.fsync, output.fileno())
            if received != length or checksum.hexdigest() != digest:
                raise HTTPException(422, "upload size or SHA256 mismatch")
            # Recheck grants after a long upload and before publication.
            job = await joined_io(owned_job, job_id, context, unit_id)
            result = await joined_io(store.publish, job, unit_for(job, unit_id), temporary)
            await joined_io(repository.append_event, AuditEvent(
                event_type="origin_transfer.bundle_published", actor_id=context.actor_id,
                subject_type="job", subject_id=job_id, details={
                    "work_unit_id": unit_id,
                    "sha256": result["sha256"], "size_bytes": result["size_bytes"],
                    "already_present": result["already_present"],
                }))
            return result
        except ClientDisconnect as exc:
            raise HTTPException(400, "upload interrupted; retry the same Job") from exc
        except StorageRootError as exc:
            raise HTTPException(409, {"reason_code": exc.reason_code}) from exc
        except (ValueError, zipfile.BadZipFile) as exc:
            raise HTTPException(422, "invalid sealed bundle or managed path") from exc
        except OSError as exc:
            raise HTTPException(507, "managed staging I/O failed; bundle was not acknowledged") from exc
        finally:
            try:
                if temporary is not None:
                    await joined_io(temporary.unlink, missing_ok=True)
            finally:
                await joined_io(store.release, key)

    @router.get("/v1/jobs/{job_id}/origin-results")
    def results(job_id: str, include_custody: bool = False, context: AuthContext = Depends(auth.actor)):
        job = owned_job(job_id, context, all_units=True)
        # Large scientific Jobs can contain thousands of Units. Re-reading all
        # manifests for each Unit turned this metadata endpoint into quadratic
        # database/deserialization work and timed out migration readbacks.
        units_by_id = {}
        for unit in job.work_units:
            units_by_id.setdefault(unit.work_unit_id, unit)
        entries = []
        for manifest in repository.list_artifact_manifests(job_id):
            try:
                identifier(manifest.work_unit_id)
            except ValueError as exc:
                raise HTTPException(400, str(exc)) from exc
            unit = units_by_id.get(manifest.work_unit_id)
            if unit is None:
                raise HTTPException(404, "work unit not found")
            manifest = checked_manifest(manifest)
            if manifest.job_id != job.job_id:
                raise HTTPException(409, "result manifest identity does not match the Job")
            producer_attempt_id = manifest.producer.get("attempt_id")
            latest = unit.attempts[-1] if unit.attempts else None
            abandoned_lineage = any(a.state == "abandoned" or a.abandonment is not None for a in unit.attempts)
            if latest is not None and (latest.state == "abandoned" or latest.abandonment is not None):
                continue
            if abandoned_lineage and (
                not producer_attempt_id or latest is None or latest.attempt_id != producer_attempt_id
            ):
                # Discarded or ambiguous historical output is not the current
                # producer, even when an old staging directory still exists.
                continue
            attempts = sorted((a for a in unit.attempts if a.state == "completed" and a.abandonment is None
                               and (not producer_attempt_id or a.attempt_id == producer_attempt_id)),
                              key=lambda a: (a.collected_at is not None,
                                  str(a.collected_at or a.finished_at or a.last_observed_at or "")),
                              reverse=True)
            declared_external_run_id = manifest.producer.get("external_run_id")
            if abandoned_lineage and declared_external_run_id is not None and any(
                a.external_run_id != declared_external_run_id for a in attempts
            ):
                raise HTTPException(409, "result manifest external run does not match its producer Attempt")
            bytes_available = True
            storage_unavailable = False
            for attempt in attempts:
                try:
                    paths, _ = result_paths(job, unit, attempt, manifest, manifest.files)
                    if all(p.is_file() and p.stat().st_size == f.size_bytes
                           for p, f in zip(paths, manifest.files)):
                        break
                except StorageRootError:
                    storage_unavailable = True
                    break
                except ValueError as exc:
                    raise HTTPException(409, "invalid managed result path") from exc
            else:
                # Collection establishes the manifest identity even after staged
                # duplicates are removed. Each file GET still verifies actual bytes.
                attempt = next((a for a in attempts if producer_attempt_id
                                and a.collected_at is not None), None)
                if attempt is None:
                    raise HTTPException(409, "result bytes have not reached managed staging")
                bytes_available = False
            if storage_unavailable:
                attempt = next((a for a in attempts if not producer_attempt_id or a.attempt_id == producer_attempt_id), None)
                if attempt is None:
                    raise HTTPException(409, "result manifest producer is not available")
                bytes_available = False
            entry = {"work_unit_id": unit.work_unit_id, "attempt_id": attempt.attempt_id,
                            "manifest_sha256": sha256_value(manifest.model_dump(mode="json")),
                            "bytes_available": bytes_available}
            if include_custody:
                custody = lifecycle.state(job_id, unit.work_unit_id, attempt.attempt_id) if lifecycle and not bytes_available else None
                entry.update(storage_state=custody["state"] if custody else ("available" if bytes_available else "temporarily_unavailable"),
                             restore_refs=custody["restore_refs"] if custody else [],
                             scientific_retention=custody.get("scientific_retention") if custody else None)
            entries.append(entry)
        return {"job_id": job_id, "units": entries}

    def prepare_result(job_id, unit_id, attempt_id, file, context, diagnostics, *, expected=None,
                       progress=None, cancelled=None, validate_only=False):
        if cancelled is not None and cancelled():
            raise PreparationCancelled()
        with diagnostics.stage("owned_job"):
            job = owned_job(job_id, context, unit_id)
        with diagnostics.stage("producer_manifest"):
            unit = unit_for(job, unit_id)
            attempt = next((a for a in unit.attempts if a.attempt_id == attempt_id and a.state == "completed"), None)
            if attempt is None or attempt.abandonment is not None:
                raise HTTPException(404, "completed attempt not found")
            manifest = manifest_for(job_id, unit_id)
            producer_attempt_id = manifest.producer.get("attempt_id")
            abandoned_lineage = any(a.state == "abandoned" or a.abandonment is not None for a in unit.attempts)
            if ((producer_attempt_id and producer_attempt_id != attempt_id) or
                    (abandoned_lineage and (not producer_attempt_id or
                     not unit.attempts or unit.attempts[-1].attempt_id != attempt_id))):
                raise HTTPException(409, "result manifest does not identify the current producer Attempt")
            declared_external_run_id = manifest.producer.get("external_run_id")
            if abandoned_lineage and declared_external_run_id is not None and declared_external_run_id != attempt.external_run_id:
                raise HTTPException(409, "result manifest external run does not match its producer Attempt")
            record = next((f for f in manifest.files if f.relative_path == file), None)
            if record is None:
                raise HTTPException(404, "file is not in the result manifest")
            if expected is not None and (manifest.job_id != job_id or manifest.work_unit_id != unit_id
                    or sha256_value(manifest.model_dump(mode="json")) != expected["manifest_sha256"]
                    or (record.size_bytes, record.sha256) != (expected["size_bytes"], expected["sha256"])):
                raise HTTPException(409, {"reason_code": "result_manifest_binding_changed"})
        with diagnostics.stage("scientific_retention"):
            if lifecycle is not None:
                retained = lifecycle.scientific.state(job_id, unit_id, attempt_id)
                for intent in retained["model_retirements"]:
                    if (intent["candidate"].get("operation_kind") == "solved_model"
                            and intent["files"].get(file) in {"deleted", "already_absent"}):
                        raise HTTPException(410, {"reason_code": "solved_model_intentionally_retired",
                            "intent_id": intent["intent_id"],
                            "scientific_restore_refs": intent["candidate"].get("restore_refs", [])})
        if validate_only:
            return
        pin = None
        opened_file = None
        restored = None
        background = None
        try:
            try:
                with diagnostics.stage("storage_root"):
                    store.check_root()
                with diagnostics.stage("result_paths"):
                    paths, relocation_validator = result_paths(job, unit, attempt, manifest, [record])
                    target = paths[0]
                    if not target.is_file():
                        raise FileNotFoundError("original staging file is unavailable")
                with diagnostics.stage("pin_reader"):
                    if lifecycle is not None:
                        pin = lifecycle.pin_reader(job_id, unit_id, attempt_id, file)
            except (FileNotFoundError, StorageRootError, ValueError) as unavailable:
                allowed = isinstance(unavailable, (FileNotFoundError, StorageRootError)) or getattr(unavailable, "reason_code", None) in {
                    "result_retirement_pending_or_completed", "file_retirement_in_progress"}
                if not allowed or restore_sources is None:
                    raise
                if progress is not None:
                    progress(0, record.size_bytes, state="restore_pending")
                background = BackgroundBudget(lifecycle.database)
                with diagnostics.stage("open_verified_result"):
                    restored, pin, target, opened_file, file_stat = restore_sources.open_verified(
                        job_id, unit_id, attempt_id, sha256_value(manifest.model_dump(mode="json")), record,
                        checkpoint=background.checkpoint,
                        opener=lambda source_path: open_verified_result(source_path, record.size_bytes, record.sha256,
                            progress=progress, cancelled=cancelled, background_budget=background))
                relocation_validator = None
            if opened_file is None:
                with diagnostics.stage("open_verified_result"):
                    if progress is None:
                        opened_file, file_stat = open_verified_result(target, record.size_bytes, record.sha256)
                    else:
                        opened_file, file_stat = open_verified_result(target, record.size_bytes, record.sha256,
                            progress=progress, cancelled=cancelled)
            with diagnostics.stage("append_event"):
                repository.append_event(AuditEvent(event_type="origin_transfer.result_requested",
                    actor_id=context.actor_id, subject_type="job", subject_id=job_id,
                    details={"work_unit_id": unit_id, "attempt_id": attempt_id,
                             "sha256": record.sha256, "size_bytes": record.size_bytes}))
            arguments = {"media_type": "application/octet-stream", "headers": {
                "X-RCN-SHA256": record.sha256, "Cache-Control": "no-store",
                "X-RCN-Transfer-Request": diagnostics.request_id}}
            def validate_result():
                with diagnostics.stage("response_storage_validate"):
                    if restored is not None:
                        try:
                            restored.validate()
                        except (ValueError, OSError) as exc:
                            from .restore_sources import source_unavailable
                            transient = source_unavailable(exc)
                            raise HTTPException(503 if transient else 409, {"reason_code": "restore_source_unavailable" if transient
                                else getattr(exc, "reason_code", "restore_source_integrity_failed")}) from exc
                        return
                    managed_path(store.incoming(job, unit_id, attempt_id), file)
                    if relocation_validator is not None:
                        relocation_validator()
            response = PinnedFileResponse(target, reader_pin=pin, opened_file=opened_file,
                stat_result=file_stat, storage_validator=validate_result, diagnostics=diagnostics,
                background_budget=background, **arguments)
            diagnostics.checkpoint("response_ready")
            return response
        except BaseException as exc:
            try:
                if opened_file is not None:
                    opened_file.close()
            finally:
                if pin is not None:
                    pin.release()
            if isinstance(exc, (OSError, ValueError)):
                reason = getattr(exc, "reason_code", "result_unavailable_or_integrity_failed")
                transient = isinstance(exc, BackgroundDeferred) or reason == "restore_source_unavailable"
                raise HTTPException(503 if transient else 409,
                    {"reason_code": reason}, headers={"Retry-After": "2"} if transient else None) from exc
            raise

    @router.get("/v1/jobs/{job_id}/origin-results/{unit_id}/{attempt_id}")
    @admitted_transfer
    async def download(job_id: str, unit_id: str, attempt_id: str, file: str,
                 context: AuthContext = Depends(auth.actor)):
        diagnostics = OriginTransferDiagnostics(control_root)

        def prepare_response():
            try:
                return prepare_result(job_id, unit_id, attempt_id, file, context, diagnostics)
            except BaseException as exc:
                diagnostics.finish("preparation_error", error_type=type(exc).__name__)
                raise

        def abandon_prepared(response):
            try:
                if response.opened_file is not None:
                    response.opened_file.close()
            finally:
                try:
                    if response.reader_pin is not None:
                        response.reader_pin.release()
                finally:
                    diagnostics.finish("preparation_cancelled", error_type="CancelledError")
        return await joined_io(prepare_response, on_cancelled_result=abandon_prepared)

    @router.post("/v1/jobs/{job_id}/origin-result-preparations", status_code=202)
    async def prepare_download(job_id: str, body: ResultPreparationRequest,
                               context: AuthContext = Depends(auth.actor)):
        identity = dict(body.model_dump(), job_id=job_id)
        diagnostics = OriginTransferDiagnostics(control_root)
        await joined_io(owned_job, job_id, context)
        await joined_io(preparations.check_identity, context.actor_id, identity)
        # Reject stale scientific identities synchronously. No file SHA runs on
        # the request path; the admitted worker repeats these checks before IO.
        await joined_io(prepare_result, job_id, body.work_unit_id, body.attempt_id, body.file,
                        context, diagnostics, expected=identity, validate_only=True)
        def factory(progress, cancelled):
            try:
                return prepare_result(job_id, body.work_unit_id, body.attempt_id, body.file,
                    context, diagnostics, expected=identity, progress=progress, cancelled=cancelled)
            except BaseException as exc:
                diagnostics.finish("preparation_error", error_type=type(exc).__name__)
                raise
        return await joined_io(preparations.prepare, context.actor_id, identity, factory)

    @router.get("/v1/jobs/{job_id}/origin-result-preparations/{ticket_id}")
    async def preparation_status(job_id: str, ticket_id: str, context: AuthContext = Depends(auth.actor)):
        await joined_io(owned_job, job_id, context)
        return await joined_io(preparations.status, ticket_id, context.actor_id, job_id)

    @router.delete("/v1/jobs/{job_id}/origin-result-preparations/{ticket_id}")
    async def cancel_preparation(job_id: str, ticket_id: str, context: AuthContext = Depends(auth.actor)):
        await joined_io(owned_job, job_id, context)
        return await joined_io(preparations.cancel_ticket, ticket_id, context.actor_id, job_id)

    @router.get("/v1/jobs/{job_id}/origin-result-preparations/{ticket_id}/content")
    async def prepared_content(job_id: str, ticket_id: str, request: Request,
                               context: AuthContext = Depends(auth.actor)):
        await joined_io(owned_job, job_id, context)
        document = await joined_io(preparations.status, ticket_id, context.actor_id, job_id)
        raw_range = request.headers.get("range")
        if raw_range is not None and request.headers.get("if-range", document["etag"]) != document["etag"]:
            raw_range = None
        start, end, status = single_result_range(raw_range, document["size_bytes"])
        def validate_binding():
            prepare_result(job_id, document["work_unit_id"], document["attempt_id"], document["file"],
                context, OriginTransferDiagnostics(control_root), expected=document, validate_only=True)
        await joined_io(validate_binding)
        ticket = await joined_io(preparations.begin_body, ticket_id, context.actor_id, job_id,
                                 on_cancelled_result=preparations.end_body)
        return PreparedContentResponse(preparations, ticket, start, end, status, validate_binding)

    return router
