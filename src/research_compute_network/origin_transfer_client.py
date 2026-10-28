"""Origin-side streaming client: repeat safely; never implicitly import data."""

from __future__ import annotations

import hashlib
import io
import gzip
import ipaddress
import json
import os
import re
import shutil
import tempfile
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPException as HTTPTransportError
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .client import RcnApiError
from .hashing import sha256_file, sha256_value
from .models import ArtifactManifest, JobEnvelope
from .origin import OriginSpool
from .origin_transfer import CHUNK_BYTES, TRANSFER_PROTOCOL, identifier, managed_path, publish_new_file, verify_file
from .origin_assets import ASSET_MARKER, TransferAssetValidationCache, verify_asset


# Only exact pre-body busy responses on idempotent requests may be resumed.
METADATA_BUSY_MAX_RETRIES = 2
METADATA_BUSY_RETRY_BUDGET_SECONDS = 30.0
METADATA_BUSY_MAX_RETRY_AFTER_SECONDS = 5


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RcnApiError(code, "origin transfer redirects are forbidden")


class OriginTransferCapacityError(ValueError):
    reason_code = "origin_result_disk_reserve"


class ResultCapacityError(OriginTransferCapacityError):
    # Keep the older public exception name, with one category at every
    # capacity gate so member clients can recover the same transfer.
    reason_code = "origin_result_disk_reserve"


class OriginTransferClient:
    def __init__(self, client, *, require_resumable_uploads=False):
        self.client = client
        self.require_resumable_uploads = require_resumable_uploads
        parsed = urlsplit(client.base_url)
        try:
            loopback = parsed.hostname == "localhost" or ipaddress.ip_address(parsed.hostname or "").is_loopback
        except ValueError:
            loopback = False
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or (parsed.scheme == "http" and not loopback)):
            raise ValueError("origin transfer requires verified HTTPS or a pinned SSH loopback tunnel")
        self._opener = build_opener(ProxyHandler({}), _NoRedirect())

    def _open(self, path, *, data=None, headers=None, method="GET", timeout=None):
        selected = dict(headers or {})
        if self.client.token:
            selected["Authorization"] = f"Bearer {self.client.token}"
        request = Request(self.client.base_url + path, data=data, headers=selected, method=method)
        original_timeout = self.client.timeout if timeout is None else timeout
        retry_deadline = None
        retries = 0
        while True:
            request_timeout = original_timeout
            if retry_deadline is not None:
                request_timeout = min(original_timeout, max(0.001, retry_deadline - time.monotonic()))
            try:
                # Returning a response ends this policy: body reads never replay.
                return self._opener.open(request, timeout=request_timeout)
            except HTTPError as exc:
                reason_code = None
                retry_after = None
                if exc.code in (400, 401, 403, 404, 409, 410, 422, 429, 503, 507):
                    try:
                        raw = exc.read(16385)
                        body = json.loads(raw) if len(raw) <= 16384 else None
                        detail = body.get("detail") if isinstance(body, dict) else None
                        if (exc.code == 422 and isinstance(detail, list) and detail
                            and all(isinstance(row, dict) and row.get("type") == "value_error"
                                and row.get("loc") == ["body", "verified_at"]
                                and row.get("msg") == "Value error, evidence time cannot be in the future"
                                for row in detail)):
                            reason_code = "receipt_evidence_clock_skew"
                        elif isinstance(detail, dict) and isinstance(detail.get("reason_code"), str) and re.fullmatch(r"[a-z][a-z0-9_]{0,127}", detail["reason_code"]):
                            reason_code = detail["reason_code"]
                        if exc.code == 503 and reason_code in {"storage_metadata_busy", "release_draining"}:
                            selected_delay = exc.headers.get("Retry-After", "1")
                            if selected_delay.isascii() and selected_delay.isdigit():
                                delay = int(selected_delay)
                                if delay <= METADATA_BUSY_MAX_RETRY_AFTER_SECONDS:
                                    retry_after = delay
                    except (OSError, ValueError):
                        pass
                # Always close the rejected response before waiting or retrying.
                exc.close()
                if (reason_code == "storage_metadata_busy" and method in {"GET", "HEAD"}
                    and data is None and retry_after is not None
                    and retries < METADATA_BUSY_MAX_RETRIES):
                    if retry_deadline is None:
                        retry_deadline = time.monotonic() + METADATA_BUSY_RETRY_BUDGET_SECONDS
                    remaining = retry_deadline - time.monotonic()
                    if retry_after < remaining:
                        time.sleep(retry_after)
                        retries += 1
                        continue
                raise RcnApiError(exc.code, "origin transfer rejected; no local fallback", reason_code=reason_code) from exc
            except (URLError, OSError) as exc:
                raise RcnApiError(0, "origin transfer connection failed; retry the same Job") from exc

    @staticmethod
    def _read_json(response):
        raw = response.read(2 * 1024**2 + 1)
        if len(raw) > 2 * 1024**2:
            raise ValueError("origin transfer response exceeds metadata limit")
        return json.loads(raw)

    def require_available(self):
        with self._open("/v1/origin-transfer") as response:
            capabilities = self._read_json(response)
        if capabilities.get("protocol") != TRANSFER_PROTOCOL or capabilities.get("enabled") is not True:
            raise RcnApiError(503, "origin transfer is unavailable; no local fallback")
        if self.require_resumable_uploads and capabilities.get("resumable_uploads") != 1:
            raise RcnApiError(409, "coordinator lacks required resumable uploads; no downgrade",
                              reason_code="resumable_uploads_required")
        return capabilities

    def _upload_resumable(self, job_id, kind, target_id, source, size, digest, capabilities):
        # A public ingress must never receive one multi-GiB HTTP request.
        chunk_bytes = 8 * 1024**2
        if (capabilities.get("upload_chunk_bytes") != chunk_bytes
            or "identity" not in capabilities.get("resumable_upload_encodings", [])):
            raise RcnApiError(409, "unsupported resumable upload contract; no downgrade",
                              reason_code="resumable_uploads_required")
        base = f"/v1/jobs/{identifier(job_id)}/origin-upload-sessions"
        identity = dict(kind=kind, target_id=target_id, size_bytes=size, sha256=digest, encoding="identity")
        def request(path, *, body=None, method="GET", headers=None):
            selected = dict(headers or {})
            if body is not None:
                selected["Content-Length"] = str(len(body))
            with self._open(path, method=method, data=io.BytesIO(body) if body is not None else None, headers=selected) as response:
                return self._read_json(response)
        status = request(base, body=json.dumps(identity).encode(), method="POST", headers={"Content-Type": "application/json"})
        session_id = identifier(status.get("session_id", ""))
        url = base + "/" + session_id
        uploaded, failures = 0, 0
        deadline = time.monotonic() + 3600
        with source.open("rb") as incoming:
            while True:
                if (status.get("job_id") != job_id or status.get("session_id") != session_id
                    or any(status.get(k) != v for k, v in identity.items())
                    or type(status.get("offset")) is not int or not 0 <= status["offset"] <= size
                    or (status["offset"] != size and status["offset"] % chunk_bytes)):
                    raise ValueError("invalid resumable upload acknowledgement")
                state, offset = status.get("state"), status["offset"]
                if state == "completed":
                    receipt = status.get("receipt", {})
                    if receipt.get("job_id") != job_id or receipt.get("ready") is not True:
                        raise ValueError("invalid resumable publication acknowledgement")
                    if kind == "bundle" and receipt.get("work_unit_id") != target_id:
                        raise ValueError("invalid resumable bundle acknowledgement")
                    accepted = ((receipt.get("size_bytes"), receipt.get("sha256")) == (size, digest)
                        or (kind == "bundle" and (receipt.get("accepted_source_size_bytes"), receipt.get("accepted_source_sha256")) == (size, digest)))
                    if not accepted:
                        raise ValueError("resumable acknowledgement differs from source bytes")
                    return receipt, uploaded, max(0, size - uploaded)
                if state in {"failed", "cancelled"}:
                    raise RcnApiError(409, "resumable upload verification failed; retain the original Job",
                                      reason_code=status.get("reason_code"))
                if time.monotonic() >= deadline:
                    raise RcnApiError(0, "upload remains resumable; retry the same Job")
                try:
                    if state == "uploading" and offset < size:
                        incoming.seek(offset)
                        content = incoming.read(min(chunk_bytes, size - offset))
                        if len(content) != min(chunk_bytes, size - offset):
                            raise ValueError("upload source changed size")
                        status = request(url + "/chunk", method="PUT", body=content, headers={
                            "Content-Type": "application/octet-stream", "Content-Length": str(len(content)),
                            "Upload-Offset": str(offset), "X-RCN-SHA256": hashlib.sha256(content).hexdigest()})
                        uploaded += len(content)
                    elif state == "uploading":
                        status = request(url + "/finalize", method="POST", body=b"")
                    elif state == "verifying":
                        time.sleep(1)
                        status = request(url)
                    else:
                        raise ValueError("unknown resumable upload state")
                    failures = 0
                except (RcnApiError, OSError, HTTPTransportError) as exc:
                    code = getattr(exc, "status", 0)
                    if code not in {0, 409, 429, 503} or failures >= 2:
                        raise
                    failures += 1
                    time.sleep(1)
                    # Lost responses are reconciled by durable offset before
                    # sending bytes again; an unknown acknowledgement is not 0.
                    status = request(url)

    def upload_bundles(self, job: JobEnvelope, spool_root: str | Path, *,
                       max_workers: int = 1, unit_ids=None, progress=None):
        """Resume confirmed bytes; optional bounded slices permit origin-side fairness.

        Progress runs on the calling thread. On failure already acknowledged
        bundles remain durable; retry the same selection, not a new Job.
        Servers without status capability use the explicit legacy PUT protocol.
        """
        if isinstance(max_workers, bool) or not isinstance(max_workers, int) or not 1 <= max_workers <= 4:
            raise ValueError("max_workers must be an integer between 1 and 4")
        units = list(job.work_units)
        if unit_ids is not None:
            selected = list(unit_ids)
            if len(selected) != len(set(selected)) or not set(selected) <= {u.work_unit_id for u in units}:
                raise ValueError("unit_ids must be unique units belonging to this Job")
            selected = set(selected)
            units = [u for u in units if u.work_unit_id in selected]
        capabilities = self.require_available()
        checked_root = Path(spool_root).expanduser().absolute()
        managed_path(checked_root, ".transfer-check")
        spool = OriginSpool(checked_root, transfer_asset_cache=TransferAssetValidationCache())
        receipts = []
        counters = {"job_id": job.job_id, "total_units": len(units), "confirmed_units": 0,
                    "pending_units": len(units), "uploaded_bytes": 0, "skipped_bytes": 0,
                    "inspected_units": 0,
                    "uploaded_asset_bytes": 0, "skipped_asset_bytes": 0,
                    "resume_supported": capabilities.get("bundle_status") is True}

        def notify(stage):
            if progress is not None:
                progress(dict(counters, stage=stage))

        def upload_one(unit):
            source = managed_path(spool.root, identifier(job.origin_submitter_id), "outgoing",
                                  identifier(job.job_id), identifier(unit.work_unit_id) + ".zip")
            spool.validate(job, unit)
            size = source.stat().st_size
            if size > capabilities["max_bundle_bytes"]:
                raise ValueError("sealed bundle exceeds coordinator transfer limit")
            digest = sha256_file(source)
            url = f"/v1/jobs/{identifier(job.job_id)}/origin-bundles/{identifier(unit.work_unit_id)}"
            if capabilities.get("resumable_uploads") == 1:
                return self._upload_resumable(job.job_id, "bundle", unit.work_unit_id,
                                              source, size, digest, capabilities)
            if capabilities.get("bundle_status") is True:
                status_url = url
                if capabilities.get("bundle_source_receipts") is True:
                    status_url += "?" + urlencode({"expected_sha256": digest, "expected_size": size})
                with self._open(status_url) as response:
                    present = self._read_json(response)
                if (present.get("job_id") != job.job_id or present.get("work_unit_id") != unit.work_unit_id
                    or not isinstance(present.get("ready"), bool)):
                    raise ValueError("invalid origin status identity")
                if present["ready"] and present.get("size_bytes") == size and present.get("sha256") == digest:
                    return present, 0, size
                if (present["ready"] and capabilities.get("bundle_source_receipts") is True
                    and present.get("accepted_source_sha256") == digest
                    and present.get("accepted_source_size_bytes") == size):
                    return present, 0, size
                # Runtime resealing can change archive bytes: the existing PUT
                # validator must check equivalence; never infer it from identity.
            with source.open("rb") as handle, self._open(
                url,
                method="PUT", data=handle, headers={
                    "Content-Type": "application/octet-stream", "Content-Length": str(size),
                    "X-RCN-SHA256": digest,
                },
            ) as response:
                receipt = self._read_json(response)
            if (receipt.get("job_id") != job.job_id or receipt.get("work_unit_id") != unit.work_unit_id
                or receipt.get("ready") is not True):
                raise ValueError("invalid origin upload acknowledgement")
            return receipt, size, 0

        try:
            notify("checking")
            # Negotiate before sending thin archives; an old server must never
            # accept a descriptor whose shared bytes it cannot resolve.
            thin = False
            for unit in units:
                source = managed_path(spool.root, identifier(job.origin_submitter_id), "outgoing",
                                      identifier(job.job_id), identifier(unit.work_unit_id) + ".zip")
                with zipfile.ZipFile(source) as archive:
                    thin = thin or ASSET_MARKER in archive.namelist()
                counters["inspected_units"] += 1
                if counters["inspected_units"] % 32 == 0:
                    notify("checking")
            if thin:
                if capabilities.get("content_addressed_inputs") != 1 or capabilities.get("asset_encoding") != "gzip":
                    raise RcnApiError(409, "coordinator lacks negotiated content-addressed inputs; no downgrade")
                for record in {r.sha256: r for r in job.input_manifest}.values():
                    if record.size_bytes > capabilities["max_bundle_bytes"]:
                        raise ValueError("asset exceeds coordinator transfer limit")
                    source = verify_asset(spool.root, job, record)
                    if capabilities.get("resumable_uploads") == 1:
                        receipt, uploaded, skipped = self._upload_resumable(job.job_id, "asset", record.sha256,
                            source, record.size_bytes, record.sha256, capabilities)
                        if receipt.get("sha256") != record.sha256 or receipt.get("size_bytes") != record.size_bytes:
                            raise ValueError("invalid resumable asset acknowledgement")
                        counters["uploaded_asset_bytes"] += uploaded
                        counters["skipped_asset_bytes"] += skipped
                        notify("assets")
                        continue
                    url = f"/v1/jobs/{identifier(job.job_id)}/origin-assets/{record.sha256}"
                    with self._open(url) as response:
                        status = self._read_json(response)
                    if (status.get("job_id") != job.job_id or status.get("sha256") != record.sha256
                        or status.get("size_bytes") != record.size_bytes or not isinstance(status.get("ready"), bool)):
                        raise ValueError("invalid origin asset status")
                    if status["ready"]:
                        counters["skipped_asset_bytes"] += record.size_bytes
                        notify("assets")
                        continue
                    temporary_root = managed_path(spool.root, ".transfer-tmp")
                    temporary_root.mkdir(parents=True, exist_ok=True)
                    with tempfile.TemporaryFile(dir=temporary_root) as encoded:
                        with gzip.GzipFile(fileobj=encoded, mode="wb", mtime=0, filename="") as output, source.open("rb") as incoming:
                            while chunk := incoming.read(CHUNK_BYTES):
                                output.write(chunk)
                        length = encoded.tell()
                        if length > capabilities["max_bundle_bytes"]:
                            raise ValueError("encoded asset exceeds coordinator transfer limit")
                        encoded.seek(0)
                        checksum = hashlib.sha256()
                        while chunk := encoded.read(CHUNK_BYTES):
                            checksum.update(chunk)
                        encoded.seek(0)
                        with self._open(url, method="PUT", data=encoded, headers={
                            "Content-Type": "application/octet-stream", "Content-Encoding": "gzip",
                            "Content-Length": str(length), "X-RCN-SHA256": checksum.hexdigest(),
                        }) as response:
                            receipt = self._read_json(response)
                        if (receipt.get("job_id") != job.job_id or receipt.get("sha256") != record.sha256
                            or receipt.get("size_bytes") != record.size_bytes or receipt.get("ready") is not True):
                            raise ValueError("invalid origin asset acknowledgement")
                    counters["uploaded_asset_bytes"] += length
                    notify("assets")
        except Exception:
            notify("interrupted")
            raise
        workers = min(max_workers, max(1, min(4, int(capabilities.get("max_parallel_uploads", 1)))))
        # Bounded windows: do not eagerly schedule all 1891 units. Failures stop
        # new windows; a retry discovers successful peers from server evidence.
        try:
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="rcn-upload") as pool:
                for start in range(0, len(units), workers):
                    futures = [pool.submit(upload_one, unit) for unit in units[start:start + workers]]
                    first_error = None
                    for future in futures:
                        try:
                            receipt, uploaded, skipped = future.result()
                        except Exception as exc:
                            first_error = first_error or exc
                            continue
                        receipts.append(receipt)
                        counters["confirmed_units"] += 1
                        counters["pending_units"] -= 1
                        counters["uploaded_bytes"] += uploaded
                        counters["skipped_bytes"] += skipped
                        notify("transferring")
                    if first_error is not None:
                        raise first_error
        except Exception:
            notify("interrupted")
            raise
        notify("complete")
        return receipts

    def download_results(self, job: dict, manifests: list[dict], spool_root: str | Path, *,
                         reserve_free_bytes: int = 0, operation_id=None, progress=None,
                         durable=None, cancel_event=None, local_sources=None):
        # An explicitly durable operation can be complete locally even when
        # the center is offline. Let its frozen contract select that path.
        capabilities = None if durable is True or operation_id is not None else self.require_available()
        if local_sources is not None or durable is True or operation_id is not None or (capabilities or {}).get('result_preparations') is True:
            from .collection import CollectionRunner
            return CollectionRunner(self, job, manifests, spool_root,
                reserve_free_bytes=reserve_free_bytes, operation_id=operation_id,
                progress=progress, capabilities=capabilities, cancel_event=cancel_event, local_sources=local_sources).run()
        return self._download_results_legacy(job, manifests, spool_root,
                                             reserve_free_bytes=reserve_free_bytes)

    def _download_results_legacy(self, job: dict, manifests: list[dict], spool_root: str | Path, *, reserve_free_bytes: int = 0):
        if type(reserve_free_bytes) is not int or reserve_free_bytes < 0:
            raise ValueError("result disk reserve must be a nonnegative integer")
        self.require_available()
        job_id = identifier(job["job_id"])
        root = Path(spool_root).expanduser().absolute()
        # Check before resolve/mkdir to avoid hiding a local junction.
        managed_path(root, ".transfer-check")
        root.mkdir(parents=True, exist_ok=True)
        expected = {}
        for payload in manifests:
            manifest = ArtifactManifest.model_validate(payload)
            if manifest.job_id != job_id or manifest.work_unit_id in expected:
                raise ValueError("invalid or duplicate result manifest identity")
            names = [f.relative_path.casefold() for f in manifest.files]
            if len(names) != len(set(names)):
                raise ValueError("ambiguous result manifest paths")
            expected[manifest.work_unit_id] = manifest
        with self._open(f"/v1/jobs/{job_id}/origin-results") as response:
            index = self._read_json(response)
        entries = index.get("units", [])
        if (index.get("job_id") != job_id or len(entries) != len(expected)
            or {entry["work_unit_id"] for entry in entries} != set(expected)):
            raise ValueError("result index does not exactly match the requested manifests")
        if reserve_free_bytes:
            needed = 0
            for entry in entries:
                directory = managed_path(root, identifier(job["origin_submitter_id"]), "incoming", job_id,
                                         identifier(entry["work_unit_id"]), identifier(entry["attempt_id"]))
                for record in expected[entry["work_unit_id"]].files:
                    target = managed_path(directory, record.relative_path)
                    if target.exists():
                        verify_file(target, record.size_bytes, record.sha256)
                    else:
                        needed += record.size_bytes
            if shutil.disk_usage(root).free < reserve_free_bytes + needed:
                raise ResultCapacityError("insufficient disk space to retain the member reserve")
        downloaded = []
        for entry in entries:
            unit_id, attempt_id = identifier(entry["work_unit_id"]), identifier(entry["attempt_id"])
            unit = next((u for u in job["work_units"] if u["work_unit_id"] == unit_id), None)
            if unit is None or not any(a["attempt_id"] == attempt_id and a["state"] == "completed"
                                      for a in unit.get("attempts", [])):
                raise ValueError("result index does not name a completed Job attempt")
            manifest = expected[unit_id]
            if entry["manifest_sha256"] != sha256_value(manifest.model_dump(mode="json")):
                raise ValueError("result manifest changed; refresh before collection")
            directory = managed_path(root, identifier(job["origin_submitter_id"]), "incoming",
                                     job_id, unit_id, attempt_id)
            for record in manifest.files:
                target = managed_path(directory, record.relative_path)
                if target.exists():
                    # Never repair by overwriting an existing scientific result.
                    verify_file(target, record.size_bytes, record.sha256)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                if reserve_free_bytes and shutil.disk_usage(root).free < reserve_free_bytes + record.size_bytes:
                    raise ResultCapacityError("insufficient disk space to retain the member reserve")
                fd, name = tempfile.mkstemp(prefix=".download-", suffix=".partial", dir=target.parent)
                temporary = Path(name)
                try:
                    with os.fdopen(fd, "wb") as output, self._open(
                        f"/v1/jobs/{job_id}/origin-results/{unit_id}/{attempt_id}?" + urlencode({"file": record.relative_path})
                    ) as response:
                        if (response.status != 200 or response.headers.get("X-RCN-SHA256") != record.sha256
                            or response.headers.get("Content-Length") != str(record.size_bytes)):
                            raise ValueError("result transfer headers do not match the manifest")
                        checksum, received = hashlib.sha256(), 0
                        while chunk := response.read(CHUNK_BYTES):
                            received += len(chunk)
                            if received > record.size_bytes:
                                raise ValueError("result exceeds declared size")
                            checksum.update(chunk)
                            output.write(chunk)
                        if received != record.size_bytes or checksum.hexdigest() != record.sha256:
                            raise ValueError("result size or SHA256 mismatch")
                        output.flush()
                        os.fsync(output.fileno())
                    managed_path(directory, record.relative_path)
                    try:
                        publish_new_file(temporary, target)
                    except FileExistsError:
                        verify_file(target, record.size_bytes, record.sha256)
                finally:
                    temporary.unlink(missing_ok=True)
            downloaded.append({"work_unit_id": unit_id, "attempt_id": attempt_id})
        return downloaded
