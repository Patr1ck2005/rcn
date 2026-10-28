"""Local member desktop broker: data packages, HTTPS and private recovery journals.

This is a separate FastAPI application. It never initializes a coordinator DB.
The browser does not receive a center token, device key or general shell API.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from functools import wraps
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import random
import time
import errno
import secrets
import shutil
import tempfile
import threading
from urllib.parse import unquote, urlsplit, urlencode
from uuid import UUID
from urllib.error import URLError
from urllib.request import ProxyHandler, build_opener

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import member_registration as storage
from .client import RcnClient, RcnApiError
from .member_client_credentials import PersonalCredentialStore, CredentialUnavailable
from .member_agent_config import (
    MemberAgentExportRequest, clear_member_agent_login, export_member_agent_config,
    list_member_agent_configs,
)
from .models import JobEnvelope
from .origin_transfer_client import OriginTransferClient

LOCAL_PORT = 18765
MAX_PACKAGE_BYTES = 16 * 1024**3
RESERVE_BYTES = 10 * 1024**3
MAX_METADATA_BYTES = 64 * 1024**2


def member_api_client(base_url, token=None, *, connection_root=None):
    from .member_client_connection import resolve_center
    endpoint = resolve_center(connection_root or default_client_root(), base_url)
    return _member_api_for_endpoint(endpoint, token)


def _member_api_for_endpoint(endpoint, token):
    from .origin_transfer_client import _NoRedirect
    return RcnClient(endpoint, token=token, opener=build_opener(ProxyHandler({}), _NoRedirect()))


def default_client_root() -> Path:
    from .node import default_node_root
    return default_node_root() / "member-client"


def _now():
    return datetime.now(timezone.utc).isoformat()


def _identity_locked(function):
    @wraps(function)
    def call(self, *args, **kwargs):
        with self.lock:
            return function(self, *args, **kwargs)
    return call


def _uuid(value: str) -> str:
    try:
        normalized = str(UUID(value))
    except (ValueError, TypeError) as exc:
        raise HTTPException(400, "invalid submission operation ID") from exc
    if normalized != value:
        raise HTTPException(400, "operation ID must be canonical")
    return normalized


def _center(value: str) -> str:
    parsed = urlsplit(value.strip())
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.path not in {"", "/"}):
        raise HTTPException(400, "请输入管理员提供的 HTTPS 中心入口")
    return value.strip().rstrip("/")


def _write_json(path: Path, value: dict):
    storage._unlinked(path)
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(raw) > MAX_METADATA_BYTES:
        raise ValueError("member journal metadata exceeds limit")
    fd, name = tempfile.mkstemp(prefix=".member-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        storage._unlinked(path)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _read_json(path: Path):
    storage._unlinked(path)
    with path.open("rb") as stream:
        raw = stream.read(MAX_METADATA_BYTES + 1)
    if len(raw) > MAX_METADATA_BYTES:
        raise ValueError("member journal metadata exceeds limit")
    return json.loads(raw)


class Login(BaseModel):
    model_config = ConfigDict(extra="forbid")
    center_url: str
    token: str = Field(min_length=1, max_length=4096)


class PlanOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")
    package_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    requested_unit_count: int | None = Field(default=None, ge=1)
    estimated_seconds_per_item: float | None = Field(default=None, gt=0)


class RerunOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")
    operation_id: str


class MemberBroker:
    def __init__(self, root: Path, *, credential_store=None, api_factory=member_api_client,
                 transfer_factory=OriginTransferClient):
        self.root = Path(root).absolute()
        storage._private_directory(self.root)
        for name in ("packages", "operations", "transfers", "results"):
            storage._private_directory(self.root / name)
        self.api_factory = api_factory
        self.transfer_factory = transfer_factory
        self.lock = threading.RLock()
        self.executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="rcn-member")
        self.busy: set[str] = set()
        self.closed = False
        self.credential_error = None
        try:
            self.credentials = credential_store or PersonalCredentialStore(self.root / "credentials")
            self.login = self.credentials.load()
        except (CredentialUnavailable, ValueError, OSError, storage.MemberRegistrationError) as exc:
            # Keep the original bytes. Public help and a new connection import
            # must remain reachable when a login record cannot be decoded.
            from .member_doctor import error_detail
            self.credential_error = error_detail(exc, stage="identity")["reason_code"]
            if not hasattr(self, "credentials"):
                from .member_client_credentials import UnavailableCredentialStore
                self.credentials = UnavailableCredentialStore(self.credential_error)
            self.login = None
        self.actor = self.login.get("actor") if self.login else None
        self.auth_generation = 0
        self.online = False
        self.connection_error = None
        self.collection_timers = {}
        from .transfer_queue import TransferQueue
        self.collection_queue = TransferQueue(self._drain_collections, lock=self.lock)
        self.collection_targets = {}
        self.collection_active = None
        self.collection_cancels = {}

    def client(self):
        if not self.login:
            raise HTTPException(401, "请先登录个人账号")
        return self._api(self.login["center_url"], self.login["token"])

    def _api(self, center, token):
        return self._api_with_connection(center, token)[0]

    def _api_with_connection(self, center, token):
        try:
            from .member_client_connection import _resolve_center
            from .member_agent_config import member_connection_root
            endpoint, descriptor = _resolve_center(member_connection_root(self), center)
            if self.api_factory is member_api_client:
                api = _member_api_for_endpoint(endpoint, token)
            else:
                api = self.api_factory(endpoint, token=token)
            return api, descriptor
        except (RuntimeError, ValueError, OSError) as exc:
            if isinstance(exc, RcnApiError):
                raise
            from .member_doctor import error_detail
            detail = error_detail(exc)
            raise RcnApiError(0, detail["message"], reason_code=detail["reason_code"]) from None

    def session(self, *, refresh=False):
        from .member_client_connection import public_connection
        with self.lock:
            login, generation, actor = self.login, self.auth_generation, self.actor
        configured_connection = None
        if login and (refresh or not actor):
            try:
                # Reuse only the descriptor validated while resolving this
                # request. Keep it even if the subsequent center call fails.
                api, configured_connection = self._api_with_connection(login["center_url"], login["token"])
                found = api.current_actor()
                if not isinstance(found, dict) or not found.get("actor_id"):
                    raise RcnApiError(502, "invalid member identity")
                error = None
            except RcnApiError as exc:
                if not actor:
                    raise
                found = actor
                error = {"reason_code": "center_login_required" if exc.status in {401, 403} else "center_unavailable",
                         "message": "中心连接未确认；可以查看本机记录或暂停自己的计算，提交与恢复接活需重新连接"}
            with self.lock:
                if generation == self.auth_generation:
                    self.actor = found
                    self.online = error is None
                    self.connection_error = error
        else:
            try:
                from .member_agent_config import member_connection_root
                configured_connection = public_connection(member_connection_root(self))
            except (RuntimeError, ValueError, OSError):
                configured_connection = None
        return self._session_payload(configured_connection)

    def _session_payload(self, configured_connection):
        with self.lock:
            return {"connected": bool(self.login and self.actor),
                    "center_url": self.login["center_url"] if self.login else (configured_connection or {}).get("center_reference", ""),
                    "configured_connection": configured_connection, "actor": self.actor,
                    "online": self.online, "remote_actions_available": bool(self.online and self.login),
                    "connection_error": self.connection_error,
                    "credential_error": self.credential_error}

    def sign_in(self, payload: Login):
        center = payload.center_url if payload.center_url.startswith("rcn-managed://") else _center(payload.center_url)
        token = payload.token.strip()
        client, configured_connection = self._api_with_connection(center, token)
        actor = client.current_actor()
        # Verify the endpoint identity before saving any personal credential.
        if not isinstance(actor, dict) or not actor.get("actor_id"):
            raise HTTPException(502, "中心没有返回有效的个人身份")
        with self.lock:
            if self.busy:
                raise HTTPException(409, "传输仍在进行，请完成后切换个人账号")
            self.credentials.save(center_url=center, token=token, actor=actor)
            self.login = {"center_url": center, "token": token, "actor": actor}
            self.actor = actor
            self.auth_generation += 1
            self.online = True
            self.connection_error = None
            self.credential_error = None
        self.recover_collections()
        return self._session_payload(configured_connection)

    def sign_out(self):
        with self.lock:
            if self.busy:
                raise HTTPException(409, "传输仍在进行，请先等待或关闭客户端后重开")
            self.credentials.clear()
            self.login = None
            self.actor = None
            self.auth_generation += 1
            self.online = False
            self.connection_error = None
        return self.session()

    def package_path(self, identifier):
        if not re.fullmatch(r"[a-f0-9]{64}", identifier):
            raise HTTPException(400, "invalid package ID")
        return self.root / "packages" / (identifier + ".zip")

    def inspect_package(self, identifier):
        from .submission_packages import inspect_submission_package
        path = self.package_path(identifier)
        if not path.is_file():
            raise HTTPException(404, "任务包不存在，请重新选择原包")
        actor = self.session()["actor"]
        if not actor:
            raise HTTPException(401, "请先登录个人账号")
        return inspect_submission_package(path, expected_actor_id=actor["actor_id"])

    @_identity_locked
    def import_package(self, path: Path):
        """Import a data package for a local Agent using the desktop's custody.

        Copies bytes into the same hash-addressed store and recovers an existing
        operation for this package/person/center. The source is never modified.
        """
        from .submission_packages import inspect_submission_package, _publish_local_data
        actor = self.session()["actor"]
        if not actor:
            raise HTTPException(401, "member_login_required")
        source = Path(path).absolute()
        storage._unlinked(source)
        if not source.is_file() or source.stat().st_size > MAX_PACKAGE_BYTES:
            raise ValueError("member_package_not_regular_or_too_large")
        fd, name = tempfile.mkstemp(prefix=".import-", dir=self.root / "packages")
        temporary = Path(name)
        checksum = hashlib.sha256()
        received = 0
        try:
            with source.open("rb") as incoming, os.fdopen(fd, "wb") as outgoing:
                while chunk := incoming.read(1024 * 1024):
                    received += len(chunk)
                    if received > MAX_PACKAGE_BYTES:
                        raise ValueError("member_package_too_large")
                    if shutil.disk_usage(self.root).free < RESERVE_BYTES + len(chunk):
                        raise MemberStorageError("member_input_disk_reserve")
                    outgoing.write(chunk)
                    checksum.update(chunk)
                outgoing.flush()
                os.fsync(outgoing.fileno())
            manifest = inspect_submission_package(temporary, expected_actor_id=actor["actor_id"])
            identifier = checksum.hexdigest()
            destination = self.package_path(identifier)
            if destination.exists():
                storage._unlinked(destination)
                with destination.open("rb") as existing:
                    if hashlib.file_digest(existing, "sha256").hexdigest() != identifier:
                        raise ValueError("existing task package was changed")
            else:
                _publish_local_data(temporary, destination)
            result = {"package_id": identifier, "filename": source.name[:160], "preview": self.preview(manifest)}
            previous = [_read_json(item) for item in (self.root / "operations").glob("*.json")]
            matches = [item for item in previous if item.get("package_id") == identifier
                       and item.get("actor_id") == actor["actor_id"]
                       and item.get("center_url") == self.login["center_url"]]
            if matches:
                original = max(matches, key=lambda item: item["created_at"])
                result.update(operation_id=original["operation_id"], operation=self.present(original))
            return result
        finally:
            temporary.unlink(missing_ok=True)

    @staticmethod
    def preview(manifest):
        value = manifest.model_dump(mode="json") if hasattr(manifest, "model_dump") else manifest
        request = value["request"]
        missing = []
        if (len(request["items"]) > 1 and not request.get("requested_unit_count")
                and not request.get("estimated_seconds_per_item")
                and any(item.get("estimated_duration_s") is None for item in request["items"])):
            missing.append("requested_unit_count")
        estimates = [item.get("estimated_duration_s") for item in request["items"]]
        duration = (request["estimated_seconds_per_item"] * len(estimates) if request.get("estimated_seconds_per_item")
                    else sum(estimates) if all(item is not None for item in estimates) else None)
        return {"project_id": request["project_id"], "profile_id": request["execution_profile_id"],
                "submitter_id": request["user_id"], "input_count": len(value["files"]),
                "total_bytes": sum(item["size_bytes"] for item in value["files"]),
                "atomic_item_count": len(request["items"]), "unit_count": request.get("requested_unit_count"),
                "missing_fields": missing, "package_contents_sha256": value["package_contents_sha256"],
                "estimated_duration_seconds": duration, "output_contract_sha256": request.get("output_contract_sha256")}

    def journal_path(self, operation_id):
        return self.root / "operations" / (_uuid(operation_id) + ".json")

    def read_operation(self, operation_id):
        path = self.journal_path(operation_id)
        if not path.exists():
            raise HTTPException(404, "提交记录不存在")
        value = _read_json(path)
        actor = self.session()["actor"]
        if not actor or value["actor_id"] != actor["actor_id"]:
            raise HTTPException(403, "该提交属于另一位成员")
        if value.get("center_url") != self.login["center_url"]:
            raise HTTPException(409, "请连接这次提交原来的中心")
        return value

    def update(self, operation_id, **fields):
        with self.lock:
            value = self.read_operation(operation_id)
            value.update(fields, updated_at=_now())
            _write_json(self.journal_path(operation_id), value)
            return value

    def present(self, value):
        canonical = value.get("collection_control", {}).get("canonical_operation_id")
        if canonical and canonical != value["operation_id"] and value.get("collection_control", {}).get("state") != "user_paused":
            current = self.read_operation(canonical)
            value = {**value, "phase": current.get("phase"), "collection": current.get("collection"),
                     "collection_control": {**current.get("collection_control", {}), "canonical_operation_id": canonical}}
        result = {key: item for key, item in value.items()
                  if key not in {"center_operation", "center_url", "actor_id", "plan_options", "collection_request"}}
        result["can_confirm"] = bool(not value.get("job_id") and value.get("center_operation"))
        result["can_upload"] = bool(value.get("job_id") and value["operation_id"] not in self.busy
                                    and value.get("upload", {}).get("state") != "complete")
        result["can_collect"] = bool(value.get("job_id") and value["operation_id"] not in self.busy
                                     and value.get("job", {}).get("status") == "completed")
        return result

    @_identity_locked
    def plan(self, operation_id, payload: PlanOptions):
        from .submission_operations import SubmissionOperationRequest
        _uuid(operation_id)
        manifest = self.inspect_package(payload.package_id)
        request = {"schema_version": 1, "package_manifest": manifest.model_dump(mode="json")}
        for key in ("requested_unit_count", "estimated_seconds_per_item"):
            if getattr(payload, key) is not None:
                request[key] = getattr(payload, key)
        # Same validation as center; never publish arbitrary scientific executable content.
        SubmissionOperationRequest.model_validate(request)
        path = self.journal_path(operation_id)
        with self.lock:
            if path.exists():
                previous = self.read_operation(operation_id)
                if previous["plan_options"] != request or previous["package_id"] != payload.package_id:
                    raise HTTPException(409, "同一提交编号的任务内容不能改变")
            else:
                value = {"schema_version": 1, "operation_id": operation_id, "package_id": payload.package_id,
                         "actor_id": self.actor["actor_id"], "center_url": self.login["center_url"],
                         "phase": "planning", "preview": self.preview(manifest), "plan_options": request,
                         "created_at": _now(), "updated_at": _now()}
                _write_json(path, value)
        try:
            remote = self.client()._request("PUT", f"/v1/submission-operations/{operation_id}", request)
            preview = self.preview(manifest)
            preview.update(unit_count=len(remote["plan"]["work_units"]), missing_fields=[])
            value = self.update(operation_id, center_operation=remote, job_id=remote.get("job_id"),
                                phase="confirmed" if remote.get("job_id") else "planned", error=None, preview=preview)
            return self.present(value)
        except Exception:
            self.update(operation_id, phase="planning-unknown",
                        error={"message": "规划回执未确认，请恢复同一提交", "reason_code": "planning_unknown"})
            raise

    @_identity_locked
    def refresh(self, operation_id):
        value = self.read_operation(operation_id)
        try:
            remote = self.client()._request("GET", f"/v1/submission-operations/{operation_id}")
        except RcnApiError as exc:
            if exc.status != 404 or value.get("job_id") or value["phase"] not in {"planning", "planning-unknown"}:
                raise
            remote = self.client()._request("PUT", f"/v1/submission-operations/{operation_id}", value["plan_options"])
        changes = {"center_operation": remote, "job_id": remote.get("job_id")}
        if remote.get("job_id"):
            job = self.client().get_job_status(remote["job_id"])
            units = job.get("work_units", [])
            changes["job"] = {"status": job["status"], "total_units": len(units),
                              "completed_units": sum(unit.get("status") == "completed" for unit in units)}
            if value["phase"] in {"planning", "planning-unknown", "planned", "confirming", "confirm-unknown"}:
                changes["phase"] = "confirmed"
                changes["error"] = None
        elif value["phase"] in {"planning", "planning-unknown"}:
            changes.update(phase="planned", error=None)
        return self.present(self.update(operation_id, **changes))

    @_identity_locked
    def confirm(self, operation_id):
        previous = self.read_operation(operation_id)
        if not previous.get("job_id"):
            self.update(operation_id, phase="confirming")
        try:
            remote = self.client()._request("POST", f"/v1/submission-operations/{operation_id}/confirm")
            value = self.update(operation_id, center_operation=remote, job_id=remote["job_id"],
                                phase=previous["phase"] if previous.get("job_id") else "confirmed", error=None)
            return self.present(value)
        except Exception:
            self.update(operation_id, phase="confirm-unknown",
                        error={"message": "提交送达尚未确认，正在恢复原任务", "reason_code": "confirm_unknown"})
            raise

    @_identity_locked
    def start_transfer(self, operation_id, *, collect=False, _automatic=False):
        value = self.read_operation(operation_id)
        if not value.get("job_id"):
            raise HTTPException(409, "先恢复原提交回执")
        with self.lock:
            if self.closed or operation_id in self.busy:
                return self.present(value)
            if collect:
                control = value.get("collection_control", {})
                if _automatic and control.get("state") in {"user_paused", "fault_paused", "complete"}:
                    return self.present(value)
                target_key = self._collection_target(value)
                canonical = self.collection_targets.setdefault(target_key, operation_id)
                if canonical != operation_id:
                    original = self.read_operation(canonical)
                    frozen = value.get("collection_request")
                    original_request = original.get("collection_request")
                    if original.get("collection_control", {}).get("state") == "complete" and frozen is None:
                        # A completed cached request still needs current owner/producer authorization.
                        client = self.client()
                        frozen = {"job": _collection_job_contract(client, value["job_id"]),
                                  "manifests": client.collect_artifacts(value["job_id"])}
                    if frozen is not None and original_request is not None and frozen != original_request:
                        raise HTTPException(409, "同一目标的结果身份已改变，不能合并旧回收")
                    if control.get("canonical_operation_id") != canonical or control.get("state") != "attached":
                        value = self.update(operation_id, collection_control={**control,
                            "canonical_operation_id": canonical, "state": "attached"})
                    return self.present(value)
                if self.collection_active is not None:
                    if self.collection_queue.enqueue(operation_id):
                        self.update(operation_id, phase="collection-waiting", collection_control={**control,
                            "operation_id": control.get("operation_id", "member-collection-" + operation_id), "state": "waiting"})
                    return self.present(self.read_operation(operation_id))
                self.collection_queue.discard(operation_id)
                self.collection_active = operation_id
                self.collection_cancels[operation_id] = threading.Event()
                control = {**control, "operation_id": control.get("operation_id", "member-collection-" + operation_id),
                           "state": "active", "next_retry_at": None}
                self.update(operation_id, collection_control=control)
            self.update(operation_id, phase="collecting" if collect else "uploading", error=None)
            self.busy.add(operation_id)
            try:
                self.executor.submit(self._transfer, operation_id, collect)
            except Exception:
                self.busy.discard(operation_id)
                if collect:
                    self.collection_active = None
                raise
        return self.present(self.read_operation(operation_id))

    def _transfer(self, operation_id, collect):
        try:
            from .submission_packages import prepare_submission_bundles
            value = self.read_operation(operation_id)
            client = self.client()
            transfer = self.transfer_factory(client)
            if collect:
                from .collection import CollectionRunner
                frozen = value.get("collection_request")
                if frozen is None:
                    job = _collection_job_contract(client, value["job_id"])
                    if job["status"] != "completed":
                        raise ValueError("member_collection_job_not_completed")
                    manifests = client.collect_artifacts(value["job_id"])
                    frozen = {"job": job, "manifests": manifests}
                    self.update(operation_id, collection_request=frozen)
                job, manifests = frozen["job"], frozen["manifests"]
                if job["job_id"] != value["job_id"]:
                    raise ValueError("member_collection_job_identity_changed")
                directory = self.root / "results" / value["job_id"]
                control = self.read_operation(operation_id)["collection_control"]
                def collected_progress(receipt):
                    self.update(operation_id, collection={"state": "downloading", "directory": str(directory),
                        "progress": receipt, **{key: receipt[key] for key in (
                            "stage", "received_bytes", "total_bytes", "source_checked_bytes", "source_total_bytes",
                            "completed_files", "total_files") if key in receipt}})
                runner = CollectionRunner(transfer, job, manifests, directory,
                    operation_id=control["operation_id"], reserve_free_bytes=RESERVE_BYTES,
                    progress=collected_progress, cancel_event=self.collection_cancels.get(operation_id))
                metadata = {"consumer": "member-client-v1", "member_operation_id": operation_id}
                if runner.status()["phase"] == "finalized":
                    receipt = runner.receipt(metadata=metadata)
                elif runner.local_files_present():
                    # Eligibility is only stat coverage. SDK finalize supplies
                    # the one strict offline SHA pass, including a crash just
                    # after publishing the last file but before bytes_complete.
                    receipt = runner.finalize(metadata=metadata)
                else:
                    runner.run()
                    receipt = runner.receipt(metadata=metadata)
                receipt_path = self.root / "operations" / (operation_id + ".collection.json")
                _write_json(receipt_path, {"schema": "member-collection-receipt-v1", "operation_id": operation_id,
                    "collection_operation_id": control["operation_id"], "job_id": job["job_id"], "receipt": receipt})
                count = sum(len(item["files"]) for item in manifests)
                self.update(operation_id, phase="collected", collection_control={**control, "state": "complete"},
                            collection={"state": "complete", "directory": str(directory), "receipt_path": str(receipt_path),
                                        "operation_id": control["operation_id"], "verified_files": count, "total_files": count})
            else:
                job = _collection_job_contract(client, value["job_id"])
                remote = client._request("GET", f"/v1/submission-operations/{operation_id}")
                spool = self.root / "transfers" / operation_id
                runtime = client.execution_runtime()["runtime_version"]
                self._input_capacity(value, remote, spool, job)
                prepare_submission_bundles(self.package_path(value["package_id"]), remote, spool,
                                          runtime_version=runtime)

                def progress(receipt):
                    self.update(operation_id, upload={"state": receipt["stage"],
                                "completed_files": receipt.get("confirmed_units", 0),
                                "total_files": receipt.get("total_units", 0),
                                "unit": "unit",
                                "uploaded_bytes": receipt.get("uploaded_bytes", 0),
                                "skipped_bytes": receipt.get("skipped_bytes", 0)})

                transfer.upload_bundles(JobEnvelope.model_validate(job), spool, max_workers=2, progress=progress)
                client.ensure_running()
                self.update(operation_id, phase="submitted", upload={"state": "complete",
                            "completed_files": len(job["work_units"]), "total_files": len(job["work_units"]), "unit": "unit"})
        except Exception as exc:
            reason = getattr(exc, "reason_code", None) or "member_transfer_interrupted"
            self.update(operation_id, phase="collection-interrupted" if collect else "upload-interrupted",
                        error={"message": "传输中断，原任务和回收身份已保留", "reason_code": reason, "error_type": type(exc).__name__})
            if collect:
                value = self.read_operation(operation_id)
                control = value.get("collection_control", {})
                if control.get("state") != "user_paused":
                    retryable = _collection_retryable(exc)
                    failures = control.get("failures", 0) + 1
                    delay = min(300, 30 * 2 ** min(failures - 1, 4)) * random.uniform(.8, 1.2)
                    self.update(operation_id, collection_control={**control,
                        "state": "retry_wait" if retryable else "fault_paused", "failures": failures,
                        "next_retry_at": time.time() + delay if retryable else None,
                        "reason_code": reason})
                    if retryable:
                        self._schedule_collection(operation_id, delay)
        finally:
            with self.lock:
                self.busy.discard(operation_id)
                if collect and self.collection_active == operation_id:
                    self.collection_active = None
                    self.collection_cancels.pop(operation_id, None)
                if collect:
                    self._drain_collections()

    def _drain_collections(self):
        with self.lock:
            while not self.closed and self.collection_active is None:
                operation_id = self.collection_queue.take()
                if operation_id is None:
                    return
                try:
                    self.start_transfer(operation_id, collect=True, _automatic=True)
                except (HTTPException, OSError, ValueError):
                    continue

    def _schedule_collection(self, operation_id, delay):
        """Only actual fault backoff owns the one earliest-deadline timer."""
        self.collection_queue.retry(operation_id, delay)

    def _collection_target(self, value):
        return (value.get("actor_id"), value.get("center_url"), value["job_id"],
                str(self.root / "results" / value["job_id"]))

    def recover_collections(self):
        """Restore only owner-bound original collections, never uploads or compute."""
        if not self.login or not self.actor or self.closed:
            return
        recovered = []
        for path in sorted((self.root / "operations").glob("*.json")):
            if path.name.endswith(".collection.json"):
                continue
            try:
                value = _read_json(path)
                control = value.get("collection_control", {})
                if (value.get("actor_id") != self.actor["actor_id"] or value.get("center_url") != self.login["center_url"]
                    or not value.get("job_id") or not control):
                    continue
                _uuid(value["operation_id"])
                recovered.append(value)
            except (ValueError, OSError, KeyError, TypeError, HTTPException):
                continue
        # Rebuild target ownership before any timer can resume a duplicate journal.
        for value in sorted(recovered, key=lambda item: item.get("created_at", "")):
            if not value["collection_control"].get("canonical_operation_id"):
                self.collection_targets.setdefault(self._collection_target(value), value["operation_id"])
        for value in recovered:
            try:
                control = value["collection_control"]
                if (value.get("phase") not in {"collecting", "collection-interrupted", "collection-waiting"}
                    or control.get("state") in {"user_paused", "fault_paused", "complete", "attached"}):
                    continue
                delay = max(0, min(360, (control.get("next_retry_at") or 0) - time.time()))
                self._schedule_collection(value["operation_id"], delay)
            except (ValueError, OSError, KeyError, TypeError, HTTPException):
                continue

    @_identity_locked
    def pause_collection(self, operation_id):
        value = self.read_operation(operation_id)
        control = value.get("collection_control", {})
        self.collection_queue.discard(operation_id)
        timer = self.collection_timers.pop(operation_id, None)
        if timer is not None:
            timer.cancel()
        if operation_id in self.collection_cancels:
            self.collection_cancels[operation_id].set()
        return self.present(self.update(operation_id, collection_control={**control, "state": "user_paused", "next_retry_at": None}))

    def _input_capacity(self, value, operation, spool, job):
        from .origin_assets import asset_path
        from .origin_transfer import managed_path, verify_file
        manifest = self.inspect_package(value["package_id"])
        envelope = JobEnvelope.model_validate(job)
        needed = 0
        for record in manifest.files:
            path = managed_path(spool, ".submission-inputs", value["operation_id"], record.relative_path)
            if path.exists():
                verify_file(path, record.size_bytes, record.sha256)
            else:
                needed += record.size_bytes
        seen = set()
        for record in envelope.input_manifest:
            if record.sha256 in seen:
                continue
            seen.add(record.sha256)
            path = asset_path(spool, envelope, record.sha256)
            if path.exists():
                verify_file(path, record.size_bytes, record.sha256)
            else:
                needed += record.size_bytes
        # Thin bundles contain metadata, while model assets are stored once.
        needed += 1024**2 + 2 * len(json.dumps(operation, ensure_ascii=False).encode("utf-8"))
        if shutil.disk_usage(self.root).free < RESERVE_BYTES + needed:
            raise MemberStorageError("member_input_disk_reserve")

    def close(self, *, cancel_active=True):
        with self.lock:
            self.closed = True
            self.collection_queue.close()
            for timer in self.collection_timers.values():
                timer.cancel()
            self.collection_timers.clear()
            if cancel_active:
                for event in self.collection_cancels.values():
                    event.set()
        self.executor.shutdown(wait=True, cancel_futures=False)


def _collection_job_contract(client, job_id):
    """Keep strict source contracts separate from operational detail DTOs."""
    getter = getattr(client, "get_job_contract", None)
    if getter is None:
        return client.get_job(job_id)  # Minimal protocol fixtures/legacy adapters.
    try:
        return getter(job_id)
    except RcnApiError as exc:
        if exc.status != 404:
            raise
    detail = client.get_job(job_id)
    if detail.get("job_id") != job_id or not detail.get("status"):
        raise ValueError("member_collection_canonical_job_unavailable")
    offset = 0
    while True:
        query = urlencode({"project_id": detail["project_id"], "status": detail["status"], "view": "full", "limit": 1, "offset": offset})
        rows = client._request("GET", "/v1/jobs?" + query)
        if not isinstance(rows, list) or not rows:
            raise ValueError("member_collection_canonical_job_not_found")
        for row in rows:
            if row.get("job_id") == job_id:
                JobEnvelope.model_validate(row)
                if any(row.get(key) != detail.get(key) for key in ("project_id", "request_hash")):
                    raise ValueError("member_collection_canonical_identity_changed")
                return row
        offset += len(rows)


def _collection_retryable(exc):
    status = getattr(exc, "status", None)
    if status == 409 and getattr(exc, "reason_code", None) in {
        "preparation_expired", "preparation_process_restarted", "preparation_process_stopped"}:
        return True
    if status is not None:
        return status in {0, 408, 425, 429, 500, 502, 503, 504}
    if isinstance(exc, PermissionError):
        return False
    if isinstance(exc, (TimeoutError, ConnectionError, URLError)):
        return True
    if isinstance(exc, OSError):
        return exc.errno in {None, errno.ENOSPC, errno.ECONNRESET, errno.ECONNABORTED, errno.ETIMEDOUT}
    return getattr(exc, "reason_code", "") in {"origin_result_disk_reserve", "collection_volume_busy", "collection_owner_active", "storage_metadata_busy",
        "storage_holder_busy", "storage_capacity_unavailable", "storage_budget_busy", "storage_ledger_busy", "collection_paused_by_owner", "storage_background_deferred", "restore_source_unavailable"}


class MemberStorageError(ValueError):
    def __init__(self, reason_code):
        super().__init__(reason_code)
        self.reason_code = reason_code


def create_member_app(*, state_root: Path | None = None, credential_store=None,
                      api_factory=member_api_client, transfer_factory=OriginTransferClient,
                      static_root: Path | None = None) -> FastAPI:
    broker = MemberBroker(state_root or default_client_root(), credential_store=credential_store,
                          api_factory=api_factory, transfer_factory=transfer_factory)
    from .member_client_compute import ContributionManager
    from .help import HelpCatalog
    contribution = ContributionManager(broker.root)
    help_catalog = HelpCatalog()

    @asynccontextmanager
    async def lifespan(app):
        broker.recover_collections()
        yield
        broker.close()

    app = FastAPI(title="RCN member client", lifespan=lifespan)
    app.state.broker = broker
    app.state.contribution = contribution
    local_session = secrets.token_urlsafe(32)
    hosts = ["127.0.0.1", "localhost"]
    if api_factory is not member_api_client:
        hosts.append("testserver")
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=hosts)

    @app.middleware("http")
    async def local_boundary(request: Request, call_next):
        origin = request.headers.get("origin")
        host = request.headers.get("host", "")
        if origin and origin not in {"http://" + host}:
            return JSONResponse({"detail": "foreign_origin"}, status_code=403)
        if request.headers.get("sec-fetch-site") in {"cross-site", "same-site"}:
            return JSONResponse({"detail": "foreign_origin"}, status_code=403)
        if request.url.path.startswith(("/local/v1/", "/v1/")):
            readonly_bootstrap = (request.method == "GET" and request.url.path in {
                "/local/v1/capabilities", "/local/v1/session"})
            service_shutdown = (request.url.path == "/local/v1/shutdown" and request.method == "POST"
                and secrets.compare_digest(request.headers.get("x-rcn-shutdown", ""), getattr(app.state, "shutdown_key", "invalid")))
            if not readonly_bootstrap and not service_shutdown and request.cookies.get("rcn-member-session") != local_session:
                return JSONResponse({"detail": "local_session_required"}, status_code=403)
        response = await call_next(request)
        if request.method == "GET" and not request.url.path.startswith(("/local/v1/", "/v1/")):
            response.set_cookie("rcn-member-session", local_session, httponly=True, samesite="strict")
        if request.url.path == "/local/v1/capabilities" and not origin:
            response.set_cookie("rcn-member-session", local_session, httponly=True, samesite="strict")
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.exception_handler(RcnApiError)
    async def api_error(request, exc):
        from .member_doctor import error_detail
        detail = error_detail(exc, stage="center")
        # Preserve a bounded server reason code for existing operation recovery.
        if exc.reason_code and re.fullmatch(r"[a-z][a-z0-9_]{0,100}", exc.reason_code):
            detail["reason_code"] = exc.reason_code
        return JSONResponse({"detail": detail},
                            status_code=exc.status if 400 <= exc.status <= 599 else 503)

    @app.exception_handler(RuntimeError)
    async def member_runtime_error(request, exc):
        from .member_doctor import error_detail
        return JSONResponse({"detail": error_detail(exc)}, status_code=409)

    @app.exception_handler(ValueError)
    async def validation_error(request, exc):
        return JSONResponse({"detail": {"message": "任务数据或本机状态未通过校验",
                             "reason_code": "member_contract_invalid"}}, status_code=422)

    @app.exception_handler(PermissionError)
    async def identity_error(request, exc):
        return JSONResponse({"detail": {"message": "任务包或本机记录属于另一位成员",
                             "reason_code": "member_identity_mismatch"}}, status_code=403)

    @app.get("/local/v1/capabilities")
    def capabilities():
        return {"mode": "member-client", "schema_version": 1, "contribution_supported": True,
                "connection_bundle_import": 1, "member_diagnostics": 1, "self_service_agent_credentials": 1,
                "submission_operation_schema": 1, "instance_id": getattr(app.state, "instance_id", None)}

    @app.post("/local/v1/doctor")
    def doctor(payload: dict = None):
        from .member_doctor import diagnose
        value = payload or {}
        if set(value) - {"repair"} or type(value.get("repair", False)) is not bool:
            raise HTTPException(422, "invalid_diagnostic_options")
        return diagnose(broker, repair=value.get("repair", False))

    @app.post("/local/v1/connection-imports")
    async def connection_import(request: Request):
        from .member_connection_bundle import preview_bundle, MAX_BUNDLE_BYTES
        if request.headers.get("content-type", "").split(";")[0] not in {"application/zip", "application/octet-stream"}:
            raise HTTPException(415, "请选择管理员提供的个人接入 ZIP")
        raw = bytearray()
        async for chunk in request.stream():
            if len(raw) + len(chunk) > MAX_BUNDLE_BYTES:
                raise HTTPException(413, "个人接入包超过大小上限")
            raw.extend(chunk)
        return preview_bundle(broker, bytes(raw))

    @app.get("/local/v1/connection-imports/{import_id}")
    def connection_import_status(import_id: str):
        from .member_connection_bundle import read_import
        return read_import(broker, import_id)

    @app.post("/local/v1/connection-imports/{import_id}/confirm")
    def connection_import_confirm(import_id: str):
        from .member_connection_bundle import confirm_import
        return confirm_import(broker, import_id)

    @app.post("/local/v1/shutdown")
    def shutdown(request: Request):
        key = getattr(app.state, "shutdown_key", None)
        if not key or not secrets.compare_digest(request.headers.get("x-rcn-shutdown", ""), key):
            raise HTTPException(403, "service_owner_required")
        app.state.stop_event.set()
        return {"stopping": True}

    @app.get("/local/v1/session")
    def session():
        return broker.session(refresh=bool(broker.login))

    @app.post("/local/v1/session")
    def login(payload: Login):
        return broker.sign_in(payload)

    @app.delete("/local/v1/session")
    def logout():
        return broker.sign_out()

    @app.post("/local/v1/agent-instructions")
    def agent_instructions(payload: MemberAgentExportRequest):
        return export_member_agent_config(broker, payload.target, payload.agent_id,
            label=payload.label, token=payload.token.get_secret_value() if payload.token else None)

    @app.get("/local/v1/agent-configurations")
    def agent_configurations():
        return list_member_agent_configs(broker)

    @app.delete("/local/v1/agent-configurations/{agent_id}")
    def clear_agent_login(agent_id: UUID):
        return clear_member_agent_login(broker, agent_id)

    @app.post("/local/v1/agent-configurations/{agent_id}/revoke")
    def revoke_agent(agent_id: UUID):
        from .member_agent_config import revoke_member_agent
        return revoke_member_agent(broker, agent_id)

    def contribution_identity(*, offline=False):
        # Revalidate credentials before exposing or changing this original scope.
        # A network outage permits local reads/pause; explicit revocation does not.
        session = broker.session(refresh=True)
        actor = session["actor"]
        if not actor:
            raise HTTPException(401, "请先登录个人账号")
        if (session.get("connection_error") or {}).get("reason_code") == "center_login_required":
            raise HTTPException(403, "个人身份已撤销，请重新连接原中心")
        if broker.login.get("actor") and broker.login["actor"]["actor_id"] != actor["actor_id"]:
            raise HTTPException(403, "原个人身份已变更")
        if not offline and not session["remote_actions_available"]:
            raise HTTPException(503, "中心连接未确认，仅允许本机暂停")
        client = broker.client()
        state = contribution.read()
        contribution._scope(state, client=client, actor_id=actor["actor_id"])
        if ((state.get("actor_id") or not offline)
                and not {"machine_owner", "admin"}.intersection(actor.get("roles", []))):
            raise HTTPException(403, "贡献计算的机主角色已撤销，请联系原中心管理员")
        if session["online"] and state.get("machine_id"):
            try:
                machine = client._request("GET", "/v1/machines/" + state["machine_id"])
            except RcnApiError as exc:
                if not offline or exc.status in {401, 403, 404}:
                    raise
            except OSError:
                if not offline:
                    raise HTTPException(503, "中心连接未确认，仅允许本机暂停") from None
            else:
                owner = (machine.get("policy") or {}).get("owner_user_id") or (machine.get("machine") or {}).get("owner_user_id")
                if owner != actor["actor_id"]:
                    raise HTTPException(403, "原机器所有权已变更")
        return actor, client

    @app.get("/local/v1/contribution")
    def contribution_status():
        with broker.lock:
            actor, client = contribution_identity(offline=True)
            result = contribution.present(contribution.read(), client=client, actor_id=actor["actor_id"])
            result["pending_operations"] = contribution.store.pending(actor_id=actor["actor_id"], center_url=client.base_url.rstrip("/"))
            return result

    @app.get("/local/v1/contribution/operations/{operation_id}")
    def contribution_original(operation_id: str):
        with broker.lock:
            actor, client = contribution_identity(offline=True)
            return contribution.original(operation_id, client=client, actor_id=actor["actor_id"])

    def contribution_mutation(kind, payload):
        with broker.lock:
            pure_pause = kind == "preferences" and {key: value for key, value in payload.items()
                if key not in {"operation_id", "expected_revision"}} == {"paused": True}
            actor, client = contribution_identity(offline=pure_pause)
            marker = f"contribution:{payload.get('operation_id', 'pause')}:{threading.get_ident()}"
            broker.busy.add(marker)
        try:
            return contribution.request(kind, payload, client=client, actor_id=actor["actor_id"])
        finally:
            with broker.lock:
                broker.busy.discard(marker)

    @app.post("/local/v1/contribution/setup")
    def contribution_setup(payload: dict):
        return contribution_mutation("setup", payload)

    @app.post("/local/v1/contribution/preferences")
    def contribution_preferences(payload: dict):
        return contribution_mutation("preferences", payload)

    @app.post("/local/v1/packages")
    async def package(request: Request):
        from .submission_packages import inspect_submission_package
        actor = broker.session()["actor"]
        if not actor:
            raise HTTPException(401, "请先登录个人账号")
        center = broker.login["center_url"]
        if request.headers.get("content-type", "").split(";")[0] not in {"application/zip", "application/octet-stream"}:
            raise HTTPException(415, "请选择 ZIP 任务包")
        filename = unquote(request.headers.get("x-rcn-filename", "任务包.zip"))
        filename = Path(filename.replace("\\", "/")).name[:160]
        length = request.headers.get("content-length")
        if length and (not length.isdigit() or int(length) > MAX_PACKAGE_BYTES):
            raise HTTPException(413, "任务包超过本机导入上限")
        fd, name = tempfile.mkstemp(prefix=".import-", dir=broker.root / "packages")
        temporary = Path(name)
        checksum = hashlib.sha256()
        received = 0
        try:
            with os.fdopen(fd, "wb") as stream:
                async for chunk in request.stream():
                    received += len(chunk)
                    if received > MAX_PACKAGE_BYTES:
                        raise HTTPException(413, "任务包超过本机导入上限")
                    if shutil.disk_usage(broker.root).free < RESERVE_BYTES + len(chunk):
                        raise HTTPException(507, "本机数据盘需要保留 10 GiB 空间")
                    checksum.update(chunk)
                    stream.write(chunk)
                stream.flush()
                os.fsync(stream.fileno())
            manifest = inspect_submission_package(temporary, expected_actor_id=actor["actor_id"])
            identifier = checksum.hexdigest()
            destination = broker.package_path(identifier)
            if destination.exists():
                with destination.open("rb") as existing:
                    if hashlib.file_digest(existing, "sha256").hexdigest() != identifier:
                        raise ValueError("existing task package was changed")
            else:
                os.link(temporary, destination)
            result = {"package_id": identifier, "filename": filename, "preview": broker.preview(manifest)}
            with broker.lock:
                if not broker.actor or broker.actor["actor_id"] != actor["actor_id"] or broker.login["center_url"] != center:
                    raise HTTPException(409, "个人身份已改变，请在当前账号重新选择任务包")
                previous = [_read_json(path) for path in (broker.root / "operations").glob("*.json")]
                matches = [value for value in previous if value.get("package_id") == identifier
                           and value.get("actor_id") == actor["actor_id"] and value.get("center_url") == center]
                if matches:
                    original = max(matches, key=lambda value: value["created_at"])
                    result.update(operation_id=original["operation_id"], operation=broker.present(original))
            return result
        finally:
            temporary.unlink(missing_ok=True)

    @app.get("/local/v1/operations")
    def operations():
        actor = broker.session()["actor"]
        if not actor:
            raise HTTPException(401, "请先登录个人账号")
        selected = []
        for path in sorted((broker.root / "operations").glob("*.json"), reverse=True):
            value = _read_json(path)
            if value.get("actor_id") == actor["actor_id"] and value.get("center_url") == broker.login["center_url"]:
                selected.append(broker.present(value))
        return {"operations": sorted(selected, key=lambda item: item["created_at"], reverse=True)}

    @app.put("/local/v1/operations/{operation_id}")
    def plan(operation_id: str, payload: PlanOptions):
        return broker.plan(operation_id, payload)

    @app.get("/local/v1/operations/{operation_id}")
    def operation(operation_id: str):
        return broker.refresh(operation_id)

    @app.post("/local/v1/operations/{operation_id}/confirm")
    def confirm(operation_id: str):
        return broker.confirm(operation_id)

    @app.post("/local/v1/operations/{operation_id}/upload")
    def upload(operation_id: str):
        return broker.start_transfer(operation_id)

    @app.post("/local/v1/operations/{operation_id}/collection/pause")
    def pause_collection(operation_id: str):
        return broker.pause_collection(operation_id)

    @app.post("/local/v1/operations/{operation_id}/collect")
    def collect(operation_id: str):
        return broker.start_transfer(operation_id, collect=True)

    @app.post("/local/v1/operations/{operation_id}/rerun")
    def rerun(operation_id: str, payload: RerunOptions):
        if _uuid(payload.operation_id) == _uuid(operation_id):
            raise HTTPException(409, "明确重算需要新的提交编号")
        previous = broker.read_operation(operation_id)
        options = {key: item for key, item in previous["plan_options"].items()
                   if key in {"requested_unit_count", "estimated_seconds_per_item"}}
        return broker.plan(payload.operation_id, PlanOptions(package_id=previous["package_id"], **options))

    @app.get("/v1/help/public")
    def public_help_index():
        return help_catalog.list_public()

    @app.get("/v1/help/public/{slug}")
    def public_help_article(slug: str, format: str = "html"):
        article = help_catalog.public_markdown(slug) if format == "markdown" else help_catalog.public(slug)
        if article is None:
            raise HTTPException(404, "help article not found")
        return article

    @app.get("/v1/help/catalog")
    def member_help_catalog():
        # Public guidance follows the installed client, including when its
        # center is older or unavailable. Only the center authorizes protected
        # entries; never derive those from packaged content or cached roles.
        protected = []
        if broker.login:
            try:
                remote = broker.client()._request("GET", "/v1/help/catalog")
                protected = remote.get("protected", [])
            except RcnApiError:
                pass
        return {"public": help_catalog.list_public(), "protected": protected}

    # Only public, read-only observation calls and explicit owner/project actions.
    # Submission is exclusively the data-package operation protocol above.
    allowed_reads = re.compile(r"^/v1/(?:me(?:/(?:enrollments|submission-policy|compute-credits|credits))?|overview|dispatcher/status|operations/(?:summary|metrics|insights)|execution-runtime|profiles|projects|settings/features|jobs(?:/[A-Za-z0-9_.-]+(?:/(?:artifact-manifests|placement-diagnostics|origin-import-receipt|events))?)?|machines(?:/[A-Za-z0-9_.-]+(?:/(?:policy|commands|admission-status))?)?|help(?:/[A-Za-z0-9_./-]+)?|project-registrations|origin-adapters|origin-transfer|events)$")
    allowed_writes = re.compile(r"^/v1/(?:project-registrations|me/enrollments|machines/[A-Za-z0-9_.-]+/policy|jobs/[A-Za-z0-9_.-]+/(?:cancel|retry))$")

    @app.api_route("/v1/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
    async def proxy(path: str, request: Request):
        target = "/v1/" + path
        allowed = allowed_reads if request.method == "GET" else allowed_writes
        if not allowed.fullmatch(target) or (request.method == "DELETE"):
            raise HTTPException(403, "member_proxy_route_not_allowed")
        suffix = "?" + request.url.query if request.url.query else ""
        client = broker.client()
        if target == "/v1/events":
            if request.method != "GET":
                raise HTTPException(405, "read only")
            def stream():
                transfer = broker.transfer_factory(client)
                headers = {"Accept": "text/event-stream"}
                if request.headers.get("last-event-id"):
                    headers["Last-Event-ID"] = request.headers["last-event-id"]
                with transfer._open(target + suffix, headers=headers) as response:
                    while not getattr(app.state, "stop_event", threading.Event()).is_set():
                        line = response.readline()
                        if not line:
                            break
                        yield line
            return StreamingResponse(stream(), media_type="text/event-stream")
        payload = None
        if request.method != "GET":
            raw = await request.body()
            if len(raw) > 2 * 1024**2:
                raise HTTPException(413, "metadata exceeds limit")
            payload = json.loads(raw) if raw else None
        import asyncio
        return await asyncio.to_thread(client._request, request.method, target + suffix, payload)

    @app.get("/{path:path}")
    def page(path: str):
        from importlib.resources import files
        root = static_root or Path(str(files("research_compute_network") / "web_dist"))
        root = Path(root).absolute()
        target = root / path
        try:
            target.resolve().relative_to(root.resolve())
        except ValueError:
            raise HTTPException(404, "unknown page") from None
        if target.is_file():
            return FileResponse(target)
        if Path(path).suffix:
            raise HTTPException(404, "unknown asset")
        return FileResponse(root / "index.html")

    return app
