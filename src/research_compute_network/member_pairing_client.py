"""One durable, secret-free public journal over a CurrentUser DPAPI pairing."""
from __future__ import annotations

import hashlib
import platform
import secrets
from typing import Any, Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Body, HTTPException
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from . import member_registration as storage
from .client import RcnApiError
from .member_client_credentials import PersonalCredentialStore


class LocalPairingRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    center_url: str
    name: str = Field(min_length=1, max_length=80)
    device_name: str = Field(default_factory=platform.node, min_length=1, max_length=80)
    agent: Literal["codex", "claude", "dsh", "generic"] = "generic"
    label: str = Field(default="RCN Agent", min_length=1, max_length=80)
    pairing_id: UUID | None = None

    @field_validator("name", "device_name", "label")
    @classmethod
    def clean_label(cls, value):
        if value != value.strip() or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("invalid pairing label")
        return value


def _fail(code, status=409):
    raise HTTPException(status, {"reason_code": code})


def _paths(broker):
    root = broker.root / "member-pairings"
    storage._private_directory(root)
    return root, root / "current.json"


def _resume_control(broker, *, paused=None):
    """Caller holds the pairing root's cross-process writer lock."""
    from .member_client import _read_json, _write_json
    path = broker.root / "member-pairings" / "resume-control.json"
    storage._check_private_file(path)
    value = _read_json(path) if path.exists() else {"schema_version": 1, "paused": False}
    if value.get("schema_version") != 1 or type(value.get("paused")) is not bool:
        _fail("member_pairing_resume_state_invalid")
    if paused is not None and value["paused"] != paused:
        value = {"schema_version": 1, "paused": paused}
        _write_json(path, value)
    return value["paused"]


def pause_pairing_resume(broker):
    """Sign-out fences queued status reads without deleting the original UUID."""
    root = broker.root / "member-pairings"
    if not root.exists():
        return
    with storage._exclusive(root):
        _resume_control(broker, paused=True)


def _load(broker, pairing_id=None):
    from .member_client import _read_json
    root, pointer = _paths(broker)
    if pairing_id is None:
        if not pointer.exists():
            return None, None
        pairing_id = _read_json(pointer)["pairing_id"]
    pairing_id = str(UUID(str(pairing_id)))
    directory = root / pairing_id
    storage._unlinked(directory)
    if not directory.exists():
        return None, None
    path = directory / "pairing.json"
    storage._check_private_file(path)
    credential = PersonalCredentialStore(directory / "credentials").load()
    original = (credential.get("actor") or {}).get("pairing_registration") if credential else None
    if not path.exists():
        if not isinstance(original, dict):
            return None, None
        value = original
        _save(broker, value)
    else:
        value = _read_json(path)
    if (not isinstance(original, dict) or original.get("pairing_id") != pairing_id
            or any(original.get(k) != value.get(k) for k in (
                "pairing_id", "center_url", "connection_reference", "name", "device_name", "agent", "label", "agent_id", "token_hash"))
            or credential["center_url"] != value["center_url"]
            or hashlib.sha256(credential["token"].encode()).hexdigest() != value["token_hash"]):
        _fail("member_pairing_local_binding_changed")
    return value, credential


def _save(broker, value):
    from .member_client import _write_json
    _write_json(broker.root / "member-pairings" / value["pairing_id"] / "pairing.json", value)


def _present(value):
    if value is None:
        return {"schema_version": 1, "state": "not_started", "secrets_included": False}
    return {"schema_version": 1, **{k: value.get(k) for k in (
        "pairing_id", "center_url", "name", "device_name", "agent", "label", "agent_id",
        "state", "phase", "short_code", "expires_at", "member_id", "credential_id",
        "agent_configuration", "doctor", "doctor_state", "resume_paused")}, "secrets_included": False,
        "poll_interval_seconds": 5, "resume_same_pairing": True}


def _connection_reference(broker, center):
    """Keep an existing pinned connection; never turn a pairing into a switch."""
    from .member_client_connection import load_spec, https_center
    if getattr(broker, "credential_error", None):
        _fail("member_pairing_existing_login_unreadable")
    if broker.root.parent.name == "agents" or (broker.root / "agent-profile.json").exists():
        _fail("member_pairing_personal_root_required")
    loaded = load_spec(broker.root)
    if loaded:
        spec, _ = loaded
        if spec.mode != "https" or https_center(spec.https_url) != center:
            _fail("member_pairing_existing_center_conflict")
    if broker.login:
        prior = broker.login["center_url"]
        if prior.startswith("rcn-managed://"):
            if not loaded:
                _fail("member_pairing_existing_center_conflict")
            return prior
        if https_center(prior) != center:
            _fail("member_pairing_existing_center_conflict")
    return center


def start_pairing(broker, payload: LocalPairingRequest):
    from .member_client import _center, _write_json
    center = _center(payload.center_url)
    with broker.lock:
        root, pointer = _paths(broker)
        with storage._exclusive(root):
            connection = _connection_reference(broker, center)
            if payload.pairing_id:
                identifier = str(payload.pairing_id)
            elif pointer.exists():
                from .member_client import _read_json
                identifier = str(UUID(_read_json(pointer)["pairing_id"]))
            else:
                identifier = str(uuid4())
            prior, credential = _load(broker, identifier) if (root / identifier).exists() else (None, None)
            expected = {"center_url": center, "connection_reference": connection,
                "name": payload.name, "device_name": payload.device_name, "agent": payload.agent, "label": payload.label}
            if prior:
                if any(prior.get(k) != v for k, v in expected.items()):
                    _fail("member_pairing_local_content_conflict")
                value = prior
            else:
                # The chosen UUID is durable before any credential or network
                # action; interruption can only resume this same request.
                _write_json(pointer, {"pairing_id": identifier})
                directory = root / identifier
                storage._private_directory(directory)
                store = PersonalCredentialStore(directory / "credentials")
                credential = store.load()
                if credential:
                    # Recover the encrypted original after a crash before journal publication.
                    original = (credential.get("actor") or {}).get("pairing_registration")
                    if not isinstance(original, dict) or any(original.get(k) != v for k, v in expected.items()):
                        _fail("member_pairing_local_binding_changed")
                    value = original
                else:
                    secret = secrets.token_urlsafe(32)
                    value = {"schema_version": 1, "pairing_id": identifier, **expected,
                        "agent_id": str(uuid4()), "token_hash": hashlib.sha256(secret.encode()).hexdigest(),
                        "state": "pending", "phase": "prepared"}
                    store.save(center_url=center, token=secret,
                        actor={"actor_id": "pending-member-pairing", "pairing_registration": value})
                    credential = store.load()
                _save(broker, value)
                _write_json(pointer, {"pairing_id": identifier})
            # The exact original credential is encrypted and durable before PUT.
            _resume_control(broker, paused=False)
            broker._api(value["connection_reference"], None)._request("PUT",
                "/v1/member-pairings/" + value["pairing_id"],
                {key: value[key] for key in ("name", "device_name", "token_hash")})
    return pairing_status(broker, value["pairing_id"])


def pairing_status(broker, pairing_id=None, *, retry_doctor=False, resume=False):
    with broker.lock:
        root, _ = _paths(broker)
        with storage._exclusive(root):
            value, credential = _load(broker, pairing_id)
            if value is None:
                return _present(None)
            if resume:
                _resume_control(broker, paused=False)
            elif _resume_control(broker):
                return _present({**value, "phase": "resume_paused", "resume_paused": True,
                    "agent_configuration": None})
            # Even a completed local receipt is checked for center revocation.
            api = broker._api(value["connection_reference"], credential["token"])
            route = "/v1/member-pairings/" + value["pairing_id"]
            try:
                response = api._request("GET", route)
            except RcnApiError as exc:
                if exc.status not in {401, 404} or value["phase"] != "prepared":
                    raise
                # The first PUT may never have reached the center. Only an
                # unobserved original request can be resent after an absent
                # read (the center deliberately hides absence behind 401).
                broker._api(value["connection_reference"], None)._request("PUT", route,
                    {key: value[key] for key in ("name", "device_name", "token_hash")})
                response = api._request("GET", route)
            if (not isinstance(response, dict) or response.get("pairing_id") != value["pairing_id"]
                    or response.get("name") != value["name"] or response.get("device_name") != value["device_name"]
                    or response.get("state") not in {"pending", "approved", "rejected", "expired", "revoked"}
                    or not isinstance(response.get("short_code"), str)
                    or value.get("short_code") not in {None, response["short_code"]}):
                _fail("member_pairing_center_binding_changed")
            value = {**value, **{k: response.get(k) for k in (
                "state", "short_code", "expires_at", "member_id", "credential_id")}, "phase": "observed"}
            _save(broker, value)
            if value["state"] != "approved":
                return _present(value)
            # /me is the authority before saving a personal login. Preserve all
            # task, download, machine-contribution and pause records in place.
            actor = api.current_actor()
            if (not isinstance(actor, dict) or actor.get("actor_id") != value["member_id"]
                    or actor.get("credential_id") != value["credential_id"]
                    or set(actor.get("scopes", [])) != {"api"}):
                _fail("member_pairing_identity_unconfirmed")
            connection = _connection_reference(broker, value["center_url"])
            if connection != value["connection_reference"]:
                _fail("member_pairing_existing_center_conflict")
            if broker.login:
                prior_actor = (broker.login.get("actor") or {}).get("actor_id")
                if prior_actor != actor["actor_id"]:
                    _fail("member_pairing_existing_identity_conflict")
            if broker.busy:
                _fail("member_pairing_transfer_in_progress")
            if not broker.login or broker.login["token"] != credential["token"]:
                broker.credentials.save(center_url=connection, token=credential["token"], actor=actor)
                broker.login = {"center_url": connection, "token": credential["token"], "actor": actor}
                broker.actor = actor
                broker.auth_generation += 1
            broker.online, broker.connection_error, broker.credential_error = True, None, None
            value["phase"] = "personal_login_saved"
            _save(broker, value)
            if not value.get("agent_configuration"):
                from .member_agent_config import export_member_agent_config
                value["agent_configuration"] = export_member_agent_config(broker, value["agent"],
                    value["agent_id"], label=value["label"])
                value["phase"] = "agent_configured"
                _save(broker, value)
            doctor_state = value.get("doctor_state")
            doctor_passed = doctor_state == "completed" and (value.get("doctor") or {}).get("ok") is True
            if (doctor_state in {None, "started"} or (retry_doctor and not doctor_passed)):
                value["doctor_state"] = "started"
                _save(broker, value)
                from .member_doctor import diagnose, error_detail
                try:
                    value["doctor"] = diagnose(broker)
                    value["doctor_state"] = "completed"
                except Exception as exc:
                    # A failed diagnostic is a receipt, not a reason to run a
                    # full installation/ACL probe on every five-second poll.
                    value["doctor"] = {"schema_version": 1, "ok": False,
                        "diagnostic_id": str(uuid4()), "checks": [error_detail(exc)],
                        "secrets_included": False, "compute_started": False}
                    value["doctor_state"] = "failed"
                _save(broker, value)
            value["phase"] = "connected"
            _save(broker, value)
            return _present(value)


def build_local_pairing_router(broker):
    router = APIRouter()

    @router.post("/local/v1/member-pairing")
    def start(payload: Any = Body(...)):
        try:
            value = LocalPairingRequest.model_validate(payload)
        except ValidationError:
            _fail("invalid_member_pairing_request", 422)
        return start_pairing(broker, value)

    @router.get("/local/v1/member-pairing")
    def status():
        return pairing_status(broker)

    @router.get("/local/v1/member-pairing/{pairing_id}")
    def original(pairing_id: UUID):
        return pairing_status(broker, pairing_id)

    @router.post("/local/v1/member-pairing/{pairing_id}/doctor")
    def retry_diagnostic(pairing_id: UUID):
        return pairing_status(broker, pairing_id, retry_doctor=True, resume=True)

    @router.post("/local/v1/member-pairing/{pairing_id}/resume")
    def resume_original(pairing_id: UUID):
        return pairing_status(broker, pairing_id, retry_doctor=True, resume=True)

    @router.post("/local/v1/member-pairing/group")
    def group(payload: Any = Body(...)):
        from .member_client import _center
        if not isinstance(payload, dict) or set(payload) != {"center_url"} or not isinstance(payload["center_url"], str):
            _fail("invalid_member_pairing_group_request", 422)
        center = _center(payload["center_url"])
        with broker.lock:
            reference = _connection_reference(broker, center)
            return broker._api(reference, None)._request("GET", "/v1/member-pairing-info")

    return router
