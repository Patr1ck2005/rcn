"""Member-owned, resumable optional compute setup from a private invitation.

Public installer state, personal login and device registration stay separate.
All Windows privileged actions use the reviewed native identity helpers.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import threading
from uuid import uuid4

from . import member_registration as storage
from .member_admission import ComputePreferences
from .member_client import _read_json, _write_json
from .member_enrollment import MemberInvitation
from .client import RcnApiError


class _PolicyConflict(RuntimeError):
    pass


class _PolicyUnknown(RcnApiError):
    def __init__(self, result=None):
        super().__init__(0, "original center policy result requires recovery", reason_code="member_compute_policy_result_unknown")
        self.result = result


def _preferences(value):
    data = {key: item for key, item in value.items() if key in ComputePreferences.model_fields}
    return ComputePreferences.model_validate(data).model_dump(mode="json")


class ContributionManager:
    def __init__(self, root):
        self.root = Path(root) / "contribution"
        storage._private_directory(self.root)
        from .member_contribution_operations import ContributionStore
        self.store = ContributionStore(self.root, initial=self._initial_state)
        self.path = self.store.path
        self.mutations = threading.RLock()
        self.intent_lock = threading.Lock()
        self.pause_generation = 0

    def read(self):
        return self.store.read()

    @staticmethod
    def _initial_state():
        from .member_execution_identity import member_root
        root_uuid = str(uuid4())
        return {"schema_version": 1, "root_uuid": root_uuid, "phase": "not-configured",
                "work_root": str(member_root(root_uuid) / "worker"), "paused": False}

    def save(self, state, **updates):
        return self.store.save(state, **updates)

    def _scope(self, state, *, client, actor_id, center_url=None):
        if state.get("actor_id") and state["actor_id"] != actor_id:
            raise PermissionError("contribution_owned_by_another_member")
        center = state.get("center_url")
        if not center and state.get("actor_id"):
            # Import legacy scope only from its original owner-private invite.
            center = MemberInvitation.model_validate(_read_json(self.root / "invitation.json")).control_plane_url.rstrip("/")
        target = center_url or (client.base_url if client else None)
        if center and target and center != target.rstrip("/"):
            raise PermissionError("contribution_owned_by_another_center")

    def present(self, state, *, client=None, actor_id=None):
        if state.get("actor_id") and actor_id and state["actor_id"] != actor_id:
            raise PermissionError("contribution_owned_by_another_member")
        if client and actor_id:
            self._scope(state, client=client, actor_id=actor_id)
        result = {key: value for key, value in state.items() if key in {
            "phase", "work_root", "machine_id", "preferences", "paused", "error", "runtime_version", "policy_sync_pending"}}
        result["configured"] = state["phase"] == "configured"
        result["status"] = state["phase"]
        result["revision"] = state["revision"]
        result["contribution_id"] = state["root_uuid"]
        if "identity" in state:
            control = _read_json(Path(state["identity"]["member_root"]) / "owner-control/state.json")
            result["paused"] = control["paused"]
            result["preferences"] = {**state.get("preferences", {}), "paused": control["paused"]}
        if state.get("machine_id") and client:
            try:
                from .member_admission_client import member_admission_status
                result["admission"] = member_admission_status(self.root / "invitation.json",
                    state_root=Path(state["registration_root"]), expected_invitation_sha256=state["invitation_sha256"])
            except Exception:
                result["admission"] = {"state": "connection-unconfirmed", "grants_execution": False}
        return result

    def setup(self, payload, *, client, actor_id):
        if payload.get("accepted") is not True:
            raise ValueError("explicit_member_compute_consent_required")
        invitation_value = payload.get("invite")
        if isinstance(invitation_value, str):
            invitation_value = storage._json_document(invitation_value.encode("utf-8"))
        invite = MemberInvitation.model_validate(invitation_value)
        if not invite.worker or invite.owner_user_id != actor_id:
            raise PermissionError("member_compute_invitation_owner_mismatch")
        if invite.control_plane_url.rstrip("/") != client.base_url:
            raise ValueError("member_compute_invitation_center_mismatch")
        from .member_release_catalog import current_member_release, approved_release_descriptor
        release = current_member_release().require_configured()
        advertised = client._request("GET", "/v1/member-release")
        approved = approved_release_descriptor({key: advertised[key] for key in ("runtime_version", "archive_sha256")})
        if approved != release:
            raise ValueError("member_installer_and_center_release_differ")
        preferences = _preferences(payload)
        if payload.get("reserved_cpu_percent", 25) < 25 or payload.get("min_free_disk_mb", 10240) != 10240:
            raise ValueError("member_compute_reserve_below_contract")
        state = self.read()
        if payload.get("work_root") not in {"", None, state["work_root"]}:
            raise ValueError("member_compute_use_displayed_managed_directory")
        invitation_path = self.root / "invitation.json"
        raw = storage._json_bytes(invitation_value)
        sha = hashlib.sha256(raw).hexdigest()
        if state.get("invitation_sha256"):
            if (state["invitation_sha256"] != sha or state["actor_id"] != actor_id
                    or state["preferences"] != preferences):
                raise ValueError("member_compute_original_setup_changed")
            if state["phase"] == "configured":
                return self.present(state, client=client, actor_id=actor_id)
        else:
            storage._publish(invitation_path, raw)
            state = self.save(state, actor_id=actor_id, center_url=client.base_url.rstrip("/"), invitation_sha256=sha,
                              preferences=preferences, phase="identity", error=None)
        try:
            from .member_execution_identity import install_identity, provision_runtime
            identity = install_identity(state["root_uuid"], state_root=self.root / "native", accept_install=True)
            state = self.save(state, identity=identity, phase="dependencies")
            source = Path(sys.executable).parent.parent
            manifest = json.loads((source.parent / "member-software-release.json").read_text(encoding="utf-8"))
            if manifest["member_runtime"]["runtime_version"] != release.runtime_version:
                raise ValueError("member_public_runtime_catalog_mismatch")
            provision_runtime(identity, source, file_hashes=manifest["runtime_files"], state_root=self.root / "native")
            state = self.save(state, phase="registration")
            registration_root = self.root / "registration"
            registered = storage.register_member(invitation_path, state_root=registration_root,
                expected_invitation_sha256=sha)
            state = self.save(state, registration_root=str(registration_root), machine_id=registered["machine_id"], phase="transport")
            from .member_openssh_prerequisite import ensure_member_openssh
            ensure_member_openssh(state_root=registration_root, accept_supply=True)
            from .member_transport_client import bind_member_transport
            bind_member_transport(invitation_path, state_root=registration_root, expected_invitation_sha256=sha)
            from .member_worker_root import prepare_worker_root
            prepare_worker_root(invitation_path, state_root=registration_root, expected_invitation_sha256=sha,
                worker_root=Path(identity["worker_root"]), root_uuid_override=state["root_uuid"])
            from .member_execution_identity import finalize_worker_access
            finalize_worker_access(identity, state_root=self.root / "native")
            from . import member_admission_client as admission
            context = admission._context(invitation_path, registration_root, sha)
            offer = admission._offer(admission._request(context, "offer"), context)
            if not offer:
                raise ValueError("member_invitation_has_no_compute_offer")
            admission.configure_member_compute(invitation_path, state_root=registration_root,
                expected_invitation_sha256=sha, preferences=preferences,
                confirm_offer_sha256=offer["offer_sha256"], accept_compute=True)
            state = self.save(state, phase="runtime")
            from .member_runtime import install_member_runtime
            runtime = install_member_runtime(invitation_path, state_root=registration_root,
                expected_invitation_sha256=sha, runtime_archive=release.archive_path, accept_runtime=True,
                release_descriptor=release, execution_identity=identity)
            from .member_supervisor_startup import start_member_supervisor
            start_member_supervisor(runtime, accept_startup=True)
            state = self.save(state, runtime_version=runtime["runtime_version"], phase="connecting")
            from .member_ssh_client import connect_member_worker
            connect_member_worker(invitation_path, state_root=registration_root, expected_invitation_sha256=sha,
                accept_connection=True, execution_identity=identity, release_descriptor=release)
            state = self.save(state, phase="configured", error=None)
            return self.present(state, client=client, actor_id=actor_id)
        except Exception:
            self.save(state, error={"reason_code": "member_compute_setup_interrupted",
                "message": "接入未完成，原身份已保留；恢复时继续此邀请"})
            raise

    def preferences(self, payload, *, client, actor_id):
        state = self.read()
        if state.get("actor_id") != actor_id or not state.get("identity"):
            raise PermissionError("member_compute_owner_required")
        self._scope(state, client=client, actor_id=actor_id)
        explicit_pause = payload.get("paused")
        if "paused" in payload and type(explicit_pause) is not bool:
            raise ValueError("member_compute_pause_invalid")
        generation = self.store.pause_intent("paused" in payload)
        if explicit_pause is True:
            from .member_execution_identity import set_owner_pause
            set_owner_pause(state["identity"], True)
        with self.mutations:
            return self._preferences(payload, client=client, actor_id=actor_id, generation=generation)

    def _preferences(self, payload, *, client, actor_id, generation):
        state = self.read()
        self._scope(state, client=client, actor_id=actor_id)
        if state.get("actor_id") != actor_id or not state.get("identity"):
            raise PermissionError("member_compute_owner_required")
        from .member_execution_identity import set_owner_pause
        control = _read_json(Path(state["identity"]["member_root"]) / "owner-control/state.json")
        requested_pause = payload.get("paused", control["paused"])
        if type(requested_pause) is not bool:
            raise ValueError("member_compute_pause_invalid")
        if requested_pause:
            set_owner_pause(state["identity"], True)
        preferences = _preferences({**state["preferences"], **payload})
        if payload.get("reserved_cpu_percent", 25) < 25 or payload.get("min_free_disk_mb", 10240) != 10240:
            raise ValueError("member_compute_reserve_below_contract")
        identifier = self.store.active.get()
        pure_pause = payload == {"paused": True}
        try:
            if identifier:
                if pure_pause:
                    self._require_metadata_receipts(client)
                revision_hash, policy = self._policy_snapshot(client, state["machine_id"], actor_id)
            else:
                # Legacy direct-call oracle; public mutations always have a claim.
                policy = client._request("GET", "/v1/machines/" + state["machine_id"])["policy"]
                revision_hash = None
        except Exception:
            if pure_pause:
                state = self.save(self.read(), paused=True, policy_sync_pending=True,
                                  completed_operation_id=identifier)
                return self.present(state, actor_id=actor_id)
            raise
        if not pure_pause:
            policy.update({key: preferences[key] for key in ("max_cpus", "max_memory_mb", "memory_reserve_mb", "timezone", "weekly_windows") if key in policy})
        current = _read_json(Path(state["identity"]["member_root"]) / "owner-control/state.json")
        fresh_resume = payload.get("paused") is False and generation == self.read().get("pause_generation", 0)
        requested_pause = (not fresh_resume if "paused" in payload else current["paused"])
        policy["owner_mode"] = "paused" if requested_pause else "open"
        if not pure_pause:
            policy.update(shared_machine=True, cpu_reserve_percent=25)
        try:
            if identifier:
                try:
                    self._send_policy(client, identifier, identifier, state["machine_id"], policy, revision_hash, generation)
                except _PolicyConflict:
                    if not pure_pause:
                        raise
                    # Only an explicit no-effect CAS rejection permits a child.
                    # A child changes only owner_mode on a fresh exact snapshot.
                    from uuid import UUID, uuid5
                    revision_hash, policy = self._policy_snapshot(client, state["machine_id"], actor_id)
                    policy["owner_mode"] = "paused"
                    child = str(uuid5(UUID(identifier), revision_hash))
                    self._send_policy(client, identifier, child, state["machine_id"], policy, revision_hash, generation)
            else:
                client._request("PUT", "/v1/machines/" + state["machine_id"] + "/policy", policy)
        except _PolicyConflict:
            if pure_pause:
                self.save(self.read(), paused=True, policy_sync_pending=True)
            raise
        except Exception:
            if pure_pause:
                state = self.save(self.read(), paused=True, policy_sync_pending=True)
                if identifier:
                    raise _PolicyUnknown(self.present(state, actor_id=actor_id)) from None
                return self.present(state, actor_id=actor_id)
            raise
        if fresh_resume:
            self.store.resume_if_current(generation, lambda: set_owner_pause(state["identity"], False))
        current = _read_json(Path(state["identity"]["member_root"]) / "owner-control/state.json")
        latest = self.read()
        newer_pause = latest.get("pause_generation", 0) != generation
        updates = {"policy_sync_pending": False, "completed_operation_id": identifier} if not newer_pause else {}
        state = self.save(latest, preferences=preferences, paused=current["paused"],
                          preserve_operation_markers=newer_pause, **updates)
        return self.present(state, client=client, actor_id=actor_id)

    @staticmethod
    def _policy_snapshot(client, machine_id, actor_id):
        import re
        from .models import MachinePolicy
        snapshot = client._request("GET", "/v1/machines/" + machine_id + "/policy-revision")
        if (not isinstance(snapshot, dict) or snapshot.get("machine_id") != machine_id
                or not re.fullmatch("[a-f0-9]{64}", snapshot.get("revision_hash", ""))):
            raise ValueError("member_compute_policy_snapshot_invalid")
        policy = MachinePolicy.model_validate(snapshot["policy"]).model_dump(mode="json")
        if policy["machine_id"] != machine_id or policy["owner_user_id"] != actor_id:
            raise PermissionError("member_compute_original_policy_owner_changed")
        return snapshot["revision_hash"], policy

    def _send_policy(self, client, parent, request_id, machine_id, policy, revision_hash, generation):
        self.store.remote(parent, policy, generation, request_id=request_id, revision_hash=revision_hash)
        try:
            client._request("PUT", "/v1/machines/" + machine_id + "/policy",
                {**policy, "expected_policy_payload_sha256": revision_hash}, request_id=request_id)
        except RcnApiError as exc:
            if exc.status == 409 and exc.reason_code == "machine_policy_revision_conflict":
                self.store.remote_rejected(parent, request_id)
                raise _PolicyConflict() from None
            # An uncertain delivery is resolved only through this exact receipt.
        except Exception:
            pass
        try:
            self._center_receipt(client, request_id, machine_id, policy)
        except Exception:
            raise _PolicyUnknown() from None

    @staticmethod
    def _require_metadata_receipts(client):
        from fastapi import HTTPException
        from .client import RcnApiError
        try:
            advertised = client._request("GET", "/v1/execution-runtime")
        except RcnApiError as exc:
            if exc.status != 404:
                raise
            advertised = None
        if (not isinstance(advertised, dict) or type(advertised.get("metadata_operation_schema")) is not int or advertised["metadata_operation_schema"] < 1
                or type(advertised.get("machine_policy_cas_schema")) is not int or advertised["machine_policy_cas_schema"] < 1):
            raise HTTPException(409, {"reason_code": "member_compute_center_upgrade_required_metadata_operations",
                "message": "中心尚不支持贡献偏好的原回执和并发策略保护，请管理员升级中心后再修改；本机暂停仍可使用。"})

    @staticmethod
    def _center_receipt(client, identifier, machine_id, policy):
        from .models import MachinePolicy
        receipt = client._request("GET", "/v1/metadata-operations/" + identifier)
        if (not isinstance(receipt, dict) or receipt.get("request_id") != identifier
                or receipt.get("kind") != "machine_policy" or receipt.get("subject_id") != machine_id
                or receipt.get("state") != "completed" or not isinstance(receipt.get("result"), dict)
                or MachinePolicy.model_validate(receipt["result"]).model_dump(mode="json", exclude={"updated_at"}) != MachinePolicy.model_validate(policy).model_dump(mode="json", exclude={"updated_at"})):
            raise ValueError("member_compute_original_center_receipt_mismatch")
        return receipt["result"]

    def request(self, kind, payload, *, client, actor_id):
        """Claim once, then execute outside SQLite. Replays only read receipts."""
        from fastapi import HTTPException
        request = dict(payload)
        identifier = request.pop("operation_id", None)
        expected_revision = request.pop("expected_revision", None)
        allowed = set(ComputePreferences.model_fields) | {"paused", "reserved_cpu_percent", "min_free_disk_mb"} | ({"accepted", "invite", "work_root"} if kind == "setup" else set())
        if set(request) - allowed:
            raise ValueError("member_compute_unexpected_request_fields")
        state = self.read()
        self._scope(state, client=client, actor_id=actor_id)
        if kind == "setup":
            raw = request.get("invite")
            if isinstance(raw, str):
                raw = storage._json_document(raw.encode("utf-8"))
            invite = MemberInvitation.model_validate(raw)
            if not invite.worker or invite.owner_user_id != actor_id or invite.control_plane_url.rstrip("/") != client.base_url.rstrip("/"):
                raise PermissionError("member_compute_invitation_scope_mismatch")
            if request.get("accepted") is not True or request.get("work_root") not in {None, "", state["work_root"]}:
                raise ValueError("member_compute_explicit_original_setup_required")
            _preferences(request)
            machine_id = invite.machine_id
            if state.get("machine_id") and state["machine_id"] != machine_id:
                raise PermissionError("member_compute_original_machine_changed")
        elif kind == "preferences" and state.get("machine_id") and state.get("identity"):
            machine_id = state["machine_id"]
        else:
            raise HTTPException(409, "contribution is not configured")
        if (request.get("reserved_cpu_percent", 25) < 25 or request.get("min_free_disk_mb", 10240) != 10240
                or "paused" in request and type(request["paused"]) is not bool):
            raise ValueError("member_compute_preferences_contract_invalid")
        # Preserve the original offline pause-only local contract. It cannot
        # resume anything, and its deterministic ID is tied to the observed state.
        if identifier is None and kind == "preferences" and request == {"paused": True}:
            from uuid import uuid5, NAMESPACE_URL
            expected_revision = state["revision"]
            identifier = str(uuid5(NAMESPACE_URL, f"rcn-local-pause:{actor_id}:{client.base_url}:{state['root_uuid']}:{expected_revision}"))
        if kind == "preferences" and request != {"paused": True} and expected_revision == state["revision"]:
            # Detect support before a new claim/effect; known original results
            # remain readable even if the center later becomes unavailable.
            try:
                self.store.get(identifier, actor_id=actor_id, center_url=client.base_url.rstrip("/"))
            except HTTPException as exc:
                if exc.status_code != 404:
                    raise
                self._require_metadata_receipts(client)
        claimed, receipt = self.store.claim(identifier, actor_id=actor_id,
            center_url=client.base_url.rstrip("/"), kind=kind, machine_id=machine_id,
            payload=request, expected_revision=expected_revision)
        if not claimed:
            return receipt
        with self.store.executing(identifier):
            try:
                result = getattr(self, kind)(request, client=client, actor_id=actor_id)
                return self.store.complete(identifier, result)
            except _PolicyConflict:
                return self.store.failed(identifier, self.present(self.read(), actor_id=actor_id))
            except BaseException as exc:
                self.store.unknown(identifier, result=exc.result if isinstance(exc, _PolicyUnknown) else None)
                raise

    def original(self, identifier, *, client, actor_id):
        state = self.read()
        self._scope(state, client=client, actor_id=actor_id)
        receipt = self.store.get(identifier, actor_id=actor_id, center_url=client.base_url.rstrip("/"))
        if state.get("machine_id") and state["machine_id"] != receipt["operation"]["machine_id"]:
            raise PermissionError("contribution_operation_machine_changed")
        if receipt["operation"]["status"] in {"completed", "failed"}:
            return receipt
        if (state.get("completed_operation_id") == identifier
                and state.get("phase") == "configured" and state.get("machine_id") == receipt["operation"]["machine_id"]):
            return self.store.complete(identifier, self.present(state, client=client, actor_id=actor_id), recovered=True)
        if receipt["operation"]["status"] == "unknown" and receipt["operation"]["kind"] == "preferences":
            intent, remote = self.store.intent(identifier)
            if remote:
                if remote.get("status") == "rejected":
                    return self.store.failed(identifier, self.present(state, actor_id=actor_id))
                try:
                    self._center_receipt(client, remote["request_id"], state["machine_id"], remote["policy"])
                except Exception:
                    return receipt
                from .member_execution_identity import set_owner_pause
                # GET reconciliation never re-sends parent or child PUT.
                if intent.get("paused") is True:
                    set_owner_pause(state["identity"], True)
                elif intent.get("paused") is False:
                    self.store.resume_if_current(remote["pause_generation"], lambda: set_owner_pause(state["identity"], False))
                current = _read_json(Path(state["identity"]["member_root"]) / "owner-control/state.json")
                with self.store.executing(identifier):
                    latest = self.read()
                    newer_pause = latest.get("pause_generation", 0) != remote["pause_generation"]
                    updates = {"policy_sync_pending": False, "completed_operation_id": identifier} if not newer_pause else {}
                    latest = self.save(latest, preferences=_preferences({**latest["preferences"], **intent}),
                        paused=current["paused"], preserve_operation_markers=newer_pause, **updates)
                    return self.store.complete(identifier, self.present(latest, client=client, actor_id=actor_id), recovered=True)
        return receipt

    def uninstall(self):
        state = self.read()
        if not state.get("identity"):
            return {"state": "not-configured"}
        if state.get("phase") == "retired-local" and state.get("retirement_receipt"):
            return state["retirement_receipt"]
        from .member_execution_identity import uninstall_member, set_owner_retirement, set_owner_pause
        set_owner_pause(state["identity"], True)
        operation = state.get("retirement_operation_id") or str(uuid4())
        state = self.save(state, retirement_operation_id=operation, paused=True, phase="retirement-pending")
        from .member_client_credentials import PersonalCredentialStore
        from .member_client import member_api_client
        login = PersonalCredentialStore(self.root.parent / "credentials").load()
        if not login:
            raise RuntimeError("member_compute_retirement_requires_original_login")
        client = member_api_client(login["center_url"], token=login["token"])
        if client.current_actor()["actor_id"] != state["actor_id"]:
            raise RuntimeError("member_compute_retirement_requires_original_login")
        self._scope(state, client=None, actor_id=state["actor_id"], center_url=login["center_url"])
        path = f"/v1/machines/{state['machine_id']}/retirement-operations/{operation}"
        client._request("PUT", path, {"reason": "member_client_uninstall"})
        set_owner_retirement(state["identity"], operation)
        retirement = client._request("POST", path + "/reconcile")
        receipt = uninstall_member(state["identity"], state_root=self.root / "native", retirement_receipt=retirement)
        self.save(state, phase=receipt["state"], paused=True, retirement_receipt=receipt)
        if receipt["state"] == "draining":
            raise RuntimeError("member_compute_inflight_still_draining")
        return receipt
