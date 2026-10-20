"""Bounded HTTPS-only management routes; no Worker request format changes."""
from __future__ import annotations

import asyncio
import json
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from starlette.concurrency import run_in_threadpool

from .auth import AuthContext, require_role
from .metadata_actions import (MetadataActionConflict, MetadataActionForbidden,
    execute_metadata_action)
from .models import UserRole
from pathlib import Path
from .member_relay import RELAY_PATH, MemberRelays, RelayRequest
from .member_relay_policy import RelayUnavailable
from .member_ssh_bootstrap import BOOTSTRAP_PATH, MemberSshBootstrap, SshBootstrapRequest
from .member_bootstrap_transport import BootstrapUnavailable
from .member_ssh_access import ACCESS_PATH, MemberSshAccess
from .member_admission import (OFFER_PATH, CONSENT_PATH, STATUS_PATH,
    MemberAdmissions, ComputeConsentRequest)
from .member_invitation_operations import (OPERATIONS_PATH, CancelInvitationOperation,
    InvitationOperationRequest, MemberInvitationOperations)
from .member_transport import MemberTransportService, TransportIdentityRequest
from .ssh_identity import SshIdentityError, TRANSPORT_PATH
from .member_worker_root_contract import ROOT_PATH, MemberWorkerRoots, WorkerRootRequest
from .member_enrollment import (EXCHANGE_PATH, EnrollmentUnavailable, MemberEnrollmentService,
                                MemberExchangeRequest, MemberInvitationRequest)

HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def _reject(code: str, status: int = 409):
    raise HTTPException(status_code=status, detail={"reason_code": code}, headers=HEADERS)


def _unique_object(items):
    result = {}
    for name, value in items:
        if name in result:
            raise ValueError("duplicate JSON key")
        result[name] = value
    return result


async def _body(request: Request, model, *, with_payload=False):
    if request.url.scheme != "https":
        # Do not infer TLS from a caller-supplied header. Trusted reverse-proxy
        # scheme handling belongs to the deployment ingress gate.
        _reject("enrollment_requires_https", 400)
    if request.headers.get("content-type", "").split(";", 1)[0].lower() != "application/json":
        _reject("enrollment_requires_json", 415)
    data = bytearray()
    try:
        async with asyncio.timeout(10):
            async for chunk in request.stream():
                if len(data) + len(chunk) > 16384:
                    _reject("enrollment_request_too_large", 413)
                data.extend(chunk)
        payload = json.loads(data, object_pairs_hook=_unique_object)
        validated = model.model_validate(payload)
        return (validated, payload) if with_payload else validated
    except TimeoutError:
        _reject("enrollment_request_timeout", 408)
    except (ValueError, ValidationError, UnicodeError, RecursionError):
        # Never return ValidationError.errors(): it may include raw secret inputs.
        _reject("invalid_enrollment_request", 422)


def build_member_enrollment_router(*, repository, auth, dataset_mode: str, verification_root) -> APIRouter:
    router = APIRouter()
    service = MemberEnrollmentService(repository)
    operations = MemberInvitationOperations(repository)
    transport = MemberTransportService(repository, verification_root=verification_root)
    worker_roots = MemberWorkerRoots(repository, verification_root=verification_root)
    admissions = MemberAdmissions(repository, verification_root=verification_root)
    bootstrap = MemberSshBootstrap(repository, authorization_root=Path(verification_root).parent / 'member-relay',
                                   verification_root=verification_root)
    ssh_access = MemberSshAccess(repository, authorization_root=Path(verification_root).parent / 'member-relay',
                                verification_root=verification_root)
    relays = MemberRelays(repository, authorization_root=Path(verification_root).parent / 'member-relay',
                         verification_root=verification_root)

    def enabled():
        if dataset_mode != "formal":
            _reject("member_enrollment_unavailable")

    @router.put(OPERATIONS_PATH + '/{operation_id}')
    async def issue_operation(operation_id: str, request: Request, context: AuthContext = Depends(auth.actor)):
        require_role(context, UserRole.ADMIN)
        enabled()
        body = await _body(request, InvitationOperationRequest)
        try:
            invitation = await run_in_threadpool(operations.issue, operation_id, body, actor_id=context.actor_id)
        except EnrollmentUnavailable:
            _reject('invitation_operation_unavailable')
        return JSONResponse(invitation.private_document(), headers=HEADERS)

    @router.post(OPERATIONS_PATH + '/{operation_id}/cancel')
    async def cancel_operation(operation_id: str, request: Request, context: AuthContext = Depends(auth.actor)):
        require_role(context, UserRole.ADMIN)
        enabled()
        await _body(request, CancelInvitationOperation)
        try:
            result = await run_in_threadpool(operations.cancel, operation_id, actor_id=context.actor_id)
        except EnrollmentUnavailable:
            _reject('invitation_operation_unavailable')
        return JSONResponse(result, headers=HEADERS)

    @router.post("/v1/admin/member-invitations")
    async def issue(request: Request, context: AuthContext = Depends(auth.actor)):
        require_role(context, UserRole.ADMIN)
        enabled()
        body = await _body(request, MemberInvitationRequest)
        try:
            invitation = await run_in_threadpool(service.issue, body, actor_id=context.actor_id)
        except EnrollmentUnavailable:
            _reject("invitation_owner_unavailable")
        return JSONResponse(invitation.private_document(), headers=HEADERS)

    @router.post("/v1/admin/member-invitations/{enrollment_id}/revoke")
    async def revoke(enrollment_id: str, request: Request, context: AuthContext = Depends(auth.actor)):
        require_role(context, UserRole.ADMIN)
        enabled()
        if request.url.scheme != "https":
            _reject("enrollment_requires_https", 400)
        try:
            result = await run_in_threadpool(service.revoke, enrollment_id, actor_id=context.actor_id)
        except EnrollmentUnavailable:
            _reject("invitation_unavailable")
        return JSONResponse(result, headers=HEADERS)

    @router.post(EXCHANGE_PATH)
    async def exchange(request: Request):
        enabled()
        body = await _body(request, MemberExchangeRequest)
        try:
            result = await run_in_threadpool(service.exchange, body)
        except EnrollmentUnavailable:
            _reject("invitation_or_device_unavailable")
        return JSONResponse(result.model_dump(mode="json"), headers=HEADERS)

    @router.post(TRANSPORT_PATH)
    async def bind_transport(request: Request):
        enabled()
        body = await _body(request, TransportIdentityRequest)
        try:
            result = await run_in_threadpool(transport.bind, body)
        except EnrollmentUnavailable:
            _reject('transport_identity_unavailable')
        except SshIdentityError:
            _reject('transport_identity_verifier_unavailable', 503)
        return JSONResponse(result.model_dump(mode='json'), headers=HEADERS)

    @router.post(ROOT_PATH)
    async def register_worker_root(request: Request):
        enabled()
        body = await _body(request, WorkerRootRequest)
        try:
            result = await run_in_threadpool(worker_roots.register, body)
        except EnrollmentUnavailable:
            _reject('worker_root_unavailable')
        except SshIdentityError:
            _reject('transport_identity_verifier_unavailable', 503)
        return JSONResponse(result.model_dump(mode='json'), headers=HEADERS)

    @router.post(RELAY_PATH)
    async def provision_relay(request: Request):
        enabled()
        body = await _body(request, RelayRequest)
        try:
            result = await run_in_threadpool(relays.request, body)
        except EnrollmentUnavailable:
            _reject('member_relay_identity_unavailable')
        except RelayUnavailable as exc:
            # This exception class only carries fixed public reason codes.
            _reject(str(exc), 503)
        except SshIdentityError:
            _reject('transport_identity_verifier_unavailable', 503)
        return JSONResponse(result, headers=HEADERS)

    @router.post(ACCESS_PATH)
    async def member_ssh_access_plan(request: Request):
        enabled()
        body = await _body(request, WorkerRootRequest)
        try:
            result = await run_in_threadpool(ssh_access.plan, body)
        except EnrollmentUnavailable:
            _reject('member_ssh_access_authority_unavailable')
        except (BootstrapUnavailable, RelayUnavailable) as exc:
            _reject(str(exc), 503)
        except SshIdentityError:
            _reject('transport_identity_verifier_unavailable', 503)
        return JSONResponse(result, headers=HEADERS)

    @router.post(BOOTSTRAP_PATH)
    async def verify_ssh_bootstrap(request: Request):
        enabled()
        body = await _body(request, SshBootstrapRequest)
        try:
            result = await run_in_threadpool(bootstrap.confirm, body)
        except EnrollmentUnavailable:
            _reject('member_bootstrap_authority_unavailable')
        except (BootstrapUnavailable, RelayUnavailable) as exc:
            _reject(str(exc), 503)
        except SshIdentityError:
            _reject('transport_identity_verifier_unavailable', 503)
        return JSONResponse(result, headers=HEADERS)

    async def admission_call(request, model, action):
        enabled()
        body = await _body(request, model)
        try:
            result = await run_in_threadpool(action, body)
        except EnrollmentUnavailable:
            _reject('member_admission_unavailable')
        except SshIdentityError:
            _reject('transport_identity_verifier_unavailable', 503)
        return JSONResponse(result, headers=HEADERS)

    @router.post(OFFER_PATH)
    async def compute_offer(request: Request):
        return await admission_call(request, WorkerRootRequest, admissions.offer)

    @router.post(CONSENT_PATH)
    async def compute_consent(request: Request):
        return await admission_call(request, ComputeConsentRequest, admissions.consent)

    @router.post(STATUS_PATH)
    async def admission_status(request: Request):
        return await admission_call(request, WorkerRootRequest, admissions.status)

    @router.post('/v1/admin/member-admissions/{enrollment_id}/revoke')
    async def revoke_compute(enrollment_id: str, request: Request, context: AuthContext = Depends(auth.actor)):
        require_role(context, UserRole.ADMIN)
        enabled()
        _, payload = await _body(request, CancelInvitationOperation, with_payload=True)
        # _body enforces the HTTPS/size/unique-key contract before fingerprinting.
        action = (request.headers.get("X-RCN-Request-ID"), {
            "method": request.method, "path": request.url.path, "body": payload})
        try:
            result = await run_in_threadpool(execute_metadata_action, repository,
                request_id=action[0], actor_id=context.actor_id, kind="member_admission_revoke",
                subject_id=enrollment_id, payload=action[1],
                mutate=lambda: admissions.revoke(enrollment_id, actor_id=context.actor_id))
        except MetadataActionForbidden as exc:
            raise HTTPException(status_code=403, detail=str(exc), headers=HEADERS) from exc
        except MetadataActionConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc), headers=HEADERS) from exc
        except EnrollmentUnavailable:
            _reject('member_admission_unavailable')
        return JSONResponse(result, headers=HEADERS)

    return router
