"""Durable identities for metadata actions; credentials are never replayed."""
from functools import wraps
from uuid import UUID

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from .repository import Base
from .hashing import sha256_value


class MetadataMutationReceipt(Base):
    __tablename__ = "metadata_mutation_receipts"
    request_id: Mapped[str] = mapped_column(String, primary_key=True)
    actor_id: Mapped[str] = mapped_column(String, nullable=False)
    kind: Mapped[str] = mapped_column(String, nullable=False)
    subject_id: Mapped[str] = mapped_column(String, nullable=False)
    confirmation_hash: Mapped[str] = mapped_column(String, nullable=False, default="")
    result_id: Mapped[str] = mapped_column(String, nullable=False)


class CredentialAlreadyIssued(ValueError):
    def __init__(self, receipt):
        self.receipt = receipt
        super().__init__("credential_already_issued: inspect or revoke the original token; plaintext is delivered once")


def mutation_receipt(repository, request_id, actor_id):
    with repository._session() as session:
        row = session.get(MetadataMutationReceipt, request_id)
        if row is None:
            return None
        if row.actor_id != actor_id:
            raise ValueError("operation belongs to another actor")
        return {"request_id": row.request_id, "kind": row.kind, "subject_id": row.subject_id,
                "result_id": row.result_id, "state": "completed"}


def credential_confirmation(function):
    @wraps(function)
    def wrapped(self, user_id, *, actor_id, request_id=None, agent=False):
        if request_id is not None:
            request_id = str(UUID(request_id))
        with self.repository.atomic_write():
            if request_id:
                old = mutation_receipt(self.repository, request_id, actor_id)
                if old:
                    if old["kind"] != "personal_token" or old["subject_id"] != user_id:
                        raise ValueError("operation identity conflicts with original request")
                    with self.repository._session() as session:
                        row = session.get(MetadataMutationReceipt, request_id)
                        expected_hash = sha256_value({"agent": agent})
                        if row.confirmation_hash != expected_hash and not (
                            not agent and row.confirmation_hash == ""
                        ):
                            raise ValueError("operation identity conflicts with original credential scope")
                    raise CredentialAlreadyIssued(old)
            issued = function(self, user_id, actor_id=actor_id, agent=agent)
            if request_id:
                with self.repository._session() as session:
                    session.add(MetadataMutationReceipt(request_id=request_id, actor_id=actor_id,
                        kind="personal_token", subject_id=user_id, result_id=issued.token_id,
                        confirmation_hash=sha256_value({"agent": agent})))
            return issued
    return wrapped


def admin_confirmation(function):
    @wraps(function)
    def wrapped(self, *, ticket_id, confirmation_hash, actor_id):
        with self.repository.atomic_write():
            with self.repository._session() as session:
                row = session.get(MetadataMutationReceipt, ticket_id)
                if row is not None:
                    if (row.actor_id, row.kind, row.confirmation_hash) != (actor_id, "admin_job", confirmation_hash):
                        raise ValueError("operation identity conflicts with original request")
                    return self.repository.get_job(row.result_id)
            ticket = self.repository.get_admin_operation_ticket(ticket_id)
            if ticket is not None and ticket.issued_by != actor_id:
                raise ValueError("administrator preview belongs to another actor")
            result = function(self, ticket_id=ticket_id, confirmation_hash=confirmation_hash, actor_id=actor_id)
            with self.repository._session() as session:
                session.add(MetadataMutationReceipt(request_id=ticket_id, actor_id=actor_id,
                    kind="admin_job", subject_id=result.job_id, result_id=result.job_id,
                    confirmation_hash=confirmation_hash))
            return result
    return wrapped


def _approval_hash(approval, *, identity=False):
    excluded = {"approval_id", "created_at"}
    if identity:
        excluded.add("active")
    payload = approval.model_dump(mode="json", exclude=excluded)
    for name in ("solver_variants", "allowed_study_kinds"):
        payload[name] = sorted(payload[name])
    return sha256_value(payload)


def _matching_receipt(session, request_id, actor_id, kind, subject_id, digest):
    row = session.get(MetadataMutationReceipt, request_id)
    if row is not None and (
        row.actor_id, row.kind, row.subject_id, row.confirmation_hash
    ) != (actor_id, kind, subject_id, digest):
        raise ValueError("operation identity conflicts with original request")
    return row


def solver_approval_confirmation(function):
    @wraps(function)
    def wrapped(self, approval, *, actor_id, request_id=None):
        request_id = str(UUID(request_id)) if request_id is not None else None
        digest = _approval_hash(approval)
        with self.repository.atomic_write():
            if request_id:
                with self.repository._session() as session:
                    row = _matching_receipt(session, request_id, actor_id,
                        "solver_approval", approval.project_id, digest)
                    if row is not None:
                        result = self.repository.get_solver_approval(row.result_id)
                        if result is None:
                            raise ValueError("original approval requires reconciliation")
                        # A replay reports the current original record. It never
                        # writes the supplied active=True over a later revocation.
                        return result
            existing = self.repository.get_solver_approval(approval.approval_id)
            if existing is not None:
                if _approval_hash(existing, identity=True) != _approval_hash(approval, identity=True):
                    raise ValueError("approval records are immutable; use a new approval identity")
                if existing.active and not approval.active:
                    existing.active = False
                    self.repository.put_solver_approval(existing)
                    self._event("solver_approval.revoked", actor_id, "solver_approval",
                        existing.approval_id, project_id=existing.project_id)
                result = existing
            else:
                result = function(self, approval, actor_id=actor_id)
            if request_id:
                with self.repository._session() as session:
                    session.add(MetadataMutationReceipt(request_id=request_id,
                        actor_id=actor_id, kind="solver_approval", subject_id=approval.project_id,
                        result_id=result.approval_id, confirmation_hash=digest))
            return result
    return wrapped


ALERT_EXPECTED_FIELDS = frozenset({"status", "last_seen_at", "occurrence_count",
    "acknowledged_at", "snoozed_until", "resolved_at"})


def alert_transition_confirmation(function):
    @wraps(function)
    def wrapped(self, alert_id, status, *, actor_id, snoozed_until=None,
                request_id=None, expected_state=None):
        request_id = str(UUID(request_id)) if request_id is not None else None
        if request_id and (expected_state is None or set(expected_state) != ALERT_EXPECTED_FIELDS):
            raise ValueError("alert operation requires the complete original state")
        digest = sha256_value({"status": status.value, "snoozed_until": snoozed_until,
                              "expected_state": expected_state})
        with self.repository.atomic_write():
            if request_id:
                with self.repository._session() as session:
                    row = _matching_receipt(session, request_id, actor_id,
                        "alert_transition", alert_id, digest)
                    if row is not None:
                        result = self.repository.get_alert(row.result_id)
                        if result is None:
                            raise ValueError("original alert requires reconciliation")
                        return result
            result = function(self, alert_id, status, actor_id=actor_id,
                snoozed_until=snoozed_until, expected_state=expected_state)
            if request_id:
                with self.repository._session() as session:
                    session.add(MetadataMutationReceipt(request_id=request_id,
                        actor_id=actor_id, kind="alert_transition", subject_id=alert_id,
                        result_id=alert_id, confirmation_hash=digest))
            return result
    return wrapped
