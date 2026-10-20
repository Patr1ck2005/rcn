"""Non-sensitive semantic identities for pending Unit reconciliation.

This module only describes the latest Attempt of each pending Unit.  It does
not classify quarantine evidence or infer whether remote execution occurred.
"""

from __future__ import annotations

from collections.abc import Iterable
import hashlib
import json
from typing import Any


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False)


def _unit_identity(job_id: Any, unit: dict[str, Any]) -> dict[str, Any]:
    malformed_fields: set[str] = set()
    malformed_value_sha256: dict[str, str] = {}

    def field(name: str, value: Any, expected: type, *, optional: bool = False) -> Any:
        valid = type(value) is expected
        if expected is str and valid:
            valid = bool(value.strip())
        if not valid and not (optional and value is None):
            malformed_fields.add(name)
        if value is None or type(value) in (str, bool, int, float):
            return value
        # A malformed identity must affect the digest without copying arbitrary
        # nested data from a corrupt identity field into publication evidence.
        malformed_value_sha256[name] = hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()
        return None

    attempts = unit.get("attempts")
    if not isinstance(attempts, list) or not attempts:
        malformed_fields.add("attempts")
        attempt: dict[str, Any] = {}
    elif not isinstance(attempts[-1], dict):
        malformed_fields.add("latest_attempt")
        attempt = {}
    else:
        attempt = attempts[-1]

    attempt_machine_id = attempt.get("machine_id")
    assigned_machine_id = unit.get("assigned_machine_id")
    machine_id = attempt_machine_id or assigned_machine_id
    identity = {
        "job_id": field("job_id", job_id, str),
        "work_unit_id": field("work_unit_id", unit.get("work_unit_id"), str),
        "unit_status": unit["status"],
        "attempt_id": field("attempt_id", attempt.get("attempt_id"), str),
        "machine_id": field("machine_id", machine_id, str),
        "attempt_machine_id": field("attempt_machine_id", attempt_machine_id, str, optional=True),
        "assigned_machine_id": field("assigned_machine_id", assigned_machine_id, str, optional=True),
        "external_run_id": field("external_run_id", attempt.get("external_run_id"), str),
        "state": field("state", attempt.get("state"), str),
        "execution_started": field("execution_started", attempt.get("execution_started"), bool),
        "execution_completed": field("execution_completed", attempt.get("execution_completed"), bool),
        "remote_run_allocated": field("remote_run_allocated", attempt.get("remote_run_allocated"), bool),
        "failure_reason": field("failure_reason", attempt.get("failure_reason"), str, optional=True),
    }
    if attempt.get("state") != "reconcile_pending":
        malformed_fields.add("state")
    if (attempt_machine_id is not None and assigned_machine_id is not None
            and attempt_machine_id != assigned_machine_id):
        malformed_fields.add("machine_identity_mismatch")
    identity["malformed"] = bool(malformed_fields)
    identity["malformed_fields"] = sorted(malformed_fields)
    identity["malformed_value_sha256"] = malformed_value_sha256
    return identity


def reconciliation_snapshot(rows: Iterable[tuple[str, str, Any]]) -> dict[str, Any]:
    """Describe all ``reconcile_pending`` Units in raw operational Job rows.

    Rows have the same ``(job_id, status, raw_payload)`` shape as deployment's
    ``_job_payload_rows``.  Job status does not filter Units.  A missing or
    malformed latest Attempt remains one counted Unit; historical Attempts
    never substitute for it.  Missing flags remain ``None``, not ``False``.

    The digest covers the sorted semantic Unit records, encoded with sorted
    JSON keys, compact separators and ASCII escapes.  Only the named identity
    and reconciliation fields are copied; timestamps, science and credentials
    elsewhere in a Job are excluded.  Unreadable Job containers raise instead
    of silently publishing an empty or partial snapshot.
    """
    units: list[dict[str, Any]] = []
    for job_id, _status, raw_payload in rows:
        payload = json.loads(raw_payload) if isinstance(raw_payload, str) else raw_payload
        if not isinstance(payload, dict):
            raise ValueError("reconciliation snapshot requires a Job payload object")
        work_units = payload.get("work_units")
        if work_units is None:
            continue
        if not isinstance(work_units, list):
            raise ValueError("reconciliation snapshot requires a work_units list")
        for unit in work_units:
            if not isinstance(unit, dict):
                raise ValueError("reconciliation snapshot requires WorkUnit objects")
            if unit.get("status") == "reconcile_pending":
                units.append(_unit_identity(job_id, unit))
    return _snapshot_from_units(units)


def _snapshot_from_units(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Combine already-derived semantic records using the same proof format."""
    units = list(records)
    units.sort(key=_canonical)
    return {
        "unit_count": len(units),
        "identity_sha256": hashlib.sha256(_canonical(units).encode("utf-8")).hexdigest(),
        "units": units,
    }
