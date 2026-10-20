"""Exact SQLite reconciliation reads with a rebuildable per-Job change index.

Only generations and delete tombstones are durable here. Job JSON remains the
authority, and cached records contain only reconciliation's semantic identities.
All epoch, delta and raw-unit values used for a refresh come from one statement.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
import json
from typing import Any
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from .reconciliation_snapshot import _snapshot_from_units, reconciliation_snapshot


_GENERATIONS = "reconciliation_job_generations"
_STATE = "reconciliation_projection_state"
_RAW = "COALESCE(job.operational_payload, job.payload)"
_TRIGGERS: dict[str, str] = {}
for _suffix, _operation, _changes in (
    ("insert", "INSERT", "NEW.job_id, 0"),
    ("delete", "DELETE", "OLD.job_id, 1"),
    # UPDATE OR REPLACE on a unique, otherwise unrelated column can implicitly
    # delete another Job. Every UPDATE must therefore advance the epoch.
    ("update", "UPDATE", "NEW.job_id, 0"),
):
    _rename = (
        f"INSERT INTO {_GENERATIONS} (job_id, generation, deleted) "
        "SELECT OLD.job_id, revision, 1 FROM operational_read_revisions "
        "WHERE scope = 'jobs' AND OLD.job_id <> NEW.job_id "
        "ON CONFLICT(job_id) DO UPDATE SET generation = excluded.generation, deleted = 1; "
        if _suffix == "update" else ""
    )
    _job_id, _deleted = _changes.split(", ")
    _name = f"rcn_job_read_revision_{_suffix}"
    _TRIGGERS[_name] = (
        f"CREATE TRIGGER {_name} AFTER {_operation} ON jobs BEGIN "
        "UPDATE operational_read_revisions SET revision = revision + 1 WHERE scope = 'jobs'; "
        f"UPDATE {_STATE} SET covered_revision = covered_revision + 1 WHERE singleton = 1; "
        + _rename +
        f"INSERT INTO {_GENERATIONS} (job_id, generation, deleted) "
        f"SELECT {_job_id}, revision, {_deleted} FROM operational_read_revisions WHERE scope = 'jobs' "
        "ON CONFLICT(job_id) DO UPDATE SET generation = excluded.generation, deleted = excluded.deleted; END"
    )


def install_reconciliation_projection(connection) -> None:
    """Install/rebase behind the caller's SQLite ``BEGIN IMMEDIATE`` gate.

    Keep the original trigger names: old constructors using IF NOT EXISTS then
    preserve these bodies. A repair changes the installation token so every
    existing reader performs a fresh baseline before trusting future deltas.
    """
    if not connection.connection.driver_connection.in_transaction:
        raise RuntimeError("reconciliation projection installation requires a writer transaction")
    connection.exec_driver_sql(
        f"CREATE TABLE IF NOT EXISTS {_GENERATIONS} ("
        "job_id TEXT PRIMARY KEY, generation INTEGER NOT NULL, deleted INTEGER NOT NULL)"
    )
    connection.exec_driver_sql(
        f"CREATE INDEX IF NOT EXISTS ix_reconciliation_job_generation ON {_GENERATIONS} (generation)"
    )
    connection.exec_driver_sql(
        f"CREATE TABLE IF NOT EXISTS {_STATE} (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), "
        "installation_id TEXT NOT NULL, covered_revision INTEGER NOT NULL)"
    )
    connection.exec_driver_sql(
        "INSERT OR IGNORE INTO operational_read_revisions (scope, revision) VALUES ('jobs', 0)"
    )
    epoch = connection.exec_driver_sql(
        "SELECT revision FROM operational_read_revisions WHERE scope = 'jobs'"
    ).scalar_one()
    state = connection.exec_driver_sql(
        f"SELECT covered_revision FROM {_STATE} WHERE singleton = 1"
    ).first()
    installed = dict(connection.exec_driver_sql(
        "SELECT name, sql FROM sqlite_master WHERE type = 'trigger' AND name LIKE 'rcn_job_read_revision_%'"
    ).all())
    if state is not None and state[0] == epoch and all(installed.get(k) == v for k, v in _TRIGGERS.items()):
        return
    for name, sql in _TRIGGERS.items():
        connection.exec_driver_sql(f"DROP TRIGGER IF EXISTS {name}")
        connection.exec_driver_sql(sql)
    # This reads only Job IDs, never their (potentially large) JSON payloads.
    connection.exec_driver_sql(
        f"INSERT INTO {_GENERATIONS} (job_id, generation, deleted) "
        "SELECT job_id, ?, 0 FROM jobs WHERE 1 "
        "ON CONFLICT(job_id) DO UPDATE SET generation = excluded.generation, deleted = 0",
        (epoch,),
    )
    connection.exec_driver_sql(
        f"INSERT INTO {_STATE} (singleton, installation_id, covered_revision) VALUES (1, ?, ?) "
        "ON CONFLICT(singleton) DO UPDATE SET installation_id = excluded.installation_id, "
        "covered_revision = excluded.covered_revision",
        (uuid4().hex, epoch),
    )


_PARAMS = {}
_matches = []
for _number, (_name, _sql) in enumerate(_TRIGGERS.items()):
    _PARAMS[f"trigger_name_{_number}"] = _name
    _PARAMS[f"trigger_sql_{_number}"] = _sql
    _matches.append(f"(name = :trigger_name_{_number} AND sql = :trigger_sql_{_number})")

_HEADER = (
    "SELECT epoch.revision AS epoch, state.installation_id, state.covered_revision, "
    "(SELECT schema_version FROM pragma_schema_version) AS schema_version, "
    "(SELECT count(*) FROM sqlite_master WHERE type = 'trigger' AND ("
    + " OR ".join(_matches) + ")) = 3 AS triggers_valid "
    f"FROM operational_read_revisions AS epoch LEFT JOIN {_STATE} AS state ON state.singleton = 1 "
    "WHERE epoch.scope = 'jobs'"
)


@dataclass(frozen=True)
class _Checkpoint:
    epoch: int
    installation_id: str
    schema_version: int
    jobs: dict[str, list[dict[str, Any]]]
    snapshot: dict[str, Any]


class ReconciliationReadProjection:
    """One repository's cache; the caller serializes ``snapshot`` calls."""

    def __init__(self, *, max_cached_units: int = 10000):
        self._checkpoint: _Checkpoint | None = None
        self._max_cached_units = max_cached_units

    @staticmethod
    def _compatible(header) -> bool:
        return bool(header.triggers_valid and header.installation_id
                    and header.covered_revision == header.epoch)

    def snapshot(self, session, *, cacheable: bool = True) -> dict[str, Any]:
        checkpoint = self._checkpoint if cacheable else None
        if checkpoint is not None:
            try:
                header = session.execute(text(_HEADER), _PARAMS).one()
            except OperationalError as exc:
                # Legacy/uninitialized projections must not hide their JSON.
                # Never mask malformed JSON or unrelated SQL failures.
                if "no such table: reconciliation_" not in str(exc.orig):
                    raise
                self._checkpoint = None
                return self._raw_snapshot(session)
            if not self._compatible(header):
                self._checkpoint = None
                return self._raw_snapshot(session)
            if (header.epoch == checkpoint.epoch
                    and header.installation_id == checkpoint.installation_id
                    and header.schema_version == checkpoint.schema_version):
                return copy.deepcopy(checkpoint.snapshot)

        params = dict(_PARAMS, seen_epoch=checkpoint.epoch if checkpoint else -1,
                      installation_id=checkpoint.installation_id if checkpoint else "",
                      schema_version=checkpoint.schema_version if checkpoint else -1,
                      pending_job_ids=json.dumps(list(checkpoint.jobs) if checkpoint else []))
        # Re-read the header IN this statement. SQLite's legacy driver need not
        # start a transaction for SELECT; separate header/delta queries alone
        # could otherwise mix two committed versions under WAL.
        query = text(
            "WITH header AS (" + _HEADER + "), policy AS (SELECT *, "
            "COALESCE((triggers_valid AND covered_revision = epoch AND installation_id = :installation_id "
            "AND schema_version = :schema_version AND epoch >= :seen_epoch), 0) AS use_delta FROM header), "
            "dirty AS ("
            f"SELECT changed.job_id, changed.deleted FROM {_GENERATIONS} AS changed, policy "
            "WHERE policy.use_delta AND changed.generation > :seen_epoch "
            # SQLite's default recursive_triggers=0 omits DELETE triggers for
            # implicit REPLACE deletions. Prune only cached pending IDs with PK
            # lookups; never inspect unchanged payloads to detect this case.
            "UNION ALL SELECT pending.value, 1 FROM json_each(:pending_job_ids) AS pending, policy "
            "WHERE policy.use_delta AND NOT EXISTS (SELECT 1 FROM jobs WHERE job_id = pending.value) "
            "UNION ALL SELECT job_id, 0 FROM jobs, policy WHERE NOT policy.use_delta) "
            "SELECT policy.*, dirty.job_id, dirty.deleted, job.status, unit.value AS unit_value "
            "FROM policy LEFT JOIN dirty ON 1 = 1 "
            "LEFT JOIN jobs AS job ON job.job_id = dirty.job_id AND dirty.deleted = 0 "
            f"LEFT JOIN json_each(CASE WHEN instr({_RAW}, 'reconcile_pending') > 0 "
            f"THEN {_RAW} ELSE NULL END, '$.work_units') AS unit "
            "ON json_extract(unit.value, '$.status') = 'reconcile_pending'"
        )
        try:
            rows = session.execute(query, params).all()
        except OperationalError as exc:
            if "no such table: reconciliation_" not in str(exc.orig):
                raise
            if cacheable:
                self._checkpoint = None
            return self._raw_snapshot(session)
        if not rows:
            raise RuntimeError("operational read revision is not initialized")
        header = rows[0]
        jobs = dict(checkpoint.jobs) if header.use_delta and checkpoint is not None else {}
        refreshed: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            if row.job_id is None:
                continue
            records = refreshed.setdefault(row.job_id, [])
            if row.unit_value is not None:
                records.extend(reconciliation_snapshot([
                    (row.job_id, row.status, {"work_units": [json.loads(row.unit_value)]})
                ])["units"])
        for job_id, records in refreshed.items():
            if records:
                jobs[job_id] = records
            else:
                jobs.pop(job_id, None)
        snapshot = _snapshot_from_units(record for records in jobs.values() for record in records)
        # Publish only a completely parsed committed read. In particular, a
        # private transaction cannot poison the checkpoint with a reused epoch.
        if cacheable and self._compatible(header) and snapshot["unit_count"] <= self._max_cached_units:
            self._checkpoint = _Checkpoint(int(header.epoch), header.installation_id,
                                           int(header.schema_version), jobs, snapshot)
        elif cacheable:
            self._checkpoint = None
        return copy.deepcopy(snapshot)

    @staticmethod
    def _raw_snapshot(session) -> dict[str, Any]:
        rows = session.execute(text(
            "SELECT job.job_id, job.status, unit.value AS unit_value FROM jobs AS job "
            f"CROSS JOIN json_each({_RAW}, '$.work_units') AS unit "
            f"WHERE instr({_RAW}, 'reconcile_pending') > 0 "
            "AND json_extract(unit.value, '$.status') = 'reconcile_pending'"
        )).all()
        return reconciliation_snapshot(
            (job_id, status, {"work_units": [json.loads(raw_unit)]})
            for job_id, status, raw_unit in rows
        )
