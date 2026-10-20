"""Transactional Control Plane deployment preparation, verification, and rollback."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import sqlite3
import subprocess
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen
import uuid
import xml.etree.ElementTree as ET

import psutil

from .control_plane_startup import CONTROL_PLANE_MANAGER, CONTROL_PLANE_TASK
from .runtime_policy import PACKAGE_VERSION, STABLE_RUNTIME_VERSION, RuntimePolicy


HttpGet = Callable[[str, str], dict]
HttpPost = Callable[[str, str, dict], dict]
HttpPut = Callable[[str, str, dict], dict]
RestartTask = Callable[[str], None]

ACTIVE_ATTEMPT_STATES = frozenset({
    "assigned",
    "submitting",
    "running",
    "cancel_pending",
    "reconcile_pending",
    "uncertain",
    "collecting",
})


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name("." + path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        with temporary.open("w", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


@contextmanager
def _release_lock(pointer_path: Path):
    """One OS lock per runtime pointer; process death releases the lock."""
    lock_path = pointer_path.parent / "release.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+b") as handle:
        if handle.tell() == 0:
            handle.write(b"\0")
            handle.flush()
        handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise RuntimeError("another release operation owns the runtime pointer lock") from exc
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == "nt":
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _pointer_value(path: Path) -> dict | None:
    return _read_json(path) if path.exists() else None


def _pointer_compare_exchange(path: Path, expected: dict | None, replacement: dict | None):
    if _pointer_value(path) != expected:
        raise RuntimeError("runtime pointer changed; refuse to overwrite another deployment")
    _restore_pointer(path, replacement)


def _intent(path: Path, manifest: dict, stage: str, action: Callable[[], Any]):
    """Persist intent before every effect; uncertain effects repeat idempotently."""
    journal = manifest.setdefault("journal", {})
    entry = journal.get(stage) or {}
    if entry.get("state") == "completed":
        return entry.get("result")
    journal[stage] = {"state": "intent", "at": _utc_now().isoformat()}
    manifest["stage"] = stage
    _atomic_json(path, manifest)
    result = action()
    journal[stage] = {"state": "completed", "at": _utc_now().isoformat(), "result": result}
    _atomic_json(path, manifest)
    return result


def _read_json(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"JSON object required: {path}")
    return payload


def _sqlite_integrity(database: Path) -> str:
    if not database.is_file():
        raise FileNotFoundError(database)
    connection = sqlite3.connect(str(database))
    try:
        result = connection.execute("PRAGMA integrity_check").fetchone()
    finally:
        connection.close()
    value = str(result[0]) if result else "missing"
    if value.lower() != "ok":
        raise RuntimeError(f"SQLite integrity_check failed: {value}")
    return value


def _online_backup(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    source_connection = sqlite3.connect(str(source))
    destination_connection = sqlite3.connect(str(destination))
    try:
        source_connection.backup(destination_connection)
    finally:
        destination_connection.close()
        source_connection.close()
    _sqlite_integrity(destination)


def _sqlite_schema_sha256(database: Path) -> str:
    connection = sqlite3.connect(str(database))
    try:
        rows = connection.execute(
            "SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
        ).fetchall()
    finally:
        connection.close()
    payload = json.dumps(rows, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _validate_hotfix_schema(python_executable: Path, database_backup: Path) -> dict:
    """Apply candidate initialization to the backup and reject schema drift."""
    before = _sqlite_schema_sha256(database_backup)
    command = [
        str(python_executable),
        "-m",
        "research_compute_network.cli",
        "--database-url",
        f"sqlite:///{database_backup.as_posix()}",
        "init-db",
    ]
    environment = os.environ.copy()
    for key in ("PYTHONPATH", "RCN_TOKEN", "RCN_DATABASE_URL", "RCN_PILOT_DATABASE_URL"):
        environment.pop(key, None)
    environment["RCN_HOME"] = str(database_backup.parent)
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=180,
        env=environment,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0:
        raise RuntimeError("candidate hotfix failed to initialize the isolated database backup")
    after = _sqlite_schema_sha256(database_backup)
    if after != before:
        raise ValueError(
            "candidate changes the database schema; use the standard maintenance release path"
        )
    return {"verified": True, "schema_sha256": before}


def _sqlite_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _sqlite_schema_snapshot(database: Path) -> dict:
    """Read definitions, including implicit indexes, without opening a writer."""
    connection = sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True)
    try:
        objects = connection.execute(
            "SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_master "
            "ORDER BY type, name"
        ).fetchall()
        tables = {}
        for kind, name, _table, sql in objects:
            if kind != "table":
                continue
            identifier = _sqlite_identifier(name)
            indexes = {}
            for _seq, index_name, unique, origin, partial in connection.execute(
                f"PRAGMA index_list({identifier})"
            ):
                index_sql = connection.execute(
                    "SELECT COALESCE(sql, '') FROM sqlite_master WHERE type='index' AND name=?",
                    (index_name,),
                ).fetchone()
                indexes[index_name] = {
                    "unique": unique, "origin": origin, "partial": partial,
                    "sql": index_sql[0] if index_sql else "",
                    "columns": [list(row) for row in connection.execute(
                        f"PRAGMA index_xinfo({_sqlite_identifier(index_name)})"
                    )],
                }
            tables[name] = {
                "sql": sql,
                "columns": [list(row) for row in connection.execute(f"PRAGMA table_info({identifier})")],
                "indexes": indexes,
                "foreign_keys": [list(row) for row in connection.execute(
                    f"PRAGMA foreign_key_list({identifier})"
                )],
            }
        return {"objects": [list(row) for row in objects], "tables": tables}
    finally:
        connection.close()


def _sqlite_table_definition_parts(sql: str) -> tuple[str, list[str], str]:
    """Split CREATE TABLE entries while respecting SQL quotes and comments."""
    depth = 0
    start = 0
    header = ""
    parts = []
    position = 0
    while position < len(sql):
        char = sql[position]
        if char in "'\"`[":
            end = "]" if char == "[" else char
            position += 1
            while position < len(sql):
                if sql[position] == end:
                    if end != "]" and sql[position:position + 2] == end * 2:
                        position += 2
                        continue
                    break
                position += 1
        elif sql[position:position + 2] == "--":
            newline = sql.find("\n", position + 2)
            position = len(sql) if newline < 0 else newline
        elif sql[position:position + 2] == "/*":
            end_comment = sql.find("*/", position + 2)
            if end_comment < 0:
                raise ValueError("unrecognized additive table definition")
            position = end_comment + 1
        elif char == "(":
            if depth == 0:
                header, start = sql[:position].strip(), position + 1
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                parts.append(sql[start:position].strip())
                return header, parts, sql[position + 1:].strip()
        elif char == "," and depth == 1:
            parts.append(sql[start:position].strip())
            start = position + 1
        position += 1
    raise ValueError("unrecognized additive table definition")


def _additive_schema_compatibility(before: dict, after: dict) -> dict:
    old_tables, new_tables = before["tables"], after["tables"]
    added_columns = {}
    for name, old in old_tables.items():
        new = new_tables.get(name)
        if new is None:
            raise ValueError(f"additive schema removed existing table: {name}")
        if new["columns"][:len(old["columns"])] != old["columns"]:
            raise ValueError(f"additive schema changed existing columns: {name}")
        additions = new["columns"][len(old["columns"]):]
        if new["foreign_keys"] != old["foreign_keys"]:
            raise ValueError(f"additive schema changed existing foreign keys: {name}")
        for index_name, definition in old["indexes"].items():
            if new["indexes"].get(index_name) != definition:
                raise ValueError(f"additive schema changed existing index: {index_name}")
        if additions:
            old_head, old_parts, old_tail = _sqlite_table_definition_parts(old["sql"])
            new_head, new_parts, new_tail = _sqlite_table_definition_parts(new["sql"])
            if (old_head != new_head or old_tail != new_tail
                    or new_parts[:len(old_parts)] != old_parts
                    or len(new_parts) != len(old_parts) + len(additions)):
                raise ValueError(f"additive schema changed existing table definition: {name}")
            for column, definition in zip(additions, new_parts[len(old_parts):]):
                _cid, column_name, _type, not_null, default, primary_key = column
                if (primary_key or (not_null and (default is None or default.upper() == "NULL"))
                        or re.search(r"\b(CHECK|UNIQUE|REFERENCES|GENERATED)\b", definition, re.I)):
                    raise ValueError(f"additive column is incompatible with the old runtime: {name}.{column_name}")
            added_columns[name] = [column[1] for column in additions]
        elif new["sql"] != old["sql"]:
            raise ValueError(f"additive schema changed existing table definition: {name}")

    old_objects = {(row[0], row[1]): row for row in before["objects"]}
    new_objects = {(row[0], row[1]): row for row in after["objects"]}
    for key, definition in old_objects.items():
        if key[0] != "table" and new_objects.get(key) != definition:
            raise ValueError(f"additive schema changed existing {key[0]}: {key[1]}")
    added = [row for key, row in new_objects.items() if key not in old_objects]
    approved_projection_triggers = {}
    triggers = [row for row in added if row[0] == "trigger"]
    if triggers:
        # This is the bounded V18 projection migration, not a general trigger
        # policy. These exact three bodies read jobs and write only the three
        # disposable projection tables; all write targets must be new here.
        from .reconciliation_read_projection import _TRIGGERS

        projection_tables = {
            "operational_read_revisions", "reconciliation_projection_state",
            "reconciliation_job_generations",
        }
        if (any(row[2] != "jobs" for row in triggers)
                or {row[1]: row[3] for row in triggers} != _TRIGGERS
                or not projection_tables.issubset(set(new_tables) - set(old_tables))):
            raise ValueError(
                "additive schema permits only new tables, columns, and indexes or the exact "
                "approved projection triggers writing exclusively to new projection tables"
            )
        approved_projection_triggers = {
            row[1]: hashlib.sha256(row[3].encode("utf-8")).hexdigest()
            for row in triggers
        }
    if any(row[0] not in {"table", "index", "trigger"} for row in added):
        raise ValueError("additive schema permits only new tables, columns, and indexes")
    return {
        "tables": sorted(set(new_tables) - set(old_tables)),
        "columns": added_columns,
        "indexes": sorted(row[1] for row in added if row[0] == "index"),
        "approved_projection_triggers": approved_projection_triggers,
    }


def _sqlite_value_bytes(value: Any) -> bytes:
    if value is None:
        kind, payload = b"n", b""
    elif isinstance(value, int):
        kind, payload = b"i", str(value).encode("ascii")
    elif isinstance(value, float):
        kind, payload = b"f", value.hex().encode("ascii")
    elif isinstance(value, str):
        kind, payload = b"s", value.encode("utf-8")
    elif isinstance(value, bytes):
        kind, payload = b"b", value
    else:
        raise ValueError("unsupported SQLite value in additive data verification")
    return kind + len(payload).to_bytes(8, "big") + payload


def _sqlite_original_data_snapshot(database: Path, original_tables: dict) -> dict:
    """Stream every original column, with binary, type-sensitive row ordering."""
    connection = sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True)
    connection.create_function("rcn_release_value_key", 1, _sqlite_value_bytes, deterministic=True)
    try:
        result = {}
        for name, table in original_tables.items():
            columns = [column[1] for column in table["columns"]]
            identifiers = [_sqlite_identifier(column) for column in columns]
            order = ", ".join(f"rcn_release_value_key({column})" for column in identifiers)
            cursor = connection.execute(
                f"SELECT {', '.join(identifiers)} FROM {_sqlite_identifier(name)} ORDER BY {order}"
            )
            digest = hashlib.sha256()
            row_count = 0
            for row in cursor:
                digest.update(b"r")
                for value in row:
                    digest.update(_sqlite_value_bytes(value))
                row_count += 1
            result[name] = {"columns": columns, "row_count": row_count, "sha256": digest.hexdigest()}
        return result
    finally:
        connection.close()


def _validate_additive_schema(python_executable: Path, database_backup: Path) -> dict:
    """Prove candidate initialization is additive on a disposable backup copy."""
    pristine_sha256 = _sha256(database_backup)
    before = _sqlite_schema_snapshot(database_backup)
    data_before = _sqlite_original_data_snapshot(database_backup, before["tables"])
    scratch = database_backup.with_name(database_backup.name + f".additive-{uuid.uuid4().hex}")
    shutil.copy2(database_backup, scratch)
    environment = os.environ.copy()
    for variable in ("PYTHONPATH", "RCN_TOKEN", "RCN_DATABASE_URL", "RCN_PILOT_DATABASE_URL"):
        environment.pop(variable, None)
    environment["RCN_HOME"] = str(scratch.parent)
    # Service.initialize also bootstraps people/audit events. Those business
    # writes are not schema migrations; register the same additional Base
    # models and run only the candidate repository's schema initialization.
    initialize_schema = (
        "import sys\n"
        "import research_compute_network.submission_policy\n"
        "import research_compute_network.compute_credits\n"
        "from research_compute_network.repository import MetadataRepository\n"
        "repository = MetadataRepository(sys.argv[1])\n"
        "try:\n"
        "    repository.init_schema()\n"
        "finally:\n"
        "    repository.engine.dispose()\n"
    )
    try:
        completed = subprocess.run(
            [str(python_executable), "-c", initialize_schema, f"sqlite:///{scratch.as_posix()}"],
            check=False, capture_output=True, text=True, timeout=180, env=environment,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    finally:
        if _sha256(database_backup) != pristine_sha256:
            raise ValueError("additive validation changed the pristine online backup")
    if completed.returncode != 0:
        raise RuntimeError("candidate additive release failed to initialize the isolated database copy")
    _sqlite_integrity(scratch)
    after = _sqlite_schema_snapshot(scratch)
    added = _additive_schema_compatibility(before, after)
    data_after = _sqlite_original_data_snapshot(scratch, before["tables"])
    changed = sorted(name for name in data_before if data_before[name] != data_after[name])
    if changed:
        raise ValueError("additive initialization rewrote original table data: " + ", ".join(changed))
    return {
        "verified": True,
        "pristine_backup_sha256": pristine_sha256,
        "validation_database": str(scratch),
        "schema_before": before,
        "schema_after": after,
        "added_objects": added,
        "compatibility_receipt": {
            "verified": True, "existing_definitions_preserved": True,
            "original_column_data_unchanged": True,
            "approved_projection_triggers": added["approved_projection_triggers"],
            "data_hash_algorithm": "sha256-typed-length-prefixed-values-binary-row-order-v1",
            "table_data_before": data_before, "table_data_after": data_after,
        },
    }


def _validate_candidate_package_origin(
    python_executable: Path,
    runtime_root: Path,
) -> dict[str, Any]:
    """Reject a candidate interpreter that resolves RCN outside its runtime."""

    command = [
        str(python_executable),
        "-c",
        (
            "import json\n"
            "from pathlib import Path\n"
            "import research_compute_network as package\n"
            "from importlib.resources import files\n"
            "from research_compute_network.runtime_policy import PACKAGE_VERSION\n"
            "fixture = files('research_compute_network.acceptance_fixtures').joinpath('project_worker_smoke.py')\n"
            "print(json.dumps({"
            "'module_path': str(Path(package.__file__).resolve()), "
            "'package_version': PACKAGE_VERSION, "
            "'project_worker_fixture_path': str(Path(str(fixture)).resolve()), "
            "'project_worker_fixture_available': fixture.is_file()"
            "}))"
        ),
    ]
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=environment,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0:
        raise RuntimeError("candidate runtime failed to import research_compute_network")
    try:
        lines = [line for line in completed.stdout.splitlines() if line.strip()]
        evidence = json.loads(lines[-1])
        module_path = Path(evidence["module_path"]).resolve()
        package_version = str(evidence["package_version"])
        fixture_path = Path(evidence["project_worker_fixture_path"]).resolve()
        fixture_available = bool(evidence["project_worker_fixture_available"])
    except (IndexError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError("candidate runtime returned invalid package-origin evidence") from exc
    expected_root = runtime_root.resolve()
    if not module_path.is_relative_to(expected_root):
        raise ValueError(
            "candidate research_compute_network package resolves outside the managed runtime"
        )
    if package_version != PACKAGE_VERSION:
        raise ValueError(
            "candidate research_compute_network package version does not match the release tool"
        )
    if not fixture_available or not fixture_path.is_relative_to(expected_root):
        raise ValueError(
            "candidate runtime is missing its package-owned project-worker acceptance fixture"
        )
    return {
        "verified": True,
        "module_path": str(module_path),
        "package_version": package_version,
        "project_worker_fixture_path": str(fixture_path),
        "project_worker_fixture_available": True,
    }


def _active_execution_snapshot(database: Path) -> dict:
    """Return non-sensitive continuity evidence for in-flight Attempts."""
    rows = _job_payload_rows(database, statuses={"queued", "running"})

    attempts: list[dict[str, Any]] = []
    active_job_ids: set[str] = set()
    for job_id, _status, raw_payload in rows:
        payload = json.loads(raw_payload) if isinstance(raw_payload, str) else raw_payload
        if not isinstance(payload, dict):
            continue
        for unit in payload.get("work_units") or []:
            if not isinstance(unit, dict):
                continue
            unit_attempts = unit.get("attempts") or []
            if not unit_attempts or not isinstance(unit_attempts[-1], dict):
                continue
            attempt = unit_attempts[-1]
            state = str(attempt.get("state") or "")
            if state not in ACTIVE_ATTEMPT_STATES:
                continue
            attempt_id = str(attempt.get("attempt_id") or "")
            if not attempt_id:
                continue
            active_job_ids.add(str(job_id))
            attempts.append({
                "attempt_id": attempt_id,
                "job_id": str(job_id),
                "work_unit_id": str(unit.get("work_unit_id") or ""),
                "machine_id": attempt.get("machine_id"),
                "external_run_id": attempt.get("external_run_id"),
                "remote_run_allocated": attempt.get("remote_run_allocated") is True,
                "failure_reason": attempt.get("failure_reason"),
                "state": state,
                "execution_started": bool(attempt.get("execution_started")),
                "execution_completed": bool(attempt.get("execution_completed")),
                "external_run_allocated": bool(
                    attempt.get("remote_run_allocated") or attempt.get("external_run_id")
                ),
            })
    attempts.sort(key=lambda item: item["attempt_id"])
    identity = "\n".join(item["attempt_id"] for item in attempts).encode("utf-8")
    return {
        "captured_at": _utc_now().isoformat(),
        "active_job_count": len(active_job_ids),
        "active_job_ids": sorted(active_job_ids),
        "active_attempt_count": len(attempts),
        "execution_started_count": sum(item["execution_started"] for item in attempts),
        "attempt_set_sha256": hashlib.sha256(identity).hexdigest(),
        "attempts": attempts,
    }


def _job_payload_rows(
    database: Path,
    *,
    statuses: set[str] | None = None,
    job_ids: set[str] | None = None,
    reconciliation_only: bool = False,
) -> list[tuple[str, str, Any]]:
    """Read compact Job state when the operational projection is available."""

    connection = sqlite3.connect(str(database))
    try:
        try:
            columns = {
                str(row[1])
                for row in connection.execute("PRAGMA table_info(jobs)").fetchall()
            }
            if not columns:
                return []
            payload_expression = (
                "COALESCE(operational_payload, payload)"
                if "operational_payload" in columns
                else "payload"
            )
            clauses = []
            parameters: tuple[str, ...] = ()
            if statuses:
                ordered = tuple(sorted(statuses))
                placeholders = ", ".join("?" for _ in ordered)
                clauses.append(f"status IN ({placeholders})")
                parameters += ordered
            if job_ids is not None:
                if not job_ids:
                    return []
                ordered_ids = tuple(sorted(job_ids))
                clauses.append("job_id IN (" + ", ".join("?" for _ in ordered_ids) + ")")
                parameters += ordered_ids
            if reconciliation_only:
                # Keep malformed containers in the candidate set: the original
                # semantic parser must still reject them, even on terminal Jobs.
                # Valid unrelated history stays in SQLite instead of becoming
                # a large Python object graph during every release check.
                clauses.append(f"""CASE
                    WHEN NOT json_valid({payload_expression}) THEN 1
                    WHEN json_type({payload_expression}) <> 'object' THEN 1
                    WHEN json_type({payload_expression}, '$.work_units') IS NULL
                         OR json_type({payload_expression}, '$.work_units') = 'null' THEN 0
                    WHEN json_type({payload_expression}, '$.work_units') <> 'array' THEN 1
                    ELSE EXISTS (SELECT 1 FROM json_each({payload_expression}, '$.work_units') AS unit
                        WHERE unit.type <> 'object' OR CASE WHEN unit.type = 'object'
                            THEN json_extract(unit.value, '$.status') = 'reconcile_pending' ELSE 0 END)
                    END""")
            where = " WHERE " + " AND ".join(clauses) if clauses else ""
            return connection.execute(
                f"SELECT job_id, status, {payload_expression} FROM jobs{where} ORDER BY job_id",
                parameters,
            ).fetchall()
        except sqlite3.OperationalError as exc:
            if "no such table" not in str(exc).lower():
                raise
            return []
    finally:
        connection.close()


def _unfinished_execution_snapshot(database: Path) -> dict:
    """Return unfinished execution-started Attempts eligible for quarantine."""

    attempts: list[dict[str, Any]] = []
    for job_id, _status, raw_payload in _job_payload_rows(database):
        payload = json.loads(raw_payload) if isinstance(raw_payload, str) else raw_payload
        if not isinstance(payload, dict):
            continue
        for unit in payload.get("work_units") or []:
            if not isinstance(unit, dict):
                continue
            unit_attempts = unit.get("attempts") or []
            if not unit_attempts or not isinstance(unit_attempts[-1], dict):
                continue
            attempt = unit_attempts[-1]
            machine_id = str(attempt.get("machine_id") or unit.get("assigned_machine_id") or "")
            if (
                not machine_id
                or not attempt.get("execution_started")
                or attempt.get("execution_completed")
            ):
                continue
            attempts.append({
                "attempt_id": str(attempt.get("attempt_id") or ""),
                "job_id": str(job_id),
                "work_unit_id": str(unit.get("work_unit_id") or ""),
                "machine_id": machine_id,
                "state": str(attempt.get("state") or ""),
                "failure_class": str(attempt.get("failure_class") or ""),
            })
    attempts.sort(key=lambda item: item["attempt_id"])
    return {
        "attempt_count": len(attempts),
        "machine_ids": sorted({item["machine_id"] for item in attempts}),
        "attempts": attempts,
    }


def _canonical_submission_unknown_reason(reason: object) -> bool:
    prefix = "submission delivery unknown:"
    return isinstance(reason, str) and reason.startswith(prefix) and bool(reason[len(prefix):].strip())


def _delivery_unknown_identity(job_id: str, unit: dict, attempt: dict) -> dict | None:
    """Classify explicit allocated delivery uncertainty, never infer nonexecution."""
    values = {
        "job_id": job_id, "work_unit_id": unit.get("work_unit_id"),
        "attempt_id": attempt.get("attempt_id"), "machine_id": attempt.get("machine_id"),
        "external_run_id": attempt.get("external_run_id"),
    }
    reason = attempt.get("failure_reason")
    if (
        any(not isinstance(value, str) or not value.strip() for value in values.values())
        or unit.get("status") != "reconcile_pending"
        or attempt.get("state") != "reconcile_pending"
        or attempt.get("remote_run_allocated") is not True
        or attempt.get("execution_started") is not False
        or attempt.get("execution_completed") is not False
        or not _canonical_submission_unknown_reason(reason)
        or (unit.get("assigned_machine_id") is not None
            and unit.get("assigned_machine_id") != values["machine_id"])
    ):
        return None
    return {**values, "reconciliation_class": "submission_delivery_unknown", "failure_reason": reason}


def _quarantined_execution_snapshot(database: Path) -> dict:
    """Keep execution quarantine separate from allocated delivery uncertainty."""

    from .reconciliation_snapshot import reconciliation_snapshot

    rows = _job_payload_rows(database, reconciliation_only=True)
    pending_snapshot = reconciliation_snapshot(rows)
    attempts: list[dict[str, Any]] = []
    deliveries: list[dict[str, Any]] = []
    for job_id, _status, raw_payload in rows:
        payload = json.loads(raw_payload) if isinstance(raw_payload, str) else raw_payload
        if not isinstance(payload, dict):
            continue
        for unit in payload.get("work_units") or []:
            if not isinstance(unit, dict) or unit.get("status") != "reconcile_pending":
                continue
            unit_attempts = unit.get("attempts") or []
            if not unit_attempts or not isinstance(unit_attempts[-1], dict):
                continue
            attempt = unit_attempts[-1]
            machine_id = str(attempt.get("machine_id") or unit.get("assigned_machine_id") or "")
            delivery = _delivery_unknown_identity(job_id, unit, attempt)
            if delivery is not None:
                deliveries.append(delivery)
                continue
            if (
                not machine_id
                or attempt.get("state") != "reconcile_pending"
                or not attempt.get("execution_started")
                or attempt.get("execution_completed")
            ):
                raise RuntimeError("invalid execution quarantine evidence")
            attempts.append({
                "attempt_id": str(attempt.get("attempt_id") or ""),
                "job_id": str(job_id),
                "work_unit_id": str(unit.get("work_unit_id") or ""),
                "machine_id": machine_id,
                "external_run_id": attempt.get("external_run_id"),
                "reconciliation_class": "execution_quarantine",
            })
    attempts.sort(key=lambda item: item["attempt_id"])
    deliveries.sort(key=lambda item: (item["job_id"], item["work_unit_id"], item["attempt_id"]))
    return {
        "attempt_count": len(attempts),
        "machine_ids": sorted({item["machine_id"] for item in attempts}),
        "attempts": attempts,
        "reconciliation_snapshot": {
            "unit_count": pending_snapshot["unit_count"],
            "identity_sha256": pending_snapshot["identity_sha256"],
        },
        "delivery_unknown": {
            "attempt_count": len(deliveries),
            "machine_ids": sorted({item["machine_id"] for item in deliveries}),
            "attempts": deliveries,
        },
    }


def _verify_hotfix_continuity(database: Path, before: dict) -> dict:
    """Ensure a Control Plane restart did not terminally fail active science."""
    expected = {
        item["attempt_id"]: item
        for item in before.get("attempts") or []
        if item.get("execution_started") or (
            not item.get("execution_completed") and (
                item.get("remote_run_allocated") is True
                or (item.get("state") == "reconcile_pending" and item.get("external_run_id")
                    and _canonical_submission_unknown_reason(item.get("failure_reason")))
            )
        )
    }
    allocated_delivery = {key: item for key, item in expected.items() if not item.get("execution_started")}
    for item in allocated_delivery.values():
        if any(not isinstance(item.get(key), str) or not item[key].strip() for key in (
            "job_id", "work_unit_id", "attempt_id", "machine_id", "external_run_id",
        )):
            raise RuntimeError("hotfix continuity failed: invalid allocated delivery identity")
    if not expected:
        return {
            "verified": True,
            "execution_started_before": 0,
            "allocated_delivery_before": 0,
            "preserved_or_completed": 0,
            "terminal_failures": [],
            "missing_attempt_ids": [],
        }

    observed: dict[str, str] = {}
    mismatched_deliveries: set[str] = set()
    for job_id, _status, raw_payload in _job_payload_rows(
        database, job_ids={str(item["job_id"]) for item in expected.values()},
    ):
        payload = json.loads(raw_payload) if isinstance(raw_payload, str) else raw_payload
        if not isinstance(payload, dict):
            continue
        for unit in payload.get("work_units") or []:
            if not isinstance(unit, dict):
                continue
            for attempt in unit.get("attempts") or []:
                if not isinstance(attempt, dict):
                    continue
                attempt_id = str(attempt.get("attempt_id") or "")
                if attempt_id in expected:
                    observed[attempt_id] = str(attempt.get("state") or "")
                    if attempt_id in allocated_delivery:
                        original = allocated_delivery[attempt_id]
                        binding = {
                            "job_id": str(job_id), "work_unit_id": unit.get("work_unit_id"),
                            "machine_id": attempt.get("machine_id"),
                            "external_run_id": attempt.get("external_run_id"),
                        }
                        if (
                            any(binding[key] != original[key] for key in binding)
                            or attempt is not (unit.get("attempts") or [None])[-1]
                            or attempt.get("state") not in ACTIVE_ATTEMPT_STATES | {"completed"}
                            or unit.get("status") in {"queued", "failed", "cancelled"}
                        ):
                            mismatched_deliveries.add(attempt_id)

    missing = sorted(set(expected) - set(observed))
    terminal_failures = sorted(
        attempt_id
        for attempt_id, state in observed.items()
        if state in {"failed", "cancelled", "abandoned"}
    )
    if missing or terminal_failures or mismatched_deliveries:
        raise RuntimeError(
            "hotfix continuity failed: "
            f"missing={len(missing)}, terminal_failures={len(terminal_failures)}, "
            f"delivery_identity_changes={len(mismatched_deliveries)}"
        )
    return {
        "verified": True,
        "execution_started_before": len(expected) - len(allocated_delivery),
        "allocated_delivery_before": len(allocated_delivery),
        "allocated_delivery_identities": [allocated_delivery[key] for key in sorted(allocated_delivery)],
        "preserved_or_completed": len(observed),
        "terminal_failures": [],
        "missing_attempt_ids": [],
    }


def _runtime_python(runtime_root: Path) -> Path:
    candidates = (
        runtime_root / "Scripts" / "python.exe",
        runtime_root / "bin" / "python",
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise FileNotFoundError(f"runtime Python executable not found under {runtime_root}")


def _task_xml_summary(xml_path: Path) -> dict:
    if not xml_path.is_file():
        return {"captured": False}
    root = ET.fromstring(xml_path.read_text(encoding="utf-16"))
    namespace = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
    value = lambda path: (root.findtext(path, default="", namespaces=namespace) or "").strip()
    return {
        "captured": True,
        "xml_path": str(xml_path),
        "sha256": _sha256(xml_path),
        "principal_id": value(".//t:Principals/t:Principal/t:UserId"),
        "command": value(".//t:Actions/t:Exec/t:Command"),
        "arguments": value(".//t:Actions/t:Exec/t:Arguments"),
    }


def _export_task_xml(task_name: str, destination: Path) -> dict:
    if os.name != "nt" or shutil.which("schtasks.exe") is None:
        return {"captured": False, "reason": "Windows Task Scheduler unavailable"}
    completed = subprocess.run(
        ["schtasks.exe", "/Query", "/TN", task_name, "/XML"],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0:
        raise RuntimeError((completed.stderr or completed.stdout or "scheduled task export failed").strip())
    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = destination.with_name(destination.name + "." + uuid.uuid4().hex + ".partial")
    try:
        with partial.open("w", encoding="utf-16") as stream:
            stream.write(completed.stdout)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(partial, destination)
    finally:
        partial.unlink(missing_ok=True)
    return _task_xml_summary(destination)


def _default_http_get(url: str, token: str) -> dict:
    request = Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urlopen(request, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        raise RuntimeError(f"authenticated probe returned HTTP {exc.code} for {url}") from exc
    except (URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"authenticated probe failed for {url}: {type(exc).__name__}") from exc
    if not isinstance(payload, dict) and not isinstance(payload, list):
        raise RuntimeError(f"authenticated probe returned invalid JSON for {url}")
    return payload


def _service_is_reachable(service_url: str) -> bool:
    parsed = urlparse(service_url)
    host = parsed.hostname
    port = parsed.port
    if host is None or port is None:
        raise ValueError("service URL must include a host and port")
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


def _stopped_release_evidence(
    *,
    database: Path,
    service_url: str,
    scheduled_task: dict,
) -> dict:
    """Prove a maintenance-stopped service cannot retain a live lease."""

    if _service_is_reachable(service_url):
        raise RuntimeError("Control Plane is still reachable; do not use service-already-stopped mode")
    command = str(scheduled_task.get("command") or "")
    if command and _manager_host_running(command):
        raise RuntimeError("Control Plane manager is still running")

    connection = sqlite3.connect(str(database))
    try:
        try:
            row = connection.execute(
                "SELECT owner_id, expires_at FROM dispatcher_leases WHERE lease_name = 'dispatcher'"
            ).fetchone()
        except sqlite3.OperationalError as exc:
            if "no such table" not in str(exc).lower():
                raise
            row = None
    finally:
        connection.close()
    lease_owner = None
    lease_expires_at = None
    if row is not None:
        lease_owner = str(row[0] or "")
        lease_expires_at = str(row[1] or "")
        parsed_expiry = datetime.fromisoformat(lease_expires_at.replace("Z", "+00:00"))
        if parsed_expiry.tzinfo is None:
            parsed_expiry = parsed_expiry.replace(tzinfo=timezone.utc)
        if parsed_expiry > _utc_now():
            raise RuntimeError("Dispatcher lease is still active; stopped release is unsafe")
    return {
        "verified": True,
        "service_unreachable": True,
        "manager_process_absent": True,
        "dispatcher_lease_owner": lease_owner,
        "dispatcher_lease_expired_at": lease_expires_at,
        "verified_at": _utc_now().isoformat(),
    }


def _default_http_post(url: str, token: str, payload: dict) -> dict:
    request = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=190) as response:
            result = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        raise RuntimeError(f"authenticated control returned HTTP {exc.code} for {url}") from exc
    except (URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"authenticated control failed for {url}: {type(exc).__name__}") from exc
    if not isinstance(result, dict):
        raise RuntimeError(f"authenticated control returned invalid JSON for {url}")
    return result


def _default_http_put(url: str, token: str, payload: dict) -> dict:
    request = Request(url, data=json.dumps(payload).encode("utf-8"),
                      headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                      method="PUT")
    with urlopen(request, timeout=30) as response:
        result = json.loads(response.read().decode("utf-8"))
    if not isinstance(result, dict):
        raise RuntimeError("release maintenance returned invalid JSON")
    return result


def _maintenance_url(manifest: dict) -> str:
    return (manifest["service_url"].rstrip("/") + "/v1/admin/release-maintenance/"
            + manifest["maintenance"]["operation_id"])


def _drain_transfers(path, manifest, *, token, http_get, http_put, timeout_s, interval_s):
    operation = manifest.setdefault("maintenance", {
        "operation_id": str(uuid.uuid4()),
        "contract": {"transaction_id": manifest["transaction_id"],
                     "candidate_deployment_id": manifest["candidate_pointer"]["deployment_id"],
                     "drain_timeout_s": float(timeout_s)},
    })
    url = _maintenance_url(manifest)
    _atomic_json(path, manifest)
    try:
        receipt = _intent(path, manifest, "maintenance_begin",
                          lambda: http_put(url, token, operation["contract"]))
        if receipt.get("gate_protocol") != "durable-transfer-gate-v1":
            raise RuntimeError("release maintenance gate capability is not confirmed")
        if receipt.get("state") == "released":
            raise RuntimeError("maintenance operation was already released; reconcile this transaction")
        deadline = time.monotonic() + max(0, timeout_s)
        while True:
            receipt = http_get(url, token)
            if (receipt.get("gate_protocol") != "durable-transfer-gate-v1"
                    or receipt.get("operation_id") != operation["operation_id"]
                    or receipt.get("contract") != operation["contract"]
                    or receipt.get("admission_closed") is not True):
                raise RuntimeError("release maintenance gate receipt does not match the original contract")
            operation["last_observation"] = receipt
            _atomic_json(path, manifest)
            if receipt.get("state") == "drained" and receipt.get("active_transfers") == 0:
                return True
            if time.monotonic() >= deadline:
                manifest.update(state="deferred", stage="maintenance_drain", deferred_reason="active_transfers")
                _atomic_json(path, manifest)
                return False
            time.sleep(min(max(0.01, interval_s), max(0, deadline - time.monotonic())))
    except HTTPError as exc:
        if exc.code in {404, 405, 501}:
            manifest.update(state="deferred", stage="maintenance_bootstrap_required",
                            deferred_reason="old_center_requires_gate_bootstrap")
            manifest["maintenance"]["bootstrap_evidence"] = {"gate_supported": False, "http_status": exc.code}
            _atomic_json(path, manifest)
            return False
        raise


def _release_maintenance(path, manifest, *, token, http_post):
    if "maintenance" in manifest:
        if (manifest.get("bootstrap_gate_evidence")
                and _pointer_value(Path(manifest["pointer_path"])) == manifest.get("previous_pointer")):
            from .release_maintenance import get_transfer_gate
            return _intent(path, manifest, "maintenance_release", lambda: get_transfer_gate(
                manifest["state_root"]).release(manifest["maintenance"]["operation_id"]))
        return _intent(path, manifest, "maintenance_release",
                       lambda: http_post(_maintenance_url(manifest) + "/release", token, {}))


def _dispatcher_control_action(
    *,
    service_url: str,
    token: str,
    action: str,
    reason: str,
    http_post: HttpPost,
) -> dict:
    base = service_url.rstrip("/")
    preview = http_post(
        f"{base}/v1/admin/dispatcher-controls/preview",
        token,
        {"action": action, "reason": reason},
    )
    ticket_id = preview.get("ticket_id")
    confirmation_hash = preview.get("confirmation_hash")
    if not ticket_id or not confirmation_hash:
        raise RuntimeError(f"Dispatcher {action} preview returned no confirmation ticket")
    return http_post(
        f"{base}/v1/admin/dispatcher-controls/confirm",
        token,
        {"ticket_id": ticket_id, "confirmation_hash": confirmation_hash},
    )


def _manager_host_running(command: str) -> bool:
    expected = Path(command).resolve()
    for process in psutil.process_iter(["exe", "cmdline"]):
        try:
            executable = process.info.get("exe")
            arguments = process.info.get("cmdline") or []
            if (
                executable
                and Path(executable).resolve() == expected
                and any(str(value).lower() == "--run" for value in arguments[1:])
            ):
                return True
        except (OSError, psutil.Error):
            continue
    return False


def _wait_for_manager_host_exit(command: str, *, timeout_s: float = 15.0) -> None:
    deadline = time.monotonic() + max(0.0, timeout_s)
    while _manager_host_running(command):
        if time.monotonic() >= deadline:
            raise RuntimeError("Control Plane manager did not stop before the restart deadline")
        time.sleep(0.2)


def _coordinator_guard_config(command: str, arguments: str) -> str | None:
    """Recognize only the fixed opt-in coordinator guard task contract."""
    if Path(command).name.lower() != "python.exe":
        return None
    match = re.fullmatch(
        r'-I\s+-m\s+research_compute_network\.coordinator_supervision\s+--config\s+"([^"\r\n]+)"\s+--action\s+run',
        arguments,
    )
    return match.group(1) if match else None


def _coordinator_guard_action(command: str, config: str, action: str) -> None:
    result = subprocess.run(
        [command, "-I", "-m", "research_compute_network.coordinator_supervision",
         "--config", config, "--action", action],
        capture_output=True, text=True, errors="replace", check=False, timeout=45,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode != 0:
        raise RuntimeError(f"coordinator guard {action} failed; no unscoped fallback")


def _validate_cooperative_guard(config: str) -> None:
    root = Path(config).resolve().parent
    try:
        state = _read_json(root / "supervision-state.json")
        if state.get("cooperative_shutdown_protocol") != "cooperative-guard-v1":
            raise ValueError("legacy guard has no cooperative exit capability")
        if state.get("child_pid") is not None:
            capability = _read_json(root / "cooperative-service.json")
            if (not state.get("generation") or capability.get("coordinator_generation") != state["generation"]):
                raise ValueError("guard/API generation does not match")
            process = psutil.Process(capability["pid"])
            if process.create_time() != capability["process_created"] or not process.is_running():
                raise ValueError("cooperative API process incarnation is no longer live")
            launcher = psutil.Process(state["child_pid"])
            if process.pid not in {launcher.pid, *(p.pid for p in launcher.children(recursive=True))}:
                raise ValueError("cooperative API is outside the recorded child tree")
    except psutil.NoSuchProcess as exc:
        # A cooperative shutdown may finish before its last advisory save.
        # Permit only the fully absent recorded tree; live/reused PIDs retain
        # the refusal and are never treated as the original service.
        pids = {state.get("wrapper_pid"), state.get("child_pid"), capability.get("pid")}
        if state.get("cooperative_shutdown_protocol") == "cooperative-guard-v1" and all(
                not psutil.pid_exists(pid) for pid in pids if type(pid) is int):
            return
        raise RuntimeError("old coordinator guard requires audited bootstrap before normal release") from exc
    except (OSError, ValueError, KeyError, psutil.Error) as exc:
        raise RuntimeError("old coordinator guard requires audited bootstrap before normal release") from exc


def _default_restart_task(task_name: str) -> None:
    if os.name != "nt" or shutil.which("schtasks.exe") is None:
        raise RuntimeError("Windows Task Scheduler is required to restart the formal Control Plane")
    query = subprocess.run(
        ["schtasks.exe", "/Query", "/TN", task_name, "/XML"],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    stopped_by_manager = False
    if query.returncode == 0:
        root = ET.fromstring(query.stdout)
        namespace = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
        command = (root.findtext(".//t:Actions/t:Exec/t:Command", default="", namespaces=namespace) or "").strip()
        arguments = (root.findtext(".//t:Actions/t:Exec/t:Arguments", default="", namespaces=namespace) or "").strip()
        pointer_match = re.search(r'--runtime-pointer\s+(?:"([^"]+)"|(\S+))', arguments, flags=re.IGNORECASE)
        guard_config = _coordinator_guard_config(command, arguments)
        if guard_config is not None:
            _validate_cooperative_guard(guard_config)
            _coordinator_guard_action(command, guard_config, "stop")
            _coordinator_guard_action(command, guard_config, "resume")
            stopped_by_manager = True
        elif Path(command).name.lower() == CONTROL_PLANE_MANAGER.lower() and pointer_match:
            pointer = pointer_match.group(1) or pointer_match.group(2)
            from .release_maintenance import cooperative_service_shutdown
            cooperative_service_shutdown(Path(pointer).resolve().parent.parent)
            _wait_for_manager_host_exit(command)
            stopped_by_manager = True
    if not stopped_by_manager:
        raise RuntimeError("cooperative shutdown unavailable; bootstrap the managed shutdown contract before release")
    _default_start_stopped_task(task_name)


def _default_start_stopped_task(task_name: str) -> None:
    """Start only after the caller's stopped-service evidence has passed."""
    if os.name != "nt" or shutil.which("schtasks.exe") is None:
        raise RuntimeError("Windows Task Scheduler is required to start the formal Control Plane")
    completed = subprocess.run(
        ["schtasks.exe", "/Run", "/TN", task_name],
        check=False,
        capture_output=True,
        text=True,
        errors="replace",
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0:
        raise RuntimeError((completed.stderr or completed.stdout or "scheduled task restart failed").strip())


def stop_control_plane_task(task_name: str) -> None:
    """Stop the managed Control Plane and wait until its GUI host releases state files."""
    if os.name != "nt" or shutil.which("schtasks.exe") is None:
        raise RuntimeError("Windows Task Scheduler is required to stop the formal Control Plane")
    query = subprocess.run(
        ["schtasks.exe", "/Query", "/TN", task_name, "/XML"],
        check=False, capture_output=True, text=True, encoding="utf-8", errors="replace",
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if query.returncode != 0:
        raise RuntimeError("unable to read the formal Control Plane task")
    root = ET.fromstring(query.stdout)
    namespace = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
    command = (root.findtext(".//t:Actions/t:Exec/t:Command", default="", namespaces=namespace) or "").strip()
    arguments = (root.findtext(".//t:Actions/t:Exec/t:Arguments", default="", namespaces=namespace) or "").strip()
    pointer_match = re.search(r'--runtime-pointer\s+(?:"([^"]+)"|(\S+))', arguments, flags=re.IGNORECASE)
    stopped = False
    guard_config = _coordinator_guard_config(command, arguments)
    if guard_config is not None:
        _validate_cooperative_guard(guard_config)
        _coordinator_guard_action(command, guard_config, "stop")
        return
    if Path(command).name.lower() == CONTROL_PLANE_MANAGER.lower() and pointer_match:
        pointer = pointer_match.group(1) or pointer_match.group(2)
        from .release_maintenance import cooperative_service_shutdown
        cooperative_service_shutdown(Path(pointer).resolve().parent.parent)
        _wait_for_manager_host_exit(command)
        stopped = True
    if not stopped:
        raise RuntimeError("cooperative shutdown unavailable; bootstrap the managed shutdown contract before release")


def _validate_runtime_root(state_root: Path, runtime_root: Path) -> Path:
    root = runtime_root.resolve()
    managed_root = (state_root.resolve() / "runtime").resolve()
    if not root.is_relative_to(managed_root):
        raise ValueError(f"runtime must be inside the managed runtime root: {managed_root}")
    _runtime_python(root)
    return root


def _process_incarnation(pid: int) -> dict:
    process = psutil.Process(int(pid))
    return {"pid": process.pid, "created": process.create_time()}


def record_bootstrap_gate_evidence(*, state_root, database, runtime_root, service_url, attestation: dict,
                                   token: str, task_name=CONTROL_PLANE_TASK, http_get=None) -> dict:
    """Record explicit operator quiescence for a center predating the gate.

    These are administrator attestations, never invented live request counts.
    No stop or scheduler mutation occurs in this recording step.
    """
    root = Path(state_root).resolve()
    if not service_url.startswith(("http://127.0.0.1:", "http://localhost:")):
        raise ValueError("bootstrap evidence supports only the registered loopback API")
    candidate = _validate_runtime_root(root, Path(runtime_root))
    required = {"all_origin_clients_paused", "old_api_requests_drained", "legacy_empty_api_stop_authorized"}
    if (not isinstance(attestation, dict) or any(attestation.get(key) is not True for key in required)
            or not isinstance(attestation.get("reason"), str) or not attestation["reason"].strip()):
        raise ValueError("bootstrap requires explicit client pause, idle API and legacy empty-API stop attestations")
    get = http_get or _default_http_get
    me = get(service_url.rstrip("/") + "/v1/me", token)
    if "admin" not in me.get("roles", []) or not me.get("actor_id"):
        raise PermissionError("bootstrap evidence requires an authenticated administrator")
    pointer_path = root / "runtime/current.json"
    pointer = _read_json(pointer_path)
    runtime = get(service_url.rstrip("/") + "/v1/execution-runtime", token)
    if runtime.get("control_plane_deployment_id") != pointer.get("deployment_id"):
        raise RuntimeError("bootstrap observation does not match the current runtime pointer")
    evidence_id = str(uuid.uuid4())
    directory = root / "releases" / "bootstrap-evidence"
    directory.mkdir(parents=True, exist_ok=True)
    task = _export_task_xml(task_name, directory / (evidence_id + ".task.xml"))
    config = _coordinator_guard_config(task.get("command", ""), task.get("arguments", ""))
    expected_config = root / "startup/supervision.json"
    if (not config or Path(config).resolve() != expected_config
            or task.get("principal_id", "").upper() not in {"SYSTEM", "S-1-5-18"}):
        raise ValueError("bootstrap supports only the registered guarded coordinator task")
    guard_state = _read_json(root / "startup/supervision-state.json")
    now = _utc_now()
    evidence = {"protocol": "operator-quiescence-bootstrap-v1", "evidence_id": evidence_id,
        "evidence_kind": "administrator_attestation_not_server_transfer_gate",
        "state_root": str(root), "database": str(Path(database).resolve()),
        "candidate_runtime_root": str(candidate), "service_url": service_url.rstrip("/"),
        "actor_id": me["actor_id"], "attestation": {**{key: True for key in required}, "reason": attestation["reason"]},
        "created_at": now.isoformat(), "expires_at": datetime.fromtimestamp(now.timestamp() + 900, timezone.utc).isoformat(),
        "previous_pointer": pointer, "pointer_sha256": _sha256(pointer_path),
        "task_name": task_name, "scheduled_task": task, "guard_config_sha256": _sha256(expected_config),
        "guard": _process_incarnation(guard_state["wrapper_pid"]),
        "api_launcher": _process_incarnation(guard_state["child_pid"]),
        "scientific_attempt_snapshot": _active_execution_snapshot(Path(database).resolve()),
        "runtime_observation": {key: runtime.get(key) for key in ("control_plane_deployment_id", "worker_runtime_version", "package_version")},
        "scientific_process_stop_authorized": False}
    destination = directory / (evidence_id + ".json")
    _atomic_json(destination, evidence)
    return {"evidence_path": str(destination), "sha256": _sha256(destination), "receipt": evidence}


def _validate_bootstrap_gate_evidence(path: Path, manifest: dict, *, check_processes=True) -> dict:
    evidence = _read_json(path)
    if (evidence.get("protocol") != "operator-quiescence-bootstrap-v1"
            or evidence.get("evidence_kind") != "administrator_attestation_not_server_transfer_gate"
            or manifest["release_mode"] not in {"hotfix", "additive"}
            or manifest["verification_policy"].get("service_already_stopped")):
        raise ValueError("bootstrap evidence is only valid for a live scientific-continuity release")
    if manifest.get("preparation_inputs", {}).get("validate_candidate_schema") is not True:
        raise ValueError("bootstrap requires the normal candidate schema validation")
    bindings = {"state_root": manifest["state_root"], "database": manifest["database"],
                "candidate_runtime_root": manifest["candidate_pointer"]["runtime_root"],
                "service_url": manifest["service_url"], "task_name": manifest["task_name"],
                "previous_pointer": manifest["previous_pointer"]}
    if any(evidence.get(key) != value for key, value in bindings.items()):
        raise ValueError("bootstrap evidence does not bind this exact release")
    created = datetime.fromisoformat(evidence["created_at"])
    expires = datetime.fromisoformat(evidence["expires_at"])
    if (created.tzinfo is None or expires.tzinfo is None or created > _utc_now()
            or (check_processes and expires <= _utc_now()) or not 0 < (expires - created).total_seconds() <= 900):
        raise ValueError("bootstrap quiet-window evidence expired or is invalid")
    for key in ("all_origin_clients_paused", "old_api_requests_drained", "legacy_empty_api_stop_authorized"):
        if evidence.get("attestation", {}).get(key) is not True:
            raise ValueError("bootstrap quiet-window authorization is incomplete")
    root = Path(manifest["state_root"])
    task_receipt = evidence["scheduled_task"]
    if _sha256(Path(task_receipt["xml_path"])) != task_receipt["sha256"]:
        raise ValueError("bootstrap original task XML changed")
    if _sha256(root / "startup/supervision.json") != evidence["guard_config_sha256"]:
        raise ValueError("bootstrap guard configuration changed")
    if check_processes:
        if _sha256(Path(manifest["pointer_path"])) != evidence["pointer_sha256"]:
            raise ValueError("bootstrap runtime pointer changed")
        for field in ("guard", "api_launcher"):
            if _process_incarnation(evidence[field]["pid"]) != evidence[field]:
                raise ValueError("bootstrap process incarnation changed")
    return evidence


def _bootstrap_stop_empty_api(manifest: dict) -> dict:
    binding = manifest["bootstrap_gate_evidence"]
    evidence = _validate_bootstrap_gate_evidence(Path(binding["path"]), manifest, check_processes=False)
    task = manifest["scheduled_task"]
    config = _coordinator_guard_config(task.get("command", ""), task.get("arguments", ""))
    if (not config or Path(config).resolve() != Path(manifest["state_root"]) / "startup/supervision.json"
            or task.get("command") != evidence["scheduled_task"].get("command")
            or task.get("arguments") != evidence["scheduled_task"].get("arguments")
            or task.get("sha256") != evidence["scheduled_task"].get("sha256")):
        raise ValueError("bootstrap task differs from the attested original task")
    try:
        observed_api = _process_incarnation(evidence["api_launcher"]["pid"])
        if observed_api != evidence["api_launcher"]:
            raise RuntimeError("bootstrap API process incarnation changed; preserve the new process")
        api_alive = True
    except psutil.NoSuchProcess:
        api_alive = False
    if api_alive:
        _validate_bootstrap_gate_evidence(Path(binding["path"]), manifest)
    if api_alive or _process_alive(evidence["guard"]):
        current_state = _read_json(Path(manifest["state_root"]) / "startup/supervision-state.json")
        if current_state.get("child_pid") not in {None, evidence["api_launcher"]["pid"]}:
            raise RuntimeError("bootstrap guard launched a different API; new quiescence evidence is required")
        _coordinator_guard_action(task["command"], config, "stop")
    result = _stopped_release_evidence(database=Path(manifest["database"]),
        service_url=manifest["service_url"], scheduled_task=task)
    result.update(stop_mechanism="attested_legacy_guard_empty_api_stop",
                  old_server_gate_supported=False, remote_scientific_processes_stopped=False)
    result["scientific_continuity"] = _verify_hotfix_continuity(Path(manifest["database"]),
        manifest["bootstrap_active_execution_at_handoff"])
    return result


def _process_alive(identity: dict) -> bool:
    try:
        return _process_incarnation(identity["pid"]) == identity
    except psutil.NoSuchProcess:
        return False


def _bootstrap_admission(path, manifest, *, token, http_get, timeout_s):
    from .release_maintenance import get_transfer_gate
    binding = manifest["bootstrap_gate_evidence"]
    if _sha256(Path(binding["path"])) != binding["sha256"]:
        raise ValueError("bootstrap evidence changed after prepare")
    stop_pending = "bootstrap_empty_api_stop" in manifest.get("journal", {})
    evidence = _validate_bootstrap_gate_evidence(Path(binding["path"]), manifest,
                                                check_processes=not stop_pending)
    if not stop_pending:
        me = http_get(manifest["service_url"] + "/v1/me", token)
        if me.get("actor_id") != evidence["actor_id"] or "admin" not in me.get("roles", []):
            raise PermissionError("bootstrap requires the original authenticated administrator")
    maintenance = manifest.setdefault("maintenance", {"operation_id": str(uuid.uuid4()), "contract": {
        "transaction_id": manifest["transaction_id"],
        "candidate_deployment_id": manifest["candidate_pointer"]["deployment_id"],
        "drain_timeout_s": float(timeout_s)}})
    receipt = _intent(path, manifest, "maintenance_begin", lambda: get_transfer_gate(manifest["state_root"]).begin(
        maintenance["operation_id"], maintenance["contract"], actor_id=evidence["actor_id"]))
    maintenance["bootstrap_admission"] = {"old_server_gate_supported": False,
        "old_api_idle_basis": "administrator_coordinated_quiescence", "evidence_sha256": binding["sha256"],
        "new_server_gate_receipt": receipt}
    _atomic_json(path, manifest)
    return receipt["active_transfers"] == 0


def _bootstrap_upgrade_guard(manifest: dict) -> dict:
    """Preserve the registered task settings; replace only its fixed guard runtime."""
    source = Path(manifest["scheduled_task"]["xml_path"])
    if _sha256(source) != manifest["scheduled_task"]["sha256"]:
        raise ValueError("prepared bootstrap task XML changed")
    tree = ET.parse(source)
    ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
    commands = tree.findall(".//t:Actions/t:Exec", ns)
    instances = tree.findtext(".//t:Settings/t:MultipleInstancesPolicy", default="IgnoreNew", namespaces=ns)
    if instances != "IgnoreNew":
        raise ValueError("bootstrap requires the registered IgnoreNew task instance policy")
    if len(commands) != 1:
        raise ValueError("bootstrap requires exactly one registered guard action")
    action = commands[0]
    action.find("t:Command", ns).text = manifest["candidate_pointer"]["python_executable"]
    config = str(Path(manifest["state_root"]) / "startup/supervision.json")
    action.find("t:Arguments", ns).text = f'-I -m research_compute_network.coordinator_supervision --config "{config}" --action run'
    target = Path(manifest["manifest_path"]).parent / "bootstrap-guard-task.xml"
    tree.write(target, encoding="utf-16", xml_declaration=True)
    probe_path = target.with_name("bootstrap-guard-current.xml")
    _export_task_xml(manifest["task_name"], probe_path)
    observed = ET.tostring(ET.parse(probe_path).getroot())
    intended = ET.tostring(tree.getroot())
    if observed == intended:
        return {"guard_runtime": manifest["candidate_pointer"]["runtime_root"],
                "task_xml_sha256": _sha256(target), "already_registered": True}
    if observed != ET.tostring(ET.parse(source).getroot()):
        raise RuntimeError("registered task changed; bootstrap refuses to overwrite another configuration")
    checked = subprocess.run([manifest["candidate_pointer"]["python_executable"], "-I", "-c",
        "from research_compute_network.coordinator_supervision import CoordinatorGuard; "
        "assert callable(CoordinatorGuard.cooperative_stop_child)"],
        check=False, capture_output=True, text=True, errors="replace", timeout=30,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if checked.returncode != 0:
        raise RuntimeError("bootstrap candidate does not provide the cooperative guard")
    completed = subprocess.run(["schtasks.exe", "/Create", "/TN", manifest["task_name"], "/XML", str(target), "/F"],
        check=False, capture_output=True, text=True, errors="replace",
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if completed.returncode != 0:
        raise RuntimeError("bootstrap guard registration not confirmed; recover the original manifest")
    return {"guard_runtime": manifest["candidate_pointer"]["runtime_root"], "task_xml_sha256": _sha256(target),
            "preserved_original_task": str(source)}


def _bootstrap_restore_guard_task(manifest: dict) -> dict:
    """Restore the exact original task before any legacy API is relaunched."""
    source = Path(manifest["scheduled_task"]["xml_path"])
    if _sha256(source) != manifest["scheduled_task"]["sha256"]:
        raise ValueError("original bootstrap task XML changed")
    original = ET.tostring(ET.parse(source).getroot())
    upgraded = source.with_name("bootstrap-guard-task.xml")
    observed_path = source.with_name("rollback-guard-current.xml")
    _export_task_xml(manifest["task_name"], observed_path)
    observed = ET.tostring(ET.parse(observed_path).getroot())
    if observed == original:
        return {"original_task_restored": True, "already_restored": True,
                "original_task_sha256": manifest["scheduled_task"]["sha256"]}
    if not upgraded.exists() or observed != ET.tostring(ET.parse(upgraded).getroot()):
        raise RuntimeError("registered task changed; refuse to overwrite another coordinator configuration")
    completed = subprocess.run(["schtasks.exe", "/Create", "/TN", manifest["task_name"], "/XML", str(source), "/F"],
        check=False, capture_output=True, text=True, errors="replace",
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if completed.returncode != 0:
        raise RuntimeError("original coordinator task restoration is unconfirmed; recover the same manifest")
    _export_task_xml(manifest["task_name"], observed_path)
    if ET.tostring(ET.parse(observed_path).getroot()) != original:
        raise RuntimeError("original coordinator task readback differs; legacy API was not restarted")
    return {"original_task_restored": True, "original_task_sha256": manifest["scheduled_task"]["sha256"]}


def _bootstrap_stop_new_guard(manifest: dict) -> dict:
    # This is the new cooperative implementation, even if the old task was not
    # upgraded yet. It writes the fixed marker and waits for the scoped guard.
    config = str(Path(manifest["state_root"]) / "startup/supervision.json")
    _coordinator_guard_action(manifest["candidate_pointer"]["python_executable"], config, "stop")
    return _stopped_release_evidence(database=Path(manifest["database"]),
        service_url=manifest["service_url"], scheduled_task=manifest["scheduled_task"])


def _bootstrap_resume_original_guard(manifest: dict) -> None:
    task = manifest["scheduled_task"]
    config = _coordinator_guard_config(task["command"], task["arguments"])
    if not config:
        raise ValueError("original task has no fixed guard contract")
    _coordinator_guard_action(task["command"], config, "resume")


def prepare_control_plane_release(
    *,
    state_root: str | Path,
    database: str | Path,
    runtime_root: str | Path,
    service_url: str = "http://127.0.0.1:8765",
    task_name: str = CONTROL_PLANE_TASK,
    wheel: str | Path | None = None,
    expected_machine_count: int = 5,
    deployment_id: str | None = None,
    worker_runtime_version: str = STABLE_RUNTIME_VERSION,
    release_mode: str = "standard",
    candidate_runtime_versions: Iterable[str] | None = None,
    validate_candidate_schema: bool = True,
    allowed_quarantined_machine_ids: Iterable[str] = (),
    allowed_maintenance_machine_ids: Iterable[str] = (),
    service_already_stopped: bool = False,
    machine_health_grace_s: float = 300.0,
    bootstrap_gate_evidence: str | Path | None = None,
) -> dict:
    """Journal preparation before generating artifacts; never mutate live execution."""

    root = Path(state_root).resolve()
    database_path = Path(database).resolve()
    candidate_root = _validate_runtime_root(root, Path(runtime_root))
    python_executable = _runtime_python(candidate_root)
    if expected_machine_count < 1:
        raise ValueError("expected machine count must be positive")
    if not service_url.startswith(("http://127.0.0.1:", "http://localhost:")):
        raise ValueError("automated release verification currently supports loopback service URLs only")

    pointer_path = root / "runtime" / "current.json"
    previous_pointer = _read_json(pointer_path) if pointer_path.is_file() else None
    if release_mode not in {"standard", "hotfix", "additive"}:
        raise ValueError("release mode must be 'standard', 'hotfix', or 'additive'")
    if release_mode == "additive" and not validate_candidate_schema:
        raise ValueError("an additive release requires candidate schema validation")
    allowed_quarantined = sorted({
        str(machine_id).strip()
        for machine_id in allowed_quarantined_machine_ids
        if str(machine_id).strip()
    })
    allowed_maintenance = sorted({
        str(machine_id).strip()
        for machine_id in allowed_maintenance_machine_ids
        if str(machine_id).strip()
    })
    if service_already_stopped and release_mode != "standard":
        raise ValueError("service-already-stopped mode is only valid for a standard release")
    machine_health_grace_s = float(machine_health_grace_s)
    if machine_health_grace_s < 0:
        raise ValueError("machine health grace must not be negative")
    if release_mode in {"hotfix", "additive"}:
        if previous_pointer is None:
            raise ValueError(f"a {release_mode} requires an existing live runtime pointer")
        live_worker_runtime = str(previous_pointer.get("worker_runtime_version") or "")
        if not live_worker_runtime:
            raise ValueError("the live runtime pointer does not identify its Worker runtime")
        if worker_runtime_version not in {STABLE_RUNTIME_VERSION, live_worker_runtime}:
            raise ValueError(f"a Control Plane {release_mode} cannot change the Worker runtime")
        worker_runtime_version = live_worker_runtime
    if candidate_runtime_versions is None:
        candidate_versions = (
            list(previous_pointer.get("candidate_runtime_versions") or [])
            if release_mode in {"hotfix", "additive"} and previous_pointer
            else []
        )
    else:
        candidate_versions = sorted({
            str(version).strip()
            for version in candidate_runtime_versions
            if str(version).strip()
        })
    RuntimePolicy.with_candidates(candidate_versions)
    candidate_pointer = {
        "schema_version": 1,
        "deployment_id": deployment_id or candidate_root.name,
        "package_version": PACKAGE_VERSION,
        "worker_runtime_version": worker_runtime_version,
        "runtime_root": str(candidate_root),
        "python_executable": str(python_executable),
        "database_url": f"sqlite:///{database_path.as_posix()}",
        "host": "127.0.0.1",
        "port": int(service_url.rsplit(":", 1)[-1]),
        "require_auth": True,
        "candidate_runtime_versions": candidate_versions,
        "created_at": _utc_now().isoformat(),
    }

    transaction_id = f"deploy-{_utc_now().strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
    transaction_root = root / "releases" / "deployments" / transaction_id
    transaction_root.mkdir(parents=True, exist_ok=False)
    manifest_path = transaction_root / "deployment-manifest.json"
    manifest = {
        "schema_version": 2, "transaction_id": transaction_id, "state": "preparing",
        "release_mode": release_mode, "state_root": str(root), "database": str(database_path),
        "task_name": task_name, "pointer_path": str(pointer_path), "previous_pointer": previous_pointer,
        "candidate_pointer": candidate_pointer, "service_url": service_url.rstrip("/"),
        "expected_machine_count": expected_machine_count, "manifest_path": str(manifest_path),
        "preparation_inputs": {"wheel_path": str(Path(wheel).resolve()) if wheel is not None else None,
            "validate_candidate_schema": validate_candidate_schema,
            "bootstrap_gate_evidence_path": str(Path(bootstrap_gate_evidence).resolve()) if bootstrap_gate_evidence is not None else None},
        "verification_policy": {"allowed_quarantined_machine_ids": allowed_quarantined,
            "allowed_maintenance_machine_ids": allowed_maintenance,
            "service_already_stopped": service_already_stopped,
            "machine_health_grace_s": machine_health_grace_s},
        "verification": None, "rollback": None,
    }
    _atomic_json(manifest_path, manifest)
    with _release_lock(pointer_path):
        return _finish_release_preparation(manifest_path, manifest)


def _preparation_backup(source: Path, target: Path) -> dict:
    if not target.exists():
        # An incomplete disposable SQLite backup is never published as a
        # completed snapshot. Each replay retains any earlier partial file.
        partial = target.with_name(target.name + ".partial-" + uuid.uuid4().hex)
        _online_backup(source, partial)
        with partial.open("r+b") as stream:
            os.fsync(stream.fileno())
        os.replace(partial, target)
    _sqlite_integrity(target)
    return {"path": str(target), "size_bytes": target.stat().st_size, "sha256": _sha256(target)}


def _finish_release_preparation(path: Path, manifest: dict) -> dict:
    """Replay only read probes and isolated artifact generation, never controls."""
    if manifest["state"] == "prepared":
        return manifest
    if manifest["state"] != "preparing":
        raise ValueError("only an incomplete preparation can be resumed here")
    if _pointer_value(Path(manifest["pointer_path"])) != manifest.get("previous_pointer"):
        raise RuntimeError("runtime pointer changed during preparation; preserve this transaction for review")
    root, database = path.parent, Path(manifest["database"])
    candidate = manifest["candidate_pointer"]
    python = Path(candidate["python_executable"])
    inputs, policy = manifest["preparation_inputs"], manifest["verification_policy"]
    mode = manifest["release_mode"]
    if inputs.get("bootstrap_gate_evidence_path"):
        evidence_path = Path(inputs["bootstrap_gate_evidence_path"])
        def bind_bootstrap():
            evidence = _validate_bootstrap_gate_evidence(evidence_path, manifest)
            return {"path": str(evidence_path), "sha256": _sha256(evidence_path), "receipt": evidence,
                    "scientific_continuity_at_prepare": _verify_hotfix_continuity(database, evidence["scientific_attempt_snapshot"])}
        manifest["bootstrap_gate_evidence"] = _intent(path, manifest, "prepare_bootstrap_evidence", bind_bootstrap)
    manifest["database_integrity"] = _intent(path, manifest, "prepare_integrity", lambda: _sqlite_integrity(database))
    def export():
        target = root / "scheduled-task.xml"
        # A completed export survives a crash before its journal receipt.
        return _task_xml_summary(target) if target.exists() else _export_task_xml(manifest["task_name"], target)
    manifest["scheduled_task"] = _intent(path, manifest, "prepare_task_export", export)
    if manifest["scheduled_task"].get("captured") and manifest["scheduled_task"].get("sha256"):
        if _sha256(Path(manifest["scheduled_task"]["xml_path"])) != manifest["scheduled_task"]["sha256"]:
            raise ValueError("saved task export changed during preparation")
    if manifest.get("bootstrap_gate_evidence") and manifest["scheduled_task"].get("sha256") != manifest["bootstrap_gate_evidence"]["receipt"]["scheduled_task"]["sha256"]:
        raise ValueError("registered task changed since the bootstrap quiet-window observation")
    manifest["active_execution_before"] = _intent(path, manifest, "prepare_active_snapshot", lambda: _active_execution_snapshot(database))
    unfinished = _intent(path, manifest, "prepare_unfinished_snapshot", lambda: _unfinished_execution_snapshot(database))
    manifest["unfinished_execution_before"] = unfinished
    unknown = sorted(set(policy["allowed_quarantined_machine_ids"]) - set(unfinished["machine_ids"]))
    if unknown:
        raise ValueError("quarantine allowlist lacks unfinished execution evidence: " + ", ".join(unknown))
    manifest["stopped_state_evidence"] = (_intent(path, manifest, "prepare_stopped_evidence", lambda: _stopped_release_evidence(
        database=database, service_url=manifest["service_url"], scheduled_task=manifest["scheduled_task"]))
        if policy["service_already_stopped"] else None)
    backup = _intent(path, manifest, "prepare_backup", lambda: _preparation_backup(database, root / "control-plane.db.online-backup"))
    if _sha256(Path(backup["path"])) != backup["sha256"]:
        raise RuntimeError("prepared backup changed; preserve the original transaction")
    manifest["database_backup"] = backup
    hotfix_schema, additive_schema = None, None
    if mode == "hotfix" and inputs["validate_candidate_schema"]:
        def hotfix_probe():
            scratch = root / ("hotfix-probe-" + uuid.uuid4().hex + ".db")
            shutil.copy2(backup["path"], scratch)
            return _validate_hotfix_schema(python, scratch)
        hotfix_schema = _intent(path, manifest, "prepare_hotfix_schema", hotfix_probe)
    if mode == "additive":
        additive_schema = _intent(path, manifest, "prepare_additive_schema", lambda: _validate_additive_schema(python, Path(backup["path"])))
    wheel_record, package_origin = None, None
    if inputs["wheel_path"]:
        wheel_path = Path(inputs["wheel_path"])
        wheel_record = _intent(path, manifest, "prepare_wheel_record", lambda: {
            "name": wheel_path.name, "size_bytes": wheel_path.stat().st_size, "sha256": _sha256(wheel_path)})
        if wheel_record["sha256"] != _sha256(wheel_path):
            raise ValueError("candidate wheel changed during preparation")
        package_origin = _intent(path, manifest, "prepare_package_origin", lambda: _validate_candidate_package_origin(python, Path(candidate["runtime_root"])))
    manifest.update(wheel=wheel_record, candidate_package_origin=package_origin,
        hotfix_contract=({"worker_runtime_unchanged": True,
            "database_schema_unchanged": bool(hotfix_schema and hotfix_schema["verified"]),
            "database_schema_sha256": hotfix_schema["schema_sha256"] if hotfix_schema else None,
            "remote_science_processes_terminated": False, "new_assignments_paused_during_restart": True}
            if mode == "hotfix" else None),
        additive_contract=({"worker_runtime_unchanged": True, "database_schema_compatible": True,
            "schema_validation": additive_schema, "remote_science_processes_terminated": False,
            "new_assignments_paused_during_restart": True, "rollback_database_strategy": "preserve_compatible_live_database"}
            if mode == "additive" else None),
        rollback_database_strategy="preserve_compatible_live_database" if mode == "additive" else None,
        state="prepared", prepared_at=_utc_now().isoformat(), stage="prepared")
    _atomic_json(path, manifest)
    return manifest


def _classify_machine_health(
    machines: list,
    *,
    allowed_quarantined: set[str],
    allowed_maintenance: set[str],
) -> dict:
    """Split machine states into healthy, transient jitter, and hard failure.

    Transient means the reverse-SSH tunnel or telemetry sampling is flapping
    while the supervisor is still online and the machine still accepts work —
    the documented self-healing home-fleet jitter class. Everything else,
    including an unpermitted maintenance state, is a hard failure.
    """

    healthy: list[str] = []
    transient: list[dict[str, Any]] = []
    hard: list[str] = []
    maintenance_only: list[str] = []
    for machine in machines:
        machine_id = str(machine.get("machine_id") or "unknown")
        status = machine.get("operational_status") or {}
        transport_ok = status.get("transport_state") == "connected"
        supervisor_online = status.get("supervisor_state") == "online"
        telemetry_live = status.get("telemetry_state") == "live"
        consistent = bool(status.get("observation_consistent", True))
        control = status.get("control_state")
        infrastructure_healthy = transport_ok and supervisor_online and telemetry_live and consistent
        if infrastructure_healthy and control == "maintenance":
            maintenance_only.append(machine_id)
            continue
        if infrastructure_healthy and control == "accepting":
            healthy.append(machine_id)
            continue
        if supervisor_online and control == "accepting" and not infrastructure_healthy:
            transient.append({
                "machine_id": machine_id,
                "transport_state": status.get("transport_state"),
                "supervisor_state": status.get("supervisor_state"),
                "telemetry_state": status.get("telemetry_state"),
                "control_state": control,
                "observation_consistent": consistent,
            })
            continue
        hard.append(machine_id)
    unpermitted_maintenance = set(maintenance_only) - set(allowed_maintenance)
    hard = sorted(set(hard) | unpermitted_maintenance)
    return {
        "healthy": sorted(healthy),
        "transient": transient,
        "hard": hard,
        "maintenance_only": sorted(maintenance_only),
        "permitted_maintenance": sorted(set(maintenance_only) & set(allowed_maintenance)),
    }


def verify_control_plane_release(
    *,
    database: str | Path,
    service_url: str,
    token: str,
    expected_machine_count: int = 5,
    http_get: HttpGet | None = None,
    now: datetime | None = None,
    allowed_quarantined_machine_ids: Iterable[str] = (),
    allowed_maintenance_machine_ids: Iterable[str] = (),
    defer_transient_machine_health: bool = False,
) -> dict:
    """Verify authenticated service, Dispatcher, machines, and SQLite evidence."""

    if not token:
        raise ValueError("RCN_TOKEN is required for formal release verification")
    get = http_get or _default_http_get
    base = service_url.rstrip("/")
    me = get(f"{base}/v1/me", token)
    if "admin" not in set(me.get("roles") or []):
        raise RuntimeError("authenticated release probe is not an administrator")

    # Require stable full identities around the current metadata counter and,
    # when published, the same semantic identity proof. Legacy HTTP contracts
    # without a proof retain the original strict count gate.
    quarantine = _quarantined_execution_snapshot(Path(database).resolve())
    for observation in range(3):
        dispatcher = get(f"{base}/v1/dispatcher/status", token)
        lease = dispatcher.get("lease") or {}
        current = now or _utc_now()
        expires_at = lease.get("expires_at")
        if not expires_at:
            raise RuntimeError("Dispatcher has no active lease")
        parsed_expiry = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
        if parsed_expiry.tzinfo is None:
            parsed_expiry = parsed_expiry.replace(tzinfo=timezone.utc)
        if parsed_expiry <= current:
            raise RuntimeError("Dispatcher lease is expired")
        if dispatcher.get("phase") != "active":
            raise RuntimeError(f"Dispatcher phase is {dispatcher.get('phase')!r}, expected 'active'")
        if dispatcher.get("control_mode") != "open" or not dispatcher.get("accepting_assignments"):
            raise RuntimeError("Dispatcher is not open for assignments")
        if dispatcher.get("last_error"):
            raise RuntimeError("Dispatcher reports a last_error")
        pending_reconciliation = int(dispatcher.get("pending_reconciliation") or 0)
        observed_quarantine = _quarantined_execution_snapshot(Path(database).resolve())
        delivery_count = int((observed_quarantine.get("delivery_unknown") or {}).get("attempt_count") or 0)
        proof_matches = True
        if "reconciliation_snapshot" in dispatcher:
            proof = dispatcher["reconciliation_snapshot"]
            expected_proof = observed_quarantine.get("reconciliation_snapshot")
            proof_matches = (
                isinstance(proof, dict)
                and type(proof.get("unit_count")) is int
                and proof["unit_count"] == pending_reconciliation
                and proof == expected_proof
            )
        if quarantine == observed_quarantine and pending_reconciliation == (
            int(observed_quarantine["attempt_count"]) + delivery_count
        ) and proof_matches:
            quarantine = observed_quarantine
            break
        quarantine = observed_quarantine
        if observation < 2:
            time.sleep(0.1)
    else:
        raise RuntimeError("Dispatcher reconciliation count does not match quarantine evidence")
    allowed_quarantined = {
        str(machine_id).strip()
        for machine_id in allowed_quarantined_machine_ids
        if str(machine_id).strip()
    }
    allowed_maintenance = {
        str(machine_id).strip()
        for machine_id in allowed_maintenance_machine_ids
        if str(machine_id).strip()
    }
    quarantined_machine_ids = set(quarantine["machine_ids"])
    delivery_unknown = quarantine.get("delivery_unknown") or {
        "attempt_count": 0, "machine_ids": [], "attempts": [],
    }
    delivery_machine_ids = set(delivery_unknown["machine_ids"])
    if quarantined_machine_ids - allowed_quarantined:
        raise RuntimeError(
            "Dispatcher has unapproved machine quarantines: "
            + ", ".join(sorted(quarantined_machine_ids - allowed_quarantined))
        )
    if pending_reconciliation and not (quarantined_machine_ids or delivery_machine_ids):
        raise RuntimeError("Dispatcher has pending reconciliation without machine quarantine evidence")

    machines = get(f"{base}/v1/machines", token)
    if not isinstance(machines, list):
        raise RuntimeError("machine inventory returned an invalid payload")
    # Machine records are append-only and include enrollment/self-test history.
    # Release health is defined over the execution fleet, not inactive records
    # that deliberately have no execution configuration.  Older test/client
    # payloads without this field retain their previous meaning.
    execution_machines = [
        machine for machine in machines
        if "execution_config" not in machine
        or (
            isinstance(machine.get("execution_config"), dict)
            and machine["execution_config"].get("enabled") is True
        )
    ]
    if len(execution_machines) != expected_machine_count:
        raise RuntimeError(
            f"expected {expected_machine_count} machines, received "
            f"{len(execution_machines)} execution-enabled machines "
            f"({len(machines)} registered records)"
        )
    health = _classify_machine_health(
        execution_machines,
        allowed_quarantined=allowed_quarantined,
        allowed_maintenance=allowed_maintenance,
    )
    permitted_maintenance = set(health["permitted_maintenance"])
    transient_unhealthy = health["transient"]
    delivery_unhealthy = delivery_machine_ids - set(health["healthy"])
    delivery_transient = {item["machine_id"] for item in transient_unhealthy}
    if delivery_unhealthy and (
        not defer_transient_machine_health or delivery_unhealthy - delivery_transient
    ):
        # Neither quarantine nor maintenance permission admits unknown delivery
        # on an unhealthy machine. Transient jitter uses the original promote
        # grace loop; its incomplete result cannot publish a successful release.
        raise RuntimeError(
            "submission delivery unknown machines are not healthy and accepting: "
            + ", ".join(sorted(delivery_unhealthy))
        )
    unhealthy = sorted(
        {item["machine_id"] for item in transient_unhealthy}
        | set(health["hard"])
        | set(health["maintenance_only"])
    )
    # With transient deferral the promote loop waits out self-healing tunnel or
    # telemetry jitter; hard failures still fail verification immediately.
    enforced_ids = (
        set(health["hard"]) if defer_transient_machine_health else set(unhealthy)
    )
    unexpected_unhealthy = sorted(
        enforced_ids - quarantined_machine_ids - permitted_maintenance
    )
    if unexpected_unhealthy:
        raise RuntimeError(
            f"machines are not healthy and accepting: {', '.join(unexpected_unhealthy)}"
        )
    if enforced_ids - allowed_quarantined - permitted_maintenance:
        raise RuntimeError("machine degradation is outside the release quarantine allowlist")

    runtime = get(f"{base}/v1/execution-runtime", token)
    process_executable = runtime.get("process_executable")
    configured_executable = runtime.get("configured_python_executable")
    configured_root = runtime.get("configured_runtime_root")
    if process_executable and configured_executable:
        if Path(str(process_executable)).resolve() != Path(str(configured_executable)).resolve():
            raise RuntimeError("live Control Plane executable does not match the launcher pointer")
    if process_executable and configured_root:
        executable_path = Path(str(process_executable)).resolve()
        root_path = Path(str(configured_root)).resolve()
        try:
            executable_path.relative_to(root_path)
        except ValueError as exc:
            raise RuntimeError("live Control Plane executable is outside the selected runtime root") from exc
    database_integrity = _sqlite_integrity(Path(database).resolve())
    return {
        "verified_at": current.isoformat(),
        "actor_id": me.get("actor_id"),
        "administrator": True,
        "package_version": runtime.get("package_version"),
        "control_plane_deployment_id": runtime.get("control_plane_deployment_id"),
        "worker_runtime_version": runtime.get("worker_runtime_version") or runtime.get("runtime_version"),
        "process_executable": process_executable,
        "configured_python_executable": configured_executable,
        "configured_runtime_root": configured_root,
        "dispatcher": {
            "phase": dispatcher.get("phase"),
            "control_mode": dispatcher.get("control_mode"),
            "lease_owner": lease.get("owner_id"),
            "pending_reconciliation": pending_reconciliation,
        },
        "machine_count": len(execution_machines),
        "machine_ids": sorted(str(machine.get("machine_id")) for machine in execution_machines),
        "registered_machine_record_count": len(machines),
        "verification_mode": (
            "degraded_machine_local_quarantine"
            if quarantined_machine_ids
            else (
                "planned_maintenance_drain"
                if permitted_maintenance
                else ("stable_submission_delivery_unknown" if delivery_machine_ids else "strict")
            )
        ),
        "quarantine": quarantine,
        "delivery_unknown": delivery_unknown,
        "delivery_unknown_machine_health_all_healthy": not delivery_unhealthy,
        "unhealthy_machine_ids": sorted(unhealthy),
        "maintenance_machine_ids": sorted(permitted_maintenance),
        "machine_health_all_healthy": not transient_unhealthy and not delivery_unhealthy,
        "transient_machine_health": transient_unhealthy,
        "database_integrity": database_integrity,
    }


def _load_transaction(manifest_path: str | Path) -> tuple[Path, dict]:
    path = Path(manifest_path).resolve()
    manifest = _read_json(path)
    if manifest.get("manifest_path") != str(path):
        raise ValueError("deployment manifest path does not match its transaction identity")
    return path, manifest


def _restore_pointer(pointer_path: Path, previous: dict | None) -> None:
    if previous is None:
        pointer_path.unlink(missing_ok=True)
    else:
        _atomic_json(pointer_path, previous)


def promote_control_plane_release(
    manifest_path: str | Path,
    *,
    token: str,
    http_get: HttpGet | None = None,
    http_post: HttpPost | None = None,
    restart_task: RestartTask | None = None,
    verify_attempts: int = 90,
    verify_interval_s: float = 2.0,
    machine_health_grace_s: float | None = None,
    http_put: HttpPut | None = None,
    drain_timeout_s: float = 300.0,
    drain_interval_s: float = 0.25,
) -> dict:
    """Promote/recover one manifest under the control-root release lock.

    Custom legacy GET/POST transports retain their isolated test contract;
    production HTTP and explicit PUT transports require the durable gate.
    """
    _, manifest = _load_transaction(manifest_path)
    with _release_lock(Path(manifest["pointer_path"]).resolve()):
        return _promote_control_plane_release_locked(
            manifest_path, token=token, http_get=http_get, http_post=http_post,
            restart_task=restart_task, verify_attempts=verify_attempts,
            verify_interval_s=verify_interval_s, machine_health_grace_s=machine_health_grace_s,
            http_put=http_put, drain_timeout_s=drain_timeout_s, drain_interval_s=drain_interval_s)


def _promote_control_plane_release_locked(
    manifest_path, *, token, http_get, http_post, restart_task, verify_attempts,
    verify_interval_s, machine_health_grace_s, http_put, drain_timeout_s, drain_interval_s,
):

    path, manifest = _load_transaction(manifest_path)
    if manifest.get("state") == "promoted":
        if _pointer_value(Path(manifest["pointer_path"])) != manifest["candidate_pointer"]:
            raise RuntimeError("runtime pointer changed after this promotion")
        return manifest
    if manifest.get("state") not in {"prepared", "promoting", "deferred", "recovery_required"}:
        raise ValueError("only a prepared or recoverable deployment transaction can be promoted")
    if manifest.get("rollback_pending"):
        raise RuntimeError("this transaction requires rollback recovery")
    release_mode = str(manifest.get("release_mode") or "standard")
    if release_mode in {"hotfix", "additive"}:
        previous_worker = str((manifest.get("previous_pointer") or {}).get("worker_runtime_version") or "")
        candidate_worker = str((manifest.get("candidate_pointer") or {}).get("worker_runtime_version") or "")
        if not previous_worker or candidate_worker != previous_worker:
            raise ValueError(f"{release_mode} promotion must preserve the live Worker runtime fingerprint")
    if release_mode == "additive":
        schema_validation = (manifest.get("additive_contract") or {}).get("schema_validation") or {}
        if (not schema_validation.get("verified")
                or not (schema_validation.get("compatibility_receipt") or {}).get("verified")
                or schema_validation.get("pristine_backup_sha256") != manifest["database_backup"]["sha256"]
                or manifest.get("rollback_database_strategy") != "preserve_compatible_live_database"):
            raise ValueError("additive promotion requires a verified compatible database receipt")
    pointer_path = Path(manifest["pointer_path"]).resolve()
    restart = restart_task or _default_restart_task
    verification_policy = manifest.get("verification_policy") or {}
    service_already_stopped = bool(verification_policy.get("service_already_stopped"))
    allowed_quarantined_machine_ids = tuple(
        verification_policy.get("allowed_quarantined_machine_ids") or []
    )
    allowed_maintenance_machine_ids = tuple(
        verification_policy.get("allowed_maintenance_machine_ids") or []
    )
    # Transient fleet-jitter grace: the promote loop waits out self-healing
    # tunnel/telemetry flapping for up to this many seconds before giving up
    # and rolling back. Zero keeps the legacy strict behavior where any
    # unhealthy machine consumes the ordinary verify-attempts budget.
    if machine_health_grace_s is None:
        machine_health_grace_s = float(
            verification_policy.get("machine_health_grace_s", 300.0)
        )
    machine_health_grace_s = max(0.0, float(machine_health_grace_s))
    defer_transient_machine_health = machine_health_grace_s > 0
    # Live releases hand the Dispatcher over explicitly. Leaving the old
    # process alive lets it retain a valid lease after the Control Plane has
    # switched runtimes; the new process then cannot start before verification
    # times out. Custom test transports keep the earlier isolated behavior
    # unless they also provide a POST adapter.
    handoff_dispatcher = (
        not service_already_stopped
        and (http_get is None or http_post is not None)
    )
    post = http_post or _default_http_post
    # A maintenance-stopped release has no old process to hand off, but the
    # candidate must still receive an explicit audited start after restart.
    dispatcher_stopped = service_already_stopped
    observed_pointer = json.loads(pointer_path.read_text(encoding="utf-8")) if pointer_path.exists() else None
    journal = manifest.setdefault("journal", {})
    pointer_pending = "pointer_switch" in journal
    if (observed_pointer != manifest.get("previous_pointer")
            and not (pointer_pending and observed_pointer == manifest["candidate_pointer"])):
        raise RuntimeError("release pointer changed after prepare; reconcile the exact transaction before promotion")
    pointer_switch_attempted = pointer_pending
    handoff_attempted = "dispatcher_stop" in journal
    dispatcher_stopped = (service_already_stopped or (journal.get("dispatcher_stop", {}).get("state") == "completed"
                          and journal.get("dispatcher_start", {}).get("state") != "completed"))
    manifest["state"] = "promoting"
    _atomic_json(path, manifest)
    bootstrap = bool(manifest.get("bootstrap_gate_evidence"))
    gate_required = not service_already_stopped and (bootstrap or http_get is None or http_put is not None or "maintenance" in manifest)
    if gate_required and not pointer_pending:
        try:
            drained = (_bootstrap_admission(path, manifest, token=token, http_get=http_get or _default_http_get,
                                             timeout_s=drain_timeout_s) if bootstrap else
                       _drain_transfers(path, manifest, token=token, http_get=http_get or _default_http_get,
                                    http_put=http_put or _default_http_put, timeout_s=drain_timeout_s,
                                    interval_s=drain_interval_s))
            if not drained:
                manifest.update(state="deferred", deferred_reason="active_transfers")
                _atomic_json(path, manifest)
                return manifest
        except Exception as exc:
            manifest.update(state="recovery_required", recovery_error_type=type(exc).__name__)
            _atomic_json(path, manifest)
            raise RuntimeError("release maintenance admission outcome is uncertain; recover the same manifest") from exc
    if service_already_stopped and not pointer_pending:
        manifest["stopped_handoff_evidence"] = _stopped_release_evidence(
            database=Path(manifest["database"]).resolve(), service_url=manifest["service_url"],
            scheduled_task=manifest["scheduled_task"])
        _atomic_json(path, manifest)
    try:
        if handoff_dispatcher:
            # One cooperative stop also drains. Do not create an idle-exit
            # window between separate drain and stop tickets on older APIs.
            handoff_attempted = True
            _intent(path, manifest, "dispatcher_stop", lambda: _dispatcher_control_action(
                service_url=manifest["service_url"], token=token, action="stop",
                reason=f"release handoff for {manifest['transaction_id']}", http_post=post,
            ))
            dispatcher_stopped = True
        if bootstrap:
            manifest["bootstrap_active_execution_at_handoff"] = _intent(path, manifest,
                "bootstrap_active_snapshot", lambda: _active_execution_snapshot(Path(manifest["database"])))
            _intent(path, manifest, "bootstrap_empty_api_stop", lambda: _bootstrap_stop_empty_api(manifest))
            _intent(path, manifest, "bootstrap_guard_upgrade", lambda: _bootstrap_upgrade_guard(manifest))
        if release_mode == "additive":
            # Preparation can precede promotion by minutes. Capture identities
            # again after the cooperative stop so newly allocated work also
            # remains covered across the runtime switch and later verification.
            if "active_execution_at_handoff" not in manifest:
                manifest["active_execution_at_handoff"] = _active_execution_snapshot(
                    Path(manifest["database"]).resolve())
            _atomic_json(path, manifest)
        pointer_switch_attempted = True
        def switch():
            if _pointer_value(pointer_path) != manifest["candidate_pointer"]:
                _pointer_compare_exchange(pointer_path, manifest.get("previous_pointer"), manifest["candidate_pointer"])
        _intent(path, manifest, "pointer_switch", switch)
        if bootstrap and restart_task is None:
            _intent(path, manifest, "bootstrap_guard_resume", lambda: _coordinator_guard_action(
                manifest["candidate_pointer"]["python_executable"],
                str(Path(manifest["state_root"]) / "startup/supervision.json"), "resume"))
        candidate_restart = (_default_start_stopped_task
                             if (service_already_stopped or bootstrap) and restart_task is None else restart)
        _intent(path, manifest, "service_restart", lambda: candidate_restart(str(manifest["task_name"])))
        last_error: Exception | None = None
        verification = (journal.get("verification", {}).get("result")
                        if journal.get("verification", {}).get("state") == "completed" else None)
        grace_deadline: float | None = None
        grace_started_mono: float | None = None
        transient_seen: dict[str, dict] = {}
        transient_observations = 0
        grace_exhausted: str | None = None
        hard_failures = 0
        attempts_budget = max(1, verify_attempts)
        while verification is None:
            try:
                if dispatcher_stopped:
                    _intent(path, manifest, "dispatcher_start", lambda: _dispatcher_control_action(
                        service_url=manifest["service_url"],
                        token=token,
                        action="start",
                        reason=f"release handoff for {manifest['transaction_id']}",
                        http_post=post,
                    ))
                    dispatcher_stopped = False
                candidate_verification = verify_control_plane_release(
                    database=manifest["database"],
                    service_url=manifest["service_url"],
                    token=token,
                    expected_machine_count=int(manifest["expected_machine_count"]),
                    http_get=http_get,
                    allowed_quarantined_machine_ids=allowed_quarantined_machine_ids,
                    allowed_maintenance_machine_ids=allowed_maintenance_machine_ids,
                    defer_transient_machine_health=defer_transient_machine_health,
                )
                if not candidate_verification["machine_health_all_healthy"]:
                    now_mono = time.monotonic()
                    if grace_deadline is None:
                        grace_started_mono = now_mono
                        grace_deadline = now_mono + machine_health_grace_s
                    if now_mono >= grace_deadline:
                        # Definitive: the transient fleet jitter outlasted its
                        # grace window. Fail directly into the rollback handler
                        # instead of consuming the ordinary attempts budget.
                        grace_exhausted = (
                            "machine health did not recover within the "
                            f"{machine_health_grace_s:g}s transient grace window: "
                            + ", ".join(sorted(transient_seen))
                        )
                        break
                    transient_observations += 1
                    for item in candidate_verification["transient_machine_health"]:
                        transient_seen[str(item.get("machine_id") or "unknown")] = item
                    time.sleep(max(0.0, verify_interval_s))
                    continue
                if transient_seen:
                    candidate_verification["machine_health_grace_used_s"] = round(
                        time.monotonic() - (grace_started_mono or time.monotonic()), 3
                    )
                    candidate_verification["transient_machine_health_events"] = {
                        "observations": transient_observations,
                        "machines": sorted(
                            transient_seen.values(),
                            key=lambda item: str(item.get("machine_id")),
                        ),
                    }
                if release_mode in {"hotfix", "additive"}:
                    candidate_verification["hotfix_continuity"] = _verify_hotfix_continuity(
                        Path(manifest["database"]).resolve(),
                        manifest.get("active_execution_before") or {},
                    )
                if release_mode == "additive":
                    candidate_verification["additive_handoff_continuity"] = _verify_hotfix_continuity(
                        Path(manifest["database"]).resolve(),
                        manifest["active_execution_at_handoff"],
                    )
                # Publish a successful result only after every release-mode
                # gate has passed. A late continuity failure must not leave a
                # truthy basic-health result behind for the loop exit check.
                verification = candidate_verification
                _intent(path, manifest, "verification", lambda: verification)
                break
            except Exception as exc:
                verification = None
                last_error = exc
                hard_failures += 1
                if hard_failures < attempts_budget:
                    time.sleep(max(0.0, verify_interval_s))
                    continue
                break
        if verification is None:
            if grace_exhausted:
                raise RuntimeError(grace_exhausted)
            raise last_error or RuntimeError("release verification failed")
    except Exception as exc:
        if bootstrap and "bootstrap_empty_api_stop" in journal and not pointer_switch_attempted:
            manifest.update(state="recovery_required", recovery_error_type=type(exc).__name__)
            _atomic_json(path, manifest)
            raise RuntimeError("bootstrap handoff incomplete; recover the same manifest") from exc
        # A cooperative service stop timeout is recoverable. Do not overwrite
        # the candidate pointer or restart/kill a still-live service instance.
        if (manifest.get("stage") == "service_restart"
                and journal.get("service_restart", {}).get("state") == "intent"):
            manifest.update(state="recovery_required", recovery_error_type=type(exc).__name__)
            _atomic_json(path, manifest)
            raise RuntimeError("cooperative service restart incomplete; recover the same manifest") from exc
        if not pointer_switch_attempted:
            # A stop timeout/409 may already have written control markers.
            # Preserve the old pointer and recover its desired state through
            # the same audited idempotent start, never by killing a guessed PID.
            recovery_error = None
            manifest["rollback_pending"] = True
            manifest["rollback"] = {"pointer_changed": False,
                "reason": f"{type(exc).__name__}: {exc}"[:500]}
            _atomic_json(path, manifest)
            if handoff_attempted:
                try:
                    _intent(path, manifest, "abort_dispatcher_start", lambda: _dispatcher_control_action(
                        service_url=manifest["service_url"], token=token,
                        action="start", reason=f"aborted release handoff for {manifest['transaction_id']}",
                        http_post=post))
                except Exception as recovery_exc:
                    recovery_error = type(recovery_exc).__name__
            if recovery_error is None:
                try:
                    _release_maintenance(path, manifest, token=token, http_post=post)
                except Exception as recovery_exc:
                    recovery_error = type(recovery_exc).__name__
            manifest["state"] = "recovery_required" if recovery_error else "rolled_back"
            manifest["rollback_pending"] = recovery_error is not None
            manifest["rollback"] = {"rolled_back_at": _utc_now().isoformat(),
                "reason": f"{type(exc).__name__}: {exc}"[:500], "automatic": recovery_error is None,
                "pointer_changed": False, "handoff_recovery_error_type": recovery_error,
                **_rollback_database_receipt(manifest)}
            _atomic_json(path, manifest)
            raise RuntimeError("promotion handoff failed; previous runtime pointer preserved; "
                               + ("operator recovery required" if recovery_error else "old dispatcher start requested")) from exc
        manifest["rollback_pending"] = True
        _atomic_json(path, manifest)
        if _pointer_value(pointer_path) not in (manifest.get("previous_pointer"), manifest["candidate_pointer"]):
            manifest.update(state="recovery_required", recovery_error_type="RuntimePointerChanged")
            _atomic_json(path, manifest)
            raise RuntimeError("runtime pointer changed; rollback refuses to affect another deployment") from exc
        if handoff_dispatcher and not dispatcher_stopped:
            try:
                _intent(path, manifest, "rollback_dispatcher_stop", lambda: _dispatcher_control_action(
                    service_url=manifest["service_url"],
                    token=token,
                    action="stop",
                    reason=f"rollback handoff for {manifest['transaction_id']}",
                    http_post=post,
                ))
                dispatcher_stopped = True
            except Exception as stop_exc:
                manifest.update(state="recovery_required", recovery_error_type=type(stop_exc).__name__)
                _atomic_json(path, manifest)
                raise RuntimeError("rollback dispatcher stop incomplete; recover the same manifest") from stop_exc
        def restore():
            if _pointer_value(pointer_path) != manifest.get("previous_pointer"):
                _pointer_compare_exchange(pointer_path, manifest["candidate_pointer"], manifest.get("previous_pointer"))
        if bootstrap:
            _intent(path, manifest, "rollback_bootstrap_api_stop", lambda: _bootstrap_stop_new_guard(manifest))
            _intent(path, manifest, "rollback_bootstrap_guard_restore", lambda: _bootstrap_restore_guard_task(manifest))
        _intent(path, manifest, "rollback_pointer", restore)
        if bootstrap and restart_task is None:
            _intent(path, manifest, "rollback_bootstrap_original_resume", lambda: _bootstrap_resume_original_guard(manifest))
        rollback_restart = _default_start_stopped_task if bootstrap and restart_task is None else restart
        _intent(path, manifest, "rollback_restart", lambda: rollback_restart(str(manifest["task_name"])))
        if dispatcher_stopped:
            for _ in range(30):
                try:
                    _intent(path, manifest, "rollback_dispatcher_start", lambda: _dispatcher_control_action(
                        service_url=manifest["service_url"],
                        token=token,
                        action="start",
                        reason=f"rollback handoff for {manifest['transaction_id']}",
                        http_post=post,
                    ))
                    dispatcher_stopped = False
                    break
                except Exception:
                    time.sleep(1.0)
        if dispatcher_stopped:
            manifest["state"] = "recovery_required"
            _atomic_json(path, manifest)
            raise RuntimeError("rollback dispatcher start incomplete; recover the same manifest") from exc
        _release_maintenance(path, manifest, token=token, http_post=post)
        manifest["state"] = "rolled_back"
        manifest["rollback_pending"] = False
        manifest["rollback"] = {
            "rolled_back_at": _utc_now().isoformat(),
            "reason": f"{type(exc).__name__}: {exc}"[:500],
            "automatic": True,
            **_rollback_database_receipt(manifest),
        }
        _atomic_json(path, manifest)
        raise RuntimeError("promotion failed; the previous runtime pointer was restored") from exc

    try:
        _release_maintenance(path, manifest, token=token, http_post=post)
    except Exception as exc:
        manifest.update(state="recovery_required", recovery_error_type=type(exc).__name__)
        _atomic_json(path, manifest)
        raise RuntimeError("release succeeded but admission release is uncertain; recover the same manifest") from exc
    manifest["state"] = "promoted"
    manifest["promoted_at"] = _utc_now().isoformat()
    manifest["verification"] = verification
    _atomic_json(path, manifest)
    return manifest


def verify_prepared_release(
    manifest_path: str | Path,
    *,
    token: str,
    http_get: HttpGet | None = None,
) -> dict:
    _, manifest = _load_transaction(manifest_path)
    with _release_lock(Path(manifest["pointer_path"]).resolve()):
        return _verify_prepared_release_locked(manifest_path, token=token, http_get=http_get)


def _verify_prepared_release_locked(manifest_path, *, token, http_get) -> dict:
    path, manifest = _load_transaction(manifest_path)
    verification = verify_control_plane_release(
        database=manifest["database"],
        service_url=manifest["service_url"],
        token=token,
        expected_machine_count=int(manifest["expected_machine_count"]),
        http_get=http_get,
        allowed_quarantined_machine_ids=(
            (manifest.get("verification_policy") or {}).get(
                "allowed_quarantined_machine_ids"
            )
            or []
        ),
        allowed_maintenance_machine_ids=(
            (manifest.get("verification_policy") or {}).get(
                "allowed_maintenance_machine_ids"
            )
            or []
        ),
    )
    if manifest.get("release_mode") in {"hotfix", "additive"}:
        verification["hotfix_continuity"] = _verify_hotfix_continuity(
            Path(manifest["database"]).resolve(),
            manifest.get("active_execution_before") or {},
        )
    if manifest.get("release_mode") == "additive":
        handoff = manifest.get("active_execution_at_handoff")
        if handoff is None and manifest.get("state") == "promoted":
            raise RuntimeError("additive verification requires the active execution handoff snapshot")
        if handoff is not None:
            verification["additive_handoff_continuity"] = _verify_hotfix_continuity(
                Path(manifest["database"]).resolve(), handoff,
            )
    manifest["verification"] = verification
    manifest["last_verified_at"] = _utc_now().isoformat()
    _atomic_json(path, manifest)
    return manifest


def _rollback_database_receipt(manifest: dict) -> dict:
    # An additive schema is readable by the old runtime. Restoring the prepare
    # backup here would discard Jobs/Attempts that advanced after that snapshot.
    if manifest.get("release_mode") == "additive":
        return {"database_strategy": "preserve_compatible_live_database", "database_restored": False}
    return {"database_strategy": "preserve_live_database", "database_restored": False}


def rollback_control_plane_release(
    manifest_path: str | Path,
    *,
    token: str,
    http_get: HttpGet | None = None,
    http_post: HttpPost | None = None,
    restart_task: RestartTask | None = None,
    http_put: HttpPut | None = None,
    drain_timeout_s: float = 300.0,
    drain_interval_s: float = 0.25,
) -> dict:
    _, manifest = _load_transaction(manifest_path)
    with _release_lock(Path(manifest["pointer_path"]).resolve()):
        return _rollback_control_plane_release_locked(
            manifest_path, token=token, http_get=http_get, http_post=http_post,
            restart_task=restart_task, http_put=http_put,
            drain_timeout_s=drain_timeout_s, drain_interval_s=drain_interval_s)


def _rollback_control_plane_release_locked(
    manifest_path, *, token, http_get, http_post, restart_task, http_put, drain_timeout_s, drain_interval_s,
):
    path, manifest = _load_transaction(manifest_path)
    if manifest.get("state") not in {"promoted", "rolled_back", "recovery_required", "promoting", "deferred", "rolling_back"}:
        raise ValueError("only a promoted or recoverable transaction can be rolled back")
    pointer_path = Path(manifest["pointer_path"]).resolve()
    current = _pointer_value(pointer_path)
    if current not in (manifest.get("previous_pointer"), manifest["candidate_pointer"]):
        raise RuntimeError("runtime pointer changed during recovery; refuse to overwrite another deployment")
    if manifest.get("state") == "rolled_back" and not manifest.get("rollback_pending"):
        if current != manifest.get("previous_pointer"):
            raise RuntimeError("runtime pointer changed after this rollback")
        return manifest
    handoff = http_get is None or http_post is not None
    post = http_post or _default_http_post
    pre_switch_recovery = (
        (manifest.get("rollback") or {}).get("pointer_changed") is False
        and current == manifest.get("previous_pointer")
        and "pointer_switch" not in manifest.get("journal", {}))
    if not manifest.get("rollback_pending"):
        # A post-promotion rollback is another admission interval. A completed
        # UUID cannot silently be reopened; retain its receipt and allocate one
        # new interval before the first rollback side effect.
        if "maintenance" in manifest and manifest.get("journal", {}).get("maintenance_release", {}).get("state") == "completed":
            manifest.setdefault("maintenance_history", []).append(manifest.pop("maintenance"))
            for stage in ("maintenance_begin", "maintenance_release"):
                manifest["journal"].pop(stage, None)
        manifest["rollback_pending"] = True
    manifest["state"] = "rolling_back"
    _atomic_json(path, manifest)
    gate_required = http_get is None or http_put is not None or "maintenance" in manifest
    legacy_bootstrap_rollback = bool(manifest.get("bootstrap_gate_evidence")) and current == manifest.get("previous_pointer")
    bootstrap_api_already_stopped = bool(manifest.get("bootstrap_gate_evidence")) and (
        manifest.get("journal", {}).get("rollback_bootstrap_api_stop", {}).get("state") == "completed")
    try:
        if legacy_bootstrap_rollback or bootstrap_api_already_stopped:
            from .release_maintenance import get_transfer_gate
            gate = get_transfer_gate(manifest["state_root"])
            if gate.snapshot(manifest["maintenance"]["operation_id"])["active_transfers"]:
                raise RuntimeError("bootstrap rollback still has managed transfer handles")
            if "rollback_restart" not in manifest.get("journal", {}):
                _intent(path, manifest, "bootstrap_empty_api_stop", lambda: _bootstrap_stop_empty_api(manifest))
                _stopped_release_evidence(database=Path(manifest["database"]),
                    service_url=manifest["service_url"], scheduled_task=manifest["scheduled_task"])
        elif gate_required and "rollback_pointer" not in manifest.get("journal", {}):
            if not _drain_transfers(path, manifest, token=token, http_get=http_get or _default_http_get,
                                    http_put=http_put or _default_http_put, timeout_s=drain_timeout_s,
                                    interval_s=drain_interval_s):
                return manifest
        if handoff and not pre_switch_recovery and not legacy_bootstrap_rollback and not bootstrap_api_already_stopped:
            _intent(path, manifest, "rollback_dispatcher_stop", lambda: _dispatcher_control_action(
                service_url=manifest["service_url"], token=token, action="stop",
                reason=f"rollback handoff for {manifest['transaction_id']}", http_post=post))
        def restore():
            if _pointer_value(pointer_path) != manifest.get("previous_pointer"):
                _pointer_compare_exchange(pointer_path, manifest["candidate_pointer"], manifest.get("previous_pointer"))
        if manifest.get("bootstrap_gate_evidence"):
            _intent(path, manifest, "rollback_bootstrap_api_stop", lambda: _bootstrap_stop_new_guard(manifest))
            _intent(path, manifest, "rollback_bootstrap_guard_restore", lambda: _bootstrap_restore_guard_task(manifest))
        _intent(path, manifest, "rollback_pointer", restore)
        if manifest.get("bootstrap_gate_evidence") and restart_task is None:
            _intent(path, manifest, "rollback_bootstrap_original_resume", lambda: _bootstrap_resume_original_guard(manifest))
        restart = restart_task or (_default_start_stopped_task if manifest.get("bootstrap_gate_evidence") else _default_restart_task)
        _intent(path, manifest, "rollback_restart", lambda: restart(str(manifest["task_name"])))
        if handoff:
            _intent(path, manifest, "rollback_dispatcher_start", lambda: _dispatcher_control_action(
                service_url=manifest["service_url"], token=token, action="start",
                reason=f"rollback handoff for {manifest['transaction_id']}", http_post=post))
    except Exception as exc:
        manifest.update(state="recovery_required", recovery_error_type=type(exc).__name__)
        _atomic_json(path, manifest)
        raise
    verification = verify_control_plane_release(
        database=manifest["database"],
        service_url=manifest["service_url"],
        token=token,
        expected_machine_count=int(manifest["expected_machine_count"]),
        http_get=http_get,
        allowed_quarantined_machine_ids=(
            (manifest.get("verification_policy") or {}).get(
                "allowed_quarantined_machine_ids"
            )
            or []
        ),
        allowed_maintenance_machine_ids=(
            (manifest.get("verification_policy") or {}).get(
                "allowed_maintenance_machine_ids"
            )
            or []
        ),
    )
    _release_maintenance(path, manifest, token=token, http_post=post)
    manifest["state"] = "rolled_back"
    manifest["rollback_pending"] = False
    manifest["rollback"] = {
        "rolled_back_at": _utc_now().isoformat(),
        "automatic": False,
        "verification": verification,
        **_rollback_database_receipt(manifest),
    }
    _atomic_json(path, manifest)
    return manifest


def recover_control_plane_release(manifest_path: str | Path, *, token: str, **kwargs) -> dict:
    """Resume only the original durable transaction; never restore an old DB."""
    _, manifest = _load_transaction(manifest_path)
    if manifest.get("state") == "preparing":
        with _release_lock(Path(manifest["pointer_path"])):
            path, current = _load_transaction(manifest_path)
            return _finish_release_preparation(path, current)
    if manifest.get("state") == "prepared":
        return manifest  # preparation recovery never implicitly publishes
    if manifest.get("state") == "rolled_back" and not manifest.get("rollback_pending"):
        if _pointer_value(Path(manifest["pointer_path"])) != manifest.get("previous_pointer"):
            raise RuntimeError("runtime pointer changed after this rollback")
        return manifest
    if manifest.get("rollback_pending") or manifest.get("state") == "rolling_back":
        allowed = {key: value for key, value in kwargs.items() if key in {
            "http_get", "http_post", "restart_task", "http_put", "drain_timeout_s", "drain_interval_s"}}
        return rollback_control_plane_release(manifest_path, token=token, **allowed)
    return promote_control_plane_release(manifest_path, token=token, **kwargs)


def control_plane_release_status(manifest_path: str | Path) -> dict:
    """Read the saved transaction and pointer; do not initialize/mutate state."""
    _, manifest = _load_transaction(manifest_path)
    current = _pointer_value(Path(manifest["pointer_path"]).resolve())
    return {**manifest, "pointer_observation": {
        "matches_previous": current == manifest.get("previous_pointer"),
        "matches_candidate": current == manifest["candidate_pointer"],
        "deployment_id": (current or {}).get("deployment_id"),
    }}
