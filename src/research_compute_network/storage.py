"""Metadata storage diagnostics and reversible payload compaction."""

from __future__ import annotations

from datetime import datetime, timezone
from contextlib import closing
import hashlib
from tempfile import SpooledTemporaryFile
import json
from pathlib import Path
import shutil
import sqlite3
import time
import zlib
from typing import Any


MARKER = "$rcn_storage_blob"
CODEC = "zlib-json-v1"
MIGRATION_SCHEMA_VERSION = 2
MIGRATION_ALGORITHM = "aggregate-item-lists-v2"


def database_path(database_url: str | Path) -> Path:
    value = str(database_url)
    if value.startswith("sqlite:///"):
        value = value[10:]
    elif value.startswith("sqlite:"):
        value = value[7:]
    return Path(value).expanduser().resolve()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _ref(payload: Any) -> dict[str, Any]:
    raw = _canonical(payload)
    return {MARKER: {"sha256": hashlib.sha256(raw).hexdigest(), "codec": CODEC}}


def _blob_row_index(connection: sqlite3.Connection) -> dict[str, tuple[str, bytes]]:
    """Load compressed rows once so legacy migrations avoid N SQLite queries."""
    try:
        return {
            str(digest): (str(codec), compressed)
            for digest, codec, compressed in connection.execute(
                "SELECT sha256, codec, compressed_payload FROM storage_blobs"
            )
        }
    except sqlite3.OperationalError:
        return {}


def _hydrate(
    connection: sqlite3.Connection,
    value: Any,
    *,
    blob_rows: dict[str, tuple[str, bytes]] | None = None,
) -> Any:
    if isinstance(value, dict) and set(value) == {MARKER}:
        digest = str(value[MARKER].get("sha256") or "")
        row = blob_rows.get(digest) if blob_rows is not None else None
        if row is None:
            row = connection.execute(
                "SELECT codec, compressed_payload FROM storage_blobs WHERE sha256 = ?", (digest,)
            ).fetchone()
        if row is None:
            raise RuntimeError(f"storage blob is missing: {digest}")
        if row[0] != CODEC:
            raise RuntimeError(f"unsupported storage codec: {row[0]}")
        return _hydrate(
            connection,
            json.loads(zlib.decompress(row[1]).decode("utf-8")),
            blob_rows=blob_rows,
        )
    if isinstance(value, dict):
        return {
            key: _hydrate(connection, item, blob_rows=blob_rows)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_hydrate(connection, item, blob_rows=blob_rows) for item in value]
    return value


def _blob_raw(
    connection: sqlite3.Connection,
    digest: str,
    *,
    blob_rows: dict[str, tuple[str, bytes]],
) -> bytes:
    row = blob_rows.get(digest)
    if row is None:
        row = connection.execute(
            "SELECT codec, compressed_payload FROM storage_blobs WHERE sha256 = ?",
            (digest,),
        ).fetchone()
    if row is None:
        raise RuntimeError(f"storage blob is missing: {digest}")
    if row[0] != CODEC:
        raise RuntimeError(f"unsupported storage codec: {row[0]}")
    raw = zlib.decompress(row[1])
    if hashlib.sha256(raw).hexdigest() != digest:
        raise RuntimeError(f"storage blob hash mismatch: {digest}")
    return raw


def _write_hydrated_canonical(
    connection: sqlite3.Connection,
    value: Any,
    *,
    blob_rows: dict[str, tuple[str, bytes]],
    emit,
) -> None:
    """Write canonical JSON while substituting blob contents in place."""
    if isinstance(value, dict) and set(value) == {MARKER}:
        digest = str(value[MARKER].get("sha256") or "")
        raw = _blob_raw(connection, digest, blob_rows=blob_rows)
        if MARKER.encode("utf-8") in raw:
            _write_hydrated_canonical(
                connection,
                json.loads(raw.decode("utf-8")),
                blob_rows=blob_rows,
                emit=emit,
            )
        else:
            emit(raw)
        return
    if isinstance(value, dict):
        emit(b"{")
        for index, key in enumerate(sorted(value)):
            if index:
                emit(b",")
            emit(_canonical(str(key)))
            emit(b":")
            _write_hydrated_canonical(
                connection,
                value[key],
                blob_rows=blob_rows,
                emit=emit,
            )
        emit(b"}")
        return
    if isinstance(value, list):
        emit(b"[")
        for index, item in enumerate(value):
            if index:
                emit(b",")
            _write_hydrated_canonical(
                connection,
                item,
                blob_rows=blob_rows,
                emit=emit,
            )
        emit(b"]")
        return
    emit(_canonical(value))


def _store_hydrated_blob(
    connection: sqlite3.Connection,
    value: Any,
    *,
    blob_rows: dict[str, tuple[str, bytes]],
) -> dict[str, Any]:
    digest = hashlib.sha256()
    compressor = zlib.compressobj(level=6)
    original_size = 0
    with SpooledTemporaryFile(max_size=16 * 1024 * 1024, mode="w+b") as sink:
        def emit(chunk: bytes) -> None:
            nonlocal original_size
            original_size += len(chunk)
            digest.update(chunk)
            compressed = compressor.compress(chunk)
            if compressed:
                sink.write(compressed)

        _write_hydrated_canonical(
            connection,
            value,
            blob_rows=blob_rows,
            emit=emit,
        )
        tail = compressor.flush()
        if tail:
            sink.write(tail)
        blob_digest = digest.hexdigest()
        sink.seek(0)
        compressed_payload = sink.read()
    connection.execute(
        "INSERT OR IGNORE INTO storage_blobs "
        "(sha256, codec, original_size, compressed_payload, created_at, reference_count) "
        "VALUES (?, ?, ?, ?, ?, 0)",
        (
            blob_digest,
            CODEC,
            original_size,
            compressed_payload,
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    return {MARKER: {"sha256": blob_digest, "codec": CODEC}}


def _compact(
    connection: sqlite3.Connection,
    value: Any,
    *,
    blob_rows: dict[str, tuple[str, bytes]] | None = None,
) -> Any:
    if isinstance(value, list):
        return [_compact(connection, item, blob_rows=blob_rows) for item in value]
    if not isinstance(value, dict):
        return value
    if set(value) == {MARKER}:
        return value
    result: dict[str, Any] = {}
    for key, item in value.items():
        if key == "items" and isinstance(item, list):
            result[key] = _store_hydrated_blob(
                connection,
                item,
                blob_rows=blob_rows or _blob_row_index(connection),
            )
            continue
        if key == "items" and isinstance(item, dict) and set(item) == {MARKER}:
            result[key] = item
            continue
        result[key] = _compact(connection, item, blob_rows=blob_rows)
    return result


def _dependency_counts(
    connection: sqlite3.Connection,
    value: Any,
    *,
    cache: dict[str, tuple[Any, dict[str, int]]],
    visiting: set[str],
) -> dict[str, int]:
    """Count every blob reachable from an aggregate, including legacy nesting."""
    if isinstance(value, dict) and set(value) == {MARKER}:
        digest = str(value[MARKER].get("sha256") or "")
        if not digest:
            raise RuntimeError("storage blob reference has no sha256")
        if digest in visiting:
            raise RuntimeError(f"storage blob reference cycle detected: {digest}")
        cached = cache.get(digest)
        if cached is None:
            row = connection.execute(
                "SELECT codec, compressed_payload FROM storage_blobs WHERE sha256 = ?",
                (digest,),
            ).fetchone()
            if row is None:
                raise RuntimeError(f"storage blob is missing: {digest}")
            if row[0] != CODEC:
                raise RuntimeError(f"unsupported storage codec: {row[0]}")
            raw = zlib.decompress(row[1])
            if hashlib.sha256(raw).hexdigest() != digest:
                raise RuntimeError(f"storage blob hash mismatch: {digest}")
            if MARKER.encode("utf-8") in raw:
                decoded = json.loads(raw.decode("utf-8"))
                visiting.add(digest)
                nested = _dependency_counts(
                    connection,
                    decoded,
                    cache=cache,
                    visiting=visiting,
                )
                visiting.remove(digest)
            else:
                decoded = None
                nested = {}
            cache[digest] = (decoded, nested)
        else:
            _, nested = cached
        result = {digest: 1}
        for nested_digest, count in nested.items():
            result[nested_digest] = result.get(nested_digest, 0) + count
        return result
    if isinstance(value, dict):
        children = value.values()
    elif isinstance(value, list):
        children = value
    else:
        return {}
    result: dict[str, int] = {}
    for child in children:
        for digest, count in _dependency_counts(
            connection,
            child,
            cache=cache,
            visiting=visiting,
        ).items():
            result[digest] = result.get(digest, 0) + count
    return result


def _rebuild_blob_reference_counts(connection: sqlite3.Connection) -> dict[str, int]:
    counts: dict[str, int] = {}
    cache: dict[str, tuple[Any, dict[str, int]]] = {}
    for table in ("partition_plans", "jobs"):
        for (raw,) in connection.execute(f"SELECT payload FROM {table}").fetchall():
            payload = json.loads(raw) if isinstance(raw, str) else raw
            for digest, count in _dependency_counts(
                connection,
                payload,
                cache=cache,
                visiting=set(),
            ).items():
                counts[digest] = counts.get(digest, 0) + count
    connection.execute("UPDATE storage_blobs SET reference_count = 0")
    for digest, count in counts.items():
        connection.execute(
            "UPDATE storage_blobs SET reference_count = ? WHERE sha256 = ?",
            (count, digest),
        )
    connection.execute("DELETE FROM storage_blobs WHERE reference_count = 0")
    return counts


def _online_backup(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(str(source))) as src, closing(sqlite3.connect(str(destination))) as dst:
        with dst:
            src.backup(dst)


def _counts(
    connection: sqlite3.Connection,
    *,
    database: str = "main",
) -> dict[str, int]:
    if database not in {"main", "live"}:
        raise ValueError("count database must be main or live")
    tables = ("jobs", "partition_plans", "work_units", "attempts", "artifact_manifests")
    result: dict[str, int] = {}
    for table in tables:
        try:
            result[table] = int(connection.execute(
                f'SELECT count(*) FROM {database}."{table}"'
            ).fetchone()[0])
        except sqlite3.OperationalError:
            result[table] = 0
    return result


def _semantic_sha256(
    connection: sqlite3.Connection,
    value: Any,
    *,
    blob_rows: dict[str, tuple[str, bytes]],
) -> str:
    """Hash hydrated canonical JSON without materializing the aggregate."""
    digest = hashlib.sha256()
    _write_hydrated_canonical(
        connection,
        value,
        blob_rows=blob_rows,
        emit=digest.update,
    )
    return digest.hexdigest()


def _identity(
    connection: sqlite3.Connection,
    *,
    blob_rows: dict[str, tuple[str, bytes]] | None = None,
) -> dict[str, Any]:
    if blob_rows is None:
        blob_rows = _blob_row_index(connection)
    result: dict[str, Any] = {"counts": _counts(connection), "jobs": [], "partition_plans": [], "active_attempts": []}
    try:
        job_columns = {
            str(row[1]) for row in connection.execute("PRAGMA table_info(jobs)").fetchall()
        }
        operational_select = (
            ", operational_payload" if "operational_payload" in job_columns else ", NULL"
        )
        rows = connection.execute(
            "SELECT job_id, request_hash, status, revision, payload"
            f"{operational_select} FROM jobs ORDER BY job_id"
        ).fetchall()
        for job_id, request_hash, status, revision, raw, operational_raw in rows:
            payload = json.loads(raw) if isinstance(raw, str) else raw
            result["jobs"].append([
                job_id,
                request_hash,
                status,
                revision,
                _semantic_sha256(connection, payload, blob_rows=blob_rows),
            ])
            operational = (
                json.loads(operational_raw)
                if isinstance(operational_raw, str)
                else operational_raw
            )
            attempt_source = operational or payload
            for unit in attempt_source.get("work_units") or []:
                attempts = unit.get("attempts") or []
                if not attempts:
                    continue
                latest = attempts[-1]
                if latest.get("state") in {"assigned", "submitting", "running", "cancel_pending", "reconcile_pending", "uncertain", "collecting"}:
                    result["active_attempts"].append([
                        latest.get("attempt_id"), job_id, unit.get("work_unit_id"), latest.get("state"),
                        bool(latest.get("execution_started")), latest.get("external_run_id"),
                    ])
    except sqlite3.OperationalError:
        pass
    try:
        rows = connection.execute(
            "SELECT plan_id, request_hash, status, payload FROM partition_plans ORDER BY plan_id"
        ).fetchall()
        for plan_id, request_hash, status, raw in rows:
            payload = json.loads(raw) if isinstance(raw, str) else raw
            result["partition_plans"].append([
                plan_id,
                request_hash,
                status,
                payload.get("plan_hash"),
                _semantic_sha256(connection, payload, blob_rows=blob_rows),
            ])
    except sqlite3.OperationalError:
        pass
    result["active_attempts"].sort(key=lambda item: str(item[0]))
    return result


def _json_payload(value: Any) -> dict[str, Any]:
    payload = json.loads(value) if isinstance(value, str) else value
    if not isinstance(payload, dict):
        raise RuntimeError("stored aggregate payload is not a JSON object")
    return payload


def _plan_hash(payload: dict[str, Any]) -> str:
    value = payload.get("plan_hash")
    if value:
        return str(value)
    plan = payload.get("plan")
    return str(plan.get("plan_hash") or "") if isinstance(plan, dict) else ""


def _cutover_identity(
    connection: sqlite3.Connection,
    *,
    database: str = "main",
) -> dict[str, Any]:
    """Return the small mutable contract that must survive a live cutover."""
    if database not in {"main", "live"}:
        raise ValueError("cutover identity database must be main or live")
    jobs_table = f"{database}.{_quoted('jobs')}"
    plans_table = f"{database}.{_quoted('partition_plans')}"
    result: dict[str, Any] = {
        "counts": _counts(connection, database=database),
        "jobs": [],
        "partition_plans": [],
        "active_attempts": [],
    }
    job_columns = {
        str(row[1])
        for row in connection.execute(
            f"PRAGMA {database}.table_info({_quoted('jobs')})"
        ).fetchall()
    }
    operational_select = (
        ", operational_payload" if "operational_payload" in job_columns else ", NULL"
    )
    for job_id, request_hash, status, revision, raw, operational_raw in connection.execute(
        "SELECT job_id, request_hash, status, revision, payload"
        f"{operational_select} FROM {jobs_table} ORDER BY job_id"
    ):
        payload = _json_payload(raw)
        operational = (
            _json_payload(operational_raw) if operational_raw is not None else None
        )
        attempt_source = operational or payload
        operational_hash = hashlib.sha256(
            _canonical(operational or {})
        ).hexdigest()
        result["jobs"].append([
            str(job_id),
            str(request_hash or ""),
            str(status or ""),
            int(revision or 0),
            operational_hash,
        ])
        for unit in attempt_source.get("work_units") or []:
            if not isinstance(unit, dict):
                continue
            attempts = unit.get("attempts") or []
            if not attempts:
                continue
            latest = attempts[-1]
            if latest.get("state") in {
                "assigned", "submitting", "running", "cancel_pending",
                "reconcile_pending", "uncertain", "collecting",
            }:
                result["active_attempts"].append([
                    latest.get("attempt_id"),
                    job_id,
                    unit.get("work_unit_id"),
                    latest.get("state"),
                    bool(latest.get("execution_started")),
                    latest.get("external_run_id"),
                ])
    for plan_id, request_hash, status, raw in connection.execute(
        "SELECT plan_id, request_hash, status, payload "
        f"FROM {plans_table} ORDER BY plan_id"
    ):
        payload = _json_payload(raw)
        result["partition_plans"].append([
            str(plan_id),
            str(request_hash or ""),
            str(status or ""),
            _plan_hash(payload),
        ])
    result["active_attempts"].sort(key=lambda item: str(item[0]))
    return result


def _scientific_contract(identity: dict[str, Any]) -> dict[str, list[list[Any]]]:
    return {
        "jobs": [[row[0], row[1]] for row in identity.get("jobs") or []],
        "partition_plans": [
            [row[0], row[1], row[3]]
            for row in identity.get("partition_plans") or []
        ],
    }


def _transplant_item_references(current: Any, prepared: Any) -> Any:
    """Keep current outer state while reusing prepared self-contained item blobs."""
    if isinstance(current, dict):
        if not isinstance(prepared, dict):
            raise RuntimeError("prepared aggregate shape differs from the live database")
        result: dict[str, Any] = {}
        for key, value in current.items():
            if key not in prepared:
                result[key] = value
                continue
            if key == "items":
                candidate = prepared[key]
                if not (
                    isinstance(candidate, dict)
                    and set(candidate) == {MARKER}
                ):
                    raise RuntimeError("prepared aggregate has no compact item-list reference")
                result[key] = candidate
            else:
                result[key] = _transplant_item_references(value, prepared[key])
        return result
    if isinstance(current, list):
        if not isinstance(prepared, list) or len(current) != len(prepared):
            raise RuntimeError("prepared aggregate list shape differs from the live database")
        return [
            _transplant_item_references(value, prepared[index])
            for index, value in enumerate(current)
        ]
    return current


def _table_names(connection: sqlite3.Connection, database: str = "main") -> list[str]:
    return [
        str(row[0])
        for row in connection.execute(
            f"SELECT name FROM {database}.sqlite_master "
            "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )
    ]


def _quoted(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def refresh_prepared_storage_migration(
    source: Path,
    prepared: Path,
    output: Path,
) -> dict[str, Any]:
    """Merge live operational deltas into a prepared compact database.

    Scientific item lists remain content-addressed from the prepared snapshot.
    A changed Job request or Plan hash rejects the cutover instead of expanding
    and recompressing hundreds of megabytes while the service is stopped.
    """
    source = source.resolve()
    prepared = prepared.resolve()
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".new")
    temporary.unlink(missing_ok=True)
    shutil.copy2(prepared, temporary)
    source_uri = source.as_posix().replace("'", "''")
    try:
        with closing(sqlite3.connect(str(temporary))) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            connection.execute(f"ATTACH DATABASE '{source_uri}' AS live")
            try:
                live_identity = _cutover_identity(connection, database="live")
                prepared_identity = _cutover_identity(connection)
                if _scientific_contract(live_identity) != _scientific_contract(prepared_identity):
                    raise RuntimeError(
                        "scientific Job or PartitionPlan contracts changed after migration prepare; "
                        "prepare a fresh online snapshot before cutover"
                    )

                live_tables = set(_table_names(connection, "live"))
                main_tables = set(_table_names(connection))
                if live_tables != main_tables:
                    raise RuntimeError("database schema changed after migration prepare")
                aggregate_tables = {"jobs", "partition_plans", "storage_blobs"}
                for table in sorted(main_tables - aggregate_tables):
                    quoted = _quoted(table)
                    main_columns = [
                        str(row[1])
                        for row in connection.execute(f"PRAGMA main.table_info({quoted})")
                    ]
                    live_columns = [
                        str(row[1])
                        for row in connection.execute(f"PRAGMA live.table_info({quoted})")
                    ]
                    if main_columns != live_columns:
                        raise RuntimeError(f"table schema changed after migration prepare: {table}")
                    columns = ", ".join(_quoted(column) for column in main_columns)
                    connection.execute(f"DELETE FROM main.{quoted}")
                    connection.execute(
                        f"INSERT INTO main.{quoted} ({columns}) "
                        f"SELECT {columns} FROM live.{quoted}"
                    )

                for table, key in (("jobs", "job_id"), ("partition_plans", "plan_id")):
                    quoted = _quoted(table)
                    columns = [
                        str(row[1])
                        for row in connection.execute(f"PRAGMA main.table_info({quoted})")
                    ]
                    column_sql = ", ".join(_quoted(column) for column in columns)
                    placeholders = ", ".join("?" for _ in columns)
                    key_index = columns.index(key)
                    payload_index = columns.index("payload")
                    live_rows = connection.execute(
                        f"SELECT {column_sql} FROM live.{quoted} ORDER BY {_quoted(key)}"
                    ).fetchall()
                    for live_row in live_rows:
                        aggregate_id = live_row[key_index]
                        prepared_row = connection.execute(
                            f"SELECT payload FROM main.{quoted} WHERE {_quoted(key)} = ?",
                            (aggregate_id,),
                        ).fetchone()
                        if prepared_row is None:
                            raise RuntimeError(
                                f"{table} changed after migration prepare: {aggregate_id}"
                            )
                        values = list(live_row)
                        values[payload_index] = json.dumps(
                            _transplant_item_references(
                                _json_payload(values[payload_index]),
                                _json_payload(prepared_row[0]),
                            ),
                            ensure_ascii=True,
                            separators=(",", ":"),
                        )
                        connection.execute(
                            f"DELETE FROM main.{quoted} WHERE {_quoted(key)} = ?",
                            (aggregate_id,),
                        )
                        connection.execute(
                            f"INSERT INTO main.{quoted} ({column_sql}) VALUES ({placeholders})",
                            values,
                        )

                _rebuild_blob_reference_counts(connection)
                connection.commit()
                refreshed_identity = _cutover_identity(connection)
                if refreshed_identity != live_identity:
                    raise RuntimeError("operational identity changed while refreshing compact storage")
                integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
                if integrity.lower() != "ok":
                    raise RuntimeError("refreshed compact database failed integrity_check")
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.execute("DETACH DATABASE live")
            connection.execute("VACUUM")
        temporary.replace(output)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return {
        "prepared": str(output),
        "after_bytes": output.stat().st_size,
        "identity": refreshed_identity,
        "integrity": "ok",
        "delta_refresh": True,
    }


def storage_doctor(database: Path, *, root: Path | None = None) -> dict[str, Any]:
    database = database.resolve()
    report: dict[str, Any] = {"database_bytes": database.stat().st_size if database.exists() else 0}
    for suffix, key in (("-wal", "wal_bytes"), ("-shm", "shm_bytes")):
        path = Path(str(database) + suffix)
        report[key] = path.stat().st_size if path.exists() else 0
    if database.exists():
        with closing(sqlite3.connect(f"file:{database}?mode=ro", uri=True)) as connection:
            report["integrity"] = connection.execute("PRAGMA integrity_check").fetchone()[0]
            report["tables"] = _counts(connection)
            report["payload_bytes"] = {
                table: int(connection.execute(f"SELECT COALESCE(sum(length(payload)), 0) FROM {table}").fetchone()[0])
                for table in ("jobs", "partition_plans")
            }
            try:
                report["storage_blobs"] = int(connection.execute("SELECT count(*) FROM storage_blobs").fetchone()[0])
                blob_sizes = connection.execute(
                    "SELECT COALESCE(sum(original_size), 0), "
                    "COALESCE(sum(length(compressed_payload)), 0), "
                    "COALESCE(sum(CASE WHEN reference_count = 0 THEN 1 ELSE 0 END), 0) "
                    "FROM storage_blobs"
                ).fetchone()
                report["storage_blob_original_bytes"] = int(blob_sizes[0])
                report["storage_blob_compressed_bytes"] = int(blob_sizes[1])
                report["storage_blob_unreferenced"] = int(blob_sizes[2])
            except sqlite3.OperationalError:
                report["storage_blobs"] = 0
                report["storage_blob_original_bytes"] = 0
                report["storage_blob_compressed_bytes"] = 0
                report["storage_blob_unreferenced"] = 0
    if root is not None:
        root = root.resolve()
        for name in ("releases", "runtime", "spool", "archive-staging"):
            path = root / name
            report[f"{name}_bytes"] = sum(item.stat().st_size for item in path.rglob("*") if item.is_file()) if path.exists() else 0
    return report


def prepare_storage_migration(database: Path, output_dir: Path) -> dict[str, Any]:
    database = database.resolve()
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    backup = output_dir / "source-backup.db"
    working = output_dir / "migrated.db"
    compacted = output_dir / "migrated-compact.db"
    _online_backup(database, backup)
    shutil.copy2(backup, working)
    with closing(sqlite3.connect(str(working))) as connection:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS storage_blobs ("
            "sha256 TEXT PRIMARY KEY, codec TEXT NOT NULL, original_size INTEGER NOT NULL, "
            "compressed_payload BLOB NOT NULL, created_at TEXT NOT NULL, reference_count INTEGER NOT NULL DEFAULT 0)"
        )
        blob_rows = _blob_row_index(connection)
        before = _identity(connection, blob_rows=blob_rows)
        for table in ("partition_plans", "jobs"):
            for row_id, raw in connection.execute(f"SELECT rowid, payload FROM {table}").fetchall():
                payload = json.loads(raw) if isinstance(raw, str) else raw
                compacted_payload = _compact(
                    connection,
                    payload,
                    blob_rows=blob_rows,
                )
                connection.execute(
                    f"UPDATE {table} SET payload = ? WHERE rowid = ?",
                    (json.dumps(compacted_payload, ensure_ascii=True, separators=(",", ":")), row_id),
                )
        _rebuild_blob_reference_counts(connection)
        connection.commit()
        after = _identity(connection)
        if before != after:
            raise RuntimeError("metadata identity changed during storage migration")
        vacuum_target = compacted.as_posix().replace("'", "''")
        connection.execute(f"VACUUM INTO '{vacuum_target}'")
    before_size = database.stat().st_size
    after_size = compacted.stat().st_size
    manifest = {
        "schema_version": MIGRATION_SCHEMA_VERSION,
        "algorithm": MIGRATION_ALGORITHM,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source": str(database),
        "backup": str(backup),
        "prepared": str(compacted),
        "before_bytes": before_size,
        "after_bytes": after_size,
        "reduction_ratio": round(1 - after_size / before_size, 6) if before_size else 0.0,
        "identity": after,
        "integrity": "ok",
    }
    manifest_path = output_dir / "migration-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest | {"manifest_path": str(manifest_path)}


def promote_storage_migration(manifest_path: Path, *, confirm: bool = False) -> dict[str, Any]:
    if not confirm:
        raise ValueError("promotion requires explicit confirmation")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if (
        int(manifest.get("schema_version") or 0) != MIGRATION_SCHEMA_VERSION
        or manifest.get("algorithm") != MIGRATION_ALGORITHM
    ):
        raise ValueError("storage migration was prepared by an unsupported implementation")
    source = Path(manifest["source"]).resolve()
    prepared = Path(manifest["prepared"]).resolve()
    rollback = source.with_suffix(source.suffix + ".pre-0.13.2.bak")
    _online_backup(source, rollback)
    temporary = source.with_suffix(source.suffix + ".new")
    shutil.copy2(prepared, temporary)
    displaced = source.with_suffix(source.suffix + ".cutover-old")
    displaced.unlink(missing_ok=True)
    source.replace(displaced)
    try:
        temporary.replace(source)
        with closing(sqlite3.connect(str(source))) as connection:
            integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
            identity = _identity(connection)
        if integrity.lower() != "ok" or identity != manifest["identity"]:
            raise RuntimeError("promoted database failed integrity or identity verification")
    except Exception:
        source.unlink(missing_ok=True)
        displaced.replace(source)
        raise
    displaced.unlink(missing_ok=True)
    return {"promoted": True, "database": str(source), "rollback": str(rollback), "manifest_path": str(manifest_path)}


def promote_storage_migration_coordinated(
    manifest_path: Path,
    *,
    confirm: bool = False,
    service_url: str = "http://127.0.0.1:8765",
    token: str,
    task_name: str = "ResearchComputeNetwork-ControlPlane",
    expected_machine_count: int = 5,
    release_manifest_path: Path | None = None,
) -> dict[str, Any]:
    """Run the production cutover with Dispatcher drain and automatic restore."""
    if not confirm or not token:
        raise ValueError("coordinated promotion requires confirmation and RCN_TOKEN")
    from .deployment import (
        _default_http_get,
        _default_http_post,
        _dispatcher_control_action,
        _default_restart_task,
        _atomic_json,
        _restore_pointer,
        stop_control_plane_task,
        verify_control_plane_release,
    )

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if (
        int(manifest.get("schema_version") or 0) != MIGRATION_SCHEMA_VERSION
        or manifest.get("algorithm") != MIGRATION_ALGORITHM
    ):
        raise ValueError("storage migration was prepared by an unsupported implementation")
    if release_manifest_path is None:
        raise ValueError("a Control Plane release manifest is required")
    release_manifest = json.loads(release_manifest_path.read_text(encoding="utf-8"))
    release_state = str(release_manifest.get("state") or "")
    if release_state not in {"prepared", "promoted"}:
        raise ValueError("a prepared or currently promoted Control Plane release is required")
    if float(manifest.get("reduction_ratio") or 0.0) < 0.30:
        raise ValueError("storage migration did not reach the required 30% reduction")
    pointer_path = Path(release_manifest["pointer_path"]).resolve()
    current_pointer = (
        json.loads(pointer_path.read_text(encoding="utf-8"))
        if pointer_path.is_file()
        else None
    )
    pointer_already_live = release_state == "promoted"
    if pointer_already_live and current_pointer != release_manifest.get("candidate_pointer"):
        raise ValueError("the promoted release manifest is not the current runtime pointer")
    rollback_pointer = (
        current_pointer
        if pointer_already_live
        else release_manifest.get("previous_pointer")
    )
    source = Path(manifest["source"]).resolve()
    if Path(release_manifest["database"]).resolve() != source:
        raise ValueError("storage and Control Plane release manifests reference different databases")
    prepared = Path(manifest["prepared"]).resolve()
    rollback = source.with_suffix(source.suffix + ".pre-0.13.2.bak")
    post = _default_http_post
    get = _default_http_get
    stopped_dispatcher = False
    stopped_control_plane = False
    database_backup_ready = False
    database_swapped = False
    try:
        _dispatcher_control_action(
            service_url=service_url, token=token, action="drain",
            reason="0.13.2 storage migration", http_post=post,
        )
        _dispatcher_control_action(
            service_url=service_url, token=token, action="stop",
            reason="0.13.2 storage migration", http_post=post,
        )
        stopped_dispatcher = True
        stop_control_plane_task(task_name)
        stopped_control_plane = True
        refreshed_path = manifest_path.parent / (
            "cutover-delta-"
            + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            + ".db"
        )
        refreshed = refresh_prepared_storage_migration(
            source,
            prepared,
            refreshed_path,
        )
        manifest.update(refreshed)
        manifest["reduction_ratio"] = (
            round(1 - int(manifest["after_bytes"]) / int(manifest["before_bytes"]), 6)
            if int(manifest.get("before_bytes") or 0)
            else 0.0
        )
        if float(manifest["reduction_ratio"]) < 0.30:
            raise RuntimeError("refreshed storage migration fell below the required 30% reduction")
        prepared = Path(manifest["prepared"]).resolve()
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        _online_backup(source, rollback)
        database_backup_ready = True
        temporary = source.with_suffix(source.suffix + ".new")
        shutil.copy2(prepared, temporary)
        displaced = source.with_suffix(source.suffix + ".cutover-old")
        displaced.unlink(missing_ok=True)
        source.replace(displaced)
        try:
            temporary.replace(source)
            database_swapped = True
        except Exception:
            source.unlink(missing_ok=True)
            displaced.replace(source)
            raise
        displaced.unlink(missing_ok=True)
        if not pointer_already_live:
            _atomic_json(pointer_path, release_manifest["candidate_pointer"])
        _default_restart_task(task_name)
        stopped_control_plane = False
        verification = None
        last_error: Exception | None = None
        for attempt in range(90):
            try:
                if stopped_dispatcher:
                    _dispatcher_control_action(
                        service_url=service_url, token=token, action="start",
                        reason="0.13.2 storage migration", http_post=post,
                    )
                    stopped_dispatcher = False
                verification = verify_control_plane_release(
                    database=source, service_url=service_url, token=token,
                    expected_machine_count=expected_machine_count, http_get=get,
                )
                break
            except Exception as exc:
                last_error = exc
                if attempt < 89:
                    time.sleep(2)
        if verification is None:
            raise last_error or RuntimeError("storage release verification timed out")
        manifest["state"] = "promoted"
        manifest["promoted_at"] = datetime.now(timezone.utc).isoformat()
        manifest["verification"] = verification
        if not pointer_already_live:
            release_manifest["state"] = "promoted"
            release_manifest["promoted_at"] = datetime.now(timezone.utc).isoformat()
            release_manifest["verification"] = verification
        release_manifest["storage_migration"] = {
            "state": "promoted",
            "manifest_path": str(manifest_path.resolve()),
            "promoted_at": manifest["promoted_at"],
            "database_bytes": int(manifest["after_bytes"]),
            "reduction_ratio": float(manifest["reduction_ratio"]),
        }
        release_manifest_path.write_text(json.dumps(release_manifest, indent=2) + "\n", encoding="utf-8")
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        return manifest | {"manifest_path": str(manifest_path)}
    except Exception as exc:
        try:
            if not stopped_control_plane:
                stop_control_plane_task(task_name)
                stopped_control_plane = True
        except Exception:
            pass
        try:
            _restore_pointer(pointer_path, rollback_pointer)
            if database_swapped and database_backup_ready:
                temporary = source.with_suffix(source.suffix + ".rollback")
                shutil.copy2(rollback, temporary)
                displaced = source.with_suffix(source.suffix + ".rollback-old")
                displaced.unlink(missing_ok=True)
                source.replace(displaced)
                try:
                    temporary.replace(source)
                except Exception:
                    source.unlink(missing_ok=True)
                    displaced.replace(source)
                    raise
                displaced.unlink(missing_ok=True)
            if stopped_control_plane or database_swapped:
                _default_restart_task(task_name)
        finally:
            if stopped_dispatcher:
                try:
                    _dispatcher_control_action(
                        service_url=service_url, token=token, action="start",
                        reason="rollback 0.13.2 storage migration", http_post=post,
                    )
                except Exception:
                    pass
        manifest["state"] = "rolled_back"
        storage_rollback = {
            "state": "rolled_back",
            "automatic": True,
            "rolled_back_at": datetime.now(timezone.utc).isoformat(),
            "reason": f"{type(exc).__name__}: {exc}"[:500],
        }
        if pointer_already_live:
            release_manifest["storage_migration"] = storage_rollback
        else:
            release_manifest["state"] = "rolled_back"
            release_manifest["rollback"] = storage_rollback
        release_manifest_path.write_text(json.dumps(release_manifest, indent=2) + "\n", encoding="utf-8")
        manifest["rollback"] = {
            "automatic": True,
            "rolled_back_at": datetime.now(timezone.utc).isoformat(),
            "reason": f"{type(exc).__name__}: {exc}"[:500],
        }
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        raise RuntimeError("storage promotion failed; previous database was restored") from exc


def rollback_storage_migration(manifest_path: Path, *, confirm: bool = False) -> dict[str, Any]:
    if not confirm:
        raise ValueError("rollback requires explicit confirmation")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    source = Path(manifest["source"]).resolve()
    rollback = source.with_suffix(source.suffix + ".pre-0.13.2.bak")
    if not rollback.exists():
        raise FileNotFoundError(rollback)
    temporary = source.with_suffix(source.suffix + ".rollback")
    shutil.copy2(rollback, temporary)
    displaced = source.with_suffix(source.suffix + ".rollback-old")
    displaced.unlink(missing_ok=True)
    source.replace(displaced)
    try:
        temporary.replace(source)
    except Exception:
        displaced.replace(source)
        raise
    displaced.unlink(missing_ok=True)
    return {"rolled_back": True, "database": str(source), "manifest_path": str(manifest_path)}
