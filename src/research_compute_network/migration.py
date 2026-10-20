"""Recoverable SQLite state migration with exact table-count verification."""

from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone
import hashlib
import sqlite3
from pathlib import Path

from .models import AuditEvent, DispatcherPhase, DispatcherStatus
from .repository import MetadataRepository


def sqlite_table_counts(path: str | Path) -> dict[str, int]:
    database = Path(path).resolve()
    if not database.is_file():
        raise FileNotFoundError(database)
    with closing(sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True)) as connection:
        quick_check = connection.execute("PRAGMA quick_check").fetchone()[0]
        if quick_check != "ok":
            raise ValueError(f"SQLite quick_check failed: {quick_check}")
        tables = [
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        ]
        return {
            table: int(connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])
            for table in tables
        }


def migrate_sqlite_database(source: str | Path, destination: str | Path) -> dict:
    source_path = Path(source).resolve()
    destination_path = Path(destination).resolve()
    if not source_path.is_file():
        raise FileNotFoundError(source_path)
    if destination_path.exists():
        raise FileExistsError(f"migration destination already exists: {destination_path}")
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    before = sqlite_table_counts(source_path)
    with closing(sqlite3.connect(f"file:{source_path.as_posix()}?mode=ro", uri=True)) as source_connection:
        with closing(sqlite3.connect(destination_path)) as destination_connection:
            source_connection.backup(destination_connection)
    after = sqlite_table_counts(destination_path)
    if before != after:
        destination_path.unlink(missing_ok=True)
        raise ValueError("SQLite migration record counts do not match; destination was removed")
    return {
        "source": str(source_path),
        "destination": str(destination_path),
        "tables": before,
        "total_records": sum(before.values()),
        "verified": True,
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _online_backup(source: Path, destination: Path) -> None:
    if destination.exists():
        raise FileExistsError(f"backup destination already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.unlink(missing_ok=True)
    with closing(sqlite3.connect(f"file:{source.as_posix()}?mode=ro", uri=True)) as source_connection:
        with closing(sqlite3.connect(temporary)) as destination_connection:
            source_connection.backup(destination_connection)
            if destination_connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise ValueError("SQLite backup integrity check failed")
    temporary.replace(destination)


def create_clean_formal_database(
    source: str | Path,
    destination: str | Path,
    archive: str | Path,
    *,
    actor_id: str,
) -> dict:
    """Create a job-free formal database from an explicit configuration whitelist."""
    source_path = Path(source).resolve()
    destination_path = Path(destination).resolve()
    archive_path = Path(archive).resolve()
    if not source_path.is_file():
        raise FileNotFoundError(source_path)
    if destination_path.exists():
        raise FileExistsError(f"clean database destination already exists: {destination_path}")
    if archive_path.exists():
        raise FileExistsError(f"archive destination already exists: {archive_path}")
    if len({source_path, destination_path, archive_path}) != 3:
        raise ValueError("source, destination, and archive paths must be distinct")

    _online_backup(source_path, archive_path)
    source_counts = sqlite_table_counts(archive_path)
    source_sha256 = _sha256(archive_path)
    source_repository = MetadataRepository(f"sqlite:///{archive_path.as_posix()}")
    destination_repository = MetadataRepository(f"sqlite:///{destination_path.as_posix()}")
    from .service import NetworkService

    NetworkService(destination_repository).initialize(dataset_mode="formal")
    migrated_counts: dict[str, int] = {}

    def copy_many(name: str, values, writer) -> None:
        copied = 0
        for value in values:
            writer(value)
            copied += 1
        migrated_counts[name] = copied

    copy_many("execution_profiles", source_repository.list_profiles(), destination_repository.put_profile)
    copy_many("users", source_repository.list_users(), destination_repository.put_user)
    copy_many(
        "active_api_tokens",
        [token for token in source_repository.list_tokens() if token.is_active()],
        destination_repository.put_token,
    )
    copy_many(
        "active_machine_credentials",
        [credential for credential in source_repository.list_machine_credentials() if credential.is_active()],
        destination_repository.put_machine_credential,
    )
    copy_many("project_grants", source_repository.list_project_grants(), destination_repository.put_project_grant)
    copy_many("machines", source_repository.list_machines(), destination_repository.put_machine)
    copy_many(
        "machine_policies",
        [
            policy
            for machine in source_repository.list_machines()
            if (policy := source_repository.get_policy(machine.machine_id)) is not None
        ],
        destination_repository.put_policy,
    )
    copy_many("approvals", source_repository.list_approvals(), destination_repository.put_approval)
    copy_many(
        "solver_approvals",
        source_repository.list_solver_approvals(),
        destination_repository.put_solver_approval,
    )
    copy_many(
        "machine_execution_configs",
        source_repository.list_machine_execution_configs(),
        lambda config: destination_repository.put_machine_execution_config(config, touch=False),
    )
    destination_repository.put_feature_settings(source_repository.get_feature_settings())
    migrated_counts["feature_settings"] = 1
    break_glass = source_repository.get_break_glass_config()
    if break_glass is not None:
        destination_repository.put_break_glass_config(break_glass)
    migrated_counts["break_glass_config"] = int(break_glass is not None)

    destination_repository.put_dispatcher_status(DispatcherStatus(
        phase=DispatcherPhase.STOPPED,
        accepting_assignments=False,
        control_mode="drain",
        desired_state="open",
        stop_reason="clean baseline prepared for automatic recovery",
        blocked_reason="",
        auto_resume_allowed=True,
        pending_reconciliation=0,
    ))
    destination_repository.append_event(AuditEvent(
        event_type="database.clean_baseline_genesis",
        actor_id=actor_id,
        subject_type="database",
        subject_id="formal",
        details={
            "source_sha256": source_sha256,
            "source_table_counts": source_counts,
            "archive_path": str(archive_path),
            "cutover_prepared_at": datetime.now(timezone.utc).isoformat(),
            "migrated_counts": migrated_counts,
        },
    ))

    destination_counts = sqlite_table_counts(destination_path)
    excluded_tables = {
        "jobs", "partition_plans", "artifact_manifests", "remote_runs",
        "machine_metric_samples", "alerts", "pressure_override_tickets",
        "admin_operation_tickets", "machine_control_tickets",
        "control_operation_runs", "machine_command_results",
        "dispatcher_control_tickets", "origin_import_receipts",
        "ssh_acceptance_runs", "machine_preflight_runs", "node_enrollments",
    }
    nonempty_excluded = {
        table: destination_counts.get(table, 0)
        for table in excluded_tables
        if destination_counts.get(table, 0)
    }
    if nonempty_excluded:
        destination_path.unlink(missing_ok=True)
        raise ValueError(f"clean database contains excluded records: {sorted(nonempty_excluded)}")
    if destination_counts.get("audit_events") != 1:
        destination_path.unlink(missing_ok=True)
        raise ValueError("clean database must contain exactly one genesis audit event")

    source_repository.engine.dispose()
    destination_repository.engine.dispose()
    archive_path.chmod(0o444)
    return {
        "source": str(source_path),
        "destination": str(destination_path),
        "archive": str(archive_path),
        "source_sha256": source_sha256,
        "source_table_counts": source_counts,
        "destination_table_counts": destination_counts,
        "migrated_counts": migrated_counts,
        "excluded_records": 0,
        "verified": True,
    }


def cutover_sqlite_database(
    active: str | Path,
    prepared: str | Path,
    rollback: str | Path,
) -> dict:
    """Atomically exchange a stopped SQLite service database with one-step rollback."""
    active_path = Path(active).resolve()
    prepared_path = Path(prepared).resolve()
    rollback_path = Path(rollback).resolve()
    if not active_path.is_file() or not prepared_path.is_file():
        raise FileNotFoundError("active and prepared databases must both exist")
    if rollback_path.exists():
        raise FileExistsError(f"rollback path already exists: {rollback_path}")
    if len({active_path, prepared_path, rollback_path}) != 3:
        raise ValueError("active, prepared, and rollback paths must be distinct")
    sidecars = [
        path
        for database in (active_path, prepared_path)
        for suffix in ("-wal", "-shm", "-journal")
        if (path := Path(str(database) + suffix)).exists()
    ]
    if sidecars:
        raise RuntimeError("SQLite sidecar files exist; stop the Control Plane before cutover")
    sqlite_table_counts(active_path)
    sqlite_table_counts(prepared_path)
    active_path.replace(rollback_path)
    try:
        prepared_path.replace(active_path)
    except BaseException:
        rollback_path.replace(active_path)
        raise
    return {
        "active": str(active_path),
        "rollback": str(rollback_path),
        "active_sha256": _sha256(active_path),
        "rollback_sha256": _sha256(rollback_path),
        "verified": True,
    }
