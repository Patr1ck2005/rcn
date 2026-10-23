"""Exercise actual candidate storage startup on a disposable release database."""
import hashlib
from pathlib import Path
import sqlite3
import sys

import pytest

from research_compute_network import deployment
from research_compute_network.repository import MetadataRepository
from research_compute_network.storage_lifecycle import StorageLifecycle


@pytest.fixture
def baseline(tmp_path):
    database = tmp_path / "online-backup.db"
    repository = MetadataRepository("sqlite:///" + database.as_posix())
    try:
        repository.init_schema()
        StorageLifecycle(repository, tmp_path / "origin-spool")
    finally:
        repository.engine.dispose()
    with sqlite3.connect(database) as db:
        # Model an initialized batch1 lifecycle with the new derived inventory
        # absent. The real custody table, its original row and all definitions
        # remain inputs to the release compatibility proof.
        db.execute("DROP TRIGGER storage_inventory_science_intent")
        names = [row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' "
                 "AND (name LIKE 'storage_inventory_%' OR name LIKE 'storage_occupancy_%')")]
        for name in names:
            db.execute("DROP TABLE " + deployment._sqlite_identifier(name))
        db.execute("INSERT INTO storage_lifecycle_receipts "
                   "(receipt_id,idempotency_key,job_id,unit_id,attempt_id,fingerprint,payload,recorded_at) "
                   "VALUES ('original-receipt','original-key','job-original','unit-original',"
                   "'attempt-original',?,'{\"verified_by\":\"owner\"}','original-time')", ("a" * 64,))
        db.commit()
        db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    db.close()
    return database


def real_candidate(monkeypatch, *, extra_sql=None):
    """Run the exact candidate script with the selected source as test runtime."""
    original = deployment.subprocess.run
    source = Path(deployment.__file__).resolve().parents[1]
    executed = []

    def run(command, **kwargs):
        assert "StorageLifecycle(repository," in command[2]
        assert "RegisteredResultSources(lifecycle)" in command[2]
        assert "service.initialize" not in command[2]
        assert "PYTHONPATH" not in kwargs["env"]
        script = "import sys\nsys.path.insert(0, " + repr(str(source)) + ")\n" + command[2]
        if extra_sql:
            script += ("\nimport sqlite3\nwith sqlite3.connect(sys.argv[1].removeprefix('sqlite:///')) as db:\n"
                       "    db.executescript(" + repr(extra_sql) + ")\n")
        executed.append(command[2])
        return original([sys.executable, "-I", "-B", "-c", script, command[-1]], **kwargs)

    monkeypatch.setattr(deployment.subprocess, "run", run)
    return executed


def test_actual_storage_startup_is_validated_and_preserves_original_database(baseline, monkeypatch):
    pristine = baseline.read_bytes()
    executed = real_candidate(monkeypatch)
    receipt = deployment._validate_additive_schema(Path(sys.executable), baseline)
    compatibility = receipt["compatibility_receipt"]
    assert executed and receipt["verified"]
    assert baseline.read_bytes() == pristine
    assert compatibility["table_data_before"] == compatibility["table_data_after"]
    after_objects = {(row[0], row[1]): row for row in receipt["schema_after"]["objects"]}
    assert all(after_objects[(row[0], row[1])] == row for row in receipt["schema_before"]["objects"])
    assert compatibility["table_data_after"]["storage_lifecycle_receipts"]["row_count"] == 1
    expected = {"storage_restore_receipt_evidence": hashlib.sha256(
        deployment._STORAGE_RESTORE_VIEW.encode()).hexdigest()}
    assert receipt["added_objects"]["approved_read_only_views"] == expected
    assert compatibility["approved_read_only_views"] == expected
    assert "storage_inventory_science_intent" in compatibility["approved_projection_triggers"]
    assert {"storage_restore_stores", "storage_restore_files", "storage_restore_readers"}.issubset(
        receipt["added_objects"]["tables"])
    with sqlite3.connect(receipt["validation_database"]) as db:
        assert db.execute("SELECT receipt_id FROM storage_restore_receipt_evidence").fetchall() == [("original-receipt",)]
        with pytest.raises(sqlite3.OperationalError, match="cannot modify"):
            db.execute("DELETE FROM storage_restore_receipt_evidence")
    # Re-running actual startup preserves the already installed view and hook.
    repeated = deployment._validate_additive_schema(Path(sys.executable), Path(receipt["validation_database"]))
    assert repeated["verified"] and not repeated["added_objects"]["approved_read_only_views"]


@pytest.mark.parametrize("extra_sql", [
    "CREATE VIEW unrelated_release_view AS SELECT 1;",
    "DROP VIEW storage_restore_receipt_evidence; CREATE VIEW storage_restore_receipt_evidence AS SELECT 1;",
    "CREATE TRIGGER restore_view_writer INSTEAD OF DELETE ON storage_restore_receipt_evidence "
    "BEGIN DELETE FROM storage_lifecycle_receipts; END;",
    "DROP TRIGGER storage_inventory_science_intent; "
    "CREATE TRIGGER storage_inventory_science_intent AFTER INSERT ON storage_lifecycle_intents "
    "BEGIN DELETE FROM storage_lifecycle_receipts; END;",
])
def test_actual_storage_startup_rejects_unreviewed_views_and_view_writers(baseline, monkeypatch, extra_sql):
    pristine = baseline.read_bytes()
    real_candidate(monkeypatch, extra_sql=extra_sql)
    with pytest.raises(ValueError, match="exact approved"):
        deployment._validate_additive_schema(Path(sys.executable), baseline)
    assert baseline.read_bytes() == pristine


def test_storage_initialization_cannot_rewrite_original_custody(baseline, monkeypatch):
    pristine = baseline.read_bytes()
    real_candidate(monkeypatch, extra_sql="UPDATE storage_lifecycle_receipts SET payload='{}';")
    with pytest.raises(ValueError, match="rewrote original table data"):
        deployment._validate_additive_schema(Path(sys.executable), baseline)
    assert baseline.read_bytes() == pristine


def test_new_storage_hook_cannot_write_existing_projection_tables(baseline, monkeypatch):
    from research_compute_network.storage_projection import ensure_schema
    with sqlite3.connect(baseline) as db:
        ensure_schema(db)
        db.commit()
        db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    db.close()
    real_candidate(monkeypatch)
    with pytest.raises(ValueError, match="writing exclusively to new projection tables"):
        deployment._validate_additive_schema(Path(sys.executable), baseline)
