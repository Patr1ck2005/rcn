import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from research_compute_network.storage_occupancy import OccupancyInventory, native_allocation
from research_compute_network.storage_projection import record_file, retire_file
from research_compute_network.storage_io import BackgroundDeferred, io_priority
from test_storage_lifecycle import custody, selection


def test_exact_path_cursor_bounds_probes_and_deduplicates_native_hardlinks(custody, monkeypatch):
    h = custody
    record = next(f for f in h.manifest.files if f.relative_path == "metrics.csv")
    alias = h.directory / "metrics-alias.csv"
    os.link(h.directory / record.relative_path, alias)
    with h.lifecycle._transaction() as db:
        record_file(db, project_id=h.job.project_id, role="origin_spool", location="center",
            job_id=h.job.job_id, unit_id=h.unit.work_unit_id, attempt_id="attempt-original",
            record={**record.model_dump(), "relative_path": alias.name},
            locator={"origin_submitter_id": h.job.origin_submitter_id})
    probes = []
    def probe(path):
        probes.append(path)
        return native_allocation(path)
    inventory = OccupancyInventory(h.lifecycle)
    # Time budget expires before touching even the first registered data file.
    ticks = iter([0, 1, 2])
    assert inventory.advance(clock=lambda: next(ticks), probe=probe)["processed"] == 0
    assert not probes
    assert inventory.advance(max_files=1, time_budget_ms=1000, probe=probe)["processed"] == 1
    partial = h.lifecycle.inventory.snapshot()["projects"][0]
    assert partial["physical_bytes"] is None and partial["measured_files"] == 1
    result = inventory.advance(max_files=32, time_budget_ms=1000, probe=probe)
    assert result["pass_complete"] and len(probes) == 4
    assert h.directory / "unlisted-evidence.json" not in probes
    original = {native_allocation(h.directory / f.relative_path)["object_key"]:
                native_allocation(h.directory / f.relative_path)["allocated_bytes"] for f in h.manifest.files}
    row = h.lifecycle.inventory.snapshot()["projects"][0]
    assert row["physical_bytes"] == sum(original.values())
    assert row["registered_files"] == row["measured_files"] == 4
    assert native_allocation(alias)["object_key"] == native_allocation(h.directory / record.relative_path)["object_key"]
    with h.lifecycle._transaction() as db:
        retire_file(db, *selection(h), record.relative_path)
    # Removing the first hardlink's reference transfers attribution to its alias.
    assert h.lifecycle.inventory.snapshot()["projects"][0]["physical_bytes"] == sum(original.values())
    assert h.lifecycle.inventory.snapshot(now=datetime.now(timezone.utc)+timedelta(days=2))["projects"][0]["physical_bytes"] is None


def test_occupancy_unknowns_and_foreground_yield_do_not_fabricate_physical_bytes(custody):
    inventory = OccupancyInventory(custody.lifecycle)
    with io_priority.foreground():
        with pytest.raises(BackgroundDeferred):
            inventory.advance()
    def unsupported(_):
        raise ValueError("fixture unsupported allocation")
    inventory.advance(time_budget_ms=1000, probe=unsupported)
    row = custody.lifecycle.inventory.snapshot()["projects"][0]
    assert row["physical_bytes"] is None and row["measured_files"] == 0


def test_metadata_snapshot_queries_only_derived_tables_and_never_data_paths(custody, monkeypatch):
    h = custody
    OccupancyInventory(h.lifecycle).advance(time_budget_ms=1000)
    statements = []
    original = h.lifecycle._open_connection
    def traced(**kwargs):
        db = original(**kwargs)
        db.set_trace_callback(statements.append)
        return db
    monkeypatch.setattr(h.lifecycle, "_open_connection", traced)
    def forbidden(*args, **kwargs):
        pytest.fail("ordinary snapshot visited data or history")
    monkeypatch.setattr(h.lifecycle, "_root", forbidden)
    monkeypatch.setattr(Path, "open", forbidden)
    monkeypatch.setattr(Path, "iterdir", forbidden)
    monkeypatch.setattr(Path, "rglob", forbidden)
    snapshot = h.lifecycle.inventory.snapshot()
    assert snapshot["data_reads"] == 0
    assert statements and all("storage_inventory_" in sql or "storage_occupancy_" in sql
                              for sql in statements if sql.lstrip().upper().startswith("SELECT"))


def test_foreground_arriving_during_probe_leaves_cursor_and_projection_unchanged(custody):
    guard = io_priority.foreground()
    def probe(path):
        result = native_allocation(path)
        guard.__enter__()
        return result
    try:
        with pytest.raises(BackgroundDeferred):
            OccupancyInventory(custody.lifecycle).advance(time_budget_ms=1000, probe=probe)
        with custody.lifecycle._connect() as db:
            assert db.execute("SELECT COUNT(*) FROM storage_occupancy_observations").fetchone()[0] == 0
            assert db.execute("SELECT value FROM storage_inventory_state WHERE key='occupancy_cursor'").fetchone() is None
    finally:
        guard.__exit__(None, None, None)


def test_locator_change_invalidates_measured_occupancy(custody):
    h = custody
    OccupancyInventory(h.lifecycle).advance(time_budget_ms=1000)
    assert h.lifecycle.inventory.snapshot()["projects"][0]["physical_bytes"] is not None
    with h.lifecycle._transaction() as db:
        record_file(db, project_id=h.job.project_id, role="origin_spool", location="center",
            job_id=h.job.job_id, unit_id=h.unit.work_unit_id, attempt_id="attempt-original",
            record=h.manifest.files[0].model_dump(), locator={"origin_submitter_id": "changed"})
    assert h.lifecycle.inventory.snapshot()["projects"][0]["physical_bytes"] is None


@pytest.mark.skipif(os.name != "nt", reason="Windows FFI cache")
def test_windows_api_definitions_are_reused_but_observations_stay_fresh(tmp_path):
    from research_compute_network.storage_occupancy import _windows_allocation_api
    path = tmp_path / "allocation.bin"
    path.write_bytes(b"a")
    first = native_allocation(path)
    definitions = _windows_allocation_api()
    path.write_bytes(b"b" * 32768)
    second = native_allocation(path)
    assert _windows_allocation_api() is definitions
    assert first["logical_bytes"] == 1 and second["logical_bytes"] == 32768
    assert second["allocated_bytes"] >= first["allocated_bytes"]


@pytest.mark.skipif(os.name != "nt", reason="Windows native-call boundary")
def test_native_probe_yields_between_os_calls_and_always_closes_handle(tmp_path, monkeypatch):
    from research_compute_network.storage_occupancy import _windows_allocation_api
    kernel = _windows_allocation_api()[1]
    path = tmp_path / "allocation.bin"
    path.write_bytes(b"one original file")
    opened, closed = [], []
    real_open, real_close = kernel.CreateFileW, kernel.CloseHandle
    guard = io_priority.foreground()
    def begin(*args):
        handle = real_open(*args)
        opened.append(handle)
        guard.__enter__()
        return handle
    def close(handle):
        closed.append(handle)
        return real_close(handle)
    monkeypatch.setattr(kernel, "CreateFileW", begin)
    monkeypatch.setattr(kernel, "CloseHandle", close)
    monkeypatch.setattr(kernel, "GetFileInformationByHandleEx", lambda *_:pytest.fail("second OS call ran after foreground arrival"))
    try:
        with pytest.raises(BackgroundDeferred):
            native_allocation(path)
        assert opened and closed == opened
    finally:
        guard.__exit__(None, None, None)


@pytest.mark.parametrize("active", [False, True])
def test_background_budget_closes_metadata_connection_on_admit_and_defer(tmp_path, monkeypatch, active):
    import sqlite3
    from research_compute_network.storage_io import BackgroundBudget
    database = tmp_path / "ledger.db"
    setup = sqlite3.connect(database)
    setup.execute("CREATE TABLE storage_volume_claims(state TEXT)")
    if active:
        setup.execute("INSERT INTO storage_volume_claims VALUES('active')")
    setup.commit()
    setup.close()
    created = []
    connect = sqlite3.connect
    class Tracked(sqlite3.Connection):
        closed = False
        def close(self):
            self.closed = True
            super().close()
    def tracked(*args, **kwargs):
        db = connect(*args, factory=Tracked, **kwargs)
        created.append(db)
        return db
    monkeypatch.setattr(sqlite3, "connect", tracked)
    if active:
        with pytest.raises(BackgroundDeferred):
            BackgroundBudget(database).checkpoint()
    else:
        BackgroundBudget(database).checkpoint()
    assert len(created) == 1 and created[0].closed
