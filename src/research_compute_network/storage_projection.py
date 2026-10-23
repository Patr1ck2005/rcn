"""Rebuildable managed-byte accounting; queries never visit data directories."""
from __future__ import annotations
import json
import sqlite3
from datetime import datetime, timezone, timedelta


def execute(db, sql, args=()):
    return db.exec_driver_sql(sql, args) if hasattr(db, "exec_driver_sql") else db.execute(sql, args)


def ensure_schema(db):
    for statement in (
        """CREATE TABLE IF NOT EXISTS storage_inventory_files (
            role TEXT NOT NULL, location TEXT NOT NULL, job_id TEXT NOT NULL, unit_id TEXT NOT NULL,
            attempt_id TEXT NOT NULL, path TEXT NOT NULL, project_id TEXT NOT NULL, size_bytes INTEGER NOT NULL,
            sha256 TEXT NOT NULL, resident INTEGER NOT NULL, PRIMARY KEY(role,location,job_id,unit_id,attempt_id,path))""",
        """CREATE TABLE IF NOT EXISTS storage_inventory_totals (
            project_id TEXT NOT NULL,role TEXT NOT NULL,location TEXT NOT NULL,bytes INTEGER NOT NULL,
            PRIMARY KEY(project_id,role,location))""",
        """CREATE TABLE IF NOT EXISTS storage_inventory_hours (
            hour TEXT NOT NULL,project_id TEXT NOT NULL,role TEXT NOT NULL,location TEXT NOT NULL,
            added_bytes INTEGER NOT NULL,removed_bytes INTEGER NOT NULL,
            PRIMARY KEY(hour,project_id,role,location))""",
        "CREATE TABLE IF NOT EXISTS storage_inventory_state (key TEXT PRIMARY KEY,value TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS storage_inventory_locations (location TEXT PRIMARY KEY,payload TEXT NOT NULL)",
        """CREATE TABLE IF NOT EXISTS storage_inventory_dirty (
            job_id TEXT NOT NULL,unit_id TEXT NOT NULL,attempt_id TEXT NOT NULL,project_id TEXT NOT NULL,
            revision INTEGER NOT NULL,PRIMARY KEY(job_id,unit_id,attempt_id))""",
        "CREATE INDEX IF NOT EXISTS storage_inventory_dirty_project ON storage_inventory_dirty(project_id)",
        "CREATE INDEX IF NOT EXISTS storage_inventory_resident ON storage_inventory_files(resident)",
        """CREATE TABLE IF NOT EXISTS storage_inventory_volumes (
            volume_key TEXT NOT NULL,hour TEXT NOT NULL,sampled_at TEXT NOT NULL,payload TEXT NOT NULL,
            PRIMARY KEY(volume_key,hour))""",
    ):
        execute(db, statement)
    for table, columns in {
        "storage_inventory_files": {"custody_state": "TEXT NOT NULL DEFAULT 'unknown'", "locator": "TEXT"},
        "storage_inventory_totals": {name: "INTEGER NOT NULL DEFAULT 0" for name in
            ("pending_custody_bytes", "eligible_bytes", "confirmed_retired_bytes", "registered_files")},
    }.items():
        existing = {row[1] for row in execute(db, f"PRAGMA table_info({table})")}
        for name, declaration in columns.items():
            if name not in existing:
                execute(db, f"ALTER TABLE {table} ADD COLUMN {name} {declaration}")
    from .storage_occupancy import ensure_schema as ensure_occupancy
    ensure_occupancy(db)


def _delta(db, project, role, location, amount, *, baseline=False, now=None, files=0):
    execute(db, """INSERT INTO storage_inventory_totals(project_id,role,location,bytes,registered_files) VALUES(?,?,?,?,?)
        ON CONFLICT(project_id,role,location) DO UPDATE SET bytes=bytes+excluded.bytes,registered_files=registered_files+excluded.registered_files""",
        (project, role, location, amount, files))
    if amount and not baseline:
        hour = (now or datetime.now(timezone.utc)).replace(minute=0, second=0, microsecond=0).isoformat()
        execute(db, """INSERT INTO storage_inventory_hours VALUES(?,?,?,?,?,?)
            ON CONFLICT(hour,project_id,role,location) DO UPDATE SET
            added_bytes=added_bytes+excluded.added_bytes,removed_bytes=removed_bytes+excluded.removed_bytes""",
            (hour, project, role, location, max(0, amount), max(0, -amount)))


def _category_delta(db, project, role, location, state, amount):
    column = {"pending_custody": "pending_custody_bytes", "eligible": "eligible_bytes",
              "confirmed_retired": "confirmed_retired_bytes"}.get(state)
    if column:
        execute(db, f"UPDATE storage_inventory_totals SET {column}={column}+? WHERE project_id=? AND role=? AND location=?",
                (amount, project, role, location))


def mark_dirty(db, project_id, job_id, unit_id, attempt_id):
    execute(db, """INSERT INTO storage_inventory_dirty VALUES(?,?,?,?,1)
        ON CONFLICT(job_id,unit_id,attempt_id) DO UPDATE SET revision=revision+1,project_id=excluded.project_id""",
        (job_id, unit_id, attempt_id, project_id))


def record_file(db, *, project_id, role, location, job_id, unit_id, attempt_id, record,
                resident=True, baseline=False, now=None, locator=None):
    key = (role, location, job_id, unit_id, attempt_id, record["relative_path"])
    old = execute(db, "SELECT project_id,size_bytes,sha256,resident,custody_state,rowid,locator FROM storage_inventory_files WHERE "
                  "role=? AND location=? AND job_id=? AND unit_id=? AND attempt_id=? AND path=?", key).fetchone()
    if old and (old[0], old[1], old[2]) == (project_id, record["size_bytes"], record["sha256"]):
        # Replayed manifests never resurrect retired files or renew their evidence.
        if locator is not None and json.dumps(locator, sort_keys=True) != old[6]:
            from .storage_occupancy import forget_observation
            forget_observation(db, old[5])
            execute(db, "UPDATE storage_inventory_files SET locator=? WHERE rowid=?", (json.dumps(locator, sort_keys=True), old[5]))
        return
    if old:
        from .storage_occupancy import forget_observation
        forget_observation(db, old[5])
        _delta(db, old[0], role, location, -old[1]*old[3], baseline=baseline, now=now, files=-old[3])
        _category_delta(db, old[0], role, location, old[4], -old[1])
    state = ("pending_custody" if resident else "confirmed_retired") if location == "center" else "registered"
    execute(db, """INSERT INTO storage_inventory_files VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(role,location,job_id,unit_id,attempt_id,path) DO UPDATE SET
        project_id=excluded.project_id,size_bytes=excluded.size_bytes,sha256=excluded.sha256,
        resident=excluded.resident,custody_state=excluded.custody_state,locator=excluded.locator""",
        (*key, project_id, record["size_bytes"], record["sha256"], int(resident), state,
         json.dumps(locator, sort_keys=True) if locator else None))
    _delta(db, project_id, role, location, record["size_bytes"]*int(resident), baseline=baseline, now=now, files=int(resident))
    _category_delta(db, project_id, role, location, state, record["size_bytes"])


def record_manifest(db, payload, project_id, *, baseline=False):
    attempt = (payload.get("producer") or {}).get("attempt_id")
    if not attempt:
        return  # Unknown producers cannot be presented as attributed physical bytes.
    retired = set()
    origin = execute(db, "SELECT json_extract(payload,'$.origin_submitter_id') FROM jobs WHERE job_id=?", (payload["job_id"],)).fetchone()
    locator = {"origin_submitter_id": origin[0]} if origin and origin[0] else None
    if execute(db, "SELECT 1 FROM sqlite_master WHERE name='storage_lifecycle_deletions'").fetchone():
        retired = {row[0] for row in execute(db, """SELECT d.relative_path FROM storage_lifecycle_deletions d
            JOIN storage_lifecycle_intents i ON i.intent_id=d.intent_id
            WHERE i.job_id=? AND i.unit_id=? AND i.attempt_id=? AND i.operation_kind IN ('relay_copy','solved_model')
            AND d.state IN ('deleted','already_absent')""", (payload["job_id"], payload["work_unit_id"], attempt))}
    for record in payload["files"]:
        record_file(db, project_id=project_id, role="origin_spool", location="center",
                    job_id=payload["job_id"], unit_id=payload["work_unit_id"], attempt_id=attempt,
                    record=record, resident=record["relative_path"] not in retired, baseline=baseline, locator=locator)
    mark_dirty(db, project_id, payload["job_id"], payload["work_unit_id"], attempt)


def retire_file(db, job_id, unit_id, attempt_id, path, *, now=None):
    key = ("origin_spool", "center", job_id, unit_id, attempt_id, path)
    row = execute(db, "SELECT project_id,size_bytes,resident,custody_state,rowid FROM storage_inventory_files WHERE "
                  "role=? AND location=? AND job_id=? AND unit_id=? AND attempt_id=? AND path=?", key).fetchone()
    if row and row[2]:
        from .storage_occupancy import forget_observation
        forget_observation(db, row[4])
        execute(db, "UPDATE storage_inventory_files SET resident=0,custody_state='confirmed_retired' WHERE "
                "role=? AND location=? AND job_id=? AND unit_id=? AND attempt_id=? AND path=?", key)
        _delta(db, row[0], key[0], key[1], -row[1], now=now, files=-1)
        _category_delta(db, row[0], key[0], key[1], row[3], -row[1])
        _category_delta(db, row[0], key[0], key[1], "confirmed_retired", row[1])


class StorageProjection:
    def __init__(self, lifecycle):
        self.lifecycle = lifecycle

    def request_rebuild(self):
        """Trusted maintenance entry: reset derived accounting, keep evidence/history."""
        from .storage_io import BackgroundBudget
        BackgroundBudget(self.lifecycle.database).checkpoint()
        with self.lifecycle._transaction() as db:
            db.execute("DELETE FROM storage_inventory_files")
            db.execute("DELETE FROM storage_inventory_totals")
            db.execute("DELETE FROM storage_inventory_state")
            db.execute("DELETE FROM storage_inventory_dirty")
            for table in ("storage_occupancy_observations", "storage_occupancy_objects", "storage_occupancy_totals"):
                db.execute(f"DELETE FROM {table}")

    def refresh_categories(self, *, limit=32):
        """Idle event work, fenced against concurrent receipt/policy changes."""
        from .storage_io import BackgroundBudget
        from .storage_lifecycle import LifecycleError
        background = BackgroundBudget(self.lifecycle.database)
        background.checkpoint()
        with self.lifecycle._connect() as db:
            rows = db.execute("SELECT * FROM storage_inventory_dirty ORDER BY rowid LIMIT ?", (limit,)).fetchall()
        for row in rows:
            background.checkpoint()
            key = tuple(row[:3])
            policy = None
            try:
                job, manifest, attempt = self.lifecycle._binding(*key)
                with self.lifecycle._connect() as db:
                    if db.execute("SELECT 1 FROM storage_lifecycle_intents WHERE job_id=? AND unit_id=? AND attempt_id=? AND operation_kind<>'relay_copy'", key).fetchone():
                        raise LifecycleError("scientific_inventory_requires_separate_relay_policy")
                    policy, _receipts, _copies = self.lifecycle._evidence(db, job, manifest, attempt)
            except (LifecycleError, ValueError):
                pass
            background.checkpoint()
            with self.lifecycle._transaction() as db:
                current = db.execute("SELECT revision FROM storage_inventory_dirty WHERE job_id=? AND unit_id=? AND attempt_id=?", key).fetchone()
                if current is None or current[0] != row["revision"]:
                    continue
                files = db.execute("SELECT path,project_id,size_bytes,custody_state FROM storage_inventory_files "
                    "WHERE job_id=? AND unit_id=? AND attempt_id=? AND location='center' AND resident=1", key).fetchall()
                for item in files:
                    state = "pending_custody" if policy is None else (
                        "retained" if self.lifecycle._protected(item[0], policy) else "eligible")
                    if state != item[3]:
                        _category_delta(db, item[1], "origin_spool", "center", item[3], -item[2])
                        _category_delta(db, item[1], "origin_spool", "center", state, item[2])
                        db.execute("UPDATE storage_inventory_files SET custody_state=? WHERE job_id=? AND unit_id=? "
                            "AND attempt_id=? AND path=? AND location='center'", (state, *key, item[0]))
                db.execute("DELETE FROM storage_inventory_dirty WHERE job_id=? AND unit_id=? AND attempt_id=?", key)
        return len(rows)

    def sample_volume(self, root, *, location="center", binding=None, now=None):
        """Called by existing idle maintenance, never by the metadata GET."""
        import shutil
        from .volume_budget import volume_for_destination, HARD_RESERVE_BYTES
        from .storage_io import io_priority
        io_priority.checkpoint()
        now = now or datetime.now(timezone.utc)
        ancestor, native_volume = volume_for_destination(root)
        usage = shutil.disk_usage(ancestor)
        binding = binding or self.lifecycle.center_binding
        host = (binding.host_id if binding else self.lifecycle.process_host).casefold()
        volume = binding.volume_id if binding else native_volume
        generation = binding.generation if binding else None
        key = host + '/' + volume
        with self.lifecycle._transaction() as db:
            claims_exist = db.execute("SELECT 1 FROM sqlite_master WHERE name='storage_volume_claims'").fetchone()
            reserved = db.execute("SELECT COALESCE(SUM(required_bytes),0) FROM storage_volume_claims "
                "WHERE state='active' AND host_id=? AND volume_id=?", (host, native_volume)).fetchone()[0] if claims_exist else 0
            payload = {"host_id": host, "volume_id": volume,
                "physical_device_id": binding.physical_device_id if binding else None, "generation": generation,
                "free_bytes": usage.free, "total_bytes": usage.total, "reserved_bytes": reserved,
                "hard_reserve_bytes": HARD_RESERVE_BYTES, "usable_bytes": max(0, usage.free-reserved-HARD_RESERVE_BYTES),
                "sampled_at": now.isoformat(), "location": location}
            db.execute("INSERT INTO storage_inventory_volumes VALUES(?,?,?,?) "
                "ON CONFLICT(volume_key,hour) DO UPDATE SET sampled_at=excluded.sampled_at,payload=excluded.payload",
                (key, now.replace(minute=0, second=0, microsecond=0).isoformat(), now.isoformat(), json.dumps(payload)))
            # Keep eight days of hourly samples; generation changes do not cross-fit.
            db.execute("DELETE FROM storage_inventory_volumes WHERE hour<?", ((now-timedelta(days=8)).isoformat(),))
            db.execute("DELETE FROM storage_inventory_hours WHERE hour<?", ((now-timedelta(days=8)).isoformat(),))
        return payload

    def sample_registered_volumes(self, *, limit=1):
        """Round-robin only registered local roots, with no directory traversal."""
        from .storage_io import io_priority, BackgroundDeferred
        from .restore_sources import RegisteredResultSources
        io_priority.checkpoint()
        with self.lifecycle._connect() as db:
            if not db.execute("SELECT 1 FROM sqlite_master WHERE name='storage_restore_stores'").fetchone():
                return 0
            state = db.execute("SELECT value FROM storage_inventory_state WHERE key='volume_cursor'").fetchone()
            rows = db.execute("SELECT store_id,payload FROM storage_restore_stores WHERE store_id>? AND active=1 ORDER BY store_id LIMIT ?",
                              (state[0] if state else "", limit)).fetchall()
        for row in rows:
            io_priority.checkpoint()
            payload = json.loads(row[1])
            try:
                resolver = RegisteredResultSources(self.lifecycle, allowed_kind=payload["kind"])
                root = resolver._validate_store(payload)
                from .storage_lifecycle import CustodyLocation
                binding = CustodyLocation.model_validate(payload["location"])
                if not self.lifecycle.center_binding or (binding.host_id.casefold(), binding.volume_id) != (
                        self.lifecycle.center_binding.host_id.casefold(), self.lifecycle.center_binding.volume_id):
                    self.sample_volume(root, location=binding.store_id+':'+binding.generation, binding=binding)
            except BackgroundDeferred:
                raise
            except (OSError, ValueError):
                pass  # An offline root must not starve later registered volumes.
        with self.lifecycle._transaction() as db:
            db.execute("INSERT INTO storage_inventory_state VALUES('volume_cursor',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                       (rows[-1][0] if len(rows) == limit else "",))
        return len(rows)

    def backfill(self, *, limit=100):
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("invalid inventory page limit")
        from .storage_io import BackgroundBudget
        BackgroundBudget(self.lifecycle.database).checkpoint()
        with self.lifecycle._transaction() as db:
            state = db.execute("SELECT value FROM storage_inventory_state WHERE key='manifest_cursor'").fetchone()
            cursor = state[0] if state else ""
            rows = db.execute("""SELECT a.work_unit_id,a.payload,j.project_id FROM artifact_manifests a
                JOIN jobs j ON j.job_id=a.job_id WHERE a.work_unit_id>? ORDER BY a.work_unit_id LIMIT ?""",
                (cursor, limit)).fetchall()
            for row in rows:
                record_manifest(db, json.loads(row[1]), row[2], baseline=True)
            if rows:
                db.execute("INSERT INTO storage_inventory_state VALUES('manifest_cursor',?) "
                           "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (rows[-1][0],))
            manifests_complete = len(rows) < limit
            source_count, sources_complete = 0, True
            if manifests_complete and db.execute("SELECT 1 FROM sqlite_master WHERE name='storage_restore_files'").fetchone():
                state = db.execute("SELECT value FROM storage_inventory_state WHERE key='source_cursor'").fetchone()
                source_cursor = int(state[0]) if state else 0
                sources = db.execute("""SELECT f.rowid,f.file,r.payload,f.source_path FROM storage_restore_files f
                    JOIN storage_restore_receipt_evidence r ON r.receipt_id=f.receipt_id
                    WHERE f.rowid>? ORDER BY f.rowid LIMIT ?""", (source_cursor, limit)).fetchall()
                for source in sources:
                    receipt = json.loads(source[2])
                    target = receipt["target"]
                    record = next(f for f in receipt["files"] if f["relative_path"] == source[1])
                    # Revocation removes eligibility, not the physical registered bytes.
                    record_file(db, project_id=receipt["project_id"], role=receipt["target_kind"],
                        location=target["store_id"] + ':' + str(target["generation"]), job_id=receipt["job_id"],
                        unit_id=receipt["work_unit_id"], attempt_id=receipt["producer_attempt_id"], record=record, baseline=True,
                        locator={"store_id": target["store_id"], "generation": str(target["generation"]), "relative_path": source[3]})
                source_count, sources_complete = len(sources), len(sources) < limit
                if sources:
                    db.execute("INSERT INTO storage_inventory_state VALUES('source_cursor',?) "
                               "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(sources[-1][0]),))
            complete = manifests_complete and sources_complete
            db.execute("INSERT INTO storage_inventory_state VALUES('backfill_complete',?) "
                       "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (json.dumps(complete),))
        return {"processed": len(rows), "source_files_processed": source_count,
                "complete": complete, "cursor": rows[-1][0] if rows else cursor}

    def snapshot(self, *, now=None):
        now = now or datetime.now(timezone.utc)
        since = (now-timedelta(hours=24)).replace(minute=0, second=0, microsecond=0).isoformat()
        with self.lifecycle._connect() as db:
            totals = [dict(row) for row in db.execute("SELECT * FROM storage_inventory_totals ORDER BY project_id,role,location")]
            pending = {row[0] for row in db.execute("SELECT DISTINCT project_id FROM storage_inventory_dirty")}
            occupancy = {(row["project_id"], row["role"], row["location"]): dict(row)
                         for row in db.execute("SELECT * FROM storage_occupancy_totals")}
            hours = [dict(row) for row in db.execute("SELECT * FROM storage_inventory_hours WHERE hour>=?", (since,))]
            state = {row[0]: row[1] for row in db.execute("SELECT * FROM storage_inventory_state")}
            locations = {row[0]: json.loads(row[1]) for row in db.execute("SELECT * FROM storage_inventory_locations")}
            samples = [(row[0], json.loads(row[1])) for row in db.execute(
                "SELECT volume_key,payload FROM storage_inventory_volumes WHERE hour>=? ORDER BY sampled_at", (since,))]
        grouped = {}
        for key, sample in samples:
            grouped.setdefault(key, []).append(sample)
        volumes = []
        for values in grouped.values():
            values = [value for value in values if value.get("generation") == values[-1].get("generation")]
            latest = dict(values[-1])
            first = values[0]
            first_time = datetime.fromisoformat(first["sampled_at"])
            start = first_time.replace(minute=0, second=0, microsecond=0)
            if start < first_time:
                start += timedelta(hours=1)
            end = datetime.fromisoformat(latest["sampled_at"]).replace(minute=0, second=0, microsecond=0)
            span = (end-start).total_seconds()
            complete = state.get("backfill_complete") == "true"
            fresh = (now-datetime.fromisoformat(latest["sampled_at"])).total_seconds() <= 120
            # Whole-volume free-space changes include migrations and unrelated
            # writes. Forecast only confirmed normal managed-file event buckets;
            # initial/backfill/registered-copy imports never emit those buckets.
            related = {location for location, identity in locations.items()
                       if (identity["host_id"].casefold(), identity["volume_id"]) ==
                          (latest["host_id"].casefold(), latest["volume_id"])}
            related.add(latest["location"])
            events = [row for row in hours if row["location"] in related
                      and start.isoformat() <= row["hour"] < end.isoformat()]
            daily_growth = sum(row["added_bytes"]-row["removed_bytes"] for row in events)*86400/span if span > 0 and events else None
            enough = len(values) >= 3 and span >= 6*3600 and complete and fresh and first["total_bytes"] == latest["total_bytes"]
            latest.update(growth_bytes_per_day=daily_growth if enough else None,
                days_to_reserve=latest["usable_bytes"] / daily_growth if enough and daily_growth is not None and daily_growth > 0 else None,
                forecast_basis="registered_logical_file_events",
                forecast_reason="registered_file_growth_estimate" if enough and daily_growth is not None and daily_growth > 0 else
                    "nonpositive_growth" if enough and daily_growth is not None else
                    "no_confirmed_natural_growth" if enough else "insufficient_or_stale_samples",
                sample_count=len(values), stale=not fresh)
            volumes.append(latest)
        measured = {(row["host_id"].casefold(), row["volume_id"]) for row in volumes}
        for location, identity in locations.items():
            key = (identity["host_id"].casefold(), identity["volume_id"])
            if key not in measured:
                volumes.append({**identity, "location": location, "free_bytes": None, "total_bytes": None,
                    "reserved_bytes": None, "hard_reserve_bytes": 10*1024**3, "usable_bytes": None,
                    "sampled_at": None, "growth_bytes_per_day": None, "days_to_reserve": None,
                    "forecast_reason": "insufficient_or_stale_samples", "sample_count": 0, "stale": True})
                measured.add(key)
        growth = {}
        for row in hours:
            key = (row["project_id"], row["role"], row["location"])
            item = growth.setdefault(key, dict(project_id=key[0], role=key[1], location=key[2],
                added_bytes=0, removed_bytes=0, first_observed_hour=row["hour"]))
            item["added_bytes"] += row["added_bytes"]
            item["removed_bytes"] += row["removed_bytes"]
            item["first_observed_hour"] = min(item["first_observed_hour"], row["hour"])
        growth = [growth[key] for key in sorted(growth)]
        for row in growth:
            row["net_bytes"] = row["added_bytes"] - row["removed_bytes"]
        for row in totals:
            row["logical_registered_bytes"] = row["bytes"]
            row["physical_bytes"] = None
            measured = occupancy.get((row["project_id"], row["role"], row["location"]), {})
            oldest = measured.get("oldest_observed_at")
            fresh = bool(oldest and now-datetime.fromisoformat(oldest) <= timedelta(hours=24))
            known = fresh and measured.get("measured_files", 0) == row["registered_files"]
            row.update(measured_files=measured.get("measured_files", 0), observed_allocated_bytes=measured.get("allocated_bytes", 0),
                physical_bytes=measured.get("allocated_bytes", 0) if known else None,
                occupancy_oldest_observed_at=oldest, occupancy_stale=not fresh,
                physical_attribution="unique_object_first_registered_path")
            row["classification_pending"] = row["project_id"] in pending
            if row["location"] != "center":
                row.update(pending_custody_bytes=None, eligible_bytes=None, confirmed_retired_bytes=None)
            elif row["classification_pending"]:
                row.update(pending_custody_bytes=None, eligible_bytes=None)
        return {"schema": 1, "generated_at": now.isoformat(), "basis": "registered_manifest_bytes",
                "projects": totals, "growth_24h": growth, "locations": locations,
                "volumes": volumes, "backfill_complete": state.get("backfill_complete") == "true",
                "occupancy_inventory": {"cursor": int(state.get("occupancy_cursor", "0")),
                    "last_completed_pass_at": state.get("occupancy_pass_completed_at"), "scope": "registered_exact_paths_only"},
                "unattributed_device_bytes": None, "data_reads": 0,
                "coverage": "manifest outputs and registered custody copies; other device usage is unattributed"}
