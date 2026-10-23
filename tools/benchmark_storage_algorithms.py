"""Isolated paired measurements. Never connect to a center or use production state.

Run with PYTHONPATH=src and an explicit --output below this checkout's .scratch.
Every valid sample is retained; this is not natural-load production acceptance.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import inspect
import json
import math
import os
from pathlib import Path
import statistics
import textwrap
import threading
import time
from datetime import datetime, timezone
from types import MethodType


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=30)
    args = parser.parse_args()
    checkout = Path(__file__).resolve().parents[1]
    root = args.output.resolve()
    if not root.is_relative_to(checkout / ".scratch") or args.samples < 30:
        parser.error("use a new .scratch output directory and at least 30 samples")
    root.mkdir(parents=True, exist_ok=False)
    for key in tuple(os.environ):
        if key.startswith("RCN_"):
            del os.environ[key]
    os.environ["RCN_HOME"] = str(root / "home")

    from research_compute_network.repository import MetadataRepository
    from research_compute_network.service import NetworkService
    from research_compute_network.models import JobEnvelope, WorkUnit
    from research_compute_network.dispatch_policy import SchedulingPolicy
    from research_compute_network.personal_runtime import policy_store
    from research_compute_network.storage_lifecycle import StorageLifecycle
    from research_compute_network.storage_projection import record_manifest, record_file
    from research_compute_network.storage_occupancy import OccupancyInventory, native_allocation
    from research_compute_network.storage_io import BackgroundDeferred, BACKGROUND_CHUNK_BYTES, io_priority
    from research_compute_network.origin_transfer_api import open_verified_result
    from research_compute_network.transfer_queue import TransferQueue

    repository = MetadataRepository("sqlite:///" + (root / "metadata.db").as_posix())
    service = NetworkService(repository)
    service.initialize()
    data = root / "data"
    data.mkdir()
    lifecycle = StorageLifecycle(repository, data)
    now, policy = datetime.now(timezone.utc), SchedulingPolicy()
    jobs = [JobEnvelope(origin_submitter_id="fixture", user_id=f"user-{i%8}", project_id=f"project-{i%8}",
        execution_profile_id="fixture", request_hash=f"{i:064x}", job_id=f"job-{i:04d}",
        work_units=[WorkUnit(work_unit_id=f"unit-{i:04d}", ordinal=0, payload={"kind": "fixture"})]) for i in range(256)]
    # Exact prior implementation of the changed method, with all other code identical.
    current = inspect.getsource(NetworkService._sort_dispatch_jobs)
    changed = "{user_id: store.get_policy(user_id) for user_id in {job.user_id for job in jobs}}"
    previous = "{job.user_id: store.get_policy(job.user_id) for job in jobs}"
    assert current.count(changed) == 1
    namespace = dict(inspect.unwrap(NetworkService._sort_dispatch_jobs).__globals__)
    exec(compile(textwrap.dedent(current.replace(changed, previous)), "<previous-sort>", "exec"), namespace)
    baseline_sort = MethodType(namespace["_sort_dispatch_jobs"], service)
    store = policy_store(service)
    real_get, calls = store.get_policy, [0]
    def counted_get(user):
        calls[0] += 1
        return real_get(user)
    store.get_policy = counted_get

    rows = []
    # Preserve each completed measurement even if a later fixture admission fails.
    sample_log = root / "samples.jsonl"
    def timed(name, variant, index, action):
        calls[0] = 0
        cpu_started = time.thread_time_ns()
        started = time.perf_counter_ns()
        result = action()
        row = {"case": name, "variant": variant, "sample": index,
               "elapsed_ms": (time.perf_counter_ns()-started)/1e6, "policy_reads": calls[0],
               "foreground_cpu_ms": (time.thread_time_ns()-cpu_started)/1e6}
        rows.append(row)
        with sample_log.open("a", encoding="utf-8") as saved:
            saved.write(json.dumps(row)+"\n")
        return result

    def ordered(method):
        batch = list(reversed(jobs))
        method(batch, now, policy=policy)
        return [job.job_id for job in batch]
    assert ordered(baseline_sort) == ordered(service._sort_dispatch_jobs)
    for i in range(args.samples):
        pair = [("before", baseline_sort), ("after", service._sort_dispatch_jobs)]
        for variant, method in pair[::1 if i%2 == 0 else -1]:
            timed("dispatch_sort", variant, i, lambda: ordered(method))

    # Same 2,048 immutable manifest inputs, full metadata reduction vs incremental view.
    manifests = []
    with lifecycle._transaction() as db:
        db.execute("CREATE TABLE benchmark_manifest_inputs(payload TEXT,project_id TEXT)")
        for i in range(2048):
            manifest = {"job_id": f"inventory-{i}", "work_unit_id": f"inventory-unit-{i}",
                "producer": {"attempt_id": "original"}, "files": [{"relative_path": f"file-{j}.csv",
                "size_bytes": (i+1)*100+j, "sha256": "a"*64} for j in range(4)]}
            project = f"inventory-project-{i%8}"
            manifests.append((manifest, project))
            db.execute("INSERT INTO benchmark_manifest_inputs VALUES(?,?)", (json.dumps(manifest), project))
            record_manifest(db, manifest, project, baseline=True)
    def full_reduce():
        totals = {}
        with lifecycle._connect() as db:
            for row in db.execute("SELECT payload,project_id FROM benchmark_manifest_inputs"):
                totals[row[1]] = totals.get(row[1], 0) + sum(f["size_bytes"] for f in json.loads(row[0])["files"])
        return totals
    def projected():
        return {row["project_id"]: row["bytes"] for row in lifecycle.inventory.snapshot()["projects"]}
    assert full_reduce() == projected()
    for i in range(args.samples):
        pair = [("before_reference_full_metadata_reduce", full_reduce), ("after", projected)]
        for variant, action in pair[::1 if i%2 == 0 else -1]:
            timed("inventory_query", variant, i, action)

    # Logical waiting work (not wall-clock sleep): original 1-second waiter retry,
    # compared with no events during waiting and one FIFO completion event per item.
    for i in range(args.samples):
        def polling():
            callbacks = 0
            for _second in range(120):
                for _request in range(256):
                    callbacks += 1
            return callbacks
        def events():
            queue = TransferQueue(lambda: None)
            for request in range(256):
                queue.enqueue(request)
            assert queue.timer is None
            count = sum(queue.take() is not None for _ in range(256))
            queue.close()
            return count
        before = timed("waiting_work", "before_callback_model", i, polling)
        rows[-1]["waiting_callbacks"] = before
        timed("waiting_work", "after_event_queue", i, events)
        rows[-1]["waiting_callbacks"] = 0

    # Actual local SHA/read path under cooperative background verification.
    path = data / "fixture.bin"
    block = bytes(range(256))*4096
    with path.open("wb") as stream:
        for _ in range(32):
            stream.write(block)
    size = path.stat().st_size
    digest = hashlib.sha256(block*32).hexdigest()
    record = {"size_bytes": size, "sha256": digest}
    def read_foreground():
        stream, _stat = open_verified_result(path, size, digest)
        try:
            while stream.read(1024*1024):
                pass
        finally:
            stream.close()
    read_foreground()
    # Occupancy uses a separate same-schema fixture, with only registered exact
    # hardlink paths. Never recurse or touch a production root.
    occupancy_repo = MetadataRepository("sqlite:///" + (root / "occupancy.db").as_posix())
    occupancy_repo.init_schema()
    occupancy = StorageLifecycle(occupancy_repo, data)
    directory = data / "fixture" / "incoming" / "occupancy-job" / "occupancy-unit" / "original"
    directory.mkdir(parents=True)
    with occupancy._transaction() as db:
        for index in range(32):
            name = f"file-{index}.bin"
            os.link(path, directory / name)
            record_file(db, project_id="occupancy", role="origin_spool", location="center",
                job_id="occupancy-job", unit_id="occupancy-unit", attempt_id="original",
                record={**record, "relative_path": name}, locator={"origin_submitter_id": "fixture"})

    # Persistent worker; controlled first-chunk race. Background passes its real
    # admission checkpoint, then foreground arrives while one already-admitted
    # chunk/native OS call executes. This prevents quiet-time from making a sample
    # pass without any background work. Barrier waits are outside measured time.
    trigger, entered, admitted, done, quit_worker = (threading.Event() for _ in range(5))
    control = {"kind": "sha"}
    diagnostics = {}
    preflight = []
    def boundary():
        if not entered.is_set():
            entered.set()
            if not admitted.wait(10):
                raise RuntimeError("foreground did not reach the overlap boundary")
    class MeasuredPath:
        is_file = path.is_file
        stat = path.stat
        @contextmanager
        def open(self, mode):
            with path.open(mode) as stream:
                class Reader:
                    def read(self, amount):
                        boundary()
                        chunk = stream.read(amount)
                        diagnostics["bytes_read"] += len(chunk)
                        return chunk
                yield Reader()
    # Instrument the real OS call after its production checkpoint. A foreground
    # arrival may now stop a multi-call Windows probe after the admitted open;
    # count that actual operation, not a completed observation or mere worker start.
    native_kernel = native_open = None
    if os.name == "nt":
        from research_compute_network.storage_occupancy import _windows_allocation_api
        native_kernel = _windows_allocation_api()[1]
        native_open = native_kernel.CreateFileW
        def measured_open(*args):
            boundary()
            result = native_open(*args)
            diagnostics["native_calls"] += 1
            return result
        native_kernel.CreateFileW = measured_open
    def measured_probe(target):
        if native_kernel is None:
            boundary()
        result = native_allocation(target)
        diagnostics["native_probes"] += 1
        return result
    def maintenance():
        while True:
            trigger.wait()
            trigger.clear()
            if quit_worker.is_set():
                return
            try:
                if control["kind"] == "sha":
                    lifecycle._verify_source(MeasuredPath(), record)
                else:
                    diagnostics["inventory_batch"] = OccupancyInventory(occupancy).advance(probe=measured_probe)
            except BackgroundDeferred:
                diagnostics["deferred"] = True
            except Exception as exc:
                diagnostics["error"] = repr(exc)
                entered.set()
            finally:
                done.set()
                entered.set()  # Also wake preflight when the idle budget expires.
    worker = threading.Thread(target=maintenance)
    worker.start()
    cases = (("foreground_read", "sha", read_foreground),
             ("dispatch_with_background", "sha", lambda: ordered(service._sort_dispatch_jobs)),
             ("foreground_read_with_inventory", "occupancy", read_foreground),
             ("dispatch_with_inventory", "occupancy", lambda: ordered(service._sort_dispatch_jobs)))
    measurement_error = None
    try:
        for case, kind, action in cases:
            print(f"measuring {case}: {args.samples} paired samples", flush=True)
            for i in range(args.samples):
                for variant in (["foreground_only", "background_enabled"] if i%2 == 0 else ["background_enabled", "foreground_only"]):
                    if variant == "background_enabled":
                        # Honor the configured grace period instead of resetting it.
                        with io_priority.lock:
                            quiet_remaining = max(0, io_priority.quiet_until-time.monotonic())
                        if quiet_remaining:
                            time.sleep(quiet_remaining+.001)
                        # The smaller production time budget can legitimately
                        # expire during metadata preflight. Do not count a
                        # no-work case as overlap or discard it silently.
                        for attempt in range(5):
                            diagnostics.clear()
                            diagnostics.update(bytes_read=0, native_probes=0, native_calls=0, deferred=False)
                            control["kind"] = kind
                            entered.clear()
                            admitted.clear()
                            done.clear()
                            trigger.set()
                            if not entered.wait(10):
                                raise RuntimeError("background preflight did not finish")
                            if not done.is_set():
                                break
                            entry = {"case": case, "sample": i, "attempt": attempt, **diagnostics}
                            preflight.append(entry)
                            with (root / "preflight.jsonl").open("a", encoding="utf-8") as saved:
                                saved.write(json.dumps(entry)+"\n")
                            batch = diagnostics.get("inventory_batch", {})
                            if diagnostics.get("error") or batch.get("processed") != 0 or batch.get("pass_complete") is not False:
                                raise RuntimeError(f"unexpected background preflight: {diagnostics}")
                        else:
                            raise RuntimeError("inventory could not enter actual work within five bounded preflights")
                    def foreground():
                        with io_priority.foreground():
                            admitted.set()
                            return action()
                    timed(case, variant, i, foreground)
                    if variant == "background_enabled":
                        if not done.wait(10) or diagnostics.get("error"):
                            raise RuntimeError(f"background failed: {diagnostics}")
                        assert diagnostics["bytes_read"] or diagnostics["native_probes"] or diagnostics["native_calls"]
                        rows[-1]["background"] = dict(diagnostics)
    except BaseException as exc:
        measurement_error = repr(exc)
    finally:
        admitted.set()
        quit_worker.set()
        trigger.set()
        worker.join()
        if native_kernel is not None:
            native_kernel.CreateFileW = native_open

    summaries = {}
    for row in rows:
        key = row["case"] + "/" + row["variant"]
        summaries.setdefault(key, []).append(row["elapsed_ms"])
    summaries = {key: {"n": len(values), "p50_ms": statistics.median(values),
        "p95_ms": sorted(values)[math.ceil(.95*len(values))-1]} for key, values in summaries.items()}
    ratios = {case: summaries[case+"/background_enabled"]["p95_ms"] / summaries[case+"/foreground_only"]["p95_ms"]
              for case, _kind, _action in cases if case+"/background_enabled" in summaries and case+"/foreground_only" in summaries}
    # Each read sample transfers/verifies exactly the same fixture bytes, so
    # total-time ratios give aggregate foreground byte-throughput ratios.
    throughput = {}
    for case in ("foreground_read", "foreground_read_with_inventory"):
        elapsed = {variant: sum(row["elapsed_ms"] for row in rows if row["case"] == case and row["variant"] == variant)
                   for variant in ("foreground_only", "background_enabled")}
        if all(elapsed.values()):
            throughput[case] = elapsed["foreground_only"] / elapsed["background_enabled"]
    report = {"schema": 1, "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": "isolated warm-cache local fixture; no production or natural full-load acceptance",
        "background_chunk_bytes": BACKGROUND_CHUNK_BYTES,
        "inventory_max_files": inspect.signature(OccupancyInventory.advance).parameters["max_files"].default,
        "inventory_time_budget_ms": inspect.signature(OccupancyInventory.advance).parameters["time_budget_ms"].default,
        "overlap_protocol": "one background chunk or native OS call admitted immediately before foreground arrival; actual work recorded per sample; Windows probe can yield between OS calls",
        "fixtures": {"dispatch_jobs": 256, "unique_users": 8, "manifest_files": 8192, "file_bytes": size},
        "summary": summaries, "background_p95_ratios": ratios,
        "foreground_throughput_ratios": throughput,
        "background_target_passed": measurement_error is None and len(ratios) == 4 and len(throughput) == 2
            and all(value <= 1.10 for value in ratios.values()) and all(value >= .90 for value in throughput.values()),
        "measurement_error": measurement_error, "preflight": preflight, "samples": rows}
    (root / "raw-samples.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({key: report[key] for key in report if key != "samples"}, indent=2))
    if measurement_error:
        raise RuntimeError(measurement_error)


if __name__ == "__main__":
    main()
