"""Bounded, parameter-free diagnostics for original result-file transfers."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import threading
import time
from uuid import uuid4


MAX_LOG_BYTES = 1024 * 1024
MAX_STACK_FRAMES = 32
_LOG_LOCK = threading.Lock()
_STAGES = frozenset({
    "owned_job", "producer_manifest", "scientific_retention", "storage_root",
    "pin_reader", "result_paths", "open_verified_result", "append_event",
    "response_storage_validate",
})


def _stack_for_thread(thread_id):
    """Never inspect locals, source text, arguments, or absolute file paths."""
    frame = None
    try:
        frame = sys._current_frames().get(thread_id)
        frames = []
        while frame is not None and len(frames) < MAX_STACK_FRAMES:
            frames.append({"file": Path(frame.f_code.co_filename).name,
                           "line": frame.f_lineno, "function": frame.f_code.co_name})
            frame = frame.f_back
        return frames
    except Exception:
        return []
    finally:
        del frame


def _write_record(control_root, record):
    """Two bounded control-disk files; diagnostic failures never escape."""
    if control_root is None:
        return
    try:
        encoded = (json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n").encode("utf-8")
        if len(encoded) > MAX_LOG_BYTES:
            return
        with _LOG_LOCK:
            directory = Path(control_root) / "diagnostics"
            directory.mkdir(parents=True, exist_ok=True)
            path = directory / "origin-transfer.jsonl"
            if path.exists() and path.stat().st_size + len(encoded) > MAX_LOG_BYTES:
                os.replace(path, path.with_name(path.name + ".1"))
            with path.open("ab") as stream:
                stream.write(encoded)
    except Exception:
        # This instrumentation must not change transfer or exception semantics.
        return


class OriginTransferDiagnostics:
    """One request, one timer per active synchronous preparation stage.

    Fast stages only update memory. A slow-stage snapshot, response-ready
    checkpoint and final summary are the only writes; no body-chunk logging.
    """

    def __init__(self, control_root, *, slow_seconds=12.0):
        self.control_root = control_root
        self.slow_seconds = slow_seconds
        self.request_id = uuid4().hex
        self._started = time.monotonic()
        self._lock = threading.Lock()
        self._active = None
        self._stages = []
        self._finished = False

    def _record(self, event, **fields):
        try:
            _write_record(self.control_root, {
                "schema": "rcn-origin-transfer-diagnostics-v1", "event": event,
                "request_id": self.request_id, "pid": os.getpid(),
                "at_UTC": datetime.now(timezone.utc).isoformat(),
                "elapsed_s": round(time.monotonic() - self._started, 6), **fields,
            })
        except Exception:
            pass

    def _slow(self, active):
        try:
            with self._lock:
                if self._finished or self._active is not active:
                    return
                fields = {
                    "stage": active["name"], "thread_id": active["thread_id"],
                    "stage_elapsed_s": round(time.monotonic() - active["started"], 6),
                    "stack": _stack_for_thread(active["thread_id"]),
                    "stages": list(self._stages),
                }
            self._record("slow_stage", **fields)
        except Exception:
            pass

    @contextmanager
    def stage(self, name):
        # Names are fixed by the service, never taken from requests or paths.
        if name not in _STAGES:
            raise ValueError("unknown origin transfer diagnostic stage")
        active = {"name": name, "started": time.monotonic(),
                  "thread_id": threading.get_ident()}
        timer = None
        with self._lock:
            self._active = active
        try:
            if self.control_root is not None:
                try:
                    timer = threading.Timer(self.slow_seconds, self._slow, args=(active,))
                    timer.daemon = True
                    active["timer"] = timer
                    timer.start()
                except Exception:
                    # Thread/resource exhaustion cannot prevent the real operation.
                    pass
            try:
                yield
            except BaseException as exc:
                active["error_type"] = type(exc).__name__[:80]
                raise
        finally:
            if timer is not None:
                timer.cancel()
            with self._lock:
                if self._active is active:
                    self._active = None
                entry = {"stage": name, "thread_id": active["thread_id"],
                         "elapsed_s": round(time.monotonic() - active["started"], 6),
                         "status": "error" if "error_type" in active else "complete"}
                if "error_type" in active:
                    entry["error_type"] = active["error_type"]
                self._stages.append(entry)

    def checkpoint(self, name):
        if name != "response_ready":
            raise ValueError("unknown origin transfer diagnostic checkpoint")
        with self._lock:
            stages = list(self._stages)
        self._record(name, stages=stages)

    def finish(self, outcome, *, asgi_accepted_body_bytes=0, response_status=None, error_type=None):
        with self._lock:
            if self._finished:
                return
            self._finished = True
            active = self._active
            self._active = None
            stages = list(self._stages)
        if active is not None and active.get("timer") is not None:
            active["timer"].cancel()
        fields = {"outcome": outcome, "stages": stages,
                  # Successful ASGI send awaits, not socket or client receipt.
                  "asgi_accepted_body_bytes": asgi_accepted_body_bytes,
                  "response_status": response_status}
        if error_type is not None:
            fields["error_type"] = error_type[:80]
        self._record("finished", **fields)
