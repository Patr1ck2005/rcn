"""Project-scoped immutable assets for thin origin archives (no remote paths)."""
from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import tempfile
import hashlib
import threading
import time
from collections import OrderedDict

from .origin_transfer import identifier, managed_path, publish_new_file, verify_file

ASSET_MARKER = "origin-assets.json"
ASSET_MARKER_BYTES = b'{"storage":"project-sha256","version":1}'


class TransferAssetValidationCache:
    """Bounded transfer-only hash cache for ACL-protected immutable assets.

    Identity/metadata are checked each time; fresh hashing repeats after 30s.
    Dispatcher validation/extraction does not use this cache. Thus an unnoticed
    at-rest corruption cannot become scientific execution merely from a hit.
    """
    def __init__(self, *, ttl_s=30, max_entries=128):
        self.ttl_s, self.max_entries = ttl_s, max_entries
        self.entries = OrderedDict()
        self.lock = threading.Lock()

    @staticmethod
    def stamp(path):
        s = path.stat()
        return (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)

    def verify(self, path, size, digest):
        try:
            before = self.stamp(path)
        except FileNotFoundError as exc:
            raise ValueError("managed asset is missing") from exc
        key = (str(path), size, digest)
        with self.lock:
            cached = self.entries.get(key)
            if cached and cached[0] == before and time.monotonic() - cached[1] < self.ttl_s:
                self.entries.move_to_end(key)
                return
        verify_file(path, size, digest)
        if self.stamp(path) != before:
            raise ValueError("asset changed during integrity verification")
        with self.lock:
            self.entries[key] = (before, time.monotonic())
            self.entries.move_to_end(key)
            while len(self.entries) > self.max_entries:
                self.entries.popitem(last=False)


def asset_path(root: Path, job, digest: str) -> Path:
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("invalid asset digest")
    origin, project = identifier(job.origin_submitter_id), identifier(job.project_id)
    # Keep differently cased identifiers isolated even on Windows filesystems.
    namespace = hashlib.sha256((origin + "\0" + project).encode()).hexdigest()
    return managed_path(root, origin, "assets", namespace, digest)


def declared_asset(job, digest: str):
    records = [r for r in job.input_manifest if r.sha256 == digest]
    if not records or len({r.size_bytes for r in records}) != 1:
        raise ValueError("asset is not bound to Job inputs")
    return records[0]


def verify_asset(root: Path, job, record, *, transfer_cache=None) -> Path:
    expected = declared_asset(job, record.sha256)
    if expected.size_bytes != record.size_bytes:
        raise ValueError("asset size is not bound to Job inputs")
    path = asset_path(root, job, record.sha256)
    if transfer_cache is None:
        verify_file(path, record.size_bytes, record.sha256)
    else:
        transfer_cache.verify(path, record.size_bytes, record.sha256)
    return path


def publish_asset(root: Path, job, record, source: Path) -> Path:
    expected = declared_asset(job, record.sha256)
    if expected.size_bytes != record.size_bytes:
        raise ValueError("asset size is not bound to Job inputs")
    target = asset_path(root, job, record.sha256)
    if target.exists():
        return verify_asset(root, job, record)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".asset-", suffix=".partial", dir=target.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as output, source.open("rb") as incoming:
            shutil.copyfileobj(incoming, output, length=1024 * 1024)
            output.flush()
            os.fsync(output.fileno())
        verify_file(temporary, record.size_bytes, record.sha256)
        asset_path(root, job, record.sha256)  # Recheck managed ancestors.
        try:
            publish_new_file(temporary, target)
        except FileExistsError:
            verify_asset(root, job, record)
    finally:
        temporary.unlink(missing_ok=True)
    return target
