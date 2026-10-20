"""Public scientific-probe boundary; origin projects supply their own evidence."""
import os
from pathlib import Path
from .runtime_policy import UNCONFIGURED_RUNTIME_VERSION
from .member_release_catalog import RuntimeNotConfigured

CAPSULE_SHA256 = ""
CAPSULE_RUNTIME = UNCONFIGURED_RUNTIME_VERSION
PROFILE = "workbench-comsol-scan-v1"
PROJECT = ACTOR = "rcn-scientific-acceptance"
CHECK_IDS = frozenset({"scientific_context", "scientific_scan", "scientific_artifacts", "scientific_numerics"})
NAMES = frozenset()


def capsule_bytes():
    raise RuntimeNotConfigured()


def publish_immutable(path: Path, raw: bytes) -> None:
    """Durable complete bytes appear atomically without replacing existing evidence."""
    import tempfile
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.is_symlink() or path.read_bytes() != raw:
            raise ValueError('scientific_acceptance_input_changed')
        return
    fd, name = tempfile.mkstemp(prefix='.science-publish-', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(raw); out.flush(); os.fsync(out.fileno())
        try:
            os.link(temporary, path)  # Atomic create-only publication, not overwrite.
        except FileExistsError:
            if path.is_symlink() or path.read_bytes() != raw:
                raise ValueError('scientific_acceptance_input_changed')
    finally:
        temporary.unlink(missing_ok=True)  # Only this invocation's private staging file.


def materialize_capsule(state_root):
    raise RuntimeNotConfigured()


def context_for(config):
    raise RuntimeNotConfigured()


def probe_job(config):
    raise RuntimeNotConfigured()


def is_bound_scientific_job(job, machine, config):
    return False


def scientific_acceptance_capability():
    return {"kind": "origin-owned-scientific-probe", "available": False,
            "reason_code": "runtime_not_configured", "profile_id": PROFILE,
            "workbench_source_adapter_required": True,
            "machine_lifecycle_acceptance": False}
