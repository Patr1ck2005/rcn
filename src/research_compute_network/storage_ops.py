"""Bounded operator CLI for registering and verifying center storage roots.

This tool never copies, deletes, formats, or rewrites scientific payloads. Roots
must already exist as plain directories. Registration changes only the role
marker and the control-plane's storage-roots.json under the original RCN_HOME.
"""

from __future__ import annotations

import argparse
import json
import os
import tempfile
import uuid
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import Iterator

from .paths import default_rcn_home
from .storage_roots import (
    STORE_MARKER, STORAGE_ROLES, StoreBinding, StorageRootError, StorageRootRegistry,
    _read_json, absolute_root, current_host_id, load_storage_registry,
    probe_volume_identity, reject_reparse_path, WRITE_PAUSE, read_write_pause,
)


def _sync_directory(directory: Path) -> None:
    if os.name == "nt":
        return  # Windows file fsync uses FlushFileBuffers; directory handles differ.
    descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_json(path: Path, payload: dict, *, create_only: bool = False) -> None:
    reject_reparse_path(path.parent)
    reject_reparse_path(path, must_exist=False)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".rcn-storage-", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(payload, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        if create_only:
            os.link(temporary, path)
        else:
            os.replace(temporary, path)
        _sync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


@contextmanager
def _registry_lock(control_root: Path) -> Iterator[None]:
    reject_reparse_path(control_root, must_exist=False)
    control_root.mkdir(parents=True, exist_ok=True)
    reject_reparse_path(control_root)
    path = control_root / ".storage-roots.lock"
    reject_reparse_path(path, must_exist=False)
    with path.open("a+b") as stream:
        if os.name == "nt":
            import msvcrt
            if stream.seek(0, os.SEEK_END) == 0:
                stream.write(b"\0")
                stream.flush()
            stream.seek(0)
            try:
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise StorageRootError("storage_registry_busy", "another storage registry operation is active") from exc
            try:
                yield
            finally:
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            try:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise StorageRootError("storage_registry_busy", "another storage registry operation is active") from exc
            try:
                yield
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def _check_layout(registry: StorageRootRegistry, binding: StoreBinding) -> None:
    if binding.root == registry.control_root or registry.control_root.is_relative_to(binding.root):
        raise StorageRootError("storage_config_invalid", "data roots cannot contain the control-plane root")
    for role, other in registry.roots.items():
        if role != binding.logical_store_id and (
            binding.root.is_relative_to(other.root) or other.root.is_relative_to(binding.root)
            or other.store_id == binding.store_id
        ):
            raise StorageRootError("storage_config_invalid", "data role roots or store UUIDs overlap")


def register_root(control_root: str | Path, role: str, root: str | Path,
                  *, store_id: str | None = None, generation: int | None = None) -> StoreBinding:
    """Create a role once, or recover an identical interrupted registration."""
    selected = absolute_root(root)
    control = absolute_root(control_root)
    if role not in STORAGE_ROLES:
        raise StorageRootError("storage_role_invalid", "unknown center storage role")
    with _registry_lock(control):
        registry = load_storage_registry(control)
        current = registry.binding(role)
        if current:
            if current.root != selected or (store_id is not None and current.store_id != store_id) or (
                generation is not None and current.generation != generation
            ):
                raise StorageRootError("storage_binding_changed", "registered role is immutable; use explicit relocate for a verified path change")
            current.validate()
            return current
        identity = probe_volume_identity(selected)
        marker = selected / STORE_MARKER
        if os.path.lexists(marker):
            payload = _read_json(marker)
            if payload.get("format") != 1:
                raise StorageRootError("storage_marker_mismatch", "unsupported existing storage marker")
            binding = StoreBinding.from_dict({key: value for key, value in payload.items() if key != "format"})
            if binding.host_id != current_host_id() or binding.logical_store_id != role or binding.root != selected or (
                binding.volume_identity != identity or (store_id is not None and binding.store_id != store_id)
                or (generation is not None and binding.generation != generation)
            ):
                raise StorageRootError("storage_marker_mismatch", "existing marker does not match this registration")
        else:
            binding = StoreBinding.from_dict({
                "host_id": current_host_id(), "logical_store_id": role,
                "store_id": store_id if store_id is not None else str(uuid.uuid4()),
                "generation": generation if generation is not None else 1,
                "root": str(selected), "volume_identity": identity.as_dict(),
            })
        _check_layout(registry, binding)
        if not os.path.lexists(marker):
            _write_json(marker, binding.marker_payload(), create_only=True)
        binding.validate()
        roots = {**registry.roots, role: binding}
        _write_json(registry.config_path, replace(registry, roots=roots).as_dict())
        return binding


def relocate_root(control_root: str | Path, role: str, root: str | Path,
                  *, expected_store_id: str, expected_generation: int) -> StoreBinding:
    """Explicitly remap the same marked volume after a drive-letter change.

    This never creates a fresh marker or accepts a different volume. The old
    marker must be present on the newly selected path. UUID/generation stay put.
    """
    selected = absolute_root(root)
    control = absolute_root(control_root)
    with _registry_lock(control):
        registry = load_storage_registry(control)
        current = registry.binding(role)
        if current is None or current.store_id != expected_store_id or current.generation != expected_generation:
            raise StorageRootError("storage_binding_changed", "expected store UUID/generation does not match the registry")
        candidate = replace(current, root=selected)
        _check_layout(registry, candidate)
        marker = _read_json(selected / STORE_MARKER)
        # The second form resumes a crash after marker replacement, before config.
        if marker not in (current.marker_payload(), candidate.marker_payload()):
            raise StorageRootError("storage_marker_mismatch", "relocate requires the original exact store marker")
        if probe_volume_identity(selected) != current.volume_identity:
            raise StorageRootError("storage_volume_mismatch", "relocate cannot change the registered physical volume")
        if marker != candidate.marker_payload():
            _write_json(selected / STORE_MARKER, candidate.marker_payload())
        candidate.validate()
        _write_json(registry.config_path, replace(registry, roots={**registry.roots, role: candidate}).as_dict())
        return candidate


def set_write_pause(control_root: str | Path, *, paused: bool, roles: list[str],
                    operation_id: str, actor_id: str, reason: str) -> dict:
    from datetime import datetime, timezone
    if type(paused) is not bool or not roles or set(roles) - STORAGE_ROLES or any(
        not isinstance(value, str) or not value.strip() for value in (operation_id, actor_id, reason)):
        raise StorageRootError("storage_write_pause_invalid", "pause requires explicit roles, operation, actor and reason")
    control = absolute_root(control_root)
    with _registry_lock(control):
        previous = read_write_pause(control)
        if previous and previous["paused"] and previous["operation_id"] != operation_id:
            raise StorageRootError("storage_writes_already_paused", "another operator owns the write barrier")
        if previous and previous["operation_id"] == operation_id and previous["paused"] == paused:
            if previous["roles"] != sorted(set(roles)):
                raise StorageRootError("storage_write_pause_invalid", "operation roles changed")
            return previous
        if not paused and (previous is None or previous["operation_id"] != operation_id):
            raise StorageRootError("storage_write_pause_invalid", "resume must match the original operation")
        value = {"format": 1, "host_id": current_host_id(), "paused": paused,
                 "roles": sorted(set(roles)), "operation_id": operation_id,
                 "actor_id": actor_id, "reason": reason, "at_utc": datetime.now(timezone.utc).isoformat()}
        _write_json(control / WRITE_PAUSE, value)
        return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rcn-home", type=Path, default=None)
    sub = parser.add_subparsers(dest="action", required=True)
    register = sub.add_parser("register", help="register an existing plain role root (no copy/delete)")
    register.add_argument("--role", choices=sorted(STORAGE_ROLES), required=True)
    register.add_argument("--root", type=Path, required=True)
    register.add_argument("--store-id")
    register.add_argument("--generation", type=int)
    relocate = sub.add_parser("relocate", help="explicitly remap the same verified store, preserving identity")
    relocate.add_argument("--role", choices=sorted(STORAGE_ROLES), required=True)
    relocate.add_argument("--root", type=Path, required=True)
    relocate.add_argument("--expected-store-id", required=True)
    relocate.add_argument("--expected-generation", type=int, required=True)
    inspect = sub.add_parser("inspect", help="read registry metadata without accessing data roots")
    inspect.add_argument("--role", choices=sorted(STORAGE_ROLES))
    verify = sub.add_parser("verify", help="strictly verify marker, host, volume and physical disk")
    verify.add_argument("--role", choices=sorted(STORAGE_ROLES))
    for action in ("pause-writes", "resume-writes"):
        pause = sub.add_parser(action, help="temporary audited migration write barrier; reads stay available")
        pause.add_argument("--role", choices=sorted(STORAGE_ROLES), action="append", required=True)
        pause.add_argument("--operation-id", required=True)
        pause.add_argument("--actor-id", required=True)
        pause.add_argument("--reason", required=True)
    args = parser.parse_args(argv)
    control = args.rcn_home if args.rcn_home is not None else default_rcn_home()
    try:
        if args.action == "register":
            result = register_root(control, args.role, args.root, store_id=args.store_id,
                                   generation=args.generation).as_dict()
        elif args.action == "relocate":
            result = relocate_root(control, args.role, args.root, expected_store_id=args.expected_store_id,
                                   expected_generation=args.expected_generation).as_dict()
        elif args.action in {"pause-writes", "resume-writes"}:
            result = set_write_pause(control, paused=args.action == "pause-writes", roles=args.role,
                operation_id=args.operation_id, actor_id=args.actor_id, reason=args.reason)
        else:
            registry = load_storage_registry(control)
            roles = [args.role] if args.role else sorted(registry.roots)
            if args.action == "verify":
                if not roles:
                    raise StorageRootError("storage_role_unregistered", "no center storage roles are registered")
                for role in roles:
                    binding = registry.binding(role)
                    if binding is None:
                        raise StorageRootError("storage_role_unregistered", f"storage role is not registered: {role}")
                    binding.validate()
            result = registry.as_dict() if not args.role else (
                registry.binding(args.role).as_dict() if registry.binding(args.role) else None
            )
        print(json.dumps({"ok": True, "action": args.action, "result": result}, sort_keys=True))
        return 0
    except (StorageRootError, OSError) as exc:
        print(json.dumps({"ok": False, "reason_code": getattr(exc, "reason_code", "storage_io_failed"),
                          "message": str(exc)}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
