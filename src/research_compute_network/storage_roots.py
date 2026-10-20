"""Host-scoped, explicit center data-root bindings.

Configuration is metadata on the original control-plane volume. Loading it does
not touch a data volume; validate a role immediately before accessing its bytes.
There is deliberately no fallback to the old path after a role is configured.
"""

from __future__ import annotations

import ctypes
import json
import os
import socket
import stat
import struct
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


STORAGE_CONFIG = "storage-roots.json"
WRITE_PAUSE = "storage-write-pause.json"
STORE_MARKER = ".rcn-store.json"
STORAGE_ROLES = frozenset({"origin_spool", "dispatcher_bundles"})
_MAX_METADATA_BYTES = 64 * 1024


class StorageRootError(ValueError):
    def __init__(self, reason_code: str, message: str):
        super().__init__(message)
        self.reason_code = reason_code


def current_host_id() -> str:
    return socket.gethostname().strip().casefold()


def read_write_pause(control_root: Path) -> dict | None:
    """A temporary operator barrier affects writes, never read/API startup."""
    path = Path(control_root) / WRITE_PAUSE
    if not path.exists():
        return None
    value = _read_json(path)
    expected = {"format", "host_id", "paused", "roles", "operation_id", "actor_id", "reason", "at_utc"}
    if (set(value) != expected or type(value["format"]) is not int or value["format"] != 1
        or type(value["paused"]) is not bool or value["host_id"] != current_host_id()
        or not isinstance(value["roles"], list) or not value["roles"]
        or any(not isinstance(role, str) for role in value["roles"])
        or set(value["roles"]) - STORAGE_ROLES
        or any(not isinstance(value[k], str) or not value[k].strip() for k in ("operation_id", "actor_id", "reason", "at_utc"))):
        raise StorageRootError("storage_write_pause_invalid", "invalid host-scoped storage write barrier")
    return value


def assert_writes_enabled(control_root: Path, role: str) -> None:
    pause = read_write_pause(control_root)
    if pause and pause["paused"] and role in pause["roles"]:
        raise StorageRootError("storage_write_paused", "center writes are paused for an operator migration")


def absolute_root(value: str | Path) -> Path:
    if not isinstance(value, (str, Path)) or "\x00" in str(value):
        raise StorageRootError("storage_config_invalid", "storage root must be a valid path")
    path = Path(value).expanduser()
    if not path.is_absolute() or ".." in path.parts or path == Path(path.anchor):
        raise StorageRootError("storage_config_invalid", "storage root must be an absolute directory below a volume root")
    return path.absolute()


def reject_reparse_path(path: Path, *, must_exist: bool = True) -> None:
    """Inspect every ancestor before resolving, so links are never hidden."""
    for item in (*reversed(path.parents), path):
        try:
            info = item.lstat()
        except (FileNotFoundError, OSError) as exc:
            if not must_exist and isinstance(exc, FileNotFoundError):
                continue
            raise StorageRootError("storage_root_unavailable", f"storage path unavailable: {item}") from exc
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise StorageRootError("storage_root_reparse", f"storage path contains a link or reparse point: {item}")


def _read_json(path: Path) -> dict[str, Any]:
    reject_reparse_path(path)
    try:
        if not path.is_file() or path.stat().st_size > _MAX_METADATA_BYTES:
            raise ValueError("not a bounded regular metadata file")
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("metadata must be an object")
        return value
    except (OSError, ValueError) as exc:
        raise StorageRootError("storage_config_invalid", f"invalid storage metadata: {path}") from exc


@dataclass(frozen=True)
class VolumeIdentity:
    platform: str
    volume_id: str
    volume_serial: str
    filesystem: str
    physical_device_id: str

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "VolumeIdentity":
        names = {"platform", "volume_id", "volume_serial", "filesystem", "physical_device_id"}
        if not isinstance(value, dict) or set(value) != names or any(
            not isinstance(value[name], str) or not value[name].strip() for name in names
        ):
            raise StorageRootError("storage_config_invalid", "invalid storage volume identity")
        result = cls(**value)
        if result.platform not in {"windows", "posix"}:
            raise StorageRootError("storage_config_invalid", "unsupported volume identity platform")
        if result.platform == "windows" and result.filesystem.upper() != "NTFS":
            raise StorageRootError("storage_filesystem_unsupported", "center data roots require NTFS on Windows")
        return result

    def as_dict(self) -> dict[str, str]:
        return dict(self.__dict__)


def _windows_device_identity(kernel: Any, volume_id: str) -> str:
    """Read the single physical disk's hardware descriptor, without a shell."""
    from ctypes import wintypes

    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p,
                                      wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                                      ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    kernel.DeviceIoControl.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    invalid_handle = ctypes.c_void_p(-1).value

    def open_device(name: str):
        handle = kernel.CreateFileW(name, 0, 3, None, 3, 0, None)
        if handle == invalid_handle:
            raise ctypes.WinError(ctypes.get_last_error())
        return handle

    volume = open_device(volume_id.rstrip("\\"))
    try:
        extents = ctypes.create_string_buffer(4096)
        returned = wintypes.DWORD()
        # IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS; DISK_EXTENT is 8-byte aligned.
        if not kernel.DeviceIoControl(volume, 0x00560000, None, 0, extents, len(extents),
                                      ctypes.byref(returned), None):
            raise ctypes.WinError(ctypes.get_last_error())
        if returned.value < 32 or struct.unpack_from("<I", extents.raw)[0] != 1:
            raise StorageRootError("storage_volume_unsupported", "center store must use one identifiable physical disk")
        disk_number = struct.unpack_from("<I", extents.raw, 8)[0]
    finally:
        kernel.CloseHandle(volume)
    disk = open_device(r"\\.\PhysicalDrive" + str(disk_number))
    try:
        query = ctypes.create_string_buffer(12)  # StorageDeviceProperty / PropertyStandardQuery
        descriptor = ctypes.create_string_buffer(64 * 1024)
        returned = wintypes.DWORD()
        if not kernel.DeviceIoControl(disk, 0x002D1400, query, len(query), descriptor,
                                      len(descriptor), ctypes.byref(returned), None):
            raise ctypes.WinError(ctypes.get_last_error())
        data = descriptor.raw[:returned.value]
        if len(data) < 36:
            raise ValueError("short disk identity descriptor")
        vendor_offset, product_offset, _, serial_offset = struct.unpack_from("<4I", data, 12)

        def component(offset: int) -> str:
            return data[offset:].split(b"\0", 1)[0].decode("ascii", errors="strict").strip() if 0 < offset < len(data) else ""

        serial = component(serial_offset)
        if not serial:
            raise StorageRootError("storage_device_identity_unavailable", "physical disk does not expose a hardware serial")
        return json.dumps([component(vendor_offset), component(product_offset), serial], separators=(",", ":"))
    finally:
        kernel.CloseHandle(disk)


def probe_volume_identity(root: Path) -> VolumeIdentity:
    """Probe the volume hosting an already existing plain root."""
    reject_reparse_path(root)
    if not root.is_dir():
        raise StorageRootError("storage_root_unavailable", "storage root is not a directory")
    if os.name != "nt":
        device = str(root.stat().st_dev)
        return VolumeIdentity("posix", "dev:" + device, device, "posix", "dev:" + device)
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetVolumePathNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    kernel.GetVolumeNameForVolumeMountPointW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    kernel.GetVolumeInformationW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD,
                                            ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
                                            ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR, wintypes.DWORD]
    try:
        mount, volume = ctypes.create_unicode_buffer(32768), ctypes.create_unicode_buffer(1024)
        filesystem = ctypes.create_unicode_buffer(256)
        serial, max_name, flags = wintypes.DWORD(), wintypes.DWORD(), wintypes.DWORD()
        if not kernel.GetVolumePathNameW(str(root), mount, len(mount)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not kernel.GetVolumeNameForVolumeMountPointW(mount.value, volume, len(volume)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not kernel.GetVolumeInformationW(mount.value, None, 0, ctypes.byref(serial), ctypes.byref(max_name),
                                            ctypes.byref(flags), filesystem, len(filesystem)):
            raise ctypes.WinError(ctypes.get_last_error())
        identity = VolumeIdentity("windows", volume.value.casefold(), f"{serial.value:08X}",
                                  filesystem.value.upper(), _windows_device_identity(kernel, volume.value))
        return VolumeIdentity.from_dict(identity.as_dict())
    except StorageRootError:
        raise
    except (OSError, ValueError) as exc:
        raise StorageRootError("storage_volume_unavailable", f"cannot verify storage volume for {root}: {exc}") from exc


@dataclass(frozen=True)
class StoreBinding:
    host_id: str
    logical_store_id: str
    store_id: str
    generation: int
    root: Path
    volume_identity: VolumeIdentity

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "StoreBinding":
        names = {"host_id", "logical_store_id", "store_id", "generation", "root", "volume_identity"}
        if not isinstance(value, dict) or set(value) != names:
            raise StorageRootError("storage_config_invalid", "invalid storage binding fields")
        if not isinstance(value["logical_store_id"], str) or value["logical_store_id"] not in STORAGE_ROLES or (
            not isinstance(value["host_id"], str) or not value["host_id"]
        ):
            raise StorageRootError("storage_config_invalid", "invalid storage role or host")
        if type(value["generation"]) is not int or value["generation"] < 1:
            raise StorageRootError("storage_config_invalid", "storage generation must be a positive integer")
        try:
            if str(uuid.UUID(value["store_id"])) != value["store_id"]:
                raise ValueError("UUID must be canonical")
        except (ValueError, TypeError, AttributeError) as exc:
            raise StorageRootError("storage_config_invalid", "store_id must be a canonical UUID") from exc
        if not isinstance(value["root"], str):
            raise StorageRootError("storage_config_invalid", "storage root must be a path string")
        return cls(value["host_id"], value["logical_store_id"], value["store_id"], value["generation"],
                   absolute_root(value["root"]), VolumeIdentity.from_dict(value["volume_identity"]))

    def as_dict(self) -> dict[str, Any]:
        return {"host_id": self.host_id, "logical_store_id": self.logical_store_id,
                "store_id": self.store_id, "generation": self.generation,
                "root": str(self.root), "volume_identity": self.volume_identity.as_dict()}

    def marker_payload(self) -> dict[str, Any]:
        return {"format": 1, **self.as_dict()}

    def validate(self, *, root: Path | None = None,
                 volume_probe: Callable[[Path], VolumeIdentity] | None = None) -> Path:
        if self.host_id != current_host_id():
            raise StorageRootError("storage_host_mismatch", "storage binding belongs to another host")
        selected = absolute_root(root) if root is not None else self.root
        reject_reparse_path(selected)
        marker_path = selected / STORE_MARKER
        if not marker_path.exists():
            raise StorageRootError("storage_marker_missing", f"managed storage marker is missing: {selected}")
        marker = _read_json(marker_path)
        if marker != self.marker_payload():
            raise StorageRootError("storage_marker_mismatch", f"managed storage binding changed: {selected}")
        actual = (volume_probe or probe_volume_identity)(selected)
        if actual != self.volume_identity:
            raise StorageRootError("storage_volume_mismatch", f"managed storage volume identity changed: {selected}")
        return selected


@dataclass(frozen=True)
class StorageRootRegistry:
    control_root: Path
    host_id: str
    roots: dict[str, StoreBinding] = field(default_factory=dict)

    @property
    def config_path(self) -> Path:
        return self.control_root / STORAGE_CONFIG

    def binding(self, role: str) -> StoreBinding | None:
        if role not in STORAGE_ROLES:
            raise StorageRootError("storage_role_invalid", "unknown center storage role")
        return self.roots.get(role)

    def path_for(self, role: str, default: Path) -> Path:
        binding = self.binding(role)
        return binding.root if binding else default

    def validate(self, role: str, default: Path) -> Path:
        binding = self.binding(role)
        return binding.validate() if binding else default

    def as_dict(self) -> dict[str, Any]:
        return {"format": 1, "host_id": self.host_id,
                "roots": {name: binding.as_dict() for name, binding in sorted(self.roots.items())}}


def load_storage_registry(control_root: str | Path) -> StorageRootRegistry:
    root = Path(control_root).absolute()
    config = root / STORAGE_CONFIG
    # Only absence enables legacy defaults. Permission/IO errors and dangling
    # linked configs must not silently change the selected storage roles.
    try:
        config.lstat()
    except FileNotFoundError:
        return StorageRootRegistry(root, current_host_id())
    except OSError as exc:
        raise StorageRootError("storage_config_unavailable", f"cannot read storage registry: {config}") from exc
    payload = _read_json(config)
    if set(payload) != {"format", "host_id", "roots"} or type(payload["format"]) is not int or payload["format"] != 1:
        raise StorageRootError("storage_config_invalid", "unsupported storage registry format")
    if payload["host_id"] != current_host_id():
        raise StorageRootError("storage_host_mismatch", "storage registry belongs to another host")
    if not isinstance(payload["roots"], dict) or set(payload["roots"]) - STORAGE_ROLES:
        raise StorageRootError("storage_config_invalid", "invalid registered center roles")
    roots = {name: StoreBinding.from_dict(value) for name, value in payload["roots"].items()}
    for role, binding in roots.items():
        if binding.host_id != payload["host_id"] or binding.logical_store_id != role:
            raise StorageRootError("storage_config_invalid", "storage registry role/host binding mismatch")
        if binding.root == root or root.is_relative_to(binding.root):
            raise StorageRootError("storage_config_invalid", "data roots cannot contain the control-plane root")
    bindings = list(roots.values())
    if len({binding.store_id for binding in bindings}) != len(bindings):
        raise StorageRootError("storage_config_invalid", "center roles require distinct store UUIDs")
    for index, left in enumerate(bindings):
        for right in bindings[index + 1:]:
            if left.root.is_relative_to(right.root) or right.root.is_relative_to(left.root):
                raise StorageRootError("storage_config_invalid", "center data role roots cannot overlap")
    return StorageRootRegistry(root, payload["host_id"], roots)
