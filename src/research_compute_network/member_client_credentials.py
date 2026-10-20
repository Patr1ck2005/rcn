"""Owner-private Windows DPAPI storage for the member's personal login.

The device credential and execution-account password belong to other stores.
Nothing in this module opens a control-plane database.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path

from . import member_registration as storage


class CredentialUnavailable(RuntimeError):
    pass


def _crypt(data: bytes, *, decrypt: bool = False) -> bytes:
    if os.name != "nt":
        raise CredentialUnavailable("member_credentials_require_windows_dpapi")

    class Blob(ctypes.Structure):
        _fields_ = [("size", wintypes.DWORD), ("data", ctypes.POINTER(ctypes.c_ubyte))]

    def blob(value):
        buffer = (ctypes.c_ubyte * len(value)).from_buffer_copy(value)
        return Blob(len(value), buffer), buffer

    incoming, incoming_buffer = blob(data)
    entropy, entropy_buffer = blob(b"RCN-personal-member-login-v1")
    outgoing = Blob()
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    function = crypt32.CryptUnprotectData if decrypt else crypt32.CryptProtectData
    function.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.POINTER(Blob),
                         ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
    function.restype = wintypes.BOOL
    # CRYPTPROTECT_UI_FORBIDDEN; CurrentUser scope, never a plaintext fallback.
    if not function(ctypes.byref(incoming), None, ctypes.byref(entropy), None, None, 1,
                    ctypes.byref(outgoing)):
        raise CredentialUnavailable("member_credentials_dpapi_failed")
    try:
        return ctypes.string_at(outgoing.data, outgoing.size)
    finally:
        kernel32.LocalFree(outgoing.data)


class PersonalCredentialStore:
    def __init__(self, root: Path):
        self.root = Path(root).absolute()
        storage._private_directory(self.root)
        self.path = self.root / "personal-login.dpapi"

    def save(self, *, center_url: str, token: str, actor: dict | None = None) -> None:
        raw = json.dumps({"schema_version": 1, "center_url": center_url, "token": token, "actor": actor},
                         separators=(",", ":")).encode("utf-8")
        encrypted = _crypt(raw)
        with storage._exclusive(self.root):
            before = storage._read_bytes(self.path) if self.path.exists() else None
            storage._publish(self.path, encrypted, expected=before)

    def load(self) -> dict | None:
        if not self.path.exists():
            return None
        storage._check_private_file(self.path)
        try:
            value = json.loads(_crypt(storage._read_bytes(self.path), decrypt=True))
            if set(value) not in ({"schema_version", "center_url", "token"}, {"schema_version", "center_url", "token", "actor"}) or value["schema_version"] != 1:
                raise ValueError("invalid credential document")
            if value.get("actor") is not None and (not isinstance(value["actor"], dict) or not value["actor"].get("actor_id")):
                raise ValueError("invalid cached owner identity")
            return value
        except (ValueError, KeyError, TypeError) as exc:
            raise CredentialUnavailable("member_credentials_invalid") from exc

    def clear(self) -> None:
        with storage._exclusive(self.root):
            storage._check_private_file(self.path)
            self.path.unlink(missing_ok=True)
