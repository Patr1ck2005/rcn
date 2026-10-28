"""Portable PRIVATE personal connection bundles; never a worker enrollment.

Only this module's builder handles plaintext bundle bytes. Import receipts and
payloads are CurrentUser DPAPI encrypted before any network request. Public
results are deliberately allowlisted. A manifest checksum detects corruption;
it is not an administrator signature. Existing local endpoint trust is checked
independently before a connection update can inherit journals.
"""
from __future__ import annotations

import argparse
import base64
from copy import deepcopy
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
import re
import socket
import stat
import tempfile
from typing import Literal
from uuid import UUID, uuid4
from urllib.error import URLError
from zipfile import BadZipFile, ZIP_DEFLATED, ZipFile

from pydantic import Field, ValidationError, model_validator

from . import member_client_connection as connection
from . import member_client_credentials as credentials
from . import member_registration as storage

MAX_BUNDLE_BYTES = 1024 * 1024
MAX_CONTENT_BYTES = 96 * 1024
MAX_STATE_BYTES = 262144
MAX_MIGRATION_FILES = 4096
MAX_MIGRATION_BYTES = 32 * 1024 * 1024
MIGRATION_CHUNK_BYTES = 128 * 1024
FORMAT = "rcn-private-member-connection"
TOKEN_FILE = "member-token.txt"
CONNECTION_FILE = "connection.json"
KEY_FILE = "ssh-identity"
HOSTS_FILE = "known_hosts"
IMPORT_REASON_CODES = frozenset("member_connection_import_" + suffix for suffix in """
agent_binding_changed archive_entries bundle_size center_trust_changed channel_children_changed
commit_failed desktop_root_required different_center different_member existing_channel_changed
existing_connection_changed existing_trust_unselected invalid_build_input invalid_bundle invalid_connection
invalid_identifier invalid_journal invalid_known_hosts invalid_manifest invalid_personal_token
invalid_ssh_identity journal_changed journal_size legacy_handoff_pending_or_changed local_state_changed
manifest_hash migration_journal_changed migration_root_changed migration_size not_found operations_busy
owner_or_root_changed personal_identity_mismatch root_not_owned ssh_prerequisite_required staged_channel_changed
staged_file_changed upstream_collides_with_broker validation_failed center_login_required
center_permission_denied center_unavailable pinned_file_changed pinned_file_missing upstream_port_in_use
channel_not_owned ssh_channel_unavailable local_secret_unavailable local_permissions_invalid
""".split())


class ConnectionImportError(RuntimeError):
    """A stable, secret-free diagnostic; do not serialize exception causes."""

    def __init__(self, reason_code):
        self.reason_code = reason_code
        super().__init__(reason_code)


def _fail(code):
    raise ConnectionImportError("member_connection_import_" + code) from None


def _json(raw):
    return storage._json_document(raw)


def _raw(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf8")


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _failure_code(exc):
    if isinstance(exc, ConnectionImportError):
        return exc.reason_code
    from .client import RcnApiError
    if isinstance(exc, RcnApiError):
        suffix = {401: "center_login_required", 403: "center_permission_denied"}.get(exc.status, "center_unavailable")
    elif isinstance(exc, credentials.CredentialUnavailable):
        suffix = "local_secret_unavailable"
    elif isinstance(exc, FileNotFoundError):
        suffix = "pinned_file_missing"
    elif isinstance(exc, (URLError, ConnectionError, TimeoutError)):
        suffix = "center_unavailable"
    else:
        suffix = {
            "member_connection_pinned_file_changed": "pinned_file_changed",
            "member_connection_upstream_port_in_use": "upstream_port_in_use",
            "member_connection_upstream_listener_not_owned": "channel_not_owned",
            "member_connection_process_identity_changed": "channel_not_owned",
            "member_connection_channel_owner_changed": "channel_not_owned",
            "member_connection_process_missing": "ssh_channel_unavailable",
            "member_connection_channel_start_pending": "ssh_channel_unavailable",
            "registration_root_permissions": "local_permissions_invalid",
            "registration_file_permissions": "local_permissions_invalid",
        }.get(str(exc), "validation_failed")
    return "member_connection_import_" + suffix


def _canonical_uuid(value):
    if str(UUID(value)) != value:
        _fail("invalid_identifier")
    return value


class PortableSsh(connection.PrivateModel):
    host: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")
    user: str = Field(pattern=r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$")
    port: int = Field(default=22, ge=1, le=65535)
    center_port: int = Field(ge=1, le=65535)
    upstream_port: int = Field(default=28765, ge=1, le=65535)

    @model_validator(mode="after")
    def separate_port(self):
        if self.upstream_port == connection.BROKER_PORT:
            _fail("upstream_collides_with_broker")
        return self


class PortableConnection(connection.PrivateModel):
    mode: Literal["https", "managed-ssh"]
    https_url: str | None = None
    ssh: PortableSsh | None = None

    @model_validator(mode="after")
    def selected(self):
        if self.mode == "https":
            if not self.https_url or self.ssh is not None:
                _fail("invalid_connection")
            if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in self.https_url):
                _fail("invalid_connection")
            self.https_url = connection.https_center(self.https_url)
        elif self.ssh is None or self.https_url is not None:
            _fail("invalid_connection")
        return self


class BundleManifest(connection.PrivateModel):
    schema_version: int = Field(ge=1, le=1)
    kind: Literal["rcn-private-member-connection"]
    center_id: str = Field(pattern=r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$")
    center_name: str = Field(min_length=1, max_length=128)
    owner_user_id: str = Field(min_length=1, max_length=128)
    files: dict[str, str]

    @model_validator(mode="after")
    def bounded_strings(self):
        _canonical_uuid(self.center_id)
        for value in (self.center_name, self.owner_user_id):
            if value != value.strip() or any(ord(char) < 32 or ord(char) == 127 for char in value):
                _fail("invalid_manifest")
        if any(not re.fullmatch(r"[a-f0-9]{64}", digest) for digest in self.files.values()):
            _fail("invalid_manifest")
        return self


def _token(raw):
    try:
        value = raw.decode("ascii")
    except UnicodeError:
        _fail("invalid_personal_token")
    if not 1 <= len(value) <= 4096 or any(ord(c) <= 32 or ord(c) >= 127 for c in value):
        _fail("invalid_personal_token")
    return value


def _ssh_material(descriptor, key, hosts):
    # No scripts, arbitrary config, ProxyCommand, wildcard/CA host trust or
    # source-machine paths. OpenSSH still performs actual key authentication.
    if (not key.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----\n")
            or not key.rstrip().endswith(b"-----END OPENSSH PRIVATE KEY-----") or len(key) > 16384):
        _fail("invalid_ssh_identity")
    expected = descriptor.host if descriptor.port == 22 else f"[{descriptor.host}]:{descriptor.port}"
    try:
        lines = hosts.decode("ascii").splitlines()
        if not lines:
            _fail("invalid_known_hosts")
        for line in lines:
            parts = line.split()
            if (len(parts) != 3 or parts[0] != expected or parts[1] not in {"ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"}
                    or not base64.b64decode(parts[2], validate=True)):
                _fail("invalid_known_hosts")
    except (UnicodeError, ValueError):
        _fail("invalid_known_hosts")


def _unpack(raw):
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_BUNDLE_BYTES:
        _fail("bundle_size")
    if not raw.startswith(b"PK\x03\x04") or len(raw) < 22 or raw[-22:-18] != b"PK\x05\x06" or raw[-2:] != b"\x00\x00":
        _fail("archive_entries")
    allowed = {"manifest.json", CONNECTION_FILE, TOKEN_FILE, KEY_FILE, HOSTS_FILE}
    try:
        with ZipFile(BytesIO(raw)) as archive:
            entries = archive.infolist()
            names = [item.filename for item in entries]
            if (not 3 <= len(entries) <= 5 or len(set(names)) != len(names)
                    or len({name.casefold() for name in names}) != len(names)
                    or set(names) - allowed):
                _fail("archive_entries")
            if sum(item.file_size for item in entries) > MAX_CONTENT_BYTES:
                _fail("bundle_size")
            files = {}
            for item in entries:
                mode = item.external_attr >> 16
                if (item.flag_bits & 1 or item.is_dir() or item.orig_filename != item.filename
                        or stat.S_IFMT(mode) not in {0, stat.S_IFREG}
                        or item.compress_type not in {0, ZIP_DEFLATED}):
                    _fail("archive_entries")
                with archive.open(item) as stream:
                    value = stream.read(MAX_CONTENT_BYTES + 1)
                if len(value) != item.file_size or len(value) > MAX_CONTENT_BYTES:
                    _fail("bundle_size")
                files[item.filename] = value
        manifest = BundleManifest.model_validate(_json(files.pop("manifest.json")))
        if set(manifest.files) != set(files) or any(_sha(value) != manifest.files[name] for name, value in files.items()):
            _fail("manifest_hash")
        descriptor = PortableConnection.model_validate(_json(files[CONNECTION_FILE]))
        expected = {CONNECTION_FILE, TOKEN_FILE} | ({KEY_FILE, HOSTS_FILE} if descriptor.ssh else set())
        if set(files) != expected:
            _fail("archive_entries")
        _token(files[TOKEN_FILE])
        if descriptor.ssh:
            _ssh_material(descriptor.ssh, files[KEY_FILE], files[HOSTS_FILE])
        return manifest, descriptor, files
    except ConnectionImportError:
        raise
    except (BadZipFile, KeyError, ValueError, TypeError, RuntimeError, OSError, NotImplementedError):
        _fail("invalid_bundle")


def build_bundle(*, center_id, center_name, owner_user_id, connection_descriptor,
                 personal_token, ssh_identity=None, known_hosts=None):
    """Return private ZIP bytes. Caller must store/distribute them privately."""
    try:
        descriptor = PortableConnection.model_validate(connection_descriptor)
        files = {CONNECTION_FILE: _raw(descriptor.model_dump(exclude_none=True)),
                 TOKEN_FILE: personal_token.encode("ascii")}
        _token(files[TOKEN_FILE])
        if descriptor.ssh:
            _ssh_material(descriptor.ssh, ssh_identity or b"", known_hosts or b"")
            files.update({KEY_FILE: ssh_identity, HOSTS_FILE: known_hosts})
        elif ssh_identity is not None or known_hosts is not None:
            _fail("archive_entries")
        manifest = BundleManifest(schema_version=1, kind=FORMAT, center_id=center_id, center_name=center_name,
                                  owner_user_id=owner_user_id, files={name: _sha(value) for name, value in files.items()})
        output = BytesIO()
        with ZipFile(output, "w", compression=ZIP_DEFLATED) as archive:
            archive.writestr("manifest.json", _raw(manifest.model_dump()))
            for name, value in files.items():
                archive.writestr(name, value)
        raw = output.getvalue()
        _unpack(raw)
        return raw
    except ConnectionImportError:
        raise
    except (ValidationError, UnicodeError, AttributeError, TypeError, ValueError, RuntimeError):
        _fail("invalid_build_input")


def _current_user_root(root):
    if os.name == "nt":
        literal = "'" + str(root).replace("'", "''") + "'"
        script = ("$ErrorActionPreference='Stop';$env:PSModulePath=(Join-Path $PSHOME 'Modules');"
                  "$who=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;"
                  "$acl=Get-Acl -LiteralPath " + literal + ";"
                  "($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq $who)|ConvertTo-Json -Compress")
        if connection._powershell(script) is not True:
            _fail("root_not_owned")
    elif root.stat().st_uid != os.getuid():
        _fail("root_not_owned")


def _root(broker):
    root = connection._path(Path(broker.root).absolute())
    storage._private_directory(root, create=False)
    _current_user_root(root)
    # Isolated Agent roots cannot change their parent's transport or identity.
    if (root / "agent-profile.json").exists():
        _fail("desktop_root_required")
    return root


def _directory(root, identifier):
    if not isinstance(identifier, str) or not re.fullmatch(r"[a-f0-9]{64}", identifier):
        _fail("invalid_identifier")
    directory = root / "connection-imports"
    storage._private_directory(directory)
    return directory / (identifier + ".dpapi")


def _save(root, state):
    path = _directory(root, state["import_id"])
    raw = credentials._crypt(_raw(state))
    if len(raw) > MAX_STATE_BYTES:
        _fail("journal_size")
    storage._check_private_file(path)
    before = storage._read_bytes(path, maximum=MAX_STATE_BYTES) if path.exists() else None
    storage._publish(path, raw, expected=before, maximum=MAX_STATE_BYTES)


def _load(root, identifier):
    path = _directory(root, identifier)
    if not path.exists():
        _fail("not_found")
    storage._check_private_file(path)
    try:
        state = _json(credentials._crypt(storage._read_bytes(path, maximum=MAX_STATE_BYTES), decrypt=True))
        if (state["schema_version"] != 1 or state["import_id"] != identifier
                or state["package_sha256"] != identifier or state["client_root"] != str(root)
                or state["owner_account"].casefold() != connection._owner().casefold()):
            _fail("owner_or_root_changed")
        # Revalidate the encrypted source as well as its exact original hash.
        package = base64.b64decode(state["package"], validate=True)
        if _sha(package) != identifier:
            _fail("journal_changed")
        manifest, descriptor, _ = _unpack(package)
        expected_preview = {"owner_user_id": manifest.owner_user_id, "center_name": manifest.center_name, "mode": descriptor.mode}
        if (state.get("preview") != expected_preview
                or state.get("state") not in {"awaiting_confirmation", "validating", "committing", "completed", "failed", "recovery_required"}
                or state.get("reason_code") is not None and state["reason_code"] not in IMPORT_REASON_CODES):
            _fail("invalid_journal")
        return state
    except ConnectionImportError:
        raise
    except (ValueError, KeyError, TypeError):
        _fail("invalid_journal")


def _present(state):
    result = {name: state[name] for name in ("import_id", "package_sha256", "state")}
    result["preview"] = {name: state["preview"][name] for name in ("owner_user_id", "center_name", "mode")}
    if state.get("reason_code"):
        result["reason_code"] = state["reason_code"]
    return deepcopy(result)


def preview_bundle(broker, raw):
    manifest, descriptor, _ = _unpack(raw)
    with broker.lock:
        root = _root(broker)
        identifier = _sha(raw)
        directory = _directory(root, identifier).parent
        with storage._exclusive(directory):
            if _directory(root, identifier).exists():
                return _present(_load(root, identifier))
            state = {"schema_version": 1, "import_id": identifier, "package_sha256": identifier,
                     "state": "awaiting_confirmation", "client_root": str(root), "owner_account": connection._owner(),
                     "package": base64.b64encode(raw).decode("ascii"),
                     "preview": {"owner_user_id": manifest.owner_user_id, "center_name": manifest.center_name,
                                 "mode": descriptor.mode}}
            _save(root, state)
            return _present(state)


def read_import(broker, import_id):
    with broker.lock:
        return _present(_load(_root(broker), import_id))


def pending_import(broker):
    """Return only the latest unfinished import's secret-free status, or None.

    A doctor may supply OpenSSH Client only for state=failed and reason_code=
    member_connection_import_ssh_prerequisite_required, then call confirm_import
    with that exact import_id. Awaiting-confirmation packages remain unapproved.
    A later completed import supersedes every earlier failed attempt.
    """
    with broker.lock:
        root = _root(broker)
        directory = root / "connection-imports"
        storage._unlinked(directory)
        if not directory.exists():
            return None
        storage._private_directory(directory, create=False)
        with storage._exclusive(directory):
            candidates = []
            for path in directory.glob("*.dpapi"):
                if re.fullmatch(r"[a-f0-9]{64}", path.stem):
                    storage._check_private_file(path)
                    candidates.append((path.stat().st_mtime_ns, path.stem))
            if not candidates:
                return None
            state = _load(root, max(candidates)[1])
            return None if state["state"] == "completed" else _present(state)


def _anchor(spec):
    if spec.mode == "https":
        return ("https", connection.https_center(spec.https_url).lower())
    if spec.ssh:
        ssh = spec.ssh
        ssh.known_hosts.verify(private=True)
        ssh.identity.verify(private=True)
        return ("managed-ssh", ssh.host.lower(), ssh.user, ssh.port, ssh.center_port, ssh.known_hosts.sha256)
    _fail("existing_trust_unselected")


def _candidate_anchor(descriptor, files):
    if descriptor.mode == "https":
        return ("https", descriptor.https_url.lower())
    ssh = descriptor.ssh
    return ("managed-ssh", ssh.host.lower(), ssh.user, ssh.port, ssh.center_port, _sha(files[HOSTS_FILE]))


def _check_identity(broker, old, manifest, descriptor, files):
    if old:
        spec, _ = old
        if spec.owner_user_id != manifest.owner_user_id:
            _fail("different_member")
        if spec.center_id and spec.center_id != manifest.center_id:
            _fail("different_center")
        if _anchor(spec) != _candidate_anchor(descriptor, files):
            _fail("center_trust_changed")
    login = broker.login
    if login:
        actor = (login.get("actor") or broker.actor or {}).get("actor_id")
        if actor != manifest.owner_user_id:
            _fail("different_member")
        valid = ({connection.reference(*old)} if old else set())
        if descriptor.mode == "https":
            valid.add(descriptor.https_url)
        if login.get("center_url") not in valid:
            _fail("different_center")


def _system_ssh():
    # Portable bundles cannot nominate an executable. Use Windows' fixed
    # optional component and pin its current bytes before creating a channel.
    if os.name != "nt":
        _fail("ssh_prerequisite_required")
    import ctypes
    buffer = ctypes.create_unicode_buffer(32768)
    count = ctypes.windll.kernel32.GetSystemDirectoryW(buffer, len(buffer))
    path = Path(buffer.value) / "OpenSSH/ssh.exe"
    if not 0 < count < len(buffer) or not path.is_file():
        _fail("ssh_prerequisite_required")
    return {"path": str(path), "sha256": connection._digest(path)}


def _publish_exact(path, raw):
    storage._check_private_file(path)
    if path.exists():
        if storage._read_bytes(path, maximum=MAX_STATE_BYTES) != raw:
            _fail("staged_file_changed")
    else:
        storage._publish(path, raw, maximum=MAX_STATE_BYTES)


def _stage(root, state, old, manifest, descriptor, files):
    directory = root / "connection-imports" / state["import_id"]
    storage._private_directory(directory)
    selected = state.get("staged_spec")
    if selected:
        _publish_exact(directory / connection.SPEC_NAME, _raw(selected))
        staged, digest = connection.load_spec(directory)
        return directory, staged, digest
    values = {"schema_version": 1, "connection_id": old[0].connection_id if old else str(uuid4()),
              "client_root": str(directory), "machine_id": old[0].machine_id if old else None,
              "owner_user_id": manifest.owner_user_id, "owner_account": connection._owner(),
              "center_id": manifest.center_id, "center_name": manifest.center_name, "mode": descriptor.mode}
    if descriptor.ssh:
        channel = descriptor.ssh.model_dump()
        channel["isolated_config"] = True
        channel["executable"] = _system_ssh()
        for field, filename in (("identity", KEY_FILE), ("known_hosts", HOSTS_FILE)):
            _publish_exact(directory / filename, files[filename])
            channel[field] = {"path": str(directory / filename), "sha256": _sha(files[filename])}
        # A known, still-owned old channel may keep serving until commit. Its
        # replacement is staged on a distinct loopback port without touching it.
        receipt = root / "connection-process.json"
        if old and old[0].ssh and channel["upstream_port"] == old[0].ssh.upstream_port and receipt.exists():
            pin = _private_json(receipt)
            old_pin = {k: v for k, v in pin.items() if k != "spec_sha256"}
            if pin.get("spec_sha256") != old[1] or pin.get("command") != connection._ssh_command(old[0].ssh):
                _fail("existing_channel_changed")
            if connection._same_process(old_pin, missing_ok=True):
                with socket.socket() as listener:
                    listener.bind(("127.0.0.1", 0))
                    channel["upstream_port"] = listener.getsockname()[1]
        values["ssh"] = channel
    else:
        values["https_url"] = descriptor.https_url
    staged = connection.ConnectionSpec.model_validate(values)
    state["staged_spec"] = staged.model_dump(exclude_none=True)
    if staged.ssh:
        # Capture the already validated argv in the encrypted journal. Cleanup
        # can still identify our process if a pinned file changes afterwards.
        state["staged_command"] = connection._ssh_command(staged.ssh)
    # Persist the exact key paths, executable pin and selected port first.
    _save(root, state)
    _publish_exact(directory / connection.SPEC_NAME, _raw(state["staged_spec"]))
    return directory, *connection.load_spec(directory)


def _private_json(path):
    storage._check_private_file(path)
    return _json(storage._read_bytes(path, maximum=MAX_MIGRATION_BYTES))


def _change(changes, root, path, after):
    path = connection._path(path)
    if not path.is_relative_to(root):
        _fail("migration_root_changed")
    storage._check_private_file(path)
    before = storage._read_bytes(path, maximum=MAX_MIGRATION_BYTES) if path.exists() else None
    if before == after:
        return
    changes.append({"path": str(path.relative_to(root)),
                    "before": base64.b64encode(before).decode() if before is not None else None,
                    "after": base64.b64encode(after).decode()})


def _migrations(broker, old_reference, new_reference, owner):
    """Rewrite only local bindings, retaining IDs, request hashes and phases."""
    root, changes = broker.root, []
    if old_reference == new_reference:
        return changes
    roots = [root]
    agents = root / "agents"
    storage._unlinked(agents)
    for path in sorted(agents.glob("*/agent-profile.json")):
        _canonical_uuid(path.parent.name)
        storage._private_directory(path.parent, create=False)
        profile = _private_json(path)
        if profile.get("center_url") != old_reference or profile.get("actor_id") != owner:
            continue
        profile["center_url"] = new_reference
        _change(changes, root, path, _raw(profile))
        store = credentials.PersonalCredentialStore(path.parent / "credentials")
        login = store.load()
        if login:
            if (login.get("center_url") != old_reference or (login.get("actor") or {}).get("actor_id") != owner
                    or _sha(login["token"].encode()) != profile.get("credential_fingerprint")):
                _fail("agent_binding_changed")
            login["center_url"] = new_reference
            registration = (login.get("actor") or {}).get("agent_registration")
            if registration:
                if registration.get("center_url") != old_reference or registration.get("agent_id") != profile.get("agent_id"):
                    _fail("agent_binding_changed")
                registration["center_url"] = new_reference
            _change(changes, root, store.path, credentials._crypt(_raw(login)))
        roots.append(path.parent)
    for member_root in roots:
        operations = member_root / "operations"
        storage._unlinked(operations)
        for path in sorted(operations.glob("*.json")):
            value = _private_json(path)
            if value.get("center_url") == old_reference and value.get("actor_id") == owner:
                value["center_url"] = new_reference
                _change(changes, root, path, _raw(value))
    return changes


def _migrate_handoff(changes, root, old, final_digest):
    """A completed handoff keeps its exact process/task proof across updates."""
    if not old or not old[0].legacy:
        return
    receipt = root / "legacy-console-handoff.json"
    if not receipt.exists():
        return
    value = _private_json(receipt)
    if value.get("spec_sha256") != old[1] or value.get("completed") is not True:
        _fail("legacy_handoff_pending_or_changed")
    value["spec_sha256"] = final_digest
    _change(changes, root, receipt, _raw(value))
    preview = root / "legacy-console-preview.json"
    if preview.exists():
        value = _private_json(preview)
        if value.get("spec_sha256") == old[1]:
            value["spec_sha256"] = final_digest
            _change(changes, root, preview, _raw(value))


def _file_apply(root, change, *, rollback=False):
    path = connection._path(root / change["path"])
    if not path.is_relative_to(root) or ".." in Path(change["path"]).parts:
        _fail("migration_root_changed")
    before = base64.b64decode(change["before"]) if change["before"] is not None else None
    after = base64.b64decode(change["after"])
    expected, desired = (after, before) if rollback else (before, after)
    storage._check_private_file(path)
    current = storage._read_bytes(path, maximum=MAX_MIGRATION_BYTES) if path.exists() else None
    if current == desired:
        return
    if current != expected:
        _fail("local_state_changed")
    if desired is None:
        path.unlink()
    elif len(desired) > MAX_STATE_BYTES:
        _publish_large_journal(path, desired, expected=current)
    else:
        storage._publish(path, desired, expected=current, maximum=MAX_STATE_BYTES)


def _publish_large_journal(path, raw, *, expected):
    if len(raw) > MAX_MIGRATION_BYTES:
        _fail("migration_size")
    descriptor, name = tempfile.mkstemp(prefix=".connection-migrate-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        storage._check_private_file(path)
        if storage._read_bytes(path, maximum=MAX_MIGRATION_BYTES) != expected:
            _fail("local_state_changed")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _stop_channel(pin):
    process = connection._same_process({k: v for k, v in pin.items() if k != "spec_sha256"}, missing_ok=True)
    if process:
        if process.children(recursive=False):
            _fail("channel_children_changed")
        process.terminate()
        process.wait(timeout=10)


def _stop_failed_stage(root, state):
    directory = root / "connection-imports" / state["import_id"]
    path = directory / "connection-process.json"
    if path.exists() and state.get("staged_spec", {}).get("ssh"):
        pin = _private_json(path)
        if pin.get("spec_sha256") != _sha(_raw(state["staged_spec"])) or pin.get("command") != state.get("staged_command"):
            _fail("staged_channel_changed")
        _stop_channel(pin)


def _retire_previous_channel(changes):
    for change in changes:
        if change["path"] == "connection-process.json" and change["before"]:
            before = _json(base64.b64decode(change["before"]))
            after = _json(base64.b64decode(change["after"]))
            if (before["pid"], before["birth"]) != (after["pid"], after["birth"]):
                _stop_channel(before)


def _persist_changes(root, state, changes):
    """Keep large operation histories out of the small import receipt."""
    if len(changes) > MAX_MIGRATION_FILES:
        _fail("migration_size")
    directory = root / "connection-imports" / state["import_id"] / "transaction"
    storage._private_directory(directory)
    checksum, total = hashlib.sha256(), 0
    for index, change in enumerate(changes):
        raw = _raw(change)
        total += len(raw)
        if total > MAX_MIGRATION_BYTES:
            _fail("migration_size")
        checksum.update(_sha(raw).encode())
        count = (len(raw) + MIGRATION_CHUNK_BYTES - 1) // MIGRATION_CHUNK_BYTES
        for chunk in range(count):
            part = raw[chunk * MIGRATION_CHUNK_BYTES:(chunk + 1) * MIGRATION_CHUNK_BYTES]
            _publish_encrypted_exact(directory / f"{index}.{chunk}.dpapi", part)
        metadata = {"chunk_count": count, "raw_sha256": _sha(raw), "raw_bytes": len(raw)}
        _publish_encrypted_exact(directory / f"{index}.index.dpapi", _raw(metadata))
    return {"change_count": len(changes), "changes_sha256": checksum.hexdigest()}


def _publish_encrypted_exact(path, raw):
    storage._check_private_file(path)
    if path.exists():
        existing = credentials._crypt(storage._read_bytes(path, maximum=MAX_STATE_BYTES), decrypt=True)
        if existing != raw:
            _fail("migration_journal_changed")
    else:
        storage._publish(path, credentials._crypt(raw), maximum=MAX_STATE_BYTES)


def _load_changes(root, state):
    transaction = state["transaction"]
    count = transaction["change_count"]
    if type(count) is not int or not 0 <= count <= MAX_MIGRATION_FILES:
        _fail("migration_size")
    directory = root / "connection-imports" / state["import_id"] / "transaction"
    storage._private_directory(directory, create=False)
    changes, checksum, total = [], hashlib.sha256(), 0
    for index in range(count):
        path = directory / f"{index}.index.dpapi"
        storage._check_private_file(path)
        metadata = _json(credentials._crypt(storage._read_bytes(path, maximum=MAX_STATE_BYTES), decrypt=True))
        chunks = metadata["chunk_count"]
        if type(chunks) is not int or not 1 <= chunks <= MAX_MIGRATION_BYTES // MIGRATION_CHUNK_BYTES + 1:
            _fail("migration_size")
        parts = []
        for chunk in range(chunks):
            path = directory / f"{index}.{chunk}.dpapi"
            storage._check_private_file(path)
            part = credentials._crypt(storage._read_bytes(path, maximum=MAX_STATE_BYTES), decrypt=True)
            if not 1 <= len(part) <= MIGRATION_CHUNK_BYTES:
                _fail("migration_size")
            parts.append(part)
        raw = b"".join(parts)
        total += len(raw)
        if total > MAX_MIGRATION_BYTES:
            _fail("migration_size")
        if metadata["raw_bytes"] != len(raw) or metadata["raw_sha256"] != _sha(raw):
            _fail("migration_journal_changed")
        checksum.update(_sha(raw).encode())
        changes.append(_json(raw))
    if checksum.hexdigest() != transaction["changes_sha256"]:
        _fail("migration_journal_changed")
    return changes


def _commit(broker, root, state):
    transaction = state["transaction"]
    changes = _load_changes(root, state)
    try:
        for change in changes:
            _file_apply(root, change)
        broker.credentials.save(**transaction["login"])
    except Exception:
        # Normal failures restore the previous usable login and descriptor.
        # A process crash resumes the durable CAS transaction instead.
        rollback_failed = False
        for change in reversed(changes):
            try:
                _file_apply(root, change, rollback=True)
            except Exception:
                # Never overwrite an independent edit; still restore every
                # other file that retains this transaction's exact bytes.
                rollback_failed = True
        if transaction["prior_login"]:
            broker.credentials.save(**transaction["prior_login"])
        else:
            broker.credentials.clear()
        if rollback_failed:
            state["state"] = "recovery_required"
            state["reason_code"] = "member_connection_import_local_state_changed"
            _save(root, state)
            _fail("local_state_changed")
        try:
            _stop_failed_stage(root, state)
        except Exception:
            pass
        state["state"] = "failed"
        state["reason_code"] = "member_connection_import_commit_failed"
        _save(root, state)
        _fail("commit_failed")
    login = deepcopy(transaction["login"])
    broker.login, broker.actor = login, login["actor"]
    broker.auth_generation += 1
    broker.online, broker.connection_error = True, None
    state["state"] = "completed"
    state.pop("reason_code", None)
    _save(root, state)
    # The new endpoint and login are durable before the former owned channel
    # is retired. A changed PID/command can never be signalled by this step.
    try:
        _retire_previous_channel(changes)
    except Exception:
        # A cleanup failure cannot roll back an already completed login.
        pass
    return _present(state)


def confirm_import(broker, import_id):
    """Verify /v1/me on a staged connection, then commit local bindings only.

    There are no enrollment, machine policy, submission, or compute API calls.
    Failed probes leave the original connection and credentials untouched.
    """
    with broker.lock:
        root = _root(broker)
        with storage._exclusive(_directory(root, import_id).parent):
            state = _load(root, import_id)
            if state["state"] == "completed":
                try:
                    _retire_previous_channel(_load_changes(root, state))
                except Exception:
                    pass
                return _present(state)
            if broker.busy:
                _fail("operations_busy")
            if state["state"] == "committing":
                return _commit(broker, root, state)
            if state["state"] == "recovery_required":
                _fail("local_state_changed")
            manifest, descriptor, files = _unpack(base64.b64decode(state["package"]))
            try:
                old = connection.load_spec(root)
                _check_identity(broker, old, manifest, descriptor, files)
                state["state"] = "validating"
                state.pop("reason_code", None)
                _save(root, state)
                directory, staged, digest = _stage(root, state, old, manifest, descriptor, files)
                endpoint = connection.resolve_center(directory, connection.reference(staged, digest))
                from .member_client import member_api_client, _member_api_for_endpoint
                token = _token(files[TOKEN_FILE])
                api = (_member_api_for_endpoint(endpoint, token) if broker.api_factory is member_api_client
                       else broker.api_factory(endpoint, token=token))
                actor = api.current_actor()
                roles = set(actor.get("roles", [])) if isinstance(actor, dict) else set()
                if (not isinstance(actor, dict) or actor.get("actor_id") != manifest.owner_user_id
                        or "member" not in roles or "admin" in roles or "agent" in actor.get("scopes", [])):
                    _fail("personal_identity_mismatch")
                # Recheck mutable pins and descriptor after the network response.
                fresh = connection.load_spec(root)
                if (fresh[1] if fresh else None) != (old[1] if old else None):
                    _fail("existing_connection_changed")
                if connection.load_spec(directory)[1] != digest:
                    _fail("staged_file_changed")
                connection.resolve_center(directory, connection.reference(staged, digest), start=False)
                final = staged.model_copy(update={"client_root": str(root), "legacy": old[0].legacy if old else None})
                final_raw = _raw(final.model_dump(exclude_none=True))
                new_reference = connection.reference(final, _sha(final_raw))
                old_reference = broker.login["center_url"] if broker.login else (connection.reference(*old) if old else None)
                changes = _migrations(broker, old_reference, new_reference, manifest.owner_user_id)
                _migrate_handoff(changes, root, old, _sha(final_raw))
                _change(changes, root, root / connection.SPEC_NAME, final_raw)
                stage_process = directory / "connection-process.json"
                if staged.ssh and stage_process.exists():
                    pin = _private_json(stage_process)
                    if pin.get("spec_sha256") != digest or pin.get("command") != connection._ssh_command(staged.ssh):
                        _fail("staged_channel_changed")
                    connection._same_process({k: v for k, v in pin.items() if k != "spec_sha256"})
                    pin["spec_sha256"] = _sha(final_raw)
                    _change(changes, root, root / "connection-process.json", _raw(pin))
                prior = {k: broker.login[k] for k in ("center_url", "token", "actor") if k in broker.login} if broker.login else None
                change_receipt = _persist_changes(root, state, changes)
                state["transaction"] = {**change_receipt, "prior_login": prior,
                                        "login": {"center_url": new_reference, "token": token, "actor": actor}}
                state["state"] = "committing"
                _save(root, state)
            except Exception as exc:
                code = _failure_code(exc)
                try:
                    _stop_failed_stage(root, state)
                except Exception:
                    # Preserve the actual failed validation; never guess which
                    # process to stop when its ownership proof has changed.
                    pass
                state["state"], state["reason_code"] = "failed", code
                _save(root, state)
                if isinstance(exc, ConnectionImportError):
                    raise
                raise ConnectionImportError(code) from None
            return _commit(broker, root, state)


def main(argv=None):
    """Private admin-side build CLI; never accepts a token as argv."""
    parser = argparse.ArgumentParser(description="Build a PRIVATE data-only RCN member connection ZIP")
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build")
    build.add_argument("--descriptor-file", type=Path, required=True,
                       help="JSON: center_id, center_name, owner_user_id, connection_descriptor")
    source = build.add_mutually_exclusive_group(required=True)
    source.add_argument("--token-file", type=Path, help="Owner-private ASCII token file")
    source.add_argument("--token-env", help="Name of environment variable containing the personal token")
    build.add_argument("--ssh-identity-file", type=Path)
    build.add_argument("--known-hosts-file", type=Path)
    build.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        def private_read(path, maximum=65536):
            path = connection._path(path.absolute())
            storage._check_private_file(path)
            return storage._read_bytes(path, maximum=maximum)
        descriptor = _json(private_read(args.descriptor_file))
        if set(descriptor) != {"center_id", "center_name", "owner_user_id", "connection_descriptor"}:
            _fail("invalid_build_input")
        token = private_read(args.token_file, 4096).decode("ascii").strip() if args.token_file else os.environ.get(args.token_env, "")
        raw = build_bundle(**descriptor, personal_token=token,
                           ssh_identity=private_read(args.ssh_identity_file) if args.ssh_identity_file else None,
                           known_hosts=private_read(args.known_hosts_file) if args.known_hosts_file else None)
        target = connection._path(args.output.absolute())
        storage._private_directory(target.parent, create=False)
        storage._publish(target, raw, maximum=MAX_STATE_BYTES)
        print(json.dumps({"state": "built", "package_sha256": _sha(raw), "private": True}))
        return 0
    except Exception:
        # Pydantic, ZIP and OS errors can contain credential inputs or paths.
        print(json.dumps({"state": "failed", "reason_code": "member_connection_bundle_build_failed"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
