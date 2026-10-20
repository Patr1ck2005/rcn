"""Native OpenSSH device-key operations; no shell, agent, network or host mutation."""
from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

NAMESPACE = 'rcn-member-transport-v1'
TRANSPORT_PATH = '/v1/member-enrollment/transport-identity'


class SshIdentityError(RuntimeError):
    """A bounded diagnostic; native stderr and private bytes must not escape."""


def public_key(value: str) -> str:
    """Exactly one canonical Ed25519 key, without options, comments or certificates."""
    if not isinstance(value, str) or not re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/]{68}', value):
        raise ValueError('invalid_transport_public_key')
    blob = base64.b64decode(value.split(' ')[1], validate=True)
    if len(blob) != 51 or blob[:19] != b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20':
        raise ValueError('invalid_transport_public_key')
    if base64.b64encode(blob).decode('ascii') != value.split(' ')[1]:
        raise ValueError('noncanonical_transport_public_key')
    return value


def fingerprint(value: str) -> str:
    blob = base64.b64decode(public_key(value).split(' ')[1])
    return 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode('ascii').rstrip('=')


def signature_text(value: str) -> str:
    if not isinstance(value, str) or len(value) > 8192:
        raise ValueError('invalid_transport_signature')
    normalized = value.replace('\r\n', '\n')
    if not re.fullmatch(r'-----BEGIN SSH SIGNATURE-----\n[A-Za-z0-9+/=\n]+\n-----END SSH SIGNATURE-----\n', normalized):
        raise ValueError('invalid_transport_signature')
    return normalized


def executable() -> str:
    # No automatic installation or fallback to a downloaded executable.
    if os.name == 'nt':
        path = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32' / 'OpenSSH' / 'ssh-keygen.exe'
        found = str(path) if path.is_file() else None
    else:
        found = shutil.which('ssh-keygen')
    if not found:
        raise SshIdentityError('ssh_identity_tool_unavailable')
    return found


def _run(args: list[str], data: bytes = b'') -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if k.upper() not in {
        'SSH_AUTH_SOCK', 'SSH_AGENT_PID', 'SSH_ASKPASS', 'SSH_ASKPASS_REQUIRE', 'DISPLAY',
    }}
    env['SSH_ASKPASS_REQUIRE'] = 'never'
    try:
        result = subprocess.run([executable(), *args], input=data, capture_output=True,
                                timeout=10, check=False, env=env)
    except (OSError, subprocess.TimeoutExpired):
        raise SshIdentityError('ssh_identity_tool_unavailable') from None
    if len(result.stdout) > 16384 or len(result.stderr) > 16384:
        raise SshIdentityError('ssh_identity_output_invalid')
    return result


def generate(path: Path) -> None:
    if path.exists() or path.with_name(path.name + '.pub').exists():
        raise SshIdentityError('ssh_identity_already_exists')
    result = _run(['-q', '-t', 'ed25519', '-N', '', '-C', NAMESPACE, '-f', str(path)])
    if result.returncode != 0:
        raise SshIdentityError('ssh_identity_generation_failed')


def derive_public(path: Path) -> str:
    result = _run(['-y', '-P', '', '-f', str(path)])
    if result.returncode != 0:
        raise SshIdentityError('ssh_identity_private_key_unusable')
    try:
        parts = result.stdout.decode('ascii').strip().split(' ')
        return public_key(' '.join(parts[:2]))
    except (ValueError, UnicodeError):
        raise SshIdentityError('ssh_identity_public_key_invalid') from None


def sign(path: Path, statement: bytes) -> str:
    result = _run(['-Y', 'sign', '-n', NAMESPACE, '-f', str(path)], statement)
    if result.returncode != 0:
        raise SshIdentityError('ssh_identity_signing_failed')
    try:
        return signature_text(result.stdout.decode('ascii'))
    except (ValueError, UnicodeError):
        raise SshIdentityError('ssh_identity_signature_invalid') from None


def verify(value: str, signature: str, statement: bytes, *, scratch_root: Path) -> bool:
    key, proof = public_key(value), signature_text(signature)
    executable()  # Fail before creating proof work files when native support is absent.
    from .member_registration import _private_directory
    from .member_registration import MemberRegistrationError
    try:
        _private_directory(scratch_root)
    except (MemberRegistrationError, OSError, subprocess.SubprocessError):
        raise SshIdentityError('ssh_identity_verifier_storage_unavailable') from None
    with tempfile.TemporaryDirectory(prefix='transport-proof-', dir=scratch_root) as temporary:
        root = Path(temporary)
        allowed, signed = root / 'allowed-signers', root / 'proof.sig'
        allowed.write_text('rcn-device namespaces="' + NAMESPACE + '" ' + key + '\n', encoding='ascii')
        signed.write_text(proof, encoding='ascii')
        result = _run(['-Y', 'verify', '-f', str(allowed), '-I', 'rcn-device',
                       '-n', NAMESPACE, '-s', str(signed)], statement)
    # OpenSSH for Windows returns unsigned -1 (4294967295) for invalid
    # signatures. It is a rejection, never a successful proof or auto-retry grant.
    if result.returncode not in {0, 1, 255, 4294967295}:
        raise SshIdentityError('ssh_identity_verifier_failed')
    return result.returncode == 0
