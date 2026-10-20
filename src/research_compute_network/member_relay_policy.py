"""Operator-owned Windows SSH relay policy; never inferred from a member request.

One dedicated account/configuration is approved during the deployment gate.
This module checks its effective restrictions, not whether that daemon is live.
No account, system config, firewall rule, service, or host private key is changed.
"""
from __future__ import annotations

import hashlib
import ipaddress
import os
from pathlib import Path
import re
import subprocess
from typing import Literal

from pydantic import Field, field_validator

from . import member_registration as storage, ssh_identity
from .member_enrollment import StrictModel, https_origin

POLICY_FILE = 'policy.json'
KEYS_FILE = 'authorized_keys'
CONFIG_FILE = 'sshd_config'
LEASE_SECONDS = 300
RENEW_SECONDS = 60


class RelayUnavailable(RuntimeError):
    """Bounded diagnostics: never include native stderr or configuration contents."""


class RelayPolicy(StrictModel):
    schema_version: Literal[1] = 1
    endpoint_id: str = Field(pattern=r'^[a-z0-9][a-z0-9-]{0,47}$')
    registration_origin: str
    coordinator_host: str
    coordinator_port: int = Field(strict=True, ge=1, le=65535)
    coordinator_user: str = Field(pattern=r'^rcn_[a-z0-9_]{1,27}$')
    account_sid: str = Field(pattern=r'^S-1-5-21-(?:[0-9]+-){3}[0-9]+$')
    host_public_key: str
    listener_ports: list[int] = Field(min_length=1, max_length=128)
    # Operator approval, NOT a machine's claim to be healthy or accepted.
    deployment_approval_id: str = Field(pattern=r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,159}$')
    server_config_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    admission_enabled: bool = Field(default=False, strict=True)
    _origin = field_validator('registration_origin')(https_origin)
    _key = field_validator('host_public_key')(ssh_identity.public_key)

    @field_validator('coordinator_host')
    @classmethod
    def host(cls, value: str) -> str:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?', value):
                raise ValueError('invalid_relay_host') from None
        else:
            if address.is_unspecified or address.is_multicast:
                raise ValueError('invalid_relay_host')
        return value

    @field_validator('listener_ports', mode='before')
    @classmethod
    def ports(cls, value):
        if (not isinstance(value, list) or not value or any(type(p) is not int or not 1024 <= p <= 65535 for p in value)
                or value != sorted(set(value))):
            raise ValueError('relay_ports_must_be_sorted_unique_unprivileged_integers')
        return value

    def digest(self) -> str:
        # Closing admissions must not change previously reserved port identities.
        return hashlib.sha256(storage._json_bytes(self.model_dump(mode='json', exclude={'admission_enabled'}))).hexdigest()


def keyfile_path(root: Path) -> str:
    return str(Path(root).absolute() / KEYS_FILE).replace('\\', '/')


def render_server_config(*, username: str, listener_ports: list[int], authorization_root: Path,
                         host_key_file: Path, ssh_port: int, listen_address: str) -> str:
    """Dedicated server configuration, never an addition to an unreviewed Match block."""
    if not re.fullmatch(r'rcn_[a-z0-9_]{1,27}', username):
        raise ValueError('dedicated_relay_account_required')
    RelayPolicy.ports(listener_ports)
    address = ipaddress.ip_address(listen_address)
    if address.is_multicast or type(ssh_port) is not int or not 1 <= ssh_port <= 65535:
        raise ValueError('invalid_relay_listener')
    def quoted(path):
        value = str(Path(path).absolute()).replace('\\', '/')
        if any(ord(c) < 32 for c in value) or any(c in value for c in '\"%'):
            raise ValueError('unsafe_relay_config_path')
        return '"' + value + '"'
    return '\n'.join([
        '# Dedicated RCN member relay. Deploy only through the maintenance gate.',
        f'Port {ssh_port}', f'ListenAddress {address}', f'HostKey {quoted(host_key_file)}',
        f'AllowUsers {username}', f'AuthorizedKeysFile {quoted(Path(authorization_root) / KEYS_FILE)}',
        'AuthenticationMethods publickey', 'PubkeyAuthentication yes',
        'PubkeyAcceptedAlgorithms ssh-ed25519', 'PasswordAuthentication no',
        'AllowAgentForwarding no', 'AllowTcpForwarding remote', 'GatewayPorts no',
        'PermitOpen none', 'PermitListen ' + ' '.join(f'localhost:{p}' for p in listener_ports),
        'MaxSessions 0', 'PermitTTY no', 'ClientAliveInterval 15', 'ClientAliveCountMax 3',
        'LoginGraceTime 15', 'MaxAuthTries 3', 'LogLevel VERBOSE', '',
    ])


def verify_effective_policy(policy: RelayPolicy, root: Path) -> None:
    """Native -T only; no listener or account login. Check two unrelated sources."""
    if os.name != 'nt':
        raise RelayUnavailable('member_relay_requires_windows')
    daemon = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32/OpenSSH/sshd.exe'
    expected = {'allowusers': policy.coordinator_user, 'authenticationmethods': 'publickey',
        'pubkeyauthentication': 'yes', 'passwordauthentication': 'no',
        'pubkeyacceptedalgorithms': 'ssh-ed25519', 'allowagentforwarding': 'no',
        'allowtcpforwarding': 'remote', 'gatewayports': 'no', 'permitopen': 'none',
        'maxsessions': '0', 'permittty': 'no', 'clientaliveinterval': '15', 'clientalivecountmax': '3'}
    try:
        for source in ('192.0.2.11', '198.51.100.17'):
            result = subprocess.run([str(daemon), '-T', '-f', str(root / CONFIG_FILE), '-C',
                f'user={policy.coordinator_user},host=member.invalid,addr={source}'],
                capture_output=True, timeout=10, check=False)
            if result.returncode or len(result.stdout) > 65536 or len(result.stderr) > 65536:
                raise RelayUnavailable('relay_server_policy_verification_failed')
            entries = [line.split(' ', 1) for line in result.stdout.decode('utf-8').splitlines() if ' ' in line]
            effective = dict(entries)
            if (len(effective) != len(entries) or any(effective.get(name) != value for name, value in expected.items())
                    or effective.get('authorizedkeysfile', '').rstrip().strip('"').replace('\\', '/').casefold() != keyfile_path(root).casefold()
                    or set(effective.get('permitlisten', '').split()) != {f'localhost:{p}' for p in policy.listener_ports}
                    or effective.get('disableforwarding', 'no') != 'no'):
                raise RelayUnavailable('relay_server_policy_not_restricted')
    except (OSError, subprocess.SubprocessError, UnicodeError):
        raise RelayUnavailable('relay_server_policy_verifier_unavailable') from None


def verify_publisher_identity() -> None:
    """SYSTEM creates files with an owner accepted by Windows OpenSSH.

    A merely unelevated admin account is NOT equivalent. Do not silently fix an
    existing file's owner, grant the relay account write access, or elevate here.
    The center deployment gate must select the proper service identity once.
    """
    if os.name != 'nt':
        raise RelayUnavailable('member_relay_requires_windows')
    try:
        result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command',
            '[Console]::Out.Write([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)'],
            capture_output=True, timeout=10, check=False)
        if result.returncode or result.stdout.strip() != b'S-1-5-18':
            raise RelayUnavailable('relay_publisher_requires_system_service')
    except (OSError, subprocess.SubprocessError):
        raise RelayUnavailable('relay_publisher_identity_unavailable') from None


def verify_account(policy: RelayPolicy) -> None:
    """Only an existing enabled nonadministrator LOCAL account, pinned by SID."""
    script = r'''$ErrorActionPreference='Stop'
$user=Get-LocalUser -SID '__SID__'
$administrators=@(Get-LocalGroupMember -SID 'S-1-5-32-544')
[pscustomobject]@{name=$user.Name.ToLowerInvariant();sid=$user.SID.Value;enabled=[bool]$user.Enabled;administrator=([bool]($administrators|Where-Object {$_.SID.Value -eq $user.SID.Value}))}|ConvertTo-Json -Compress
'''.replace('__SID__', policy.account_sid)
    try:
        result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
            capture_output=True, timeout=10, check=False)
        if result.returncode or len(result.stdout) > 4096:
            raise ValueError('account unavailable')
        value = storage._json_document(result.stdout)
        if (value.get('name') != policy.coordinator_user or value.get('sid') != policy.account_sid
                or value.get('enabled') is not True or value.get('administrator') is not False):
            raise ValueError('unsafe account')
    except (OSError, ValueError, subprocess.SubprocessError):
        raise RelayUnavailable('relay_requires_existing_nonadmin_account') from None


def load_policy(root: Path, *, require_enabled: bool = True) -> RelayPolicy:
    """Missing deployment configuration disables relay, not existing enrollment."""
    try:
        verify_publisher_identity()
        storage._private_directory(root, create=False)
        for name in (POLICY_FILE, CONFIG_FILE):
            storage._check_private_file(root / name)
        raw = storage._read_bytes(root / POLICY_FILE)
        value = storage._json_document(raw)
        if type(value.get('schema_version')) is not int or value['schema_version'] != 1:
            raise ValueError('invalid schema')
        policy = RelayPolicy.model_validate(value)
        config = storage._read_bytes(root / CONFIG_FILE, maximum=65536)
        # The dedicated relay cannot inherit unknown per-source/account overrides.
        # A bounded -T sample alone would not prove safety of arbitrary Match blocks.
        if re.search(r'^\s*(?:Match|Include)\s', config.decode('utf-8-sig'), re.I | re.M):
            raise RelayUnavailable('relay_dedicated_config_cannot_include_or_match')
        if hashlib.sha256(config).hexdigest() != policy.server_config_sha256:
            raise RelayUnavailable('relay_server_configuration_changed')
        if require_enabled and not policy.admission_enabled:
            raise RelayUnavailable('member_relay_not_enabled')
        verify_account(policy)
        verify_effective_policy(policy, root)
        if (storage._read_bytes(root / POLICY_FILE) != raw
                or storage._read_bytes(root / CONFIG_FILE, maximum=65536) != config):
            raise RelayUnavailable('relay_policy_changed_during_verification')
        return policy
    except (OSError, ValueError, storage.MemberRegistrationError, subprocess.SubprocessError):
        raise RelayUnavailable('member_relay_deployment_required') from None
