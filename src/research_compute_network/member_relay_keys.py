"""Bounded, recoverable publication to ONE dedicated SSH authorized-key file.

Not an append operation on the host's normal authorized_keys. The deployment
policy and native effective restrictions must already be operator-approved.
Only new-connection authority is leased; existing SSH sessions are not revoked
by removing a key and are never reported as terminated by this component.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import re

from . import member_registration as storage
from .member_relay_policy import CONFIG_FILE, KEYS_FILE, LEASE_SECONDS, POLICY_FILE, RelayPolicy, RelayUnavailable

JOURNAL = 'key-publication.json'


def _sha(raw):
    return hashlib.sha256(raw).hexdigest() if raw is not None else 'absent'


def _optional(path):
    storage._check_private_file(path)
    return storage._read_bytes(path, maximum=262144) if path.exists() else None


def _policy_unchanged(root, expected: RelayPolicy):
    from .member_relay_policy import verify_publisher_identity
    verify_publisher_identity()
    storage._private_directory(root, create=False)
    storage._check_private_file(root / POLICY_FILE)
    storage._check_private_file(root / CONFIG_FILE)
    actual = RelayPolicy.model_validate(storage._json_document(storage._read_bytes(root / POLICY_FILE)))
    if actual != expected or _sha(storage._read_bytes(root / CONFIG_FILE, maximum=65536)) != expected.server_config_sha256:
        raise RelayUnavailable('relay_policy_changed_during_publication')


def _render(policy, allocations, expires_at):
    # restrict disables other channels; port-forwarding re-enables only what the
    # independently checked remote-only account policy and permitlisten intersect.
    stamp = expires_at.strftime('%Y%m%d%H%M%SZ')
    lines = [f'# RCN dedicated relay policy {policy.digest()}; managed, do not edit']
    for item in allocations:
        lines.append(f'restrict,port-forwarding,permitlisten="localhost:{item.listener_port}",'
            f'expiry-time="{stamp}" {item.public_key} rcn-{item.enrollment_id}')
    return ('\n'.join(lines) + '\n').encode('ascii')


def _publish(root, policy, raw):
    target, journal = root / KEYS_FILE, root / JOURNAL
    before, saved = _optional(target), _optional(journal)
    if saved is None:
        if before is not None:
            raise RelayUnavailable('relay_keyfile_has_no_publication_journal')
        state = {'schema_version': 1, 'policy_sha256': policy.digest(),
                 'applied_sha256': 'absent', 'pending_sha256': None}
    else:
        try:
            state = storage._json_document(saved)
            if (set(state) != {'schema_version','policy_sha256','applied_sha256','pending_sha256'}
                    or type(state['schema_version']) is not int or state['schema_version'] != 1
                    or state['policy_sha256'] != policy.digest()
                    or (state['applied_sha256'] != 'absent' and not re.fullmatch(r'[a-f0-9]{64}', state['applied_sha256']))
                    or (state['pending_sha256'] is not None and not re.fullmatch(r'[a-f0-9]{64}', state['pending_sha256']))):
                raise ValueError('invalid publication journal')
        except (ValueError, TypeError, KeyError):
            raise RelayUnavailable('relay_key_publication_requires_review') from None
        if _sha(before) not in {state['applied_sha256'], state['pending_sha256']}:
            raise RelayUnavailable('relay_keyfile_changed_outside_provisioner')
    if saved is not None and before == raw and state['pending_sha256'] is None:
        _policy_unchanged(root, policy)
        return
    pending = {'schema_version': 1, 'policy_sha256': policy.digest(),
               'applied_sha256': _sha(before), 'pending_sha256': _sha(raw)}
    pending_raw = storage._json_bytes(pending)
    if pending_raw != saved:
        storage._publish(journal, pending_raw, expected=saved)
    _policy_unchanged(root, policy)
    if before != raw:
        storage._publish(target, raw, expected=before, maximum=262144)
    if _optional(target) != raw:
        raise RelayUnavailable('relay_keyfile_readback_failed')
    _policy_unchanged(root, policy)
    done = {**pending, 'applied_sha256': _sha(raw), 'pending_sha256': None}
    storage._publish(journal, storage._json_bytes(done), expected=pending_raw)


def synchronize_keys(manager, policy: RelayPolicy, *, now=None) -> dict:
    """Reconcile current authority with bounded retries; no DB write lock during IO."""
    root = manager.root
    try:
        _policy_unchanged(root, policy)
        with storage._exclusive(root):
            # Minute buckets avoid needless writes on identical requests. At least
            # 240 and at most 300 seconds, independently enforced at SSH login.
            at = now or datetime.now(timezone.utc)
            if at.tzinfo is None:
                raise RelayUnavailable('relay_publication_time_requires_timezone')
            expires = datetime.fromtimestamp(int(at.timestamp()) // 60 * 60 + LEASE_SECONDS, timezone.utc)
            for _ in range(3):
                allocations = manager.active(policy)
                raw = _render(policy, allocations, expires)
                _publish(root, policy, raw)
                if manager.active(policy) == allocations:
                    return {'policy_sha256': policy.digest(), 'keyfile_sha256': _sha(raw),
                        'authorized_enrollments': [item.enrollment_id for item in allocations],
                        'authorized_count': len(allocations), 'expires_at': expires.isoformat(),
                        'existing_sessions_revoked': False, 'grants_execution': False}
            raise RelayUnavailable('relay_authority_changed_during_publication')
    except RelayUnavailable:
        raise
    except (storage.MemberRegistrationError, OSError, ValueError, TypeError, KeyError):
        raise RelayUnavailable('relay_key_publication_unavailable') from None
