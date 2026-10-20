"""Acceptance projection of center-authenticated, independently dated channel evidence.

No client-supplied passed flags, networking, runtime mutation or process control.
This verifies present observations, not recovery under a real network change.
"""
from __future__ import annotations

from datetime import datetime, timezone

from .member_admission_contract import canonical_digest
from .member_enrollment import https_origin


KIND = 'member-independent-channel-observation-v1'
MAX_AGE = 90


def _stamp(value, now):
    if not isinstance(value,str):
        return None
    try:
        at=datetime.fromisoformat(value.replace('Z','+00:00'))
        if at.tzinfo is None or not 0<=(now-at).total_seconds()<=MAX_AGE:
            return None
        return at
    except ValueError:
        return None


def evaluate_channels(config, operational: dict | None, *, registration_origin: str, now=None) -> dict:
    now=now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError('channel_verification_requires_timezone')
    base={'schema_version':1,'verification_kind':KIND,'machine_id':config.machine_id,
        'root_uuid':config.root_uuid,'execution_config_sha256':canonical_digest(config.model_dump(mode='json')),
        'channels':{},'passed':False,'state':'host-or-network-unconfirmed'}
    # The origin is the enrollment-bound one, not a client-chosen override or SSH
    # loopback path. Network independence still needs deployment/real-network tests.
    try:
        if (https_origin(config.control_plane_heartbeat_url)!=https_origin(registration_origin)
                or config.control_plane_heartbeat_url!=registration_origin):
            return {**base,'state':'heartbeat-origin-mismatch'}
    except (TypeError,ValueError):
        return {**base,'state':'heartbeat-origin-mismatch'}
    if operational is None:
        return base
    if (not isinstance(operational,dict) or operational.get('machine_id')!=config.machine_id
            or operational.get('observation_consistent') is not True
            or not isinstance(operational.get('connection_evidence'),dict)):
        return {**base,'state':'invalid-channel-evidence'}
    channels=operational['connection_evidence']
    for name in ('ssh','outbound'):
        raw=channels.get(name)
        if raw is None:
            continue
        if (not isinstance(raw,dict) or type(raw.get('healthy')) is not bool
                or raw.get('transport_state') not in {'unknown','connected','disconnected'}
                or any(raw.get(k) is not None and not isinstance(raw[k],str) for k in ('observed_at','supervisor_at','metric_at'))):
            return {**base,'state':'invalid-channel-evidence'}
        at=_stamp(raw.get('observed_at'),now);supervisor=_stamp(raw.get('supervisor_at'),now);metrics=_stamp(raw.get('metric_at'),now)
        live=bool(at and supervisor and metrics and raw['healthy'] and raw['transport_state']=='connected'
                  and supervisor<=at and metrics<=at)
        base['channels'][name]={k:raw.get(k) for k in ('observed_at','supervisor_at','metric_at','transport_state','healthy')}
        base['channels'][name]['fresh_and_healthy']=live
    ssh=base['channels'].get('ssh',{}).get('fresh_and_healthy',False)
    outbound=base['channels'].get('outbound',{}).get('fresh_and_healthy',False)
    if ssh and outbound:
        base.update(passed=True,state='both-channels-live')
    elif outbound:
        base['state']='host-reporter-live-ssh-unavailable'
    elif ssh:
        base['state']='ssh-live-independent-heartbeat-unavailable'
    return base
