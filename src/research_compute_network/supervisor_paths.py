"""Nonsecret control-plane configuration locations, never task-provided paths."""
from __future__ import annotations

from pathlib import PureWindowsPath

LOCATION_KEY = 'supervisor_config_location'
MANAGED_LOCATION = 'managed-root-v1'


def supervisor_config_path(config) -> PureWindowsPath:
    location = config.execution_provenance.get(LOCATION_KEY)
    if location is not None:
        if location != MANAGED_LOCATION or not config.root_uuid:
            raise ValueError('invalid managed supervisor configuration identity')
        from .member_worker_root_contract import canonical_root
        return PureWindowsPath(canonical_root(config.remote_root)) / 'agent' / 'machine.json'
    account = config.ssh_user.strip()
    if not account or any(ch in account for ch in '\\/:*?"<>|'):
        raise ValueError('invalid SSH account for supervisor configuration')
    return PureWindowsPath(fr'C:\Users\{account}\AppData\Local\ResearchComputeNetwork\machine.json')
