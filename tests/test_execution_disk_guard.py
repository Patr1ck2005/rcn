import base64
from datetime import datetime, timedelta, timezone
import gzip
from pathlib import PureWindowsPath
import re

import pytest

from research_compute_network.capacity import effective_capacity
from research_compute_network.disk_guard import (
    execution_disk_block_reason, execution_disk_headroom, update_disk_snapshot,
)
from research_compute_network.machine_observation import MachineObservation
from research_compute_network.models import (
    ExecutionDiskSnapshot, MachineExecutionConfig, MachineHeartbeat, MachineMetrics,
    PressurePolicySettings, PressureState, TelemetryState,
)
from research_compute_network.placement import evaluate_placement
from research_compute_network.profiles import WORKBENCH_COMSOL_SCAN_V1
from research_compute_network.ssh_disk_probe import supervisor_status_with_disk_probe
from conftest import approved_grant, open_machine, project_approval, register_live_machine, simple_job


NOW = datetime(2026, 9, 8, 4, tzinfo=timezone.utc)


def snapshot(free=5 * 1024, *, at=NOW, **changes):
    return ExecutionDiskSnapshot(
        observed_at=at, available=True, volumes=[
            {'role': 'work_root', 'volume': 'E:', 'free_mb': 95 * 1024},
            *[{'role': role, 'volume': 'C:', 'free_mb': free}
              for role in ('temp', 'tmp', 'comsol_user')],
        ], **changes,
    )


def advance(incoming, previous=None):
    return update_disk_snapshot(incoming, previous, reserve_mb=50 * 1024, clear_after_s=120)


def decision(metrics, *, at=NOW, **changes):
    return effective_capacity(
        policy_cap=3, execution_cap=3, profile_cap=None, profile_id='test',
        pressure=metrics.external_load, free_disk_mb=metrics.free_disk_mb,
        disk_reserve_mb=50 * 1024,
        disk_block_reason=execution_disk_block_reason(metrics, now=at, reserve_mb=50 * 1024),
        now=at, **changes,
    )


def test_low_c_high_e_blocks_immediately_without_relabelling_root_metrics():
    metrics = MachineMetrics(free_disk_mb=95 * 1024, execution_disk=advance(snapshot()))
    assert execution_disk_headroom(metrics, now=NOW) == (5 * 1024, 'temp (C:)')
    assert metrics.free_disk_mb == 95 * 1024
    assert decision(metrics, telemetry_state=TelemetryState.LIVE).effective_cap == 0
    assert metrics.execution_disk.blocked


@pytest.mark.parametrize('state', [TelemetryState.LIVE, TelemetryState.STALE, TelemetryState.UNAVAILABLE])
def test_hard_disk_gate_not_bypassed_by_pressure_override_or_stale_grace(state):
    metrics = MachineMetrics(free_disk_mb=95 * 1024, execution_disk=advance(snapshot()))
    result = decision(metrics, telemetry_state=state, telemetry_stale_age_s=1,
                      override_until=NOW + timedelta(hours=1), override_cap=3)
    assert result.effective_cap == 0
    assert 'disk_reserve_pressure' in result.reason


def test_legacy_root_disk_also_is_a_hard_zero_capacity_gate():
    result = effective_capacity(policy_cap=3, execution_cap=3, profile_cap=None,
        profile_id='test', pressure=MachineMetrics().external_load, telemetry_state=TelemetryState.LIVE,
        free_disk_mb=5 * 1024, disk_reserve_mb=50 * 1024,
        override_until=NOW + timedelta(hours=1), now=NOW)
    assert result.effective_cap == 0


def test_disk_recovers_automatically_after_clear_window_not_an_admin_unlock():
    current = advance(snapshot())
    for seconds in (10, 40, 129, 130):
        current = advance(snapshot(90 * 1024, at=NOW + timedelta(seconds=seconds)), current)
        assert current.blocked == (seconds < 130)
    metrics = MachineMetrics(free_disk_mb=95 * 1024, execution_disk=current)
    assert decision(metrics, at=NOW + timedelta(seconds=130), telemetry_state=TelemetryState.LIVE).effective_cap == 3


def test_low_sample_resets_recovery_window():
    current = advance(snapshot())
    current = advance(snapshot(90 * 1024, at=NOW + timedelta(seconds=10)), current)
    current = advance(snapshot(at=NOW + timedelta(seconds=100)), current)
    assert current.clear_since is None
    current = advance(snapshot(90 * 1024, at=NOW + timedelta(seconds=130)), current)
    assert current.blocked and current.clear_since == NOW + timedelta(seconds=130)


def test_probe_gap_does_not_count_as_confirmed_recovery():
    current = advance(snapshot())
    current = advance(snapshot(90 * 1024, at=NOW + timedelta(seconds=10)), current)
    current = advance(snapshot(90 * 1024, at=NOW + timedelta(seconds=300)), current)
    assert current.blocked and current.clear_since == NOW + timedelta(seconds=300)


@pytest.mark.parametrize('kind', ['unavailable', 'missing_role', 'stale', 'future'])
def test_missing_or_untrustworthy_volume_evidence_blocks(kind):
    probe = snapshot(90 * 1024)
    if kind == 'unavailable':
        probe.available = False
    elif kind == 'missing_role':
        probe.volumes.pop()
    elif kind == 'stale':
        probe.observed_at -= timedelta(seconds=181)
    else:
        probe.observed_at += timedelta(seconds=10)
    metrics = MachineMetrics(free_disk_mb=95 * 1024, execution_disk=probe)
    assert decision(metrics, telemetry_state=TelemetryState.LIVE).effective_cap == 0


def test_old_outbound_heartbeat_cannot_erase_or_refresh_ssh_disk_evidence():
    previous = MachineMetrics(free_disk_mb=95 * 1024, execution_disk=advance(snapshot()), observed_at=NOW)
    incoming = MachineHeartbeat(machine_id='worker-1', metrics=MachineMetrics(
        free_disk_mb=95 * 1024, observed_at=NOW + timedelta(seconds=10)))
    observed = MachineObservation.from_heartbeat(incoming, previous_metrics=previous,
        pressure_settings=PressurePolicySettings(), disk_reserve_mb=50 * 1024)
    assert observed.metrics.execution_disk == previous.execution_disk
    assert decision(observed.metrics, at=NOW + timedelta(seconds=10), telemetry_state=TelemetryState.LIVE).effective_cap == 0
    # Nor may a delayed high-space report overwrite a newer low-space report.
    assert advance(snapshot(90 * 1024, at=NOW - timedelta(seconds=10)), previous.execution_disk) == previous.execution_disk


def test_unit_headroom_gate_uses_the_limiting_write_volume(service):
    machine, policy = open_machine()
    machine.metrics.execution_disk = snapshot(37 * 1024, at=machine.metrics.observed_at)
    register_live_machine(service, machine, policy)
    config = MachineExecutionConfig(machine_id=machine.machine_id, enabled=True,
        disk_reserve_gib=50, c_drive_reserve_gib=20)
    service.repository.put_machine_execution_config(config)
    job = simple_job()
    unit = job.work_units[0]
    unit.resources.disk_mb = 32 * 1024
    result = evaluate_placement(job=job, unit=unit, machine=machine, policy=policy,
        grant=approved_grant(), approvals=[project_approval()],
        profile=WORKBENCH_COMSOL_SCAN_V1, active_units=[], active_profile_units=[], solver_approval=None,
        execution_config=config, operational_status=service.repository.get_machine_operational_status(machine.machine_id))
    disk = next(block for block in result.blockers if block.code == 'disk_headroom')
    assert disk.available == 37 * 1024 and disk.required == 52 * 1024
    assert 'C:' in disk.message
    assert not result.eligible


def test_live_observation_blocks_capacity_without_touching_policy(service):
    machine, policy = open_machine()
    register_live_machine(service, machine, policy)
    service.repository.put_machine_execution_config(MachineExecutionConfig(machine_id=machine.machine_id))
    baseline = service.repository.get_policy(machine.machine_id).model_dump()
    metrics = machine.metrics.model_copy(deep=True)
    metrics.observed_at = datetime.now(timezone.utc)
    metrics.execution_disk = snapshot(at=metrics.observed_at)
    service.record_heartbeat(MachineHeartbeat(machine_id=machine.machine_id, metrics=metrics), actor_id='test-agent')
    status = service.repository.get_machine_operational_status(machine.machine_id)
    assert status.effective_capacity == 0
    assert 'disk_reserve_pressure' in status.capacity_reason
    assert service.repository.get_policy(machine.machine_id).model_dump() == baseline


def unpack_probe():
    encoded = supervisor_status_with_disk_probe(PureWindowsPath(r'E:\ResearchComputeNetwork\agent\status.json'))
    assert len(base64.b64encode(encoded.encode('utf-16-le'))) < 7900
    packed = re.search(r"FromBase64String\('([^']+)'\)", encoded).group(1)
    return gzip.decompress(base64.b64decode(packed)).decode('utf-8')


def test_probe_is_bounded_read_only_identity_checked_and_path_private():
    script = unpack_probe()
    assert 'GetOwnerSid' in script and 'WindowsIdentity' in script
    assert 'AvailableFreeSpace' in script and 'ReparsePoint' in script
    assert 'ReadAllBytes' in script and 'status.json' in script
    assert all(word not in script for word in (
        'Remove-Item', 'Set-Content', 'WriteAllBytes', 'Stop-Process', 'sshd_config',
        'invitation.json', 'node.json', 'machine.token', 'comsol.prefs'))
    assert 'volume=$diskDrive.Name.Substring(0,2)' in script
    assert 'Exception.Message' not in script


def test_wire_storage_evidence_refuses_private_paths_as_volume_ids():
    with pytest.raises(ValueError):
        ExecutionDiskSnapshot(observed_at=NOW, available=True, volumes=[
            {'role': 'temp', 'volume': r'C:\Users\private', 'free_mb': 10}])


def test_c_drive_twenty_gib_floor_does_not_lower_e_drive_fifty_gib_floor():
    metrics = MachineMetrics(free_disk_mb=95 * 1024, execution_disk=advance(snapshot(37 * 1024)))
    assert not metrics.execution_disk.blocked
    assert decision(metrics, telemetry_state=TelemetryState.LIVE).effective_cap == 3
    metrics.execution_disk.volumes[0].free_mb = 49 * 1024
    assert 'work_root (E:)' in execution_disk_block_reason(metrics, now=NOW, reserve_mb=50 * 1024)
    assert decision(metrics, telemetry_state=TelemetryState.LIVE).effective_cap == 0


def test_concurrent_legacy_observation_cannot_overwrite_a_newer_disk_probe(service):
    machine, policy = open_machine()
    register_live_machine(service, machine, policy)
    service.repository.put_machine_execution_config(MachineExecutionConfig(machine_id=machine.machine_id))
    future = machine.metrics.model_copy(deep=True)
    future.observed_at += timedelta(seconds=1)
    prepared = service.machine_observations.prepare(
        MachineHeartbeat(machine_id=machine.machine_id, metrics=future), status=None)
    live = machine.model_copy(deep=True)
    live.metrics.execution_disk = snapshot(at=machine.metrics.observed_at)
    service.repository.put_machine(live)  # simulate another probe winning the write race
    assert not service.repository.put_machine_observation(prepared.machine, None, prepared.raw_sample)
    assert service.repository.get_machine(machine.machine_id).metrics.execution_disk == live.metrics.execution_disk


@pytest.mark.parametrize('owner_matches', [True, False])
def test_probe_runs_under_windows_powershell_without_writing_files(tmp_path, owner_matches):
    import os
    import json
    import subprocess
    if os.name != 'nt':
        pytest.skip('Windows PowerShell acceptance')
    root = tmp_path / 'worker'
    (root / 'agent').mkdir(parents=True)
    status_path = root / 'agent/status.json'
    status_path.write_text(json.dumps({'pid': 42, 'metrics': {'available': True},
                                     'message': '无法打开原生文件'}, ensure_ascii=False), encoding='utf-8')
    script = supervisor_status_with_disk_probe(PureWindowsPath(str(status_path)))
    packed = re.search(r"FromBase64String\('([^']+)'\)", script).group(1)
    original = gzip.decompress(base64.b64decode(packed)).decode('utf-8')
    owner = '[Security.Principal.WindowsIdentity]::GetCurrent().User.Value' if owner_matches else "'S-1-0-0'"
    mocked = original.replace('Get-CimInstance Win32_Process -Filter "ProcessId=$diskProcessId"',
        '[pscustomobject]@{ProcessId=42}').replace(
        'Invoke-CimMethod -InputObject $diskProcess -MethodName GetOwnerSid',
        f'[pscustomobject]@{{ReturnValue=0; Sid={owner}}}')
    script = script.replace(packed, base64.b64encode(gzip.compress(mocked.encode('utf-8'))).decode())
    completed = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-EncodedCommand',
        base64.b64encode(script.encode('utf-16-le')).decode()], capture_output=True, timeout=20)
    assert completed.returncode == 0
    data = json.loads(base64.b64decode(completed.stdout.strip()).decode('utf-8'))
    assert data['message'] == '无法打开原生文件'
    probe = ExecutionDiskSnapshot.model_validate(data['metrics']['execution_disk'])
    assert probe.available is owner_matches
    assert {path.name for path in root.rglob('*') if path.is_file()} == {'status.json'}
