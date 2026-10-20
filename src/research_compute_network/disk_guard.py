"""Automatic, reversible disk eligibility; no policy changes or file cleanup."""
from __future__ import annotations

from datetime import datetime, timezone

from .models import ExecutionDiskSnapshot, MachineMetrics


DISK_MAX_AGE_S = 180
C_DRIVE_RESERVE_MB = 20 * 1024


def volume_reserve_mb(volume: str, reserve_mb: int, c_drive_reserve_mb: int) -> int:
    return c_drive_reserve_mb if volume.upper().startswith("C:") else reserve_mb


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def disk_snapshot_fresh(snapshot: ExecutionDiskSnapshot, now: datetime) -> bool:
    age = (_aware(now) - _aware(snapshot.observed_at)).total_seconds()
    return -5 <= age <= DISK_MAX_AGE_S


def disk_snapshot_complete(snapshot: ExecutionDiskSnapshot) -> bool:
    roles = {volume.role for volume in snapshot.volumes}
    return snapshot.available and {"work_root", "temp", "tmp", "comsol_user"} <= roles


def update_disk_snapshot(
    incoming: ExecutionDiskSnapshot | None,
    previous: ExecutionDiskSnapshot | None,
    *, reserve_mb: int, clear_after_s: int, c_drive_reserve_mb: int = C_DRIVE_RESERVE_MB,
) -> ExecutionDiskSnapshot | None:
    # Old outbound heartbeats have no supplementary SSH evidence. Preserve
    # the last probe with its own timestamp, never refresh its age artificially.
    if incoming is None or (previous is not None and
            _aware(incoming.observed_at) <= _aware(previous.observed_at)):
        return previous.model_copy(deep=True) if previous else None
    result = incoming.model_copy(deep=True)
    sufficient = disk_snapshot_complete(result) and all(
        volume.free_mb >= volume_reserve_mb(volume.volume, reserve_mb, c_drive_reserve_mb)
        for volume in result.volumes
    )
    result.clear_since = None
    result.blocked = not sufficient
    was_blocked = previous is not None and (
        previous.blocked or not disk_snapshot_fresh(previous, result.observed_at)
    )
    if sufficient and was_blocked:
        result.clear_since = (
            previous.clear_since if disk_snapshot_fresh(previous, result.observed_at)
            else None
        ) or result.observed_at
        result.blocked = (
            _aware(result.observed_at) - _aware(result.clear_since)
        ).total_seconds() < clear_after_s
    return result


def execution_disk_headroom(metrics: MachineMetrics, *, now: datetime) -> tuple[int, str]:
    """Minimum usable headroom across known write volumes; root display stays true."""
    snapshot = metrics.execution_disk
    if snapshot is None:
        return metrics.free_disk_mb, "work_root"
    if not disk_snapshot_complete(snapshot):
        return 0, "disk_probe_unavailable"
    if not disk_snapshot_fresh(snapshot, now):
        return 0, "disk_probe_stale"
    limiting = min(snapshot.volumes, key=lambda volume: volume.free_mb)
    if metrics.free_disk_mb < limiting.free_mb:
        return metrics.free_disk_mb, "work_root"
    return limiting.free_mb, f"{limiting.role} ({limiting.volume})"


def execution_disk_block_reason(
    metrics: MachineMetrics, *, now: datetime, reserve_mb: int,
    c_drive_reserve_mb: int = C_DRIVE_RESERVE_MB, root_volume: str = "",
) -> str:
    free_mb, required_reserve, source = execution_disk_space(
        metrics, now=now, reserve_mb=reserve_mb,
        c_drive_reserve_mb=c_drive_reserve_mb, root_volume=root_volume,
    )
    if source.startswith("disk_probe_"):
        return source
    if free_mb < required_reserve:
        return f"disk_reserve_pressure: {source}; free {free_mb} MiB < reserve {required_reserve} MiB"
    if metrics.execution_disk is not None and metrics.execution_disk.blocked:
        return "disk_recovery_pending: waiting for fresh clear samples"
    return ""


def execution_disk_space(
    metrics: MachineMetrics, *, now: datetime, reserve_mb: int,
    c_drive_reserve_mb: int = C_DRIVE_RESERVE_MB, root_volume: str = "",
) -> tuple[int, int, str]:
    """Limiting (free, reserve, role) selected by usable space, not raw free."""
    free_mb, source = execution_disk_headroom(metrics, now=now)
    if source.startswith("disk_probe_"):
        return 0, reserve_mb, source
    snapshot = metrics.execution_disk
    if snapshot is not None:
        root_volume = next(volume.volume for volume in snapshot.volumes if volume.role == "work_root")
    spaces = [(metrics.free_disk_mb, volume_reserve_mb(root_volume, reserve_mb, c_drive_reserve_mb), "work_root")]
    if snapshot is not None:
        spaces.extend((volume.free_mb, volume_reserve_mb(volume.volume, reserve_mb, c_drive_reserve_mb),
                       f"{volume.role} ({volume.volume})") for volume in snapshot.volumes)
    return min(spaces, key=lambda space: space[0] - space[1])
