"""Standard-library pressure tracking for the standalone remote runtime."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone


@dataclass
class ExternalPressureSnapshot:
    schema_version: int = 1
    state: str = "normal"
    external_process_count: int = 0
    external_cpu_percent: float = 0.0
    external_memory_mb: int = 0
    external_gpu_utilization_percent: float = 0.0
    process_set_hash: str | None = None
    attribution_quality: str = "unavailable"
    unattributed_cpu_percent: float = 0.0
    unattributed_memory_mb: int = 0
    reason_codes: list[str] | None = None
    # Historical naming trap: despite the name, these carry the WHOLE
    # non-Network process aggregate (not only COMSOL).  Kept only for
    # 0.13.0 supervisor/payload compatibility; the generic fields above are
    # authoritative.  See docs/operations-runbook.zh.md section S4.
    external_comsol_count: int | None = None
    external_comsol_cpu_percent: float | None = None
    external_comsol_memory_mb: int | None = None
    candidate_since: datetime | None = None
    pressured_since: datetime | None = None
    cleared_at: datetime | None = None
    reason: str = "no external load pressure"
    observed_at: datetime | None = None

    def __post_init__(self):
        if self.external_comsol_count is not None and self.external_process_count == 0:
            self.external_process_count = self.external_comsol_count
        if self.external_comsol_cpu_percent is not None and self.external_cpu_percent == 0.0:
            self.external_cpu_percent = self.external_comsol_cpu_percent
        if self.external_comsol_memory_mb is not None and self.external_memory_mb == 0:
            self.external_memory_mb = self.external_comsol_memory_mb
        self.external_comsol_count = self.external_process_count
        self.external_comsol_cpu_percent = self.external_cpu_percent
        self.external_comsol_memory_mb = self.external_memory_mb

    def model_copy(self, *, update: dict):
        return replace(self, **update)

    def model_dump(self, *, mode: str = "python") -> dict:
        payload = dict(vars(self))
        payload["reason_codes"] = list(self.reason_codes or [])
        # Compatibility aliases for 0.13.0 agents and persisted payloads.
        # Names are historical: the values describe all non-Network processes.
        payload["external_comsol_count"] = self.external_process_count
        payload["external_comsol_cpu_percent"] = self.external_cpu_percent
        payload["external_comsol_memory_mb"] = self.external_memory_mb
        if mode == "json":
            for name in ("candidate_since", "pressured_since", "cleared_at", "observed_at"):
                value = payload[name]
                payload[name] = value.isoformat() if value is not None else None
        return payload


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class PressureTracker:
    """Keep the standalone payload shape; the Control Plane owns policy evaluation."""

    def __init__(self) -> None:
        self.snapshot = ExternalPressureSnapshot(observed_at=_utc_now())

    def update(
        self,
        sample: ExternalPressureSnapshot,
        *,
        now: datetime | None = None,
    ) -> ExternalPressureSnapshot:
        current = now or sample.observed_at or _utc_now()
        result = sample.model_copy(update={
            "state": "normal",
            "candidate_since": None,
            "pressured_since": None,
            "cleared_at": None,
            "reason": "raw external load observation; Control Plane applies configured policy",
            "observed_at": current,
        })
        self.snapshot = result
        return result
