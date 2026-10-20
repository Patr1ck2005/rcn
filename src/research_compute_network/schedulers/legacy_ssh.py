"""Read-only characterization of the existing project-specific SSH dispatcher."""

from __future__ import annotations

from pathlib import Path

from ..models import Assignment, JobEnvelope, RemoteRunRecord
from .base import SchedulerAdapter, SchedulerProbe


class LegacySshBaseline(SchedulerAdapter):
    REQUIRED_MARKERS = (
        "WORKERS =",
        "subprocess.Popen",
        "ssh",
        "scp",
        "max-attempts",
        "StrictHostKeyChecking=no",
    )

    def __init__(self, dispatcher_path: str | Path) -> None:
        self.dispatcher_path = Path(dispatcher_path)

    def probe(self) -> SchedulerProbe:
        if not self.dispatcher_path.is_file():
            return SchedulerProbe(
                adapter="legacy-ssh",
                available=False,
                errors=[f"dispatcher not found: {self.dispatcher_path}"],
            )
        text = self.dispatcher_path.read_text(encoding="utf-8", errors="replace")
        markers = {marker: marker in text for marker in self.REQUIRED_MARKERS}
        missing = [marker for marker, found in markers.items() if not found]
        return SchedulerProbe(
            adapter="legacy-ssh",
            available=not missing,
            details={"path": str(self.dispatcher_path), **markers},
            errors=[f"missing characterization marker: {marker}" for marker in missing],
        )

    def submit(self, job: JobEnvelope, assignment: Assignment) -> str:
        raise RuntimeError("legacy SSH is a read-only baseline in the pilot")

    def cancel(self, external_job_id: str) -> None:
        raise RuntimeError("legacy SSH is a read-only baseline in the pilot")

    def poll(self, external_job_id: str) -> RemoteRunRecord:
        raise RuntimeError("legacy SSH is a read-only baseline in the pilot")

    def collect_artifacts(self, external_job_id: str, destination: str) -> list[str]:
        raise RuntimeError("legacy SSH is a read-only baseline in the pilot")
