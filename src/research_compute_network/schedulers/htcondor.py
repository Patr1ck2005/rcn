"""HTCondor acceptance-probe adapter.

Real submission remains disabled until the documented Windows/COMSOL probe has
passed. This prevents the pilot from silently becoming an arbitrary-command
launcher.
"""

from __future__ import annotations

import shutil
import subprocess

from ..models import Assignment, JobEnvelope, RemoteRunRecord
from .base import SchedulerAdapter, SchedulerProbe


class HtcondorAdapter(SchedulerAdapter):
    REQUIRED_TOOLS = ("condor_status", "condor_q", "condor_submit", "condor_rm")

    def probe(self) -> SchedulerProbe:
        paths = {tool: shutil.which(tool) for tool in self.REQUIRED_TOOLS}
        missing = [tool for tool, path in paths.items() if path is None]
        if missing:
            return SchedulerProbe(
                adapter="htcondor",
                available=False,
                details={tool: path or False for tool, path in paths.items()},
                errors=[f"missing required tool: {tool}" for tool in missing],
            )
        completed = subprocess.run(
            [paths["condor_status"], "-version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
        output = (completed.stdout + completed.stderr).strip()
        version = output.splitlines()[0] if output else None
        errors = [] if completed.returncode == 0 else [f"condor_status returned {completed.returncode}"]
        return SchedulerProbe(
            adapter="htcondor",
            available=completed.returncode == 0,
            version=version,
            details={tool: path for tool, path in paths.items()},
            errors=errors,
        )

    def submit(self, job: JobEnvelope, assignment: Assignment) -> str:
        raise RuntimeError(
            "HTCondor submission is locked until the Windows/COMSOL acceptance probe passes"
        )

    def cancel(self, external_job_id: str) -> None:
        raise RuntimeError(
            "HTCondor cancellation is locked until the Windows/COMSOL acceptance probe passes"
        )

    def poll(self, external_job_id: str) -> RemoteRunRecord:
        raise RuntimeError("HTCondor polling remains locked while the adapter is paused")

    def collect_artifacts(self, external_job_id: str, destination: str) -> list[str]:
        raise RuntimeError("HTCondor artifact collection remains locked while the adapter is paused")
