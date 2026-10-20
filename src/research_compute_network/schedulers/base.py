"""Scheduler adapter boundary."""

from __future__ import annotations

from abc import ABC, abstractmethod

from pydantic import BaseModel, Field

from ..models import Assignment, JobEnvelope, RemoteRunRecord


class PreLaunchSubmissionError(RuntimeError):
    """Submission failed before a remote run could have been activated."""

    def __init__(
        self,
        message: str,
        *,
        reason_code: str = "prelaunch_failure",
        error_type: str | None = None,
        timeout_s: float | None = None,
    ) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.error_type = error_type or type(self).__name__
        self.timeout_s = timeout_s


class SubmissionUncertainError(RuntimeError):
    """The fixed publication boundary may have been crossed; never pre-launch.

    The original execution identity must be retained and polled. A missing
    acknowledgement is not evidence that it is safe to create another Attempt.
    """

    def __init__(self, message: str, *, external_run_id: str) -> None:
        super().__init__(message)
        self.external_run_id = external_run_id
        self.reason_code = "submission_delivery_unknown"


class SchedulerProbe(BaseModel):
    adapter: str
    available: bool
    version: str | None = None
    details: dict[str, str | bool | int | float | None] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)


class SchedulerAdapter(ABC):
    @abstractmethod
    def probe(self) -> SchedulerProbe:
        raise NotImplementedError

    @abstractmethod
    def submit(self, job: JobEnvelope, assignment: Assignment) -> str:
        raise NotImplementedError

    def prepare(self, job: JobEnvelope, assignment: Assignment, external_job_id: str) -> str:
        raise NotImplementedError("scheduler adapter does not support prepared dispatch")

    def activate(self, external_job_id: str) -> None:
        raise NotImplementedError("scheduler adapter does not support prepared dispatch")

    @abstractmethod
    def cancel(self, external_job_id: str) -> None:
        raise NotImplementedError

    @abstractmethod
    def poll(self, external_job_id: str) -> RemoteRunRecord:
        raise NotImplementedError

    @abstractmethod
    def collect_artifacts(self, external_job_id: str, destination: str) -> list[str]:
        raise NotImplementedError
