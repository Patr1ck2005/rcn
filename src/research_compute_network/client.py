"""Small dependency-free client for project Agents.

The client deliberately mirrors the HTTP resources instead of exposing SSH or
remote paths.  It is safe to use from a project-local Agent wrapper.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .models import JobEnvelope, OriginImportReceipt, PartitionRequest, UnitDiskEstimate
from .transport_diagnostics import gateway_failure_code, network_failure_code


MINIMUM_CONTROL_PLANE_VERSION = "0.12.3"


class RcnApiError(RuntimeError):
    def __init__(
        self,
        status: int,
        detail: str,
        *,
        reason_code: str | None = None,
        restriction: dict | None = None,
    ):
        super().__init__(f"RCN API {status}: {detail}")
        self.status = status
        self.detail = detail
        self.reason_code = reason_code
        self.restriction = restriction


class RcnSubmitWakeError(RcnApiError):
    """Dispatcher wake failure after the submitted Job was persisted."""

    def __init__(self, cause: RcnApiError, submitted_job: dict):
        super().__init__(
            cause.status,
            cause.detail,
            reason_code=cause.reason_code,
            restriction=cause.restriction,
        )
        self.submitted_job = submitted_job


def _version_key(value: str) -> tuple[int, ...]:
    release = value.split("+", 1)[0].split("-", 1)[0]
    try:
        parts = tuple(int(part) for part in release.split("."))
    except ValueError as exc:
        raise ValueError(f"invalid Network version: {value!r}") from exc
    if not parts:
        raise ValueError(f"invalid Network version: {value!r}")
    return parts + (0,) * (3 - len(parts))


class RcnClient:
    def __init__(self, base_url: str = "http://127.0.0.1:8765", token: str | None = None, *, timeout: float = 30.0, opener=None):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.opener = opener

    def _request(self, method: str, path: str, payload: dict | None = None, *, request_id: str | None = None):
        import re
        import time

        headers = {"Accept": "application/json"}
        if request_id is not None:
            from uuid import UUID
            if not isinstance(request_id, str) or str(UUID(request_id)) != request_id:
                raise ValueError("request_id must be a canonical UUID")
            headers["X-RCN-Request-ID"] = request_id
        body = None
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if payload is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request = Request(self.base_url + path, data=body, headers=headers, method=method)
        route = re.fullmatch(r"/v1/jobs/[A-Za-z0-9_.-]+/units/[A-Za-z0-9_.-]+/(scientific-exports|scientific-dependencies)", path)
        frozen = json.loads(body) if method == "POST" and route and body is not None else None

        def future_evidence_only(errors):
            if not isinstance(frozen, dict) or not isinstance(errors, list) or not 0 < len(errors) <= 64:
                return False
            for error in errors:
                if (not isinstance(error, dict) or error.get("type") != "value_error"
                    or error.get("msg") != "Value error, evidence time cannot be in the future"):
                    return False
                loc = error.get("loc")
                if route[1] == "scientific-dependencies":
                    allowed = loc == ["body", "completion", "completed_at"]
                else:
                    allowed = (loc == ["body", "export_accepted_at"]
                        or isinstance(loc, list) and len(loc) == 4 and loc[0] == "body"
                        and loc[1] in {"critical_analyses", "completed_dependencies"}
                        and type(loc[2]) is int and loc[2] >= 0 and loc[3] == "completed_at")
                if not allowed:
                    return False
                value = frozen
                try:
                    for part in loc[1:]:
                        value = value[part]
                except (KeyError, IndexError, TypeError):
                    return False
                if not isinstance(value, str) or error.get("input") != value:
                    return False
            return True

        deadline = None
        for attempt in range(3):
            timeout = self.timeout
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise prior_clock_error
                timeout = min(timeout, 5, remaining)
            try:
                with (self.opener.open if self.opener is not None else urlopen)(request, timeout=timeout) as response:
                    raw = response.read()
                    return json.loads(raw.decode("utf-8")) if raw else None
            except HTTPError as exc:
                raw = exc.read().decode("utf-8", errors="replace")
                detail = raw
                reason_code = None
                restriction = None
                try:
                    error_payload = json.loads(raw)
                except json.JSONDecodeError:
                    error_payload = None
                if isinstance(error_payload, dict):
                    restriction_payload = error_payload.get("restriction")
                    if isinstance(restriction_payload, dict):
                        restriction = restriction_payload
                        reason_code = restriction_payload.get("reason_code")
                    detail_payload = error_payload.get("detail")
                    if isinstance(detail_payload, dict):
                        reason_code = detail_payload.get("reason_code") or reason_code
                        detail = str(
                            detail_payload.get("message")
                            or detail_payload.get("detail")
                            or reason_code
                            or raw
                        )
                    elif detail_payload is not None:
                        detail = str(detail_payload)
                    if restriction is not None:
                        detail = str(restriction.get("message") or detail)
                future = (exc.code == 422 and restriction is None and isinstance(error_payload, dict)
                    and future_evidence_only(error_payload.get("detail")))
                if future:
                    reason_code = "scientific_evidence_clock_skew"
                reason_code = reason_code or gateway_failure_code(exc.code, exc.headers, raw)
                failure = RcnApiError(exc.code, detail, reason_code=reason_code, restriction=restriction)
                if future and attempt < 2:
                    if deadline is None:
                        deadline = time.monotonic() + 10
                    remaining = deadline - time.monotonic()
                    if remaining > 0:
                        prior_clock_error = failure
                        time.sleep(min(2, remaining))
                        if time.monotonic() < deadline:
                            continue
                raise failure from exc
            except URLError as exc:
                raise RcnApiError(0, "center connection failed", reason_code=network_failure_code(exc)) from exc

    def submit(self, job: JobEnvelope | dict) -> dict:
        runtime = self.require_minimum_version()
        payload = job.model_dump(mode="json") if isinstance(job, JobEnvelope) else job
        self._require_priority_contract(payload, runtime)
        submitted = self._request("POST", "/v1/jobs", payload)
        try:
            self.ensure_running()
        except RcnApiError as exc:
            # The Job already exists. Preserve its receipt so a Workbench Agent
            # can report the blocked wake without resubmitting or losing work.
            raise RcnSubmitWakeError(exc, submitted) from exc
        return submitted

    @staticmethod
    def _require_priority_contract(payload: dict, runtime: dict) -> None:
        if payload.get('priority_explicit') is not None and runtime.get('task_priority_schema') != 1:
            raise RcnApiError(409, 'Server must support explicit task priority and omitted defaults.',
                              reason_code='task_priority_not_supported')

    def require_minimum_version(self, minimum: str = MINIMUM_CONTROL_PLANE_VERSION) -> dict:
        runtime = self.execution_runtime()
        current = str(runtime.get("package_version") or "")
        try:
            compatible = _version_key(current) >= _version_key(minimum)
        except ValueError as exc:
            raise RcnApiError(0, str(exc)) from exc
        if not compatible:
            raise RcnApiError(
                426,
                f"Network {minimum} or newer is required; Control Plane reports {current}",
            )
        return runtime

    def ensure_running(self) -> dict:
        """Idempotently ensure dispatch after a Job has been persisted."""
        return self._request("POST", "/v1/dispatcher/ensure-running")

    def plan_partition(self, request: PartitionRequest | dict) -> dict:
        """Plan grouping; on partition_duration_confirmation_required ask the
        user for estimates or a Unit count. Never guess or bypass the gate.
        """
        payload = request.model_dump(mode="json") if isinstance(request, PartitionRequest) else request
        return self._plan_with_disk_contract(payload)

    def _plan_with_disk_contract(self, payload: dict) -> dict:
        estimate = payload.get("disk_estimate")
        if estimate is not None or payload.get('priority_explicit') is not None:
            runtime = self._request("GET", "/v1/execution-runtime")
            self._require_priority_contract(payload, runtime)
        if estimate is not None:
            estimate = UnitDiskEstimate.model_validate(estimate).model_dump(mode="json")
            if runtime.get("disk_estimate_schema") != 1:
                raise RcnApiError(409, "Server does not support per-Unit disk estimates; do not confirm or submit this plan.",
                    reason_code="disk_estimate_not_supported")
        result = self._request("POST", "/v1/partition-plans", payload)
        if payload.get('priority_explicit') is not None:
            echoed = result.get('request', {})
            if (echoed.get('priority_explicit') is not payload['priority_explicit']
                    or echoed.get('priority') != payload.get('priority', 0)):
                raise RcnApiError(409, 'Server did not preserve task priority intent.',
                                  reason_code='task_priority_not_preserved')
        if estimate is not None:
            echoed = result.get("request", {}).get("disk_estimate")
            if echoed is None or UnitDiskEstimate.model_validate(echoed).model_dump(mode="json") != estimate:
                raise RcnApiError(409, "Server did not preserve the disk estimate; do not confirm or submit this plan.",
                    reason_code="disk_estimate_not_preserved")
        return result

    def plan_declarative_study(
        self,
        request: PartitionRequest | dict,
        *,
        origin_adapter_id: str,
    ) -> dict:
        """Plan a public v2 Study without uploading executable project code.

        Missing grouping estimates require asking the user, as in plan_partition.
        """
        payload = request.model_dump(mode="json") if isinstance(request, PartitionRequest) else dict(request)
        payload["schema_version"] = 2
        payload["origin_adapter_id"] = origin_adapter_id
        if payload.get("execution_profile_id") == "project-worker-v1":
            raise ValueError("project-worker-v1 is read-only; use a registered declarative Profile")
        return self._plan_with_disk_contract(payload)

    def project_registrations(self) -> list[dict]:
        return self._request("GET", "/v1/project-registrations")

    def request_project_registration(
        self,
        *,
        project_id: str,
        display_name: str,
        purpose: str,
        requested_profiles: list[str],
    ) -> dict:
        return self._request("POST", "/v1/project-registrations", {
            "project_id": project_id,
            "display_name": display_name,
            "purpose": purpose,
            "requested_profiles": requested_profiles,
        })

    def issue_self_enrollment(self, *, ttl_minutes: int = 30) -> dict:
        return self._request("POST", "/v1/me/enrollments", {"ttl_minutes": ttl_minutes})

    def origin_adapters(self) -> list[dict]:
        return self._request("GET", "/v1/origin-adapters")

    def execution_compatibility(self, request: PartitionRequest | dict) -> dict:
        payload = request.model_dump(mode="json") if isinstance(request, PartitionRequest) else request
        project_id = str(payload.get("project_id") or "")
        if not project_id:
            raise ValueError("execution compatibility requires project_id")
        return self._request(
            "POST",
            f"/v1/projects/{project_id}/execution-compatibility",
            payload,
        )

    def get_partition_plan(self, plan_id: str) -> dict:
        return self._request("GET", f"/v1/partition-plans/{plan_id}")

    def confirm_partition(self, plan_id: str) -> dict:
        return self._request("POST", f"/v1/partition-plans/{plan_id}/confirm")

    def get_job(self, job_id: str) -> dict:
        """Return the Job detail DTO, including presentation/operational fields."""
        return self._request("GET", f"/v1/jobs/{job_id}")

    def get_job_contract(self, job_id: str) -> dict:
        """Return the original strict JobEnvelope without presentation fields."""
        return self._request("GET", f"/v1/jobs/{job_id}/contract")

    def get_job_status(self, job_id: str) -> dict:
        """Return lifecycle, Attempt, ETA, solver, and resource metadata only."""
        return self._request("GET", f"/v1/jobs/{job_id}?view=operational")

    def get_job_storage_metadata(self, job_id: str) -> dict:
        """Fresh producer/Attempt metadata without scientific blobs or fleet ETA."""
        return self._request("GET", f"/v1/jobs/{job_id}?view=storage")

    def current_actor(self) -> dict:
        return self._request("GET", "/v1/me")

    def execution_runtime(self) -> dict:
        """Return the server-authorized runtime used for Origin bundles."""
        return self._request("GET", "/v1/execution-runtime")

    def list_jobs(
        self,
        *,
        view: str = "compact",
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        """List operational Job records without expanding scientific payloads.

        Use :meth:`get_job` for one complete immutable Job contract.
        """

        if view not in {"compact", "summary"}:
            raise ValueError("list_jobs view must be 'compact' or 'summary'")
        if not 1 <= limit <= 500:
            raise ValueError("list_jobs limit must be between 1 and 500")
        if offset < 0:
            raise ValueError("list_jobs offset must be non-negative")
        return self._request(
            "GET",
            f"/v1/jobs?view={view}&limit={limit}&offset={offset}",
        )

    def cancel(self, job_id: str, reason: str = "") -> dict:
        return self._request("POST", f"/v1/jobs/{job_id}/cancel", {"reason": reason})

    def cancel_unit(self, job_id: str, work_unit_id: str, reason: str = "") -> dict:
        return self._request(
            "POST",
            f"/v1/jobs/{job_id}/units/{work_unit_id}/cancel",
            {"reason": reason},
        )

    def retry(self, job_id: str) -> dict:
        return self._request("POST", f"/v1/jobs/{job_id}/retry")

    def retry_unit(self, job_id: str, work_unit_id: str) -> dict:
        return self._request("POST", f"/v1/jobs/{job_id}/units/{work_unit_id}/retry")

    def auto_retry(self) -> dict:
        return self._request("POST", "/v1/scheduler/auto-retry")

    def assign_once(self) -> dict | None:
        return self._request("POST", "/v1/scheduler/assign-once")

    def artifact_manifests(self, job_id: str) -> list[dict]:
        return self._request("GET", f"/v1/jobs/{job_id}/artifact-manifests")

    def get_origin_import_receipt(self, job_id: str) -> dict | None:
        return self._request("GET", f"/v1/jobs/{job_id}/origin-import-receipt")

    def record_origin_import(self, receipt: OriginImportReceipt | dict) -> dict:
        payload = receipt.model_dump(mode="json") if isinstance(receipt, OriginImportReceipt) else receipt
        return self._request(
            "POST",
            f"/v1/jobs/{payload['job_id']}/origin-import-receipt",
            payload,
        )

    def collect_artifacts(self, job_id: str) -> list[dict]:
        """Return the verified artifact manifests for origin-side staging.

        The control plane intentionally returns manifest metadata only. This
        method does not transfer bytes; an approved origin-side adapter owns
        transfer and promotion into its own ``data/processed`` boundary.
        """
        return self.artifact_manifests(job_id)

    def attempts(self, job_id: str, work_unit_id: str | None = None) -> list[dict]:
        suffix = f"/units/{work_unit_id}/attempts" if work_unit_id else "/attempts"
        return self._request("GET", f"/v1/jobs/{job_id}{suffix}")

    def machines(self) -> list[dict]:
        return self._request("GET", "/v1/machines")

    def profiles(self) -> list[dict]:
        return self._request("GET", "/v1/profiles")

    def audit_events(self, limit: int = 200) -> list[dict]:
        return self._request("GET", f"/v1/audit-events?limit={int(limit)}")

    def iter_events(self, *, last_sequence: int = 0) -> Iterator[dict]:
        """Yield structured audit events from the resumable SSE stream."""
        headers = {"Accept": "text/event-stream"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if last_sequence:
            headers["Last-Event-ID"] = str(last_sequence)
        request = Request(self.base_url + "/v1/events/stream", headers=headers, method="GET")
        try:
            response = (self.opener.open if self.opener is not None else urlopen)(request, timeout=self.timeout)
        except HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            try:
                response_payload = json.loads(raw)
            except json.JSONDecodeError:
                response_payload = {}
            detail = response_payload.get("detail", raw)
            if isinstance(detail, dict):
                message = str(detail.get("message") or detail.get("reason_code") or detail)
                reason_code = detail.get("reason_code")
            else:
                message = str(detail)
                reason_code = None
            restriction = response_payload.get("restriction")
            raise RcnApiError(
                exc.code,
                message,
                reason_code=reason_code or (restriction or {}).get("reason_code"),
                restriction=restriction,
            ) from exc
        except URLError as exc:
            raise RcnApiError(0, "center connection failed", reason_code=network_failure_code(exc)) from exc
        event_type = ""
        data_lines: list[str] = []
        with response:
            for raw_line in response:
                line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
                if not line:
                    if event_type in {"state", "connected"} and data_lines:
                        try:
                            payload = json.loads("\n".join(data_lines))
                        except json.JSONDecodeError:
                            payload = None
                        if payload:
                            if event_type == "connected":
                                payload = {"_connected": True, **payload}
                            yield payload
                    elif not data_lines:
                        # The server emits a comment keepalive once per
                        # second. Exposing it lets callers enforce deadlines
                        # even when no state event has arrived.
                        yield {"_keepalive": True}
                    event_type = ""
                    data_lines = []
                    continue
                if line.startswith("event:"):
                    event_type = line[6:].strip()
                elif line.startswith("data:"):
                    data_lines.append(line[5:].lstrip())
