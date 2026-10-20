"""HTTP routes for canonical machine observations."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Query

from .auth import AuthContext, PilotAuthenticator
from .hashing import sha256_value
from .models import FeatureVisibility, MachineHeartbeat, MachineState, UserRole
from .repository import MetadataRepository
from .service import NetworkService


def build_machine_observation_router(
    *,
    repository: MetadataRepository,
    service: NetworkService,
    auth: PilotAuthenticator,
    require_machine_detail_visibility: Callable[[str, AuthContext], MachineState],
    wake_dispatcher: Callable[..., None],
    public_execution_config: Callable[..., dict],
) -> APIRouter:
    router = APIRouter()

    @router.get("/v1/machines")
    def machines(context: AuthContext = Depends(auth.actor)) -> list[dict]:
        result = []
        settings = repository.get_feature_settings()
        visible_machines = repository.list_machines()
        if UserRole.ADMIN not in context.roles and settings.visibility == FeatureVisibility.OWN_DETAIL:
            visible_machines = [
                machine
                for machine in visible_machines
                if machine.owner_user_id == context.actor_id
            ]
        for machine in visible_machines:
            item = machine.model_dump(mode="json")
            runtime = repository.get_machine_operational_status(machine.machine_id)
            config = repository.get_machine_execution_config(machine.machine_id)
            item["operational_status"] = runtime.model_dump(mode="json") if runtime else None
            item["execution_config"] = (
                public_execution_config(
                    config,
                    include_connection_details=(
                        UserRole.ADMIN in context.roles
                        or machine.owner_user_id == context.actor_id
                    ),
                )
                if config
                else None
            )
            result.append(item)
        return result

    @router.get("/v1/machines/{machine_id}/policy")
    def machine_policy(
        machine_id: str,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        require_machine_detail_visibility(machine_id, context)
        policy = repository.get_policy(machine_id)
        if policy is None:
            raise HTTPException(status_code=404, detail="machine policy not found")
        return policy.model_dump(mode="json")

    @router.get("/v1/machines/{machine_id}/operational-status")
    def machine_operational_status(
        machine_id: str,
        context: AuthContext = Depends(auth.actor),
    ) -> dict:
        require_machine_detail_visibility(machine_id, context)
        status = repository.get_machine_operational_status(machine_id)
        if status is None:
            raise HTTPException(status_code=404, detail="machine operational status not found")
        return status.model_dump(mode="json")

    @router.get("/v1/machines/{machine_id}/metrics")
    def machine_metrics(
        machine_id: str,
        window: str = Query(default="1h", pattern="^(1h|6h|24h)$"),
        context: AuthContext = Depends(auth.actor),
    ) -> list[dict]:
        require_machine_detail_visibility(machine_id, context)
        now = datetime.now(timezone.utc)
        duration = timedelta(hours={"1h": 1, "6h": 6, "24h": 24}[window])
        kind = "raw" if window in {"1h", "6h"} else "minute"
        return [
            sample.model_dump(mode="json")
            for sample in repository.list_metric_samples(
                machine_id,
                sample_kind=kind,
                since=now - duration,
                limit=5000,
            )
        ]

    @router.post("/v1/machines/{machine_id}/heartbeat")
    def heartbeat(
        machine_id: str,
        heartbeat: MachineHeartbeat,
        authorization: str | None = Header(default=None),
    ) -> dict:
        if heartbeat.machine_id != machine_id:
            raise HTTPException(status_code=400, detail="machine ID mismatch")
        auth.machine_agent(machine_id, authorization)
        try:
            machine = service.record_heartbeat(
                heartbeat,
                actor_id=f"machine-agent:{machine_id}",
            )
            wake_dispatcher(reason=f"heartbeat:{machine_id}")
            payload = machine.model_dump(mode="json")
            observed = repository.get_machine_operational_status(machine_id)
            ssh_evidence = observed.connection_evidence.get("ssh") if observed else None
            payload["control_plane_observation"] = {
                "transport_state": observed.transport_state.value if observed and ssh_evidence else "unknown",
                "executor_state": observed.supervisor_state.value if observed else "unavailable",
                "telemetry_state": observed.telemetry_state.value if observed else "unavailable",
                "control_state": observed.control_state.value if observed else "executor_unavailable",
                # This timestamp belongs to the SSH check, not this HTTP reply.
                # A non-null old epoch avoids legacy workers substituting now.
                "observed_at": ssh_evidence.observed_at if ssh_evidence else datetime.fromtimestamp(0, timezone.utc),
            }
            config = repository.get_machine_execution_config(machine_id)
            if config is not None:
                desired_policy = config.telemetry_policy.model_dump(mode="json")
                payload["desired_telemetry_policy"] = desired_policy
                payload["desired_telemetry_policy_sha256"] = sha256_value(desired_policy)
            return payload
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    return router
