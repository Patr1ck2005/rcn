"""Read-only Fleet projection; never retire machines from telemetry guesses."""

from collections import defaultdict

from .models import MachinePolicy


def present_fleet(overview: dict, credentials: list) -> dict:
    """Add a scoped presentation without changing legacy operational contracts.

    Credential hashes and IDs deliberately never enter the response. An expired
    credential is not an explicitly revoked credential. Conflicting execution
    evidence keeps a record current, even when all credentials were revoked.
    """
    visible = {machine["machine_id"] for machine in overview["machines"]}
    active_flags = defaultdict(list)
    for credential in credentials:
        if credential.machine_id in visible:
            active_flags[credential.machine_id].append(credential.active)
    capacity = {item["machine_id"]: item for item in overview["capacity"]}
    historical = set()
    for machine in overview["machines"]:
        machine_id = machine["machine_id"]
        policy_data = overview["policies"].get(machine_id)
        if policy_data is not None:
            typed_policy = MachinePolicy.model_validate(policy_data)
            machine["effective_cpu_cap"] = typed_policy.effective_cpu_cap(machine.get("total_cpus", 0))
        config = overview["execution_configs"].get(machine_id)
        slots = capacity.get(machine_id, {})
        flags = active_flags[machine_id]
        revoked = bool(flags) and all(flag is False for flag in flags)
        idle = not machine.get("scheduled_active_units", 0) and not any(
            slots.get(key, 0)
            for key in ("occupied_slots", "reserved_slots", "prepared_reservations", "preparing_reservations")
        )
        is_history = revoked and (config is None or config.get("enabled") is False) and idle
        machine["record_state"] = "revoked_history" if is_history else "current"
        if is_history:
            historical.add(machine_id)

    current = [m for m in overview["machines"] if m["machine_id"] not in historical]
    statuses = overview["operational_statuses"]
    policies = overview["policies"]
    configs = overview["execution_configs"]
    online = [m for m in current if statuses.get(m["machine_id"], {}).get("supervisor_state") == "online"]
    schedulable = []
    for machine in online:
        machine_id = machine["machine_id"]
        policy = policies.get(machine_id, {})
        if (
            statuses[machine_id].get("telemetry_state") == "live"
            and (policy.get("admin_mode_override") or policy.get("owner_mode")) == "open"
            and (machine_id not in configs or configs[machine_id].get("enabled"))
        ):
            schedulable.append(machine)
    summary = dict(overview["summary"])
    summary.update(
        total_machines=len(current), historical_machines=len(historical),
        online_machines=len(online), offline_machines=len(current) - len(online),
        available_memory_mb=sum(m["metrics"].get("available_memory_mb", 0) for m in schedulable),
        available_cpus=sum(m.get("effective_cpu_cap", 0) for m in schedulable),
        available_gpus=sum(min(m.get("total_gpus", 0), policies[m["machine_id"]].get("max_gpus", 0)) for m in schedulable),
        alert_count=sum(item.get("machine_id") not in historical for item in overview["alerts"]),
    )
    for key in (
        "validated_slots", "eligible_slots", "occupied_slots", "overcommitted_slots",
        "physical_available_slots", "reserved_slots", "prepared_reservations", "preparing_reservations",
    ):
        summary[key] = sum(item.get(key, 0) for machine_id, item in capacity.items() if machine_id not in historical)
    overview["fleet_summary"] = summary
    return overview
