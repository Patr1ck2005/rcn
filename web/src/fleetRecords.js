export const isHistorical = (machine) => machine?.record_state === "revoked_history";

export function fleetRecords(machines = [], query = "", selected = "") {
  const matches = (machine) => `${machine.machine_id} ${machine.owner_user_id} ${(machine.capabilities || []).join(" ")}`.toLowerCase().includes(query.toLowerCase());
  const current = machines.filter((machine) => !isHistorical(machine));
  const currentIds = new Set(current.map((machine) => machine.machine_id));
  return {
    current,
    rows: current.filter(matches),
    historical: machines.filter(isHistorical),
    historicalMatches: machines.filter((machine) => isHistorical(machine) && matches(machine)),
    selectedIds: [...new Set(selected.split(","))].filter((id) => currentIds.has(id)).slice(0, 5),
  };
}
