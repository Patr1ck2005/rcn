export async function controlRunByTicket(request, ticketId) {
  const run = await request(`/v1/admin/control-runs/by-ticket/${encodeURIComponent(ticketId)}`);
  if (!run?.operation_id || run.ticket_id !== ticketId) throw new Error("控制回执与原票据不匹配");
  return run;
}

// A dropped HTTP reply is not evidence that the audited operation failed.
// Recover the original run before offering another confirmation of this ticket.
export async function confirmControlTicket(request, path, body, { recoverFirst = false } = {}) {
  if (recoverFirst) {
    try { return await controlRunByTicket(request, body.ticket_id); }
    catch (caught) { if (caught.status !== 404) throw caught; }
  }
  try {
    const run = await request(path, { method: "POST", body: JSON.stringify(body) });
    if (!run?.operation_id || run.ticket_id !== body.ticket_id) throw new Error("未收到与原票据匹配的控制回执");
    return run;
  } catch (caught) {
    try { return await controlRunByTicket(request, body.ticket_id); }
    catch { throw caught; }
  }
}
