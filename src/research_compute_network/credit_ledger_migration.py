"""One atomic projection of legacy mixed credits into isolated ledgers.

The original account rows and append-only journal remain intact. Unknown legacy
unlimited funding is deliberately not inferred from today's global switch.
"""
from collections import defaultdict

from sqlalchemy import select


MIGRATION_ID = 'credit-ledger-scopes-v1'
SCOPES = {'real', 'shadow', 'legacy_shadow'}


def migrate_legacy_credits(session, *, account_type, legacy_type, reservation_type,
                           journal_type, migration_type, created_at):
    if session.get(migration_type, MIGRATION_ID) is not None:
        return None
    totals = defaultdict(lambda: [0, 0, 0, 0])
    scopes, ambiguous = {}, []
    reservations = session.scalars(select(reservation_type)).all()
    for row in reservations:
        payload = dict(row.payload)
        scope = payload.get('ledger_scope')
        if scope not in SCOPES:
            mode = payload.get('quota_mode', 'shadow')
            if mode == 'metered' and payload.get('metering_enforced') is True:
                scope = 'real'
            elif mode in {'shadow', 'metered'}:
                scope = 'shadow'
            else:
                scope = 'legacy_shadow'
                ambiguous.append(row.attempt_id)
        scopes[row.attempt_id] = scope
        payload.update(ledger_scope=scope, ledger_origin='legacy_projection')
        row.payload = payload
        if row.state in {'reserved', 'pending_review'}:
            held = totals[(row.requester_id, scope)]
            held[2] += int(payload.get('held_cpu_units', 0))
            held[3] += int(payload.get('held_gpu_units', 0))
    journal = session.scalars(select(journal_type)).all()
    for row in journal:
        scope = ('real' if row.payload.get('kind') == 'admin_adjustment'
                 else row.payload.get('ledger_scope') or scopes.get(row.attempt_id, 'legacy_shadow'))
        if scope not in SCOPES:
            scope = 'legacy_shadow'
        values = totals[(row.person_id, scope)]
        values[0] += int(row.payload.get('cpu_delta_units', 0))
        values[1] += int(row.payload.get('gpu_delta_units', 0))
    mismatched = []
    legacy = session.scalars(select(legacy_type)).all()
    projected_by_person = defaultdict(lambda: [0, 0, 0, 0])
    for (person, _), values in totals.items():
        for index in range(4):
            projected_by_person[person][index] += values[index]
    for row in legacy:
        projected = projected_by_person[row.person_id]
        difference = [row.cpu_units-projected[0], row.gpu_units-projected[1],
                      row.cpu_reserved-projected[2], row.gpu_reserved-projected[3]]
        if any(difference):
            mismatched.append(row.person_id)
            isolated = totals[(row.person_id, 'legacy_shadow')]
            isolated[0] += difference[0]
            isolated[1] += difference[1]
            # Holds with no supporting Attempt remain isolated. Never subtract
            # a proven live hold because an old mixed snapshot was inconsistent.
            isolated[2] += max(0, difference[2])
            isolated[3] += max(0, difference[3])
    for (person_id, scope), values in totals.items():
        session.add(account_type(person_id=person_id, ledger_scope=scope,
            cpu_units=values[0], gpu_units=values[1], cpu_reserved=values[2], gpu_reserved=values[3]))
    payload = {'created_at':created_at, 'legacy_account_count':len(legacy),
        'legacy_journal_count':len(journal), 'legacy_reservation_count':len(reservations),
        'ambiguous_attempt_ids':sorted(ambiguous), 'account_journal_mismatch_person_ids':sorted(mismatched),
        'automatic_conversion':False}
    session.add(migration_type(migration_id=MIGRATION_ID, payload=payload))
    return payload
