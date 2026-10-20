"""Read-only cluster/project operational insights; no scheduler or scientific writes.

Only the compact Job read model is selected. UI page limits, scientific blobs,
credentials, remote I/O and production mutations are deliberately absent.
Forecasts describe the current queue at its observed share of compute; they are
not a placement promise, statistical confidence interval, or scientific score.
"""
from __future__ import annotations

from collections import Counter, defaultdict, OrderedDict
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import math
import json
import statistics
import threading
import time

from sqlalchemy import JSON, Float, Integer, LargeBinary, Text, and_, cast, case, func, literal, or_, select, true
from sqlalchemy.exc import OperationalError

from .models import FeatureVisibility, MachineMode, UserRole
from .policy import active_window
from .repository import JobRow
from .read_models import JobReadRow, UnitReadRow, AttemptReadRow, epoch_microseconds

TERMINAL = {'completed', 'cancelled', 'failed_terminal'}
ACTIVE = {'running', 'assigned'}
WAITING = {'queued', 'prepared', 'staged', 'failed_retriable'}
RECOVERING = {'collecting', 'reconcile_pending', 'uncertain', 'cancel_pending'}
PENDING_ATTEMPTS = ACTIVE | RECOVERING | {'submitting'}
BLOCKED = {'blocked', 'awaiting_approval', 'awaiting_environment'}
BUCKETS = ('completed', 'running', 'waiting', 'collecting', 'attention', 'cancelled')
MAX_JOBS = 5000
MAX_ROW_BYTES = 8 * 1024 * 1024
MAX_UNITS = 250000
MAX_TOTAL_CHARS = 32 * 1024 * 1024
MAX_PROJECTS = 500
WINDOWS = (1, 6, 24, 168)
SQLITE_PACK_ROWS = 256


def _insight_rows(session, statement, *, max_rows, budget):
    """Bound SQLite JSON batches by actual UTF-8 bytes in the caller's snapshot.

    The original stream remains the portable/oversized path. Ordinals preserve
    ordered selections independently of JSON aggregate input order. Each read's
    three packed results share one byte budget; no facts survive this call.
    """
    dialect = session.get_bind().dialect
    if dialect.name != 'sqlite':
        yield from session.execute(statement).mappings()
        return
    columns = list(statement.selected_columns)
    ordered = statement.add_columns(func.row_number().over(
        order_by=tuple(statement._order_by_clauses)).label('_insight_ordinal')).subquery()
    values = []
    invalid_json = []
    for column in columns:
        value = ordered.c[column.key]
        if isinstance(column.type, JSON):
            invalid_json.append(and_(value.is_not(None), func.json_valid(value) != 1))
            value = func.json(value)
        elif isinstance(column.type, Float):
            # SQLite's JSON numeric formatter rounds binary floats to about
            # 15 digits. A round-trippable string preserves the typed reader.
            value = case((value.is_(None), None), else_=func.printf('%!.26g', value))
        values.append(value)
    # json() accepts JSON5 in newer SQLite. Preserve the original Python
    # decoder's semantics by sending all non-standard JSON through that reader.
    invalid = case((or_(*invalid_json), 1), else_=0) if invalid_json else literal(0)
    encoded = select(ordered.c._insight_ordinal.label('ordinal'),
        func.json_array(ordered.c._insight_ordinal, *values).label('payload'),
        invalid.label('invalid')).subquery()
    size = func.length(cast(encoded.c.payload, LargeBinary))
    try:
        count, total, largest, invalid = session.execute(select(func.count(), func.sum(size),
            func.max(size), func.sum(encoded.c.invalid)).select_from(encoded)).one()
    except OperationalError as exc:
        if 'malformed json' not in str(exc.orig).lower():
            raise
        # Preserve the original typed reader's malformed-JSON exception.
        yield from session.execute(statement).mappings()
        return
    batches = math.ceil(count / SQLITE_PACK_ROWS)
    required = int(total or 0) + count + batches  # commas and batch brackets
    if invalid or count > max_rows or int(largest or 0) > MAX_ROW_BYTES or required > budget[0]:
        yield from session.execute(statement).mappings()
        return
    if not count:
        return
    budget[0] -= required
    batch = cast((encoded.c.ordinal-1)/SQLITE_PACK_ROWS, Integer)
    packed = select(batch, func.json_group_array(func.json(encoded.c.payload))).group_by(batch).order_by(batch)
    processors = [None if isinstance(column.type, JSON) else
        column.type.dialect_impl(dialect).result_processor(dialect, None) for column in columns]
    for _batch, payload in session.execute(packed):
        rows = json.loads(payload)
        rows.sort(key=lambda row: row[0])
        for row in rows:
            value = {}
            for column, processor, item in zip(columns, processors, row[1:]):
                if item is not None:
                    if processor is not None:
                        item = processor(item)
                    elif isinstance(column.type, Float):
                        item = float(item)
                value[column.key] = item
            yield value


def _number(value, default=0.0):
    if isinstance(value, bool):
        return default
    try:
        number = float(value)
        return number if math.isfinite(number) and 0 <= number <= 1e15 else default
    except (ValueError, TypeError, OverflowError):
        return default


def _at(value):
    if not value:
        return None
    try:
        parsed = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError):
        return None


def _fresh(value, now, seconds=90):
    at = _at(value)
    return at is not None and -5 <= (now - at).total_seconds() <= seconds


def _percent(numerator, denominator):
    return round(100 * numerator / denominator, 1) if denominator > 0 else None


def _resources(unit, attempt=None):
    # Attempt resources are the frozen actual allocation, not the requested plan.
    return ((attempt or {}).get('resolved_resources') or {}).get('resources') or (
        unit.get('resolved_resources') or {}).get('resources') or unit.get('resources') or {}


def _pending_attempts(unit):
    if '_pending_states' in unit:
        return [{'state': state} for state in unit['_pending_states']]
    attempts = [a for a in (unit.get('attempts') or []) if isinstance(a, dict)]
    pending = [a for a in attempts if a.get('state') in PENDING_ATTEMPTS]
    latest = attempts[-1] if attempts else {}
    # Match the Dispatcher's unresolved remote-recovery contract. A failed
    # Attempt or historical machine attribution alone is not current work.
    if (unit.get('status') not in {'completed', 'cancelled'}
            and latest.get('state') == 'failed'
            and latest.get('failure_class') == 'infrastructure'
            and latest.get('external_run_id') and not latest.get('execution_completed')
            and str(latest.get('failure_reason') or unit.get('failure_reason') or '').startswith('remote state remained uncertain:')):
        pending.append(latest)
    return pending


def _pending_projection(repository):
    if hasattr(repository, "pending_job_predicate"):
        return repository.pending_job_predicate(PENDING_ATTEMPTS)
    if repository.engine.dialect.name == 'sqlite':
        units = func.json_each(JobRow.operational_payload, '$.work_units').table_valued('key', 'value').alias('insight_unit')
        attempts = func.json_each(units.c.value, '$.attempts').table_valued('key', 'value').alias('insight_attempt')
        value = lambda key: func.json_extract(attempts.c.value, '$.' + key)
        uncertain = and_(
            attempts.c.key == func.json_array_length(func.json_extract(units.c.value, '$.attempts')) - 1,
            func.coalesce(func.json_extract(units.c.value, '$.status'), '').not_in(['completed', 'cancelled']),
            value('state') == 'failed', value('failure_class') == 'infrastructure',
            func.coalesce(value('external_run_id'), '') != '',
            func.coalesce(value('execution_completed'), 0) == 0,
            func.coalesce(func.nullif(value('failure_reason'), ''),
                          func.json_extract(units.c.value, '$.failure_reason'), '').like('remote state remained uncertain:%'),
        )
        return select(1).select_from(units.join(attempts, true())).where(
            or_(value('state').in_(sorted(PENDING_ATTEMPTS)), uncertain)).correlate(JobRow).exists()
    # Portable conservative prefilter. False positives only load a bounded
    # metadata projection; the typed aggregate still verifies actual Attempts.
    compact = func.replace(cast(JobRow.operational_payload, Text), ' ', '')
    return or_(*(compact.contains('"state":"' + state + '"') for state in sorted(PENDING_ATTEMPTS)),
               compact.contains('remotestateremaineduncertain:'))


def _read_legacy_jobs(repository, *, now, user_id=None, visibility=None, max_jobs=MAX_JOBS):
    """Bounded SQL projection, never fallback to Job.payload/scientific blobs.

    Read active Jobs plus recently updated history (7 days for calibration).
    Incomplete read models and safety limits are explicit, not an empty fleet.
    """
    active = or_(~JobRow.status.in_(sorted(TERMINAL)), _pending_projection(repository))
    projection_length = func.length(cast(JobRow.operational_payload, Text))
    statement = select(JobRow.job_id, case(
        (projection_length <= MAX_ROW_BYTES, JobRow.operational_payload),
        else_=None,
    ).label('projection'), projection_length.label('projection_chars')).where(or_(active, JobRow.updated_at >= now - timedelta(days=7)))
    statement = repository._filter_jobs(statement, user_id=user_id, visibility=visibility)
    statement = statement.order_by(active.desc(), JobRow.updated_at.desc(), JobRow.job_id).limit(max_jobs + 1)
    truncated = False
    jobs = []
    missing = units = scanned = characters = 0
    with repository._session() as session:
        # Stream one bounded projection at a time, never materialize every row
        # before enforcing the aggregate memory/unit guard.
        result = session.execute(statement.execution_options(stream_results=True, yield_per=1))
        for index, row in enumerate(result):
            if index >= max_jobs:
                truncated = True
                break
            scanned += 1
            value = row.projection
            if not isinstance(value, dict) or not isinstance(value.get('work_units'), list):
                missing += 1
                continue
            if units + len(value['work_units']) > MAX_UNITS or characters + int(row.projection_chars or 0) > MAX_TOTAL_CHARS:
                truncated = True
                break
            units += len(value['work_units'])
            characters += int(row.projection_chars or 0)
            jobs.append(value)
        result.close()
    return jobs, {'jobs_scanned': scanned, 'units_scanned': units,
        'missing_or_oversized_projections': missing, 'source_truncated': truncated,
        'job_limit': max_jobs, 'unit_limit': MAX_UNITS, 'character_limit': MAX_TOTAL_CHARS,
        'projection_characters_scanned': characters, 'scientific_payloads_loaded': False}


def read_jobs(repository, *, now, user_id=None, visibility=None, max_jobs=MAX_JOBS,
              window_hours=24):
    """Read narrow Unit facts and SQL Attempt aggregates, never Job histories.

    Last-success and earliest-start facts cover all history for calibration;
    terminal counters/core time are aggregated in SQL for the requested window.
    The same explicit source limits and authorization apply before selection.
    """
    active = or_(~JobRow.status.in_(sorted(TERMINAL)), _pending_projection(repository))
    statement = select(JobRow.job_id, JobRow.status, JobRow.updated_at,
        JobReadRow.insight_payload,
        or_(JobRow.operational_payload.is_(None), cast(JobRow.operational_payload, Text) == 'null').label('missing')
    ).outerjoin(JobReadRow, JobReadRow.job_id == JobRow.job_id).where(
        or_(active, JobRow.updated_at >= now-timedelta(days=7)))
    statement = repository._filter_jobs(statement, user_id=user_id, visibility=visibility)
    statement = statement.order_by(active.desc(), JobRow.updated_at.desc(), JobRow.job_id).limit(max_jobs+1)
    jobs, by_id = [], {}
    scanned = units = characters = missing = 0
    truncated = False
    with repository._session() as session:
        if repository.engine.dialect.name == 'sqlite':
            connection = session.connection()
            if not connection.connection.driver_connection.in_transaction:
                connection.exec_driver_sql('BEGIN')
        packed_budget = [MAX_TOTAL_CHARS]
        for index, row in enumerate(_insight_rows(session, statement, max_rows=max_jobs+1, budget=packed_budget)):
            if index >= max_jobs:
                truncated = True; break
            scanned += 1
            value = row['insight_payload']
            if row['missing'] or not isinstance(value, dict) or value.get('_operational_chars', MAX_ROW_BYTES+1) > MAX_ROW_BYTES:
                missing += 1; continue
            amount = int(value.get('_operational_chars') or 0)
            count = int(value.get('_unit_count') or 0)
            if characters+amount > MAX_TOTAL_CHARS or units+count > MAX_UNITS:
                truncated = True; break
            units += count; characters += amount
            value = dict(value, status=row['status'], updated_at=row['updated_at'], work_units=[])
            jobs.append(value); by_id[row['job_id']] = value
        ids = list(by_id)
        if ids:
            # One bound JSON array avoids expanding the same 5,000 authorized
            # identifiers into SQL parameters for every child aggregate.
            selected_ids = (select(func.json_each(json.dumps(ids)).table_valued('value').c.value)
                if repository.engine.dialect.name == 'sqlite' else ids)
            # Malformed globally repeated Attempt identities retain the pure
            # reader's original de-duplication order rather than multiplying
            # an ambiguous timing fact in SQL. This bounded repair path is rare.
            duplicate = session.scalar(select(AttemptReadRow.attempt_id).where(
                AttemptReadRow.job_id.in_(selected_ids)).group_by(AttemptReadRow.attempt_id)
                .having(func.count() > 1).limit(1))
            if duplicate:
                return _read_legacy_jobs(repository, now=now, user_id=user_id,
                    visibility=visibility, max_jobs=max_jobs)
            unit_by_id = {}
            unit_statement = (select(UnitReadRow.job_id,
                    UnitReadRow.work_unit_id, UnitReadRow.insight_payload).where(UnitReadRow.job_id.in_(selected_ids))
                    .order_by(UnitReadRow.job_id, UnitReadRow.ordinal, UnitReadRow.work_unit_id))
            for row in _insight_rows(session, unit_statement, max_rows=MAX_UNITS, budget=packed_budget):
                jid, uid, payload = row['job_id'], row['work_unit_id'], row['insight_payload']
                if not isinstance(payload, dict):
                    continue
                value = dict(payload, _attempt_metrics={})
                by_id[jid]['work_units'].append(value)
                unit_by_id[jid, uid] = value
            cutoff = now-timedelta(hours=window_hours)
            a = AttemptReadRow
            cutoff_us, now_us = epoch_microseconds(cutoff), epoch_microseconds(now)
            bucket = cast((a.finished_epoch_us-cutoff_us)/(window_hours*3600*1000000/24), Integer)
            bucket = case((bucket >= 24, 23), else_=bucket)
            timed = and_(a.started_epoch_us.is_not(None), a.started_epoch_us < a.finished_epoch_us, a.allocated_cpus > 0)
            overlap = (a.finished_epoch_us-case((a.started_epoch_us < cutoff_us, cutoff_us),
                else_=a.started_epoch_us))/1000000.0*a.allocated_cpus
            fields = {
                'terminal_attempts': func.count(),
                'successful_attempts': func.sum(case((a.state == 'completed', 1), else_=0)),
                'failed_attempts': func.sum(case((a.state == 'failed', 1), else_=0)),
                'cancelled_attempts': func.sum(case((a.state == 'cancelled', 1), else_=0)),
                'timed_attempts': func.sum(case((timed, 1), else_=0)),
                'successful_core_seconds': func.sum(case((and_(timed, a.state == 'completed'), overlap), else_=0)),
                'unsuccessful_core_seconds': func.sum(case((and_(timed, a.state != 'completed'), overlap), else_=0)),
            }
            aggregate = select(a.job_id, a.work_unit_id, bucket.label('bucket'),
                *(value.label(name) for name, value in fields.items())).where(a.job_id.in_(selected_ids),
                a.state.in_(['completed', 'failed', 'cancelled']), a.finished_epoch_us >= cutoff_us, a.finished_epoch_us <= now_us
            ).group_by(a.job_id, a.work_unit_id, bucket)
            for row in _insight_rows(session, aggregate, max_rows=MAX_UNITS*24, budget=packed_budget):
                unit = unit_by_id.get((row['job_id'], row['work_unit_id']))
                if unit is None:
                    continue
                metrics = unit['_attempt_metrics']
                for name in fields:
                    metrics[name] = metrics.get(name, 0) + (row[name] or 0)
                if row['failed_attempts']:
                    metrics.setdefault('failed_bins', []).append((row['bucket'], row['failed_attempts']))
    complete_jobs = []
    for job in jobs:
        if len(job['work_units']) != job['_unit_count']:
            missing += 1
        else:
            complete_jobs.append(job)
    return complete_jobs, {'jobs_scanned': scanned, 'units_scanned': units,
        'missing_or_oversized_projections': missing, 'source_truncated': truncated,
        'job_limit': max_jobs, 'unit_limit': MAX_UNITS, 'character_limit': MAX_TOTAL_CHARS,
        'projection_characters_scanned': characters, 'scientific_payloads_loaded': False,
        'read_model': 'indexed-unit-facts-and-sql-attempt-aggregates', 'attempt_histories_loaded': False}


def machine_snapshot(repository, *, now, owner_id=None, allowed_machine_ids=None):
    all_machines = repository.list_machines()
    if not all_machines:
        return []
    policies = {p.machine_id: p for p in (repository.get_policy(m.machine_id) for m in all_machines) if p}
    configs = {c.machine_id: c for c in repository.list_machine_execution_configs()}
    statuses = {s.machine_id: s for s in repository.list_machine_operational_statuses()}
    running = repository.list_attempt_counts_by_state({'running'})
    occupied = repository.list_active_attempt_counts()
    rows = []
    for m in all_machines:
        if owner_id is not None and m.owner_user_id != owner_id:
            continue
        if allowed_machine_ids is not None and m.machine_id not in allowed_machine_ids:
            continue
        p, c, s = policies.get(m.machine_id), configs.get(m.machine_id), statuses.get(m.machine_id)
        live = bool(s and s.supervisor_state == 'online' and s.telemetry_state == 'live'
                    and m.metrics.available and _fresh(m.metrics.observed_at, now)
                    and _fresh(s.last_supervisor_heartbeat_at or m.last_heartbeat_at, now))
        enabled = c is None or c.enabled
        opened = bool(p and p.effective_mode() == MachineMode.OPEN)
        scheduled = bool(p and active_window(p, now) is not None)
        target = min(p.max_concurrent_units if p else 0,
                     c.target_concurrent_units if c else (p.max_concurrent_units if p else 0))
        observed_cap = s.effective_capacity if s and s.effective_capacity is not None else (
            s.effective_comsol_concurrency if s else None)
        cap = min(target, observed_cap if observed_cap is not None else target)
        eligible = live and enabled and opened and scheduled and bool(s and s.control_state == 'accepting')
        slots = max(0, cap) if eligible else 0
        reason = 'ready' if eligible else ('telemetry_unavailable' if not live else 'disabled' if not enabled
                 else 'owner_paused' if not opened else 'outside_schedule' if not scheduled else 'control_not_accepting')
        rows.append({'machine_id': m.machine_id, 'live': live, 'eligible': eligible,
            'effective_slots': slots, 'target_slots': target,
            'running_units': running.get(m.machine_id, 0), 'occupied_slots': occupied.get(m.machine_id, 0),
            'cpu_budget': p.effective_cpu_cap(m.total_cpus) if p else 0,
            'cpu_percent': _number(m.metrics.cpu_current_percent if m.metrics.cpu_current_percent is not None
                                   else m.metrics.cpu_total_percent, None) if live else None,
            'network_cpu_percent': _number(m.metrics.network_cpu_percent, None) if live else None,
            'observed_at': m.metrics.observed_at.isoformat() if live else None, 'reason': reason})
    return sorted(rows, key=lambda x: (-x['running_units'], x['machine_id']))


def _calibration(job):
    # Do not pool unrelated templates/projects or compare raw Unit speeds.
    ratios = []
    for u in job.get('work_units', []):
        if not isinstance(u, dict) or u.get('status') != 'completed':
            continue
        expected, actual = _number(u.get('expected_duration_s')), _number(u.get('actual_duration_s'))
        if expected and actual:
            ratio = _number(actual / expected)
            if ratio: ratios.append(ratio)
    return (statistics.median(ratios) if len(ratios) >= 3 else 1.0), len(ratios)


def _estimate(remaining, completions, starts, active_slots, active_tail, unknown, blocked, recovering,
              now, incomplete=False, calibrated=0):
    result = {'seconds': None, 'lower_seconds': None, 'upper_seconds': None, 'finish_at': None,
              'confidence': 'unknown', 'basis': 'no_work', 'sample_count': 0,
              'remaining_serial_seconds': round(remaining, 1), 'active_slots': active_slots,
              'unknown_units': unknown, 'blocked_units': blocked, 'recovering_units': recovering}
    if incomplete:
        result['basis'] = 'incomplete_source'
    elif blocked:
        result['basis'] = 'blocked_work'
    elif unknown or recovering:
        result['basis'] = 'recovery_or_missing_duration'
    elif not remaining:
        result.update(seconds=0.0, lower_seconds=0.0, upper_seconds=0.0, finish_at=now.isoformat(), confidence='complete')
    elif active_slots <= 0:
        result['basis'] = 'waiting_for_dispatch_or_fresh_telemetry'
    else:
        rate = None
        recent = []
        first = min(starts) if starts else now
        for span in (3600, 21600):
            recent = [(at, weight) for at, weight in completions if now-timedelta(seconds=span) <= at <= now]
            if len(recent) >= 3:
                exposure = min(span, max(300, (now-first).total_seconds()))
                rate = sum(weight for _, weight in recent) / exposure
                result['rate_window_seconds'] = exposure
                break
        result['sample_count'] = len(recent) if rate else calibrated
        if rate and rate > 0:
            seconds = max(active_tail, remaining / rate)
            result.update(basis='observed_work_rate', confidence='medium' if len(recent) >= 5 else 'low')
        else:
            seconds = max(active_tail, remaining / active_slots)
            result.update(basis='current_slots_calibrated' if calibrated >= 3 else 'current_slots_declared',
                          confidence='low')
        if math.isfinite(seconds) and seconds <= 3650*86400:
            # A scenario band, not a calibrated statistical confidence interval.
            spread = .3 if result['confidence'] == 'medium' else .6
            result.update(seconds=round(seconds, 1), lower_seconds=round(max(active_tail, seconds*(1-spread)), 1),
                          upper_seconds=round(seconds*(1+spread), 1), finish_at=(now+timedelta(seconds=seconds)).isoformat())
        else:
            result.update(basis='outside_forecast_horizon', confidence='unknown')
    return result


def build_insights(jobs, machines, *, now, window_hours=24, source=None, include_demo=False,
                   dispatcher_open=True):
    """Pure aggregate, deterministic clock; never emits a job's scientific data."""
    if window_hours not in WINDOWS:
        raise ValueError('window_hours must be 1, 6, 24 or 168')
    source = dict(source or {})
    cutoff = now-timedelta(hours=window_hours)
    bin_count = 24
    bin_s = window_hours*3600/bin_count
    machine_by_id = {m['machine_id']: m for m in machines}
    projects = {}
    job_estimates = {}
    bad_rows = 0
    ignored = 0
    timeline_at = [(cutoff+timedelta(seconds=i*bin_s)).isoformat() for i in range(bin_count)]

    def group(identity):
        return {'project_id': identity, 'job_count': 0, 'active_jobs': 0, 'counts': Counter(),
                'completed_in_window': 0, 'failed_attempts': 0, 'successful_attempts': 0,
                'cancelled_attempts': 0, 'timed_attempts': 0, 'terminal_attempts': 0,
                'successful_core_seconds': 0.0, 'unsuccessful_core_seconds': 0.0,
                'timeline': [{'at': at, 'completed': 0, 'failed': 0} for at in timeline_at],
                '_remaining': 0.0, '_completions': [], '_starts': [], '_slots': 0,
                '_tail': 0.0, '_unknown': 0, '_blocked': 0, '_recovering': 0, '_calibrated': 0}

    def bin_index(at):
        return min(bin_count-1, max(0, int((at-cutoff).total_seconds()/bin_s)))

    seen_jobs, seen_units, seen_attempts = set(), set(), set()
    for job in jobs:
        if not isinstance(job, dict) or not job.get('job_id') or job['job_id'] in seen_jobs:
            bad_rows += 1; continue
        seen_jobs.add(job['job_id'])
        if job.get('record_class', 'production') not in ({'production', 'demo'} if include_demo else {'production'}):
            ignored += 1; continue
        units = job.get('work_units') or []
        terminal_job = job.get('status') in TERMINAL
        is_active = not terminal_job or any(
            isinstance(u,dict) and _pending_attempts(u) for u in units)
        if not is_active and (_at(job.get('updated_at')) or datetime.min.replace(tzinfo=timezone.utc)) < cutoff:
            continue
        pid = str(job.get('project_id') or 'unassigned')
        g = projects.get(pid)
        if g is None:
            g = projects[pid] = group(pid)
        # Historical Jobs have no individual forecast or remaining work.
        # Accumulate them directly, avoiding a temporary 24-bin group and
        # another full merge for every completed Job in a large ledger.
        jg = group(pid) if is_active else g
        g['job_count'] += 1
        g['active_jobs'] += int(is_active)
        ratio, samples = _calibration(job)
        jg['_calibrated'] += samples
        start = _at(job.get('created_at'))
        # Actual start, not queue submission, determines short-job exposure.
        actual_starts = [
            _at(u.get('_first_attempt_started_at')) if '_first_attempt_started_at' in u else _at(a.get('started_at'))
            for u in units if isinstance(u, dict)
            for a in ([{}] if '_first_attempt_started_at' in u else (u.get('attempts') or [])) if isinstance(a, dict)]
        actual_starts = [at for at in actual_starts if at and at <= now]
        jg['_starts'].extend(actual_starts or ([start] if start and start <= now else []))
        for unit in units:
            if not isinstance(unit,dict):
                bad_rows += 1; continue
            uid = (job['job_id'], unit.get('work_unit_id'))
            if not unit.get('work_unit_id') or uid in seen_units:
                bad_rows += 1; continue
            seen_units.add(uid)
            state = unit.get('status', 'unknown')
            pending = _pending_attempts(unit) if terminal_job else []
            bucket = ('completed' if state=='completed' else 'cancelled' if state=='cancelled'
                      else 'attention' if state=='failed_terminal' or (state in WAITING and job.get('status') in BLOCKED)
                      else 'running' if state=='running' else 'collecting' if state in RECOVERING
                      else 'waiting' if state in WAITING|{'assigned'} else 'attention')
            if terminal_job:
                if pending:
                    # Terminal Jobs cannot enqueue work, but original Attempts
                    # still need truthful cancellation/reconciliation evidence.
                    bucket = 'running' if any(a.get('state') == 'running' for a in pending) else 'collecting'
                    jg['_recovering'] += 1
                elif state not in {'completed', 'cancelled'}:
                    bucket = 'cancelled' if job.get('status') == 'cancelled' else 'attention'
            jg['counts'][bucket] += 1
            attempts = [a for a in (unit.get('attempts') or []) if isinstance(a,dict)]
            latest = attempts[-1] if attempts else {}
            expected = _number(_number(unit.get('expected_duration_s')) * ratio)
            if state=='completed':
                success = next((a for a in reversed(attempts) if a.get('state')=='completed'), {})
                finished = (_at(unit['_successful_finished_at']) if '_successful_finished_at' in unit
                    else _at(success.get('collected_at')) or _at(success.get('finished_at')))
                if finished and finished <= now:
                    jg['_completions'].append((finished, expected))
                    if finished >= cutoff:
                        jg['completed_in_window'] += 1
                        jg['timeline'][bin_index(finished)]['completed'] += 1
            elif not terminal_job and state not in {'cancelled','failed_terminal'}:
                if bucket=='attention': jg['_blocked'] += 1
                if bucket=='collecting': jg['_recovering'] += 1
                remaining = expected
                if state in ACTIVE:
                    m = machine_by_id.get(latest.get('machine_id') or unit.get('assigned_machine_id'))
                    if m and m.get('live') and dispatcher_open:
                        jg['_slots'] += 1
                    reported = _number(unit.get('eta_s'))
                    observed = latest.get('last_observed_at') or unit.get('updated_at')
                    if reported and m and m.get('live') and _fresh(observed, now, 120):
                        remaining = reported
                    elif state=='running' and expected:
                        at = _at(latest.get('started_at'))
                        elapsed = max(0,(now-at).total_seconds()) if at else 0
                        if (at and at > now + timedelta(seconds=5)) or elapsed > max(3*expected, expected+3600):
                            # A badly overrun prediction must not say '45 seconds'
                            # forever. Keep running state but withdraw the ETA.
                            remaining = 0
                        else:
                            remaining = max(expected-elapsed, .15*expected)
                    jg['_tail'] = max(jg['_tail'], remaining)
                if remaining <= 0: jg['_unknown'] += 1
                jg['_remaining'] += remaining
            if '_attempt_metrics' in unit:
                metrics = unit['_attempt_metrics']
                for key in ('terminal_attempts', 'successful_attempts', 'failed_attempts', 'cancelled_attempts',
                            'timed_attempts', 'successful_core_seconds', 'unsuccessful_core_seconds'):
                    jg[key] += metrics.get(key, 0)
                for index, amount in metrics.get('failed_bins', []):
                    jg['timeline'][index]['failed'] += amount
            for a in ([] if '_attempt_metrics' in unit else attempts):
                identity = a.get('attempt_id')
                if not identity or identity in seen_attempts: continue
                seen_attempts.add(identity)
                ended = _at(a.get('finished_at'))
                astate = a.get('state')
                if astate not in {'completed','failed','cancelled'} or ended is None or not cutoff <= ended <= now:
                    continue
                jg['terminal_attempts'] += 1
                label = {'completed':'successful_attempts','failed':'failed_attempts','cancelled':'cancelled_attempts'}[astate]
                jg[label] += 1
                if astate=='failed': jg['timeline'][bin_index(ended)]['failed'] += 1
                began = _at(a.get('started_at'))
                cpus = _number(_resources(unit,a).get('cpus'))
                if began and began < ended and cpus:
                    # Completed-at-window cohort, overlap clipped to the window.
                    seconds = max(0,(ended-max(began,cutoff)).total_seconds())*cpus
                    key = 'successful_core_seconds' if astate=='completed' else 'unsuccessful_core_seconds'
                    jg[key] += seconds
                    jg['timed_attempts'] += 1
        if jg is not g:
            for key in ('completed_in_window','failed_attempts','successful_attempts','cancelled_attempts','timed_attempts',
                        'terminal_attempts','successful_core_seconds','unsuccessful_core_seconds','_remaining',
                        '_slots','_unknown','_blocked','_recovering','_calibrated'):
                g[key] += jg[key]
            g['counts'].update(jg['counts'])
            g['_starts'].extend(jg['_starts']);g['_completions'].extend(jg['_completions'])
            g['_tail'] = max(g['_tail'],jg['_tail'])
            for i in range(bin_count):
                g['timeline'][i]['completed'] += jg['timeline'][i]['completed']
                g['timeline'][i]['failed'] += jg['timeline'][i]['failed']
        if is_active:
            job_estimates[job['job_id']] = _estimate(jg['_remaining'],jg['_completions'],jg['_starts'],jg['_slots'],
                jg['_tail'],jg['_unknown'],jg['_blocked'],jg['_recovering'],now,calibrated=samples)
    source.update(excluded_nonproduction_jobs=ignored, malformed_records=bad_rows)
    incomplete = bool(source.get('source_truncated') or source.get('missing_or_oversized_projections') or bad_rows)
    overall = group('all')
    group_rows=[]
    for g in projects.values():
        for key in ('job_count','active_jobs','completed_in_window','failed_attempts','successful_attempts','cancelled_attempts',
                    'timed_attempts','terminal_attempts','successful_core_seconds','unsuccessful_core_seconds'):
            overall[key]+=g[key]
        overall['counts'].update(g['counts'])
        for i in range(bin_count):
            overall['timeline'][i]['completed']+=g['timeline'][i]['completed']
            overall['timeline'][i]['failed']+=g['timeline'][i]['failed']
        g['forecast'] = _estimate(g['_remaining'],g['_completions'],g['_starts'],g['_slots'],g['_tail'],
            g['_unknown'],g['_blocked'],g['_recovering'],now,incomplete,calibrated=g['_calibrated'])
        group_rows.append(g)
    group_rows.sort(key=lambda g: (-g['active_jobs'], -g['completed_in_window'], g['project_id']))
    active_forecasts=[g['forecast'] for g in group_rows if g['active_jobs']]
    unknown_forecasts=sum(e['seconds'] is None for e in active_forecasts)
    full_seconds=max((e['seconds'] for e in active_forecasts if e['seconds'] is not None), default=0)
    overall['forecast']={'seconds':None if unknown_forecasts or incomplete else full_seconds,
        'lower_seconds': None if unknown_forecasts or incomplete else max((e['lower_seconds'] or 0 for e in active_forecasts),default=0),
        'upper_seconds': None if unknown_forecasts or incomplete else max((e['upper_seconds'] or 0 for e in active_forecasts),default=0),
        'finish_at': None if unknown_forecasts or incomplete else (now+timedelta(seconds=full_seconds)).isoformat(),
        'confidence':'unknown' if unknown_forecasts or incomplete else 'low' if active_forecasts else 'complete',
        'basis':'incomplete_source' if incomplete else 'partial_project_forecasts' if unknown_forecasts else 'max_project_finish',
        'unknown_projects':unknown_forecasts,
        'known_work_seconds':full_seconds, 'sample_count':sum(e['sample_count'] for e in active_forecasts)}

    def present(g):
        good,bad=g['successful_core_seconds'],g['unsuccessful_core_seconds']
        total=good+bad
        return {**{k:v for k,v in g.items() if not k.startswith('_') and k!='counts'},
            'counts':{k:g['counts'].get(k,0) for k in BUCKETS},
            'throughput_units_per_hour':round(g['completed_in_window']/window_hours,2),
            'effective_execution_percent':_percent(good,total),
            'unproductive_core_hours':round(bad/3600,2),
            'successful_core_hours':round(good/3600,2),
            'timing_coverage_percent':_percent(g['timed_attempts'],g['terminal_attempts']),
            'completion_percent':_percent(g['counts'].get('completed',0),sum(g['counts'].values()))}
    capacity=sum(m['effective_slots'] for m in machines)
    live_running=sum(m['running_units'] for m in machines if m['live'])
    stale_running=sum(m['running_units'] for m in machines if not m['live'])
    if incomplete:
        for forecast in job_estimates.values():
            forecast.update(seconds=None,finish_at=None,lower_seconds=None,upper_seconds=None,
                            basis='incomplete_source',confidence='unknown')
    return {'schema_version':1, 'generated_at':now.isoformat(), 'window_hours':window_hours,
        'window_start':cutoff.isoformat(), 'bin_seconds':bin_s, 'source':source,
        'overall':present(overall), 'projects':[present(g) for g in group_rows[:MAX_PROJECTS]],
        'projects_truncated':len(group_rows)>MAX_PROJECTS, 'project_count':len(group_rows),
        'job_forecasts':job_estimates, 'machines':machines,
        'capacity':{'effective_slots':capacity,'running_slots':live_running,'unconfirmed_running_slots':stale_running,
                    'utilization_percent':_percent(live_running,capacity),
                    'over_capacity_slots':max(0,live_running-capacity),
                    'live_machines':sum(m['live'] for m in machines),'machine_count':len(machines),
                    'dispatcher_open':dispatcher_open},
        'definitions':{'efficiency':'成功核时 / 已结束且有完整计时的尝试核时；核时=窗口内运行秒数×该Attempt分配线程数。不含在途尝试，不代表实际CPU耗时或科学正确率。',
                       'throughput':'所选时窗内已完成并回收的单元数 / 时窗小时数。单元工作量不同，不用于项目间算力速度排名。',
                       'utilization':'新鲜机器上的运行Attempt数 / 当前开放有效并发。不是CPU使用率，也不证明所有空槽均满足某个Job的门禁。',
                       'forecast':'按当前队列和已获并发份额估算；优先本Job历史时长/声明时长中位比与近期工作量完成速率，冷启动使用当前并发。全网取各项目最晚完工，不相加。范围是情景带，不是置信区间；不含新增任务或未来配额/机器变化。'}}


class ClusterInsights:
    """Bounded, identity-scoped derived views; refresh cannot enqueue work.

    Fresh views live for 15 seconds. Between 15 and 30 seconds, a last good
    view can be returned with explicit stale/refresh state while one fixed
    worker rebuilds it. A cold view or a view at the hard age limit must be
    rebuilt synchronously; failures never extend the stale deadline.
    """
    FRESH_SECONDS = 15
    MAX_AGE_SECONDS = 30
    MAX_PENDING = 16

    def __init__(self, repository):
        self.repository=repository
        self._cache=OrderedDict()
        self._lock=threading.Lock()
        self._fill_lock=threading.Lock()
        self._executor=ThreadPoolExecutor(max_workers=1, thread_name_prefix='rcn-insights')
        self._refreshing={}
        self._errors={}
        self._closed=False

    def close(self):
        """Stop this reader's bounded worker before the ASGI lifespan exits."""
        with self._lock:
            self._closed=True
        self._executor.shutdown(wait=True, cancel_futures=True)
        with self._lock:
            self._refreshing.clear()

    def _response(self, key, cached):
        # Caller holds _lock. The age begins before computation, so a slow
        # successful rebuild cannot silently extend the hard freshness bound.
        age=max(0.0, time.monotonic()-cached[0])
        data=deepcopy(cached[1])
        stale=age >= self.FRESH_SECONDS
        data['read_state']={'stale':stale,
            'refreshing':stale and key in self._refreshing,
            'age_seconds':round(age, 3),
            'last_success_at':data['generated_at'],
            'refresh_error':self._errors.get(key) if stale else None,
            'max_age_seconds':self.MAX_AGE_SECONDS}
        return data

    def _refresh(self, key, *, user, visibility, owner, settings):
        try:
            self._fill(key, user=user, visibility=visibility, owner=owner, settings=settings)
        except Exception as exc:
            # Keep only the exception type; database paths, credentials and
            # other exception details must not become public chart metadata.
            with self._lock:
                if key in self._cache:
                    self._errors[key]=type(exc).__name__
        finally:
            with self._lock:
                self._refreshing.pop(key, None)

    def prepare_default_snapshot(self):
        """Build the default derived view after schema/backfill, before ready.

        This is the same unrestricted cache key used by administrators. It
        creates no account/token, and member requests still derive their own
        SQL visibility/scope keys. Ordinary bounded refresh semantics apply.
        """
        from .auth import AuthContext
        context = AuthContext('insights-read-model-startup', frozenset({UserRole.ADMIN}), frozenset({'api'}))
        return self.snapshot(context, window_hours=24)

    def snapshot(self, context, *, window_hours=24, now=None):
        if window_hours not in WINDOWS:raise ValueError('unsupported insights time window')
        settings=self.repository.get_feature_settings()
        admin=UserRole.ADMIN in context.roles
        own=not admin and (settings.visibility==FeatureVisibility.OWN_DETAIL or not settings.show_group_job_details)
        owner=context.actor_id if not admin and settings.visibility==FeatureVisibility.OWN_DETAIL else None
        user=context.actor_id if own else None
        from .read_models import JobVisibility
        visibility = None if admin else JobVisibility(user_id=context.actor_id,
            project_ids=frozenset(g.project_id for g in self.repository.list_project_grants()
                if not own and g.authorizes(context.actor_id)))
        owned_ids = tuple(sorted(m.machine_id for m in self.repository.list_machines()
            if m.owner_user_id == owner)) if owner is not None else None
        key=(context.actor_id if not admin else None, user,owner,window_hours,
             tuple(sorted(visibility.project_ids)) if visibility is not None else None,
             settings.visibility.value, settings.show_group_job_details, owned_ids)
        with self._lock:
            if self._closed:
                raise RuntimeError('insights reader is closed')
            cached=self._cache.get(key)
            if now is None and cached:
                age=time.monotonic()-cached[0]
                if age < self.FRESH_SECONDS:
                    return self._response(key, cached)
                if age < self.MAX_AGE_SECONDS:
                    if key not in self._refreshing and len(self._refreshing)<self.MAX_PENDING:
                        self._refreshing[key]=self._executor.submit(self._refresh, key,
                            user=user, visibility=visibility, owner=owner, settings=settings)
                    return self._response(key, cached)
        return self._fill(key, user=user, visibility=visibility, owner=owner, settings=settings, now=now)

    def _fill(self, key, *, user, visibility, owner, settings, now=None):
        # Cold requests and hard-limit reads share the same single-flight gate
        # as the fixed background worker. Recheck after waiting for that gate.
        with self._fill_lock:
            with self._lock:
                cached=self._cache.get(key)
                if now is None and cached and time.monotonic()-cached[0]<self.FRESH_SECONDS:
                    return self._response(key, cached)
            built_at=time.monotonic()
            current=now or datetime.now(timezone.utc)
            jobs,source=read_jobs(self.repository,now=current,user_id=user,visibility=visibility,
                window_hours=key[3])
            # Live observations can advance while the bounded history read is
            # waiting. Judge telemetry against its actual read clock, not a
            # stale fill-start clock that would call new heartbeats "future".
            runtime_now=current if now is not None else datetime.now(timezone.utc)
            machines=machine_snapshot(self.repository,now=runtime_now,owner_id=owner,
                allowed_machine_ids=key[7])
            ds=self.repository.get_dispatcher_status()
            metadata=self.repository.get_dataset_metadata()
            data=build_insights(jobs,machines,now=current,window_hours=key[3],source=source,
                include_demo=bool(metadata and metadata.mode=='demo'),
                dispatcher_open=ds.desired_state=='open' and ds.accepting_assignments)
            data['dataset_mode'] = metadata.mode if metadata else 'formal'
            data['runtime_observed_at'] = runtime_now.isoformat()
            data['scope']={'jobs':'own' if user else 'cluster','machines':'own' if owner else 'cluster',
                           'visibility':settings.visibility.value,'details_filtered':bool(user),
                           'projects_filtered':visibility is not None}
            with self._lock:
                if now is None and time.monotonic()-built_at >= self.MAX_AGE_SECONDS:
                    raise RuntimeError('insights rebuild exceeded maximum snapshot age')
                self._cache[key]=(built_at,deepcopy(data));self._cache.move_to_end(key)
                self._errors.pop(key, None)
                while len(self._cache)>16:
                    evicted, _value=self._cache.popitem(last=False)
                    self._errors.pop(evicted, None)
                return self._response(key, self._cache[key])
