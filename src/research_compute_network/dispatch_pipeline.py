"""Bounded I/O orchestration for the existing lease-owning Dispatcher.

There is still one scheduler and the same Attempt/reservation state machine.
A slow machine keeps at most one control operation in flight. Whole-fleet
cycles never wait for that operation; results are reaped on later cycles.
"""
from __future__ import annotations
from collections import deque
from dataclasses import dataclass
from concurrent.futures import Future
import os
from pathlib import Path
import time

from .failure_diagnostics import safe_failure_reason


@dataclass
class MachineWork:
    kind: str
    future: Future
    started: float
    completed_at: float | None = None


class DispatchPipeline:
    def __init__(self, dispatcher):
        self.d = dispatcher
        self.inflight: dict[str, MachineWork] = {}
        self.next_poll: dict[str, float] = {}
        self.failures: dict[str, int] = {}
        self.cursor: dict[str, str] = {}
        self.observation_order: dict[str, deque[str]] = {}
        self.last_machine = ''
        self.just_reaped: set[str] = set()
        self.observation_due: set[str] = set()
        self._post_dispatch_work: dict[str, list] = {}
        self.completed_assignments = 0
        self.completed_preparations = 0

    def _enqueue(self, machine, kind, pool, function, *args):
        if (machine in self.inflight or self.d.io_stop_event.is_set()
                or getattr(self.d, '_stopping', False) or getattr(self.d, '_lease_lost', False)):
            return False
        stop_file = os.environ.get('RCN_DISPATCHER_STOP_FILE', '')
        if stop_file and Path(stop_file).resolve().exists():
            return False
        future = pool.submit(function, *args)
        task = MachineWork(kind, future, time.monotonic())
        self.inflight[machine] = task

        def completed(_):
            # Install the task before registering: Future invokes this inline
            # if it finished before add_done_callback. Capture this task so a
            # late callback cannot timestamp a successor on the same machine.
            task.completed_at = time.monotonic()
            self.d.wake()

        future.add_done_callback(completed)
        return True

    def _observe_machine(self, machine, work):
        d = self.d
        d._reconcile_reservations(machine_id=machine)
        count = pending = 0
        last = self.cursor.get(machine, '')
        by_attempt = {item[2]: item for item in work}
        # Keep existing waiters ahead of newly created Attempts. Rebuilding
        # from a lexical cursor lets a continuously refilled Job starve later
        # Jobs when a single slow read consumes the whole observation budget.
        ordered = deque(
            attempt_id for attempt_id in self.observation_order.get(machine, ())
            if attempt_id in by_attempt
        )
        queued = set(ordered)
        ordered.extend(sorted(by_attempt.keys() - queued))
        self.observation_order[machine] = ordered
        deadline = time.monotonic() + 2.0
        for _ in range(min(4, len(ordered))):
            if d.io_stop_event.is_set():
                break
            attempt_id = ordered.popleft()
            item = by_attempt[attempt_id]
            try:
                good, waiting = d._reconcile_machine_attempts([item])
            finally:
                # An uncertain or raised read still used this Attempt's turn;
                # its original identity remains pending for the next round.
                ordered.append(attempt_id)
            count += good
            pending += waiting
            last = item[2]
            # A single unresponsive read cannot multiply into N timeouts in
            # the same machine batch. Other machines have their own futures.
            if waiting or time.monotonic() >= deadline:
                break
        return count, pending, last

    def observe(self):
        d = self.d
        reconciled = 0
        self.just_reaped = set()
        self._post_dispatch_work = {}
        now = time.monotonic()
        for machine, task in list(self.inflight.items()):
            # done() can become visible just before its callback runs. Let the
            # callback publish the completion timestamp before harvesting it.
            if not task.future.done() or task.completed_at is None:
                continue
            del self.inflight[machine]
            self.just_reaped.add(machine)
            if task.kind != 'observe':
                self.observation_due.add(machine)
            try:
                result = task.future.result()
                if task.kind == 'observe':
                    good, pending, last = result
                    reconciled += good
                    self.cursor[machine] = last
                    self.failures[machine] = self.failures.get(machine, 0) + 1 if pending else 0
                elif task.kind in {'submit', 'activate'}:
                    self.completed_assignments += int(bool(result))
                elif task.kind == 'prepare':
                    self.completed_preparations += int(bool(result))
                delay = min(30.0, 2.0 * (2 ** min(self.failures.get(machine, 0), 4)))
                # A healthy read may have finished a whole slow scheduler
                # cycle ago. Do not start its cooldown again when reaping it.
                # Pending/failed reads retain backoff from this harvest, so an
                # old failure cannot trigger an immediate retry burst.
                completed_at = task.completed_at if task.kind == 'observe' and not pending else now
                self.next_poll[machine] = completed_at + delay
            except Exception as exc:
                self.failures[machine] = min(5, self.failures.get(machine, 0) + 1)
                self.next_poll[machine] = now + min(30.0, 2.0 ** self.failures[machine])
                d.service._event('dispatcher.machine_io_deferred', d.owner_id, 'machine', machine,
                    operation=task.kind, reason=safe_failure_reason(exc, action='machine I/O'),
                    retry_after_s=round(self.next_poll[machine]-now, 1),
                    execution_replayed=False)
        work = d._pending_reconciliation_work()
        reservations = d.repository.list_dispatch_reservations(active_only=True)
        machines = set(work) | {r.machine_id for r in reservations} | self.observation_due
        self._post_dispatch_work = {
            machine: work.get(machine, [])
            for machine in self.just_reaped & machines
            if machine not in self.observation_due
        }
        self._enqueue_observations(work, machines, defer_reaped=True)
        # In-flight healthy observation is not an uncertain scientific attempt.
        pending = sum(item[1].status.value=='reconcile_pending' for items in work.values() for item in items)
        d.status.io_snapshot = self.snapshot()
        return reconciled, pending

    def _enqueue_observations(self, work, machines, *, defer_reaped):
        d = self.d
        now = time.monotonic()
        ordered = sorted(machines)
        ordered = [m for m in ordered if m > self.last_machine] + [m for m in ordered if m <= self.last_machine]
        for machine in ordered:
            if machine in self.inflight:
                continue
            if machine not in self.observation_due and (
                (defer_reaped and machine in self.just_reaped) or self.next_poll.get(machine,0)>now
            ):
                continue
            if sum(w.kind=='observe' for w in self.inflight.values()) >= d.max_concurrent_reconciliations:
                break
            if self._enqueue(machine,'observe',d._reconciliation_pool,self._observe_machine,machine,work.get(machine,[])):
                self.observation_due.discard(machine)
                self.last_machine=machine

    def _observe_after_dispatch(self):
        # Just-reaped machines first get the original dispatch/prepare turn.
        # If it used none of them, restart already-due observations now rather
        # than waiting another whole cycle. Reuse the bounded snapshot: no
        # second operational-job scan or different Attempt identities.
        work, self._post_dispatch_work = self._post_dispatch_work, {}
        self._enqueue_observations(work, work, defer_reaped=False)

    def blocked_machines(self):
        now = time.monotonic()
        return set(self.inflight) | self.observation_due | {m for m,n in self.failures.items() if n and self.next_poll.get(m,0)>now}

    def dispatch(self):
        d = self.d
        if not d.status.accepting_assignments or not d._scan_allowed():
            self._observe_after_dispatch()
            d.status.io_snapshot = self.snapshot()
            return 0, 0
        # Existing prepared work has fixed identity/resources. Activate at most
        # one on each available machine, without waiting on the remote response.
        for reservation in d.repository.list_dispatch_reservations(active_only=True):
            if sum(w.kind in {'submit','activate'} for w in self.inflight.values()) >= d.max_concurrent_submissions:
                break
            if reservation.machine_id in self.blocked_machines() or reservation.state!='prepared':
                continue
            assignment=d.service.activate_dispatch_reservation(reservation.reservation_id,
                actor_id=d.owner_id,ready_for_assignment=d._origin_bundle_ready)
            if assignment is not None:
                self._enqueue(reservation.machine_id,'activate',d._submission_pool,
                    d._activate_prepared_reservation,reservation,assignment)
        for _ in range(d.max_assignments_per_cycle):
            if not d._scan_allowed() or sum(w.kind in {'submit','activate'} for w in self.inflight.values())>=d.max_concurrent_submissions:
                break
            assignment=d.service.schedule_once(actor_id=d.owner_id,
                ready_for_assignment=d._origin_bundle_ready,should_continue=d._scan_allowed,
                excluded_machine_ids=self.blocked_machines())
            if assignment is None:
                break
            self._enqueue(assignment.machine_id,'submit',d._submission_pool,d._submit_assignment,assignment)
        for _ in range(d.max_assignments_per_cycle):
            if not d._scan_allowed() or sum(w.kind=='prepare' for w in self.inflight.values())>=d.max_concurrent_preparations:
                break
            reservation=d.service.prepare_dispatch_once(actor_id=d.owner_id,
                ready_for_assignment=d._origin_bundle_ready,should_continue=d._scan_allowed,
                excluded_machine_ids=self.blocked_machines())
            if reservation is None:
                break
            self._enqueue(reservation.machine_id,'prepare',d._preparation_pool,d._prepare_reservation,reservation)
        assignments,self.completed_assignments=self.completed_assignments,0
        prepared,self.completed_preparations=self.completed_preparations,0
        self._observe_after_dispatch()
        d.status.io_snapshot=self.snapshot()
        return assignments,prepared

    def snapshot(self):
        now=time.monotonic()
        return {'mode':'bounded-machine-pipeline','inflight_machines':len(self.inflight),
            'observations':sum(w.kind=='observe' for w in self.inflight.values()),
            'submissions':sum(w.kind in {'submit','activate'} for w in self.inflight.values()),
            'preparations':sum(w.kind=='prepare' for w in self.inflight.values()),
            'oldest_io_seconds':round(max((now-w.started for w in self.inflight.values()),default=0),2),
            'backoff_machines':sum(bool(n) and self.next_poll.get(m,0)>now for m,n in self.failures.items()),
            'global_wait_barrier':False}
