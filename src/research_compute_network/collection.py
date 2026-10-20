"""Durable origin-side byte collection; never submits Jobs or imports science.

The journal owns only its temporary files. The final receipt commits verified
transport evidence, not scientific acceptance or custody/garbage-collection rights.
"""
from __future__ import annotations

from contextlib import contextmanager, nullcontext
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import time
from urllib.parse import urlencode
import uuid

import psutil

from .hashing import sha256_value
from .models import ArtifactManifest
from .origin_transfer import CHUNK_BYTES, identifier, managed_path, publish_new_file, verify_file
from .volume_budget import VolumeBudget, VolumeClaim, volume_for_destination

SCHEMA = 'rcn-origin-collection-v1'
CHECKPOINT_BYTES = 8 * 1024**2
CHECKPOINT_SECONDS = 5.0


class CollectionConflict(ValueError):
    reason_code = 'collection_identity_or_integrity_conflict'


class CollectionBusy(RuntimeError):
    reason_code = 'collection_owner_active'


class CollectionPaused(RuntimeError):
    reason_code = 'collection_paused_by_owner'


def collection_failure_state(exc):
    """Transient transport/capacity failures retry; consent and integrity do not."""
    if isinstance(exc, (CollectionPaused, KeyboardInterrupt)):
        return 'paused'
    if getattr(exc, 'reason_code', None) in {'origin_result_disk_reserve', 'storage_capacity_unavailable',
        'storage_holder_busy', 'storage_budget_busy', 'storage_ledger_busy', 'storage_metadata_busy',
        'collection_owner_active', 'collection_volume_busy'}:
        return 'retry_wait'
    status = getattr(exc, 'status', None)
    if status in {401, 403}:
        return 'credentials_required'
    if isinstance(exc, (CollectionConflict, ValueError)) or status in {400, 404, 409, 410, 422}:
        return 'conflict'
    return 'retry_wait'


def _sync_directory(path):
    if os.name != 'nt':
        descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def durable_json(path, value, *, immutable=False):
    """File-fsync then atomic publication; existing immutable values must match."""
    path = Path(path)
    managed_path(path.parent, path.name)
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode() + b'\n'
    descriptor, temporary = tempfile.mkstemp(prefix='.collection-', suffix='.tmp', dir=path.parent)
    temporary = Path(temporary)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        managed_path(path.parent, path.name)
        if immutable:
            try:
                publish_new_file(temporary, path)
            except FileExistsError:
                if path.read_bytes() != raw:
                    raise CollectionConflict('immutable collection evidence differs')
        else:
            os.replace(temporary, path)
        _sync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


@contextmanager
def collection_lock(path):
    path = Path(path)
    managed_path(path.parent, path.name)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a+b') as stream:
        stream.seek(0, 2)
        if not stream.tell():
            stream.write(b'0')
            stream.flush()
        stream.seek(0)
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise CollectionBusy('the original collection writer is still active') from exc
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == 'nt':
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def _client(transfer):
    selected = transfer
    while not hasattr(selected, 'client') and hasattr(selected, 'transfer'):
        selected = selected.transfer
    return getattr(selected, 'client', None)


def _ledger_root():
    selected = os.environ.get('RCN_COLLECTION_STATE_HOME')
    if selected is None:
        selected = Path(os.environ.get('LOCALAPPDATA', str(Path.home() / '.local/share'))) / 'ResearchComputeNetwork'
    root = Path(selected).absolute()
    managed_path(root, 'collection-volume-budget.db')
    root.mkdir(parents=True, exist_ok=True)
    return root


class CollectionRunner:
    def __init__(self, transfer, job, manifests, spool_root, *, operation_id=None,
                 reserve_free_bytes=0, progress=None, capabilities=None, cancel_event=None):
        if type(reserve_free_bytes) is not int or reserve_free_bytes < 0:
            raise ValueError('result disk reserve must be a nonnegative integer')
        self.transfer, self.job = transfer, job
        self.root = Path(spool_root).expanduser().absolute()
        managed_path(self.root, '.collection-check')
        self.job_id = identifier(job['job_id'])
        self.origin = identifier(job['origin_submitter_id'])
        self.manifests = {}
        for raw in manifests:
            manifest = ArtifactManifest.model_validate(raw)
            if manifest.job_id != self.job_id or manifest.work_unit_id in self.manifests:
                raise CollectionConflict('invalid or duplicate result manifest identity')
            names = [f.relative_path.casefold() for f in manifest.files]
            if len(names) != len(set(names)):
                raise CollectionConflict('ambiguous result manifest paths')
            self.manifests[manifest.work_unit_id] = manifest
        self.binding = {'job_id': self.job_id, 'origin_submitter_id': self.origin,
            'project_id': job.get('project_id'), 'user_id': job.get('user_id'),
            'request_hash': job.get('request_hash'), 'destination': str(self.root),
            'manifests': {key: sha256_value(value.model_dump(mode='json'))
                          for key, value in sorted(self.manifests.items())}}
        self.operation_id = identifier(operation_id or ('collect-' + sha256_value(self.binding)[:40]))
        self.directory = managed_path(self.root, '.rcn-collections', self.operation_id)
        self.state_path = self.directory / 'operation.json'
        self.contract_path = self.directory / 'contract.json'
        self.reserve = reserve_free_bytes
        self.progress = progress
        self.capabilities = capabilities
        self.cancel_event = cancel_event
        self.state = None
        self.budget = None
        self.claim = None

    @classmethod
    def from_operation(cls, transfer, spool_root, operation_id, *, progress=None):
        directory = managed_path(Path(spool_root).absolute(), '.rcn-collections', identifier(operation_id))
        contract = json.loads((directory / 'contract.json').read_text(encoding='utf-8'))
        return cls(transfer, contract['job'], contract['manifests'], spool_root,
                   operation_id=operation_id, progress=progress)

    def status(self):
        if self.state_path.exists():
            value = json.loads(self.state_path.read_text(encoding='utf-8'))
            if (value.get('schema') != SCHEMA or value.get('binding') != self.binding
                or value.get('operation_id') != self.operation_id):
                raise CollectionConflict('collection operation identity changed')
            return value
        return {'schema': SCHEMA, 'operation_id': self.operation_id, 'binding': self.binding,
                'phase': 'planned', 'files': {}, 'scientific_imported': False}

    def _save(self, phase=None, **fields):
        self.state.update(fields)
        if phase is not None:
            self.state['phase'] = phase
        self.state['updated_at'] = time.time()
        durable_json(self.state_path, self.state)
        if self.progress is not None:
            try:
                self.progress({'stage': self.state['phase'], 'operation_id': self.operation_id,
                    'completed_files': sum(r.get('state') == 'published' for r in self.state['files'].values()),
                    'total_files': sum(len(m.files) for m in self.manifests.values()),
                    'received_bytes': sum(r.get('durable_offset', 0) for r in self.state['files'].values()),
                    'total_bytes': sum(f.size_bytes for m in self.manifests.values() for f in m.files),
                    'source_checked_bytes': self.state.get('preparation', {}).get('checked_bytes'),
                    'source_total_bytes': self.state.get('preparation', {}).get('total_bytes')})
            except Exception:
                # UI observation is not part of durable publication. Explicit
                # cancellation uses cancel_event rather than an observer error.
                pass

    def _check_cancelled(self):
        if self.cancel_event is not None and self.cancel_event.is_set():
            raise CollectionPaused('collection paused; original operation and partials preserved')

    def _validate_index(self, index):
        entries = index.get('units', [])
        if (index.get('job_id') != self.job_id or len(entries) != len(self.manifests)
            or {row.get('work_unit_id') for row in entries} != set(self.manifests)):
            raise CollectionConflict('result index does not exactly match requested manifests')
        for entry in entries:
            unit_id, attempt_id = identifier(entry['work_unit_id']), identifier(entry['attempt_id'])
            unit = next((u for u in self.job['work_units'] if u['work_unit_id'] == unit_id), None)
            attempts = [a for a in (unit or {}).get('attempts', [])
                        if a['attempt_id'] == attempt_id and a['state'] == 'completed'
                        and a.get('abandonment') is None]
            manifest = self.manifests[unit_id]
            if len(attempts) != 1 or entry['manifest_sha256'] != self.binding['manifests'][unit_id]:
                raise CollectionConflict('result index does not identify a completed producer Attempt')
            producer = manifest.producer or {}
            lineage = (unit or {}).get('attempts', [])
            if any(a.get('state') == 'abandoned' or a.get('abandonment') is not None for a in lineage):
                if not producer.get('attempt_id') or lineage[-1]['attempt_id'] != attempt_id:
                    raise CollectionConflict('result index names abandoned or superseded output')
            if producer.get('attempt_id') not in (None, attempt_id):
                raise CollectionConflict('manifest producer Attempt changed')
            if producer.get('external_run_id') not in (None, attempts[0].get('external_run_id')):
                raise CollectionConflict('manifest external run changed')
        return entries

    def _freeze(self, *, local_only=False):
        self.root.mkdir(parents=True, exist_ok=True)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.state = self.status()
        volume = volume_for_destination(self.root)[1]
        if self.state.get('volume_id', volume) != volume:
            raise CollectionConflict('collection destination volume changed')
        self.state['volume_id'] = volume
        if self.contract_path.exists():
            contract = json.loads(self.contract_path.read_text(encoding='utf-8'))
            if contract.get('binding') != self.binding:
                raise CollectionConflict('frozen collection contract changed')
            index = contract['index']
        else:
            if local_only:
                raise CollectionConflict('local finalization requires a frozen real result contract')
            with self.transfer._open(f'/v1/jobs/{self.job_id}/origin-results', timeout=60) as response:
                index = self.transfer._read_json(response)
            self._validate_index(index)
            contract = {'schema': SCHEMA, 'binding': self.binding, 'job': self.job,
                'manifests': [m.model_dump(mode='json') for m in self.manifests.values()], 'index': index}
            durable_json(self.contract_path, contract, immutable=True)
        self.entries = self._validate_index(index)
        self._save()

    def _targets(self):
        for entry in self.entries:
            unit_id, attempt_id = entry['work_unit_id'], entry['attempt_id']
            directory = managed_path(self.root, self.origin, 'incoming', self.job_id, unit_id, attempt_id)
            for record in self.manifests[unit_id].files:
                target = managed_path(directory, record.relative_path)
                key = sha256_value({'unit_id': unit_id, 'attempt_id': attempt_id, 'file': record.relative_path})
                yield entry, record, target, key

    def _capacity(self, needed, *, reconcile_only=False):
        if needed == 0 and not self.state.get('capacity_claim') and not reconcile_only:
            return
        if needed and shutil.disk_usage(self.root).free < self.reserve + needed:
            from .origin_transfer_client import ResultCapacityError
            raise ResultCapacityError('insufficient disk space to retain the member reserve')
        # Shared by all SDK users on this owner/host, not one ledger per Job.
        ledger_root = _ledger_root()
        self.budget = VolumeBudget(ledger_root / 'collection-volume-budget.db')
        self.budget._flush_pending_releases()
        self._recover_exited_collection_claims()
        old = self.state.get('capacity_claim')
        if old and any(row['token'] == old['token'] for row in self.budget.active_claims()):
            # This runner uses no child writers. Owning its OS lock and proving
            # that its exact old process exited proves the complete writer ended.
            if (old['owner_pid'], old['owner_started_at']) == (os.getpid(), psutil.Process().create_time()):
                self.budget.release(VolumeClaim(**old), writer_stopped=True,
                    evidence='same_owner_collection_lock_reacquired_no_child_writers')
            else:
                self.budget.reconcile_orphan(old['token'], expected_owner_pid=old['owner_pid'],
                    expected_owner_started_at=old['owner_started_at'], writer_tree_exited=True,
                    evidence=f'collection_lock_acquired_no_child_writers:{self.operation_id}')
        if needed == 0:
            self._save(capacity_claim=None)
            return
        # Persist exact no-child writer intent before the reservation itself,
        # closing the reserve-committed / claim-journal-not-written crash gap.
        self._save('downloading', owner={'pid': os.getpid(),
            'birth': psutil.Process().create_time(), 'child_writers': False})
        self.claim = self.budget.reserve(self.root, needed, holder_kind='origin_collection',
            holder_key=self.operation_id, max_kind_claims=1, expected_volume_id=self.state['volume_id'])
        self._save(capacity_claim=asdict(self.claim))

    @contextmanager
    def _volume_slot(self):
        # Full local SHA readback is IO too, even when no new bytes need a
        # capacity reservation. Keep it within the same per-owner volume slot.
        volume = volume_for_destination(self.root)[1]
        path = managed_path(_ledger_root(), 'collection-slots', sha256_value(volume) + '.lock')
        with collection_lock(path):
            yield

    def _recover_exited_collection_claims(self):
        """Prove the exact journaled, no-child writer ended before freeing it.

        A different pending Job must not stay blocked by a crashed collector.
        This is deliberately narrower than generic PID/age based GC.
        """
        for row in self.budget.active_claims():
            if row['holder_kind'] != 'origin_collection':
                continue
            if self.budget._owner_alive(row['owner_pid'], row['owner_started_at']) is not False:
                continue
            try:
                root = Path(row['destination']).absolute()
                operation = identifier(row['holder_key'])
                directory = managed_path(root, '.rcn-collections', operation)
                own_lock = directory == self.directory
                with (nullcontext() if own_lock else collection_lock(directory / 'writer.lock')):
                    journal = managed_path(directory, 'operation.json')
                    state = json.loads(journal.read_text(encoding='utf-8'))
                    owner = state.get('owner', {})
                    if (state.get('schema') != SCHEMA or state.get('operation_id') != operation
                        or state.get('binding', {}).get('destination') != str(root)
                        or owner != {'pid': row['owner_pid'], 'birth': row['owner_started_at'], 'child_writers': False}):
                        continue
                    self.budget.reconcile_orphan(row['token'], expected_owner_pid=row['owner_pid'],
                        expected_owner_started_at=row['owner_started_at'], writer_tree_exited=True,
                        evidence=f'exclusive_collection_lock_and_exact_journal_no_child_writer:{operation}')
                    state.update(capacity_claim=None, capacity_recovered_after_owner_exit=True)
                    durable_json(journal, state)
            except (CollectionBusy, FileNotFoundError, ValueError, OSError):
                continue

    def _prepare(self, entry, record, key):
        body = {'operation_id': 'file-' + sha256_value({'collection': self.operation_id, 'key': key}),
            'work_unit_id': entry['work_unit_id'], 'attempt_id': entry['attempt_id'],
            'file': record.relative_path, 'manifest_sha256': entry['manifest_sha256'],
            'size_bytes': record.size_bytes, 'sha256': record.sha256}
        base = f'/v1/jobs/{self.job_id}/origin-result-preparations'
        with self.transfer._open(base, data=json.dumps(body).encode(),
                headers={'Content-Type': 'application/json'}, method='POST', timeout=60) as response:
            ticket = self.transfer._read_json(response)
        ticket_id = identifier(ticket.get('ticket_id', ticket.get('ticket', body['operation_id'])))
        path = base + '/' + ticket_id
        while True:
            self._check_cancelled()
            phase = ticket.get('state', ticket.get('status'))
            if phase == 'ready':
                return path + '/content'
            if phase in {'failed', 'cancelled', 'conflict'}:
                from .client import RcnApiError
                raise RcnApiError(ticket.get('http_status', 409), 'result preparation rejected',
                    reason_code=ticket.get('reason_code', 'result_unavailable_or_integrity_failed'))
            if phase in {'expired', 'reprepare_required'}:
                # A repeated immutable POST reacquires the same producer; it
                # never names a replacement Attempt or loses local partials.
                with self.transfer._open(base, data=json.dumps(body).encode(),
                        headers={'Content-Type': 'application/json'}, method='POST', timeout=60) as response:
                    ticket = self.transfer._read_json(response)
                continue
            self._save('preparing', preparation={'ticket_id': ticket_id,
                'checked_bytes': ticket.get('checked_bytes', 0), 'total_bytes': record.size_bytes})
            delay = min(5, max(0.1, float(ticket.get('retry_after', 2))))
            if self.cancel_event is not None:
                self.cancel_event.wait(delay)
                self._check_cancelled()
            else:
                time.sleep(delay)
            with self.transfer._open(path, timeout=60) as response:
                ticket = self.transfer._read_json(response)

    def _download(self, entry, record, target, key):
        partial = managed_path(self.directory, key + '.partial')
        row = self.state['files'].setdefault(key, {'relative_path': record.relative_path,
            'work_unit_id': entry['work_unit_id'], 'attempt_id': entry['attempt_id'],
            'size_bytes': record.size_bytes, 'sha256': record.sha256, 'durable_offset': 0})
        offset = row.get('durable_offset', 0)
        if type(offset) is not int or not 0 <= offset <= record.size_bytes:
            raise CollectionConflict('invalid durable collection offset')
        if partial.exists():
            if partial.stat().st_size < offset:
                raise CollectionConflict('durable collection prefix is missing')
        elif offset:
            raise CollectionConflict('durable collection prefix is missing')
        target.parent.mkdir(parents=True, exist_ok=True)
        checksum = hashlib.sha256()
        # A new process reconstructs the ordinary SHA state from its prefix.
        with partial.open('r+b' if partial.exists() else 'w+b') as output:
            output.truncate(offset)
            remaining = offset
            while remaining:
                chunk = output.read(min(CHUNK_BYTES, remaining))
                if not chunk:
                    raise CollectionConflict('truncated collection prefix')
                checksum.update(chunk)
                remaining -= len(chunk)
            if offset != record.size_bytes:
                caps = self.capabilities or {}
                prepared = caps.get('result_preparations') is True
                path = self._prepare(entry, record, key) if prepared else (
                    f'/v1/jobs/{self.job_id}/origin-results/{entry["work_unit_id"]}/{entry["attempt_id"]}?'
                    + urlencode({'file': record.relative_path}))
                headers = {'If-Range': '"' + record.sha256 + '"'}
                if offset:
                    headers['Range'] = f'bytes={offset}-'
                with self.transfer._open(path, headers=headers, timeout=180) as response:
                    expected_status = 206 if offset else 200
                    if response.status == 200 and offset:
                        # A legacy server may ignore Range: explicitly restart
                        # this owned temporary, never append the complete body.
                        output.seek(0)
                        output.truncate()
                        offset = 0
                        row['durable_offset'] = 0
                        checksum = hashlib.sha256()
                        expected_status = 200
                        self._save('downloading')
                    if (response.status != expected_status
                        or response.headers.get('X-RCN-SHA256') != record.sha256
                        or response.headers.get('Content-Length') != str(record.size_bytes - offset)
                        or (offset and response.headers.get('Content-Range') !=
                            f'bytes {offset}-{record.size_bytes - 1}/{record.size_bytes}')):
                        raise CollectionConflict('result transfer headers do not match the manifest')
                    checkpoint, checkpoint_time = offset, time.monotonic()
                    received = offset
                    try:
                        while chunk := response.read(CHUNK_BYTES):
                            self._check_cancelled()
                            received += len(chunk)
                            if received > record.size_bytes:
                                raise CollectionConflict('result exceeds declared size')
                            output.write(chunk)
                            checksum.update(chunk)
                            if (received - checkpoint >= CHECKPOINT_BYTES
                                or time.monotonic() - checkpoint_time >= CHECKPOINT_SECONDS):
                                output.flush()
                                os.fsync(output.fileno())
                                row['durable_offset'] = received
                                self._save('downloading')
                                checkpoint, checkpoint_time = received, time.monotonic()
                        if received != record.size_bytes:
                            raise OSError('result transfer ended before declared size')
                    finally:
                        output.flush()
                        os.fsync(output.fileno())
                        row['durable_offset'] = min(output.tell(), record.size_bytes)
                        self._save('downloading')
            if checksum.hexdigest() != record.sha256:
                row['state'] = 'conflict'
                self._save('conflict')
                raise CollectionConflict('managed file size or SHA256 mismatch')
            output.flush()
            os.fsync(output.fileno())
        managed_path(self.root, target.relative_to(self.root).as_posix())
        try:
            publish_new_file(partial, target)
        except FileExistsError:
            verify_file(target, record.size_bytes, record.sha256)
        _sync_directory(target.parent)
        row.update(state='published', durable_offset=record.size_bytes,
            verification_method='sha256_download_stream', path=target.relative_to(self.root).as_posix())
        self._save('downloading')
        partial.unlink(missing_ok=True)

    def run(self):
        self.directory.mkdir(parents=True, exist_ok=True)
        with collection_lock(self.directory / 'writer.lock'), self._volume_slot():
            try:
                local_complete = self.local_files_present()
                if not local_complete and self.capabilities is None:
                    self.capabilities = self.transfer.require_available()
                self._freeze(local_only=local_complete)
                needed = 0
                for entry, record, target, key in self._targets():
                    self._check_cancelled()
                    if target.exists():
                        verify_file(target, record.size_bytes, record.sha256)
                        previous = self.state['files'].get(key)
                        self.state['files'][key] = previous if previous and previous.get('state') == 'published' else {'state': 'published',
                            'work_unit_id': entry['work_unit_id'], 'attempt_id': entry['attempt_id'],
                            'path': target.relative_to(self.root).as_posix(), 'relative_path': record.relative_path,
                            'sha256': record.sha256, 'size_bytes': record.size_bytes,
                            'durable_offset': record.size_bytes, 'verification_method': 'sha256_full_read'}
                    else:
                        row = self.state['files'].get(key, {})
                        needed += max(0, record.size_bytes - row.get('durable_offset', 0))
                self._capacity(needed, reconcile_only=True)
                self._save('downloading', owner={'pid': os.getpid(),
                    'birth': psutil.Process().create_time(), 'child_writers': False})
                for entry, record, target, key in self._targets():
                    self._check_cancelled()
                    if not target.exists():
                        self._download(entry, record, target, key)
                    if volume_for_destination(self.root)[1] != self.state['volume_id']:
                        raise CollectionConflict('collection destination volume changed')
                self._save('bytes_complete')
                self._finalize_locked()
                return [{'work_unit_id': row['work_unit_id'], 'attempt_id': row['attempt_id']}
                        for row in self.entries]
            except BaseException as exc:
                if self.state is not None:
                    phase = collection_failure_state(exc)
                    self._save(phase, error_type=type(exc).__name__)
                    # A refused preparation owns no useful prefix. Keep every
                    # nonempty partial, including bytes saved on connection loss.
                    for partial in self.directory.glob('*.partial'):
                        managed_path(self.directory, partial.name)
                        if partial.stat().st_size == 0:
                            partial.unlink()
                raise
            finally:
                if self.claim is not None:
                    self.budget.release(self.claim, writer_stopped=True, evidence='synchronous_collection_writer_finished')
                    self.claim = None
                    self._save(capacity_claim=None)

    def _finalize_locked(self, metadata=None):
        expected = {}
        for entry, record, target, key in self._targets():
            expected[key] = {'work_unit_id': entry['work_unit_id'], 'attempt_id': entry['attempt_id'],
                'path': target.relative_to(self.root).as_posix(), 'relative_path': record.relative_path,
                'sha256': record.sha256, 'size_bytes': record.size_bytes, 'state': 'published'}
        if set(self.state['files']) != set(expected):
            raise CollectionConflict('collection file coverage differs from the manifest')
        for key, values in expected.items():
            if any(self.state['files'][key].get(field) != value for field, value in values.items()):
                raise CollectionConflict('collection file evidence differs from the manifest')
        self._save('finalizing')
        receipt = {'schema': SCHEMA, 'operation_id': self.operation_id,
            'binding': self.binding, 'contract_sha256': hashlib.sha256(self.contract_path.read_bytes()).hexdigest(),
            'units': [{'work_unit_id': row['work_unit_id'], 'attempt_id': row['attempt_id']}
                      for row in self.entries],
            'files': sorted(self.state['files'].values(), key=lambda row: row['path']),
            'scientific_imported': False, 'custody_attested': False}
        if metadata is not None:
            # A distinct evidence generation cannot mutate an existing receipt.
            durable_json(self.directory / 'finalization-metadata.json', metadata, immutable=True)
        destination = self.directory / 'transport-receipt.json'
        durable_json(destination, receipt, immutable=True)
        self._save('finalized', receipt_path=str(destination),
            receipt_sha256=hashlib.sha256(destination.read_bytes()).hexdigest(), error_type=None)
        return receipt

    def finalize(self, metadata=None):
        """Strictly local read-back and transport finalization, no HTTP calls."""
        self.directory.mkdir(parents=True, exist_ok=True)
        with collection_lock(self.directory / 'writer.lock'), self._volume_slot():
            self._freeze(local_only=True)
            self._capacity(0, reconcile_only=True)
            verified = {}
            for entry, record, target, key in self._targets():
                verify_file(target, record.size_bytes, record.sha256)
                previous = self.state['files'].get(key)
                verified[key] = previous if previous and previous.get('state') == 'published' else {
                    'state': 'published', 'work_unit_id': entry['work_unit_id'], 'attempt_id': entry['attempt_id'],
                    'path': target.relative_to(self.root).as_posix(), 'relative_path': record.relative_path,
                    'sha256': record.sha256, 'size_bytes': record.size_bytes,
                    'durable_offset': record.size_bytes, 'verification_method': 'sha256_full_read'}
            self.state['files'] = verified
            return self._finalize_locked(metadata)

    def local_files_present(self):
        """Cheap local-only eligibility check; finalize() still verifies full SHA.

        A crash can publish the last file before the bytes_complete checkpoint.
        Presence and size select the offline path without depending on that
        checkpoint or reading every partial download on each background retry.
        This method does not assert integrity or create a final receipt.
        """
        if not self.contract_path.is_file():
            return False
        state = self.status()
        contract = json.loads(self.contract_path.read_text(encoding='utf-8'))
        if contract.get('binding') != self.binding:
            raise CollectionConflict('frozen collection contract changed')
        self.entries = self._validate_index(contract['index'])
        volume = volume_for_destination(self.root)[1]
        if state.get('volume_id', volume) != volume:
            raise CollectionConflict('collection destination volume changed')
        for _, record, target, _ in self._targets():
            try:
                if not target.is_file() or target.stat().st_size != record.size_bytes:
                    return False
            except FileNotFoundError:
                return False
        return True

    def receipt(self, metadata=None):
        """Read the committed transport evidence, without asserting new custody.

        Call after run() in the same flow, or to recover an already committed
        acknowledgement. Use finalize() when a new local full read is required.
        """
        with collection_lock(self.directory / 'writer.lock'):
            state = self.status()
            if state['phase'] != 'finalized':
                raise CollectionConflict('collection has no committed final receipt')
            path = managed_path(self.directory, 'transport-receipt.json')
            raw = path.read_bytes()
            if hashlib.sha256(raw).hexdigest() != state.get('receipt_sha256'):
                raise CollectionConflict('committed transport receipt changed')
            receipt = json.loads(raw)
            if receipt.get('binding') != self.binding or receipt.get('operation_id') != self.operation_id:
                raise CollectionConflict('committed transport receipt identity changed')
            self.state = state
            self._capacity(0, reconcile_only=True)
            if metadata is not None:
                durable_json(self.directory / 'finalization-metadata.json', metadata, immutable=True)
            return receipt
