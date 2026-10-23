from __future__ import annotations

import hashlib
from io import BytesIO
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from research_compute_network.collection import CollectionRunner, CollectionConflict, collection_lock, CollectionBusy
from research_compute_network.hashing import sha256_value
from research_compute_network.models import ArtifactManifest, FileRecord


class Response(BytesIO):
    def __init__(self, content, headers=None, *, status=200, interrupt=False):
        super().__init__(content)
        self.status, self.headers, self.interrupt = status, headers or {}, interrupt
        self.read_count = 0

    def read(self, size=-1):
        self.read_count += 1
        if self.interrupt and self.read_count > 1:
            raise OSError('fixture connection lost')
        return super().read(min(size, 3) if self.interrupt and size >= 0 else size)


def test_local_full_read_and_download_share_one_volume_slot(collection_case):
    c = collection_case
    first = c.runner()
    first.run()
    with first._volume_slot():
        with pytest.raises(CollectionBusy):
            c.runner().finalize()
        with pytest.raises(CollectionBusy):
            c.runner().run()
        # Reading a committed acknowledgement performs no payload IO.
        assert c.runner().receipt()['operation_id'] == first.operation_id
    assert c.runner().finalize()['binding'] == first.binding


def test_public_durable_download_finishes_local_last_publication_without_center(collection_case, monkeypatch):
    from research_compute_network.origin_transfer_client import OriginTransferClient
    c = collection_case
    runner = c.runner()
    original = runner._save
    def crash(phase=None, **fields):
        if phase == 'bytes_complete':
            raise OSError('fixture exit after final publication')
        return original(phase, **fields)
    monkeypatch.setattr(runner, '_save', crash)
    with pytest.raises(OSError, match='final publication'):
        runner.run()
    assert c.target.exists() and c.runner().status()['phase'] == 'retry_wait'
    monkeypatch.setattr(c.transfer, 'require_available', lambda: pytest.fail('offline capability query'))
    monkeypatch.setattr(c.transfer, '_open', lambda *args, **kwargs: pytest.fail('offline request'))
    assert OriginTransferClient.download_results(c.transfer, c.job,
        [c.manifest.model_dump(mode='json')], c.root, operation_id='original-operation', durable=True) == [
            {'work_unit_id': 'unit-a', 'attempt_id': 'attempt-a'}]
    assert c.runner().status()['phase'] == 'finalized'


@pytest.fixture
def collection_case(tmp_path, monkeypatch):
    monkeypatch.setenv('RCN_COLLECTION_STATE_HOME', str(tmp_path / 'owner-state'))
    content = b'original scientific bytes retained across retries'
    record = FileRecord(relative_path='results/result.dat', size_bytes=len(content),
                        sha256=hashlib.sha256(content).hexdigest())
    manifest = ArtifactManifest(job_id='job-a', work_unit_id='unit-a', output_schema='fixture',
        producer={'attempt_id': 'attempt-a', 'external_run_id': 'external-a'}, files=[record])
    job = {'job_id': 'job-a', 'origin_submitter_id': 'origin-a', 'project_id': 'project-a',
        'user_id': 'alice', 'request_hash': 'a' * 64,
        'work_units': [{'work_unit_id': 'unit-a', 'attempts': [{'attempt_id': 'attempt-a',
            'state': 'completed', 'external_run_id': 'external-a'}]}]}
    index = {'job_id': 'job-a', 'units': [{'work_unit_id': 'unit-a', 'attempt_id': 'attempt-a',
        'manifest_sha256': sha256_value(manifest.model_dump(mode='json'))}]}

    class Transfer:
        client = SimpleNamespace(token='fixture-only', base_url='http://127.0.0.1:1')
        interrupted = False
        calls = []

        def require_available(self):
            return {}

        def _read_json(self, response):
            return json.loads(response.read())

        def _open(self, path, *, headers=None, **kwargs):
            self.calls.append((path, headers or {}))
            if path.endswith('/origin-results'):
                return Response(json.dumps(index).encode())
            offset = int((headers or {}).get('Range', 'bytes=0-')[6:-1])
            selected = {'X-RCN-SHA256': record.sha256, 'Content-Length': str(len(content) - offset)}
            if offset:
                selected['Content-Range'] = f'bytes {offset}-{len(content)-1}/{len(content)}'
            return Response(content[offset:], selected, status=206 if offset else 200,
                            interrupt=self.interrupted)

    transfer = Transfer()
    root = tmp_path / 'results'

    def runner(**kwargs):
        return CollectionRunner(transfer, job, [manifest.model_dump(mode='json')], root,
                                operation_id='original-operation', **kwargs)

    return SimpleNamespace(transfer=transfer, runner=runner, root=root, job=job,
        manifest=manifest, record=record, content=content,
        target=root / 'origin-a/incoming/job-a/unit-a/attempt-a/results/result.dat')


def test_interrupted_file_resumes_original_prefix_and_publishes_one_receipt(collection_case):
    c = collection_case
    c.transfer.interrupted = True
    with pytest.raises(OSError, match='connection lost'):
        c.runner().run()
    status = c.runner().status()
    assert status['phase'] == 'retry_wait'
    assert next(iter(status['files'].values()))['durable_offset'] == 3
    assert not c.target.exists()
    c.transfer.interrupted = False
    assert c.runner().run() == [{'work_unit_id': 'unit-a', 'attempt_id': 'attempt-a'}]
    assert c.target.read_bytes() == c.content
    assert c.transfer.calls[-1][1]['Range'] == 'bytes=3-'
    assert len([call for call in c.transfer.calls if call[0].endswith('/origin-results')]) == 1
    state = c.runner().status()
    receipt = Path(state['receipt_path']).read_bytes()
    calls = len(c.transfer.calls)
    c.runner().run()
    assert len(c.transfer.calls) == calls
    assert Path(c.runner().status()['receipt_path']).read_bytes() == receipt
    assert not list(c.root.rglob('*.partial'))


def test_crash_after_file_publication_before_checkpoint_only_finishes_metadata(collection_case, monkeypatch):
    import research_compute_network.collection as module
    c = collection_case
    original = module.publish_new_file
    injected = False

    def publish_then_exit(temporary, destination):
        nonlocal injected
        original(temporary, destination)
        if destination == c.target and not injected:
            injected = True
            raise OSError('fixture died after publication')

    monkeypatch.setattr(module, 'publish_new_file', publish_then_exit)
    with pytest.raises(OSError, match='after publication'):
        c.runner().run()
    assert c.target.read_bytes() == c.content
    before = len(c.transfer.calls)
    c.runner().run()
    assert len(c.transfer.calls) == before
    assert c.runner().status()['phase'] == 'finalized'


def test_receipt_published_before_state_ack_is_recovered_without_download(collection_case, monkeypatch):
    import research_compute_network.collection as module
    c = collection_case
    original = module.durable_json
    injected = False

    def fail_ack(path, payload, **kwargs):
        nonlocal injected
        if Path(path).name == 'operation.json' and payload.get('phase') == 'finalized' and not injected:
            injected = True
            raise OSError('fixture lost final acknowledgement')
        return original(path, payload, **kwargs)

    monkeypatch.setattr(module, 'durable_json', fail_ack)
    with pytest.raises(OSError, match='final acknowledgement'):
        c.runner().run()
    receipt_path = c.runner().directory / 'transport-receipt.json'
    receipt = receipt_path.read_bytes()
    before = len(c.transfer.calls)
    c.runner().run()
    assert receipt_path.read_bytes() == receipt
    assert len(c.transfer.calls) == before


def test_local_finalization_performs_no_http_and_does_not_claim_scientific_import(collection_case, monkeypatch):
    c = collection_case
    c.runner().run()
    monkeypatch.setattr(c.transfer, '_open', lambda *a, **kw: pytest.fail('local finalize made an HTTP request'))
    monkeypatch.setattr(c.transfer, 'require_available', lambda: pytest.fail('local finalize queried capabilities'))
    receipt = CollectionRunner.from_operation(c.transfer, c.root, 'original-operation').finalize()
    assert receipt['scientific_imported'] is False
    assert receipt['custody_attested'] is False


def test_same_size_corruption_is_rejected_and_never_overwritten(collection_case):
    c = collection_case
    c.runner().run()
    corrupt = b'x' * len(c.content)
    c.target.write_bytes(corrupt)
    with pytest.raises(ValueError, match='SHA256 mismatch'):
        c.runner().run()
    assert c.target.read_bytes() == corrupt
    assert c.runner().status()['phase'] == 'conflict'


def test_changed_contract_cannot_reuse_operation_id(collection_case):
    c = collection_case
    c.runner().run()
    c.job['request_hash'] = 'b' * 64
    with pytest.raises(CollectionConflict, match='identity changed'):
        c.runner().run()


def test_second_collector_cannot_enter_original_writer_lock(collection_case):
    c = collection_case
    operation = c.runner()
    with collection_lock(operation.directory / 'writer.lock'):
        with pytest.raises(CollectionBusy):
            c.runner().run()


def test_complete_payload_without_real_frozen_contract_cannot_be_finalized(collection_case):
    c = collection_case
    c.target.parent.mkdir(parents=True)
    c.target.write_bytes(c.content)
    with pytest.raises(CollectionConflict, match='frozen real result contract'):
        c.runner().finalize()


def test_disk_reserve_deferral_is_retryable_not_a_scientific_conflict():
    from research_compute_network.collection import collection_failure_state
    from research_compute_network.origin_transfer_client import ResultCapacityError
    assert collection_failure_state(ResultCapacityError('fixture capacity unavailable')) == 'retry_wait'


@pytest.mark.parametrize('resume_operation', ['original-operation', 'another-original-job-operation'])
@pytest.mark.parametrize('crash_stage', ['body', 'reservation_before_checkpoint'])
def test_abrupt_writer_process_exit_reclaims_exact_claim_and_resumes_durable_prefix(collection_case, tmp_path, resume_operation, crash_stage):
    import os
    import subprocess
    import sys
    import time
    c = collection_case
    source = Path(__file__).resolve().parents[1] / 'src'
    document = tmp_path / 'child-contract.json'
    ready = tmp_path / 'durable-prefix-ready'
    document.write_text(json.dumps({'job': c.job, 'manifest': c.manifest.model_dump(mode='json'),
        'root': str(c.root), 'ready': str(ready), 'content': c.content.hex(), 'crash_stage': crash_stage}))
    child = '''
from io import BytesIO
import json,sys,time
from pathlib import Path
from types import SimpleNamespace
import research_compute_network.collection as module
from research_compute_network.hashing import sha256_value
doc=json.loads(Path(sys.argv[1]).read_text())
module.CHECKPOINT_BYTES=3
content=bytes.fromhex(doc['content'])
original_save=module.CollectionRunner._save
def save(self,phase=None,**fields):
    if doc['crash_stage']=='reservation_before_checkpoint' and fields.get('capacity_claim'):
        Path(doc['ready']).write_text('reservation_committed_before_claim_checkpoint')
        time.sleep(60)
    return original_save(self,phase,**fields)
module.CollectionRunner._save=save
class Stream(BytesIO):
    status=200
    headers={'X-RCN-SHA256':doc['manifest']['files'][0]['sha256'],'Content-Length':str(len(content))}
    def read(self,n=-1):
        if self.tell():
            Path(doc['ready']).write_text('flushed-prefix-and-journal')
            time.sleep(60)
        return super().read(3)
class Transfer:
    client=SimpleNamespace(token='fixture',base_url='http://127.0.0.1:1')
    def require_available(self):return {}
    def _read_json(self,response):return json.loads(response.read())
    def _open(self,path,**kw):
        if path.endswith('/origin-results'):
            return BytesIO(json.dumps({'job_id':'job-a','units':[{'work_unit_id':'unit-a','attempt_id':'attempt-a',
                'manifest_sha256':sha256_value(doc['manifest'])}]}).encode())
        return Stream(content)
module.CollectionRunner(Transfer(),doc['job'],[doc['manifest']],doc['root'],operation_id='original-operation').run()
'''
    environment = dict(os.environ)
    environment['PYTHONPATH'] = os.pathsep.join([str(source), *[p for p in sys.path if 'site-packages' in p]])
    # Run the actual interpreter rather than Windows' venv launcher, so the
    # PID being terminated is the tested writer, not an intermediate parent.
    process = subprocess.Popen([sys._base_executable, '-c', child, str(document)], env=environment,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=0x08000000 if os.name == 'nt' else 0)
    try:
        deadline = time.monotonic() + 15
        while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(.02)
        if not ready.exists():
            process.kill()
            _, stderr = process.communicate(timeout=5)
            pytest.fail('isolated writer never reached durable checkpoint: ' + stderr.decode(errors='replace'))
        process.kill()
        process.communicate(timeout=5)
        state = c.runner().status()
        assert state['owner']['pid'] == process.pid
        if crash_stage == 'body':
            assert next(iter(state['files'].values()))['durable_offset'] == 3
            assert state['capacity_claim']['owner_pid'] == process.pid
        selected = CollectionRunner(c.transfer, c.job, [c.manifest.model_dump(mode='json')], c.root,
                                    operation_id=resume_operation)
        selected.run()
        assert c.target.read_bytes() == c.content
        if resume_operation == 'original-operation' and crash_stage == 'body':
            assert c.transfer.calls[-1][1]['Range'] == 'bytes=3-'
        elif resume_operation != 'original-operation':
            assert c.runner().status()['capacity_recovered_after_owner_exit'] is True
        assert selected.status()['capacity_claim'] is None
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)
