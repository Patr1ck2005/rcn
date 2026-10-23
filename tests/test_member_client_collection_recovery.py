from __future__ import annotations
from copy import deepcopy
import json
from pathlib import Path
import threading
import time
from types import SimpleNamespace
from uuid import uuid4
import pytest
from research_compute_network import member_client as member
from research_compute_network.client import RcnApiError

class Credentials:
    def load(self):
        return {"actor": {"actor_id": "owner"}, "center_url": "https://center.example", "token": "fixture"}

@pytest.fixture
def broker(tmp_path, monkeypatch):
    monkeypatch.setattr(member.storage, "_private_directory", lambda root: Path(root).mkdir(parents=True, exist_ok=True))
    result=member.MemberBroker(tmp_path/'member',credential_store=Credentials(),api_factory=lambda *a, **kw: object())
    yield result
    result.close()


def operation(broker, state="retry_wait", phase="collection-interrupted", actor="owner"):
    operation_id=str(uuid4())
    value={"operation_id": operation_id, "actor_id": actor, "center_url": "https://center.example",
           "job_id": "original-job", "phase": phase,
           "collection_control": {"state": state, "operation_id": "member-collection-"+operation_id, "next_retry_at": 0}}
    member._write_json(broker.journal_path(operation_id), value)
    return operation_id


def test_startup_recovers_only_unpaused_original_owner_collections(broker, monkeypatch):
    original=operation(broker);operation(broker,state="user_paused");operation(broker,state="fault_paused")
    operation(broker,phase="upload-interrupted");operation(broker,actor="another")
    calls=[]
    monkeypatch.setattr(broker,"_schedule_collection",lambda op,delay:calls.append((op,delay)))
    broker.recover_collections()
    assert calls==[(original,0)]


def test_retry_timer_reuses_executor_and_original_operation_and_paused_stays_paused(broker, monkeypatch):
    original=operation(broker)
    started=[]
    monkeypatch.setattr(broker,"_transfer",lambda op,collect:started.append((op,collect)))
    # Exercise the real Timer callback without waiting through production backoff.
    broker._schedule_collection(original,.01)
    deadline=time.monotonic()+2
    while not started and time.monotonic()<deadline:time.sleep(.01)
    assert started==[(original,True)]
    broker.busy.clear();broker.collection_active=None
    broker.pause_collection(original)
    broker._schedule_collection(original,.01)
    time.sleep(.1)
    assert started==[(original,True)]


def test_real_network_fault_records_backoff_and_integrity_fault_pauses_one_operation(broker, monkeypatch):
    original=operation(broker)
    delays=[]
    monkeypatch.setattr(broker,"_schedule_collection",lambda op,delay:delays.append((op,delay)))
    monkeypatch.setattr(member.random,"uniform",lambda *a:1)
    class Client:
        def get_job_contract(self,job):raise RcnApiError(0,"synthetic disconnected")
    broker.api_factory=lambda *a,**kw:Client();broker.transfer_factory=lambda _:object()
    for expected in [30,60,120,240,300]:
        broker._transfer(original,True)
        assert delays[-1]==(original,expected)
    Client.get_job_contract=lambda *a:(_ for _ in ()).throw(ValueError("changed hash"))
    broker._transfer(original,True)
    value=broker.read_operation(original)
    assert value['collection_control']['state']=='fault_paused'and len(delays)==5
    assert value['job_id']=='original-job'


def test_active_download_pause_signals_only_its_own_original_cancel_event(broker):
    original=operation(broker);other=operation(broker)
    first=threading.Event();second=threading.Event()
    broker.collection_cancels={original:first,other:second}
    broker.pause_collection(original)
    assert first.is_set()and not second.is_set()
    assert broker.read_operation(original)['collection_control']['state']=='user_paused'


def test_bytes_complete_restart_finalizes_locally_and_saves_formal_transport_receipt(broker,monkeypatch):
    from research_compute_network import collection
    original=operation(broker)
    frozen={"job":{"job_id":"original-job"},"manifests":[{"files":[{}]}]}
    broker.update(original,collection_request=frozen)
    called=[]
    class Runner:
        def __init__(self,transfer,job,manifests,directory,**kwargs):
            assert kwargs['operation_id']=='member-collection-'+original
            kwargs['progress']({'stage':'source_preparing','received_bytes':5,'total_bytes':10,
                                'source_checked_bytes':7,'source_total_bytes':10})
            live=broker.read_operation(original)['collection']
            assert live['received_bytes']==5 and live['source_checked_bytes']==7
        def status(self):return {"phase":"bytes_complete"}
        def local_files_present(self):return True
        def run(self):pytest.fail("bytes-complete restart downloaded again")
        def finalize(self,metadata):called.append(metadata);return {"scientific_imported":False,"units":[]}
    monkeypatch.setattr(collection,'CollectionRunner',Runner)
    broker.transfer_factory=lambda _:object()
    broker._transfer(original,True)
    value=broker.read_operation(original)
    assert value['phase']=='collected'and called
    receipt=json.loads(Path(value['collection']['receipt_path']).read_bytes())
    assert receipt['job_id']=='original-job'and receipt['receipt']['scientific_imported']is False


def test_collection_uses_canonical_contract_method_when_available():
    api=SimpleNamespace(get_job_contract=lambda job:{"job_id":job},get_job=lambda *_:pytest.fail("detail DTO used"))
    assert member._collection_job_contract(api,"original-job")=={"job_id":"original-job"}


def test_relogin_keeps_explicit_collection_pause(broker,monkeypatch):
    original=operation(broker,state='user_paused')
    broker.credentials.save=lambda **kw:None
    broker.api_factory=lambda *a,**kw:SimpleNamespace(current_actor=lambda:{'actor_id':'owner'})
    scheduled=[]
    monkeypatch.setattr(broker,'_schedule_collection',lambda *a:scheduled.append(a))
    broker.sign_in(member.Login(center_url='https://center.example',token='fixture'))
    assert not scheduled and broker.read_operation(original)['collection_control']['state']=='user_paused'


def test_successful_run_reuses_committed_receipt_without_second_payload_read(broker,monkeypatch):
    from research_compute_network import collection
    original=operation(broker)
    broker.update(original,collection_request={'job':{'job_id':'original-job'},'manifests':[{'files':[{}]}]})
    calls=[]
    class Runner:
        def __init__(self,*args,**kwargs):self.phase='planned'
        def status(self):return {'phase':self.phase}
        def local_files_present(self):return False
        def run(self):calls.append('run');self.phase='finalized'
        def receipt(self,metadata):calls.append('receipt');return {'scientific_imported':False,'units':[]}
        def finalize(self,metadata):pytest.fail('successful run read payload twice')
    monkeypatch.setattr(collection,'CollectionRunner',Runner)
    broker.transfer_factory=lambda _:object()
    broker._transfer(original,True)
    assert calls==['run','receipt']and broker.read_operation(original)['phase']=='collected'
