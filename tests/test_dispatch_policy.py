"""Exact resource windows, configurable ordering and atomic policy changes."""
from datetime import datetime, timedelta, timezone
import pytest
from pydantic import ValidationError
from conftest import approved_grant,open_machine,register_live_machine,project_approval,simple_job
from research_compute_network.dispatch_policy import SchedulingPolicy,dispatch_order,usage_from_projections,job_size
from research_compute_network.models import FeatureSettings,WorkUnitStatus
from research_compute_network.scheduling_controls import SchedulingChange,SchedulingConfirmation,preview,confirm

NOW=datetime(2026,10,1,12,tzinfo=timezone.utc)

def projection():
    def attempt(identity,state,start=None,end=None,cpus=1,gpus=0):
        return dict(attempt_id=identity,state=state,started_at=start.isoformat() if start else None,
            finished_at=end.isoformat() if end else None,resolved_resources={'resources':{'cpus':cpus,'gpus':gpus}})
    return {'job_id':'one','project_id':'project','user_id':'owner','record_class':'production','work_units':[
        {'work_unit_id':'old','status':'completed','actual_duration_s':999999,'attempts':[
            attempt('old-a','completed',NOW-timedelta(days=4),NOW-timedelta(days=3),64)]},
        {'work_unit_id':'overlap','status':'completed','attempts':[
            attempt('window-a','failed',NOW-timedelta(hours=3),NOW-timedelta(hours=1),4,1)]},
        {'work_unit_id':'live','status':'running','attempts':[
            attempt('live-a','running',NOW-timedelta(minutes=30),cpus=2)]},
        {'work_unit_id':'unknown','status':'completed','attempts':[attempt('unknown','completed')]},
    ]}

def test_exact_window_not_job_update_time_and_live_failures_count():
    value=usage_from_projections([projection()],now=NOW,hours=2)
    p=value['projects']['project'];assert p==value['users']['owner']
    assert p['wall_seconds']==5400 and p['core_seconds']==18000 and p['gpu_seconds']==3600
    assert p['timed_attempts']==2 and p['missing_timing_attempts']==1 and p['live_attempts']==1

def test_collection_wait_does_not_keep_charging_observed_finished_execution():
    value=projection();unit=value['work_units'][2];a=unit['attempts'][0]
    a['execution_end_observed_at']=(NOW-timedelta(minutes=20)).isoformat()
    a['state']='reconcile_pending';a['execution_completed']=True
    result=usage_from_projections([value],now=NOW,hours=2)['projects']['project']
    assert result['core_seconds']==15600 and result['observed_execution_end_attempts']==1
    a.pop('execution_end_observed_at')
    unknown=usage_from_projections([value],now=NOW,hours=2)['projects']['project']
    assert unknown['core_seconds']==14400 and unknown['missing_timing_attempts']==2


def test_duplicates_and_acceptance_do_not_inflate_usage():
    item=projection();acceptance={**item,'job_id':'acceptance','record_class':'acceptance'}
    value=usage_from_projections([item,item,acceptance],now=NOW,hours=2)
    assert value['projects']['project']['core_seconds']==18000

def sized_job(count,letter,age=0,last_age=None):
    job=simple_job(request_hash=letter*64);base=job.work_units[0]
    job.work_units=[base.model_copy(deep=True,update={'work_unit_id':f'{letter}-{i}',
        'ordinal':i,'expected_duration_s':60}) for i in range(count)]
    job.created_at=NOW-timedelta(seconds=age)
    job.last_scheduled_at=NOW-timedelta(seconds=last_age) if last_age is not None else None
    return job

def test_small_batch_first_with_equal_project_entitlement():
    policy=SchedulingPolicy(strategy='small_batch_first');large=sized_job(30,'a');small=sized_job(2,'b')
    order=lambda j:dispatch_order(j,now=NOW,policy=policy,priority=0)
    assert sorted([large,small],key=order)==[small,large]
    huge=sized_job(1,'c');huge.work_units[0].expected_duration_s=7200
    assert not job_size(huge,policy)['small_batch']

def test_starvation_serves_large_without_preemption_and_resets_after_service():
    policy=SchedulingPolicy(strategy='small_batch_first',starvation_after_s=3600)
    large=sized_job(30,'a',age=7200);small=sized_job(1,'b')
    assert dispatch_order(large,now=NOW,policy=policy,priority=-100)>dispatch_order(small,now=NOW,policy=policy,priority=100)
    assert dispatch_order(large,now=NOW,policy=policy,priority=0)<dispatch_order(small,now=NOW,policy=policy,priority=0)
    large.last_scheduled_at=NOW
    assert dispatch_order(large,now=NOW,policy=policy,priority=0)>dispatch_order(small,now=NOW,policy=policy,priority=0)

def test_project_band_prevents_unlimited_advantage_from_job_splitting():
    policy=SchedulingPolicy(strategy='small_batch_first');small=sized_job(1,'b');large=sized_job(30,'a')
    assert dispatch_order(large,now=NOW,policy=policy,priority=0,project_usage={'core_seconds':0}) < dispatch_order(
        small,now=NOW,policy=policy,priority=0,project_usage={'core_seconds':7200})

@pytest.mark.parametrize('strategy',['balanced','small_batch_first','throughput'])
def test_strategies_preserve_scientific_payloads(strategy):
    jobs=[sized_job(20,'a'),sized_job(2,'b')];before=[j.model_dump_json() for j in jobs]
    sorted(jobs,key=lambda j:dispatch_order(j,now=NOW,policy=SchedulingPolicy(strategy=strategy),priority=0))
    assert [j.model_dump_json() for j in jobs]==before

@pytest.mark.parametrize('values',[{'strategy':'shell-command'},{'starvation_after_s':True},
    {'small_batch_max_units':0},{'history_window_hours':169},{'extra':'forbidden'}])
def test_invalid_policy_rejected(values):
    with pytest.raises(ValidationError):SchedulingPolicy(**values)

def test_real_assignment_uses_small_batch_and_hard_caps(service):
    settings=service.repository.get_feature_settings();settings.scheduling_policy=SchedulingPolicy(strategy='small_batch_first')
    service.repository.put_feature_settings(settings, preserve_scheduling=False);service.register_project(approved_grant(),actor_id='admin')
    machine,policy=open_machine();register_live_machine(service,machine,policy);service.approve(project_approval(),actor_id='owner-1')
    large=sized_job(8,'a');small=sized_job(1,'b');large.created_at=small.created_at=datetime.now(timezone.utc)
    a=service.submit(large,actor_id='user-a');b=service.submit(small,actor_id='user-a')
    assert service.schedule_once().job_id==b.job_id
    assert service.repository.get_job(a.job_id).work_units[0].status==WorkUnitStatus.QUEUED

def test_confirmation_actor_bound_monotonic_atomic_and_idempotent(service):
    repo=service.repository
    change=SchedulingChange(expected_revision=0,policy=SchedulingPolicy(strategy='small_batch_first'),reason='owner-approved small batches')
    p=preview(repo,change,'admin');request=SchedulingConfirmation(**change.model_dump(),confirmation_hash=p['confirmation_hash'])
    with pytest.raises(ValueError,match='mismatch'):confirm(repo,request,'other-admin')
    before=repo.latest_event_sequence();first=confirm(repo,request,'admin')
    assert first['revision']==1 and not first['replayed']
    assert confirm(repo,request,'admin')['replayed'] and repo.latest_event_sequence()==before+1
    c=SchedulingChange(expected_revision=1,policy=SchedulingPolicy(strategy='balanced'),reason='return to balance')
    confirm(repo,SchedulingConfirmation(**c.model_dump(),confirmation_hash=preview(repo,c,'admin')['confirmation_hash']),'admin')
    with pytest.raises(ValueError,match='revision_conflict'):confirm(repo,request,'admin')

def test_policy_confirmation_preserves_machine_configs_and_other_settings(service):
    machine,policy=open_machine();register_live_machine(service,machine,policy)
    before=service.repository.get_policy(machine.machine_id).model_dump_json()
    settings=service.repository.get_feature_settings();settings.show_machine_details=False;service.repository.put_feature_settings(settings)
    c=SchedulingChange(expected_revision=0,policy=SchedulingPolicy(strategy='throughput'),reason='explicit optimization')
    confirm(service.repository,SchedulingConfirmation(**c.model_dump(),confirmation_hash=preview(service.repository,c,'admin')['confirmation_hash']),'admin')
    assert service.repository.get_policy(machine.machine_id).model_dump_json()==before
    assert not service.repository.get_feature_settings().show_machine_details
    with pytest.raises(ValueError,match='dedicated'):
        service.update_feature_settings(FeatureSettings(scheduling_policy=SchedulingPolicy(strategy='balanced')),actor_id='admin')
