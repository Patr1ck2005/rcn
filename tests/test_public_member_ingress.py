import json

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
import pytest

from research_compute_network.public_member_ingress import (
    INGRESS_HOST, PublicMemberIngress, member_ingress_settings, public_route_access,
)


def client(tmp_path, enabled=True):
    (tmp_path/'member-ingress.json').write_text(json.dumps({
        'schema_version':1,'enabled':enabled,'public_url':'https://rcn.example.org','group_name':'测试课题组'}), encoding='utf-8')
    app=FastAPI()
    @app.get('/v1/me')
    def me(): return {'actor_id':'synthetic'}
    @app.get('/v1/admin/people')
    def admin(): return {'private':True}
    @app.get('/')
    def private_home(): return {'private_home':True}
    @app.put('/v1/member-pairings/example')
    async def pair(request: Request): return {'size':len(await request.body())}
    app.add_middleware(PublicMemberIngress,state_root=tmp_path)
    return TestClient(app)


def test_public_host_cannot_inherit_local_trust(tmp_path):
    c=client(tmp_path)
    r=c.get('/v1/me',headers={'host':INGRESS_HOST})
    assert r.status_code==401
    assert r.headers['cache-control']=='no-store, private'
    assert c.get('/v1/me',headers={'host':INGRESS_HOST,'Authorization':'Bearer synthetic'}).status_code==200


def test_management_never_exposed_even_with_bearer(tmp_path):
    c=client(tmp_path)
    assert c.get('/v1/admin/people',headers={'host':INGRESS_HOST,'Authorization':'Bearer admin'}).status_code==404
    assert c.get('/v1/admin/people').json()=={'private':True}
    assert c.get('/').json()=={'private_home':True}


def test_public_pages_and_actual_hostname(tmp_path):
    c=client(tmp_path)
    response=c.get('/',headers={'host':'rcn.example.org'})
    assert response.status_code==200 and '加入 测试课题组' in response.text
    instructions=c.get('/agent-start',headers={'host':INGRESS_HOST})
    assert 'join --center' in instructions.text and 'https://rcn.example.org' in instructions.text
    assert instructions.headers['cache-control']=='no-store, private'


def test_disabled_or_damaged_descriptor_is_closed(tmp_path):
    c=client(tmp_path,False)
    assert c.get('/',headers={'host':INGRESS_HOST}).status_code==503
    (tmp_path/'member-ingress.json').write_text('{broken',encoding='utf-8')
    assert member_ingress_settings(tmp_path)['enabled'] is False


def test_public_plain_http_redirects_to_configured_https_only(tmp_path):
    c=client(tmp_path)
    response=c.get('/join',headers={'host':INGRESS_HOST,'x-forwarded-proto':'http',
        'x-forwarded-host':'untrusted.invalid'},follow_redirects=False)
    assert response.status_code==308
    assert response.headers['location']=='https://rcn.example.org/join'
    assert response.headers['cache-control']=='no-store, private'


@pytest.mark.parametrize('path',['/v1/admin/storage/status','/docs','/openapi.json','/v1/users','/v1/jobs/x/../admin','/v1/jobs/%2e%2e','/v1/jobs//x','/v1/jobs/x\\y'])
def test_closed_route_set(path):
    assert public_route_access('GET',path) is None


@pytest.mark.parametrize('method,path',[
    ('POST','/v1/jobs/job-a/origin-upload-sessions'),
    ('PUT','/v1/jobs/job-a/origin-upload-sessions/abc/chunk'),
    ('POST','/v1/jobs/job-a/origin-upload-sessions/abc/finalize'),
    ('GET','/v1/jobs/job-a/origin-result-preparations/ticket/content'),
    ('PUT','/v1/me/agent-credentials/abc'),
    ('PUT','/v1/machines/own-machine/policy'),
    ('GET','/v1/metadata-operations/original-operation'),
    ('GET','/v1/operations/insights'),
])
def test_transfer_and_agent_routes_keep_auth(method,path):
    assert public_route_access(method,path)=='authenticated'


def test_pairing_body_is_bounded(tmp_path):
    c=client(tmp_path)
    assert c.put('/v1/member-pairings/example',headers={'host':INGRESS_HOST},content=b'a'*16385).status_code==413
    assert c.put('/v1/member-pairings/example',headers={'host':INGRESS_HOST},content=(b'a'*9000 for _ in range(2))).status_code==413


def test_real_center_public_pairing_and_private_approval(tmp_path, monkeypatch):
    from hashlib import sha256
    from uuid import uuid4
    from research_compute_network.api import create_app
    monkeypatch.setenv('RCN_HOME', str(tmp_path))
    (tmp_path/'member-ingress.json').write_text(json.dumps({
        'schema_version':1, 'enabled':True, 'public_url':'https://rcn.example.org',
        'group_name':'Synthetic acceptance'}), encoding='utf-8')
    app=create_app(database_url='sqlite:///'+(tmp_path/'state.db').as_posix(),
                   trusted_hosts=['testserver'], allow_local_trusted=True)
    c=TestClient(app)
    public={'host':INGRESS_HOST}
    key=str(uuid4())
    secret='synthetic-not-a-real-member-secret'
    request={'name':'Same name', 'device_name':'Synthetic PC',
             'token_hash':sha256(secret.encode()).hexdigest()}
    assert c.get('/v1/member-pairing-info',headers=public).status_code==200
    first=c.put('/v1/member-pairings/'+key,json=request,headers=public)
    assert first.status_code==200, first.text
    assert c.get('/v1/me',headers=public).status_code==401
    approval='/v1/admin/member-pairings/'+key+'/approve'
    assert c.post(approval,json={'create_new':True},headers=public).status_code==404
    approved=c.post(approval,json={'create_new':True})
    assert approved.status_code==200, approved.text
    member={**public, 'Authorization':'Bearer '+secret}
    me=c.get('/v1/me',headers=member)
    assert me.status_code==200, me.text
    assert me.json()['actor_id']==approved.json()['member_id']
    assert c.get('/v1/member-pairings/'+key,headers=member).json()['state']=='approved'
    assert c.get('/v1/admin/member-pairings',headers=member).status_code==404
    assert c.get('/v1/origin-transfer',headers=member).status_code==200
