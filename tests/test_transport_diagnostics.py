import io
import socket
import ssl
from email.message import Message
from urllib.error import HTTPError, URLError

import pytest

from research_compute_network.client import RcnApiError, RcnClient
from research_compute_network.member_doctor import error_detail
from research_compute_network.transport_diagnostics import gateway_failure_code, network_failure_code


@pytest.mark.parametrize('reason,code', [
    (socket.gaierror('private connection data'), 'center_dns_unavailable'),
    (ssl.SSLCertVerificationError('private certificate data'), 'center_certificate_invalid'),
    (ssl.SSLError('private tls data'), 'center_tls_failed'),
    (TimeoutError('private network data'), 'center_unavailable'),
])
def test_url_failures_have_actionable_private_free_diagnostics(reason, code):
    error=URLError(reason)
    assert network_failure_code(error)==code
    class Opener:
        def open(self, *a, **k): raise error
    client=RcnClient('https://example.invalid',token='synthetic',opener=Opener())
    with pytest.raises(RcnApiError) as caught:
        client.current_actor()
    detail=error_detail(caught.value)
    assert detail['reason_code']==code
    assert 'private' not in str(detail)
    assert detail['next_action'] and detail['help_slug']


@pytest.mark.parametrize('status,body,expected', [
    (530, 'error code: 1033', 'center_tunnel_unavailable'),
    (502, 'Bad Gateway', 'center_origin_unavailable'),
    (524, 'Timeout', 'center_origin_unavailable'),
    (526, 'Certificate', 'center_gateway_tls_failed'),
    (401, 'Login', None),
])
def test_proxy_diagnosis_requires_gateway_evidence(status,body,expected):
    assert gateway_failure_code(status,{},body) is None
    headers=Message(); headers['CF-Ray']='synthetic'
    assert gateway_failure_code(status,headers,body)==expected
    if expected:
        class Opener:
            def open(self, *a, **k):
                raise HTTPError('https://example.invalid',status,'failed',headers,io.BytesIO(body.encode()))
        with pytest.raises(RcnApiError) as caught:
            RcnClient('https://example.invalid',opener=Opener()).current_actor()
        assert error_detail(caught.value)['reason_code']==expected
