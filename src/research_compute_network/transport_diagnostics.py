"""Small, evidence-based transport classifications; never reflect remote text."""
import socket
import ssl


def network_failure_code(error):
    reason = getattr(error, 'reason', error)
    if isinstance(reason, socket.gaierror):
        return 'center_dns_unavailable'
    if isinstance(reason, ssl.SSLCertVerificationError):
        return 'center_certificate_invalid'
    if isinstance(reason, ssl.SSLError):
        return 'center_tls_failed'
    return 'center_unavailable'


def gateway_failure_code(status, headers, body):
    # A generic origin 502 is not evidence of Cloudflare or a dead Tunnel.
    if not headers or not headers.get('cf-ray'):
        return None
    lowered = body[:16384].lower()
    if status == 530 and ('1033' in lowered or 'tunnel error' in lowered):
        return 'center_tunnel_unavailable'
    if status in {502, 503, 504, 521, 522, 523, 524}:
        return 'center_origin_unavailable'
    if status in {525, 526}:
        return 'center_gateway_tls_failed'
    return None
