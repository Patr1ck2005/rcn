"""Owner-session launch gate for the dedicated member execution account.

Only the standard library is used. A lock or disconnected desktop still counts
as a signed-in session; logout prevents new processes while existing work drains.
The immutable binding is outside the mutable worker root.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
from uuid import UUID

EXECUTION_INTENT = '.rcn-member-execution.json'
RETIREMENT_PROOF = '.rcn-member-retirement-proof.json'


def _run_identity(supervisor, request):
    return {'schema_version': 1, 'machine_id': supervisor.machine_id,
        'root_uuid': supervisor.root_uuid, 'runtime_version': supervisor.runtime_version,
        **{key: request[key] for key in ('external_run_id', 'job_id', 'work_unit_id', 'request_hash')}}


def record_execution_intent(supervisor, request, run_dir):
    """Write before Popen, including profiles without the COMSOL start gate."""
    path = Path(run_dir)/EXECUTION_INTENT
    expected = _run_identity(supervisor, request)
    # Reusing an earlier intent cannot prove an earlier child process stopped.
    with path.open('x', encoding='utf-8') as out:
        json.dump(expected, out, sort_keys=True)
        out.flush()
        os.fsync(out.fileno())


def authorize_execution_intent(supervisor, request, run_dir):
    """Owner/session check follows fsync, immediately before the caller's Popen."""
    record_execution_intent(supervisor, request, run_dir)
    if supervisor._member_launch_permission()['allowed']:
        return True
    path = Path(run_dir)/EXECUTION_INTENT
    if _read(path) != _run_identity(supervisor, request):
        raise ValueError('fresh execution intent changed')
    path.unlink()  # This caller has not invoked Popen; queued identity is intact.
    return False


def reconcile_retirement(supervisor):
    """Withdraw only exact queued/prepared work with durable no-launch evidence.

    This runs in the same supervisor loop that owns Popen. Missing or conflicting
    metadata remains pending; live work is neither cancelled nor moved. Proof is
    written before retention so a crash between the move and publication resumes
    the same withdrawal rather than losing its evidence.
    """
    if supervisor._member_launch_permission().get('reason') != 'member-retiring':
        return None
    root = Path(supervisor.root)
    try:
        control = _read(root.parent/'owner-control/state.json')
        operation = control['retirement_operation_id']
        if str(UUID(operation)) != operation or not control['retired'] or not control['paused']:
            return None
    except (OSError, ValueError, KeyError, TypeError):
        return None
    try:
        from .worker_storage import START_GATE, SCRATCH_MARKER
    except ImportError:
        from worker_storage import START_GATE, SCRATCH_MARKER
    active_root = root/'runs/active'
    retained_root = root/'runs/retained/failed'
    withdrawals, pending = {}, set()
    paths = list(active_root.glob('*/*/*/.rcn-run.json'))
    paths += list(retained_root.glob('*/*/*/' + RETIREMENT_PROOF))
    for marker_path in sorted(paths):
        run_dir = marker_path.parent
        external = 'unknown:' + run_dir.name
        try:
            request = _read(run_dir/'request.json', maximum=1048576)
            external = request['external_run_id']
            marker = _read(run_dir/'.rcn-run.json')
            supervisor._validate_request(dict(request))
            expected = _run_identity(supervisor, request)
            if (request['machine_id'] != supervisor.machine_id
                    or request['runtime_version'] != supervisor.runtime_version
                    or not re.fullmatch(r'[a-f0-9]{64}', request['request_hash'])
                    or marker.get('root_uuid') != supervisor.root_uuid
                    or any(marker.get(key) != request[key] for key in ('external_run_id', 'request_hash'))):
                raise ValueError('retirement run identity changed')
            relative = run_dir.resolve().relative_to(root.resolve())
            active = relative.parts == ('runs', 'active', request['project_id'], request['job_id'], request['work_unit_id'])
            retained = (relative.parts[:5] == ('runs', 'retained', 'failed', request['project_id'], request['job_id'])
                and len(relative.parts) == 6 and (relative.parts[5] == request['work_unit_id']
                    or relative.parts[5].startswith(request['work_unit_id']+'-conflict-')))
            if not active and not retained:
                raise ValueError('retirement run path changed')
            if external in supervisor.active:
                pending.add(external)
                continue
            if (run_dir/EXECUTION_INTENT).exists() or (run_dir/START_GATE).exists() or (run_dir/'progress.json').exists():
                raise ValueError('run has execution evidence')
            for name in ('stdout.txt', 'stderr.txt'):
                log = run_dir/name
                if log.exists() and log.stat().st_size:
                    raise ValueError('run has process output')
            proof_path = run_dir/RETIREMENT_PROOF
            proof = {**expected, 'operation_id': operation, 'never_started': True}
            status = _read(supervisor.status_path(external))
            if any(status.get(key) != request[key] for key in ('external_run_id','machine_id','job_id','work_unit_id','request_hash')):
                raise ValueError('retirement status identity changed')
            if proof_path.exists():
                if _read(proof_path) != proof or status.get('state') not in {'prepared','queued','cancelled'}:
                    raise ValueError('retirement proof changed')
            elif active and status.get('state') in {'prepared','queued'} and status.get('started_at') is None:
                if (run_dir/SCRATCH_MARKER).exists() and not rollback_prelaunch_scratch(
                        root, supervisor.root_uuid, run_dir, request, known_not_launched=True):
                    pending.add(external)
                    continue
                with proof_path.open('x', encoding='utf-8') as out:
                    json.dump(proof, out, sort_keys=True)
                    out.flush()
                    os.fsync(out.fileno())
            else:
                raise ValueError('run is not confirmed unstarted')
            if active:
                supervisor._finish_failed(request, run_dir, 'cancelled before launch: member retirement; confirmed never started', cancelled=True)
            elif retained:
                supervisor.publish(request, 'cancelled', 'cancelled before launch: member retirement; confirmed never started',
                    100, str(relative), False)
            status = _read(supervisor.status_path(external))
            if status.get('state') != 'cancelled' or status.get('artifacts_available') is not False:
                raise ValueError('retirement cancellation not published')
            withdrawals[external] = {key: expected[key] for key in ('external_run_id','job_id','work_unit_id','request_hash')}
            withdrawals[external].update(state='cancelled', never_started=True, artifacts_available=False, started_at=None)
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            pending.add(external)
    pending.update(path.stem for path in (root/'spool/incoming').glob('*.ready'))
    pending.update(path.stem for path in (root/'spool/incoming').glob('*.part'))
    receipt = {'schema_version': 1, 'machine_id': supervisor.machine_id,
        'root_uuid': supervisor.root_uuid, 'runtime_version': supervisor.runtime_version,
        'operation_id': operation, 'updated_at': datetime.now(timezone.utc).isoformat(),
        'active_run_ids': sorted(supervisor.active), 'pending_run_ids': sorted(pending),
        'withdrawals': [withdrawals[key] for key in sorted(withdrawals)]}
    path = root/'agent/member-retirement.json'
    temporary = path.with_suffix('.tmp')
    with temporary.open('w', encoding='utf-8') as out:
        json.dump(receipt, out, sort_keys=True)
        out.flush()
        os.fsync(out.fileno())
    os.replace(temporary, path)
    return receipt


def _read(path, *, maximum=16384):
    path = Path(path)
    if path.is_symlink() or path.stat().st_size > maximum:
        raise ValueError("invalid member gate file")
    return json.loads(path.read_text(encoding="utf-8"))


def current_sid():
    """Read this process token without relying on usernames or environment."""
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    token = wintypes.HANDLE()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        size = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        buffer = ctypes.create_string_buffer(size.value)
        if not advapi.GetTokenInformation(token, 1, buffer, size, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        text = wintypes.LPWSTR()
        if not advapi.ConvertSidToStringSidW(ctypes.c_void_p(sid), ctypes.byref(text)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return text.value
        finally:
            kernel.LocalFree(text)
    finally:
        kernel.CloseHandle(token)


def _account_sid(name):
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi.LookupAccountNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_void_p,
        ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD)]
    sid_size, domain_size, kind = wintypes.DWORD(), wintypes.DWORD(), wintypes.DWORD()
    advapi.LookupAccountNameW(None, name, None, ctypes.byref(sid_size), None, ctypes.byref(domain_size), ctypes.byref(kind))
    sid = ctypes.create_string_buffer(sid_size.value)
    domain = ctypes.create_unicode_buffer(domain_size.value)
    if not advapi.LookupAccountNameW(None, name, sid, ctypes.byref(sid_size), domain, ctypes.byref(domain_size), ctypes.byref(kind)):
        raise ctypes.WinError(ctypes.get_last_error())
    text = wintypes.LPWSTR()
    if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(text)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return text.value
    finally:
        kernel = ctypes.WinDLL("kernel32")
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.LocalFree(text)


def logged_on_sids():
    """Enumerate local/remote signed-in Windows sessions including locked ones."""
    class Session(ctypes.Structure):
        _fields_ = [("id", wintypes.DWORD), ("station", wintypes.LPWSTR), ("state", ctypes.c_int)]
    wts = ctypes.WinDLL("wtsapi32", use_last_error=True)
    rows, count = ctypes.POINTER(Session)(), wintypes.DWORD()
    wts.WTSEnumerateSessionsW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(ctypes.POINTER(Session)), ctypes.POINTER(wintypes.DWORD)]
    wts.WTSQuerySessionInformationW.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_int,
        ctypes.POINTER(wintypes.LPWSTR), ctypes.POINTER(wintypes.DWORD)]
    wts.WTSFreeMemory.argtypes = [ctypes.c_void_p]
    if not wts.WTSEnumerateSessionsW(None, 0, 1, ctypes.byref(rows), ctypes.byref(count)):
        raise ctypes.WinError(ctypes.get_last_error())
    def text(session, field):
        result, size = wintypes.LPWSTR(), wintypes.DWORD()
        if not wts.WTSQuerySessionInformationW(None, session, field, ctypes.byref(result), ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return result.value or ""
        finally:
            wts.WTSFreeMemory(result)
    try:
        result = set()
        for index in range(count.value):
            row = rows[index]
            if row.state not in {0, 1, 4}:  # Active, Connected, Disconnected
                continue
            user = text(row.id, 5)
            if user:
                domain = text(row.id, 7)
                result.add(_account_sid((domain + "\\" if domain else "") + user))
        return result
    finally:
        wts.WTSFreeMemory(rows)


def launch_permission(config, *, required=False, sid_reader=None, sessions_reader=None):
    """A machine capacity change cannot override this separate owner binding."""
    root = Path(config["remote_root"])
    binding_path = root.parent / "execution-identity.json"
    if not required and not binding_path.exists():
        return {"allowed": True, "reason": "legacy-runtime"}
    try:
        if os.name != "nt" and (sid_reader is None or sessions_reader is None):
            return {"allowed": False, "reason": "member-session-requires-windows"}
        binding = _read(binding_path)
        if (binding.get("schema_version") != 1 or binding.get("worker_root") != str(root)
                or binding.get("root_uuid") != config["root_uuid"]
                or not re.fullmatch(r"S-1-5-21-(?:[0-9]+-){3}[0-9]+", binding.get("owner_sid", ""))
                or not re.fullmatch(r"S-1-5-21-(?:[0-9]+-){3}[0-9]+", binding.get("execution_sid", ""))):
            raise ValueError("member identity mismatch")
        if (sid_reader or current_sid)() != binding["execution_sid"]:
            return {"allowed": False, "reason": "member-execution-identity-mismatch"}
        control = _read(root.parent / "owner-control" / "state.json")
        if (control.get("schema_version") != 1 or control.get("root_uuid") != binding["root_uuid"]
                or control.get("owner_sid") != binding["owner_sid"]
                or type(control.get("revision")) is not int or control["revision"] < 0
                or type(control.get("paused")) is not bool or type(control.get("retired")) is not bool):
            raise ValueError("member control mismatch")
        if control["retired"]:
            return {"allowed": False, "reason": "member-retiring"}
        if control["paused"]:
            return {"allowed": False, "reason": "owner-paused"}
        if binding["owner_sid"] not in (sessions_reader or logged_on_sids)():
            return {"allowed": False, "reason": "owner-logged-out"}
        return {"allowed": True, "reason": "owner-logged-on"}
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return {"allowed": False, "reason": "member-session-unconfirmed"}


def run_sealed_worker(argv=None):
    """Execute only this version's unchanged fixed bootstrap with hidden children.

    Embeddable Python ignores PYTHONPATH. Insert the explicit sealed directories
    here, and apply Windows console suppression before MPh imports Popen. No
    scientific worker, template, mesh, solver or export bytes are modified.
    """
    import argparse
    import runpy
    import subprocess
    import sys
    parser = argparse.ArgumentParser()
    parser.add_argument('--worker', required=True)
    parser.add_argument('--job', required=True)
    args = parser.parse_args(argv)
    remote = Path(__file__).resolve().parent
    bootstrap = remote/'comsol_worker_bootstrap.py'
    if Path(args.worker).resolve() != bootstrap:
        raise ValueError('fixed sealed bootstrap required')
    for path in (remote, remote.parent/'workbench-src', remote.parent/'site-packages'):
        if path.is_dir() and str(path) not in sys.path:
            sys.path.insert(0, str(path))
    if os.name == 'nt':
        original = subprocess.Popen
        class HiddenPopen(original):
            def __init__(self, *arguments, **options):
                options['creationflags'] = options.get('creationflags', 0) | subprocess.CREATE_NO_WINDOW
                super().__init__(*arguments, **options)
        subprocess.Popen = HiddenPopen
    sys.argv = [str(bootstrap), '--job', args.job]
    runpy.run_path(str(bootstrap), run_name='__main__')


def rollback_prelaunch_scratch(root, root_uuid, run_dir, request, *, known_not_launched=False):
    """Remove only fresh, never-authorized scratch, preserving the queued Attempt."""
    try:
        from . import worker_storage as storage
    except ImportError:
        import worker_storage as storage
    run_dir = Path(run_dir)
    proof = storage._plain_path(run_dir/'.rcn-member-prelaunch.json', root)
    marker = storage._plain_path(run_dir/storage.SCRATCH_MARKER, root)
    if not marker.exists():
        if proof.exists():
            proof.unlink()
        return True
    expected = storage._identity(root, root_uuid, run_dir, request)
    if storage._load(marker) != expected or (run_dir/storage.START_GATE).exists():
        raise ValueError('prelaunch scratch has execution evidence')
    if proof.exists():
        if storage._load(proof) != expected:
            raise ValueError('prelaunch proof identity changed')
    elif known_not_launched:
        with proof.open('x', encoding='utf-8') as out:
            json.dump(expected, out, sort_keys=True)
    else:
        raise ValueError('never-launched proof required')
    try:
        result = storage.cleanup_scratch(root, root_uuid, run_dir, request, tree_stopped=True)
        if result['state'] not in {'cleaned','already_clean'}:
            return False
        marker.unlink()
        proof.unlink()
        return True
    except OSError:
        return False  # Exact never-launched proof permits bounded next-loop retry.


if __name__ == '__main__':
    run_sealed_worker()
