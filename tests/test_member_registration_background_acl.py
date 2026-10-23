"""Background ACL checks stay enforced without creating Windows consoles."""
import os
import subprocess
from types import SimpleNamespace

import pytest

from research_compute_network import member_registration as client


@pytest.mark.parametrize('kind', ['directory', 'file'])
@pytest.mark.parametrize('returncode', [0, 1])
def test_windows_acl_checks_hide_console_and_preserve_rejection(tmp_path, monkeypatch, kind, returncode):
    target = tmp_path / 'private-state'
    target.mkdir(mode=0o700)
    if kind == 'file':
        target = target / 'credential'
        target.write_bytes(b'not-a-real-secret')
    calls = []
    no_window = 0x08000000

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=returncode)

    # Simulate the Windows branch without changing the process-wide os.name or
    # launching a shell on a non-Windows test host.
    monkeypatch.setattr(client, 'os', SimpleNamespace(name='nt'))
    monkeypatch.setattr(client, '_managed_worker_acl', lambda path: '')
    monkeypatch.setattr(client, 'subprocess', SimpleNamespace(run=run, CREATE_NO_WINDOW=no_window))
    check = (lambda: client._private_directory(target, create=False)) if kind == 'directory' else (
        lambda: client._check_private_file(target))
    if returncode:
        with pytest.raises(client.MemberRegistrationError, match=f'registration_{"root" if kind == "directory" else "file"}_permissions'):
            check()
    else:
        check()

    assert len(calls) == 1
    command, kwargs = calls[0]
    assert command[:4] == ['powershell.exe', '-NoProfile', '-NonInteractive', '-Command']
    assert 'Get-Acl -LiteralPath' in command[4]
    assert 'GetOwner([Security.Principal.SecurityIdentifier])' in command[4]
    assert 'Other reader or writer' in command[4]
    assert kwargs == dict(capture_output=True, timeout=20, check=False, creationflags=no_window)


@pytest.mark.parametrize('kind', ['directory', 'file'])
def test_posix_private_acl_checks_do_not_launch_a_shell(monkeypatch, kind):
    target = SimpleNamespace(is_dir=lambda: True, exists=lambda: True,
        stat=lambda: SimpleNamespace(st_uid=123, st_mode=0o100600 if kind == 'file' else 0o40700))
    monkeypatch.setattr(client, 'os', SimpleNamespace(name='posix', getuid=lambda: 123))
    monkeypatch.setattr(client, 'subprocess', SimpleNamespace(run=lambda *args, **kwargs: pytest.fail('POSIX shell spawn')))
    monkeypatch.setattr(client, '_unlinked', lambda path: None)
    if kind == 'directory':
        client._private_directory(target, create=False)
    else:
        client._check_private_file(target)


@pytest.mark.skipif(os.name != 'nt', reason='native Windows ACL and console API')
def test_native_windows_private_acl_calls_execute_without_console(tmp_path, monkeypatch):
    native_run = subprocess.run
    results = []
    console_probe = r"""
Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public static class RcnAclConsoleProbe { [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow(); }'
[RcnAclConsoleProbe]::GetConsoleWindow().ToInt64()
"""

    def run(command, **kwargs):
        assert kwargs['creationflags'] == subprocess.CREATE_NO_WINDOW
        command = [*command[:-1], command[-1] + console_probe]
        result = native_run(command, **kwargs)
        results.append(result)
        return result

    monkeypatch.setattr(client.subprocess, 'run', run)
    root = tmp_path / 'native-private-state'
    client._private_directory(root)
    credential = root / 'credential'
    credential.write_bytes(b'not-a-real-secret')
    client._check_private_file(credential)

    assert len(results) == 2
    assert all(result.returncode == 0 and result.stdout.strip() == b'0' for result in results)
