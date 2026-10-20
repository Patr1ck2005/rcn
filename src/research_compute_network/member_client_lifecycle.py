"""Owner-scoped desktop entry and logon restoration for the local client.

The coordinator, worker tasks and local client have separate lifecycles. A port
collision is reported, never resolved by killing a process or selecting a port.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener
import webbrowser

from . import member_registration as storage
from .member_client import LOCAL_PORT, create_member_app, default_client_root, _write_json, _read_json

ENTRY_NAME = "ResearchComputeNetwork-MemberClient"
MODULE = "research_compute_network.member_client_lifecycle"
URL = f"http://127.0.0.1:{LOCAL_PORT}"


def instance_id(root):
    return hashlib.sha256(str(Path(root).absolute()).casefold().encode()).hexdigest()[:24]


def _request(path, payload=None, headers=None):
    body = json.dumps(payload).encode() if payload is not None else None
    request = Request(URL + path, data=body, headers=headers or {}, method="POST" if body is not None else "GET")
    with build_opener(ProxyHandler({})).open(request, timeout=3) as response:
        return json.loads(response.read(1024 * 1024))


def _state(root):
    root = Path(root).absolute()
    storage._private_directory(root)
    return root / "service.json"


def _pythonw():
    return Path(sys.executable).absolute().with_name("pythonw.exe")


def _same_executable(left, right):
    return os.path.normcase(str(Path(left).absolute())) == os.path.normcase(str(Path(right).absolute()))


def _startup_command(root):
    return subprocess.list2cmdline([str(_pythonw()), "-B", "-m", MODULE, "launch", "--no-open", "--restore", "--state-root", str(Path(root).absolute())])


def _owns_active_version(root):
    """An old version's uninstaller must not retire a newer installation."""
    root = Path(root).absolute()
    marker = root / "active-version.json"
    if marker.exists() and not _same_executable(_read_json(marker)["pythonw_path"], _pythonw()):
        return False
    service = root / "service.json"
    if service.exists() and not _same_executable(_read_json(service)["executable"], _pythonw()):
        return False
    if os.name == "nt":
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run") as key:
                current = winreg.QueryValueEx(key, ENTRY_NAME)[0]
                if MODULE in current and current != _startup_command(root):
                    return False
        except FileNotFoundError:
            pass
    return True


def status(root):
    try:
        value = _request("/local/v1/capabilities")
    except (HTTPError, ValueError):
        raise RuntimeError("member_client_port_in_use_by_another_service") from None
    except (URLError, OSError):
        return {"running": False}
    if value.get("mode") != "member-client" or value.get("instance_id") != instance_id(root):
        raise RuntimeError("member_client_port_in_use_by_another_service")
    return {"running": True, "instance_id": value["instance_id"], "url": URL}


def _intent(root, desired=None):
    path = Path(root).absolute() / "client-intent.json"
    if desired is not None:
        _state(root)
        _write_json(path, {"instance_id": instance_id(root), "desired_state": desired, "at": time.time()})
    if not path.exists():
        return "running"
    value = _read_json(path)
    if value.get("instance_id") != instance_id(root) or value.get("desired_state") not in {"running", "stopped"}:
        raise RuntimeError("member_client_intent_identity_changed")
    return value["desired_state"]


def launch(root, *, open_browser=True, restore=False):
    root = Path(root).absolute()
    _state(root)
    if restore and _intent(root) == "stopped":
        return {"running": False, "explicitly_stopped": True}
    # Validate port ownership before changing the managed intent.
    running = status(root)["running"]
    if restore:
        # Restore never grants a new running intent. A concurrent explicit stop
        # wins even when it arrived after the first intent read/port probe.
        if _intent(root) == "stopped":
            return {"running": False, "explicitly_stopped": True}
    else:
        _intent(root, "running")
    if not running:
        python = Path(sys.executable)
        hidden_python = python.with_name("pythonw.exe") if os.name == "nt" else python
        if not hidden_python.is_file():
            hidden_python = python
        command = [str(hidden_python), "-B", "-m", MODULE, "supervise", "--state-root", str(root)]
        if restore and _intent(root) == "stopped":
            return {"running": False, "explicitly_stopped": True}
        subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        # First launch prepares owner-private directories with native ACL checks.
        # Concurrent Windows security scans can outlast a 15-second UI budget.
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if restore and _intent(root) == "stopped":
                return {"running": False, "explicitly_stopped": True}
            if status(root)["running"]:
                break
            time.sleep(.15)
        else:
            raise RuntimeError("member_client_start_failed")
    if restore and _intent(root) == "stopped":
        return {"running": False, "explicitly_stopped": True}
    if open_browser:
        webbrowser.open(URL + "/member")
    return status(root)


def _serve_command(root):
    return [sys.executable, "-B", "-m", MODULE, "serve", "--state-root", str(root)]


def supervise(root, *, check_interval=1):
    """One owner-scoped supervisor restarts only its local API after real exit."""
    from .collection import collection_lock, CollectionBusy
    import psutil
    root = Path(root).absolute()
    _state(root)
    try:
        with collection_lock(root / "supervisor.lock"):
            process = psutil.Process()
            identity = {"pid": process.pid, "birth": process.create_time(), "executable": process.exe(),
                        "instance_id": instance_id(root)}
            _write_json(root / "supervisor.json", identity)
            while _intent(root) == "running":
                if status(root)["running"]:
                    time.sleep(check_interval)
                    continue
                command = _serve_command(root)
                child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
                while True:
                    try:
                        child.wait(timeout=check_interval)
                        break
                    except subprocess.TimeoutExpired:
                        if _intent(root) == "stopped":
                            # The owner's stop API drains the exact child. No kill fallback.
                            return
                if _intent(root) == "running":
                    time.sleep(check_interval)
    except CollectionBusy:
        return


def serve(root):
    import psutil
    import uvicorn
    root = Path(root).absolute()
    path = _state(root)
    if _intent(root) == "stopped":
        return
    shutdown_key = secrets.token_urlsafe(32)
    stop_event = threading.Event()
    app = create_member_app(state_root=root)
    app.state.instance_id = instance_id(root)
    app.state.shutdown_key = shutdown_key
    app.state.stop_event = stop_event
    process = psutil.Process()
    receipt = {"schema_version": 1, "pid": process.pid, "birth": process.create_time(),
               "executable": process.exe(), "instance_id": instance_id(root), "shutdown_key": shutdown_key}
    # Only publish after binding our exact socket. Failed starts do not replace
    # another instance's shutdown receipt.
    import socket
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if os.name == "nt":
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    try:
        listener.bind(("127.0.0.1", LOCAL_PORT))
        listener.listen(128)
        _write_json(path, receipt)
        server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=LOCAL_PORT, log_level="warning"))
        def stopper():
            while not stop_event.wait(1):
                if _intent(root) == "stopped":
                    break
            server.should_exit = True
        threading.Thread(target=stopper, daemon=True).start()
        server.run(sockets=[listener])
    finally:
        listener.close()
        if path.exists() and _read_json(path).get("shutdown_key") == shutdown_key:
            path.unlink()


def _wait_supervisor(root, timeout):
    import psutil
    path = Path(root).absolute() / "supervisor.json"
    if not path.exists():
        return
    value = _read_json(path)
    if value.get("instance_id") != instance_id(root):
        raise RuntimeError("member_client_supervisor_identity_changed")
    try:
        process = psutil.Process(value["pid"])
        if abs(process.create_time() - value["birth"]) >= .001:
            return  # This original supervisor exited; a reused PID is untouched.
        arguments = process.cmdline()
        if (Path(process.exe()) != Path(value["executable"]) or MODULE not in arguments
            or "supervise" not in arguments or str(Path(root).absolute()) not in arguments):
            raise RuntimeError("member_client_supervisor_identity_changed")
        process.wait(timeout=timeout)
    except psutil.NoSuchProcess:
        return
    except psutil.TimeoutExpired:
        raise RuntimeError("member_client_supervisor_still_draining") from None


def stop(root, *, timeout=35):
    import psutil
    path = _state(root)
    _intent(root, "stopped")
    if not path.exists():
        if status(root)["running"]:
            raise RuntimeError("member_client_receipt_missing")
        _wait_supervisor(root, timeout)
        return {"stopped": True}
    value = _read_json(path)
    try:
        process = psutil.Process(value["pid"])
        same = (abs(process.create_time() - value["birth"]) < .001 and
                Path(process.exe()) == Path(value["executable"]) and
                "research_compute_network.member_client_lifecycle" in process.cmdline() and
                value["instance_id"] == instance_id(root))
    except psutil.NoSuchProcess:
        path.unlink()
        _wait_supervisor(root, timeout)
        return {"stopped": True}
    if not same:
        raise RuntimeError("member_client_process_identity_changed")
    _request("/local/v1/shutdown", {}, {"X-RCN-Shutdown": value["shutdown_key"], "Content-Type": "application/json"})
    try:
        process.wait(timeout=timeout)
    except psutil.TimeoutExpired:
        raise RuntimeError("member_client_transfer_still_draining") from None
    _wait_supervisor(root, timeout)
    return {"stopped": True}


def install_entry(root, *, desktop=True, startup=True):
    if os.name != "nt":
        raise RuntimeError("member_client_entry_requires_windows")
    import winreg
    # Updating the software cannot leave an old local API serving new assets.
    stop(root)
    python = _pythonw()
    if not python.is_file():
        raise RuntimeError("member_client_pythonw_missing")
    arguments = subprocess.list2cmdline(["-B", "-m", MODULE, "launch", "--state-root", str(Path(root).absolute())])
    command = _startup_command(root)
    if startup:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run") as key:
            winreg.SetValueEx(key, ENTRY_NAME, 0, winreg.REG_SZ, command)
    if desktop:
        from .member_ssh_service import _powershell
        def literal(value):
            return "'" + str(value).replace("'", "''") + "'"
        script = "$w=New-Object -ComObject WScript.Shell;$s=$w.CreateShortcut((Join-Path ([Environment]::GetFolderPath('Desktop')) 'Research Compute Network.lnk'));$s.TargetPath=" + literal(python) + ";$s.Arguments=" + literal(arguments) + ";$s.WindowStyle=7;$s.Save()"
        result = subprocess.run([_powershell(), "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, timeout=15)
        if result.returncode:
            raise RuntimeError("member_client_shortcut_failed")
    _write_json(Path(root).absolute() / "active-version.json", {
        "schema_version": 1, "pythonw_path": str(python),
    })
    return {"entry_installed": True, "startup": startup, "desktop": desktop}


def uninstall(root):
    if not _owns_active_version(root):
        return {"uninstalled": True, "inactive_version": True, "identity_and_results_preserved": True}
    # Ask the execution identity helper to pause and drain before withdrawing
    # tasks/services. Credentials, registration history and results remain.
    from .member_client_compute import ContributionManager
    ContributionManager(Path(root)).uninstall()
    stop(root)
    if os.name == "nt":
        import winreg
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run") as key:
            try:
                current = winreg.QueryValueEx(key, ENTRY_NAME)[0]
                if current == _startup_command(root):
                    winreg.DeleteValue(key, ENTRY_NAME)
            except FileNotFoundError:
                pass
        from .member_ssh_service import _powershell
        expected_python = "'" + str(_pythonw()).replace("'", "''") + "'"
        script = "$p=Join-Path ([Environment]::GetFolderPath('Desktop')) 'Research Compute Network.lnk';if(Test-Path -LiteralPath $p){$w=New-Object -ComObject WScript.Shell;$s=$w.CreateShortcut($p);if(($s.Arguments -like '*research_compute_network.member_client_lifecycle*') -and ($s.TargetPath -ieq " + expected_python + ")){Remove-Item -LiteralPath $p}}"
        subprocess.run([_powershell(), "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, timeout=15, check=True)
    marker = Path(root).absolute() / "active-version.json"
    if marker.exists() and _same_executable(_read_json(marker)["pythonw_path"], _pythonw()):
        marker.unlink()
    return {"uninstalled": True, "identity_and_results_preserved": True}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["serve", "supervise", "launch", "stop", "install-entry", "uninstall", "status"])
    parser.add_argument("--state-root", type=Path, default=default_client_root())
    parser.add_argument("--no-open", action="store_true")
    parser.add_argument("--restore", action="store_true")
    parser.add_argument("--no-desktop", action="store_true")
    parser.add_argument("--no-startup", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.action == "serve":
            serve(args.state_root)
        elif args.action == "supervise":
            supervise(args.state_root)
        elif args.action == "launch":
            launch(args.state_root, open_browser=not args.no_open, restore=args.restore)
        elif args.action == "install-entry":
            install_entry(args.state_root, desktop=not args.no_desktop, startup=not args.no_startup)
        elif args.action == "uninstall":
            uninstall(args.state_root)
        elif args.action == "stop":
            stop(args.state_root)
        else:
            print(json.dumps(status(args.state_root)))
        return 0
    except Exception as exc:
        # No secret-bearing exception strings from HTTP/native calls.
        from .member_registration import MemberRegistrationError
        reason = str(exc) if isinstance(exc, (RuntimeError, MemberRegistrationError)) and str(exc).startswith("member_") else "member_client_action_failed"
        if Path(sys.executable).name.casefold() == "pythonw.exe":
            import ctypes
            ctypes.windll.user32.MessageBoxW(None, "RCN 客户端未完成操作：" + reason + "\n请将此编号提供给管理员。原身份和结果会保留。", "Research Compute Network", 16)
        else:
            print(json.dumps({"completed": False, "reason_code": reason}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
