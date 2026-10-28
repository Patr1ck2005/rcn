from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from types import SimpleNamespace
from urllib.error import URLError

import pytest

from research_compute_network import member_client_lifecycle as lifecycle


@pytest.fixture
def logical_service_state(monkeypatch):
    # Native ACL creation is covered by the separate real-process case.
    def state(root):
        Path(root).mkdir(parents=True, exist_ok=True)
        return Path(root) / "service.json"
    monkeypatch.setattr(lifecycle, "_state", state)


def test_local_identity_rejects_another_service_on_the_fixed_port(tmp_path, monkeypatch, logical_service_state):
    started = []
    monkeypatch.setattr(lifecycle, "_request", lambda *a, **k: {"mode": "member-client", "instance_id": "another-member"})
    monkeypatch.setattr(lifecycle.subprocess, "Popen", lambda *a, **k: started.append(a))
    with pytest.raises(RuntimeError, match="port_in_use_by_another_service"):
        lifecycle.launch(tmp_path / "owner", open_browser=False)
    assert started == []


def test_launch_reuses_the_same_client_and_does_not_open_browser_on_logon(tmp_path, monkeypatch, logical_service_state):
    root = tmp_path / "owner"
    started, opened = [], []
    monkeypatch.setattr(lifecycle, "_request", lambda *a, **k: {"mode": "member-client", "instance_id": lifecycle.instance_id(root)})
    monkeypatch.setattr(lifecycle.subprocess, "Popen", lambda *a, **k: started.append(a))
    monkeypatch.setattr(lifecycle.webbrowser, "open", lambda url: opened.append(url))
    assert lifecycle.launch(root, open_browser=False)["running"]
    assert started == [] and opened == []
    lifecycle.launch(root, open_browser=True)
    assert opened == [lifecycle.URL + "/member"]


def test_launch_uses_hidden_pythonw_and_the_importable_module_name(tmp_path, monkeypatch, logical_service_state):
    root = tmp_path / "owner"
    checks = iter([{"running": False}, {"running": True}, {"running": True}])
    calls = []
    monkeypatch.setattr(lifecycle, "status", lambda value: next(checks))
    monkeypatch.setattr(lifecycle.subprocess, "Popen", lambda command, **options: calls.append((command, options)))
    lifecycle.launch(root, open_browser=False)
    command, options = calls[0]
    assert command[2:4] == ["-m", "research_compute_network.member_client_lifecycle"]
    assert "supervise" in command and str(root.absolute()) in command
    assert options["stdin"] == options["stdout"] == options["stderr"] == subprocess.DEVNULL
    if os.name == "nt":
        assert Path(command[0]).name == "pythonw.exe"
        assert options["creationflags"] & subprocess.CREATE_NO_WINDOW


def test_changed_process_birth_refuses_shutdown_without_sending_any_signal(tmp_path, monkeypatch, logical_service_state):
    root = tmp_path / "owner"
    root.mkdir()
    receipt = {"pid": 12345, "birth": 10, "executable": sys.executable,
        "instance_id": lifecycle.instance_id(root), "shutdown_key": "synthetic-private-key"}
    (root / "service.json").write_text(json.dumps(receipt), encoding="utf-8")
    request_calls = []
    monkeypatch.setattr("psutil.Process", lambda pid: SimpleNamespace(create_time=lambda: 11, exe=lambda: sys.executable,
        cmdline=lambda: ["pythonw.exe", "-m", lifecycle.MODULE]))
    monkeypatch.setattr(lifecycle, "_request", lambda *a, **k: request_calls.append(a))
    with pytest.raises(RuntimeError, match="process_identity_changed"):
        lifecycle.stop(root)
    assert not request_calls
    assert (root / "service.json").is_file()


def test_matching_process_receives_only_its_owner_shutdown_key(tmp_path, monkeypatch, logical_service_state):
    root = tmp_path / "owner"
    root.mkdir()
    receipt = {"pid": 12345, "birth": 10, "executable": sys.executable,
        "instance_id": lifecycle.instance_id(root), "shutdown_key": "synthetic-private-key"}
    (root / "service.json").write_text(json.dumps(receipt), encoding="utf-8")
    request_calls, waits = [], []
    monkeypatch.setattr("psutil.Process", lambda pid: SimpleNamespace(create_time=lambda: 10, exe=lambda: sys.executable,
        cmdline=lambda: ["pythonw.exe", "-m", lifecycle.MODULE], wait=lambda timeout: waits.append(timeout)))
    monkeypatch.setattr(lifecycle, "_request", lambda *args: request_calls.append(args))
    assert lifecycle.stop(root, timeout=7) == {"stopped": True}
    assert waits == [7]
    assert request_calls == [("/local/v1/shutdown", {}, {"X-RCN-Shutdown": "synthetic-private-key", "Content-Type": "application/json"})]


@pytest.mark.parametrize("ownership", ["marker", "service", "startup"])
def test_old_version_uninstall_preserves_new_version_and_compute(tmp_path, monkeypatch, ownership):
    root = tmp_path / "member-state"
    root.mkdir()
    first = tmp_path / "software-v1/pythonw.exe"
    newer = tmp_path / "software-v2/pythonw.exe"
    monkeypatch.setattr(lifecycle, "_pythonw", lambda: first)
    marker = root / "active-version.json"
    marker.write_text(json.dumps({"schema_version": 1, "pythonw_path": str(newer if ownership == "marker" else first)}), encoding="utf-8")
    if ownership == "service":
        (root / "service.json").write_text(json.dumps({"executable": str(newer)}), encoding="utf-8")
    if ownership == "startup":
        class Key:
            def __enter__(self): return self
            def __exit__(self, *args): pass
        command = subprocess.list2cmdline([str(newer), "-B", "-m", lifecycle.MODULE, "launch", "--no-open", "--state-root", str(root)])
        monkeypatch.setitem(sys.modules, "winreg", SimpleNamespace(HKEY_CURRENT_USER=object(),
            OpenKey=lambda *a: Key(), QueryValueEx=lambda *a: (command, 1)))
    monkeypatch.setattr(lifecycle, "stop", lambda *a, **k: pytest.fail("old version must not stop the active newer broker"))
    monkeypatch.setattr("research_compute_network.member_client_compute.ContributionManager",
        lambda root: pytest.fail("old software uninstall must not retire current compute"))
    original = marker.read_bytes()
    retained = root / "retained-result.csv"
    retained.write_bytes(b"retained fixture result")
    result = lifecycle.uninstall(root)
    assert result["inactive_version"] and result["identity_and_results_preserved"]
    assert marker.read_bytes() == original
    assert retained.read_bytes() == b"retained fixture result"


@pytest.mark.skipif(os.name != "nt", reason="Windows registry and shortcut entry contract")
def test_active_version_uninstall_removes_only_its_matching_entry(tmp_path, monkeypatch):
    root = tmp_path / "member-state"
    root.mkdir()
    pythonw = tmp_path / "software-v2/pythonw.exe"
    monkeypatch.setattr(lifecycle, "_pythonw", lambda: pythonw)
    marker = root / "active-version.json"
    marker.write_text(json.dumps({"schema_version": 1, "pythonw_path": str(pythonw)}), encoding="utf-8")
    events = []
    class Key:
        def __enter__(self): return self
        def __exit__(self, *args): pass
    command = lifecycle._startup_command(root)
    registry = SimpleNamespace(HKEY_CURRENT_USER=object(), OpenKey=lambda *a: Key(), CreateKey=lambda *a: Key(),
        QueryValueEx=lambda *a: (command, 1), DeleteValue=lambda key, name: events.append(("registry", name)))
    monkeypatch.setitem(sys.modules, "winreg", registry)
    monkeypatch.setattr("research_compute_network.member_client_compute.ContributionManager",
        lambda root: SimpleNamespace(uninstall=lambda: events.append(("compute", "drained"))))
    monkeypatch.setattr(lifecycle, "stop", lambda root: events.append(("broker", "stopped")))
    monkeypatch.setattr(lifecycle.subprocess, "run", lambda command, **kwargs: events.append(("shortcut", command[-1])))
    retained = root / "retained-result.csv"
    retained.write_bytes(b"retained fixture result")
    result = lifecycle.uninstall(root)
    assert result["identity_and_results_preserved"] and not result.get("inactive_version")
    assert [item[0] for item in events] == ["compute", "broker", "registry", "shortcut"]
    assert "TargetPath -ieq" in events[-1][1] and str(pythonw) in events[-1][1]
    assert not marker.exists() and retained.read_bytes() == b"retained fixture result"


@pytest.mark.skipif(os.name != "nt", reason="native hidden Windows process and DPAPI service root")
def test_real_native_client_start_reuse_stop_preserves_private_data(tmp_path, monkeypatch):
    # The fixed production port must be available; never displace another app.
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        probe.bind(("127.0.0.1", lifecycle.LOCAL_PORT))
    except OSError:
        pytest.skip("fixed member port already occupied; no existing service is modified")
    finally:
        probe.close()
    root = tmp_path / "native-member"
    lifecycle._state(root)
    retained = root / "results" / "retained.csv"
    lifecycle.storage._private_directory(retained.parent)
    retained.write_bytes(b"synthetic retained scientific output\n")
    source = Path(lifecycle.__file__).parents[1]
    monkeypatch.setenv("PYTHONPATH", str(source))
    started = lifecycle.launch(root, open_browser=False)
    try:
        assert started["running"]
        assert started["instance_id"] == lifecycle.instance_id(root)
        receipt = json.loads((root / "service.json").read_text(encoding="utf-8"))
        assert lifecycle.launch(root, open_browser=False) == started
        assert json.loads((root / "service.json").read_text(encoding="utf-8"))["pid"] == receipt["pid"]
        assert lifecycle.stop(root)["stopped"]
        assert not (root / "service.json").exists()
        assert retained.read_bytes() == b"synthetic retained scientific output\n"
        assert lifecycle.status(root) == {"running": False}
    finally:
        if (root / "service.json").exists():
            lifecycle.stop(root)


def test_explicit_stop_is_not_revoked_by_automatic_logon_restore(tmp_path, monkeypatch, logical_service_state):
    root = tmp_path / "owner"
    lifecycle._state(root)
    lifecycle._intent(root, "stopped")
    monkeypatch.setattr(lifecycle, "status", lambda *_: pytest.fail("automatic restore contacted port after explicit stop"))
    monkeypatch.setattr(lifecycle.subprocess, "Popen", lambda *a, **kw: pytest.fail("explicit stop was revoked"))
    assert lifecycle.launch(root, open_browser=False, restore=True) == {"running": False, "explicitly_stopped": True}
    assert "--restore" in lifecycle._startup_command(root)


def test_supervisor_restores_real_child_exit_within_recovery_bound(tmp_path, monkeypatch, logical_service_state):
    root = tmp_path / "supervised"
    lifecycle._state(root); lifecycle._intent(root, "running")
    started = []; clocks = []
    monkeypatch.setattr(lifecycle, "status", lambda *_: {"running": False})
    class Child:
        def wait(self, timeout):
            assert timeout <= 60
            if len(started) == 1:
                return 27  # A real process exited abnormally; its original owner restarts it.
            lifecycle._intent(root, "stopped")
            return 0
    def popen(command, **options):
        started.append((command, options)); return Child()
    monkeypatch.setattr(lifecycle.subprocess, "Popen", popen)
    monkeypatch.setattr(lifecycle.time, "sleep", lambda delay: clocks.append(delay))
    lifecycle.supervise(root, check_interval=1)
    assert len(started) == 2 and clocks == [1]
    assert all("serve" in command and str(root.absolute()) in command for command, _ in started)
    assert all(options["stdout"] == subprocess.DEVNULL for _, options in started)


def test_managed_supervisor_observes_real_process_exit_and_restores_under_60_seconds(tmp_path, monkeypatch, logical_service_state):
    import time
    import psutil
    root = tmp_path / "real-child-exit"
    lifecycle._state(root); lifecycle._intent(root, "running")
    marker = root / "child-identities.jsonl"
    intent = root / "client-intent.json"
    stopped = json.dumps({"instance_id": lifecycle.instance_id(root), "desired_state": "stopped"})
    child_source = (
        "import os,pathlib,sys; p=pathlib.Path(" + repr(str(marker)) + "); "
        "old=p.read_text() if p.exists() else ''; p.open('a').write(str(os.getpid())+'\\n'); "
        "pathlib.Path(" + repr(str(intent)) + ").write_text(" + repr(stopped) + ") if old else None; "
        "sys.exit(0 if old else 27)"
    )
    monkeypatch.setattr(lifecycle, "status", lambda *_: {"running": False})
    monkeypatch.setattr(lifecycle, "_serve_command", lambda _: [sys.executable, "-c", child_source])
    started = time.monotonic()
    lifecycle.supervise(root, check_interval=.05)
    pids = [int(value) for value in marker.read_text().splitlines()]
    assert len(pids) == 2 and pids[0] != pids[1]
    assert time.monotonic() - started < 60
    assert not any(psutil.pid_exists(pid) for pid in pids)
    assert lifecycle._intent(root) == "stopped"


@pytest.mark.skipif(os.name != "nt", reason="native Windows private-root API lifecycle")
def test_real_member_api_process_crash_recovers_under_60_seconds_on_isolated_port(tmp_path, monkeypatch):
    import time
    import psutil
    root = tmp_path / "real-member-recovery"
    lifecycle._state(root)
    lifecycle._intent(root, "running")
    retained = root / "retained-fixture.csv"; retained.write_bytes(b"preserved result fixture")
    probe = socket.socket(); probe.bind(("127.0.0.1", 0)); port = probe.getsockname()[1]; probe.close()
    monkeypatch.setattr(lifecycle, "LOCAL_PORT", port)
    monkeypatch.setattr(lifecycle, "URL", "http://127.0.0.1:" + str(port))
    prefix = "from pathlib import Path; from research_compute_network import member_client_lifecycle as lifecycle; lifecycle.LOCAL_PORT=" + str(port) + "; lifecycle.URL=" + repr(lifecycle.URL) + "; "
    serve_source = prefix + "lifecycle.serve(Path(" + repr(str(root)) + "))"
    serve_command = [sys.executable, "-c", serve_source, lifecycle.MODULE, "serve", "--state-root", str(root)]
    supervisor_source = prefix + "lifecycle._serve_command=lambda root:" + repr(serve_command) + "; lifecycle.supervise(Path(" + repr(str(root)) + "),check_interval=.2)"
    env = {**os.environ, "PYTHONPATH": str(Path(lifecycle.__file__).parents[1]),
           "RCN_COLLECTION_STATE_HOME": str(root / "isolated-collection-state")}
    supervisor = subprocess.Popen([sys.executable, "-c", supervisor_source, lifecycle.MODULE, "supervise", "--state-root", str(root)],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env,
        creationflags=subprocess.CREATE_NO_WINDOW)
    def await_api(previous=None):
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if lifecycle.status(root)["running"] and (root / "service.json").exists():
                receipt = json.loads((root / "service.json").read_bytes())
                if previous is None or receipt["pid"] != previous:
                    return receipt
            time.sleep(.2)
        pytest.fail("original member API was not restored under 60 seconds")
    try:
        original = await_api()
        crashed = psutil.Process(original["pid"])
        assert abs(crashed.create_time() - original["birth"]) < .001
        started = time.monotonic()
        crashed.terminate(); crashed.wait(timeout=10)
        restored = await_api(previous=original["pid"])
        assert time.monotonic() - started < 60 and restored["instance_id"] == original["instance_id"]
        assert retained.read_bytes() == b"preserved result fixture"
        assert lifecycle.stop(root)["stopped"]
        supervisor.wait(timeout=10)
        time.sleep(.5)
        assert lifecycle.status(root) == {"running": False}
        assert lifecycle._intent(root) == "stopped"
        assert retained.read_bytes() == b"preserved result fixture"
    finally:
        lifecycle._intent(root, "stopped")
        if lifecycle.status(root)["running"]:
            lifecycle.stop(root)
        supervisor.wait(timeout=35)


def test_restore_cannot_overwrite_stop_between_intent_read_and_status(tmp_path,monkeypatch,logical_service_state):
    root=tmp_path/'interleaved-owner'
    lifecycle._state(root);lifecycle._intent(root,'running')
    original=lifecycle._intent;writes=[];started=[]
    def intent(path,desired=None):
        if desired is not None:writes.append(desired)
        return original(path,desired)
    def status(path):
        # Deterministic interleaving: explicit stop commits after restore's
        # first intent read, before its port-status response returns.
        original(path,'stopped')
        return {'running':False}
    monkeypatch.setattr(lifecycle,'_intent',intent)
    monkeypatch.setattr(lifecycle,'status',status)
    monkeypatch.setattr(lifecycle.subprocess,'Popen',lambda *a,**kw:started.append(a))
    assert lifecycle.launch(root,open_browser=False,restore=True)=={'running':False,'explicitly_stopped':True}
    assert original(root)=='stopped'and writes==[]and started==[]


def test_restore_observes_stop_during_supervisor_start_without_new_running_intent(tmp_path,monkeypatch,logical_service_state):
    root=tmp_path/'start-interleaving'
    lifecycle._state(root);lifecycle._intent(root,'running')
    original=lifecycle._intent;writes=[];started=[]
    def intent(path,desired=None):
        if desired is not None:writes.append(desired)
        return original(path,desired)
    def popen(*a,**kw):
        started.append(a);original(root,'stopped')
    monkeypatch.setattr(lifecycle,'_intent',intent)
    monkeypatch.setattr(lifecycle,'status',lambda *_:{'running':False})
    monkeypatch.setattr(lifecycle.subprocess,'Popen',popen)
    monkeypatch.setattr(lifecycle.time,'sleep',lambda *_:pytest.fail('restore kept waiting after explicit stop'))
    assert lifecycle.launch(root,open_browser=False,restore=True)=={'running':False,'explicitly_stopped':True}
    assert original(root)=='stopped'and writes==[]and len(started)==1


def test_actual_stop_wins_deterministic_restore_thread_interleaving(tmp_path,monkeypatch,logical_service_state):
    import threading
    root=tmp_path/'actual-stop-race'
    lifecycle._state(root);lifecycle._intent(root,'running')
    in_status=threading.Event();stop_committed=threading.Event();started=[];result=[];errors=[]
    def status(path):
        if threading.current_thread().name=='automatic-restore':
            in_status.set();assert stop_committed.wait(3)
        return {'running':False}
    monkeypatch.setattr(lifecycle,'status',status)
    monkeypatch.setattr(lifecycle.subprocess,'Popen',lambda *a,**kw:started.append(a))
    def restore():
        try:result.append(lifecycle.launch(root,open_browser=False,restore=True))
        except BaseException as exc:errors.append(exc)
    thread=threading.Thread(target=restore,name='automatic-restore');thread.start()
    try:
        assert in_status.wait(3)
        assert lifecycle.stop(root)=={'stopped':True}
    finally:
        stop_committed.set();thread.join(3)
    assert not thread.is_alive()and not errors
    assert result==[{'running':False,'explicitly_stopped':True}]
    assert lifecycle._intent(root)=='stopped'and started==[]
