"""Installed entry migration, transport preservation and hidden background calls."""
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from urllib.error import HTTPError, URLError

import pytest

from research_compute_network import member_client_lifecycle as lifecycle
from research_compute_network import member_client_connection as connection
from test_member_client_connection import local_metadata, fake_processes, add_legacy


@pytest.fixture
def windows_entry(tmp_path, monkeypatch):
    python = tmp_path / "new-runtime" / "pythonw.exe"
    python.parent.mkdir()
    python.write_bytes(b"synthetic installed interpreter")
    monkeypatch.setattr(lifecycle, "_pythonw", lambda: python)
    monkeypatch.setattr(lifecycle, "os", SimpleNamespace(name="nt", path=os.path))
    values, native_calls = {}, []
    class Key:
        def __enter__(self): return self
        def __exit__(self, *args): pass
    def query(key, name):
        if name not in values: raise FileNotFoundError(name)
        return values[name], 1
    monkeypatch.setitem(sys.modules, "winreg", SimpleNamespace(
        HKEY_CURRENT_USER=object(), REG_SZ=1, CreateKey=lambda *a: Key(), OpenKey=lambda *a: Key(),
        QueryValueEx=query, SetValueEx=lambda key,name,reserved,kind,value: values.__setitem__(name,value),
        DeleteValue=lambda key,name: values.pop(name)))
    def run(command, **kwargs):
        native_calls.append((command, kwargs))
        return SimpleNamespace(returncode=0)
    # Patch only this module's launcher; ACL and transport launchers stay intact.
    monkeypatch.setattr(lifecycle, "subprocess", SimpleNamespace(run=run,
        list2cmdline=subprocess.list2cmdline, CREATE_NO_WINDOW=0x08000000))
    return python, values, native_calls


def disconnected_or_legacy():
    if connection._listeners(lifecycle.LOCAL_PORT):
        raise HTTPError(lifecycle.URL, 404, "synthetic legacy gateway", {}, None)
    raise URLError("synthetic disconnected broker")


@pytest.mark.parametrize("mode", ["https", "managed-ssh"])
def test_installed_cli_entry_hands_off_exact_legacy_before_publishing_new_version(
        local_metadata, fake_processes, windows_entry, monkeypatch, mode):
    root, spec, save = local_metadata
    add_legacy(root, spec, fake_processes)
    if mode == "https":
        spec.update(mode="https", https_url="https://center.example")
        spec.pop("ssh")
        save()
    before = {Path(pin["path"]): Path(pin["path"]).read_bytes() for pin in spec["legacy"].values()}
    before[root / connection.SPEC_NAME] = (root / connection.SPEC_NAME).read_bytes()
    result = root / "results" / "retained.csv"
    result.parent.mkdir(); result.write_bytes(b"retained research bytes")
    before[result] = result.read_bytes()
    monkeypatch.setattr(lifecycle, "_request", lambda *a, **kw: disconnected_or_legacy())
    assert lifecycle.main(["install-entry", "--state-root", str(root), "--no-desktop", "--no-startup"]) == 0
    assert json.loads((root / "legacy-console-handoff.json").read_bytes())["completed"]
    assert json.loads((root / "active-version.json").read_bytes())["pythonw_path"] == str(windows_entry[0])
    assert fake_processes[2] == [11, 10] and fake_processes[3] == []
    assert lifecycle._intent(root) == "stopped"
    assert {path: path.read_bytes() for path in before} == before


def test_update_drains_broker_then_hands_off_before_switch_and_hides_shortcut(
        tmp_path, windows_entry, monkeypatch):
    root = tmp_path / "member"; root.mkdir()
    events = []
    monkeypatch.setattr(lifecycle, "stop", lambda value: events.append("drain"))
    monkeypatch.setattr(connection, "prepare_handoff", lambda value: events.append("handoff"))
    original = lifecycle._write_json
    def write(path, value):
        events.append("switch")
        return original(path, value)
    monkeypatch.setattr(lifecycle, "_write_json", write)
    assert lifecycle.install_entry(root, desktop=True, startup=True)["entry_installed"]
    assert events == ["drain", "handoff", "switch"]
    command, kwargs = windows_entry[2][0]
    assert command[1:4] == ["-NoProfile", "-NonInteractive", "-Command"]
    assert "CreateShortcut" in command[-1]
    assert kwargs == {"capture_output": True, "timeout": 15, "creationflags": 0x08000000}
    assert lifecycle.ENTRY_NAME in windows_entry[1]


def test_failed_graceful_drain_does_not_handoff_or_switch(tmp_path, windows_entry, monkeypatch):
    root = tmp_path / "member"; root.mkdir()
    marker = root / "active-version.json"; marker.write_bytes(b"original version marker")
    def drain(root): raise RuntimeError("member_client_transfer_still_draining")
    monkeypatch.setattr(lifecycle, "stop", drain)
    monkeypatch.setattr(connection, "prepare_handoff", lambda *a: pytest.fail("drain has not completed"))
    with pytest.raises(RuntimeError, match="transfer_still_draining"):
        lifecycle.install_entry(root)
    assert marker.read_bytes() == b"original version marker" and not windows_entry[2]


def test_unknown_listener_is_never_retired_or_replaced(
        local_metadata, fake_processes, windows_entry, monkeypatch):
    root, spec, _ = local_metadata
    add_legacy(root, spec, fake_processes)
    fake_processes[1][lifecycle.LOCAL_PORT] = [(999, "127.0.0.1")]
    monkeypatch.setattr(lifecycle, "_request", lambda *a, **kw: disconnected_or_legacy())
    with pytest.raises(RuntimeError, match="legacy_listener_changed"):
        lifecycle.install_entry(root, desktop=False, startup=False)
    assert not fake_processes[2] and not fake_processes[3]
    assert not (root / "active-version.json").exists()


def test_upgrade_preserves_completed_handoff_and_exact_live_ssh_channel(
        local_metadata, fake_processes, windows_entry, monkeypatch):
    root, spec, save = local_metadata
    add_legacy(root, spec, fake_processes)
    reference = save()
    connection.prepare_handoff(root)
    endpoint = connection.resolve_center(root, reference)
    retained = (root / "connection-process.json").read_bytes()
    signals = list(fake_processes[2])
    monkeypatch.setattr(lifecycle, "_request", lambda *a, **kw: disconnected_or_legacy())
    assert lifecycle.install_entry(root, desktop=False, startup=False)["entry_installed"]
    assert connection.resolve_center(root, reference) == endpoint
    assert (root / "connection-process.json").read_bytes() == retained
    assert fake_processes[2] == signals and len(fake_processes[3]) == 1


def test_spec_without_legacy_needs_no_retirement_or_channel_start(local_metadata, monkeypatch):
    root, spec, save = local_metadata
    spec["legacy"] = None; save()
    monkeypatch.setattr(connection, "_listeners", lambda *a: pytest.fail("no legacy process inspection"))
    monkeypatch.setattr(connection.subprocess, "Popen", lambda *a, **kw: pytest.fail("no channel start"))
    assert connection.prepare_handoff(root) == {"handoff": "not-required"}
    assert not (root / "legacy-console-handoff.json").exists()


def test_uninstall_shortcut_check_stays_hidden_and_owner_bound(tmp_path, windows_entry, monkeypatch):
    root = tmp_path / "member"; root.mkdir()
    marker = root / "active-version.json"
    marker.write_text(json.dumps({"schema_version": 1, "pythonw_path": str(windows_entry[0])}))
    monkeypatch.setattr(lifecycle, "stop", lambda root: None)
    monkeypatch.setattr("research_compute_network.member_client_compute.ContributionManager",
        lambda root: SimpleNamespace(uninstall=lambda: None))
    assert lifecycle.uninstall(root)["identity_and_results_preserved"]
    command, kwargs = windows_entry[2][0]
    assert "TargetPath -ieq" in command[-1] and str(windows_entry[0]) in command[-1]
    assert kwargs == {"capture_output": True, "timeout": 15, "check": True, "creationflags": 0x08000000}
