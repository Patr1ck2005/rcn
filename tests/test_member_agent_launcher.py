import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from research_compute_network import member_agent_launcher as launcher
from research_compute_network.member_release_catalog import current_member_release


def manifest(release):
    files = {p.relative_to(release / "runtime").as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in (release / "runtime").rglob("*") if p.is_file()}
    current = current_member_release()
    value = {"payload_id": "member-" + hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:24],
             "runtime_files": files, "member_runtime": {"runtime_version": current.runtime_version, "archive_sha256": current.archive_sha256}}
    (release / "member-software-release.json").write_text(json.dumps(value))


@pytest.mark.skipif(os.name != "nt", reason="native Windows launcher acceptance")
def test_stable_entry_follows_upgraded_version_and_rejects_changed_binary(tmp_path, monkeypatch):
    from research_compute_network import member_registration as storage
    root = tmp_path / "用户 客户端"
    storage._private_directory(root)
    compiler = Path(os.environ["WINDIR"]) / "Microsoft.NET/Framework64/v4.0.30319/csc.exe"
    if not compiler.is_file():
        pytest.skip("inbox build compiler not available")
    stable = root / "bin/RCN-Agent.exe"
    for version in ("one", "two"):
        release = tmp_path / ("release-" + version)
        python = release / "runtime/python/python.exe"
        python.parent.mkdir(parents=True)
        source = tmp_path / "probe.cs"
        source.write_text('using System;using System.Text;class Probe {static int Main(string[] a){Console.OutputEncoding=new UTF8Encoding(false);if(a[a.Length-1]=="hold")System.Threading.Thread.Sleep(5000);Console.WriteLine("' + version + '");Console.WriteLine(a[a.Length-1]);return 0;}}')
        subprocess.run([str(compiler), "/nologo", "/out:" + str(python), str(source)], check=True, capture_output=True,
                       creationflags=subprocess.CREATE_NO_WINDOW)
        launcher.build_launcher(release / "runtime")
        manifest(release)
        monkeypatch.setattr(sys, "executable", str(python))
        running = None
        if version == "two":
            running = subprocess.Popen([str(stable), "hold"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       creationflags=subprocess.CREATE_NO_WINDOW)
            previous_launcher = stable.read_bytes()
        active = launcher.install_launcher(root)
        if running:
            assert running.poll() is None  # Old long command survives upgrade.
            assert stable.read_bytes() == previous_launcher
        marker = root / "active-version.json"
        marker.write_text(json.dumps(active))
        result = subprocess.run([str(stable), "--state-root", str(root / "agents"), "中文 参数 & literal"], capture_output=True,
                                encoding="utf-8", creationflags=subprocess.CREATE_NO_WINDOW)
        assert result.returncode == 0, result.stderr
        assert result.stdout.splitlines() == [version, "中文 参数 & literal"]
        if version == "two":
            assert running.communicate(timeout=15)[0].splitlines() == [b"one", b"hold"]
            # The same stable path was exported before upgrading; no old runtime is consulted.
            (tmp_path / "release-one/runtime/python/python.exe").rename(tmp_path / "old-python-retired.exe")
            assert subprocess.run([str(stable), "status"], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW).returncode == 0
            python.write_bytes(python.read_bytes() + b"changed")
            failed = subprocess.run([str(stable), "secret-not-for-diagnostics"], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
            assert failed.returncode == 2 and b"secret-not-for-diagnostics" not in failed.stderr
