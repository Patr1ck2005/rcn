"""Inert public installer fixtures; no release build or scientific assets."""
import hashlib
import json
from pathlib import Path
import subprocess
from zipfile import ZipFile

from research_compute_network import member_agent_launcher, member_client_installer as installer


def test_public_client_manifest_pins_launcher_without_scientific_runtime(tmp_path, monkeypatch):
    selected = tmp_path / "research_compute_network-0.15.0a5-py3-none-any.whl"
    def wheel(path, name):
        with ZipFile(path, "w") as bundle:
            bundle.writestr(name.replace("-", "_") + "-1.dist-info/METADATA",
                f"Metadata-Version: 2.1\nName: {name}\nVersion: 0.15.0a5\n")
    wheel(selected, "research-compute-network")
    house = tmp_path / "inert-wheelhouse"
    house.mkdir()
    for name in ("pip", "setuptools", "wheel", "greenlet"):
        wheel(house / (name + "-1-py3-none-any.whl"), name)
    (house / "get-pip.py").write_text("# Inert bootstrap fixture\n")
    embedded = tmp_path / "inert-python.zip"
    with ZipFile(embedded, "w") as bundle:
        for name in ("python.exe", "pythonw.exe", "python311._pth"):
            bundle.writestr(name, b"inert-runtime-input")
    launcher_bytes = b"MZ-inert-stable-launcher-fixture"
    def launcher(runtime):
        path = runtime / "bin/RCN-Agent.exe"
        path.parent.mkdir()
        path.write_bytes(launcher_bytes)
        return path
    monkeypatch.setattr(member_agent_launcher, "build_launcher", launcher)
    def run(command, **options):
        if command[0] == "inert-makensis":
            (Path(options["cwd"]) / "__setup__.exe").write_bytes(b"MZ-inert-setup-fixture")
            return subprocess.CompletedProcess(command, 0)
        probe = {"no_user_site": True, "module_paths": {
            name: f"Lib/site-packages/{name}/__init__.py" for name in ("fastapi", "sqlalchemy", "greenlet")}}
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(probe), stderr="")
    monkeypatch.setattr(installer.subprocess, "run", run)
    output = tmp_path / "inert-setup.exe"
    result = installer.build_member_client_installer(wheel_path=selected, wheelhouse_dir=house,
        embeddable_zip=embedded, output_exe=output,
        expected_wheel_sha256=hashlib.sha256(selected.read_bytes()).hexdigest(), makensis="inert-makensis")
    assert result["production_ready"] is False
    with ZipFile(output.with_suffix(".runtime.zip")) as bundle:
        assert bundle.read("runtime/bin/RCN-Agent.exe") == launcher_bytes
        manifest = json.loads(bundle.read("member-software-release.json"))
        assert manifest["runtime_files"]["bin/RCN-Agent.exe"] == hashlib.sha256(launcher_bytes).hexdigest()
        assert bundle.read("runtime/python/python311._pth").decode().splitlines() == [
            "python311.zip", ".", "Lib/site-packages"]
        assert not any("worker/agent" in name or name.endswith(".mph") for name in bundle.namelist())
