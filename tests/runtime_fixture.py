"""Synthetic operator catalogue for isolated public-platform tests."""
import hashlib
import json
import zipfile

TEST_RUNTIME_VERSION = "1" * 24

def configure_external_runtime(tmp_path, monkeypatch):
    # These are synthetic verifier inputs, never executed or installed.
    sources = {name: ("# synthetic " + name + "\n").encode() for name in (
        "supervisor.py", "remote_metrics.py", "windows_job.py", "worker_storage.py",
        "member_session_gate.py", "operator_worker.py")}
    version = TEST_RUNTIME_VERSION
    manifest = {"schema_version": 1, "version": version,
        "files": {"__runtime_layout_version__": "2", **{
            "remote-agent/" + name: hashlib.sha256(raw).hexdigest()
            for name, raw in sources.items()}}}
    archive = tmp_path / "approved-runtime.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("runtime-manifest.json", json.dumps(manifest))
        for name, raw in sources.items():
            output.writestr("remote-agent/" + name, raw)
    descriptor = {"format": "rcn-public-runtime-approval-v1", "runtime_version": version,
        "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "supervisor_sha256": hashlib.sha256(sources["supervisor.py"]).hexdigest(),
        "archive_path": str(archive), "actor_id": "operator-example",
        "reason": "synthetic validation only", "owner_session_required": True}
    path = tmp_path / "approval.json"
    path.write_text(json.dumps(descriptor), encoding="utf-8")
    monkeypatch.setenv("RCN_RUNTIME_DESCRIPTOR", str(path))
    return path, descriptor, archive

