"""Independent distribution, build and API version checks; no live state."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace
import tomllib
import zipfile

import pytest

from research_compute_network import deployment, release_identity, runtime_policy


VERSION = "9.8.7+versiontest"


def installed_package(tmp_path, *, stale_runtime=False, build_version=VERSION, full=False):
    site = tmp_path / "site-packages"
    package = site / "research_compute_network"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    source = Path(release_identity.__file__).parent
    if full:
        shutil.copytree(source, package, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.zip", release_identity.NAME))
    for name in ("release_identity.py", "runtime_policy.py"):
        text = (source / name).read_text(encoding="utf-8")
        if stale_runtime and name == "runtime_policy.py":
            text = text.replace("PACKAGE_VERSION = resolve_package_version()",
                                'PACKAGE_VERSION = "0.0.0+stale"')
        (package / name).write_text(text, encoding="utf-8")
    metadata = site / f"research_compute_network-{VERSION}.dist-info"
    metadata.mkdir()
    (metadata / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: research-compute-network\nVersion: {VERSION}\n",
        encoding="utf-8")
    release_identity.stamp(package, package_version=build_version)
    return site, package


def wheel_from_install(site, tmp_path):
    wheel = tmp_path / f"research_compute_network-{VERSION}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        for path in site.rglob("*"):
            if path.is_file():
                archive.write(path, path.relative_to(site).as_posix())
    return wheel


def test_checkout_version_ignores_unrelated_installed_distribution(tmp_path, monkeypatch):
    package = tmp_path / "src" / "research_compute_network"
    package.mkdir(parents=True)
    (tmp_path / "pyproject.toml").write_text(
        f'[project]\nname = "research-compute-network"\nversion = "{VERSION}"\n',
        encoding="utf-8")

    def unrelated_metadata(_name):
        raise AssertionError("source checkout must use its own project version")

    monkeypatch.setattr(release_identity.distribution_metadata, "distribution", unrelated_metadata)
    assert release_identity.resolve_package_version(package) == VERSION


def test_installed_version_requires_metadata_from_same_package_origin(tmp_path, monkeypatch):
    package = tmp_path / "site-packages" / "research_compute_network"
    metadata = SimpleNamespace(version=VERSION, locate_file=lambda name: package)
    monkeypatch.setattr(release_identity.distribution_metadata, "distribution", lambda name: metadata)
    assert release_identity.resolve_package_version(package) == VERSION
    metadata.locate_file = lambda name: tmp_path / "other-install" / name
    with pytest.raises(ValueError, match="another package origin"):
        release_identity.resolve_package_version(package)


def test_api_and_runtime_match_independent_source_project_version(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from research_compute_network.api import create_app

    project = Path(__file__).resolve().parents[1]
    expected = tomllib.loads((project / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    monkeypatch.setenv("RCN_HOME", str(tmp_path / "state"))
    app = create_app(database_url=f"sqlite:///{(tmp_path / 'api.db').as_posix()}", allow_local_trusted=True)
    with TestClient(app) as client:
        response = client.get("/v1/release/identity")
    assert response.status_code == 200, response.text
    assert response.json()["package_version"] == expected
    assert runtime_policy.PACKAGE_VERSION == expected
    assert app.version == expected


def test_wheel_and_installed_versions_use_actual_artifact_code(tmp_path):
    site, package = installed_package(tmp_path)
    wheel = wheel_from_install(site, tmp_path)
    evidence = release_identity.verify_wheel_version(wheel, expected_version=VERSION)
    assert evidence["version_verified"]
    assert {evidence[key] for key in ("runtime_package_version", "control_plane_package_version",
                                    "distribution_package_version", "build_package_version")} == {VERSION}
    assert str(wheel) in evidence["runtime_policy_origin"]
    installed = release_identity.verify_installed(package)
    assert installed["verified"] and installed["version_verified"]
    assert Path(installed["runtime_policy_origin"]).parent == package


def test_installed_api_build_runtime_and_metadata_versions_agree(tmp_path):
    # Load the real API from an installed layout with an independent metadata
    # version. A stale checkout constant cannot accidentally satisfy this test.
    site, package = installed_package(tmp_path, full=True)
    script = """import json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import research_compute_network as package
from importlib.metadata import version
from fastapi.testclient import TestClient
from research_compute_network.api import create_app
from research_compute_network.runtime_policy import PACKAGE_VERSION
from research_compute_network.release_identity import read_identity, verify_installed
app = create_app(database_url='sqlite:///' + (Path(sys.argv[2])/'api.db').as_posix(), allow_local_trusted=True)
with TestClient(app) as client:
    response = client.get('/v1/release/identity')
    response.raise_for_status()
    api = response.json()
    execution = client.get('/v1/execution-runtime').json()
print(json.dumps({'api': api['package_version'], 'api_build': api['build']['package_version'],
    'execution_api': execution['package_version'], 'openapi': app.version, 'runtime': PACKAGE_VERSION,
    'build': read_identity()['package_version'], 'distribution': version('research-compute-network'),
    'module_origin': package.__file__, 'installed_verified': verify_installed()['verified']}))
"""
    import os
    environment = {key: value for key, value in os.environ.items()
                   if key not in {"PYTHONPATH", "RCN_DATABASE_URL", "DATABASE_URL"}}
    environment["RCN_HOME"] = str(tmp_path / "state")
    result = subprocess.run([sys.executable, "-I", "-B", "-c", script, str(site), str(tmp_path)],
                            capture_output=True, text=True, timeout=60, env=environment,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    assert result.returncode == 0, result.stderr
    evidence = json.loads(result.stdout)
    assert Path(evidence.pop("module_origin")).parent == package
    assert evidence.pop("installed_verified")
    assert set(evidence.values()) == {VERSION}


@pytest.mark.parametrize("stale_runtime,build_version,error", [
    (True, VERSION, "runtime/distribution version mismatch"),
    (False, "0.0.0+stale", "build identity version mismatch"),
])
def test_wheel_and_install_reject_independent_version_drift(tmp_path, stale_runtime, build_version, error):
    site, package = installed_package(tmp_path, stale_runtime=stale_runtime, build_version=build_version)
    wheel = wheel_from_install(site, tmp_path)
    with pytest.raises(ValueError, match=error):
        release_identity.verify_wheel_version(wheel)
    installed = release_identity.verify_installed(package)
    assert not installed["verified"] and not installed["version_verified"]
    assert not installed["mismatched_files"]  # The receipt itself is hash-consistent.
    assert "version mismatch" in installed["version_error"]


def test_wheel_rejects_different_project_version(tmp_path):
    site, _package = installed_package(tmp_path)
    with pytest.raises(ValueError, match="wheel/project version mismatch"):
        release_identity.verify_wheel_version(wheel_from_install(site, tmp_path), expected_version="0.0.0")


def test_integrity_failure_does_not_execute_changed_runtime(tmp_path, monkeypatch):
    _site, package = installed_package(tmp_path)
    (package / "runtime_policy.py").write_text("raise RuntimeError('must not execute')", encoding="utf-8")
    monkeypatch.setattr(release_identity, "_runtime_version_probe", lambda *args:
                        pytest.fail("must not execute a package with mismatched hashes"))
    evidence = release_identity.verify_installed(package)
    assert not evidence["verified"] and not evidence["version_verified"]
    assert "runtime_policy.py" in evidence["mismatched_files"]


@pytest.mark.parametrize("drift", ["distribution", "build", "metadata_origin"])
def test_deployment_rejects_drift_even_when_runtime_matches_release_tool(tmp_path, monkeypatch, drift):
    root = tmp_path / "runtime"
    package = root / "Lib" / "site-packages" / "research_compute_network"
    evidence = {
        "module_path": str(package / "__init__.py"),
        "package_version": deployment.PACKAGE_VERSION,
        "distribution_package_version": deployment.PACKAGE_VERSION,
        "build_package_version": deployment.PACKAGE_VERSION,
        "distribution_package_root": str(package),
        "project_worker_fixture_path": str(package / "acceptance_fixtures" / "project_worker_smoke.py"),
        "project_worker_fixture_available": True,
    }
    if drift == "metadata_origin":
        evidence["distribution_package_root"] = str(tmp_path / "user-site" / package.name)
    else:
        evidence[f"{drift}_package_version"] = "0.0.0+stale"
    monkeypatch.setattr(deployment.subprocess, "run", lambda *args, **kwargs:
                        SimpleNamespace(returncode=0, stdout=json.dumps(evidence)))
    with pytest.raises(ValueError, match="another package origin|versions do not match"):
        deployment._validate_candidate_package_origin(root / "python.exe", root)
