from pathlib import Path
import ast
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def test_public_package_does_not_carry_science_archives():
    package = ROOT / "src/research_compute_network"
    assert not list(package.rglob("*.mph"))
    assert not list((package / "acceptance_fixtures").glob("*.zip"))
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert "acceptance_fixtures/*.zip" not in metadata["tool"]["setuptools"]["package-data"]["research_compute_network"]


def test_public_installer_requires_fresh_input_not_private_snapshot():
    import pytest
    from research_compute_network.member_client_installer import build_member_client_installer_from_snapshot
    with pytest.raises(ValueError, match="requires_fresh_build"):
        build_member_client_installer_from_snapshot(snapshot_zip="private.zip")


def test_installer_has_no_scientific_equivalence_dependency():
    source = (ROOT / "src/research_compute_network/member_client_installer.py").read_text(encoding="utf-8")
    ast.parse(source)
    assert "approved_scientific_equivalence" not in source
    assert '"mph", "jpype1"' not in source


def test_public_metadata():
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert metadata["project"]["version"] == "0.15.0a6"
    assert metadata["project"]["license"]["text"] == "MIT"
    assert "MIT License" in (ROOT / "LICENSE").read_text(encoding="utf-8")


def test_runtime_sanitization_preserves_code_and_interpreter(tmp_path):
    import csv
    from research_compute_network.member_client_installer import _sanitize_public_runtime
    python = tmp_path / "python"
    package = python / "Lib/site-packages/example"
    package.mkdir(parents=True)
    (package / "module.py").write_text("value = 1\n")
    (package / "module.pyc").write_bytes(b"build-path-bytecode")
    metadata = package.parent / "example-1.dist-info"
    metadata.mkdir()
    (metadata / "direct_url.json").write_text('{"url":"file:///private-build"}')
    (python / "Scripts").mkdir()
    (python / "Scripts/example.exe").write_bytes(b"temporary-interpreter-launcher")
    (python / "python.exe").write_bytes(b"real-interpreter")
    (metadata / "RECORD").write_text("example/module.py,,\nexample/module.pyc,,\nexample-1.dist-info/direct_url.json,,\n../../Scripts/example.exe,,\n")
    assert _sanitize_public_runtime(python) == 3
    assert (package / "module.py").is_file() and (python / "python.exe").is_file()
    assert not list(python.rglob("*.pyc")) and not list(python.rglob("direct_url.json"))
    assert not (python / "Scripts").exists()
    assert all(any(path.iterdir()) for path in python.rglob("*") if path.is_dir())
    with (metadata / "RECORD").open(newline="") as stream:
        assert list(csv.reader(stream)) == [["example/module.py", "", ""]]
