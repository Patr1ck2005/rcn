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
    assert metadata["project"]["version"] == "0.15.0a1"
    assert metadata["project"]["license"]["text"] == "MIT"
    assert "MIT License" in (ROOT / "LICENSE").read_text(encoding="utf-8")
