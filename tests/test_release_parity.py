"""Release parity must inspect payload bytes, including coherent stale builds."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import zipfile

import pytest


spec = importlib.util.spec_from_file_location("release_parity", Path(__file__).resolve().parents[1] / "scripts/release_parity.py")
parity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parity)

COMMON = ["src/research_compute_network/member_client.py",
          "src/research_compute_network/help_content/public/member-task-package.md",
          "web/src/MemberClient.jsx"]
MANIFEST = {"schema_version": 1, "common_files": COMMON,
            "intentional_differences": [{"paths": ["src/research_compute_network/__init__.py"], "reason": "release versions"}],
            "excluded_public": ["release-assets.json", "src/research_compute_network/*.zip",
                                "src/research_compute_network/**/*.zip"]}


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def archive(path, files):
    with zipfile.ZipFile(path, "w") as target:
        for name, data in files.items():
            target.writestr(name, data)


def bundle(root, side, *, wheel_changes=None, runtime_changes=None, extra_runtime=None):
    """Create independent, internally consistent wheel/Setup test artifacts."""
    for name in COMMON:
        write(root / name, ("current " + name + "\n").encode())
    web = root / "src/research_compute_network/web_dist"
    web_files = {"index.html": b"<script src='assets/app.js'></script>",
                 "assets/app.js": (side + " current UI").encode(), "assets/app.css": b".member { color: blue; }"}
    for name, data in web_files.items():
        write(web / name, data)
    files = {name.removeprefix("src/"): (root / name).read_bytes() for name in COMMON if name.startswith("src/")}
    files["research_compute_network/__init__.py"] = ("VERSION = '" + side + "'\n").encode()
    files.update({"research_compute_network/web_dist/" + name: data for name, data in web_files.items()})
    files.update(wheel_changes or {})
    for name in [name for name, data in files.items() if data is None]:
        del files[name]
    wheel = root / (side + ".whl")
    archive(wheel, files)
    runtime_files = {"python/Lib/site-packages/" + name: data for name, data in files.items()}
    runtime_files["python/Lib/site-packages/dependency.py"] = b"dependency contents\n"
    runtime_files.update(runtime_changes or {})
    digests = {name: parity.sha256(data) for name, data in runtime_files.items()}
    value = {"schema_version": 1, "kind": "rcn-public-member-client-v1", "runtime_files": digests,
             "package_version": side, "wheel_sha256": parity.file_sha256(wheel),
             "member_runtime": {"runtime_version": side, "archive_sha256": "0" * 64},
             "payload_id": "member-" + parity.sha256(json.dumps(digests, sort_keys=True, separators=(",", ":")).encode())[:24]}
    payload = {"member-software-release.json": json.dumps(value).encode(),
               **{"runtime/" + name: data for name, data in runtime_files.items()}, **(extra_runtime or {})}
    runtime = root / (side + ".runtime.zip")
    archive(runtime, payload)
    setup = root / (side + ".exe")
    setup.write_bytes(b"inert test setup")
    value.update(runtime_zip_sha256=parity.file_sha256(runtime), setup_sha256=parity.file_sha256(setup))
    setup_manifest = root / (side + ".manifest.json")
    setup_manifest.write_text(json.dumps(value), encoding="utf-8")
    return {"wheel": wheel, "runtime": runtime, "setup_manifest": setup_manifest, "setup": setup}


def artifacts(tmp_path, **changes):
    roots = {side: tmp_path / side for side in ("internal", "public")}
    inputs = {side: bundle(root, side, **changes.get(side, {})) for side, root in roots.items()}
    return roots, {side + "_" + key: value for side, values in inputs.items() for key, value in values.items()}


def check(roots, inputs):
    return parity.check_artifacts(roots["internal"], roots["public"], MANIFEST, **inputs)


def test_artifacts_match_with_separate_versions_and_ui(tmp_path):
    roots, inputs = artifacts(tmp_path)
    errors, hashes = check(roots, inputs)
    assert errors == []
    assert set(hashes) == {n.removeprefix("src/") for n in COMMON if n.startswith("src/")}


def test_coherent_stale_member_wheel_is_compared_to_source(tmp_path):
    roots, inputs = artifacts(tmp_path, public={"wheel_changes": {"research_compute_network/member_client.py": b"stale member\n"}})
    errors, _ = check(roots, inputs)
    assert any("public wheel/source payload differs" in error for error in errors)
    assert any("common wheel payload differs" in error for error in errors)


def test_identical_sources_do_not_hide_stale_help_in_both_builds(tmp_path):
    change = {"wheel_changes": {"research_compute_network/help_content/public/member-task-package.md": b"old help"}}
    roots, inputs = artifacts(tmp_path, internal=change, public=change)
    errors, _ = check(roots, inputs)
    assert sum("wheel/source payload differs" in error for error in errors) == 2


def test_coherent_stale_runtime_detected_even_with_updated_hash_manifest(tmp_path):
    roots, inputs = artifacts(tmp_path, public={"runtime_changes": {"python/Lib/site-packages/research_compute_network/member_client.py": b"old installed module"}})
    errors, _ = check(roots, inputs)
    assert any("public wheel/runtime payload differs" in error for error in errors)
    assert not any("Setup runtime ZIP checksum differs" in error for error in errors)


@pytest.mark.parametrize("name", ["research_compute_network/web_dist/index.html",
                                  "research_compute_network/web_dist/assets/app.js",
                                  "research_compute_network/web_dist/assets/app.css"])
def test_missing_packaged_web_artifact_fails(tmp_path, name):
    roots, inputs = artifacts(tmp_path, public={"wheel_changes": {name: None}})
    errors, _ = check(roots, inputs)
    assert "public wheel/built web inventory differs" in errors


def test_stale_built_ui_is_compared_to_actual_wheel(tmp_path):
    roots, inputs = artifacts(tmp_path, public={"wheel_changes": {"research_compute_network/web_dist/assets/app.js": b"old UI"}})
    errors, _ = check(roots, inputs)
    assert "public wheel/built web asset differs: assets/app.js" in errors


def test_public_scientific_zip_is_rejected_in_actual_payload(tmp_path):
    roots, inputs = artifacts(tmp_path, public={"wheel_changes": {"research_compute_network/acceptance_fixtures/science.zip": b"private archive"}})
    errors, _ = check(roots, inputs)
    assert "public artifact contains excluded file: research_compute_network/acceptance_fixtures/science.zip" in errors


def test_scientific_zip_outside_package_cannot_bypass_public_boundary(tmp_path):
    roots, inputs = artifacts(tmp_path, public={"runtime_changes": {"worker/scientific.zip": b"private archive"}})
    errors, _ = check(roots, inputs)
    assert "public runtime contains excluded scientific asset: runtime/worker/scientific.zip" in errors


def test_edition_specific_required_help_matches_own_build_without_copy(tmp_path, monkeypatch):
    help_name = COMMON[1]
    roots, inputs = artifacts(tmp_path, public={"wheel_changes": {help_name.removeprefix("src/"): b"public adapter links"}})
    write(roots["public"] / help_name, b"public adapter links")
    manifest = {**MANIFEST, "common_files": [n for n in COMMON if n != help_name], "required_files": [help_name]}
    monkeypatch.setattr(subprocess, "check_output", lambda *a, **kw: b"README.md\0")
    assert parity.check_sources(*roots.values(), manifest, copy_common=True) == ([], [])
    assert (roots["public"] / help_name).read_bytes() == b"public adapter links"
    assert parity.check_artifacts(*roots.values(), manifest, **inputs)[0] == []
    write(roots["public"] / help_name, b"new help needs rebuilding")
    errors, _ = parity.check_artifacts(*roots.values(), manifest, **inputs)
    assert "public wheel/source payload differs: " + help_name in errors


def test_missing_help_fails_wheel_and_runtime_checks(tmp_path):
    roots, inputs = artifacts(tmp_path, public={"wheel_changes": {"research_compute_network/help_content/public/member-task-package.md": None}})
    errors, _ = check(roots, inputs)
    assert any("public wheel missing: research_compute_network/help_content/" in error for error in errors)


def test_all_runtime_files_are_hashed_not_only_common_modules(tmp_path):
    roots, inputs = artifacts(tmp_path)
    runtime = inputs["public_runtime"]
    with zipfile.ZipFile(runtime) as source:
        contents = {name: source.read(name) for name in source.namelist()}
    contents["runtime/python/Lib/site-packages/dependency.py"] = b"changed dependency"
    archive(runtime, contents)
    errors, _ = check(roots, inputs)
    assert "public Setup runtime ZIP checksum differs" in errors
    assert any("runtime payload checksum differs: python/Lib/site-packages/dependency.py" in error for error in errors)


def test_extra_runtime_files_fail_inventory(tmp_path):
    roots, inputs = artifacts(tmp_path, public={"extra_runtime": {"runtime/python/unlisted.txt": b"unexpected"}})
    errors, _ = check(roots, inputs)
    assert "public runtime ZIP inventory differs from Setup manifest" in errors


def test_external_manifest_cannot_silently_replace_embedded_identity(tmp_path):
    roots, inputs = artifacts(tmp_path)
    path = inputs["public_setup_manifest"]
    value = json.loads(path.read_text())
    value["payload_id"] = "member-" + "0" * 24
    path.write_text(json.dumps(value))
    errors, _ = check(roots, inputs)
    assert "public embedded/Setup manifest differs: payload_id" in errors
    assert "public payload identity differs" in errors


def test_setup_exe_is_checked_when_supplied(tmp_path):
    roots, inputs = artifacts(tmp_path)
    inputs["public_setup"].write_bytes(b"changed setup")
    errors, _ = check(roots, inputs)
    assert "public Setup EXE checksum differs" in errors


@pytest.mark.parametrize("name", ["../private.py", "C:/private.py", "a\\b.py", "/private.py", "a/./b.py", "a//b.py"])
def test_unsafe_manifest_paths_fail(name, tmp_path):
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({**MANIFEST, "common_files": [name]}))
    with pytest.raises(ValueError, match="unsafe relative path"):
        parity.load_manifest(path)


def test_excluded_files_cannot_be_added_to_copy_allowlist(tmp_path):
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({**MANIFEST, "common_files": ["release-assets.json"]}))
    with pytest.raises(ValueError, match="excluded path cannot be common"):
        parity.load_manifest(path)


def test_duplicate_archive_members_fail(tmp_path):
    path = tmp_path / "duplicate.zip"
    with pytest.warns(UserWarning):
        with zipfile.ZipFile(path, "w") as target:
            target.writestr("same.py", b"a")
            target.writestr("same.py", b"b")
    with zipfile.ZipFile(path) as source, pytest.raises(ValueError, match="duplicate archive member"):
        parity.zip_inventory(source)


def test_source_check_is_read_only_and_copy_is_allowlisted(tmp_path, monkeypatch):
    roots, _ = artifacts(tmp_path)
    monkeypatch.setattr(subprocess, "check_output", lambda *a, **kw: b"README.md\0")
    member = roots["public"] / COMMON[0]
    member.write_bytes(b"old public member")
    private = roots["public"] / "service.py"
    private.write_bytes(b"keep independent public service")
    errors, copied = parity.check_sources(*roots.values(), MANIFEST)
    assert errors == ["common source differs: " + COMMON[0]] and copied == []
    assert member.read_bytes() == b"old public member"
    errors, copied = parity.check_sources(*roots.values(), MANIFEST, copy_common=True)
    assert not errors and copied == [COMMON[0]]
    assert member.read_bytes() == (roots["internal"] / COMMON[0]).read_bytes()
    assert private.read_bytes() == b"keep independent public service"


def test_copy_preflight_refuses_partial_writes(tmp_path, monkeypatch):
    roots, _ = artifacts(tmp_path)
    monkeypatch.setattr(subprocess, "check_output", lambda *a, **kw: b"README.md\0")
    public_member = roots["public"] / COMMON[0]
    public_member.write_bytes(b"unchanged until preflight passes")
    manifest = {**MANIFEST, "common_files": [*COMMON, "missing.py"]}
    errors, copied = parity.check_sources(*roots.values(), manifest, copy_common=True)
    assert errors == ["internal source missing: missing.py"] and not copied
    assert public_member.read_bytes() == b"unchanged until preflight passes"


def test_copy_rejects_hardlinked_target(tmp_path, monkeypatch):
    internal, public = tmp_path / "internal", tmp_path / "public"
    write(internal / "common.txt", b"new source")
    public.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"preserve unrelated file")
    os.link(outside, public / "common.txt")
    monkeypatch.setattr(subprocess, "check_output", lambda *a, **kw: b"common.txt\0")
    with pytest.raises(ValueError, match="linked source path"):
        parity.check_sources(internal, public, {**MANIFEST, "common_files": ["common.txt"]}, copy_common=True)
    assert outside.read_bytes() == b"preserve unrelated file"


def test_source_lf_crlf_is_normalized_but_artifact_hashes_are_raw(tmp_path, monkeypatch):
    roots, inputs = artifacts(tmp_path)
    monkeypatch.setattr(subprocess, "check_output", lambda *a, **kw: b"README.md\0")
    path = roots["public"] / COMMON[0]
    path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
    assert parity.check_sources(*roots.values(), MANIFEST) == ([], [])
    assert check(roots, inputs)[0] == []
    assert parity.sha256(b"a\n") != parity.sha256(b"a\r\n")


def test_public_git_boundary_blocks_copy_without_reading_excluded_content(tmp_path, monkeypatch):
    roots, _ = artifacts(tmp_path)
    monkeypatch.setattr(subprocess, "check_output", lambda *a, **kw: b"release-assets.json\0")
    errors, copied = parity.check_sources(*roots.values(), MANIFEST, copy_common=True)
    assert errors == ["public source contains excluded file: release-assets.json"] and not copied


def test_artifact_cli_cannot_report_source_success_for_partial_inputs(tmp_path):
    with pytest.raises(SystemExit) as error:
        parity.main(["--internal-root", str(tmp_path), "--public-root", str(tmp_path), "--internal-wheel", "only.whl"])
    assert error.value.code == 2
