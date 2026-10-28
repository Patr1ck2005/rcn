"""One known validator literal is allowed; credential material is still denied."""
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("public_tree_checker", ROOT / "scripts/check_public_tree.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
BUNDLE = "src/research_compute_network/member_connection_bundle.py"
HEADER = b" ".join(checker._VALIDATION_HEADER_WORDS)
VALIDATOR = checker._VALIDATION_PREFIX + HEADER + checker._VALIDATION_SUFFIX


def test_known_validator_and_full_source_are_not_credentials():
    assert not checker.contains_secret(BUNDLE, VALIDATOR)
    assert not checker.contains_secret(BUNDLE, VALIDATOR.replace(b"\n", b"\r\n"))
    assert not checker.contains_secret(BUNDLE, (ROOT / BUNDLE).read_bytes())


@pytest.mark.parametrize("name", ["src/other.py", "tests/member_connection_bundle.py",
                                 "src/research_compute_network/member_connection_bundle_copy.py"])
def test_other_paths_keep_the_original_header_rejection(name):
    assert checker.contains_secret(name, VALIDATOR)
    assert checker.contains_secret(name, HEADER)


@pytest.mark.parametrize("data", [HEADER, VALIDATOR + VALIDATOR,
    VALIDATOR.replace(b"16384", b"8192"), VALIDATOR.replace(b"key.startswith", b"value.startswith")])
def test_only_one_exact_known_block_gets_the_exception(data):
    assert checker.contains_secret(BUNDLE, data)


@pytest.mark.parametrize("kind", [b"RSA", b"EC"])
def test_other_private_key_kinds_do_not_qualify_for_the_exception(kind):
    assert checker.contains_secret(BUNDLE, VALIDATOR.replace(b"OPENSSH ", kind + b" "))


@pytest.fixture
def generated_key(tmp_path):
    executable = shutil.which("ssh-keygen")
    if executable is None:
        pytest.skip("ssh-keygen is needed only for the real disposable key regression")
    key = tmp_path / "disposable-key"
    subprocess.run([executable, "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
        capture_output=True, check=True, timeout=15,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return key.read_bytes()


@pytest.mark.parametrize("name", [BUNDLE, "src/other.py"])
def test_real_disposable_private_key_blocks_and_fields_still_fail(name, generated_key):
    raw_block = checker.contains_secret(name, generated_key)
    json_field = checker.contains_secret(name, json.dumps({"private_key": generated_key.decode()}).encode())
    assert raw_block and json_field


def test_valid_validator_cannot_hide_an_additional_key_or_field(generated_key):
    block = checker.contains_secret(BUNDLE, VALIDATOR + generated_key)
    field = checker.contains_secret(BUNDLE,
        VALIDATOR + json.dumps({"private_key": generated_key.decode()}).encode())
    assert block and field


def test_original_token_rule_is_applied_after_the_exception():
    github_token = b"github_pat_" + b"x" * 40
    assert checker.contains_secret(BUNDLE, VALIDATOR + github_token)
    assert checker.contains_secret("src/other.py", github_token)


def test_untracked_candidates_are_checked_without_staging(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(checker, "ROOT", tmp_path)
    (tmp_path / "tracked.py").write_text("value = 1\n")
    (tmp_path / "candidate.py").write_bytes(HEADER)
    calls = []
    def inventory(command, **kwargs):
        calls.append(command)
        assert kwargs["cwd"] == tmp_path
        if "--others" in command:
            return b"tracked.py\0candidate.py\0"
        return b"tracked.py\0"
    monkeypatch.setattr(checker.subprocess, "check_output", inventory)
    checker.main([])
    with pytest.raises(SystemExit) as rejected:
        checker.main(["--include-untracked"])
    assert rejected.value.code == 1
    assert "candidate.py: credential-shaped content" in capsys.readouterr().out
    assert "--cached" in calls[-1] and "--others" in calls[-1] and "--exclude-standard" in calls[-1]
    assert all("add" not in command for command in calls)
