import json
from pathlib import Path
import subprocess

import pytest

from research_compute_network.release_identity import source_metadata
from research_compute_network.release_source import export_release_source, verify_source_export


@pytest.fixture
def repository(tmp_path):
    root = tmp_path / 'repo'
    root.mkdir()
    def git(*args):
        return subprocess.check_output(['git', '-C', str(root), *args], stderr=subprocess.PIPE).decode().strip()
    git('init', '-q')
    git('config', 'user.name', 'Isolated release fixture')
    git('config', 'user.email', 'fixture@example.invalid')
    package = root / 'src/research_compute_network'
    package.mkdir(parents=True)
    (package / '__init__.py').write_bytes(b'"""Original fixture."""\n')
    (package / 'runtime.zip').write_bytes(b'fixed-binary-fixture\x00')
    (root / 'pyproject.toml').write_bytes(b'[project]\nname="fixture"\nversion="1.0"\n')
    git('add', '.')
    git('commit', '-qm', 'Fixture baseline')
    return root, git


def test_clean_export_binds_exact_commit_and_all_input_hashes(repository, tmp_path):
    root, git = repository
    target = tmp_path / 'export'
    exported = export_release_source(root, target)
    assert exported == {'source_commit': git('rev-parse', 'HEAD'), 'source_dirty': False,
                        'source_tree': git('rev-parse', 'HEAD^{tree}')}
    assert source_metadata(target) == {key: exported[key] for key in ('source_commit', 'source_dirty')}
    (target / 'src/research_compute_network/web_dist').mkdir()
    (target / 'src/research_compute_network/web_dist/index.html').write_text('generated fixture')
    assert verify_source_export(target) == exported


@pytest.mark.parametrize('change', ['modified', 'missing_runtime', 'extra_module'])
def test_tampered_or_incomplete_export_is_rejected(repository, tmp_path, change):
    root, _ = repository
    target = tmp_path / 'export'
    export_release_source(root, target)
    package = target / 'src/research_compute_network'
    if change == 'modified':
        (package / '__init__.py').write_bytes(b'changed')
    elif change == 'missing_runtime':
        (package / 'runtime.zip').unlink()
    else:
        (package / 'unexpected.py').write_bytes(b'injected')
    with pytest.raises(ValueError):
        verify_source_export(target)


def test_nested_candidate_does_not_inherit_ancestor_commit(repository):
    root, _ = repository
    target = root / '.scratch/candidate'
    target.mkdir(parents=True)
    assert source_metadata(target) == {'source_commit': None, 'source_dirty': None}


def test_dirty_tree_and_nested_export_are_refused(repository, tmp_path):
    root, _ = repository
    with pytest.raises(ValueError, match='outside all Git'):
        export_release_source(root, root / 'nonexistent/deep/export')
    (root / 'untracked.py').write_text('not an approved build input')
    with pytest.raises(ValueError, match='clean exact'):
        export_release_source(root, tmp_path / 'dirty-export')


def test_official_build_refuses_unattributed_source_before_building_web(tmp_path, monkeypatch):
    from research_compute_network import release
    monkeypatch.setattr(release, 'stage_web_assets', lambda path: pytest.fail('Web build started without source identity'))
    with pytest.raises(ValueError, match='verified clean source'):
        release.build_wheel(tmp_path, tmp_path / 'wheels', require_clean_source=True)


def test_export_ignore_cannot_silently_drop_tracked_runtime(repository, tmp_path):
    root, git = repository
    (root / '.gitattributes').write_text('src/research_compute_network/runtime.zip export-ignore\n')
    git('add', '.gitattributes')
    git('commit', '-qm', 'Fixture archive omission')
    destination = tmp_path / 'complete-export'
    export_release_source(root, destination)
    assert (destination / 'src/research_compute_network/runtime.zip').read_bytes() == b'fixed-binary-fixture\x00'


def test_export_refuses_untracked_web_build_inputs_but_allows_locked_dependency_tree(repository, tmp_path):
    root, git = repository
    (root / 'web').mkdir()
    (root / 'web/package.json').write_text('{"name":"fixture"}')
    git('add', 'web')
    git('commit', '-qm', 'Fixture Web source')
    destination = tmp_path / 'web-export'
    export_release_source(root, destination)
    (destination / 'web/node_modules/fixture').mkdir(parents=True)
    (destination / 'web/node_modules/fixture/index.js').write_text('locked dependency')
    verify_source_export(destination)
    (destination / 'web/.env').write_text('VITE_UNCOMMITTED_INPUT=unexpected')
    with pytest.raises(ValueError, match='untracked Web input'):
        verify_source_export(destination)


def _pin_external_asset(root, git, name='src/research_compute_network/acceptance_fixtures/runtime-fixture.zip'):
    import hashlib
    raw = b'immutable external fixture\x00'
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    (root / '.gitignore').write_text('src/research_compute_network/acceptance_fixtures/*.zip\n')
    (root / 'release-assets.json').write_text(json.dumps({'schema':'rcn-release-assets-v1',
        'files':{name:hashlib.sha256(raw).hexdigest()}}))
    git('add', '.gitignore', 'release-assets.json')
    git('commit', '-qm', 'Pin immutable external input')
    return name, path


def test_external_archives_are_verified_from_committed_manifest(repository, tmp_path):
    root, git = repository
    name, path = _pin_external_asset(root, git)
    target = tmp_path / 'export-assets'
    exported = export_release_source(root, target)
    assert (target / name).read_bytes() == path.read_bytes()
    assert exported['source_dirty'] is False
    (target / name).write_bytes(b'changed')
    with pytest.raises(ValueError, match='release asset missing or changed'):
        verify_source_export(target)


def test_external_archive_missing_or_wrong_bytes_cannot_build(repository, tmp_path):
    root, git = repository
    _, path = _pin_external_asset(root, git)
    path.write_bytes(b'not approved')
    with pytest.raises(ValueError, match='hash mismatch'):
        export_release_source(root, tmp_path / 'bad-asset')


def test_external_manifest_cannot_supply_python_or_traversal(repository, tmp_path):
    root, git = repository
    _pin_external_asset(root, git)
    for i, name in enumerate(['src/research_compute_network/injected.py', '../outside.zip']):
        (root / 'release-assets.json').write_text(json.dumps({'schema':'rcn-release-assets-v1','files':{name:'0'*64}}))
        git('add', 'release-assets.json')
        git('commit', '-qm', 'Invalid fixture manifest')
        with pytest.raises(ValueError, match='invalid release asset path'):
            export_release_source(root, tmp_path / f'bad-path-{i}')
