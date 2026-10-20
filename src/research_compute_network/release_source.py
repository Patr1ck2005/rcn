"""Verifiable clean Git exports, including builds outside any Git checkout."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess

RECEIPT = '.rcn-source-export.json'


def _git(root, *args):
    env = {key: value for key, value in os.environ.items()
           if key not in {'GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE'}}
    return subprocess.check_output(['git', '-C', str(root), *args], env=env, stderr=subprocess.PIPE)


def git_source_metadata(project_root):
    """Never attribute a nested staging directory to its ancestor repository."""
    root = Path(project_root).resolve()
    try:
        top = Path(_git(root, 'rev-parse', '--show-toplevel').decode().strip()).resolve()
        if top != root:
            return {'source_commit': None, 'source_dirty': None}
        head = _git(root, 'rev-parse', 'HEAD').decode().strip()
        if not re.fullmatch('[0-9a-f]{40}', head):
            return {'source_commit': None, 'source_dirty': None}
        dirty = bool(_git(root, 'status', '--porcelain=v1', '--untracked-files=all').strip())
        return {'source_commit': head, 'source_dirty': dirty}
    except (OSError, subprocess.CalledProcessError):
        return {'source_commit': None, 'source_dirty': None}


def verify_source_export(project_root):
    root = Path(project_root).resolve()
    receipt = root / RECEIPT
    if not receipt.is_file() or receipt.is_symlink():
        raise ValueError('verified source export receipt is required')
    value = json.loads(receipt.read_text(encoding='utf-8'))
    if (value.get('schema') != 'rcn-clean-source-export-v1'
        or not re.fullmatch('[0-9a-f]{40}', value.get('source_commit', ''))
        or not re.fullmatch('[0-9a-f]{40,64}', value.get('source_tree', ''))
        or not isinstance(value.get('files'), dict) or not value['files']):
        raise ValueError('invalid source export identity')
    for name, digest in value['files'].items():
        relative = PurePosixPath(name)
        if (relative.is_absolute() or '..' in relative.parts or '\\' in name or ':' in name
            or not re.fullmatch('[0-9a-f]{64}', digest)):
            raise ValueError('invalid source export path or digest')
        path = root / relative
        if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('source export changed: ' + name)
    # Generated web_dist is expected. Additional Python/ZIP inputs are not.
    package = root / 'src/research_compute_network'
    declared = {name for name in value['files'] if name.startswith('src/research_compute_network/')}
    for path in package.rglob('*'):
        if path.is_symlink():
            raise ValueError('source export contains linked package content')
        if path.is_file():
            relative = path.relative_to(root)
            if ('web_dist' not in relative.parts and '__pycache__' not in relative.parts
                and path.name != 'build_identity.json' and path.suffix != '.pyc'
                and relative.as_posix() not in declared):
                raise ValueError('untracked package input in source export')
    web = root / 'web'
    if web.exists():
        # Vite reads more than package.json: an untracked .env, config or
        # imported module can change the generated resources. Only the locked
        # dependency installation is an expected additional Web input tree.
        for current, directories, names in os.walk(web):
            if Path(current) == web:
                directories[:] = [name for name in directories if name != 'node_modules']
            for name in [*directories, *names]:
                path = Path(current) / name
                if path.is_symlink():
                    raise ValueError('source export contains linked Web input')
            for name in names:
                relative = (Path(current) / name).relative_to(root).as_posix()
                if relative not in value['files']:
                    raise ValueError('untracked Web input in source export')
    return {'source_commit': value['source_commit'], 'source_dirty': False,
            'source_tree': value['source_tree']}


def export_release_source(project_root, destination, *, commit=None):
    root, destination = Path(project_root).resolve(), Path(destination).absolute()
    metadata = git_source_metadata(root)
    if metadata['source_dirty'] is not False or metadata['source_commit'] is None:
        raise ValueError('release export requires a clean exact repository root')
    commit = commit or metadata['source_commit']
    if commit != metadata['source_commit']:
        raise ValueError('release export must identify the checked clean HEAD')
    if destination.exists():
        raise FileExistsError('release export destination already exists')
    ancestor = destination.parent
    while not ancestor.exists() and ancestor != ancestor.parent:
        ancestor = ancestor.parent
    try:
        _git(ancestor, 'rev-parse', '--show-toplevel')
    except (OSError, subprocess.CalledProcessError):
        pass
    else:
        raise ValueError('release export must be outside all Git workspaces')
    tree = _git(root, 'rev-parse', commit + '^{tree}').decode().strip()
    tree_files = {}
    for entry in _git(root, 'ls-tree', '-r', '-z', '--full-tree', commit).split(b'\0'):
        if not entry:
            continue
        metadata, name = entry.split(b'\t', 1)
        mode, kind, blob = metadata.decode('ascii').split()
        if mode not in {'100644', '100755'} or kind != 'blob':
            raise ValueError('release export refuses nonregular Git tree entries')
        tree_files[name.decode('utf-8')] = blob
    destination.mkdir(parents=True)
    files = {}
    # git archive also applies core.autocrlf/export-subst/export-ignore. Read
    # the committed blobs directly so neither attributes nor the caller's
    # global Git configuration can silently change the release inputs.
    environment = {key: value for key, value in os.environ.items()
                   if key not in {'GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE'}}
    batch = subprocess.Popen(['git', '-C', str(root), 'cat-file', '--batch'],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
    try:
        for name, expected_blob in tree_files.items():
            relative = PurePosixPath(name)
            if relative.is_absolute() or '..' in relative.parts or '\\' in name or ':' in name:
                raise ValueError('unsafe Git export path')
            batch.stdin.write(expected_blob.encode('ascii') + b'\n')
            batch.stdin.flush()
            header = batch.stdout.readline().decode('ascii').strip().split()
            if len(header) != 3 or header[:2] != [expected_blob, 'blob']:
                raise ValueError('committed Git blob unavailable')
            size = int(header[2])
            raw = batch.stdout.read(size)
            if len(raw) != size or batch.stdout.read(1) != b'\n':
                raise ValueError('committed Git blob truncated')
            blob = hashlib.sha1(b'blob ' + str(size).encode() + b'\0' + raw).hexdigest()
            if blob != expected_blob:
                raise ValueError('export content differs from the committed blob')
            path = destination / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            files[name] = hashlib.sha256(raw).hexdigest()
        batch.stdin.close()
        batch.wait(timeout=30)
        if batch.returncode:
            raise ValueError('Git source export process failed')
    finally:
        if batch.poll() is None:
            batch.kill()
            batch.wait(timeout=5)
        batch.stdout.close()
        batch.stderr.close()
    if set(files) != set(tree_files):
        raise ValueError('export omitted committed source inputs')
    (destination / RECEIPT).write_text(json.dumps({'schema': 'rcn-clean-source-export-v1',
        'source_commit': commit, 'source_tree': tree, 'files': files}, sort_keys=True, indent=2) + '\n', encoding='utf-8')
    return verify_source_export(destination)
