"""Content-addressed build identity, distinct from version, deployment and worker.

The build receipt contains package-relative paths and hashes only. It is not a
signature, machine configuration, secret inventory or proof of live deployment.
"""
from __future__ import annotations
from functools import lru_cache
from importlib import metadata as distribution_metadata
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import zipfile
from email.parser import Parser
import tomllib

NAME='build_identity.json'
KIND='rcn-build-identity-v1'
CAPABILITIES={
    'publication_delivery_unknown':1,'bounded_machine_pipeline':1,
    'scheduling_policy':1,'small_batch_first':1,'exact_resource_window':1,
    'evidence_failure_advice':1,'member_distribution_preflight':1,
    'person_submission_policy':1,'compute_credits':1,'control_operation_replay':1,
    'canonical_job_contract':1,'durable_collection':1,'resumable_result_transfer':1,
    'personal_agent_credentials':1,'member_connection_bundle':1,'member_agent_stable_entry':1,
    'member_online_pairing':1,'member_https_ingress':1,'resumable_origin_upload':1,
}


def resolve_package_version(package_root: Path | None = None):
    """Use this checkout's project version or this installed distribution's metadata."""
    root = (Path(package_root) if package_root else Path(__file__).parent).resolve()
    project = root.parent.parent
    if root == project / 'src' / 'research_compute_network' and (project / 'pyproject.toml').is_file():
        value = tomllib.loads((project / 'pyproject.toml').read_text(encoding='utf-8'))['project']
        if value.get('name', '').replace('_', '-').lower() != 'research-compute-network':
            raise ValueError('unexpected source distribution identity')
        return str(value['version'])
    distribution = distribution_metadata.distribution('research-compute-network')
    installed = Path(str(distribution.locate_file('research_compute_network'))).resolve()
    if installed != root:
        raise ValueError('distribution metadata belongs to another package origin')
    return distribution.version


def _runtime_version_probe(package_root, import_root):
    # A fresh isolated process avoids comparing the build tool's already-loaded
    # constant with itself. Only the two stdlib-only identity modules are loaded;
    # package initialization, a coordinator DB and scientific executors are not.
    probe = """import importlib, importlib.metadata, json, sys, types
sys.path.insert(0, sys.argv[2])
package = types.ModuleType('research_compute_network')
package.__path__ = [sys.argv[1]]
sys.modules['research_compute_network'] = package
policy = importlib.import_module('research_compute_network.runtime_policy')
print(json.dumps({'runtime_package_version': policy.PACKAGE_VERSION,
    'control_plane_package_version': policy.ControlPlaneIdentity.current(policy.DEFAULT_RUNTIME_POLICY).package_version,
    'distribution_package_version': importlib.metadata.version('research-compute-network'),
    'runtime_policy_origin': policy.__file__}))
"""
    result = subprocess.run([sys.executable, '-I', '-B', '-c', probe, str(package_root), str(import_root)],
        capture_output=True, text=True, timeout=30,
        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    if result.returncode:
        raise ValueError('release runtime version probe failed')
    value = json.loads(result.stdout)
    expected = value['distribution_package_version']
    if any(value[key] != expected for key in ('runtime_package_version', 'control_plane_package_version')):
        raise ValueError('release runtime/distribution version mismatch')
    return value


def verify_wheel_version(wheel_path: Path, *, expected_version: str | None = None):
    """Fail release builds on wheel, runtime-policy or build-receipt version drift."""
    wheel = Path(wheel_path).resolve()
    with zipfile.ZipFile(wheel) as archive:
        metadata_names = [name for name in archive.namelist() if name.endswith('.dist-info/METADATA')]
        if len(metadata_names) != 1:
            raise ValueError('release wheel metadata is ambiguous')
        metadata = Parser().parsestr(archive.read(metadata_names[0]).decode('utf-8'))
        version = metadata['Version']
        if (metadata['Name'].replace('_', '-').lower() != 'research-compute-network'
                or expected_version is not None and version != expected_version):
            raise ValueError('release wheel/project version mismatch')
        declared = json.loads(archive.read('research_compute_network/' + NAME))['package_version']
        if declared != version:
            raise ValueError('release wheel/build identity version mismatch')
    value = _runtime_version_probe(str(wheel) + '/research_compute_network', wheel)
    if value['distribution_package_version'] != version:
        raise ValueError('release wheel distribution metadata shadowed')
    return {**value, 'build_package_version': declared, 'version_verified': True}


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()).hexdigest()


def source_metadata(project_root: Path):
    from .release_source import RECEIPT, git_source_metadata, verify_source_export
    root=Path(project_root).resolve()
    if (root/RECEIPT).exists():
        metadata=verify_source_export(root)
        return {key:metadata[key] for key in ('source_commit','source_dirty')}
    return git_source_metadata(root)


def package_hashes(package_root: Path):
    package_root=Path(package_root)
    if package_root.is_symlink():raise ValueError('build identity refuses linked package root')
    manifest={}
    for path in sorted(package_root.rglob('*')):
        relative=path.relative_to(package_root)
        if relative.as_posix()==NAME or '__pycache__' in relative.parts or path.suffix=='.pyc':continue
        if path.is_symlink():raise ValueError('build identity refuses linked package content')
        if path.is_file():manifest[relative.as_posix()]=hashlib.sha256(path.read_bytes()).hexdigest()
    if not manifest:raise ValueError('build identity has no package content')
    return manifest


def stamp(package_root: Path, *, package_version: str, metadata: dict | None=None):
    package_root=Path(package_root)
    manifest=package_hashes(package_root)
    info={'schema_version':1,'kind':KIND,'package_version':package_version,
          'source_commit':(metadata or {}).get('source_commit'),
          'source_dirty':(metadata or {}).get('source_dirty'),
          'files':manifest,'capabilities':CAPABILITIES,
          'content_sha256':digest(manifest),'signature_kind':'unsigned-content-integrity'}
    info['build_id']='rcn-'+info['content_sha256'][:24]
    path=package_root/NAME
    raw=json.dumps(info,sort_keys=True,indent=2)+'\n'
    if path.exists() and path.read_text(encoding='utf-8')!=raw:
        raise ValueError('refusing to overwrite a different build identity')
    if not path.exists():path.write_text(raw,encoding='utf-8')
    return info


def read_identity(package_root: Path | None=None):
    root=Path(package_root) if package_root else Path(__file__).resolve().parent
    path=root/NAME
    if not path.is_file():return {'available':False,'reason_code':'legacy_or_source_build_identity_absent'}
    try:
        if path.is_symlink() or path.stat().st_size>2*1024*1024:raise ValueError('identity bounds')
        value=json.loads(path.read_text(encoding='utf-8'))
        entries=value['files']
        if (value.get('schema_version')!=1 or value.get('kind')!=KIND or not isinstance(entries,dict)
                or not 1<=len(entries)<=10000 or digest(entries)!=value.get('content_sha256')
                or value.get('build_id')!='rcn-'+value['content_sha256'][:24]):raise ValueError('identity format')
        for name,sha in entries.items():
            p=PurePosixPath(name)
            if p.is_absolute() or '..' in p.parts or '\\' in name or ':' in name or not re.fullmatch(r'[0-9a-f]{64}',sha):
                raise ValueError('identity path or hash')
        if (not isinstance(value.get('package_version'),str)
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.+_-]{0,100}',value['package_version'])
                or value.get('signature_kind')!='unsigned-content-integrity'
                or (value.get('source_dirty') is not None and type(value.get('source_dirty')) is not bool)
                or not isinstance(value.get('capabilities'),dict)
                or any(k not in CAPABILITIES or type(v) is not int or v<1 for k,v in value['capabilities'].items())):
            raise ValueError('invalid build metadata')
        commit=value.get('source_commit')
        if commit is not None and not re.fullmatch(r'[0-9a-f]{40}',commit):raise ValueError('invalid commit')
        return {'available':True,**value}
    except (OSError,ValueError,TypeError,KeyError):
        return {'available':False,'reason_code':'build_identity_invalid'}


@lru_cache(maxsize=1)
def current_build():
    info=read_identity()
    if not info.get('available'):return info
    return {key:info[key] for key in ('available','build_id','content_sha256','source_commit','source_dirty',
            'package_version','signature_kind','capabilities')} | {
            'package_file_count':len(info['files']),'integrity_state':'declared_not_rehashed_on_request'}


def verify_installed(package_root: Path | None=None):
    root=Path(package_root) if package_root else Path(__file__).resolve().parent
    info=read_identity(root)
    if not info.get('available'):return {**info,'verified':False}
    failed=[]
    for name,sha in info['files'].items():
        path=root.joinpath(*PurePosixPath(name).parts)
        if (path.is_symlink() or not path.resolve().is_relative_to(root.resolve())
                or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=sha):
            failed.append(name)
    actual = {p.relative_to(root).as_posix() for p in root.rglob('*')
              if p.is_file() and p != root/NAME and p.suffix != '.pyc' and '__pycache__' not in p.parts}
    failed.extend(sorted(actual - set(info['files'])))
    version = {}
    if failed:
        # Integrity verification must not execute a package whose contents
        # already differ from the build receipt.
        version = {'version_verified': False, 'version_error': 'package content mismatch prevented version probe'}
    elif (root/'runtime_policy.py').is_file():
        try:
            version = _runtime_version_probe(root, root.parent)
            if version['distribution_package_version'] != info['package_version']:
                raise ValueError('release build identity/distribution version mismatch')
            version['version_verified'] = True
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
            version = {'version_verified': False, 'version_error': str(error)}
    return {'available':True,'verified':not failed and version.get('version_verified', True),'build_id':info['build_id'],
            'content_sha256':info['content_sha256'],'file_count':len(info['files']),
            'mismatched_files':failed[:100],'mismatches_truncated':len(failed)>100,
            'signature_kind':'unsigned-content-integrity', **version}
