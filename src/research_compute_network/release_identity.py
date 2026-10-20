"""Content-addressed build identity, distinct from version, deployment and worker.

The build receipt contains package-relative paths and hashes only. It is not a
signature, machine configuration, secret inventory or proof of live deployment.
"""
from __future__ import annotations
from functools import lru_cache
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tomllib

NAME='build_identity.json'
KIND='rcn-build-identity-v1'
CAPABILITIES={
    'publication_delivery_unknown':1,'bounded_machine_pipeline':1,
    'scheduling_policy':1,'small_batch_first':1,'exact_resource_window':1,
    'evidence_failure_advice':1,'member_distribution_preflight':1,
    'person_submission_policy':1,'compute_credits':1,'control_operation_replay':1,
    'canonical_job_contract':1,'durable_collection':1,'resumable_result_transfer':1,
}


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
    return {'available':True,'verified':not failed,'build_id':info['build_id'],
            'content_sha256':info['content_sha256'],'file_count':len(info['files']),
            'mismatched_files':failed[:100],'mismatches_truncated':len(failed)>100,
            'signature_kind':'unsigned-content-integrity'}
