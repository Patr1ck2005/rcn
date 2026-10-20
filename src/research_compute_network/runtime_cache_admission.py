"""Audited exact sealed runtimes cached beside a machine's primary runtime.

This is execution inventory, not a scientific-equivalence grant. A requested
runtime keeps its original solver approval and sealed scientific source. The
operator must prove that the configured interpreter actually imports that
source through the same explicit sealed launcher used for scientific workers.
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from functools import lru_cache
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, field_validator, model_validator

from .runtime_policy import STABLE_RUNTIME_VERSION

CACHE_ADMISSION_KEY = "runtime_cache_admission_v1"
RUNTIME_CACHE_PREFIX = "runtime_cache_"
SERVER_CACHE_ARCHIVE_DIR = Path(__file__).parent / "acceptance_fixtures"
SERVER_CACHE_ARCHIVE_PINS = {}  # Public package has no preapproved scientific archives.
REQUESTED_RUNTIME_LAUNCHER_SHA256 = "a852f060842d9b4b6587985a3fd47d693cc526843eb3e4bb9edf52e978361f6e"


def normalized_path(value: str) -> str:
    if not value or "\x00" in value:
        raise ValueError("an explicit execution path is required")
    cls = PureWindowsPath if re.match(r"^[A-Za-z]:", value) or "\\" in value else PurePosixPath
    path = cls(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("execution inventory requires an absolute path without traversal")
    result = path.as_posix().rstrip("/")
    return result.casefold() if cls is PureWindowsPath else result


class RuntimeImportProbe(BaseModel):
    model_config = ConfigDict(extra="forbid")
    route_mode: Literal["explicit-sealed-path-v1"]
    isolated: StrictInt = Field(ge=0, le=1)
    ignore_environment: StrictInt = Field(ge=0, le=1)
    workbench_module_path: str
    workbench_module_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    bootstrap_path: str
    bootstrap_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    launcher_path: str
    launcher_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


def _server_cache_files(cache_runtime: str) -> dict[str, bytes]:
    """Verify only the explicitly operator-approved external archive."""
    import hashlib
    import io
    import stat
    import zipfile
    from .member_runtime import MAX_ARCHIVE, MAX_EXPANDED, MAX_FILE
    from .member_registration import _unlinked
    from .member_release_catalog import release_for_runtime
    from .member_runtime import approved_runtime
    release = release_for_runtime(cache_runtime).require_configured()
    # Preserve the existing caller contract while obtaining trust only from the
    # local operator descriptor, never a hash in a job or HTTP request.
    SERVER_CACHE_ARCHIVE_PINS[cache_runtime] = release.archive_sha256
    return approved_runtime(release.archive_path, release_descriptor=release)

def server_cached_runtime_files(cache_runtime: str = STABLE_RUNTIME_VERSION) -> dict[str, bytes]:
    # A caller cannot mutate the trusted cached inventory used by later requests.
    return dict(_server_cache_files(cache_runtime))


def _route_pins(cache_runtime: str = STABLE_RUNTIME_VERSION) -> dict[str, str]:
    """Independent server pins for the original scientific entry and launcher."""
    # Keep tiny digest sets across many exact runtimes; expanded archive bytes
    # remain separately bounded to six versions by _server_cache_files.
    import hashlib
    from .remote_agent import requested_runtime_imports
    files = server_cached_runtime_files(cache_runtime)
    launcher_sha = hashlib.sha256(Path(requested_runtime_imports.__file__).read_bytes()).hexdigest()
    if launcher_sha != REQUESTED_RUNTIME_LAUNCHER_SHA256:
        raise ValueError("server requested-runtime launcher differs from its immutable pin")
    return {"workbench_module_sha256": hashlib.sha256(files["workbench-src/research_agent_workbench/__init__.py"]).hexdigest(),
            "bootstrap_sha256": hashlib.sha256(files["remote-agent/comsol_worker_bootstrap.py"]).hexdigest(),
            "launcher_sha256": launcher_sha}


class CachedRuntimeAdmission(BaseModel):
    model_config = ConfigDict(extra="forbid")
    machine_id: str = Field(min_length=1)
    root_uuid: str = Field(min_length=1)
    remote_root: str
    primary_runtime: str = Field(min_length=1)
    python_executable: str
    cache_runtime: str = Field(pattern=r"^[0-9a-f]{24}$")
    archive_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    inventory_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    file_count: StrictInt = Field(ge=1)
    transport_closed_normally: StrictBool = True
    verified_at: datetime
    route_probe: RuntimeImportProbe

    @field_validator("verified_at")
    @classmethod
    def aware_time(cls, value):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("inventory verification time requires a timezone")
        return value

    @model_validator(mode="after")
    def exact_import_paths(self):
        root = normalized_path(self.remote_root)
        normalized_path(self.python_executable)
        runtime = root + "/agent/versions/" + self.cache_runtime
        expected = runtime + "/workbench-src/research_agent_workbench/__init__.py"
        if normalized_path(self.route_probe.workbench_module_path) != expected:
            raise ValueError("configured Python did not import the requested sealed Workbench")
        if normalized_path(self.route_probe.bootstrap_path) != runtime + "/remote-agent/comsol_worker_bootstrap.py":
            raise ValueError("worker bootstrap is outside the requested sealed runtime")
        launcher = root + "/agent/versions/" + self.primary_runtime + "/remote-agent/requested_runtime_imports.py"
        if normalized_path(self.route_probe.launcher_path) != launcher:
            raise ValueError("requested scientific launcher is outside the current primary runtime")
        if any(getattr(self.route_probe, key) != expected for key, expected in _route_pins(self.cache_runtime).items()):
            raise ValueError("actual scientific import entry or launcher differs from server-pinned bytes")
        if self.primary_runtime == self.cache_runtime:
            raise ValueError("the primary runtime does not need a cache admission")
        return self


class RuntimeCacheInventory(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: StrictInt = Field(ge=1, le=1)
    admissions: list[CachedRuntimeAdmission] = Field(default_factory=list, max_length=32)

    @model_validator(mode="after")
    def unique_versions(self):
        versions = [record.cache_runtime for record in self.admissions]
        if len(versions) != len(set(versions)):
            raise ValueError("duplicate cached runtime admissions")
        return self


class CachedRuntimeAdmissionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    evidence: CachedRuntimeAdmission
    reason: str = Field(min_length=1)
    cache_runtime: str = Field(default=STABLE_RUNTIME_VERSION, pattern=r"^[0-9a-f]{24}$")


def admission_matches_machine(record, machine, config) -> bool:
    if config is None or machine is None:
        return False
    try:
        return bool(
            record.machine_id == machine.machine_id == config.machine_id
            and record.root_uuid == config.root_uuid
            and record.primary_runtime == machine.runtime_version == config.runtime_version
            and normalized_path(record.remote_root) == normalized_path(config.remote_root)
            and normalized_path(record.python_executable) == normalized_path(config.python_executable)
        )
    except (TypeError, ValueError, AttributeError):
        return False


def accepted_cache_admissions(machine, config) -> list[CachedRuntimeAdmission]:
    if config is None:
        return []
    raw = config.execution_provenance.get(CACHE_ADMISSION_KEY)
    if raw is None:
        return []
    try:
        inventory = RuntimeCacheInventory.model_validate_json(raw)
    except (TypeError, ValueError):
        return []
    return [record for record in inventory.admissions if admission_matches_machine(record, machine, config)]


def accepts_cached_runtime(machine, config, runtime: str | None) -> bool:
    return any(record.cache_runtime == runtime for record in accepted_cache_admissions(machine, config))


def merge_cache_admission(machine, config, record: CachedRuntimeAdmission) -> tuple[str, bool]:
    record = CachedRuntimeAdmission.model_validate(record.model_dump(mode="json"))
    if not admission_matches_machine(record, machine, config):
        raise ValueError("cached runtime proof differs from the current registered execution binding")
    # Retain only admissions whose binding still describes this execution root.
    records = accepted_cache_admissions(machine, config)
    for old in records:
        if old.cache_runtime == record.cache_runtime and old == record:
            return config.execution_provenance[CACHE_ADMISSION_KEY], False
    records = [old for old in records if old.cache_runtime != record.cache_runtime] + [record]
    inventory = RuntimeCacheInventory(schema_version=1, admissions=sorted(records, key=lambda item: item.cache_runtime))
    return json.dumps(inventory.model_dump(mode="json"), sort_keys=True, separators=(",", ":")), True


# A fixed read operation, launched with the registered interpreter and pinned
# transport. It neither installs a runtime nor starts a scientific task.
_CACHE_READ = r'''
import datetime,hashlib,json,os,stat,sys
from pathlib import Path
q=CONTEXT;root=Path(q['root']);base=root/'agent/versions'/q['cache']
def read(p):
 for ancestor in (p,*p.parents):
  if ancestor==root.parent:break
  s=ancestor.lstat()
  if stat.S_ISLNK(s.st_mode) or getattr(s,'st_file_attributes',0)&1024:raise ValueError('linked execution inventory')
 if p.stat().st_size>262144:raise ValueError('inventory file bound')
 return p.read_bytes()
marker=json.loads(read(root/'.rcn-root.json').decode('utf-8-sig'))
status=json.loads(read(root/'agent/status.json').decode('utf-8-sig'))
assert marker['machine_id']==q['machine'] and marker['root_uuid']==q['uuid']
assert status['machine_id']==q['machine'] and status['root_uuid']==q['uuid'] and status['runtime_version']==q['primary']
assert Path(sys.executable).resolve()==Path(q['python']).resolve()
raw=read(base/'runtime-manifest.json');assert hashlib.sha256(raw).hexdigest()==q['manifest']
manifest=json.loads(raw);assert manifest['version']==q['cache']
files={'runtime-manifest.json':raw}
for name,sha in manifest['files'].items():
 if name=='__runtime_layout_version__':continue
 rel='workbench-src/research_agent_workbench/'+name[len('workbench/'):] if name.startswith('workbench/') else name
 assert rel.startswith(('workbench-src/research_agent_workbench/','remote-agent/')) and '..' not in Path(rel).parts
 data=read(base/rel);assert hashlib.sha256(data).hexdigest()==sha;files[rel]=data
lines=[name+'\0'+str(len(data))+'\0'+hashlib.sha256(data).hexdigest()+'\n' for name,data in sorted(files.items())]
primary=root/'agent/versions'/q['primary'];launcher=primary/'remote-agent/requested_runtime_imports.py'
launcher_raw=read(launcher);assert hashlib.sha256(launcher_raw).hexdigest()==q['launcher']
primary_manifest=json.loads(read(primary/'runtime-manifest.json'));assert primary_manifest['version']==q['primary']
assert primary_manifest['files']['remote-agent/requested_runtime_imports.py']==q['launcher']
scope={'__name__':'cached_runtime_import_probe','__file__':str(launcher)}
exec(compile(launcher_raw,str(launcher),'exec'),scope)
route=scope['probe_requested_runtime'](base)
value={'machine_id':q['machine'],'root_uuid':q['uuid'],'remote_root':str(root),'primary_runtime':q['primary'],'python_executable':q['python'],'cache_runtime':q['cache'],'archive_sha256':q['archive'],'manifest_sha256':hashlib.sha256(raw).hexdigest(),'inventory_sha256':hashlib.sha256(''.join(lines).encode('ascii')).hexdigest(),'file_count':len(files),'verified_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'route_probe':route}
out=json.dumps(value,separators=(',',':')).encode('utf8');os.write(1,out+b'\n');os._exit(0)
'''


def verify_cached_runtime(machine, config, transport, *, cache_runtime: str = STABLE_RUNTIME_VERSION,
                          runtime_policy=None) -> CachedRuntimeAdmission:
    """Read every pinned source and prove the supervisor's actual import route."""
    import base64
    import hashlib
    import zlib
    from .member_runtime_verification import inventory_digest
    from .runtime_policy import runtime_policy_from_environment
    policy = runtime_policy if runtime_policy is not None else runtime_policy_from_environment()
    if not policy.accepts_worker_runtime(cache_runtime):
        raise ValueError("cached runtime is not accepted by the current worker runtime policy")
    files = server_cached_runtime_files(cache_runtime)
    archive_sha = SERVER_CACHE_ARCHIVE_PINS[cache_runtime]
    manifest_sha = hashlib.sha256(files["runtime-manifest.json"]).hexdigest()
    if config.runtime_version != machine.runtime_version or not config.root_uuid:
        raise ValueError("current primary execution binding is not attested")
    q = dict(root=config.remote_root, uuid=config.root_uuid, machine=machine.machine_id,
             primary=machine.runtime_version, python=config.python_executable,
             cache=cache_runtime, manifest=manifest_sha, archive=archive_sha,
             launcher=_route_pins(cache_runtime)["launcher_sha256"])
    source = _CACHE_READ.replace("CONTEXT", repr(q))
    compressed = base64.b64encode(zlib.compress(source.encode("utf8"))).decode("ascii")
    boot = "exec(__import__('zlib').decompress(__import__('base64').b64decode('" + compressed + "')))"
    script = "$ErrorActionPreference='Stop'; & '" + config.python_executable.replace("'", "''") + "' -B -X utf8 -c \"" + boot + "\";exit $LASTEXITCODE"
    if len(base64.b64encode(script.encode("utf-16-le"))) > 7500:
        raise ValueError("fixed cache verification exceeds the native command bound")
    import subprocess
    closed_normally = True
    try:
        result = transport._powershell(script, timeout=45)
        if result.returncode:
            raise ValueError("exact cached runtime readback is unavailable")
        raw = result.stdout
    except subprocess.TimeoutExpired as exc:
        # A complete authenticated read receipt can precede a hung SSH close.
        # Verify that very receipt; no alternative route or request is used.
        raw = exc.stdout or b""
        if isinstance(raw, bytes):
            raw = raw.decode("utf8")
        closed_normally = False
    if len(raw.encode("utf8")) > 8192:
        raise ValueError("exact cached runtime readback is unavailable")
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        raise ValueError("exact cached runtime receipt is incomplete") from None
    value["transport_closed_normally"] = closed_normally
    value["evidence_sha256"] = hashlib.sha256(raw.encode("utf8")).hexdigest()
    evidence = CachedRuntimeAdmission.model_validate(value)
    if (not admission_matches_machine(evidence, machine, config)
            or evidence.cache_runtime != cache_runtime
            or evidence.archive_sha256 != archive_sha
            or evidence.manifest_sha256 != manifest_sha
            or evidence.inventory_sha256 != inventory_digest(files)
            or evidence.file_count != len(files)):
        raise ValueError("cached runtime differs from the complete server-pinned inventory")
    return evidence
