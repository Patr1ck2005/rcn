"""Installed full-SSH-acceptance inputs, independent of a Workbench checkout.

This is an equivalent fixed-profile acceptance backend, NOT a fake runtime_source
entry point. Scientific inputs and sealed archives are immutable release bytes.
Full lifecycle checks remain owned by SshAcceptanceHarness. Nothing here enables
machines, restarts supervisors, changes scientific code, or grants approvals.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
from functools import lru_cache
import hashlib
from importlib.resources import files
import io
import json
from pathlib import Path
import re
import time
from subprocess import TimeoutExpired
from uuid import uuid4
import zipfile

from .hashing import sha256_value
from .models import JobEnvelope, ResourceMode
from .runtime_policy import DEFAULT_RUNTIME_POLICY
from .scientific_acceptance_contract import (
    CAPSULE_SHA256, capsule_bytes, materialize_capsule,
)

ARCHIVE_PINS = {}


def sealed_files(version: str) -> dict[str, bytes]:
    from .member_release_catalog import release_for_runtime
    from .member_runtime import approved_runtime
    release = release_for_runtime(version).require_configured()
    return approved_runtime(release.archive_path, release_descriptor=release)


class PackagedAcceptanceInputs:
    def __init__(self, state_root: Path):
        self.root = materialize_capsule(Path(state_root))

    def validate(self) -> None:
        for name, raw in capsule_bytes().items():
            path = self.root / name
            if path.is_symlink() or not path.is_file() or path.read_bytes() != raw:
                raise ValueError('packaged_acceptance_input_integrity')

    @property
    def project_yaml(self) -> Path:
        return self.root / 'project.yaml'

    @property
    def template(self) -> Path:
        self.validate()
        return self.root / 'template.mph'

    @property
    def references(self) -> dict[str, Path]:
        self.validate()
        return {
            'local_TEST-3PT': self.root / 'reference-local.json',
            'legacy_SSH_TEST-3PT-R': self.root / 'reference-ssh.json',
        }

    def build_job(self, run, config, policy, machine, concurrency: int, attempt: int):
        self.validate()
        if (run.worker_id != config.machine_id or run.remote_root != config.remote_root
                or concurrency not in run.concurrency_levels or attempt < 1
                or config.comsol_version != '6.4'):
            raise ValueError('packaged_acceptance_run_context_mismatch')
        sealed_files(config.runtime_version)
        if policy is None or machine is None:
            raise ValueError('packaged_acceptance_machine_policy_required')
        budget = policy.effective_cpu_cap(machine.total_cpus)
        cpus = min(4, budget // concurrency)
        if cpus < 1 or 8192 * concurrency > min(policy.max_memory_mb, machine.total_memory_mb):
            raise ValueError('packaged_acceptance_owner_budget_insufficient')
        if policy.member_execution_limit is not None:
            scope = policy.member_execution_limit
            if not scope.is_active():
                raise ValueError('packaged_acceptance_consent_inactive')
            if concurrency > scope.max_concurrent_units or concurrency * 8192 > scope.max_memory_mb:
                raise ValueError('packaged_acceptance_consent_budget_insufficient')
        value = json.loads(capsule_bytes()['compiled-job.json'])
        origin = f'ssh-acceptance-{run.run_id}-c{concurrency}-a{attempt}'
        digest = sha256_value({'capsule_sha256': CAPSULE_SHA256, 'origin': origin,
            'machine_id': config.machine_id, 'root_uuid': config.root_uuid,
            'runtime_version': config.runtime_version, 'cpus': cpus})
        value.update(job_id='job-'+digest[:24], request_hash=digest,
            origin_submitter_id=origin, user_id='admin', record_class='acceptance',
            resource_mode='fixed', revision=0, partition_plan_id=None,
            created_at=run.created_at.isoformat(), updated_at=run.created_at.isoformat())
        for unit in value['work_units']:
            unit.update(work_unit_id=f'unit-{digest[:16]}-{unit["ordinal"]:04d}',
                required_machine_id=config.machine_id, resource_mode='fixed')
            unit['resources']['cpus'] = cpus
            unit['resolved_resources']['resources']['cpus'] = cpus
        job = JobEnvelope.model_validate(value)
        if len(job.work_units) != 3 or any(len(u.atomic_item_ids) != 1 for u in job.work_units):
            raise ValueError('packaged_acceptance_atomic_coverage')
        return self.project_yaml, self.root/'test_batch_3pt.yaml', job

    def verify_runtime(self, config, transport) -> dict:
        """Read the existing exact sealed tree; no deployment, cleanup or restart."""
        from .member_runtime_verification import READ_SCRIPT, inventory_digest
        from .member_registration import _json_document
        from .member_worker_root_contract import canonical_root, root_uuid

        version = config.runtime_version
        contents = sealed_files(version)
        manifest_sha = hashlib.sha256(contents['runtime-manifest.json']).hexdigest()
        inventory_sha = inventory_digest(contents)
        total_bytes = sum(map(len, contents.values()))
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,159}', config.machine_id):
            raise ValueError('packaged_acceptance_machine_identity')
        nonce = uuid4().hex
        context = {'root': canonical_root(config.remote_root), 'uuid': root_uuid(config.root_uuid),
            'machine': config.machine_id, 'version': version, 'nonce': nonce, 'manifest': manifest_sha}
        literal = json.dumps(context, ensure_ascii=True, separators=(',', ':')).replace("'", "''")
        script = "$c='" + literal + "'|ConvertFrom-Json\n" + READ_SCRIPT
        if len(base64.b64encode(script.encode('utf-16-le'))) > 7500:
            raise ValueError('packaged_acceptance_verification_command_bound')
        result = transport._powershell(script, timeout=30)
        if result.returncode or len(result.stdout.encode('utf-8')) > 4096:
            raise RuntimeError('packaged_acceptance_runtime_unconfirmed')
        value = _json_document(result.stdout.encode('utf-8'))
        expected = {'schema_version': 1, 'nonce': nonce, 'machine_id': config.machine_id,
            'root_uuid': config.root_uuid, 'runtime_version': version, 'manifest_sha256': manifest_sha,
            'inventory_sha256': inventory_sha, 'file_count': len(contents), 'total_bytes': total_bytes}
        if (set(value) != set(expected) | {'supervisor_at'}
                or any(value.get(k) != v or type(value.get(k)) is not type(v) for k, v in expected.items())):
            raise RuntimeError('packaged_acceptance_runtime_inventory_mismatch')
        at = datetime.fromisoformat(value['supervisor_at'].replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)
        if at.tzinfo is None or not -5 <= (now-at).total_seconds() <= 45:
            raise RuntimeError('packaged_acceptance_runtime_heartbeat_stale')
        return {k: v for k, v in expected.items() if k != 'nonce'} | {
            'approved_archive_sha256': ARCHIVE_PINS[version], 'read_only': True,
            'verified_at': now.isoformat(), 'verification_kind': 'sealed-runtime-inventory-v1',
        }


def packaged_acceptance_capability() -> dict:
    return {"kind": "origin-owned-ssh-acceptance", "available": False,
            "reason_code": "runtime_not_configured", "runtime_versions": [],
            "workbench_entry_point_required": True,
            "full_lifecycle_checks_preserved": True}



class AcceptanceReadTransport:
    """Bounded retries of known idempotent reads/verified collection only.

    Never retries stage_bundle, config uploads, cancellation, tunnel interruption
    or arbitrary PowerShell. Their uncertain effects must be inspected by the
    operator, using the original run rather than replaying a stage.
    """
    def __init__(self, transport, *, sleep=time.sleep):
        self.transport = transport
        self.sleep = sleep

    def __getattr__(self, name):
        return getattr(self.transport, name)

    def _read(self, operation, *args):
        from .schedulers.ssh import SshTransportUnavailableError
        for attempt in range(3):
            try:
                return operation(*args)
            except (TimeoutExpired, ConnectionError, SshTransportUnavailableError):
                if attempt == 2:
                    raise
                self.sleep(2 * (attempt + 1))

    def read_status(self, external_id):
        return self._read(self.transport.read_status, external_id)

    def download_outputs(self, external_id, destination):
        return self._read(self.transport.download_outputs, external_id, destination)
