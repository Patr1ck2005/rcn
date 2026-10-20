"""Operator-invoked full acceptance using existing CLI stages and exact receipts.

Run with the installed coordinator interpreter. Never installs a package,
rebuilds a runtime, enables a machine, changes a machine owner, or commits code.
An incomplete/uncertain stage stops: inspect its retained receipt instead of
silently repeating a remote side effect. Fault injection is explicitly opt-in.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from .models import AcceptanceStatus
from .paths import ControlPlanePaths
from .repository import MetadataRepository
from .scientific_acceptance import _lock
from .ssh_acceptance_inputs import packaged_acceptance_capability


def _save(path: Path, value: dict):
    temporary = path.with_suffix('.writing')
    with temporary.open('w', encoding='utf-8') as out:
        json.dump(value, out, ensure_ascii=True, indent=2); out.flush(); os.fsync(out.fileno())
    os.replace(temporary, path)


def run_acceptance(*, state_root: Path, machine_id: str, run_id: str | None = None,
                   allow_tunnel_interruption: bool = False, actor: str = 'acceptance-operator',
                   timeout_s: int = 7200) -> dict:
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,159}', machine_id):
        raise ValueError('invalid machine identity')
    paths = ControlPlanePaths.from_root(state_root)
    if not paths.database.is_file():
        raise ValueError('existing coordinator database required; never initialize a replacement')
    capability = packaged_acceptance_capability()
    if not capability['available']:
        raise RuntimeError('install the release acceptance dependencies before running')
    repo = MetadataRepository('sqlite:///'+paths.database.as_posix())
    config = repo.get_machine_execution_config(machine_id)
    if config is None or config.enabled:
        raise ValueError('full acceptance runner requires one registered disabled machine; active fleet is untouched')
    if run_id:
        previous = repo.get_ssh_acceptance_run(run_id)
        if previous is None or previous.worker_id != machine_id or previous.concurrency_levels != [1]:
            raise ValueError('existing run must match this machine at concurrency one')
    root = paths.root/'.state'/'ssh-acceptance'
    root.mkdir(parents=True, exist_ok=True)
    journal_path = root/(machine_id+'-operator.json')
    with _lock(root/(machine_id+'-operator.lock')) as acquired:
        if not acquired:
            raise RuntimeError('another operator acceptance invocation owns this machine')
        if journal_path.exists():
            journal = json.loads(journal_path.read_text(encoding='utf-8'))
            if (journal.get('machine_id') != machine_id or journal.get('root_uuid') != config.root_uuid
                    or journal.get('runtime_version') != config.runtime_version
                    or (run_id and journal.get('run_id') != run_id)):
                raise ValueError('acceptance journal context changed; preserve and inspect it')
        else:
            if run_id is None:
                existing = [r for r in repo.list_ssh_acceptance_runs() if r.worker_id == machine_id]
                if existing:
                    raise ValueError('existing acceptance records require an explicit --run-id; '
                                     'inspect them before creating another run: '
                                     + ', '.join(r.run_id for r in existing[:5]))
            journal = {'schema_version': 1, 'machine_id': machine_id, 'root_uuid': config.root_uuid,
                       'runtime_version': config.runtime_version, 'run_id': run_id, 'stages': {}}
            _save(journal_path, journal)

        def stage(name, command):
            latest = repo.get_machine_execution_config(machine_id)
            if (latest is None or latest.enabled or latest.root_uuid != config.root_uuid
                    or latest.remote_root != config.remote_root or latest.runtime_version != config.runtime_version
                    or latest.comsol_root != config.comsol_root or latest.comsol_version != config.comsol_version):
                raise RuntimeError('machine execution context changed; stop before another acceptance stage')
            old = journal['stages'].get(name)
            if old:
                if old.get('state') == 'completed':
                    return old['result']
                raise RuntimeError(f'{name}: retained {old.get("state")} receipt; inspect the exact run before any replay')
            row = {'state': 'executing', 'command': command,
                   'started_at': datetime.now(timezone.utc).isoformat()}
            journal['stages'][name] = row
            _save(journal_path, journal)  # Durable intent before any remote side effect.
            env = os.environ.copy()
            env.update(RCN_HOME=str(paths.root), RCN_DATABASE_URL='sqlite:///'+paths.database.as_posix())
            output = root/(machine_id+'-'+name+'.stdout.log')
            errors = root/(machine_id+'-'+name+'.stderr.log')
            with output.open('x', encoding='utf-8') as out, errors.open('x', encoding='utf-8') as err:
                result = subprocess.run([sys.executable, '-X', 'utf8', '-B', '-m',
                    'research_compute_network.cli', '--database-url', env['RCN_DATABASE_URL'],
                    *command], env=env, stdout=out, stderr=err, timeout=timeout_s+120)
            row.update(exit_code=result.returncode, stdout=str(output), stderr=str(errors))
            if result.returncode:
                row['state'] = 'failed'; _save(journal_path, journal)
                raise RuntimeError(f'{name} failed; preserve {output} and {errors}; no automatic replay')
            try:
                value = json.loads(output.read_text(encoding='utf-8-sig'))
            except ValueError:
                row['state'] = 'unconfirmed'; _save(journal_path, journal)
                raise RuntimeError(f'{name} returned non-JSON evidence; inspect before replay') from None
            row.update(state='completed', result=value, finished_at=datetime.now(timezone.utc).isoformat())
            _save(journal_path, journal)
            print(json.dumps({'stage': name, 'state': 'completed', 'run_id': journal['run_id']}), flush=True)
            return value

        if not journal.get('run_id'):
            value = stage('create', ['ssh-acceptance-create', machine_id, '--concurrency', '1', '--actor', actor])
            journal['run_id'] = value['run_id']; _save(journal_path, journal)
        selected = journal['run_id']
        current = repo.get_ssh_acceptance_run(selected)
        if (current is None or current.worker_id != machine_id or current.remote_root != config.remote_root
                or current.concurrency_levels != [1]):
            raise ValueError('retained run binding differs from current registered machine')
        def invoke(name, *args):
            return stage(name, ['ssh-acceptance-'+name, selected, *args, '--actor', actor])
        invoke('preflight')
        invoke('init-root')
        invoke('verify-runtime')
        invoke('safe-fake')
        invoke('project-worker')
        normal = invoke('submit', '1')['external_run_ids']
        invoke('collect', '1', *normal, '--timeout-s', str(timeout_s))
        for when in ('python_start', 'comsol_start', 'solve'):
            stage('cancel-'+when, ['ssh-acceptance-cancel-stage', selected, when, '--actor', actor])
        invoke('transfer-cancel', normal[0])
        if not allow_tunnel_interruption:
            return {'state': 'awaiting_explicit_tunnel_interruption', 'run_id': selected,
                    'journal': str(journal_path), 'enabled': False}
        tunnel = invoke('tunnel-prepare')['external_run_ids']
        invoke('tunnel-cycle', '--outage-seconds', '30')
        invoke('tunnel-verify', *tunnel, '--outage-seconds', '30', '--timeout-s', str(timeout_s))
        invoke('no-residual')
        report = invoke('report', '--require-passed')
        current = repo.get_ssh_acceptance_run(selected)
        if current is None or current.status != AcceptanceStatus.PASSED or report.get('status') != 'passed':
            raise RuntimeError('full acceptance has not passed; never enable from partial results')
        return {'state': 'passed', 'run_id': selected, 'report': report, 'journal': str(journal_path),
                'enabled': repo.get_machine_execution_config(machine_id).enabled,
                'enable_performed': False}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--state-root', required=True, type=Path)
    p.add_argument('--machine', required=True)
    p.add_argument('--run-id')
    p.add_argument('--allow-tunnel-interruption', action='store_true')
    p.add_argument('--actor', default='acceptance-operator')
    p.add_argument('--timeout-s', type=int, default=7200)
    args = p.parse_args(argv)
    if not 120 <= args.timeout_s <= 14400:
        p.error('timeout must be between 120 and 14400 seconds')
    result = run_acceptance(state_root=args.state_root, machine_id=args.machine, run_id=args.run_id,
        allow_tunnel_interruption=args.allow_tunnel_interruption, actor=args.actor, timeout_s=args.timeout_s)
    print(json.dumps(result, ensure_ascii=True, indent=2))
    return 0 if result['state']=='passed' else 2


if __name__ == '__main__':
    raise SystemExit(main())
