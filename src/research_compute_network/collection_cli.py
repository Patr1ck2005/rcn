"""Origin collection commands run before constructing any local control plane."""
from __future__ import annotations

import json
import os
from pathlib import Path

from .collection import CollectionRunner
from .origin_transfer_client import OriginTransferClient


def add_collection_parser(origin_sub):
    parser = origin_sub.add_parser('collect', help='Recover original result bytes and transport evidence')
    actions = parser.add_subparsers(dest='collection_command', required=True)
    for action in ('start', 'status', 'resume', 'finalize'):
        selected = actions.add_parser(action)
        selected.add_argument('--destination', required=True)
        selected.add_argument('--operation-id', required=action != 'start')
        selected.add_argument('--url', default='http://127.0.0.1:8765')
        if action == 'start':
            selected.add_argument('--job-id', required=True)
            selected.add_argument('--job-json', help='Pinned original strict contract for a legacy center')
        if action == 'finalize':
            selected.add_argument('--local-only', action='store_true', required=True)


def execute_collection_command(args):
    from .client import RcnClient
    from .models import JobEnvelope
    # Credentials remain in the existing environment/owner identity mechanisms.
    # No token is accepted in argv or persisted into an operation contract.
    transfer = OriginTransferClient(RcnClient(args.url, os.environ.get('RCN_TOKEN', ''), timeout=60))
    if args.collection_command == 'start':
        if args.job_json:
            job = JobEnvelope.model_validate(json.loads(Path(args.job_json).read_text(encoding='utf-8'))).model_dump(mode='json')
            if job['job_id'] != args.job_id:
                raise ValueError('pinned Job contract does not match the requested identity')
        else:
            job = transfer.client.get_job_contract(args.job_id)
            JobEnvelope.model_validate(job)
        manifests = transfer.client.collect_artifacts(args.job_id)
        runner = CollectionRunner(transfer, job, manifests, args.destination, operation_id=args.operation_id,
                                  reserve_free_bytes=10 * 1024**3)
    else:
        runner = CollectionRunner.from_operation(transfer, args.destination, args.operation_id)
    if args.collection_command == 'status':
        return runner.status()
    if args.collection_command == 'finalize':
        return runner.finalize()
    runner.run()
    return runner.status()
