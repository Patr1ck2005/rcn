"""Operator entry for dedicated relay key-lease reconciliation, not service installation."""
from __future__ import annotations

import json
from pathlib import Path
import time

from .member_relay import MemberRelays
from .member_relay_policy import RENEW_SECONDS, RelayUnavailable, load_policy


def synchronize(database_url: str | None, root: Path, *, watch: bool = False) -> int:
    # Never infer the production database from a development shell/environment.
    if not database_url or not database_url.startswith('sqlite:///'):
        print(json.dumps({'success': False, 'reason_code': 'explicit_sqlite_database_required'}))
        return 2
    repository = None
    try:
        # Validate deployment BEFORE constructing anything that initializes metadata.
        load_policy(root, require_enabled=False)
        from sqlalchemy.engine import make_url
        path = Path(make_url(database_url).database or '')
        if not path.is_file():
            raise RelayUnavailable('existing_relay_database_required')
        from .repository import MetadataRepository
        repository = MetadataRepository(database_url)
        manager = MemberRelays(repository, authorization_root=root, verification_root=root / 'proof-work')
        while True:
            try:
                result = manager.synchronize()
                print(json.dumps({key: value for key, value in result.items() if key != 'authorized_enrollments'}), flush=True)
                status = 0
            except RelayUnavailable as exc:
                print(json.dumps({'success': False, 'reason_code': str(exc),
                                  'existing_sessions_revoked': False}), flush=True)
                status = 2
            except (RelayUnavailable, OSError, ValueError, RuntimeError):
                # Raw exceptions can contain database/host information. An error is
                # never labelled a successful refresh; old keys expire independently.
                print(json.dumps({'success': False, 'reason_code': 'relay_reconciliation_failed',
                                  'existing_sessions_revoked': False}), flush=True)
                status = 2
            if not watch:
                return status
            time.sleep(RENEW_SECONDS)
    except KeyboardInterrupt:
        return 0
    except RelayUnavailable as exc:
        print(json.dumps({'success': False, 'reason_code': str(exc)}))
        return 2
    except (RelayUnavailable, OSError, ValueError, RuntimeError):
        print(json.dumps({'success': False, 'reason_code': 'relay_deployment_not_ready'}))
        return 2
    finally:
        if repository is not None:
            repository.engine.dispose()
