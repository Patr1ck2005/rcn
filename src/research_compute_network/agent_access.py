"""Agent-neutral local CLI over MemberBroker and its DPAPI credential store.

Run ``python -m research_compute_network.agent_access --help``. This module
never opens a coordinator database, exposes a shell, or accepts token argv.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path
import sys
import time
from uuid import uuid4
from urllib.parse import quote

from fastapi import HTTPException

from .client import RcnApiError
from .member_client import Login, MemberBroker, PlanOptions, default_client_root
from .member_client_credentials import CredentialUnavailable

MODULE = "research_compute_network.agent_access"
TERMINAL = {"completed", "failed_terminal", "cancelled"}
PENDING_ATTEMPTS = {"assigned", "submitting", "running", "uncertain", "reconcile_pending",
                    "cancel_pending", "collecting"}


class AgentAccessError(ValueError):
    def __init__(self, reason_code, message=None):
        self.reason_code = reason_code
        super().__init__(message or reason_code)


def remote_confirmation_pending(job):
    return any(attempt.get("state") in PENDING_ATTEMPTS
               for unit in job.get("work_units", []) for attempt in unit.get("attempts", []))


class _Parser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("allow_abbrev", False)
        super().__init__(*args, **kwargs)

    def error(self, message):
        # A mistaken --token SECRET must not be echoed back to a transcript.
        super().error("invalid arguments; run --help (tokens belong in the hidden prompt or named environment variable)")


def _emit(value):
    print(json.dumps(value, ensure_ascii=False, allow_nan=False), flush=True)


def parser():
    result = _Parser(description="RCN personal Agent access (local DPAPI credentials)")
    result.add_argument("--state-root", type=Path, default=None)
    commands = result.add_subparsers(dest="action", required=True)
    commands.add_parser("status")
    commands.add_parser("capabilities")
    configure = commands.add_parser("configure")
    configure.add_argument("--center-url", required=True)
    configure.add_argument("--token-env", default="RCN_PERSONAL_TOKEN", help="Environment variable NAME, never a token value")
    instructions = commands.add_parser("instructions")
    instructions.add_argument("--output", type=Path, required=True, help="New instruction directory")
    plan = commands.add_parser("plan")
    plan.add_argument("--package", type=Path, required=True)
    plan.add_argument("--operation-id", help="Recover this exact UUID; omitted reuses the same package's existing operation")
    plan.add_argument("--unit-count", type=int)
    plan.add_argument("--estimated-seconds-per-item", type=float)
    submit = commands.add_parser("submit")
    submit.add_argument("--operation-id", required=True)
    collect = commands.add_parser("collect")
    collect.add_argument("--operation-id", required=True)
    watch = commands.add_parser("watch")
    watch.add_argument("--operation-id", required=True)
    watch.add_argument("--timeout-s", type=float, default=60)
    watch.add_argument("--interval-s", type=float, default=5)
    cancel = commands.add_parser("cancel")
    cancel.add_argument("--operation-id", required=True)
    cancel.add_argument("--reason", required=True)
    diagnostics = commands.add_parser("diagnostics")
    diagnostics.add_argument("--operation-id", required=True)
    pool = commands.add_parser("pool", help="Inspect or explicitly set this owner's machine pools")
    pool.add_argument("--machine-id", required=True)
    pool.add_argument("--free-idle", choices=["on", "off"])
    pool.add_argument("--mutual", choices=["on", "off"])
    return result


def instruction_artifacts(broker, directory: Path) -> dict:
    session = broker.session()
    directory = Path(directory).absolute()
    directory.mkdir(parents=True, exist_ok=False)
    config = {"schema_version": 1, "kind": "rcn-agent-access", "module": MODULE,
              "command_prefix": [sys.executable, "-B", "-m", MODULE, "--state-root", str(broker.root)],
              "center_url": session.get("center_url", ""), "credential_storage": "windows-current-user-dpapi",
              "token_argv_supported": False, "submission_format": "rcn-data-package-v1",
              "commands": ["status", "capabilities", "configure", "plan", "submit", "watch", "cancel", "collect", "diagnostics", "pool"]}
    (directory / "rcn-agent-access.json").write_text(json.dumps(config, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    text = """# RCN personal Agent access

Use `rcn-agent-access.json` for the installed interpreter, module and local state
root. This interface works with any Agent that can call a local command and
read JSON lines. The personal credential remains in Windows CurrentUser DPAPI.

1. Run `status`, then `capabilities`. Check the returned person, allowed
   Profiles and quota before planning. A cached identity alone is not online.
2. If login is needed, the human configures `configure --center-url HTTPS_URL`.
   It reads the named token environment variable or a hidden interactive
   prompt. Never put a token in a command argument, artifact, prompt or log.
3. Produce a registered data-only RCN submission ZIP through the origin-side
   compiler. Never invent scientific inputs, Unit counts or duration estimates.
4. Call `plan --package PATH`. Keep the returned operation UUID. The same
   package recovers its existing operation by default. A deliberately supplied
   fresh UUID means a separate execution and requires explicit user intent.
5. Call `submit --operation-id UUID` to confirm and upload that operation.
   Interrupted or unknown delivery must resume the same UUID and original ZIP.
6. Call `watch --operation-id UUID --timeout-s 60`. A timeout means observation
   stopped, not that the job failed or was cancelled. Invoke it again as needed.
7. Once completed, call `collect --operation-id UUID`. Use the verified local
   result directory in the JSON receipt; scientific import/acceptance belongs
   to the originating project. A completed Job is not scientific validation.

No command grants roles, opens a remote shell, or
creates another submission to recover uncertain delivery. Consumers using the
same state root share package and operation journals. With a different Agent
state root, explicitly preserve the original operation UUID when recovering;
do not submit another execution because its local journal is absent.
"""
    text += """
Use `diagnostics --operation-id UUID` for the original Job's placement blockers.
Use `cancel --operation-id UUID --reason REASON` only when the human wants that
Job cancelled. Retry the same operation after a lost reply; cancellation records
intent, while remote acknowledgement and completed stopping are separate states.

Codex: read AGENT_ACCESS.md as this project's local instructions and use the
JSON command prefix. Claude Code: reference the same file from CLAUDE.md or the
project's existing instructions. DSH: reference it from the workspace AGENTS.md.
These references contain no credential and do not grant new execution types.

Machine owners can inspect `pool --machine-id ID`. Changing it requires both
`--free-idle on|off --mutual on|off` explicitly. The center verifies ownership;
an administrator role does not substitute for owner consent. Free-idle usage
never earns exchange credits. This does not alter CPU budgets, schedules,
execution types or already running work.
"""
    (directory / "AGENT_ACCESS.md").write_text(text, encoding="utf-8")
    return {"config": str(directory / "rcn-agent-access.json"), "instructions": str(directory / "AGENT_ACCESS.md")}


def execute(args, broker):
    if args.action == "status":
        _emit(broker.session(refresh=bool(broker.login)))
    elif args.action == "configure":
        token = os.environ.get(args.token_env) or getpass.getpass("RCN personal token: ")
        if not token.strip():
            raise AgentAccessError("personal_token_required")
        _emit(broker.sign_in(Login(center_url=args.center_url, token=token)))
    elif args.action == "instructions":
        _emit(instruction_artifacts(broker, args.output))
    elif args.action == "capabilities":
        value = {"schema_version": 1, "kind": "rcn-agent-access", "credential_storage": "windows-current-user-dpapi",
                 "token_argv_supported": False, "commands": ["status", "capabilities", "configure", "plan", "submit", "watch", "cancel", "collect", "diagnostics", "pool"],
                 "session": broker.session(refresh=bool(broker.login))}
        if broker.login and value["session"].get("online"):
            for key, path in [("submission_policy", "/v1/me/submission-policy"), ("credits", "/v1/me/credits"), ("profiles", "/v1/profiles")]:
                try:
                    value[key] = broker.client()._request("GET", path)
                except RcnApiError as exc:
                    value[key] = {"available": False, "reason_code": exc.reason_code or "center_capability_unavailable"}
        _emit(value)
    elif args.action == "plan":
        package = broker.import_package(args.package)
        operation_id = args.operation_id or package.get("operation_id") or str(uuid4())
        options = {"package_id": package["package_id"]}
        if args.unit_count is not None:
            options["requested_unit_count"] = args.unit_count
        if args.estimated_seconds_per_item is not None:
            options["estimated_seconds_per_item"] = args.estimated_seconds_per_item
        if not args.operation_id and package.get("operation_id") and len(options) == 1:
            _emit(broker.refresh(operation_id))
        else:
            _emit(broker.plan(operation_id, PlanOptions(**options)))
    elif args.action in {"submit", "collect"}:
        if args.action == "submit":
            broker.confirm(args.operation_id)
        else:
            broker.refresh(args.operation_id)
        broker.start_transfer(args.operation_id, collect=args.action == "collect")
        # A one-shot CLI must keep its process alive until the transfer receipt
        # is written. close() waits for the broker's existing transfer worker.
        broker.close()
        receipt = broker.present(broker.read_operation(args.operation_id))
        _emit(receipt)
        if receipt.get("error"):
            return 2
    elif args.action == "pool":
        path = f"/v1/machines/{quote(args.machine_id, safe='')}/compute-pool-consent"
        if args.free_idle is None and args.mutual is None:
            _emit(broker.client()._request("GET", path))
        else:
            if args.free_idle is None or args.mutual is None:
                raise AgentAccessError("pool_choices_required", "both pool choices must be explicit")
            _emit(broker.client()._request("PUT", path, {
                "free_idle_enabled": args.free_idle == "on", "mutual_enabled": args.mutual == "on"}))
    elif args.action in {"cancel", "diagnostics"}:
        receipt = broker.refresh(args.operation_id)
        job_id = receipt.get("job_id") or receipt.get("job", {}).get("job_id")
        if not job_id:
            raise AgentAccessError("operation_not_submitted")
        if args.action == "cancel":
            broker.client().cancel(job_id, reason=args.reason)
            observed = broker.refresh(args.operation_id)
            _emit({**observed, "cancellation": {"request_accepted": True,
                "remote_confirmation_pending": remote_confirmation_pending(observed.get("job") or {})}})
        else:
            _emit(broker.client()._request("GET", f"/v1/jobs/{quote(job_id, safe='')}/placement-diagnostics"))
    elif args.action == "watch":
        if not (0 < args.interval_s <= 60 and 0 < args.timeout_s <= 43200):
            raise AgentAccessError("watch_bounds_invalid")
        deadline = time.monotonic() + args.timeout_s
        previous = None
        while True:
            receipt = broker.refresh(args.operation_id)
            # The local journal updates its timestamp on every observation;
            # changes to that timestamp alone are not useful watch events.
            signature = json.dumps({k: v for k, v in receipt.items() if k != "updated_at"}, sort_keys=True)
            if signature != previous:
                _emit(receipt)
                previous = signature
            job = receipt.get("job") or {}
            if job.get("status") in TERMINAL and not remote_confirmation_pending(job):
                return 0
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _emit({"operation_id": args.operation_id, "reason_code": "watch_timeout", "resume_same_operation": True})
                return 3
            time.sleep(min(args.interval_s, remaining))
    return 0


def main(argv=None):
    args = parser().parse_args(argv)
    broker = None
    try:
        broker = MemberBroker(args.state_root or default_client_root())
        return execute(args, broker)
    except KeyboardInterrupt:
        _emit({"reason_code": "agent_action_interrupted", "resume_same_operation": True})
        return 130
    except (RcnApiError, HTTPException, CredentialUnavailable, ValueError, OSError) as exc:
        # Network/native exception text can contain response bodies or secrets.
        code = getattr(exc, "reason_code", None) or "agent_access_unavailable"
        _emit({"reason_code": code, "resume_same_operation": args.action in {"plan", "submit", "watch", "cancel", "collect", "diagnostics"}})
        return 2
    finally:
        if broker is not None and not broker.closed:
            broker.close()


if __name__ == "__main__":
    raise SystemExit(main())
