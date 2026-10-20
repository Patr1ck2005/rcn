"""Member-side one-shot installation wizard (post-bootstrap phase).

The packaged ``install-member.ps1`` owns the pre-package bootstrap (locating
the invitation file, ensuring Python 3.11, installing the wheel). Once
``research_compute_network`` is importable it hands over to ``run_wizard``,
which performs the complete member setup with zero technical input:

1. materialize the invitation's gateway keypair + pinned known_hosts;
2. enroll via the one-time invitation code (the gateway tunnel is started by
   ``node setup`` before the enrollment POST, exactly like the documented
   member flow);
3. install the desktop launcher (collision-tolerant, never destructive);
4. write the welcome note (personal token) and open the console login page.

The wizard is idempotent for the same member-machine identity: re-running it
after a completed enrollment skips enrollment instead of consuming a second
invitation code. A replacement invitation for the same owner but a new machine
ID first removes the superseded local node state; it never inherits a revoked
machine credential.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

WIZARD_SCHEMA = 1


class WizardError(RuntimeError):
    """Raised when the member setup cannot proceed safely."""


def _windows_current_user_sid() -> str:
    """Resolve the current user's SID without depending on localized usernames."""
    completed = subprocess.run(
        ["whoami.exe", "/user", "/fo", "csv", "/nh"],
        check=False,
        capture_output=True,
    )
    match = re.search(rb"S-\d+(?:-\d+)+", completed.stdout)
    if completed.returncode != 0 or match is None:
        raise WizardError("could not resolve the Windows user SID for the gateway key ACL")
    return match.group(0).decode("ascii")


def _protect_private_key(key_path: Path, *, windows: bool | None = None) -> None:
    """Make a gateway private key acceptable to the platform SSH client."""
    is_windows = os.name == "nt" if windows is None else windows
    if not is_windows:
        os.chmod(key_path, 0o600)
        return

    user_sid = _windows_current_user_sid()
    completed = subprocess.run(
        [
            "icacls.exe",
            str(key_path),
            "/inheritance:r",
            "/grant:r",
            f"*{user_sid}:F",
            "*S-1-5-18:F",
            "*S-1-5-32-544:F",
        ],
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).decode(errors="replace").strip()
        raise WizardError(f"could not protect the Windows gateway private key: {detail}")


def _materialize_keys(invitation: dict, state_root: Path) -> tuple[Path, Path]:
    gateway = invitation["gateway"]
    state_root.mkdir(parents=True, exist_ok=True)
    key_path = state_root / "gateway-key"
    key_path.write_text(gateway["private_key"], encoding="ascii", newline="\n")
    _protect_private_key(key_path)
    known = state_root / "known_hosts"
    known.write_text(gateway["known_hosts_line"] + "\n", encoding="ascii")
    return key_path, known


def _require_gateway_authorized(invitation: dict) -> str | None:
    """The invitation is a snapshot: ``pending_authorized_keys_line`` records
    the generation-time state, not the live state (the administrator may have
    authorized the key after generating the file). Return the stale line as a
    warning; the live authority is proven by the SSH connection itself."""
    return invitation.get("gateway", {}).get("pending_authorized_keys_line")


def _enroll_through_gateway(invitation: dict, *, identity_file: Path, known_hosts_file: Path) -> dict:
    """Run `rcn node setup` in-process. --start-gateway brings the SSH local
    forward up BEFORE the enrollment POST, so a member machine with no direct
    Control-Plane route can still enroll (documented member flow)."""
    from research_compute_network.cli import main as cli_main

    machine_id = invitation["machine_id"]
    gateway = invitation["gateway"]
    args = [
        "rcn", "node", "setup",
        "--url", f"http://127.0.0.1:{gateway['local_web_port']}",
        "--enrollment-code", invitation["enrollment_code"],
        "--machine-id", machine_id,
        "--owner-user-id", invitation["member"]["user_id"],
        "--ssh-host", gateway["center_host"],
        "--ssh-user", gateway["center_ssh_user"],
        "--ssh-port", str(gateway["center_ssh_port"]),
        "--identity-file", str(identity_file),
        "--known-hosts-file", str(known_hosts_file),
        "--central-web-port", str(gateway["central_web_port"]),
        "--local-web-port", str(gateway["local_web_port"]),
        "--start-gateway",
    ]
    if invitation.get("worker"):
        args.append("--worker")
    argv_backup = sys.argv
    sys.argv = args
    try:
        cli_main()
    finally:
        sys.argv = argv_backup
    return {"machine_id": machine_id}


def _write_welcome_note(state_root: Path, invitation: dict) -> Path:
    note = state_root / "WELCOME.txt"
    note.write_text(
        "Research Compute Network - welcome!\n\n"
        "Your login token (paste it on the page that just opened):\n"
        f"{invitation['member']['personal_token']}\n\n"
        "Keep this file private. Your administrator can revoke it and issue a new one.\n",
        encoding="utf-8",
    )
    return note


def run_wizard(
    *,
    invitation_path: Path,
    install_launcher: bool = True,
    install_startup: bool = False,
    open_browser: bool = False,
    expected_invitation_sha256: str | None = None,
) -> dict:
    if expected_invitation_sha256 is not None:
        from .member_registration import _read_bytes
        raw = _read_bytes(invitation_path)
    else:
        raw = invitation_path.read_bytes()
    if expected_invitation_sha256 is not None and hashlib.sha256(raw).hexdigest() != expected_invitation_sha256:
        raise WizardError('invitation_changed_after_confirmation')
    invitation = json.loads(raw)
    if invitation.get("schema_version") != WIZARD_SCHEMA:
        raise WizardError(
            f"unsupported invitation schema {invitation.get('schema_version')!r}; "
            "ask your administrator for a fresh invitation"
        )
    stale_authorization = _require_gateway_authorized(invitation)
    if stale_authorization:
        print(
            "NOTE: this invitation was generated before the center host "
            "authorized the gateway key. If enrollment fails with a "
            "permission error, send your administrator this line and rerun:\n"
            f"{stale_authorization}",
            flush=True,
        )
    steps: list[dict] = []

    from research_compute_network.node import (
        default_node_root,
        install_node_launcher,
        node_status,
        start_node_gateway,
        uninstall_node,
    )

    state_root = default_node_root()
    status = node_status(root=state_root)
    existing_config = None
    if status.get("configured"):
        try:
            existing_config = json.loads((state_root / "node.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise WizardError("the existing member-node state is unreadable; ask the administrator") from exc
    intended_owner = invitation["member"]["user_id"]
    intended_machine = invitation["machine_id"]
    same_identity = bool(existing_config) and (
        existing_config.get("owner_user_id") == intended_owner
        and existing_config.get("machine_id") == intended_machine
    )
    already_enrolled = same_identity and status.get("enrollment_state") in (
        "enrolled_paused",
        "enrolled_open",
    )
    if existing_config and not same_identity:
        existing_owner = existing_config.get("owner_user_id")
        if existing_owner != intended_owner:
            raise WizardError(
                "the existing member-node state belongs to another owner; "
                "refusing to replace it"
            )
        previous_machine = existing_config.get("machine_id")
        uninstall_node(root=state_root)
        steps.append({
            "step": "replace-superseded-node",
            "ok": True,
            "previous_machine_id": previous_machine,
            "machine_id": intended_machine,
        })
        status = node_status(root=state_root)
    steps.append({"step": "gateway-keys", "ok": True})

    if already_enrolled:
        # Idempotent rerun: never consume a second one-time code.
        steps.append({"step": "enroll", "ok": True, "skipped": "already enrolled"})
        key_path, known_path = _materialize_keys(invitation, state_root)
    else:
        key_path, known_path = _materialize_keys(invitation, state_root)
        steps.append({
            "step": "enroll",
            "ok": True,
            **_enroll_through_gateway(
                invitation, identity_file=key_path, known_hosts_file=known_path
            ),
        })

    gateway = start_node_gateway(root=state_root)
    steps.append({"step": "gateway", **gateway})

    if install_launcher:
        try:
            launcher = install_node_launcher(root=state_root)
            steps.append({"step": "launcher", "ok": True, **launcher})
        except FileExistsError as exc:
            # B0 friction fix: a pre-existing desktop shortcut must not fail the
            # whole setup after enrollment consumed the one-time code. On plain
            # member machines this branch never triggers.
            steps.append({
                "step": "launcher",
                "ok": True,
                "launcher_installed": False,
                "reason": str(exc),
                "hint": "an existing desktop icon was left untouched",
            })
    else:
        steps.append({"step": "launcher", "ok": True, "skipped": "member unchecked the desktop icon"})

    if install_startup:
        from research_compute_network.node import install_node_startup

        startup = install_node_startup(root=state_root)
        steps.append({"step": "startup-task", "ok": True, **startup})

    note = _write_welcome_note(state_root, invitation)
    steps.append({"step": "welcome-note", "ok": True, "path": str(note)})

    url = f"http://127.0.0.1:{invitation['gateway']['local_web_port']}/app/fleet"
    if open_browser:
        try:
            import webbrowser

            webbrowser.open(url, new=2)
            steps.append({"step": "browser", "ok": True, "url": url})
        except Exception as exc:  # pragma: no cover - browser is best effort
            steps.append({"step": "browser", "ok": False, "error": str(exc), "url": url})
    else:
        # Default OFF: automated runs and repeat invocations must not spam
        # browser tabs. The NSIS finish page (or the desktop icon) opens the
        # console exactly once, deliberately.
        steps.append({"step": "browser", "ok": True, "skipped": True, "url": url})

    return {"machine_id": invitation["machine_id"], "steps": steps}
