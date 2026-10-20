"""Member invitation packages: one command turns a user into a ready-to-run
invitation file so the member-side wizard needs zero technical input.

Security model (docs/security.md trusted-lab domain):
- The invitation file carries the member's gateway private key. The key is
  generated on the center host, stored ONLY in the invitation file, and its
  public half is installed on the center host restricted to
  ``restrict,port-forwarding,permitopen="127.0.0.1:<central-web-port>"`` so a
  leaked key can only open the console tunnel and is centrally revocable.
- The invitation file also carries the personal API token so the wizard can
  put it on the clipboard for the login page. Both secrets are revocable
  centrally without touching other members.
- The center host key is pinned via ``ssh-keyscan`` against the address the
  member will actually dial, so the strict host-key check on the member side
  is anchored to the key the center itself presents (no elevated filesystem
  access needed on the center host).
"""

from __future__ import annotations

import json
import secrets
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .models import UserRole
from .service import PACKAGE_VERSION, PROTOCOL_VERSION, NetworkService

GATEWAY_KEY_COMMENT_PREFIX = "rcn-member-gateway"
AUTHORIZED_KEYS_OPTIONS = "restrict,port-forwarding,permitopen"


class InvitationError(RuntimeError):
    """Raised when an invitation cannot be produced safely."""


def _ssh_keygen() -> str:
    ssh_keygen = shutil.which("ssh-keygen")
    if ssh_keygen is None:
        raise InvitationError("ssh-keygen is required on the center host to mint member keys")
    return ssh_keygen


def _host_public_key_line(center_host: str, port: int = 22) -> tuple[str, str]:
    """Return the pinned known_hosts line for the center host plus its
    fingerprint. The line comes from ``ssh-keyscan`` - the center's own
    presentation of its host key, which is exactly what the member's strict
    check will compare against - so this works without elevated filesystem
    access to C:/ProgramData/ssh."""
    keygen = _ssh_keygen()
    keyscan = shutil.which("ssh-keyscan")
    if keyscan is None:
        raise InvitationError("ssh-keyscan is required on the center host to pin its host key")
    scan = subprocess.run(
        [keyscan, "-p", str(port), "-t", "ed25519", center_host],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    line = next(
        (raw.strip() for raw in scan.stdout.splitlines() if raw.strip() and not raw.startswith("#")),
        None,
    )
    if not line or len(line.split()) < 3:
        raise InvitationError(f"ssh-keyscan returned no host key for {center_host}:{port}")
    with tempfile.TemporaryDirectory(prefix="rcn-invitation-") as temporary:
        pin = Path(temporary) / "known_hosts"
        pin.write_text(line + "\n", encoding="ascii")
        fingerprint = subprocess.run(
            [keygen, "-lf", str(pin)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    return line, fingerprint


def _install_restricted_public_key(
    public_key_line: str,
    *,
    central_web_port: int,
    authorized_keys_file: Path | None = None,
) -> dict:
    """Append the restricted gateway public key to the center's authorized keys.

    The file is administrator-managed on Windows OpenSSH; when this function
    cannot write it (non-elevated process), it returns the exact line plus the
    target path so the administrator can add it with one elevated command.
    """
    target = authorized_keys_file or Path("C:/ProgramData/ssh/administrators_authorized_keys")
    restricted = f'{AUTHORIZED_KEYS_OPTIONS}="127.0.0.1:{central_web_port}" {public_key_line}'
    installed = False
    try:
        existing = target.read_text(encoding="utf-8") if target.is_file() else ""
        if public_key_line.split(" ", 1)[1] in existing:
            installed = True
        else:
            with target.open("a", encoding="utf-8") as handle:
                handle.write(restricted + "\n")
            installed = True
    except PermissionError:
        installed = False
    return {
        "installed": installed,
        "restricted_line": restricted,
        "authorized_keys_file": str(target),
    }


def generate_member_invitation(
    repository,
    *,
    user_id: str,
    actor_id: str,
    center_host: str,
    center_ssh_user: str,
    machine_id: str | None = None,
    worker: bool = False,
    central_web_port: int = 8765,
    coordinator_ssh_port: int = 22,
    local_web_port: int = 18765,
    display_name: str | None = None,
    ttl_minutes: int = 60,
    output: Path | None = None,
    authorized_keys_file: Path | None = None,
    host_key_line: str | None = None,
) -> dict:
    """Create or update the member user, mint secrets, install the restricted
    gateway public key on the center host, and write the invitation payload.

    ``host_key_line`` overrides the ssh-keyscan pin (used by tests against
    unroutable addresses); production leaves it unset.
    """
    if not center_host.strip() or not center_ssh_user.strip():
        raise InvitationError("center host and center SSH user are required")
    user = repository.get_user(user_id)
    if user is None:
        raise InvitationError(
            f"user {user_id!r} does not exist; create it with `rcn create-user` first"
        )
    if not user.active:
        raise InvitationError(f"user {user_id!r} is not active")
    if worker and UserRole.MACHINE_OWNER not in user.roles:
        raise InvitationError(
            "worker invitations require the machine_owner role; "
            f"add it with `rcn create-user {user_id} --roles member machine_owner`"
        )

    service = NetworkService(repository)
    token = service.issue_token(user_id, actor_id=actor_id)
    enrollment = service.issue_enrollment(user_id, actor_id=actor_id, ttl_minutes=ttl_minutes)

    keygen = _ssh_keygen()
    key_comment = f"{GATEWAY_KEY_COMMENT_PREFIX}:{user_id}"
    key_dir = Path(output).parent if output else Path.cwd()
    key_dir.mkdir(parents=True, exist_ok=True)
    key_path = key_dir / f"gateway-key-{user_id}"
    for stale in (key_path, key_path.with_suffix(".pub")):
        stale.unlink(missing_ok=True)
    subprocess.run(
        [keygen, "-t", "ed25519", "-N", "", "-C", key_comment, "-f", str(key_path), "-q"],
        check=True,
    )
    public_key_line = key_path.with_suffix(".pub").read_text(encoding="ascii").strip()
    key_body = public_key_line.split(" ", 1)[1]
    installation = _install_restricted_public_key(
        public_key_line,
        central_web_port=central_web_port,
        authorized_keys_file=authorized_keys_file,
    )
    if host_key_line:
        pinned_line = host_key_line
        with tempfile.TemporaryDirectory(prefix="rcn-invitation-") as temporary:
            pin = Path(temporary) / "known_hosts"
            pin.write_text(pinned_line + "\n", encoding="ascii")
            host_fingerprint = subprocess.run(
                [keygen, "-lf", str(pin)], check=True, capture_output=True, text=True
            ).stdout.strip()
    else:
        pinned_line, host_fingerprint = _host_public_key_line(
            center_host, port=coordinator_ssh_port
        )

    invitation = {
        "schema_version": 1,
        "package_version": PACKAGE_VERSION,
        "protocol_version": PROTOCOL_VERSION,
        "member": {
            "user_id": user_id,
            "display_name": display_name or user.display_name,
            "personal_token": token.token,
            "token_id": token.token_id,
        },
        "enrollment_code": enrollment.enrollment_code,
        "enrollment_expires_at": enrollment.expires_at.isoformat(),
        "machine_id": machine_id
        or f"MEMBER-{user_id}-{secrets.token_hex(2).upper()}",
        "worker": worker,
        "gateway": {
            "center_host": center_host,
            "center_ssh_port": coordinator_ssh_port,
            "center_ssh_user": center_ssh_user,
            "central_web_port": central_web_port,
            "local_web_port": local_web_port,
            "private_key": key_path.read_text(encoding="ascii"),
            "known_hosts_line": pinned_line,
            "host_key_fingerprint": host_fingerprint,
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    if not installation["installed"]:
        invitation["gateway"]["pending_authorized_keys_line"] = installation["restricted_line"]
        invitation["gateway"]["authorized_keys_file"] = installation["authorized_keys_file"]

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(invitation, indent=2) + "\n", encoding="utf-8")

    # The private key material lives only in the invitation payload; remove the
    # intermediate files so no second copy lingers on the center host.
    key_path.unlink(missing_ok=True)
    key_path.with_suffix(".pub").unlink(missing_ok=True)

    return {
        "invitation_file": str(output) if output is not None else None,
        "machine_id": invitation["machine_id"],
        "token_id": token.token_id,
        "enrollment_id": enrollment.enrollment_id,
        "enrollment_expires_at": invitation["enrollment_expires_at"],
        "host_key_fingerprint": host_fingerprint,
        "authorized_keys_installed": installation["installed"],
        "authorized_keys_manual_step": None
        if installation["installed"]
        else installation["restricted_line"],
    }
