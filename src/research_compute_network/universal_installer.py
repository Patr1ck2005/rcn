"""One public Setup.exe per reviewed release; invitations remain external.

This bridge reuses the existing enrollment wizard and deliberately does not
turn successful gateway registration into Worker acceptance or authorization.
No user, machine, token, private key or invitation is a build-time parameter.
"""
from __future__ import annotations

from email.parser import BytesParser
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tempfile
import zipfile

from .member_installer import EMBEDDABLE_ZIP, RUNTIME_DIR, WHEELHOUSE_DIRNAME, _makensis, render_nsis
from .universal_installer_flow import INVITATION_PAGE, INVITATION_PROBE, adapt_setup_flow


_PUBLIC_NOTICE = """Research Compute Network - universal member installer

This program contains release software, not your invitation or credentials.
The same reviewed Setup.exe may be shared with other invited members.
Obtain the release and SHA-256 from a trusted administrator. This preview is
not organization code-signed. Do not disable antivirus or system protections.

Your invitation is separate and private. Select the invitation file sent by
your administrator during installation; never post that file in a group.
V2 registration submits device name, CPU and memory to the invitation's HTTPS
center and saves a private device identity locally. Workers additionally create
an SSH key locally and submit only its public key and proof of possession.
Private keys stay on the member computer. A new protected Worker directory is
prepared with the same identity and heartbeat references; its location is registered
with the center. A restricted reverse relay is requested under the center's approved
policy and its pinned configuration is prepared locally. Existing compute directories
are never taken over. No local SSH service or task is started and no computation is granted. Uninstalling preserves
both identity and Worker data;
device retirement must be confirmed with the administrator.
Silent registration requires /ACCEPTREGISTRATION=1 as explicit consent.
Interactive Workers separately choose project-scoped compute consent, resource limits
and weekly availability. Cancelling keeps the machine paused. Silent registration
never assumes compute consent; it must be given in the member configuration flow.
Registration remains subject to machine acceptance and approval checks.
"""

def _replace(text: str, old: str, new: str, count: int = 1) -> str:
    if text.count(old) != count:
        raise ValueError("legacy installer template changed; universal adaptation needs review")
    return text.replace(old, new)


def render_universal_nsis(*, wheel_name: str, package_version: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.+-]*\.whl", wheel_name):
        raise ValueError("invalid release wheel filename")
    if not re.fullmatch(r"[0-9][A-Za-z0-9_.+!-]{0,100}", package_version):
        raise ValueError("invalid release version")
    text = render_nsis(invitation={"member": {"user_id": "public-release"}}, wheel_name=wheel_name,
                       product_name="Research Compute Network")
    text = _replace(text, '!include "LogicLib.nsh"', '!include "LogicLib.nsh"\n!include "FileFunc.nsh"\n!include "nsDialogs.nsh"')
    text = _replace(text, '!insertmacro MUI_PAGE_COMPONENTS', 'Page custom InvitationPage InvitationLeave\n!insertmacro MUI_PAGE_COMPONENTS')
    text = _replace(text, '  File "invitation.json"', '  ; Invitation is selected at runtime and is never embedded or copied here.')
    text = _replace(text, '"' + RUNTIME_DIR + r'\invitation.json"', '"$InvitationPath"', 4)
    text = _replace(text, '"DisplayVersion" "0.13.3"', '"DisplayVersion" "' + package_version + '"')
    text = _replace(text,
        "  Exec '\"$SYSDIR\\rundll32.exe\" url.dll,FileProtocolHandler http://127.0.0.1:18765/app/fleet'",
        "  Exec '\"" + RUNTIME_DIR + "\\python\\python.exe\" -m research_compute_network.cli node open'")
    # Put global variables before their references in Sections.
    text = _replace(text, '; ---------------- core (always installed) ----------------',
                    INVITATION_PAGE + '\n; ---------------- core (always installed) ----------------')
    text = adapt_setup_flow(text, _replace)
    if 'File "invitation.json"' in text or 'public-release' in text:
        raise ValueError("universal template retained personalized input")
    return text


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def _regular(path: Path) -> None:
    # Never follow reparse/symlink input trees into another credential location.
    for item in (path, *path.parents):
        info = item.lstat()
        if item.is_symlink() or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError("linked build input or output path is not allowed")
    if not path.is_file():
        raise ValueError("build input is not a regular file")


def _validate_archive_paths(archive: zipfile.ZipFile) -> None:
    seen: set[str] = set()
    for info in archive.infolist():
        # ZipInfo normalizes separators and truncates NULs on Windows. Inspect
        # the original central-directory name before accepting that conversion.
        name = info.orig_filename
        parts = PurePosixPath(name).parts
        folded = name.rstrip('/').casefold()
        if (not parts or name.startswith('/') or '..' in parts or '\\' in name or '\0' in name
                or any(':' in part or part.endswith((' ', '.')) for part in parts)
                or folded in seen or (info.external_attr >> 16) & 0o170000 == 0o120000):
            raise ValueError("archive contains an unsafe, linked or duplicate path")
        seen.add(folded)


def _wheel_identity(path: Path) -> tuple[str, str]:
    _regular(path)
    with zipfile.ZipFile(path) as archive:
        _validate_archive_paths(archive)
        names = archive.namelist()
        # pip/setuptools ship nested vendored dist-info metadata. Only the
        # wheel's top-level distribution record establishes its own identity.
        metadata = [name for name in names if name.endswith('.dist-info/METADATA')
                    and len(PurePosixPath(name).parts) == 2]
        if len(metadata) != 1:
            raise ValueError("wheel must contain one METADATA record")
        info = archive.getinfo(metadata[0])
        if info.file_size > 1024 * 1024:
            raise ValueError("wheel metadata exceeds bound")
        for name in names:
            parts = PurePosixPath(name).parts
            if name.startswith('/') or '..' in parts or '\\' in name or any(':' in part for part in parts):
                raise ValueError("wheel contains an unsafe path")
            leaf = parts[-1].lower() if parts else ''
            if leaf in {'invitation.json', 'node.json', 'gateway-key', '.env', 'id_rsa', 'id_ed25519'}:
                raise ValueError("wheel contains a forbidden credential-state filename")
        parsed = BytesParser().parsebytes(archive.read(info))
        name, version = str(parsed.get('Name', '')), str(parsed.get('Version', ''))
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', name) or not version:
            raise ValueError("wheel identity is missing or invalid")
        return re.sub(r'[-_.]+', '-', name).lower(), version


def _require_setup_support(path: Path) -> None:
    # Presence/entry checks catch an older wheel paired with the new wizard; they
    # are not proof of code trust. The reviewed release digest remains required.
    with zipfile.ZipFile(path) as archive:
        for name in ('member_setup.py', 'member_registration.py', 'member_enrollment.py', 'invitation_wizard.py',
                     'member_transport_client.py', 'member_transport.py', 'ssh_identity.py',
                     'member_worker_root.py', 'member_worker_root_contract.py',
                     'member_relay.py', 'member_relay_client.py', 'member_relay_policy.py', 'member_relay_keys.py',
                     'member_admission.py', 'member_admission_contract.py', 'member_admission_invitation.py',
                     'member_admission_client.py', 'member_compute_dialog.py'):
            if 'research_compute_network/' + name not in archive.namelist():
                raise ValueError('release wheel lacks universal setup support')
        info = archive.getinfo('research_compute_network/cli.py')
        if info.file_size > 1048576 or b'"member-setup"' not in archive.read(info):
            raise ValueError('release wheel lacks member-setup CLI entry')


def build_universal_installer(
    *,
    wheel_path: Path,
    wheelhouse_dir: Path,
    embeddable_zip: Path,
    output_exe: Path,
    expected_wheel_sha256: str,
    makensis: str | None = None,
    sealed_runtime: Path | None = None,
    member_ssh: bool = False,
) -> dict:
    """Compile once from a reviewed wheel, without contacting any control plane.

    Explicit hashes and a public input manifest are provenance, not a code
    signature. Build from a reviewed snapshot; dependency trust is a release
    responsibility and filename checks are not a complete secret scanner.
    """
    if type(member_ssh) is not bool or (member_ssh and sealed_runtime is None):
        raise ValueError('member SSH connection variant requires sealed runtime')
    probe = INVITATION_PROBE
    wheel_path, wheelhouse_dir, embeddable_zip, output_exe = [Path(p).absolute() for p in
        (wheel_path, wheelhouse_dir, embeddable_zip, output_exe)]
    if not re.fullmatch(r'[0-9a-f]{64}', expected_wheel_sha256):
        raise ValueError("an explicit reviewed wheel SHA-256 is required")
    name, version = _wheel_identity(wheel_path)
    if name != 'research-compute-network' or _sha(wheel_path) != expected_wheel_sha256:
        raise ValueError("release wheel identity or SHA-256 mismatch")
    _require_setup_support(wheel_path)
    script = render_universal_nsis(wheel_name=wheel_path.name, package_version=version)
    if sealed_runtime is not None:
        from .member_runtime import approved_runtime
        from .universal_runtime_flow import add_runtime_flow, require_runtime_support
        sealed_runtime = Path(sealed_runtime).absolute()
        approved_runtime(sealed_runtime)
        require_runtime_support(wheel_path)
        script = add_runtime_flow(script, _replace)
    if member_ssh:
        from .universal_ssh_flow import add_connection_flow, require_connection_support
        require_connection_support(wheel_path)
        script, probe = add_connection_flow(script, probe, _replace)
    _regular(embeddable_zip)
    if not zipfile.is_zipfile(embeddable_zip):
        raise ValueError("Python embeddable input is not a ZIP")
    with zipfile.ZipFile(embeddable_zip) as archive:
        _validate_archive_paths(archive)
        if not {'python.exe', 'python311._pth'}.issubset(archive.namelist()):
            raise ValueError("Python embeddable archive is incomplete")
        if sealed_runtime is not None and 'pythonw.exe' not in archive.namelist():
            raise ValueError('worker supervision requires embedded pythonw.exe')
    sources = {wheel_path.name: wheel_path, EMBEDDABLE_ZIP: embeddable_zip}
    if sealed_runtime is not None:
        from .universal_runtime_flow import RUNTIME_NAME
        sources[RUNTIME_NAME] = sealed_runtime
    distributions = {'research-compute-network'}
    for dependency in sorted(wheelhouse_dir.glob('*.whl')):
        dist, _ = _wheel_identity(dependency)
        if dist == 'research-compute-network':
            continue  # The hash-reviewed selected wheel is the sole authority.
        if dist in distributions:
            raise ValueError("ambiguous duplicate dependency distribution")
        distributions.add(dist)
        if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.+-]*\.whl', dependency.name):
            raise ValueError("invalid dependency filename")
        sources[dependency.name] = dependency
    bootstrap = wheelhouse_dir / 'get-pip.py'
    _regular(bootstrap)
    sources['get-pip.py'] = bootstrap
    input_hashes = {filename: _sha(path) for filename, path in sources.items()}
    if sealed_runtime is not None:
        from .member_runtime import APPROVED_ARCHIVE_SHA256
        if input_hashes[RUNTIME_NAME] != APPROVED_ARCHIVE_SHA256:
            raise ValueError('approved sealed runtime changed during preparation')
    if input_hashes[wheel_path.name] != expected_wheel_sha256:
        raise ValueError("reviewed release wheel changed during preparation")
    if output_exe.suffix.lower() != '.exe':
        raise ValueError("installer destination must end in .exe")
    if output_exe.exists() or output_exe.is_symlink():
        raise FileExistsError("refusing to replace an existing installer")
    # Check existing ancestors before creating directories through them.
    for parent in (output_exe.parent, *output_exe.parent.parents):
        if not parent.exists() and not parent.is_symlink():
            continue
        stat = parent.lstat()
        if parent.is_symlink() or getattr(stat, 'st_file_attributes', 0) & 0x400:
            raise ValueError("linked output directory is not allowed")
    output_exe.parent.mkdir(parents=True, exist_ok=True)
    compiler = makensis or _makensis()
    with tempfile.TemporaryDirectory(prefix='rcn-universal-', dir=output_exe.parent) as temporary:
        stage = Path(temporary)
        payload = stage / WHEELHOUSE_DIRNAME
        payload.mkdir()
        for filename, source in sources.items():
            shutil.copyfile(source, payload / filename)
            if _sha(payload / filename) != input_hashes[filename]:
                raise ValueError("build input changed while being copied")
        manifest = {'schema_version': 1, 'kind': 'universal-member-installer', 'package_version': version,
                    'invitation_mode': 'external-private-file', 'supported_invitation_schemas': [1, 2],
                    'worker_admission': 'paused-pending-acceptance',
                    # Retain the legacy label for existing installer readers;
                    # v2 governance is explicit rather than falsely requiring
                    # full scientific PASS before every trust-first admission.
                    'worker_admission_by_policy': {
                        'trust_first': 'identity-consent-runtime-ready-then-async-audit',
                        'legacy_or_acceptance_required': 'paused-pending-acceptance'},
                    'package_kind': 'public-universal-member-installer',
                    'contains_personal_invitation': False,
                    'contains_production_state': False,
                    'inputs_sha256': input_hashes}
        if member_ssh:
            manifest['member_connection_mode'] = 'standard-local-user-v1'
            manifest['openssh_component_supply'] = 'windows-fod-v1'
        (stage / 'public-release-manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
        script = _replace(script, '  ; Invitation is selected at runtime and is never embedded or copied here.',
                          '  File "public-release-manifest.json"\n  ; No invitation or user credential in the release.')
        if sealed_runtime is not None:
            from .universal_runtime_flow import preserve_running_runtime
            script = preserve_running_runtime(script, _replace, _sha(stage/'public-release-manifest.json'))
        (stage / 'inspect-invitation.ps1').write_text(probe, encoding='utf-8-sig')
        notice = _PUBLIC_NOTICE
        if sealed_runtime is not None:
            notice = notice.replace('No local SSH service or task is started and no computation is granted.',
                'The sealed supervisor is installed and started as a zero-capacity current-user logon task. '
                'It has a one-minute watchdog and sends authenticated independent heartbeat. '
                'Silent startup additionally requires /ACCEPTSUPERVISOR=1; registration consent alone does not start it. '
                'No local SSH service is installed and no computation is granted.')
        if member_ssh:
            notice = notice.replace('No local SSH service is installed and no computation is granted.',
                'Interactive Worker setup requires a standard local account. Missing OpenSSH components are supplied '
                'by Windows Update/WSUS with visible UAC, no reboot and no modification of pre-existing SSH services/rules. '
                'Only an exactly verified new default SSH allow rule is disabled. '
                'It explicitly installs a dedicated loopback SSH service with visible UAC, starts user transport tasks, '
                'and requests center acceptance. Silent setup does not install SSH. No computation is granted.')
        (stage / 'publisher-notice.txt').write_text(notice, encoding='utf-8-sig')
        script_path = stage / 'installer.nsi'
        script_path.write_text(script, encoding='utf-8-sig')
        completed = subprocess.run([compiler, '/NOCONFIG', '/V2', str(script_path)], cwd=stage,
                                   capture_output=True, text=True, timeout=600, check=False)
        if completed.returncode != 0:
            raise RuntimeError(f"universal NSIS compilation failed ({completed.returncode}): {completed.stdout}\n{completed.stderr}")
        built = stage / '__setup__.exe'
        if not built.is_file() or built.stat().st_size == 0:
            raise RuntimeError("compiler produced no non-empty installer")
        # Atomic no-clobber publication from a closed file on the same volume.
        # A competing output creation is never silently overwritten.
        os.link(built, output_exe)
        digest = _sha(output_exe)
    return {'installer_path': str(output_exe), 'sha256': digest, 'size_bytes': output_exe.stat().st_size,
            'package_version': version, 'invitation_mode': 'external-private-file',
            'contains_embedded_invitation': False, 'worker_admission': 'paused-pending-acceptance',
            'release_manifest': manifest}
