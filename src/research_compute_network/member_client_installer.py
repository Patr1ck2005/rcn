"""Public, invitation-free member desktop installer with an offline closure.

The dependency environment is assembled and exercised before NSIS compilation.
Members unpack the same verified snapshot; installation never runs pip online.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager, ExitStack
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tempfile
import zipfile

from .member_installer import _makensis
from .universal_installer import _regular, _validate_archive_paths, _wheel_identity, _sha
from .member_release_catalog import PUBLIC_RELEASE


NSIS = r'''!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"
Unicode true
Name "Research Compute Network 成员客户端"
OutFile "__setup__.exe"
InstallDir "$LOCALAPPDATA\ResearchComputeNetwork\member-software"
RequestExecutionLevel user
SetCompressor /SOLID lzma
ShowInstDetails show
Var TestState
Var EntryOptions
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "notice.txt"
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_TEXT "打开成员客户端"
!define MUI_FINISHPAGE_RUN_FUNCTION OpenMember
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "SimpChinese"
Function .onInit
  StrCpy $EntryOptions ""
  ${GetParameters} $0
  ${GetOptions} $0 "/TESTSTATE=" $TestState
  ${If} $TestState != ""
    StrCpy $EntryOptions '--state-root "$TestState" --no-desktop --no-startup'
  ${EndIf}
FunctionEnd
Section "成员客户端" Core
  InitPluginsDir
  SetOutPath "$PLUGINSDIR"
  File "member-runtime.zip"
  CreateDirectory "$INSTDIR\@ID@"
  ; Interrupted extraction may resume this same content-addressed version.
  nsExec::ExecToLog '"$SYSDIR\tar.exe" -xf "$PLUGINSDIR\member-runtime.zip" -C "$INSTDIR\@ID@"'
  Pop $0
  ${If} $0 != 0
    Abort "运行环境解压未完成；请重新运行原安装包。"
  ${EndIf}
  nsExec::ExecToLog '"$INSTDIR\@ID@\runtime\python\python.exe" -B -m research_compute_network.member_client_installer verify --release-root "$INSTDIR\@ID@" --expected-payload-id "@ID@"'
  Pop $0
  ${If} $0 != 0
    Abort "安装文件校验失败。"
  ${EndIf}
  nsExec::ExecToLog '"$INSTDIR\@ID@\runtime\python\python.exe" -B -m research_compute_network.member_client_lifecycle install-entry $EntryOptions'
  Pop $0
  ${If} $0 != 0
    Abort "客户端入口尚未完成；原身份和结果将保留。"
  ${EndIf}
  ${If} $TestState == ""
    WriteUninstaller "$INSTDIR\@ID@\uninstall.exe"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\RCN-MemberClient" "DisplayName" "Research Compute Network 成员客户端"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\RCN-MemberClient" "DisplayVersion" "@VERSION@"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\RCN-MemberClient" "UninstallString" '"$INSTDIR\@ID@\uninstall.exe"'
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\RCN-MemberClient" "InstallLocation" "$INSTDIR\@ID@"
  ${EndIf}
SectionEnd
Function OpenMember
  Exec '"$INSTDIR\@ID@\runtime\python\pythonw.exe" -B -m research_compute_network.member_client_lifecycle launch $EntryOptions'
FunctionEnd
Section "Uninstall"
  nsExec::ExecToLog '"$INSTDIR\runtime\python\python.exe" -B -m research_compute_network.member_client_lifecycle uninstall'
  Pop $0
  ${If} $0 != 0
    Abort "正在排空计算或传输；请保留此安装并稍后重试卸载。"
  ${EndIf}
  ; This uninstaller belongs to one version directory. Never remove the
  ; member-client state, another version, worker results or registration.
  nsExec::ExecToLog '"$INSTDIR\runtime\python\python.exe" -B -m research_compute_network.member_client_installer verify --release-root "$INSTDIR" --expected-payload-id "@ID@"'
  Pop $0
  ${If} $0 != 0
    Abort "软件目录身份无法确认；保留文件。"
  ${EndIf}
  ReadRegStr $0 HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\RCN-MemberClient" "InstallLocation"
  ${If} $0 == $INSTDIR
    DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\RCN-MemberClient"
  ${EndIf}
  RMDir /r "$INSTDIR\runtime"
  Delete "$INSTDIR\member-software-release.json"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
SectionEnd
'''


if os.name == "nt":
    import ctypes
    from ctypes import wintypes
    import msvcrt

    _snapshot_kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    _snapshot_create_file = _snapshot_kernel.CreateFileW
    _snapshot_create_file.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    _snapshot_create_file.restype = wintypes.HANDLE
    _snapshot_close_handle = _snapshot_kernel.CloseHandle
    _snapshot_close_handle.argtypes = [wintypes.HANDLE]


def _snapshot_info_valid(info, *, directory, entry=False):
    if (getattr(info, "st_file_attributes", 0) & 0x400 or stat.S_ISLNK(info.st_mode)
            or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            or (not directory and not entry and info.st_nlink != 1)):
        raise ValueError("member_software_linked_directory")


def _snapshot_identity(info):
    return info.st_dev, info.st_ino


@contextmanager
def _snapshot_open(path, *, directory=False, parent_fd=None, validate_entries=False):
    """Pin an object while checking it; never hash through a replaced parent.

    Windows handles deny writes/deletes for their lifetime. POSIX children are
    opened relative to the pinned parent descriptor with O_NOFOLLOW.
    """
    name = path if os.name == "nt" or parent_fd is None else path.name
    before = os.stat(name, dir_fd=parent_fd if os.name != "nt" else None, follow_symlinks=False)
    _snapshot_info_valid(before, directory=directory)
    if os.name == "nt":
        handle = _snapshot_create_file(str(path), 0x80000000, 1, None, 3,
            0x00200000 | (0x02000000 if directory else 0), None)
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
        except BaseException:
            _snapshot_close_handle(handle)
            raise
    else:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | (os.O_DIRECTORY if directory else 0),
            dir_fd=parent_fd)
    try:
        opened = os.fstat(descriptor)
        _snapshot_info_valid(opened, directory=directory)
        if _snapshot_identity(opened) != _snapshot_identity(before):
            raise ValueError("member_software_files_changed")
        yield descriptor, opened
        after = os.stat(name, dir_fd=parent_fd if os.name != "nt" else None, follow_symlinks=False)
        _snapshot_info_valid(after, directory=directory)
        if (_snapshot_identity(after) != _snapshot_identity(opened)
                or (not directory and (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                    != (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns))
                or (validate_entries and (after.st_mtime_ns, after.st_ctime_ns)
                    != (opened.st_mtime_ns, opened.st_ctime_ns))):
            raise ValueError("member_software_files_changed")
    finally:
        os.close(descriptor)


def _snapshot_hash(descriptor, before):
    digest, size = hashlib.sha256(), 0
    with os.fdopen(os.dup(descriptor), "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(block)
            digest.update(block)
    after = os.fstat(descriptor)
    if (size != before.st_size or (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            != (before.st_size, before.st_mtime_ns, before.st_ctime_ns)):
        raise ValueError("member_software_files_changed")
    return digest.hexdigest()


def verify_snapshot(root, *, expected_payload_id=None):
    root = Path(root).absolute()
    actual = {}
    # Ancestors are checked/pinned once per call, rather than once per file.
    # Retain all handles until the complete manifest has been checked.
    with ExitStack() as stack:
        parent_fd = None
        for directory in (*reversed(root.parents), root):
            parent_fd, _ = stack.enter_context(_snapshot_open(directory, directory=True, parent_fd=parent_fd))
        manifest_fd, manifest_info = stack.enter_context(_snapshot_open(root / "member-software-release.json", parent_fd=parent_fd))
        if manifest_info.st_size > 16 * 1024 * 1024:
            raise ValueError("member_software_manifest_invalid")
        with os.fdopen(os.dup(manifest_fd), "r", encoding="utf-8") as stream:
            manifest = json.load(stream)
        if expected_payload_id is not None and (root.name != expected_payload_id or manifest["payload_id"] != expected_payload_id):
            raise ValueError("member_software_directory_identity_changed")
        runtime = root / "runtime"
        expected = manifest["runtime_files"]
        if not isinstance(expected, dict):
            raise ValueError("member_software_manifest_invalid")
        expected_directories = set()
        for name, digest in expected.items():
            if not isinstance(name, str):
                raise ValueError("member_software_manifest_invalid")
            relative = PurePosixPath(name)
            if (not relative.parts or relative.as_posix() != name or relative.is_absolute()
                    or any(part in {"..", "."} or ":" in part or "\\" in part for part in relative.parts)
                    or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)):
                raise ValueError("member_software_manifest_invalid")
            expected_directories.update(parent.as_posix() for parent in relative.parents if parent != PurePosixPath("."))

        def inventory(directory, descriptor, before):
            with os.scandir(directory if os.name == "nt" else descriptor) as entries:
                for entry in entries:
                    path = directory / entry.name
                    info = entry.stat(follow_symlinks=False)
                    is_directory = stat.S_ISDIR(info.st_mode)
                    # Windows FindFirstFile data has no link count/identity;
                    # the pinned handle below supplies both authoritatively.
                    _snapshot_info_valid(info, directory=is_directory, entry=True)
                    relative = path.relative_to(runtime).as_posix()
                    if relative not in (expected_directories if is_directory else expected):
                        raise ValueError("member_software_files_changed")
                    child_fd, opened = stack.enter_context(_snapshot_open(path, directory=is_directory,
                        parent_fd=descriptor, validate_entries=is_directory))
                    if is_directory:
                        inventory(path, child_fd, opened)
                    else:
                        actual[relative] = _snapshot_hash(child_fd, opened)
            after = os.fstat(descriptor)
            if (after.st_mtime_ns, after.st_ctime_ns) != (before.st_mtime_ns, before.st_ctime_ns):
                raise ValueError("member_software_files_changed")

        runtime_fd, runtime_info = stack.enter_context(_snapshot_open(runtime, directory=True,
            parent_fd=parent_fd, validate_entries=True))
        inventory(runtime, runtime_fd, runtime_info)
        if actual != expected:
            raise ValueError("member_software_files_changed")
        if manifest["payload_id"] != "member-" + hashlib.sha256(json.dumps(actual, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:24]:
            raise ValueError("member_software_identity_changed")
        release = PUBLIC_RELEASE
        if manifest["member_runtime"] != {"runtime_version": release.runtime_version, "archive_sha256": release.archive_sha256}:
            raise ValueError("member_software_runtime_catalog_changed")
        return manifest


def build_member_client_installer(*, wheel_path, wheelhouse_dir, embeddable_zip, output_exe,
                                  expected_wheel_sha256, makensis=None):
    wheel_path, wheelhouse_dir, embeddable_zip, output_exe = map(lambda value: Path(value).absolute(),
        (wheel_path, wheelhouse_dir, embeddable_zip, output_exe))
    name, version = _wheel_identity(wheel_path)
    if name != "research-compute-network" or _sha(wheel_path) != expected_wheel_sha256:
        raise ValueError("member_installer_wheel_identity_changed")
    if output_exe.exists():
        raise FileExistsError("member_installer_output_exists")
    _regular(embeddable_zip)
    with zipfile.ZipFile(embeddable_zip) as archive:
        _validate_archive_paths(archive)
        if not {"python.exe", "pythonw.exe", "python311._pth"}.issubset(archive.namelist()):
            raise ValueError("member_embedded_python_incomplete")
    inputs = {wheel_path.name: _sha(wheel_path), embeddable_zip.name: _sha(embeddable_zip)}
    distributions = {}
    for path in sorted(wheelhouse_dir.glob("*.whl")):
        dist, _ = _wheel_identity(path)
        if dist == "research-compute-network":
            continue
        if dist in distributions:
            raise ValueError("member_dependency_distribution_ambiguous")
        distributions[dist] = path
        inputs[path.name] = _sha(path)
    required = {"pip", "setuptools", "wheel", "greenlet"}
    if required - distributions.keys():
        raise ValueError("member_offline_closure_missing")
    bootstrap = wheelhouse_dir / "get-pip.py"
    _regular(bootstrap)
    inputs["get-pip.py"] = _sha(bootstrap)
    output_exe.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="rcn-member-installer-") as temporary:
        stage = Path(temporary)
        release_root = stage / "release"
        python = release_root / "runtime/python"
        python.mkdir(parents=True)
        with zipfile.ZipFile(embeddable_zip) as archive:
            archive.extractall(python)
        runtime = release_root / "runtime"
        successor = PUBLIC_RELEASE
        # Public client has no science runtime and never searches user packages.
        (python / "python311._pth").write_text("python311.zip\n.\nLib/site-packages\n", encoding="utf-8")
        interpreter = python / "python.exe"
        env = {**__import__("os").environ, "PIP_NO_INDEX": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PYTHONDONTWRITEBYTECODE": "1"}
        def run(args):
            result = subprocess.run([str(interpreter), "-B", *args], capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=300, env=env)
            if result.returncode:
                raise RuntimeError("member_offline_runtime_validation_failed: " + result.stdout[-2000:] + result.stderr[-2000:])
            return result.stdout
        run([str(bootstrap), "--no-index", "--find-links", str(wheelhouse_dir), "--no-warn-script-location"])
        run(["-m", "pip", "install", "--no-index", "--find-links", str(wheelhouse_dir), "--no-compile", str(wheel_path)])
        run(["-m", "pip", "check"])
        probe = run(["-c", "import json,sys;from pathlib import Path;import fastapi,sqlalchemy,greenlet;from research_compute_network.member_client import create_member_app;root=Path(sys.executable).parent;modules=[fastapi,sqlalchemy,greenlet];assert sys.flags.no_site and all(Path(x.__file__).resolve().is_relative_to(root) for x in modules),'dependency escaped offline closure';print(json.dumps({'module_paths':{x.__name__:Path(x.__file__).relative_to(root).as_posix() for x in modules},'no_user_site':True,'distribution':'public-client-only'}))"])
        validation = json.loads(probe.strip().splitlines()[-1])
        module_paths = validation.get("module_paths", {})
        if (validation.get("no_user_site") is not True or not isinstance(module_paths, dict)
                or set(module_paths) != {"fastapi", "sqlalchemy", "greenlet"}
                or any(not isinstance(value, str) or not value.startswith("Lib/site-packages/")
                       or PurePosixPath(value).as_posix() != value or ".." in PurePosixPath(value).parts
                       or "\\" in value or ":" in value for value in module_paths.values())):
            raise RuntimeError("member_offline_runtime_provenance_failed")
        if any(path.suffix.lower() in {".mph", ".zip"} for path in (python / "Lib/site-packages/research_compute_network").rglob("*")):
            raise ValueError("public_client_contains_scientific_asset")
        files = {path.relative_to(runtime).as_posix(): _sha(path) for path in sorted(runtime.rglob("*")) if path.is_file()}
        payload_id = "member-" + hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:24]
        manifest = {"schema_version": 1, "kind": "rcn-public-member-client-v1", "payload_id": payload_id,
            "package_version": version, "wheel_sha256": expected_wheel_sha256, "inputs": inputs,
            "runtime_files": files, "member_runtime": {"runtime_version": successor.runtime_version, "archive_sha256": successor.archive_sha256},
            "offline_validation": validation, "scientific_acceptance": "external-operator-runtime-not-included",
            "production_ready": False, "signature_kind": "unsigned-content-integrity"}
        (release_root / "member-software-release.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        verify_snapshot(release_root)
        with zipfile.ZipFile(stage / "member-runtime.zip", "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            for path in sorted(release_root.rglob("*")):
                if path.is_file():
                    archive.write(path, path.relative_to(release_root).as_posix())
        # Also deliver the exact raw snapshot for independent/offline acceptance.
        shutil.copy2(stage / "member-runtime.zip", output_exe.with_suffix(".runtime.zip"))
        (stage / "notice.txt").write_text("Research Compute Network public preview\n\nMIT-licensed client software. Contains no personal token, invitation, model, COMSOL installation or scientific runtime. Connect to your own managed center with an administrator-issued personal token. Compute contribution requires a separately configured operator-approved runtime. Unsigned preview: check the published SHA-256. Third-party components retain their own license notices.\n", encoding="utf-8-sig")
        (stage / "installer.nsi").write_text(NSIS.replace("@ID@", payload_id).replace("@VERSION@", version), encoding="utf-8-sig")
        subprocess.run([makensis or _makensis(), "/V2", str(stage / "installer.nsi")], cwd=stage, check=True, capture_output=True, timeout=300)
        shutil.copy2(stage / "__setup__.exe", output_exe)
        manifest.update(setup_sha256=_sha(output_exe), runtime_zip_sha256=_sha(output_exe.with_suffix(".runtime.zip")))
        output_exe.with_suffix(".manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {"setup_path": str(output_exe), "setup_sha256": manifest["setup_sha256"],
            "payload_id": payload_id, "manifest_path": str(output_exe.with_suffix(".manifest.json")),
            "production_ready": False}


def build_member_client_installer_from_snapshot(**kwargs):
    raise ValueError("public_client_requires_fresh_build_not_private_snapshot")


def main(argv=None):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="action", required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("--release-root", type=Path, required=True)
    verify.add_argument("--expected-payload-id")
    args = parser.parse_args(argv)
    try:
        manifest = verify_snapshot(args.release_root, expected_payload_id=args.expected_payload_id)
        print(json.dumps({"verified": True, "payload_id": manifest["payload_id"]}))
        return 0
    except Exception:
        print(json.dumps({"verified": False, "reason_code": "member_software_integrity_failed"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
