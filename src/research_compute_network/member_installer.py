"""NSIS installer template for per-member Setup.exe builds.

The generated script embeds: the member invitation JSON, the Python 3.11
embeddable runtime, an offline wheelhouse, and the RCN wheel. The installer
extracts them into %LOCALAPPDATA%\\ResearchComputeNetwork\\runtime, boots
pip offline, installs the wheel, then hands to the in-package
``member-install`` wizard (enroll through the SSH tunnel, gateway, welcome
note, browser).

NSIS page flow: Welcome -> License (publisher notice) -> Components ->
Install -> Finish (launch console). Components: core (required, locked),
desktop icon (optional, default ON), logon autostart (optional, default
OFF). Supports silent installs with /S; silent mode applies defaults.

The template is a plain string with @TOKENS@ (no f-string) so NSIS LogicLib
macros like ${If} never collide with Python brace escaping.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

WHEELHOUSE_DIRNAME = "wheelhouse"
RUNTIME_DIR = "$LOCALAPPDATA\\ResearchComputeNetwork\\runtime"
NSIS_LANG = "SimpChinese"
EMBEDDABLE_ZIP = "python-3.11.9-embed-amd64.zip"
MAKENSIS_CANDIDATES = (
    "C:\\Program Files (x86)\\NSIS\\makensis.exe",
    "C:\\Program Files\\NSIS\\makensis.exe",
)

_NSIS_TEMPLATE = r"""!include "MUI2.nsh"
!include "LogicLib.nsh"

Unicode true
Name "@PRODUCT_NAME@"
OutFile "__setup__.exe"
InstallDir "$LOCALAPPDATA\ResearchComputeNetwork"
RequestExecutionLevel user
SetCompressor /SOLID lzma
ShowInstDetails show

!define MUI_ABORTWARNING
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "publisher-notice.txt"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_INSTFILES

!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_TEXT "立即打开科研计算网络看板"
!define MUI_FINISHPAGE_RUN_FUNCTION LaunchConsole
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_LANGUAGE "@NSIS_LANG@"

; ---------------- core (always installed) ----------------
Section "科研计算网络核心（必需）" SEC_CORE
  SectionIn RO
  DetailPrint "释放 Python 3.11 运行时..."
  ; Stage the archive in NSIS' unique per-run directory. The old installer
  ; staged it inside the runtime and deleted the wrong path, so a retry could
  ; collide with the leftover 11 MB archive and fail before enrollment.
  InitPluginsDir
  SetOutPath "$PLUGINSDIR"
  File /oname=@EMBEDDABLE_ZIP@ "@WHEELHOUSE_DIRNAME@\@EMBEDDABLE_ZIP@"
  CreateDirectory "@RUNTIME_DIR@\python"
  nsExec::ExecToLog '"$SYSDIR\tar.exe" -xf "$PLUGINSDIR\@EMBEDDABLE_ZIP@" -C "@RUNTIME_DIR@\python"'
  Pop $0
  ${If} $0 != 0
    DetailPrint "运行时解压失败（代码 $0）"
    Abort
  ${EndIf}
  ${If} ${FileExists} "@RUNTIME_DIR@\python\python.exe"
  ${Else}
    DetailPrint "运行时解压不完整：未找到 python.exe"
    Abort
  ${EndIf}
  Delete "$PLUGINSDIR\@EMBEDDABLE_ZIP@"
  ; Clean the stale location left by the pre-hotfix installer. It is not used
  ; by this run, so a transient scanner lock cannot block installation.
  Delete /REBOOTOK "@RUNTIME_DIR@\python\@EMBEDDABLE_ZIP@"

  ; embeddable python ships with import site disabled; pip needs it
  FileOpen $0 "@RUNTIME_DIR@\python\python311._pth" a
  FileSeek $0 0 END
  FileWrite $0 "$\nLib\site-packages$\nimport site$\n"
  FileClose $0

  DetailPrint "准备离线依赖包..."
  SetOutPath "@RUNTIME_DIR@\wheelhouse"
  File "@WHEELHOUSE_DIRNAME@\*.whl"
  File "@WHEELHOUSE_DIRNAME@\get-pip.py"

  DetailPrint "引导 pip（离线，约一分钟）..."
  nsExec::ExecToLog '"@RUNTIME_DIR@\python\python.exe" "@RUNTIME_DIR@\wheelhouse\get-pip.py" --no-index --find-links "@RUNTIME_DIR@\wheelhouse" --no-warn-script-location'
  Pop $0
  ${If} $0 != 0
    DetailPrint "pip 引导失败（代码 $0）"
    Abort
  ${EndIf}

  DetailPrint "安装科研计算网络..."
  ; --force-reinstall: a foreign user-site copy must never shadow the
  ; embedded runtime, and offline deps come from the embedded wheelhouse.
  nsExec::ExecToLog '"@RUNTIME_DIR@\python\python.exe" -m pip install --no-index --find-links "@RUNTIME_DIR@\wheelhouse" --no-warn-script-location --force-reinstall "@WHEEL_NAME@"'
  Pop $0
  ${If} $0 != 0
    DetailPrint "包安装失败（代码 $0）"
    Abort
  ${EndIf}
  Delete "@RUNTIME_DIR@\wheelhouse\get-pip.py"

  SetOutPath "@RUNTIME_DIR@"
  File "invitation.json"
SectionEnd

; ---------------- member options ----------------
Section "桌面快捷方式" SEC_LAUNCHER
SectionEnd

Section /o "开机自动启动网关" SEC_STARTUP
SectionEnd

; ---------------- final step: enroll + gateway ----------------
Section "-post" SEC_POST
  DetailPrint "入网与网关配置（约半分钟）..."
  ${If} ${SectionIsSelected} ${SEC_STARTUP}
    ${If} ${SectionIsSelected} ${SEC_LAUNCHER}
      nsExec::ExecToLog '"@RUNTIME_DIR@\python\python.exe" -m research_compute_network.cli member-install "@RUNTIME_DIR@\invitation.json" --install-startup'
    ${Else}
      nsExec::ExecToLog '"@RUNTIME_DIR@\python\python.exe" -m research_compute_network.cli member-install "@RUNTIME_DIR@\invitation.json" --install-startup --no-launcher'
    ${EndIf}
  ${Else}
    ${If} ${SectionIsSelected} ${SEC_LAUNCHER}
      nsExec::ExecToLog '"@RUNTIME_DIR@\python\python.exe" -m research_compute_network.cli member-install "@RUNTIME_DIR@\invitation.json"'
    ${Else}
      nsExec::ExecToLog '"@RUNTIME_DIR@\python\python.exe" -m research_compute_network.cli member-install "@RUNTIME_DIR@\invitation.json" --no-launcher'
    ${EndIf}
  ${EndIf}
  Pop $0
  ${If} $0 != 0
    DetailPrint "入网失败（代码 $0）：请把本窗口截图发给管理员"
    Abort
  ${EndIf}

  ; uninstaller entry point + Add/Remove Programs record (per-user)
  WriteUninstaller "$INSTDIR\uninstall.exe"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\ResearchComputeNetwork-Member" "DisplayName" "@PRODUCT_NAME@"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\ResearchComputeNetwork-Member" "UninstallString" "$INSTDIR\uninstall.exe"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\ResearchComputeNetwork-Member" "DisplayVersion" "0.13.3"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\ResearchComputeNetwork-Member" "Publisher" "Research Compute Network"
SectionEnd

Function LaunchConsole
  Exec '"$SYSDIR\rundll32.exe" url.dll,FileProtocolHandler http://127.0.0.1:18765/app/fleet'
FunctionEnd

; ---------------- uninstaller ----------------
Section "Uninstall"
  nsExec::ExecToLog '"$INSTDIR\runtime\python\python.exe" -m research_compute_network.cli node stop'
  Pop $0
  nsExec::ExecToLog '"$INSTDIR\runtime\python\python.exe" -m research_compute_network.cli node startup-remove'
  Pop $0
  nsExec::ExecToLog '"$INSTDIR\runtime\python\python.exe" -m research_compute_network.cli node uninstall'
  Pop $0
  RMDir /r "$INSTDIR"
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\ResearchComputeNetwork-Member"
SectionEnd
"""


def _nsis_escape(value: str) -> str:
    """Escape for a double-quoted NSIS string: $ -> $$, " -> $\"."""
    return value.replace("$", "$$").replace('"', '$"')


def render_nsis(
    *,
    invitation: dict,
    wheel_name: str,
    wheelhouse_dirname: str = WHEELHOUSE_DIRNAME,
    product_name: str | None = None,
) -> str:
    member = invitation["member"]["user_id"]
    name = _nsis_escape(product_name or f"Research Compute Network ({member})")
    replacements = {
        "@PRODUCT_NAME@": name,
        "@NSIS_LANG@": NSIS_LANG,
        "@WHEELHOUSE_DIRNAME@": wheelhouse_dirname,
        "@EMBEDDABLE_ZIP@": EMBEDDABLE_ZIP,
        "@RUNTIME_DIR@": RUNTIME_DIR,
        "@WHEEL_NAME@": _nsis_escape(wheel_name),
    }
    script = _NSIS_TEMPLATE
    for token, value in replacements.items():
        script = script.replace(token, value)
    assert "@PRODUCT_NAME@" not in script
    return script


def _makensis() -> str:
    found = next((path for path in MAKENSIS_CANDIDATES if Path(path).is_file()), None)
    if found is None:
        raise FileNotFoundError(
            "makensis.exe not found; install NSIS (winget install NSIS.NSIS)"
        )
    return found


def build_member_installer(
    *,
    invitation: dict,
    invitation_bytes: bytes,
    wheel_path: Path,
    wheelhouse_dir: Path,
    embeddable_zip: Path,
    output_exe: Path,
    makensis: str | None = None,
    product_name: str | None = None,
) -> dict:
    """Stage one member's Setup.exe inputs and compile it with NSIS.

    Secrets (token, enrollment code, private key) live ONLY in the invitation
    JSON copied into the staging tree; the staging tree is removed after
    compilation. Returns the exe path plus its sha256 for out-of-band checks.
    """
    compiler = makensis or _makensis()
    output_exe = Path(output_exe).resolve()
    output_exe.parent.mkdir(parents=True, exist_ok=True)
    script = render_nsis(invitation=invitation, wheel_name=wheel_path.name, product_name=product_name)
    # Stage beside the protected per-member output rather than in the process
    # TEMP directory, whose inherited Windows ACL may include unrelated local
    # groups. The directory is removed after compilation as before.
    with tempfile.TemporaryDirectory(prefix="rcn-setup-", dir=output_exe.parent) as temporary:
        stage = Path(temporary)
        shutil.copytree(wheelhouse_dir, stage / WHEELHOUSE_DIRNAME, dirs_exist_ok=True)
        # The selected wheel is authoritative. A cached wheelhouse commonly has
        # an older wheel with the same release filename during a same-version
        # installer hotfix; overwrite it before NSIS expands wheelhouse/*.whl.
        shutil.copyfile(wheel_path, stage / WHEELHOUSE_DIRNAME / wheel_path.name)
        shutil.copyfile(embeddable_zip, stage / WHEELHOUSE_DIRNAME / EMBEDDABLE_ZIP)
        (stage / "invitation.json").write_bytes(invitation_bytes)
        (stage / "publisher-notice.txt").write_text(
            "Research Compute Network - member installer\n\n"
            "This installer is lab-internal software and is not organization "
            "code-signed; SmartScreen may warn. Choose 'More info -> Run anyway'.\n"
            "The installer carries your personal enrollment secrets - do not "
            "forward it to anyone else.\n",
            encoding="utf-8-sig",
        )
        script_path = stage / "installer.nsi"
        # NSIS Unicode requires the BOM, else it decodes the script as ANSI
        # and dies on the Chinese UI strings ("Bad text encoding").
        script_path.write_text(script, encoding="utf-8-sig")
        compile_result = subprocess.run(
            [compiler, "/NOCONFIG", "/V2", str(script_path)],
            cwd=stage,
            capture_output=True,
            text=True,
            timeout=600,
        )
        if compile_result.returncode != 0:
            raise RuntimeError(
                f"makensis failed ({compile_result.returncode}):\n"
                f"{compile_result.stdout}\n{compile_result.stderr}"
            )
        built = stage / "__setup__.exe"
        if not built.is_file():
            raise RuntimeError("makensis reported success but produced no exe")
        shutil.copyfile(built, output_exe)
    digest = hashlib.sha256(output_exe.read_bytes()).hexdigest()
    return {
        "installer_path": str(output_exe),
        "sha256": digest,
        "size_bytes": output_exe.stat().st_size,
        "machine_id": invitation["machine_id"],
        "member": invitation["member"]["user_id"],
    }
