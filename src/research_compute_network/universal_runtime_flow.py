"""Opt-in public installer variant carrying the original sealed Worker archive.

No member-specific inputs. Legacy public installer bytes are left unchanged.
The member's installer consent explicitly includes a zero-capacity user task.
"""
from __future__ import annotations

from pathlib import Path
import zipfile

RUNTIME_NAME = 'sealed-member-runtime.zip'


def add_runtime_flow(script: str, replace) -> str:
    script = replace(script, 'Var ComputeDialogArgument', 'Var ComputeDialogArgument\nVar SupervisorStartupArgument')
    script = replace(script, '  StrCpy $ComputeDialogArgument ""', '''  StrCpy $SupervisorStartupArgument "--start-supervisor"
  IfSilent 0 supervisor_consent_done
  StrCpy $SupervisorStartupArgument ""
  ${GetParameters} $R0
  ${GetOptions} $R0 "/ACCEPTSUPERVISOR=" $R1
  StrCmp $R1 "1" 0 supervisor_consent_done
  StrCpy $SupervisorStartupArgument "--start-supervisor"
  supervisor_consent_done:
  StrCpy $ComputeDialogArgument ""''')
    script = replace(script, '--prepare-relay $ComputeDialogArgument',
        '--prepare-relay --worker-runtime "$LOCALAPPDATA\\ResearchComputeNetwork\\runtime\\sealed-member-runtime.zip" $SupervisorStartupArgument $ComputeDialogArgument')
    script = replace(script, '  ; Invitation is selected at runtime and is never embedded or copied here.',
        '  File /oname=sealed-member-runtime.zip "wheelhouse\\sealed-member-runtime.zip"\n  ; Invitation is selected at runtime and is never embedded or copied here.')
    script = replace(script,
        '同意提交设备信息和目录身份，保存本机凭据，并申请限定回环端口的回连授权；私钥不上传，不启动计算或终止私人进程。',
        '同意登记及受限回连配置；安装密封监督程序并以本机用户自启动（零容量）。私钥不上传，不开放计算、远程管理或终止私人进程权限。')
    script = replace(script,
        '守护任务、实际 SSH 通道、运行时及机器验收尚未完成，不能接收计算任务。',
        '已进入密封监督程序的安装与零容量启动流程；实际 SSH、科学依赖和整机验收仍待完成，不能接收计算任务。')
    script = replace(script, 'Section "Uninstall"\n',
        'Section "Uninstall"\n  IfFileExists "$INSTDIR\\member-registration\\member-runtime.json" runtime_remove_refuse 0\n'
        '  IfFileExists "$INSTDIR\\worker\\agent\\member-supervisor-startup.json" 0 runtime_remove_safe\n  runtime_remove_refuse:\n'
        '  MessageBox MB_OK|MB_ICONEXCLAMATION "监督程序仍有受管启动记录，请先完成节点退役；本次未删除运行文件。" /SD IDOK\n'
        '  SetErrorLevel 2\n  Abort\n  runtime_remove_safe:\n')
    return script


def preserve_running_runtime(script: str, replace, manifest_sha256: str) -> str:
    """Same-release resume skips extraction/pip; a different release needs migration."""
    import re
    if not re.fullmatch(r'[a-f0-9]{64}', manifest_sha256):
        raise ValueError('invalid release manifest hash')
    import base64
    command = "$ProgressPreference='SilentlyContinue';try { [Console]::Out.Write((Get-FileHash -LiteralPath ($env:LOCALAPPDATA + '\\ResearchComputeNetwork\\runtime\\public-release-manifest.json') -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()) } catch { exit 2 }"
    encoded = base64.b64encode(command.encode('utf-16-le')).decode('ascii')
    gate = r'''
  IfFileExists "$LOCALAPPDATA\ResearchComputeNetwork\member-registration\member-runtime.json" rcn_runtime_check 0
  IfFileExists "$LOCALAPPDATA\ResearchComputeNetwork\worker\agent\member-supervisor-startup.json" 0 rcn_runtime_fresh
  rcn_runtime_check:
  nsExec::ExecToStack '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -EncodedCommand __COMMAND__'
  Pop $0
  Pop $1
  StrCmp $0 "0" 0 rcn_runtime_refuse
  StrCmp $1 "__MANIFEST__" 0 rcn_runtime_refuse
  IfFileExists "$LOCALAPPDATA\ResearchComputeNetwork\runtime\python\python.exe" 0 rcn_runtime_refuse
  Goto rcn_runtime_preserved
  rcn_runtime_refuse:
  DetailPrint "已存在监督任务，但发行包不匹配；保留现有运行文件，需受控升级。"
  SetErrorLevel 2
  Abort
  rcn_runtime_fresh:
'''.replace('__MANIFEST__', manifest_sha256).replace('__COMMAND__', encoded)
    script = replace(script, '  SectionIn RO\n', '  SectionIn RO\n' + gate)
    script = replace(script, '  ; No invitation or user credential in the release.\nSectionEnd',
        '  ; No invitation or user credential in the release.\n  rcn_runtime_preserved:\nSectionEnd')
    return script


def require_runtime_support(wheel: Path):
    with zipfile.ZipFile(wheel) as archive:
        for name in ('member_runtime.py','member_supervisor_startup.py'):
            if 'research_compute_network/'+name not in archive.namelist():
                raise ValueError('release wheel lacks sealed member runtime installation')
        if b'"--worker-runtime"' not in archive.read('research_compute_network/cli.py'):
            raise ValueError('release wheel lacks worker-runtime CLI support')
