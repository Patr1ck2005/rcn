"""Public, credential-free NSIS presentation and bounded invitation classification."""
from __future__ import annotations

INVITATION_PROBE = r'''param(
 [Parameter(Mandatory=$true)][string]$InvitationPath,
 [Parameter(Mandatory=$true)][string]$NodeRoot
)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
try {
 foreach($candidate in @($InvitationPath,$NodeRoot)){
  $path=[IO.Path]::GetFullPath($candidate)
  while($path){
   if(Test-Path -LiteralPath $path){if((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked path'}}
   $path=[IO.Path]::GetDirectoryName($path)
  }
 }
 $file=[IO.File]::Open($InvitationPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try {
  if($file.Length -gt 16384){throw 'Oversize'}
  $buffer=New-Object byte[] 16385;$count=0
  while($count -lt $buffer.Length){$n=$file.Read($buffer,$count,$buffer.Length-$count);if($n -eq 0){break};$count+=$n}
  if($count -gt 16384){throw 'Oversize'}
  $raw=New-Object byte[] $count;[Array]::Copy($buffer,$raw,$count)
 }finally{$file.Dispose()}
 $value=[Text.Encoding]::UTF8.GetString($raw).TrimStart([char]0xfeff)|ConvertFrom-Json
 if(($value.schema_version -isnot [int] -and $value.schema_version -isnot [long]) -or $value.schema_version -notin @(1,2)){throw 'Unsupported version'}
 if($value.schema_version -eq 2 -and (Test-Path -LiteralPath (Join-Path $NodeRoot 'node.json'))){throw 'Legacy node needs review'}
 if($value.schema_version -eq 1 -and (Test-Path -LiteralPath (Join-Path $NodeRoot 'member-registration'))){throw 'V2 identity needs review'}
 $hash=[Security.Cryptography.SHA256]::Create()
 try{$digest=([BitConverter]::ToString($hash.ComputeHash($raw))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
 # Classification is not validation or authorization. Python rechecks this exact
 # snapshot and the complete schema before any registration request.
 [Console]::Out.Write($digest)
 if($value.schema_version -eq 2){exit 12}else{exit 11}
}catch{exit 2}
'''

INVITATION_PAGE = r'''
Var InvitationPath
Var InvitationInput
Var InvitationDialog
Var InvitationConsent
Var InvitationSchema
Var InvitationSha256
Var ComputeDialogArgument

Function .onInit
  StrCpy $InvitationPath ""
  StrCpy $InvitationSchema ""
  StrCpy $ComputeDialogArgument ""
  IfSilent compute_dialog_done 0
    StrCpy $ComputeDialogArgument "--configure-compute"
  compute_dialog_done:
  InitPluginsDir
  SetOutPath "$PLUGINSDIR"
  File "inspect-invitation.ps1"
  ${GetParameters} $R0
  ClearErrors
  ${GetOptions} $R0 "/INVITATION=" $InvitationPath
  ClearErrors
  IfSilent 0 init_done
    ${GetOptions} $R0 "/ACCEPTREGISTRATION=" $R1
    StrCmp $R1 "1" 0 init_missing
    Call InspectInvitation
    StrCmp $InvitationSchema "" init_missing init_done
  init_missing:
    SetErrorLevel 2
    Quit
  init_done:
FunctionEnd

Function InspectInvitation
  StrCpy $InvitationSchema ""
  StrCpy $InvitationSha256 ""
  StrCmp $InvitationPath "" inspect_done
  nsExec::ExecToStack '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$PLUGINSDIR\inspect-invitation.ps1" -InvitationPath "$InvitationPath" -NodeRoot "$LOCALAPPDATA\ResearchComputeNetwork"'
  Pop $0
  Pop $InvitationSha256
  StrLen $1 $InvitationSha256
  StrCmp $1 64 0 inspect_done
  ${If} $0 == 11
    StrCpy $InvitationSchema "1"
  ${ElseIf} $0 == 12
    StrCpy $InvitationSchema "2"
  ${EndIf}
  inspect_done:
FunctionEnd

Function InvitationPage
  !insertmacro MUI_HEADER_TEXT "选择私密邀请" "同一个安装包支持新版登记与旧版网关邀请。"
  nsDialogs::Create 1018
  Pop $InvitationDialog
  ${If} $InvitationDialog == error
    Abort
  ${EndIf}
  ${NSD_CreateLabel} 0 0 100% 27u "请选择管理员私下交付的邀请 JSON。安装包可以分享，邀请文件不能发群；请核对文件来源。"
  Pop $0
  ${NSD_CreateText} 0 32u 78% 14u "$InvitationPath"
  Pop $InvitationInput
  ${NSD_CreateBrowseButton} 80% 32u 20% 14u "浏览..."
  Pop $0
  ${NSD_OnClick} $0 InvitationBrowse
  ${NSD_CreateLabel} 0 56u 100% 32u "新版登记设备；计算成员还会准备 worker 目录并申请中心预授权的受限回连配置。不启动计算或旧网关。"
  Pop $0
  ${NSD_CreateCheckbox} 0 94u 100% 43u "同意提交设备信息和目录身份，保存本机凭据，并申请限定回环端口的回连授权；私钥不上传，不启动计算或终止私人进程。"
  Pop $InvitationConsent
  nsDialogs::Show
FunctionEnd

Function InvitationBrowse
  Pop $0
  nsDialogs::SelectFileDialog open "$InvitationPath" "邀请文件 (*.json)|*.json"
  Pop $0
  ${If} $0 != ""
    StrCpy $InvitationPath $0
    ${NSD_SetText} $InvitationInput "$InvitationPath"
    ${NSD_Uncheck} $InvitationConsent
  ${EndIf}
FunctionEnd

Function InvitationLeave
  ${NSD_GetText} $InvitationInput $InvitationPath
  ${NSD_GetState} $InvitationConsent $0
  ${If} $0 != ${BST_CHECKED}
    MessageBox MB_OK|MB_ICONEXCLAMATION "请先确认设备信息提交与本机凭据保存。" /SD IDOK
    Abort
  ${EndIf}
  Call InspectInvitation
  ${If} $InvitationSchema == ""
    MessageBox MB_OK|MB_ICONEXCLAMATION "邀请不可用、版本不支持或本机已有不同登记方式。请保留原状态并核对，不要删除凭据重新登记。" /SD IDOK
    Abort
  ${EndIf}
FunctionEnd

Function SetupComponentsPre
  ${If} $InvitationSchema == "2"
    ; V2 has no configured gateway yet: never offer fictitious shortcuts/startup.
    Abort
  ${EndIf}
FunctionEnd

Function SetupFinishShow
  ${If} $InvitationSchema == "2"
    ${NSD_SetText} $mui.FinishPage.Title "设备登记已确认"
    ${NSD_SetText} $mui.FinishPage.Text "设备身份已保存；计算成员的 worker 目录及受限回连配置已准备。计算资源许可由独立窗口确认；守护任务、实际 SSH 通道、运行时及机器验收尚未完成，不能接收计算任务。$\r$\n$\r$\n再次运行原安装包并选择同一邀请可以续接。不要删除本机登记目录；卸载软件不会撤销中心身份。"
    ${NSD_Uncheck} $mui.FinishPage.Run
    ShowWindow $mui.FinishPage.Run 0
  ${EndIf}
FunctionEnd
'''


def adapt_setup_flow(text: str, replace) -> str:
    text = replace(text, 'Page custom InvitationPage InvitationLeave\n!insertmacro MUI_PAGE_COMPONENTS',
        'Page custom InvitationPage InvitationLeave\n!define MUI_PAGE_CUSTOMFUNCTION_PRE SetupComponentsPre\n!insertmacro MUI_PAGE_COMPONENTS')
    text = replace(text, '!insertmacro MUI_PAGE_FINISH',
        '!define MUI_PAGE_CUSTOMFUNCTION_SHOW SetupFinishShow\n!insertmacro MUI_PAGE_FINISH')
    text = replace(text, 'member-install "$InvitationPath"',
        'member-setup "$InvitationPath" --expected-schema 1 --invitation-sha256 "$InvitationSha256" --accept-registration', 4)
    text = replace(text, '  DetailPrint "入网与网关配置（约半分钟）..."', r'''  ${If} $InvitationSchema == "2"
    DetailPrint "正在确认设备登记；本阶段不启用计算..."
    nsExec::ExecToLog '"$LOCALAPPDATA\ResearchComputeNetwork\runtime\python\python.exe" -m research_compute_network.cli member-setup "$InvitationPath" --expected-schema 2 --invitation-sha256 "$InvitationSha256" --accept-registration --no-launcher --prepare-worker-root --prepare-relay $ComputeDialogArgument'
  ${Else}
    DetailPrint "正在配置旧版邀请的网关..."''')
    text = replace(text, '  Pop $0\n  ${If} $0 != 0\n    DetailPrint "入网失败（代码 $0）：请把本窗口截图发给管理员"',
        '  ${EndIf}\n  Pop $0\n  ${If} $0 != 0\n    SetErrorLevel 2\n    DetailPrint "登记未完成（代码 $0）。保留原邀请和本机身份；连接故障可重试，证书/权限/冲突须先核对。"')
    text = replace(text, 'Function LaunchConsole\n',
        'Function LaunchConsole\n  ${If} $InvitationSchema != "1"\n    Return\n  ${EndIf}\n')
    # Universal software removal must not erase the v2 recovery identity or invoke
    # legacy node-uninstall against it. Machine retirement is a separate operation.
    text = replace(text, 'Section "Uninstall"\n',
        'Section "Uninstall"\n  IfFileExists "$INSTDIR\\member-registration\\*.*" keep_registration 0\n')
    text = replace(text, '  RMDir /r "$INSTDIR"',
        '  keep_registration:\n  RMDir /r "$INSTDIR\\runtime"\n  Delete "$INSTDIR\\uninstall.exe"\n  RMDir "$INSTDIR"')
    return text
