"""Explicit release variant for standard local members, not an implicit upgrade.

Interactive Worker consent covers the local SSH service/UAC and user tasks. Silent
registration remains preparation-only for this feature; submitters never get SSH.
"""
from pathlib import Path
import zipfile


def add_connection_flow(script: str, probe: str, replace) -> tuple[str,str]:
    script=replace(script,'Var SupervisorStartupArgument','Var SupervisorStartupArgument\nVar MemberConnectionArgument')
    script=replace(script,'  StrCpy $InvitationSchema ""\n  StrCpy $InvitationSha256 ""',
        '  StrCpy $InvitationSchema ""\n  StrCpy $InvitationSha256 ""\n  StrCpy $MemberConnectionArgument ""')
    script=replace(script,'  ${ElseIf} $0 == 12\n    StrCpy $InvitationSchema "2"',
        '  ${ElseIf} $0 == 13\n    StrCpy $InvitationSchema "2"\n'
        '    IfSilent member_connection_preparation_only 0\n'
        '    StrCpy $MemberConnectionArgument "--connect-worker --prepare-openssh"\n'
        '    member_connection_preparation_only:\n'
        '  ${ElseIf} $0 == 12\n    StrCpy $InvitationSchema "2"')
    script=replace(script,'$SupervisorStartupArgument $ComputeDialogArgument',
        '$SupervisorStartupArgument $ComputeDialogArgument $MemberConnectionArgument')
    script=replace(script,
        '同意登记及受限回连配置；安装密封监督程序并以本机用户自启动（零容量）。私钥不上传，不开放计算、远程管理或终止私人进程权限。',
        '计算成员：同意由 Windows 更新补齐 OpenSSH、安装零容量监督程序和回环服务；系统安装显示 UAC，不自动重启。允许中心固定运维与验收，私钥不上传，不授权终止私人进程。')
    script=replace(script,
        '新版登记设备；计算成员还会准备 worker 目录并申请中心预授权的受限回连配置。不启动计算或旧网关。',
        '此接入变体支持标准本地账户，缺失 OpenSSH 由系统更新补齐；管理员/域账户仍待受控部署支持。仅提交任务不会安装组件；计算资格须完整验收后确认。')
    script=replace(script,
        '已进入密封监督程序的安装与零容量启动流程；实际 SSH、科学依赖和整机验收仍待完成，不能接收计算任务。',
        '安装状态以回执为准；本机 SSH 与中心交接不等于机器验收通过。完整科学依赖及整机验收完成前，不开放正常计算。')
    probe=replace(probe,'if($value.schema_version -eq 2){exit 12}else{exit 11}',
        'if($value.schema_version -eq 2){if($value.worker -is [bool] -and $value.worker){exit 13};exit 12}else{exit 11}')
    return script,probe


def require_connection_support(wheel: Path):
    with zipfile.ZipFile(wheel) as archive:
        for name in ('member_ssh_service.py','member_ssh_client.py','member_ssh_access.py','member_tunnel_identity.py',
                     'member_tunnel_install.py','tunnel_activation.py','member_openssh_prerequisite.py','member_comsol_discovery.py'):
            if 'research_compute_network/'+name not in archive.namelist():
                raise ValueError('release wheel lacks member SSH connection support')
        if b'"--connect-worker"' not in archive.read('research_compute_network/cli.py'):
            raise ValueError('release wheel lacks explicit member connection CLI')
        if b'"--prepare-openssh"' not in archive.read('research_compute_network/cli.py'):
            raise ValueError('release wheel lacks explicit Windows component supply CLI')
