"""Current-member transport tasks: same guard, no SYSTEM execution of user files.

Only explicitly selected new installs use this variant. Existing SYSTEM bundles
retain their exact bytes and cannot be silently converted. A one-minute trigger
owns recovery when a startup response is lost; the client never replays Run.
"""
from __future__ import annotations

from dataclasses import replace
import re
import hashlib
import xml.etree.ElementTree as ET

NS = 'http://schemas.microsoft.com/windows/2004/02/mit/task'


def member_sid(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r'S-1-5-21-(?:[0-9]+-){3}[0-9]+', value):
        raise ValueError('explicit_member_account_sid_required')
    return value


def _replace(text: str, old: str, new: str) -> str:
    if text.count(old) != 1:
        raise ValueError('member_tunnel_template_changed_requires_review')
    return text.replace(old, new, 1)


def member_bundle(bundle, sid: str):
    """Specialize freshly generated definitions, never modify a saved/live task."""
    sid = member_sid(sid)
    def xml(source: str, guard: bool) -> str:
        tree = ET.fromstring(source)
        principal = tree.find('{'+NS+'}Principals/{'+NS+'}Principal')
        principal.find('{'+NS+'}UserId').text = sid
        principal.find('{'+NS+'}RunLevel').text = 'LeastPrivilege'
        logon_type = ET.Element('{'+NS+'}LogonType'); logon_type.text = 'InteractiveToken'
        principal.insert(list(principal).index(principal.find('{'+NS+'}RunLevel')), logon_type)
        triggers = tree.find('{'+NS+'}Triggers')
        triggers.clear()
        if guard:
            logon = ET.SubElement(triggers, '{'+NS+'}LogonTrigger')
            ET.SubElement(logon, '{'+NS+'}Enabled').text = 'true'
            ET.SubElement(logon, '{'+NS+'}UserId').text = sid
            timer = ET.SubElement(triggers, '{'+NS+'}TimeTrigger')
            repetition = ET.SubElement(timer, '{'+NS+'}Repetition')
            ET.SubElement(repetition, '{'+NS+'}Interval').text = 'PT1M'
            ET.SubElement(repetition, '{'+NS+'}StopAtDurationEnd').text = 'false'
            ET.SubElement(timer, '{'+NS+'}StartBoundary').text = '2020-01-01T00:00:00+00:00'
            ET.SubElement(timer, '{'+NS+'}Enabled').text = 'true'
        # Preserve namespace-qualified elements without mutating the global registry.
        return '<?xml version="1.0" encoding="UTF-16"?>\n' + ET.tostring(tree, encoding='unicode')
    script = _replace(bundle.script, "$ErrorActionPreference='Stop'",
        "$ErrorActionPreference='Stop'\n$memberSid='"+sid+"'\n"
        "if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne $memberSid){throw 'Member transport identity changed'}")
    script = _replace(script, "$task.Principal.UserId -notin @('SYSTEM','S-1-5-18')", "$taskSid -cne $memberSid")
    # Avoid resolving a SID as an NTAccount: either form is canonicalized first.
    script = _replace(script, "$task=Get-ScheduledTask -TaskName $guardTaskName -TaskPath '\\' -ErrorAction Stop",
        "$task=Get-ScheduledTask -TaskName $guardTaskName -TaskPath '\\' -ErrorAction Stop\n"
        "    $taskSid=[string]$task.Principal.UserId\n"
        "    if($taskSid -notmatch '^S-1-'){ $taskSid=([Security.Principal.NTAccount]::new($taskSid)).Translate([Security.Principal.SecurityIdentifier]).Value }")
    match = re.search(r"(?m)^\$configHash='([a-f0-9]{64})'$", script)
    if not match:
        raise ValueError('member_tunnel_configuration_hash_missing')
    digest = hashlib.sha256((match[1] + ':' + sid).encode('ascii')).hexdigest()
    script = _replace(script, match[0], "$configHash='" + digest + "'")
    return replace(bundle, script=script, guard_task_xml=xml(bundle.guard_task_xml, True),
                   request_task_xml=xml(bundle.request_task_xml, False), member_sid=sid)


def member_installer(script: str, sid: str) -> str:
    sid = member_sid(sid)
    script = _replace(script,
        "if(-not $admin -and $identity.User.Value -ne 'S-1-5-18'){throw 'Elevated administrator required for task installation'}",
        "if($identity.User.Value -cne '"+sid+"'){throw 'Original member identity required for task installation'}")
    script = _replace(script, "$definition.Principal.UserId='SYSTEM';$definition.Principal.LogonType=5",
        "$definition.Principal.UserId='"+sid+"';$definition.Principal.LogonType=3;$definition.Principal.RunLevel=0")
    script = _replace(script, "RegisterTask($Name,$Text,54,'SYSTEM',$null,5,$Sddl)",
        "RegisterTask($Name,$Text,54,'"+sid+"',$null,3,$Sddl)")
    script = _replace(script, "$newTaskSddl='O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)'",
        "$newTaskSddl='O:"+sid+"G:"+sid+"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;"+sid+")'")
    script = _replace(script, "$principals[0].UserId -notin @('SYSTEM','S-1-5-18')",
        "$principalSid -cne '"+sid+"'")
    script = _replace(script, " if($principals.Count -ne 1", " if($principals.Count -ne 1){throw 'Invalid member task principal count'}\n $principalSid=[string]$principals[0].UserId\n"
        "  if($principalSid -notmatch '^S-1-'){ $principalSid=([Security.Principal.NTAccount]::new($principalSid)).Translate([Security.Principal.SecurityIdentifier]).Value }\n"
        "  if($principals.Count -ne 1")
    script = _replace(script, "if(@($triggers|Where-Object {$_.LocalName -ne 'BootTrigger'}).Count){throw 'Unexpected task trigger'}",
        "if(@($triggers|Where-Object {$_.LocalName -notin @('LogonTrigger','TimeTrigger')}).Count){throw 'Unexpected member task trigger'}\n"
        "  $matches=@($desired.Values | Where-Object {(Canonical-Xml $_) -ceq (Canonical-Xml $Task.xml)})\n"
        "  if($matches.Count -ne 1){throw 'Existing member task differs from the reviewed definition'}")
    return script


def execution_bundle(bundle, identity):
    """New dedicated-account transport; owner login triggers Password-logon work."""
    from .member_execution_identity import _validated
    identity = _validated(identity)
    result = member_bundle(bundle, identity['execution_sid'])
    def xml(source):
        tree = ET.fromstring(source)
        tree.find('{'+NS+'}Principals/{'+NS+'}Principal/{'+NS+'}LogonType').text = 'Password'
        for trigger in tree.findall('{'+NS+'}Triggers/{'+NS+'}LogonTrigger'):
            trigger.find('{'+NS+'}UserId').text = identity['owner_sid']
        return '<?xml version="1.0" encoding="UTF-16"?>\n'+ET.tostring(tree,encoding='unicode')
    return replace(result, member_owner_sid=identity['owner_sid'],
        guard_task_xml=xml(result.guard_task_xml), request_task_xml=xml(result.request_task_xml))


def execution_installer(script, execution_sid, owner_sid):
    execution_sid, owner_sid = member_sid(execution_sid), member_sid(owner_sid)
    result = member_installer(script, execution_sid)
    result = _replace(result, "if($identity.User.Value -cne '"+execution_sid+"'){throw 'Original member identity required for task installation'}",
        "if(-not $admin){throw 'Explicit task elevation required'}")
    result = _replace(result, "LogonType=3;$definition.Principal.RunLevel=0", "LogonType=1;$definition.Principal.RunLevel=0")
    result = _replace(result, "RegisterTask($Name,$Text,54,'"+execution_sid+"',$null,3,$Sddl)",
        "RegisterTask($Name,$Text,54,'"+execution_sid+"',$global:rcnMemberExecutionPassword,1,$Sddl)")
    old = "$allowed=@('S-1-5-18','S-1-5-32-544',[Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"
    if result.count(old) not in {1,2}:
        raise ValueError('member_execution_tunnel_acl_shape_changed')
    result = result.replace(old, "$allowed=@('S-1-5-18','S-1-5-32-544','"+owner_sid+"','"+execution_sid+"')")
    return result
