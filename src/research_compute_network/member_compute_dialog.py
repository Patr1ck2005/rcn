"""Member-owned native consent UI. Displays data; never evaluates supplied code."""
from __future__ import annotations

import base64
import json
import os
import subprocess

DIALOG_SCRIPT = r'''
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()
$data=[Console]::In.ReadToEnd()|ConvertFrom-Json
$form=New-Object Windows.Forms.Form
$form.Text='科研计算网络 · 计算资源授权';$form.Width=700;$form.Height=760
$form.StartPosition='CenterScreen';$form.MinimumSize=New-Object Drawing.Size(600,600)
$form.AutoScaleMode='Dpi';$form.AutoScroll=$true
function Label([string]$text,[int]$y,[int]$height=26){
 $c=New-Object Windows.Forms.Label;$c.Text=$text;$c.Left=22;$c.Top=$y;$c.Width=625;$c.Height=$height
 $form.Controls.Add($c);return $c
}
$null=Label ([string]$data.admission_notice) 18 40
$projects=New-Object Windows.Forms.TextBox;$projects.Multiline=$true;$projects.ReadOnly=$true
$projects.Left=22;$projects.Top=62;$projects.Width=625;$projects.Height=135;$projects.ScrollBars='Vertical'
$validity=if($null -eq $data.expires_at){'无到期，直到主动撤销'}else{'有效至：'+([string]$data.expires_at)}
$projects.Text=([string]$data.project_summary)+"`r`n"+$validity
$form.Controls.Add($projects)
function Number([int]$x,[int]$y,[int]$minimum,[int]$maximum,[int]$value){
 $c=New-Object Windows.Forms.NumericUpDown;$c.Left=$x;$c.Top=$y;$c.Width=130
 $c.Minimum=$minimum;$c.Maximum=$maximum;$c.Value=[Math]::Min($maximum,[Math]::Max($minimum,$value));$form.Controls.Add($c);return $c
}
$null=Label 'CPU 逻辑线程上限                   最多内存（MiB）                  给日常使用保留内存（MiB）' 210
$cpus=Number 22 239 1 ([int]$data.max_cpus) ([int]$data.default_cpus)
$memory=Number 225 239 256 ([int]$data.max_memory_mb) ([int]$data.default_memory_mb)
$reserve=Number 440 239 0 ([int]$data.total_memory_mb-1) ([int]$data.default_reserve_mb)
$null=Label '时区（请选择与你期望的计算时段一致的时区）：' 280
$zone=New-Object Windows.Forms.ComboBox;$zone.Left=22;$zone.Top=310;$zone.Width=620;$zone.DropDownStyle='DropDownList'
foreach($name in $data.timezones){$null=$zone.Items.Add([string]$name)}
$zone.SelectedIndex=-1;$form.Controls.Add($zone)
$days=@();$names=@('周一','周二','周三','周四','周五','周六','周日')
for($i=0;$i -lt 7;$i++){$c=New-Object Windows.Forms.CheckBox;$c.Text=$names[$i];$c.Checked=$true;$c.Left=22+$i*88;$c.Top=356;$c.Width=80;$form.Controls.Add($c);$days+=,$c}
$all=New-Object Windows.Forms.CheckBox;$all.Text='所选日期全天允许（仍遵守空闲及资源限制）';$all.Left=22;$all.Top=395;$all.Width=590;$all.Checked=$true;$form.Controls.Add($all)
$start=New-Object Windows.Forms.DateTimePicker;$start.Format='Custom';$start.CustomFormat='HH:mm';$start.ShowUpDown=$true;$start.Left=22;$start.Top=431;$start.Width=140;$start.Enabled=$false
$end=New-Object Windows.Forms.DateTimePicker;$end.Format='Custom';$end.CustomFormat='HH:mm';$end.ShowUpDown=$true;$end.Left=225;$end.Top=431;$end.Width=140;$end.Enabled=$false
$form.Controls.Add($start);$form.Controls.Add($end)
$start.Value=[DateTime]::Today.AddHours(9);$end.Value=[DateTime]::Today.AddHours(18)
$all.Add_CheckedChanged({$start.Enabled=-not $all.Checked;$end.Enabled=-not $all.Checked})
$idle=New-Object Windows.Forms.CheckBox;$idle.Text='仅在键盘空闲 20 分钟后接收新计算';$idle.Left=22;$idle.Top=472;$idle.Width=600;$idle.Checked=$true;$form.Controls.Add($idle)
$consent=New-Object Windows.Forms.CheckBox;$consent.Text='我同意在上述范围和资源限制内参与计算；不授权终止我的私人程序。';$consent.Left=22;$consent.Top=509;$consent.Width=625;$consent.Height=48;$form.Controls.Add($consent)
$ok=New-Object Windows.Forms.Button;$ok.Text='同意并继续';$ok.Left=335;$ok.Top=577;$ok.Width=145;$ok.Height=36;$ok.Enabled=$false;$form.Controls.Add($ok)
$cancel=New-Object Windows.Forms.Button;$cancel.Text='暂不参与计算';$cancel.Left=490;$cancel.Top=577;$cancel.Width=155;$cancel.Height=36;$cancel.DialogResult='Cancel';$form.Controls.Add($cancel)
$consent.Add_CheckedChanged({$ok.Enabled=$consent.Checked -and $zone.SelectedIndex -ge 0})
$zone.Add_SelectedIndexChanged({$ok.Enabled=$consent.Checked -and $zone.SelectedIndex -ge 0})
$script:answer=$null
$ok.Add_Click({
 $windows=@{}
 for($i=0;$i -lt 7;$i++){if($days[$i].Checked){$a=if($all.Checked){'00:00'}else{$start.Value.ToString('HH:mm')};$b=if($all.Checked){'00:00'}else{$end.Value.ToString('HH:mm')};$windows[[string]$i]=@(@{start=$a;end=$b})}}
 if($windows.Count -eq 0){$null=[Windows.Forms.MessageBox]::Show('至少选择一个允许计算的日期。');return}
 $script:answer=@{max_cpus=[int]$cpus.Value;max_memory_mb=[int]$memory.Value;memory_reserve_mb=[int]$reserve.Value;timezone=[string]$zone.SelectedItem;weekly_windows=$windows;keyboard_idle_min_s=$(if($idle.Checked){1200}else{0})}
 $form.DialogResult='OK';$form.Close()
})
$form.CancelButton=$cancel
try{$result=$form.ShowDialog();if($result -eq 'OK' -and $script:answer){[Console]::Out.Write(($script:answer|ConvertTo-Json -Depth 8 -Compress))}else{[Console]::Out.Write('null')}}finally{$form.Dispose()}
'''


def show_compute_dialog(offer: dict, facts: dict) -> dict | None:
    from .member_registration import MemberRegistrationError, _json_document
    if os.name != 'nt':
        raise MemberRegistrationError('native_compute_dialog_requires_windows')
    scope=offer['scope']
    cpu=min(scope['max_cpus'],facts['total_cpus'])
    trust=scope.get('admission_policy')=='trust_first'
    if trust:
        cpu=min(cpu,facts['total_cpus']*75//100)
    if cpu<1:
        raise MemberRegistrationError('shared_cpu_budget_exhausted')
    memory=min(scope['max_memory_mb'],facts['total_memory_mb'])
    from zoneinfo import available_timezones
    common=['Asia/Shanghai','America/Los_Angeles','UTC']
    choices=common+sorted(available_timezones()-set(common))
    # An explicit choice avoids guessing from a translated Windows zone name.
    payload={'project_summary':'\r\n'.join(project+'：'+', '.join(profiles) for project,profiles in scope['project_profiles'].items()),
        'expires_at':offer['expires_at'],'max_cpus':cpu,'max_memory_mb':memory,
        'admission_notice':('你同意后，机器就绪即可接活；实际验收异步补。共享机调度线程预算至少保留 25%。' if trust
            else '只有你同意且机器通过实际验收后，才会接收下面范围内的计算任务。'),
        'total_memory_mb':facts['total_memory_mb'],'default_cpus':max(1,min(cpu,facts['total_cpus']//2)),
        'default_memory_mb':max(256,min(memory,facts['total_memory_mb']//2)),
        'default_reserve_mb':min(4096,facts['total_memory_mb']//4),'timezones':choices}
    encoded=base64.b64encode(DIALOG_SCRIPT.encode('utf-16-le')).decode('ascii')
    try:
        result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-STA','-EncodedCommand',encoded],
            input=json.dumps(payload,ensure_ascii=True).encode('ascii'),capture_output=True,timeout=1800,check=False)
        if result.returncode or len(result.stdout)>16384:
            raise MemberRegistrationError('compute_dialog_unavailable')
        if result.stdout.strip()==b'null':
            return None
        # Answers contain fixed fields and IANA ASCII timezone names, no secrets.
        value=_json_document(result.stdout)
        if value is not None and not isinstance(value,dict):
            raise MemberRegistrationError('invalid_compute_dialog_result')
        return value
    except (OSError,ValueError,subprocess.SubprocessError):
        raise MemberRegistrationError('compute_dialog_unavailable') from None
