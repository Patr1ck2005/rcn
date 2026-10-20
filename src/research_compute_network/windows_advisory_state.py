"""Self-contained PowerShell snapshot writer for non-authoritative guard state.

Callers already serialize their own state with the guard lock. A reader denying
rename must not kill the recovery loop. Configuration, identities, stop markers
and installation journals MUST NOT use this best-effort writer.
"""

ADVISORY_STATE_SCRIPT = r'''# RCN advisory state writer begin
function Write-RcnAdvisoryState([string]$Path,[byte[]]$Bytes,[int]$BudgetMs=2000){
 if($Bytes.Length -gt 65536 -or $BudgetMs -lt 50 -or $BudgetMs -gt 5000){throw 'Invalid advisory state bounds'}
 $parent=[IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Path))
 $check=$parent
 while($check){
  if(-not(Test-Path -LiteralPath $check -PathType Container) -or ((Get-Item -LiteralPath $check -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Invalid advisory state parent'}
  $check=[IO.Path]::GetDirectoryName($check)
 }
 $temporary=$Path+'.'+[Guid]::NewGuid().ToString('N')+'.tmp'
 try{
  $stream=[IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try{$stream.Write($Bytes,0,$Bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
  $clock=[Diagnostics.Stopwatch]::StartNew()
  while($true){
   if(Test-Path -LiteralPath $Path){
    $item=Get-Item -LiteralPath $Path -Force
    if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Invalid advisory state target'}
   }
   try{
    if([IO.File]::Exists($Path)){[IO.File]::Replace($temporary,$Path,[NullString]::Value)}else{[IO.File]::Move($temporary,$Path)}
    return $true
   }catch{
    $failure=$_.Exception
    while($failure.InnerException){$failure=$failure.InnerException}
    $code=$failure.HResult -band 65535
    if($code -notin @(2,5,32,33,80,183)){throw}
    if($clock.ElapsedMilliseconds -ge $BudgetMs){
     # Retain the last complete snapshot and its OLD timestamp. The next loop
     # tries again. Never clear a security/intentional-stop marker to log status.
     [Console]::Error.WriteLine('rcn-advisory-state-write-deferred')
     return $false
    }
    Start-Sleep -Milliseconds 50
   }
  }
 }finally{
  if([IO.File]::Exists($temporary)){[IO.File]::Delete($temporary)}
 }
}
# RCN advisory state writer end
'''
