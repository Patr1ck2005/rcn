"""Read-only local COMSOL 6.4 discovery for self-service member onboarding.

The member proposes only an observed local install root. The center later binds the
proposal into the signed bootstrap request and independently verifies it over SSH
before any compute admission. No installer, license, registry or environment state
is changed here.
"""
from __future__ import annotations

from pathlib import PureWindowsPath
import json
import os
import re
import subprocess

from . import member_registration as storage
from .member_ssh_service import _powershell

VERSION = "6.4"

DISCOVERY_SCRIPT = r"""
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$candidates=[Collections.Generic.List[string]]::new()
foreach($exe in @(
 'C:\Program Files\COMSOL\COMSOL64\Multiphysics\bin\win64\comsol.exe',
 'D:\Program Files\COMSOL\COMSOL64\Multiphysics\bin\win64\comsol.exe',
 'D:\Program Files\COMSOL64\Multiphysics\bin\win64\comsol.exe',
 'E:\Program Files\COMSOL\COMSOL64\Multiphysics\bin\win64\comsol.exe',
 'F:\Program Files\COMSOL\COMSOL64\Multiphysics\bin\win64\comsol.exe'
)){if($seen.Add($exe)){$candidates.Add($exe)}}
foreach($key in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')){
 Get-ItemProperty $key -ErrorAction SilentlyContinue | Where-Object {
   [string]$_.DisplayName -like 'COMSOL Multiphysics*6.4*' -and [string]$_.InstallLocation
 } | ForEach-Object {
   try{$exe=Join-Path ([IO.Path]::GetFullPath([string]$_.InstallLocation)) 'Multiphysics\bin\win64\comsol.exe'
       if($seen.Add($exe)){$candidates.Add($exe)}}catch{}
 }
}
$result=@()
foreach($exe in $candidates){
 if(-not(Test-Path -LiteralPath $exe -PathType Leaf)){continue}
 $p=[IO.Path]::GetFullPath($exe);$a=$p
 while($a){if((Get-Item -LiteralPath $a -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked COMSOL path'};$a=[IO.Path]::GetDirectoryName($a)}
 $version=[string](Get-Item -LiteralPath $p).VersionInfo.ProductVersion
 if($version -notmatch '^6\.4(?:\.|$)'){continue}
 $suffix='\Multiphysics\bin\win64\comsol.exe'
 if(-not $p.EndsWith($suffix,[StringComparison]::OrdinalIgnoreCase)){continue}
 $root=$p.Substring(0,$p.Length-$suffix.Length)
 $result += [ordered]@{root=$root;version='6.4';executable=$p}
}
@{schema_version=1;candidates=@($result)} | ConvertTo-Json -Depth 5 -Compress
"""


def _validate(item: dict) -> dict:
    if not isinstance(item, dict) or set(item) != {"root", "version", "executable"} or item["version"] != VERSION:
        raise ValueError("invalid COMSOL discovery")
    root = PureWindowsPath(str(item["root"]))
    exe = PureWindowsPath(str(item["executable"]))
    if (not root.is_absolute() or ".." in root.parts or root.name.casefold() != "comsol64"
            or exe != root / "Multiphysics" / "bin" / "win64" / "comsol.exe"):
        raise ValueError("invalid COMSOL discovery")
    return {"comsol_root": str(root), "comsol_version": VERSION}


def discover_comsol() -> dict:
    if os.name != "nt":
        raise storage.MemberRegistrationError("member_comsol_requires_windows")
    try:
        completed = subprocess.run([_powershell(), "-NoProfile", "-NonInteractive", "-Command", DISCOVERY_SCRIPT],
                                   capture_output=True, timeout=20, check=False)
        if completed.returncode or len(completed.stdout) > 32768:
            raise ValueError("COMSOL discovery failed")
        document = storage._json_document(completed.stdout)
        if (set(document) != {'schema_version','candidates'} or type(document['schema_version']) is not int
                or document['schema_version'] != 1 or not isinstance(document['candidates'], list)):
            raise ValueError("COMSOL discovery shape")
        items = document['candidates']
        valid = []
        seen = set()
        for item in items:
            value = _validate(item)
            folded = value["comsol_root"].casefold()
            if folded not in seen:
                seen.add(folded); valid.append(value)
        if not valid:
            raise storage.MemberRegistrationError("member_comsol_64_not_detected")
        # Deterministic fixed/registry order. A later center SSH preflight rechecks
        # the exact signed path before any scientific execution is permitted.
        return {**valid[0], "candidate_count": len(valid), "grants_execution": False}
    except storage.MemberRegistrationError:
        raise
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError, json.JSONDecodeError):
        raise storage.MemberRegistrationError("member_comsol_discovery_unconfirmed") from None
