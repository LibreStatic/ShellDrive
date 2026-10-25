<#
.SYNOPSIS
  Builds the payload ISO for a lab run: the guest smoke scripts plus the Release binaries of the
  given flavours (and, with -IncludeTests, their unit-test executables).

.DESCRIPTION
  Uses oscdimg.exe (Windows ADK "Deployment Tools") when it is on PATH or in the default ADK folder,
  otherwise the IMAPI2 file-system COM objects that ship with Windows. ISO 9660 + Joliet, readable by
  XP. Layout: \sdlab\ (smoke.cmd, sysinfo.vbs, install-runner.cmd, sdlab-runner.cmd, expect.txt),
  \<flavour>\ (shelldrive.exe, shelldrive-host.exe), \<flavour>\tests\ (sd-test-*.exe without the
  interop and Dokany tests).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tests\lab\New-PayloadIso.ps1 -Flavours x86-ia32,x86-sse2 -OutIso D:\sdlab\payload.iso -IncludeTests
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)] [string[]]$Flavours,
  [Parameter(Mandatory)] [string]$OutIso,
  [string]$BuildRoot,
  [ValidateSet('Release', 'Debug')] [string]$Configuration = 'Release',
  [switch]$IncludeTests,
  [ValidateSet(-1, 0, 1)] [int]$ExpectSse2 = -1    # 1 = CPU has SSE2, 0 = it does not, -1 = do not judge
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'SdLab.psm1') -Force
if (-not $BuildRoot) { $BuildRoot = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'build' }
New-LabPayload -Flavours $Flavours -OutIso $OutIso -BuildRoot $BuildRoot -Configuration $Configuration `
  -IncludeTests:$IncludeTests -ExpectSse2 $(if ($ExpectSse2 -lt 0) { $null } else { [bool]$ExpectSse2 })
