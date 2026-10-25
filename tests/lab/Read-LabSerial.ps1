<#
.SYNOPSIS
  Host-side COM1 reader: connects to a VM's serial named pipe and prints/logs the smoke transcript
  until "SDLAB END", the guest powering off, or the timeout. Exit code 0 when the transcript passes.

.DESCRIPTION
  Hyper-V: the pipe is the VM's COM1 (Set-VMComPort \\.\pipe\sd-lab-<vm>, set by New-LabVM.ps1).
  QEMU: -serial pipe:sd-lab-<vm> (qemu\Start-QemuPentium3.ps1). One client at a time.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tests\lab\Read-LabSerial.ps1 -Name sd-xp-sp3-x86 -LogPath D:\sdlab\logs\xp.log
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)] [string]$Name,
  [int]$TimeoutSec = 900,
  [string]$LogPath,
  [ValidateSet(-1, 0, 1)] [int]$ExpectSse2 = -1    # 1 = CPU has SSE2, 0 = it does not, -1 = do not judge
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'SdLab.psm1') -Force
$lines = Read-LabSerialPipe -PipeName (Get-LabPipeName $Name) -TimeoutSec $TimeoutSec -LogPath $LogPath
$verdict = Test-LabTranscript -Lines $lines -ExpectSse2 $(if ($ExpectSse2 -lt 0) { $null } else { [bool]$ExpectSse2 })
if ($verdict.Passed) { Write-Host "PASS ($($verdict.Results) results)"; exit 0 }
$verdict.Failures | ForEach-Object { Write-Host "FAIL: $_" }
exit 1
