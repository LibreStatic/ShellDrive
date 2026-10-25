<#
.SYNOPSIS
  Restores a lab VM to its "base" checkpoint, attaches a payload ISO and optionally starts it.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tests\lab\Restore-LabVM.ps1 -Name sd-xp-sp3-x86 -Iso D:\sdlab\payload.iso -Start
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)] [string]$Name,
  [string]$Iso,
  [switch]$Start
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'SdLab.psm1') -Force
Assert-HyperV
$vm = Get-VM -Name $Name
if ($vm.State -ne 'Off') { Stop-VM -VM $vm -TurnOff -Force }
$snap = Get-VMSnapshot -VM $vm -Name base -ErrorAction SilentlyContinue
if (-not $snap) { throw "$Name has no 'base' checkpoint (New-LabVM.ps1 -Checkpoint)." }
Restore-VMSnapshot -VMSnapshot $snap -Confirm:$false
if ($Iso) { Set-VMDvdDrive -VMName $Name -Path (Resolve-Path -LiteralPath $Iso).Path }
if ($Start) { Start-VM -VM $vm }
$what = "$Name restored to 'base'"
if ($Iso) { $what += " with $Iso" }
if ($Start) { $what += ', started' }
Write-Host "$what."
