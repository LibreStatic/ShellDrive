<#
.SYNOPSIS
  Creates the Hyper-V lab VMs from user-supplied disks or ISOs, or takes their "base" checkpoint.

.DESCRIPTION
  For each VM in the lab config (or only -Name): COM1 on the named pipe
  \\.\pipe\sd-lab-<name> (read by Read-LabSerial.ps1; Set-VMComPort works on both generations),
  standard checkpoints, no automatic checkpoints. The config's Generation field selects the VM
  generation (1 by default; Windows 11 and Server 2022 use 2 with Secure Boot, and Windows 11
  also with a virtual TPM via Tpm = $true). CompatOlderOs = $true limits the guest's CPUID set
  (generation 1 only; off by default, set it for XP).
  With BaseVhdx a differencing disk is created on top of it (the base image is never written).
  Without it, a 20 GB dynamic disk is created and InstallIso is attached for a manual Windows setup.

  First-time workflow per VM (04 section 11.4):
    1. New-LabVM.ps1 -Config lab.psd1 -Name <vm>
    2. New-PayloadIso.ps1 -Flavours x86-ia32 -OutIso <iso>; attach it (Set-VMDvdDrive), boot the VM and
       run \sdlab\install-runner.cmd inside the guest as an administrator; shut the guest down.
    3. New-LabVM.ps1 -Config lab.psd1 -Name <vm> -Checkpoint     (takes the "base" checkpoint)
  Afterwards Invoke-SdLab.ps1 restores "base" before every run.

  Needs an elevated shell (or membership in "Hyper-V Administrators"). Downloads nothing.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tests\lab\New-LabVM.ps1 -Config D:\sdlab\lab.psd1
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)] [string]$Config,
  [string[]]$Name,
  [switch]$Checkpoint
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'SdLab.psm1') -Force
Assert-HyperV
$cfg = Import-LabConfig $Config
$vms = @($cfg.VMs | Where-Object { -not $Name -or $Name -contains $_.Name })
if (-not $vms) { throw 'No matching VM in the lab config.' }

foreach ($v in $vms) {
  $pipe = Get-LabPipeName $v.Name
  if ($Checkpoint) {
    $vm = Get-VM -Name $v.Name
    if ($vm.State -ne 'Off') { throw "$($v.Name) is $($vm.State); shut the guest down first." }
    Get-VMSnapshot -VM $vm -Name base -ErrorAction SilentlyContinue | Remove-VMSnapshot
    Set-VMDvdDrive -VMName $v.Name -Path $null
    Checkpoint-VM -VM $vm -SnapshotName base
    Write-Host "$($v.Name): checkpoint 'base' taken."
    continue
  }
  if (Get-VM -Name $v.Name -ErrorAction SilentlyContinue) { Write-Host "$($v.Name) exists, skipped."; continue }
  $dir = Join-Path $cfg.LabRoot "vms\$($v.Name)"
  New-Item -ItemType Directory -Force $dir | Out-Null
  $disk = Join-Path $dir 'system.vhdx'
  if ($v.BaseVhdx) {
    if (-not (Test-Path -LiteralPath $v.BaseVhdx)) { throw "$($v.Name): BaseVhdx '$($v.BaseVhdx)' not found." }
    New-VHD -Path $disk -ParentPath $v.BaseVhdx -Differencing | Out-Null
  } elseif ($v.InstallIso) {
    if (-not (Test-Path -LiteralPath $v.InstallIso)) { throw "$($v.Name): InstallIso '$($v.InstallIso)' not found." }
    New-VHD -Path $disk -SizeBytes 20GB -Dynamic | Out-Null
  } else {
    throw "$($v.Name): set BaseVhdx or InstallIso in the lab config."
  }
  $gen = 1
  if ($v.ContainsKey('Generation')) { $gen = [int]$v.Generation }
  if ($gen -ne 1 -and $gen -ne 2) { throw "$($v.Name): Generation must be 1 or 2." }
  $wantTpm = $false
  if ($v.ContainsKey('Tpm')) { $wantTpm = [bool]$v.Tpm }
  if ($wantTpm -and $gen -ne 2) { throw "$($v.Name): Tpm needs Generation 2." }
  $vm = New-VM -Name $v.Name -Generation $gen -MemoryStartupBytes ([int64]$v.MemoryMB * 1MB) -VHDPath $disk -Path $dir
  Set-VM -VM $vm -CheckpointType Standard -AutomaticStopAction TurnOff -AutomaticCheckpointsEnabled $false
  Set-VMMemory -VM $vm -DynamicMemoryEnabled $false
  $wantCompat = $false
  if ($v.ContainsKey('CompatOlderOs')) { $wantCompat = [bool]$v.CompatOlderOs }
  if ($wantCompat -and $gen -ne 1) { throw "$($v.Name): CompatOlderOs needs Generation 1." }
  # Reduced CPUID set, opt-in per VM: only pre-Windows 7 guests (XP) need it.
  Set-VMProcessor -VM $vm -Count $v.Cpus -CompatibilityForOlderOperatingSystemsEnabled $wantCompat
  Get-VMNetworkAdapter -VM $vm | Remove-VMNetworkAdapter
  if ($cfg.SwitchName) {
    if ($gen -eq 1) {
      # XP has no synthetic NIC driver: use the emulated DEC 21140 adapter.
      Add-VMNetworkAdapter -VM $vm -SwitchName $cfg.SwitchName -IsLegacy $true
    } else {
      Add-VMNetworkAdapter -VM $vm -SwitchName $cfg.SwitchName
    }
  }
  Set-VMComPort -VM $vm -Number 1 -Path "\\.\pipe\$pipe"
  if (-not (Get-VMDvdDrive -VM $vm)) {
    if ($gen -eq 1) { Add-VMDvdDrive -VM $vm -ControllerNumber 1 -ControllerLocation 0 }
    else { Add-VMDvdDrive -VM $vm }
  }
  if (-not $v.BaseVhdx) {
    Set-VMDvdDrive -VMName $v.Name -Path $v.InstallIso
    # Fresh install: boot the setup ISO first.
    if ($gen -eq 1) { Set-VMBios -VM $vm -StartupOrder @('CD', 'IDE', 'LegacyNetworkAdapter', 'Floppy') }
    else {
      $dvd = Get-VMDvdDrive -VM $vm
      Set-VMFirmware -VM $vm -FirstBootDevice $dvd
    }
  }
  if ($gen -eq 2) {
    # 04 section 11.4: Server 2022 with Secure Boot; Windows 11 also with a virtual TPM.
    Set-VMFirmware -VM $vm -EnableSecureBoot On -SecureBootTemplate MicrosoftWindows
    if ($wantTpm) {
      Set-VMKeyProtector -VM $vm -NewLocalKeyProtector
      Enable-VMTPM -VM $vm
    }
  }
  Write-Host "$($v.Name): created (generation $gen), COM1 = \\.\pipe\$pipe. Next: install-runner.cmd in the guest, then -Checkpoint."
}
