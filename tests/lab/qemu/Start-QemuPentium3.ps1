<#
.SYNOPSIS
  Boots the lab's no-SSE2 VM: qemu-system-i386 -cpu pentium3 (SSE, no SSE2) with XP SP3 x86, the
  payload ISO and COM1 on \\.\pipe\sd-lab-<name> (read by Read-LabSerial.ps1).

.DESCRIPTION
  The x86-ia32 runtime check of 04 section 11.4: x86-ia32 binaries must run here and x86-sse2 binaries
  must refuse to start through their entry thunk (exit code 0xC000001D) before the CRT runs.

  TCG (software emulation) is used on purpose: hardware accelerators (WHPX, KVM) pass most host CPUID
  bits through, so the guest would see SSE2. -snapshot discards every disk write, so each run starts
  from the same state without checkpoints.

  QEMU is not installed by this repository. Install it yourself, for example:
    winget install --id SoftwareFreedomConservancy.QEMU      (installs to C:\Program Files\qemu)
  or the MSYS2 package mingw-w64-ucrt-x86_64-qemu. Point Qemu.QemuDir in the lab config at the folder
  that contains qemu-system-i386.exe and qemu-img.exe.

  Preparing the disk (once, with YOUR licensed Windows XP Professional SP3 x86 ISO):
    qemu-img create -f qcow2 D:\images\xp-pro-sp3-x86-p3.qcow2 8G
    qemu-system-i386 -M pc -cpu pentium3 -accel tcg -m 512 -hda D:\images\xp-pro-sp3-x86-p3.qcow2 `
      -cdrom D:\images\xp-pro-sp3-x86.iso -boot d -net none
  After setup, boot once more with a payload ISO (-cdrom payload.iso), run \sdlab\install-runner.cmd
  as an administrator and shut down. From then on the disk is only booted with -snapshot (this script).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tests\lab\qemu\Start-QemuPentium3.ps1 -Config D:\sdlab\lab.psd1 -Iso D:\sdlab\payload-sd-p3-xp.iso
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)] [string]$Config,
  [Parameter(Mandatory)] [string]$Iso,
  [switch]$Display,
  [switch]$PassThru
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'SdLab.psm1') -Force
$cfg = Import-LabConfig $Config
if (-not $cfg.ContainsKey('Qemu')) { throw 'The lab config has no Qemu entry.' }
$q = $cfg.Qemu
$exe = Join-Path $q.QemuDir 'qemu-system-i386.exe'
if (-not (Test-Path -LiteralPath $exe)) {
  throw "qemu-system-i386.exe not found in '$($q.QemuDir)'. Install QEMU first (Get-Help $PSCommandPath -Full)."
}
if (-not (Test-Path -LiteralPath $q.Disk)) { throw "QEMU disk '$($q.Disk)' not found (Get-Help $PSCommandPath -Full)." }
$pipe = Get-LabPipeName $q.Name
$isoPath = (Resolve-Path -LiteralPath $Iso).Path
$qemuArgs = @(
  '-M', 'pc', '-cpu', 'pentium3', '-accel', 'tcg', '-m', [string]$q.MemoryMB,
  '-drive', "`"file=$($q.Disk),format=qcow2,if=ide,index=0,media=disk`"",
  '-drive', "`"file=$isoPath,if=ide,index=2,media=cdrom`"",
  '-boot', 'c', '-snapshot', '-net', 'none', '-rtc', 'base=localtime',
  '-serial', "pipe:$pipe", '-no-reboot'
)
if (-not $Display) { $qemuArgs += @('-display', 'none') }
$proc = Start-Process -FilePath $exe -ArgumentList $qemuArgs -PassThru -WindowStyle Hidden
Write-Host "QEMU pid $($proc.Id): $($q.Name) (pentium3, TCG, -snapshot), COM1 = \\.\pipe\$pipe"
if ($PassThru) { return $proc }
