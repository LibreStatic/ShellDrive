<#
.SYNOPSIS
  One lab smoke run per VM: payload ISO -> restore "base" -> boot -> read COM1 -> judge -> power off.

.DESCRIPTION
  Hyper-V VMs come from the lab config's VMs list; the config's Qemu entry (by -Name) runs the QEMU
  Pentium III VM instead (no SSE2: x86-sse2 must refuse to start, x86-ia32 must run). Transcripts go to
  <LabRoot>\logs\<vm>-<timestamp>.log. Exit code 0 only if every selected VM passed.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tests\lab\Invoke-SdLab.ps1 -Config D:\sdlab\lab.psd1
  powershell -ExecutionPolicy Bypass -File tests\lab\Invoke-SdLab.ps1 -Config D:\sdlab\lab.psd1 -Name sd-p3-xp -IncludeTests
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)] [string]$Config,
  [string[]]$Name,
  [string]$BuildRoot,
  [switch]$IncludeTests,
  [int]$TimeoutSec = 1800
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'SdLab.psm1') -Force
$cfg = Import-LabConfig $Config
if (-not $BuildRoot) { $BuildRoot = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'build' }
$all = @($cfg.VMs)
if ($cfg.ContainsKey('Qemu')) { $all += $cfg.Qemu }
$sel = @($all | Where-Object { -not $Name -or $Name -contains $_.Name })
if (-not $sel) { throw 'No matching VM in the lab config.' }
$logs = Join-Path $cfg.LabRoot 'logs'
New-Item -ItemType Directory -Force $logs | Out-Null

$summary = @()
foreach ($v in $sel) {
  $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
  $iso = Join-Path $cfg.LabRoot "payload-$($v.Name).iso"
  $log = Join-Path $logs "$($v.Name)-$stamp.log"
  $isQemu = $cfg.ContainsKey('Qemu') -and $v.Name -eq $cfg.Qemu.Name
  Write-Host "== $($v.Name)"
  $proc = $null
  try {
    New-LabPayload -Flavours $v.Flavours -OutIso $iso -BuildRoot $BuildRoot -IncludeTests:$IncludeTests -ExpectSse2 $v.ExpectSse2
    if ($isQemu) {
      $proc = & (Join-Path $PSScriptRoot 'qemu\Start-QemuPentium3.ps1') -Config $Config -Iso $iso -PassThru
    } else {
      & (Join-Path $PSScriptRoot 'Restore-LabVM.ps1') -Name $v.Name -Iso $iso -Start
    }
    $lines = Read-LabSerialPipe -PipeName (Get-LabPipeName $v.Name) -TimeoutSec $TimeoutSec -LogPath $log
    $verdict = Test-LabTranscript -Lines $lines -ExpectSse2 $v.ExpectSse2
  } catch {
    $verdict = [pscustomobject]@{ Passed = $false; Results = 0; Failures = @($_.Exception.Message) }
  } finally {
    if ($isQemu) {
      if ($proc -and -not $proc.HasExited) {
        if (-not $proc.WaitForExit(60000)) { $proc.Kill() }
      }
    } else {
      $vm = Get-VM -Name $v.Name -ErrorAction SilentlyContinue
      if ($vm) {
        $until = (Get-Date).AddSeconds(60)
        while ($vm.State -ne 'Off' -and (Get-Date) -lt $until) { Start-Sleep -Seconds 2; $vm = Get-VM -Name $v.Name }
        if ($vm.State -ne 'Off') { Stop-VM -VM $vm -TurnOff -Force }
      }
    }
  }
  $verdict.Failures | ForEach-Object { Write-Host "  FAIL: $_" }
  $result = 'FAIL'
  if ($verdict.Passed) { $result = 'pass' }
  $summary += [pscustomobject]@{ VM = $v.Name; Result = $result; Results = $verdict.Results; Log = $log }
}
$summary | Format-Table -AutoSize | Out-Host
if ($summary | Where-Object Result -ne 'pass') { exit 1 }
exit 0
