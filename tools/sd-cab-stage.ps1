<#
.SYNOPSIS
  Stage the payload cabinet members under one folder with a fixed file time (04 section 12.2).

.DESCRIPTION
  makecab stores each member's date and time in the cabinet, so building straight from the build
  outputs makes the CAB - and the PAYLOAD_TABLE hash shelldrive-setup.exe embeds - depend on the
  build clock. This script copies every member into the stage folder under its cabinet name and
  stamps the copy with the fixed epoch, so two builds of the same tree produce byte-identical
  cabinets.

.PARAMETER StageDir
  Folder to copy the members into (created when missing).

.PARAMETER Epoch
  UNIX time (seconds) written as the copies' creation and last-write time.

.PARAMETER Members
  One string of "source path;cabinet name" pairs, "|" between pairs; the cabinet name may contain a
  subfolder ("x86\file.dll"). ("|" cannot appear in a Windows file name, so it is a safe delimiter.)

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File tools\sd-cab-stage.ps1 -StageDir build\payload\stage -Epoch 315619200 -Members "build\bin\Release\shelldrive.exe;shelldrive.exe|build\bin\Release\shelldrive-ui.exe;shelldrive-ui.exe"
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$StageDir,
  [Parameter(Mandatory = $true)][long]$Epoch,
  [Parameter(Mandatory = $true)][string]$Members
)

$ErrorActionPreference = 'Stop'
$stamp = [DateTimeOffset]::FromUnixTimeSeconds($Epoch).UtcDateTime
New-Item -ItemType Directory -Force $StageDir | Out-Null
# A stale member of another configuration would ride along into this cabinet: start empty.
Get-ChildItem $StageDir -Force | Remove-Item -Recurse -Force -Confirm:$false
foreach ($m in $Members -split '\|') {
  if ($m -eq '') { continue }
  $pair = $m -split ';', 2
  if ($pair.Count -ne 2 -or $pair[0] -eq '' -or $pair[1] -eq '') {
    throw "member must be source;cabinet-name: $m"
  }
  $dst = Join-Path $StageDir $pair[1]
  New-Item -ItemType Directory -Force (Split-Path -Parent $dst) | Out-Null
  Copy-Item $pair[0] $dst -Force
  $item = Get-Item $dst
  $item.CreationTimeUtc = $stamp
  $item.LastWriteTimeUtc = $stamp
}
