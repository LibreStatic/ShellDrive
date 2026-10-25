# Fault injection for the WSL fixture sshd (see ctl.sh): kill | start | restart | drop | freeze | reap | thaw | status.
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File tests\fixtures\wsl-sshd\ctl.ps1 kill [-Instance ossh10] [-Distro Ubuntu-24.04]
# -Instance names an M2 fixture instance (tests\fixtures\matrix\README.md); default: this M1 fixture ("modern").
param([Parameter(Position = 0)][string]$Command = 'status', [Parameter(Position = 1)][string]$Instance = 'modern',
      [string]$Distro = '')
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$wslArgs = @()
if ($Distro) { $wslArgs += @('-d', $Distro) }
$winPath = $here.Replace([char]92, [char]47)
$wslPath = (& wsl.exe @wslArgs -e wslpath -a $winPath | Out-String).Trim()
& wsl.exe @wslArgs -e sh "$wslPath/ctl.sh" $Command $Instance
exit $LASTEXITCODE
