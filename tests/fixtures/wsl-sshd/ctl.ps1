# Fault injection for the WSL fixture sshd (see ctl.sh): kill | start | restart | drop | freeze | reap | thaw | status.
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File tests\fixtures\wsl-sshd\ctl.ps1 kill [-Distro Ubuntu-24.04]
param([Parameter(Position = 0)][string]$Command = 'status', [string]$Distro = '')
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$wslArgs = @()
if ($Distro) { $wslArgs += @('-d', $Distro) }
$winPath = $here.Replace([char]92, [char]47)
$wslPath = (& wsl.exe @wslArgs -e wslpath -a $winPath | Out-String).Trim()
& wsl.exe @wslArgs -e sh "$wslPath/ctl.sh" $Command
exit $LASTEXITCODE
