# Stops the WSL fixture sshd (see stop.sh).
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File tests\fixtures\wsl-sshd\stop.ps1 [-Purge] [-Distro Ubuntu-24.04]
param([switch]$Purge, [string]$Distro = '')
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$wslArgs = @()
if ($Distro) { $wslArgs += @('-d', $Distro) }
$winPath = $here.Replace([char]92, [char]47)
$wslPath = (& wsl.exe @wslArgs -e wslpath -a $winPath | Out-String).Trim()
$extra = @()
if ($Purge) { $extra += '--purge' }
& wsl.exe @wslArgs -e sh "$wslPath/stop.sh" @extra
exit $LASTEXITCODE
