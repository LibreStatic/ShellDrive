# Starts the WSL fixture sshd (see start.sh).
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File tests\fixtures\wsl-sshd\start.ps1 [-Distro Ubuntu-24.04]
param([string]$Distro = '')
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$wslArgs = @()
if ($Distro) { $wslArgs += @('-d', $Distro) }
$winPath = $here.Replace([char]92, [char]47)
$wslPath = (& wsl.exe @wslArgs -e wslpath -a $winPath | Out-String).Trim()
& wsl.exe @wslArgs -e sh "$wslPath/start.sh"
exit $LASTEXITCODE
