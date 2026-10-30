# Builds OpenSSH 10.x inside WSL (see build.sh). Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File tests\fixtures\openssh10\build.ps1 [-Force] [-Distro <name>]
param([switch]$Force, [string]$Distro = '')
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$wslArgs = @()
if ($Distro) { $wslArgs += @('-d', $Distro) }
$wslPath = (& wsl.exe @wslArgs -e wslpath -a $here.Replace([char]92, [char]47) | Out-String).Trim()
$envPrefix = @()
if ($Force) { $envPrefix = @('env', 'SD_OSSH_FORCE=1') }
& wsl.exe @wslArgs -e @envPrefix sh "$wslPath/build.sh"
exit $LASTEXITCODE
