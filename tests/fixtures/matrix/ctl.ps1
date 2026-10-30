# Drives the M2 fixture set inside WSL (see fixture.sh): start | stop | status | env | rotate | otp-code | otp-pam |
# selftest | kill | drop | freeze | thaw | reap | restart, with the same arguments as fixture.sh.
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File tests\fixtures\matrix\ctl.ps1 start [ossh10 ...] [-Distro <name>]
[CmdletBinding(PositionalBinding = $false)]
param([string]$Distro = '', [Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest)
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$wslArgs = @()
if ($Distro) { $wslArgs += @('-d', $Distro) }
$wslPath = (& wsl.exe @wslArgs -e wslpath -a $here.Replace([char]92, [char]47) | Out-String).Trim()
if (-not $Rest -or $Rest.Count -eq 0) { $Rest = @('status') }
if ($Rest[0] -eq 'selftest') {
  & wsl.exe @wslArgs -e sh "$wslPath/selftest.sh"
} else {
  & wsl.exe @wslArgs -e sh "$wslPath/fixture.sh" @Rest
}
exit $LASTEXITCODE
