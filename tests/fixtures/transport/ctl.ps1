# Runs tests/fixtures/transport/fixture.sh inside WSL (default distribution; SD_WSL_DISTRO overrides it).
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File tests\fixtures\transport\ctl.ps1 start|stop|status [args]
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$wslArgs = @()
if ($env:SD_WSL_DISTRO) { $wslArgs += @('-d', $env:SD_WSL_DISTRO) }
$wslPath = (& wsl.exe @wslArgs -e wslpath -a ($here.Replace([char]92, [char]47)) | Out-String).Trim()
& wsl.exe @wslArgs -e sh "$wslPath/fixture.sh" @args
exit $LASTEXITCODE
