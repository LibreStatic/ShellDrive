<#
.SYNOPSIS
  Local CI: the same build/test matrix as .github/workflows/ci.yml, plus the interop (WSL sshd/sftp-server)
  and Dokany tests that hosted runners cannot run.

.DESCRIPTION
  For each preset: configure (from a clean build dir with -Clean), build Release (and Debug where the preset
  has one), run ctest. Starts the WSL sshd fixture if it is not running. Fails when an interop or dokany test is
  skipped, unless -AllowSkip is given (the x86 presets always skip dokany.* under WOW64; that is reported,
  not failed). Writes a JUnit file per preset under build\ci-local\.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tools\ci-local.ps1
  powershell -ExecutionPolicy Bypass -File tools\ci-local.ps1 -Presets x64-modern -Clean
#>
[CmdletBinding()]
param(
  [string[]]$Presets = @('x64-modern', 'x64-xp', 'x86-ia32', 'x86-sse2', 'x64-analysis'),
  [switch]$Clean,
  [switch]$AllowSkip,
  [switch]$NoFixture
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Find-CMakeBin {
  $cmd = Get-Command cmake.exe -ErrorAction SilentlyContinue
  if ($cmd) { return Split-Path -Parent $cmd.Source }
  $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
  if (-not (Test-Path $vswhere)) { throw 'vswhere.exe not found; install VS 2022 Build Tools' }
  $vs = & $vswhere -latest -products * -property installationPath
  $bin = Join-Path $vs 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin'
  if (-not (Test-Path (Join-Path $bin 'cmake.exe'))) { throw "cmake.exe not found under $bin" }
  return $bin
}

$bin = Find-CMakeBin
$cmake = Join-Path $bin 'cmake.exe'
$ctest = Join-Path $bin 'ctest.exe'
$out = Join-Path $root 'build\ci-local'
New-Item -ItemType Directory -Force $out | Out-Null

if (-not $NoFixture) {
  $start = Join-Path $root 'tests\fixtures\wsl-sshd\start.ps1'
  if (Test-Path $start) {
    Write-Host '== Starting the WSL sshd fixture (no-op if already running)'
    & powershell -NoProfile -ExecutionPolicy Bypass -File $start | Out-Host
  }
}

$results = @()
foreach ($preset in $Presets) {
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $status = 'pass'
  $note = ''
  try {
    $dir = Join-Path $root "build\$preset"
    if ($Clean -and (Test-Path $dir)) {
      # A scanner or a test process that is just exiting can hold a file for a moment; retry before failing.
      for ($try = 1; ; $try++) {
        try { Remove-Item -Recurse -Force $dir -ErrorAction Stop; break }
        catch { if ($try -ge 5) { throw }; Start-Sleep -Seconds 5 }
      }
    }

    Write-Host "== [$preset] configure"
    & $cmake --preset $preset | Out-Host
    if ($LASTEXITCODE) { throw 'configure failed' }

    $configs = @($preset)
    $listing = & $cmake --list-presets=build 2>$null
    if ($listing -match "`"$preset-debug`"") { $configs += "$preset-debug" }

    foreach ($cfg in $configs) {
      Write-Host "== [$cfg] build"
      $log = & { $ErrorActionPreference = 'Continue'; & $cmake --build --preset $cfg 2>&1 }
      $log | Out-Host
      if ($LASTEXITCODE) { throw "build $cfg failed" }
      $warn = @($log | Select-String -Pattern ' (warning|error) [A-Z]+[0-9]+').Count
      if ($warn) { throw "build $cfg reported $warn warnings/errors" }

      Write-Host "== [$cfg] test"
      $junit = Join-Path $out "ctest-$cfg.xml"
      # Windows PowerShell 5.1 turns native stderr into error records, which 'Stop' would throw on before the
      # failing tests are printed; judge by the exit code instead. -LE matrix excludes the srv_* interop
      # tests: they need the per-row matrix fixtures and are run by tests\interop\run-matrix.ps1.
      # -LE also excludes the opt-in benchmarks (bench.vfs_pool needs SD_IT_BENCH=1 and the fixture; run by
      # hand). One expression: ctest's repeated -LE flags replace rather than accumulate.
      $tlog = & { $ErrorActionPreference = 'Continue'; & $ctest --preset $cfg --output-on-failure --output-junit $junit -LE 'matrix|bench|repro' 2>&1 }
      $tlog | Out-Host
      if ($LASTEXITCODE) { throw "tests $cfg failed" }
      $skipped = @($tlog | Select-String -Pattern '\*\*\*Skipped' | ForEach-Object { ($_ -split ':')[1].Trim().Split(' ')[0] })
      if ($preset -like 'x86-*') {
        # Expected: the x86 test binaries run under WOW64, where sd_dokan refuses to mount (02 section 6.1).
        $wow = @($skipped | Where-Object { $_ -like 'dokany.*' })
        if ($wow.Count) { $note += "skipped under WOW64 in ${cfg}: $($wow -join ', '); " }
        $skipped = @($skipped | Where-Object { $_ -notlike 'dokany.*' })
      }
      if ($skipped.Count -and -not $AllowSkip) { throw "tests $cfg skipped: $($skipped -join ', ')" }
      if ($skipped.Count) { $note += "skipped in ${cfg}: $($skipped -join ', '); " }
    }
  } catch {
    $status = 'FAIL'
    $note += $_.Exception.Message
  }
  $sw.Stop()
  $results += [pscustomobject]@{ Preset = $preset; Result = $status; Minutes = [math]::Round($sw.Elapsed.TotalMinutes, 1); Note = $note }
}

Write-Host ''
$results | Format-Table -AutoSize | Out-Host
if ($results | Where-Object Result -ne 'pass') { exit 1 }
exit 0
