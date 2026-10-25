<#
.SYNOPSIS
  M2 interop matrix: starts the WSL fixtures, runs the interop-labelled CTest set of a build directory once per
  server row (endpoints passed as SD_IT_* environment variables) and prints a feature x server table.

.DESCRIPTION
  Test infrastructure only (decisions.md D21). See tests/interop/README.md and docs/dev/m2-notes.md for the rows,
  the SD_IT_* variables and the label convention:
    - a test labelled  srv_<row>  runs in that row; srv_all  runs in every row;
    - an interop test without any srv_* label runs in the "modern" row only (the M1 behaviour).
  A test that does not apply to the row it is run in exits 77 (CTest SKIP_RETURN_CODE) and shows as "skip".
  Fixtures already running before the script are left running; the ones it started are stopped at the end
  unless -Keep is given. Idempotent: running it twice in a row gives the same result.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File tests\interop\run-matrix.ps1 -BuildDir build\x64-modern
.EXAMPLE
  ... -BuildDir build\x64-modern -Rows ossh10,jump2,socks5-auth -Keep
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$BuildDir,
  [string]$Config = 'Release',
  [string[]]$Rows = @(),
  [string]$Label = 'interop',
  [string]$Ctest = '',
  [string]$Distro = '',
  [switch]$Keep,
  [switch]$NoStart,
  [switch]$NoSelfTest,
  [int]$Timeout = 900
)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$fixM1 = Join-Path $repo 'tests\fixtures\wsl-sshd'
$fixM2 = Join-Path $repo 'tests\fixtures\matrix'
if (-not [IO.Path]::IsPathRooted($BuildDir)) { $BuildDir = Join-Path $repo $BuildDir }
if (-not (Test-Path (Join-Path $BuildDir 'CTestTestfile.cmake'))) { throw "not a CTest build directory: $BuildDir" }
$outDir = Join-Path $BuildDir 'interop-matrix'
New-Item -ItemType Directory -Force $outDir | Out-Null

# ------------------------------------------------------------------ ctest
if (-not $Ctest) {
  $c = Get-Command ctest.exe -ErrorAction SilentlyContinue
  if ($c) { $Ctest = $c.Source }
  else {
    foreach ($ed in @('BuildTools', 'Community', 'Professional', 'Enterprise')) {
      foreach ($pf in @(${env:ProgramFiles(x86)}, $env:ProgramFiles)) {
        $p = Join-Path $pf "Microsoft Visual Studio\2022\$ed\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\ctest.exe"
        if (Test-Path $p) { $Ctest = $p; break }
      }
      if ($Ctest) { break }
    }
  }
  if (-not $Ctest) { throw 'ctest.exe not found; pass -Ctest <path>' }
}

$wslArgs = @()
if ($Distro) { $wslArgs += @('-d', $Distro) }
function Invoke-Wsl([string[]]$argv) { & wsl.exe @wslArgs -e @argv }
function To-WslPath([string]$p) { (& wsl.exe @wslArgs -e wslpath -a $p.Replace([char]92, [char]47) | Out-String).Trim() }
$m1Wsl = To-WslPath $fixM1
$m2Wsl = To-WslPath $fixM2

# ------------------------------------------------------------------ fixtures
function Get-Running {
  $r = @{}
  $m1 = (Invoke-Wsl @('sh', "$m1Wsl/ctl.sh", 'status') | Out-String)
  if ($m1 -match 'listener: \d+') { $r['modern'] = $true }
  foreach ($line in (Invoke-Wsl @('sh', "$m2Wsl/fixture.sh", 'status'))) {
    if ($line -match '^(\S+): running') { $r[$Matches[1]] = $true }
  }
  return $r
}

$before = Get-Running
if (-not $NoStart) {
  Write-Host '== starting fixtures'
  Invoke-Wsl @('sh', "$m1Wsl/start.sh") | Out-Host
  Invoke-Wsl @('sh', "$m2Wsl/fixture.sh", 'start') | Out-Host
} else {
  Invoke-Wsl @('sh', "$m2Wsl/fixture.sh", 'env') | Out-Null
}
$running = Get-Running

$envFile = Join-Path $fixM2 'state\endpoints.env'
if (-not (Test-Path $envFile)) { throw "fixture endpoints missing: $envFile" }
$E = @{}
foreach ($line in Get-Content $envFile) {
  if ($line -match '^(SD_IT_[A-Z0-9_]+)=(.*)$') { $E[$Matches[1]] = $Matches[2] }
}
$m1Env = @{}
if (Test-Path (Join-Path $fixM1 'state\env')) {
  foreach ($line in Get-Content (Join-Path $fixM1 'state\env')) { if ($line -match '^([a-z_]+)=(.*)$') { $m1Env[$Matches[1]] = $Matches[2] } }
}

$selftest = @()
if (-not $NoSelfTest) {
  Write-Host '== fixture self-test (stock OpenSSH clients inside WSL)'
  $selftest = @(Invoke-Wsl @('sh', "$m2Wsl/selftest.sh"))
  $selftest | Where-Object { $_ -notmatch '^PASS ' } | Out-Host
}

# ------------------------------------------------------------------ rows
$h = $E['SD_IT_WIN_HOST']; $u = $E['SD_IT_USER']
$proxyCred = "$($E['SD_IT_PROXY_USER']):$($E['SD_IT_PROXY_PASS'])"
function Row($name, $needs, $vars) { [pscustomobject]@{ Name = $name; Needs = $needs; Vars = $vars } }
$ed = $E['SD_IT_KEY_ED25519']
$allRows = @(
  (Row 'modern' @('modern') @{ SD_IT_HOST = $h; SD_IT_PORT = '2222'; SD_IT_KEY = (Join-Path $fixM1 'state\client_ed25519');
      SD_IT_FEATURES = 'baseline' }),
  (Row 'ossh10' @('ossh10') @{ SD_IT_HOST = $h; SD_IT_PORT = '2230'; SD_IT_KEY = $ed;
      SD_IT_EXPECT_KEX = 'mlkem768x25519-sha256'; SD_IT_FEATURES = 'pq-kex,hostkey-ed25519,hostkey-ecdsa,hostkey-rsa' }),
  (Row 'ossh10pq' @('ossh10pq') @{ SD_IT_HOST = $h; SD_IT_PORT = '2239'; SD_IT_KEY = $ed;
      SD_IT_EXPECT_KEX = 'mlkem768x25519-sha256'; SD_IT_FEATURES = 'pq-kex-only' }),
  (Row 'legacy' @('legacy') @{ SD_IT_HOST = $h; SD_IT_PORT = '2231'; SD_IT_KEY = $E['SD_IT_KEY_RSA'];
      SD_IT_EXPECT_LEGACY = '1'; SD_IT_FEATURES = 'legacy-cbc,legacy-sha1-mac,legacy-md5-mac,legacy-dh-sha1,gex,ssh-rsa-sha1,ssh-dss' }),
  (Row 'legacy3des' @('legacy3des') @{ SD_IT_HOST = $h; SD_IT_PORT = '2238'; SD_IT_KEY = $E['SD_IT_KEY_RSA'];
      SD_IT_EXPECT_LEGACY = '1'; SD_IT_FEATURES = '3des-cbc' }),
  (Row 'cert' @('cert') @{ SD_IT_HOST = $h; SD_IT_PORT = '2235'; SD_IT_KEY = $ed; SD_IT_CERT = $E['SD_IT_CERT_ED25519'];
      SD_IT_FEATURES = 'user-cert,host-cert' }),
  (Row 'rotate' @('rotate') @{ SD_IT_HOST = $h; SD_IT_PORT = '2236'; SD_IT_KEY = $ed; SD_IT_FEATURES = 'hostkeys-00' }),
  (Row 'jump2' @('bastion1', 'target') @{ SD_IT_HOST = '127.0.0.2'; SD_IT_PORT = '2234'; SD_IT_KEY = $ed;
      SD_IT_JUMP = "$u@${h}:2232"; SD_IT_FEATURES = 'proxyjump' }),
  (Row 'jump3' @('bastion1', 'bastion2', 'target') @{ SD_IT_HOST = '127.0.0.2'; SD_IT_PORT = '2234'; SD_IT_KEY = $ed;
      SD_IT_JUMP = "$u@${h}:2232,$u@127.0.0.2:2233"; SD_IT_FEATURES = 'proxyjump' }),
  (Row 'http-proxy' @('ossh10', 'http') @{ SD_IT_HOST = $h; SD_IT_PORT = '2230'; SD_IT_KEY = $ed;
      SD_IT_PROXY = "http://${h}:2280"; SD_IT_FEATURES = 'proxy-http' }),
  (Row 'http-proxy-auth' @('ossh10', 'http-auth') @{ SD_IT_HOST = $h; SD_IT_PORT = '2230'; SD_IT_KEY = $ed;
      SD_IT_PROXY = "http://$proxyCred@${h}:2281"; SD_IT_FEATURES = 'proxy-http,proxy-auth' }),
  (Row 'socks5' @('ossh10', 'socks5') @{ SD_IT_HOST = $h; SD_IT_PORT = '2230'; SD_IT_KEY = $ed;
      SD_IT_PROXY = "socks5://${h}:2290"; SD_IT_FEATURES = 'proxy-socks5' }),
  (Row 'socks5-auth' @('ossh10', 'socks5-auth') @{ SD_IT_HOST = $h; SD_IT_PORT = '2230'; SD_IT_KEY = $ed;
      SD_IT_PROXY = "socks5://$proxyCred@${h}:2291"; SD_IT_FEATURES = 'proxy-socks5,proxy-auth' }),
  (Row 'squid' @('ossh10', 'squid') @{ SD_IT_HOST = $h; SD_IT_PORT = '2230'; SD_IT_KEY = $ed;
      SD_IT_PROXY = "http://$proxyCred@${h}:2282"; SD_IT_FEATURES = 'proxy-http,proxy-auth' }),
  (Row 'dante' @('ossh10', 'dante') @{ SD_IT_HOST = $h; SD_IT_PORT = '2230'; SD_IT_KEY = $ed;
      SD_IT_PROXY = "socks5://${h}:2292"; SD_IT_FEATURES = 'proxy-socks5' }),
  (Row 'otp' @('otp') @{ SD_IT_HOST = $h; SD_IT_PORT = '2237'; SD_IT_KEY = $ed; SD_IT_OTP = '1'; SD_IT_FEATURES = 'kbdint-otp' }),
  # M2 demo (00-integration-review.md 6): SOCKS5 -> OTP bastion -> target with a PPK v3 key, ML-KEM KEX.
  # Without the OTP instance the row uses bastion1 and says so in SD_IT_OTP=0.
  (Row 'demo' @('socks5-auth', 'target') @{ SD_IT_HOST = '127.0.0.2'; SD_IT_PORT = '2234'; SD_IT_KEY = $E['SD_IT_KEY_ED25519_PPK3'];
      SD_IT_JUMP = $(if ($running['otp']) { "$u@${h}:2237" } else { "$u@${h}:2232" });
      SD_IT_OTP = $(if ($running['otp']) { '1' } else { '0' });
      SD_IT_PROXY = "socks5://$proxyCred@${h}:2291"; SD_IT_EXPECT_KEX = 'mlkem768x25519-sha256';
      SD_IT_FEATURES = 'demo,proxy-socks5,proxyjump,ppk3,pq-kex' })
)
if ($Rows.Count -gt 0) {
  $want = @($Rows | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
  $allRows = @($allRows | Where-Object { $want -contains $_.Name })
}

# ------------------------------------------------------------------ tests and labels
$json = (& $Ctest --test-dir $BuildDir -C $Config -L $Label --show-only=json-v1 | Out-String) | ConvertFrom-Json
$tests = @()
foreach ($t in $json.tests) {
  $labels = @()
  foreach ($p in $t.properties) { if ($p.name -eq 'LABELS') { $labels = @($p.value) } }
  $tests += [pscustomobject]@{ Name = $t.name; Labels = $labels }
}
Write-Host "== $($tests.Count) test(s) labelled '$Label' in $BuildDir ($Config)"

function Select-Tests($row) {
  @($tests | Where-Object {
      $srv = @($_.Labels | Where-Object { $_ -like 'srv_*' })
      ($srv -contains "srv_$($row.Name)") -or ($srv -contains 'srv_all') -or ($row.Name -eq 'modern' -and $srv.Count -eq 0)
    } | ForEach-Object { $_.Name })
}

$rowVarNames = @('SD_IT_SERVER', 'SD_IT_HOST', 'SD_IT_PORT', 'SD_IT_KEY', 'SD_IT_CERT', 'SD_IT_JUMP', 'SD_IT_PROXY',
  'SD_IT_EXPECT_KEX', 'SD_IT_EXPECT_LEGACY', 'SD_IT_OTP', 'SD_IT_FEATURES')
$saved = @{}
foreach ($k in $E.Keys) { $saved[$k] = [Environment]::GetEnvironmentVariable($k, 'Process') }
foreach ($k in $rowVarNames) { $saved[$k] = [Environment]::GetEnvironmentVariable($k, 'Process') }
foreach ($k in $E.Keys) { [Environment]::SetEnvironmentVariable($k, $E[$k], 'Process') }
[Environment]::SetEnvironmentVariable('SD_IT_ENV_FILE', $envFile, 'Process')
[Environment]::SetEnvironmentVariable('SD_IT_USER', $u, 'Process')

# results[test][row] = pass|fail|skip|n/a ; rowState[row] = ran|no-tests|fixture-down
$results = @{}
$rowState = [ordered]@{}
try {
  foreach ($row in $allRows) {
    $missing = @($row.Needs | Where-Object { -not $running[$_] })
    if ($missing.Count -gt 0) { $rowState[$row.Name] = "fixture-down ($($missing -join ','))"; continue }
    $names = Select-Tests $row
    if ($names.Count -eq 0) { $rowState[$row.Name] = 'no-tests'; continue }
    foreach ($k in $rowVarNames) { [Environment]::SetEnvironmentVariable($k, $null, 'Process') }
    [Environment]::SetEnvironmentVariable('SD_IT_SERVER', $row.Name, 'Process')
    foreach ($k in $row.Vars.Keys) { [Environment]::SetEnvironmentVariable($k, [string]$row.Vars[$k], 'Process') }
    $list = Join-Path $outDir "$($row.Name).tests"
    $junit = Join-Path $outDir "$($row.Name).junit.xml"
    Set-Content -Path $list -Value $names -Encoding Ascii
    Remove-Item -ErrorAction SilentlyContinue $junit
    Write-Host "== row $($row.Name): $($names.Count) test(s)"
    & $Ctest --test-dir $BuildDir -C $Config --tests-from-file $list --output-junit $junit --timeout $Timeout `
      --output-on-failure *> (Join-Path $outDir "$($row.Name).log")
    $rowState[$row.Name] = 'ran'
    foreach ($n in $names) { if (-not $results[$n]) { $results[$n] = @{} }; $results[$n][$row.Name] = 'fail' }
    if (Test-Path $junit) {
      [xml]$x = Get-Content -Raw $junit
      foreach ($tc in $x.SelectNodes('//testcase')) {
        $st = 'pass'
        if ($tc.SelectSingleNode('failure') -or $tc.SelectSingleNode('error') -or $tc.status -eq 'fail') { $st = 'fail' }
        elseif ($tc.SelectSingleNode('skipped') -or $tc.status -eq 'notrun' -or $tc.status -eq 'disabled') { $st = 'skip' }
        $results[$tc.name][$row.Name] = $st
      }
    }
  }
} finally {
  foreach ($k in $saved.Keys) { [Environment]::SetEnvironmentVariable($k, $saved[$k], 'Process') }
  [Environment]::SetEnvironmentVariable('SD_IT_ENV_FILE', $null, 'Process')
  if (-not $Keep -and -not $NoStart) {
    $now = Get-Running
    $stopM2 = @($now.Keys | Where-Object { $_ -ne 'modern' -and -not $before[$_] })
    if ($stopM2.Count -gt 0) { Invoke-Wsl (@('sh', "$m2Wsl/fixture.sh", 'stop') + $stopM2) | Out-Null }
    if ($now['modern'] -and -not $before['modern']) { Invoke-Wsl @('sh', "$m1Wsl/stop.sh") | Out-Null }
    if ($stopM2.Count -gt 0 -or ($now['modern'] -and -not $before['modern'])) { Write-Host '== stopped the fixtures this run started' }
  }
}

# ------------------------------------------------------------------ report
$cols = @($rowState.Keys | Where-Object { $rowState[$_] -eq 'ran' })
$feat = @($results.Keys | Sort-Object)
$w = [Math]::Max(24, (@($feat | ForEach-Object { $_.Length }) + 7 | Measure-Object -Maximum).Maximum)
$lines = @()
if ($cols.Count -gt 0) {
  $hdr = 'test'.PadRight($w) + (($cols | ForEach-Object { $_.PadRight([Math]::Max(6, $_.Length + 1)) }) -join '')
  $lines += $hdr
  $lines += ('-' * $hdr.Length)
  foreach ($f in $feat) {
    $line = $f.PadRight($w)
    foreach ($c in $cols) {
      $v = $results[$f][$c]; if (-not $v) { $v = '.' }
      $line += $v.PadRight([Math]::Max(6, $c.Length + 1))
    }
    $lines += $line
  }
}
$lines += ''
foreach ($k in $rowState.Keys) { if ($rowState[$k] -ne 'ran') { $lines += "row $k`: $($rowState[$k])" } }
if ($selftest.Count -gt 0) {
  $p = @($selftest | Where-Object { $_ -like 'PASS *' }).Count
  $f = @($selftest | Where-Object { $_ -like 'FAIL *' }).Count
  $s = @($selftest | Where-Object { $_ -like 'SKIP *' }).Count
  $lines += "fixture self-test: $p pass, $f fail, $s skip"
}
Write-Host ''
$lines | ForEach-Object { Write-Host $_ }
$lines | Set-Content -Path (Join-Path $outDir 'matrix.txt') -Encoding Ascii
$obj = [ordered]@{ build = $BuildDir; config = $Config; rows = $rowState; results = $results; selftest = $selftest }
$obj | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $outDir 'matrix.json') -Encoding Ascii
Write-Host "(logs and junit per row: $outDir)"

$anyFail = @($results.Values | Where-Object { $_.Values -contains 'fail' }).Count -gt 0
if ($selftest | Where-Object { $_ -like 'FAIL *' }) { $anyFail = $true }
if ($anyFail) { exit 1 } else { exit 0 }
