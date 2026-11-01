<#
.SYNOPSIS
  Package a beta pre-release of ShellDrive (docs/design/04-build-install-update.md section 12.3 step 10, D48).

.DESCRIPTION
  The whole beta packaging, runnable by the maintainer locally and by the release workflow (both with and without
  the release-beta seed). It configures fresh build trees with -DSD_SETUP_CHANNEL=beta (so the pre-release notice
  defaults ON, 04 section 10), builds the setup EXEs and per-machine MSIs of the flavours this repository can
  produce, verifies the upstream Dokany files against installer/dokany/dokany.lock (sd-release dokany verify,
  TM-R23; it never downloads anything), produces the payload tables and, when -Seed is given, signs them and
  reattaches the payloads with PAYLOAD_SIG (SD_PAYLOAD_SIG, TM-R38) plus the DOKANY_X64/X86 resources (04 section 7.3).
  Then SHA256SUMS + SHA256SUMS.sig and the signed beta manifest (TM-R36: at most 14 days), and every signature is
  verified again with sd-release verify. Without -Seed it stops after the UNSIGNED artifacts and
  payload-tables.txt, so the signing can happen elsewhere (an offline session, a CI signing job).

  What cannot be produced is skipped with a clear message and listed at the end; nothing is faked:
    - setup EXEs exist only for the x86-ia32, arm64 and arm32 payloads (the stub targets of those presets). The
      x64-modern, x64-xp and x86-sse2 payload CABs and the universal EXE are release-pipeline work that is not in
      the repository yet (docs/dev/m4-notes.md, M4 row audit).
    - the MSIs need WiX 3.14; without it every per-machine MSI is skipped.
    - Dokany rides only in the x86-ia32 setup EXE (DOKANY_X64 + DOKANY_X86): the lock pins no ARM64 installer and
      there is no ARM32 one upstream (04 section 7.1).

  Exit code: 0 ok, 1 a check or build step failed.

.PARAMETER Version
  The version to release; must match the VERSION file (checked like release.yml does).

.PARAMETER Commit
  The full 40-hex commit the release is built from (the workflow passes github.sha). Bound into the gates record.

.PARAMETER BuildRoot
  Folder of the build trees; fresh "beta-<preset>" trees are configured inside it (default: <repo>\build).

.PARAMETER DokanyDir
  Folder holding the upstream Dokany files of the lock (Dokan_x64.msi, Dokan_x86.msi, DokanSetup.exe). They are
  verified against the lock here, never downloaded.

.PARAMETER OutDir
  Output folder (default: <repo>\dist\beta-<version>). Its previous content is removed.

.PARAMETER Seed
  Path to the release-beta seed file (64 hex digits). Optional: without it the script stops after the unsigned
  artifacts and payload-tables.txt.

.PARAMETER Gates
  The release gates record (04 section 12.3; default installer\keys\release-gates.txt). Required with -Seed: every
  sd-release sign refuses to sign unless the record validates for this version and commit.

.PARAMETER BuildNumber
  The build number stamped into the binaries (CI: the run number; local: 0).

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File tools\release\package-beta.ps1 -Version 0.1.0 -Commit <sha40> -DokanyDir E:\dokany -Seed E:\keys\release-beta.seed
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Version,
  [Parameter(Mandatory = $true)][string]$Commit,
  [string]$BuildRoot = '',
  [Parameter(Mandatory = $true)][string]$DokanyDir,
  [string]$OutDir = '',
  [string]$Seed = '',
  [string]$Gates = '',
  [string]$BuildNumber = '0'
)

$ErrorActionPreference = 'Stop'
$env:MSBUILDDISABLENODEREUSE = '1'
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$script:Skipped = New-Object System.Collections.ArrayList
$script:Configured = @{}

function Fail([string]$Message) {
  Write-Host ("package-beta: ERROR: " + $Message) -ForegroundColor Red
  exit 1
}

function Skip([string]$Message) {
  [void]$script:Skipped.Add($Message)
  Write-Host ("package-beta: SKIPPED: " + $Message) -ForegroundColor Yellow
}

# Runs a program and fails the script on a non-zero exit code.
function Invoke-Checked([string]$Title, [string]$Exe, [string[]]$ExeArgs) {
  Write-Host (">> " + $Title)
  & $Exe @ExeArgs
  if ($LASTEXITCODE -ne 0) { Fail ("$Title failed (exit $LASTEXITCODE)") }
}

# Locates cmake.exe: on PATH, else the Visual Studio Build Tools installation (as tools/ci-local.ps1 does).
function Find-CMake {
  $cmd = Get-Command cmake.exe -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
  if (-not (Test-Path $vswhere)) { Fail 'cmake.exe not found on PATH and vswhere.exe not found' }
  $vs = & $vswhere -latest -products * -property installationPath
  $bin = Join-Path $vs 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
  if (-not (Test-Path $bin)) { Fail ("cmake.exe not found under " + $bin) }
  return $bin
}

# Reads a configure preset from CMakePresets.json: generator, platform (-A), toolset (-T) and the inherited
# cacheVariables, so the fresh trees configure exactly like the presets (that file stays the single source).
function Get-PresetConfig([string]$Name) {
  $all = (Get-Content -Raw (Join-Path $repo 'CMakePresets.json') | ConvertFrom-Json).configurePresets
  $chain = @()
  $cur = $all | Where-Object { $_.name -eq $Name } | Select-Object -First 1
  if (-not $cur) { Fail ("preset not found in CMakePresets.json: " + $Name) }
  while ($cur) {
    $chain = @($cur) + $chain
    if ($cur.inherits) {
      $cur = $all | Where-Object { $_.name -eq $cur.inherits } | Select-Object -First 1
    } else { $cur = $null }
  }
  $cfg = @{ Generator = $null; Platform = $null; Toolset = $null; Vars = @{} }
  foreach ($e in $chain) {
    if ($e.generator) { $cfg.Generator = $e.generator }
    if ($e.architecture -and $e.architecture.value) { $cfg.Platform = $e.architecture.value }
    if ($e.toolset -and $e.toolset.value) { $cfg.Toolset = $e.toolset.value }
    if ($e.cacheVariables) {
      foreach ($p in $e.cacheVariables.PSObject.Properties) { $cfg.Vars[$p.Name] = [string]$p.Value }
    }
  }
  return $cfg
}

# Writes LF-only text without a BOM (the payload tables, the manifest spec and the notes are read byte for byte).
function Write-LfText([string]$Path, [string]$Text) {
  [System.IO.File]::WriteAllText($Path, ($Text -replace "`r`n", "`n"), (New-Object System.Text.UTF8Encoding($false)))
}

# Configures the fresh beta tree of a preset (a tree configured for another channel is removed first, so the
# SD_SETUP_PRERELEASE_NOTICE default is evaluated for beta, 04 section 10).
function New-BetaTree([string]$Tree, [string]$PresetName) {
  if ($script:Configured.ContainsKey($Tree)) { return }
  $cache = Join-Path $Tree 'CMakeCache.txt'
  if (Test-Path $cache) {
    $chan = Select-String -Path $cache -Pattern 'SD_SETUP_CHANNEL:STRING=(.+)$' | Select-Object -First 1
    if (-not $chan -or $chan.Matches[0].Groups[1].Value.Trim() -ne 'beta') {
      Write-Host ("removing the stale build tree " + $Tree + " (not configured for the beta channel)")
      Remove-Item $Tree -Recurse -Force -Confirm:$false
    }
  }
  $cfg = Get-PresetConfig $PresetName
  $confArgs = @('-S', $repo, '-B', $Tree, '-G', $cfg.Generator)
  if ($cfg.Platform) { $confArgs += @('-A', $cfg.Platform) }
  if ($cfg.Toolset) { $confArgs += @('-T', $cfg.Toolset) }
  foreach ($k in $cfg.Vars.Keys) { $confArgs += ("-D$k=" + $cfg.Vars[$k]) }
  $confArgs += @('-DSD_SETUP_CHANNEL=beta', ("-DSD_BUILD_NUMBER=" + $BuildNumber))
  if ($script:HaveWix) { $confArgs += '-DSD_BUILD_MSI=ON' }
  Invoke-Checked ("configure beta-$PresetName") $cmake $confArgs
  $script:Configured[$Tree] = $true
}

# The updater's per-flavour minimum OS (04 section 9.2; ARM32 is Windows 10+ best effort, D5).
function Get-MinOs([string]$Flavour) {
  switch ($Flavour) {
    'x86-ia32'   { '5.1' }
    'x86-sse2'   { '5.1' }
    'x64-xp'     { '5.2' }
    'x64-modern' { '10.0' }
    'arm64'      { '10.0' }
    'arm32'      { '10.0' }
    default      { Fail ("no min-os known for flavour " + $Flavour) }
  }
}

# Reads one RT_RCDATA resource of a PE file (as a data file, nothing is executed); $null when it is not there.
function Get-ExeResource([string]$Path, [string]$Name) {
  if (-not ('SdBetaRes' -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class SdBetaRes {
  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern IntPtr LoadLibraryExW(string f, IntPtr h, uint flags);
  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern IntPtr FindResourceW(IntPtr m, string name, IntPtr type);
  [DllImport("kernel32.dll")] static extern uint SizeofResource(IntPtr m, IntPtr r);
  [DllImport("kernel32.dll")] static extern IntPtr LoadResource(IntPtr m, IntPtr r);
  [DllImport("kernel32.dll")] static extern IntPtr LockResource(IntPtr r);
  [DllImport("kernel32.dll")] static extern bool FreeLibrary(IntPtr m);
  public static byte[] Get(string path, string name) {
    IntPtr m = LoadLibraryExW(path, IntPtr.Zero, 2);
    if (m == IntPtr.Zero) throw new Exception("cannot load " + path);
    try {
      IntPtr r = FindResourceW(m, name, (IntPtr)10);
      if (r == IntPtr.Zero) return null;
      uint n = SizeofResource(m, r);
      byte[] b = new byte[n];
      Marshal.Copy(LockResource(LoadResource(m, r)), b, 0, (int)n);
      return b;
    } finally { FreeLibrary(m); }
  }
}
"@
  }
  return [SdBetaRes]::Get($Path, $Name)
}

function Test-BytesEqual([byte[]]$A, [byte[]]$B) {
  if ($null -eq $A -or $null -eq $B -or $A.Length -ne $B.Length) { return $false }
  for ($i = 0; $i -lt $A.Length; $i++) { if ($A[$i] -ne $B[$i]) { return $false } }
  return $true
}

function Invoke-Summary {
  Write-Host ''
  Write-Host 'Beta packaging finished:'
  foreach ($name in $script:ReleaseFiles) {
    $p = Get-Item (Join-Path $OutDir $name)
    Write-Host ("  " + $name + "  " + $p.Length + " bytes")
  }
  foreach ($extra in $script:OutExtras) {
    $p = Get-Item (Join-Path $OutDir $extra)
    Write-Host ("  " + $extra + "  " + $p.Length + " bytes")
  }
  if ($script:Skipped.Count -gt 0) {
    Write-Host 'Skipped:'
    foreach ($s in $script:Skipped) { Write-Host ("  - " + $s) }
  }
}

# ---- preflight -------------------------------------------------------------

if ($Version -ne (Get-Content -Raw (Join-Path $repo 'VERSION')).Trim()) {
  Fail ("-Version $Version does not match the VERSION file " + (Get-Content -Raw (Join-Path $repo 'VERSION')).Trim())
}
if ($Commit -notmatch '^[0-9a-f]{40}$') { Fail '-Commit must be the full 40-digit lowercase hex commit SHA' }

$keysDir = Join-Path $repo 'installer\keys'
$rootsTxt = Join-Path $keysDir 'roots.txt'
$keysetTxt = Join-Path $keysDir 'keyset.txt'
if (-not (Test-Path $rootsTxt) -or -not (Test-Path $keysetTxt)) {
  Fail 'installer/keys/roots.txt and keyset.txt are missing: run the key ceremony first (docs/dev/key-ceremony.md); without them the stubs compile no release key and refuse every payload'
}

if ($Gates -eq '') { $Gates = Join-Path $keysDir 'release-gates.txt' }
if ($Seed -ne '' -and -not (Test-Path $Gates)) {
  Fail ("-Gates not found: " + $Gates + " - every sd-release sign needs a validated release gates record (04 section 12.3)")
}

$dokanyLock = Join-Path $repo 'installer\dokany\dokany.lock'
if (-not (Test-Path $DokanyDir -PathType Container)) { Fail ("-DokanyDir not found: " + $DokanyDir) }

$script:HaveWix = $false
$wixBin = $env:WIX
if (-not $wixBin) { $wixBin = 'C:\Program Files (x86)\WiX Toolset v3.14' }
if (Test-Path (Join-Path $wixBin 'bin\candle.exe')) {
  $script:HaveWix = $true
  Write-Host ("WiX: " + $wixBin)
} else {
  Skip ("the per-machine MSIs: WiX 3.14 not found at '" + $wixBin + "' (set WIX)")
}

$cmake = Find-CMake
if ($BuildRoot -eq '') { $BuildRoot = Join-Path $repo 'build' }
if ($OutDir -eq '') { $OutDir = Join-Path $repo ("dist\beta-" + $Version) }
$work = Join-Path $BuildRoot ('beta-work-' + $Version)
New-Item -ItemType Directory -Force $work | Out-Null
New-Item -ItemType Directory -Force (Join-Path $work 'tables') | Out-Null
if (Test-Path $OutDir) { Remove-Item (Join-Path $OutDir '*') -Recurse -Force -Confirm:$false }
New-Item -ItemType Directory -Force $OutDir | Out-Null

# The flavours: setup EXEs only where the repository builds a setup stub and payload; MSIs for every flavour the
# packaging supports (the x64 pair and the x86 pair share one UpgradeCode, 04 section 8.2).
$flavours = @(
  @{ Preset = 'x64-modern'; Flavour = 'x64-modern'; Setup = $false; Msi = $true },
  @{ Preset = 'x64-xp';     Flavour = 'x64-xp';     Setup = $false; Msi = $true },
  @{ Preset = 'x86-ia32';   Flavour = 'x86-ia32';   Setup = $true;  Msi = $true;  Dokany = $true },
  @{ Preset = 'x86-sse2';   Flavour = 'x86-sse2';   Setup = $false; Msi = $true },
  @{ Preset = 'arm64';      Flavour = 'arm64';      Setup = $true;  Msi = $true },
  @{ Preset = 'arm32';      Flavour = 'arm32';      Setup = $true;  Msi = $true }
)
$setupFlavours = @('x86-ia32', 'arm64', 'arm32')   # presets whose apps/shelldrive-setup builds a stub + payload
foreach ($f in $flavours | Where-Object { -not $_.Setup }) {
  Skip ("the setup EXE of $($f.Flavour): no payload target for that preset; the universal EXE assembly is release-pipeline work not in the repository yet (m4-notes, M4 row audit)")
}

$script:ReleaseFiles = New-Object System.Collections.ArrayList
$script:OutExtras = @('SHA256SUMS', 'SHA256SUMS.sig', 'manifest.txt', 'release-notes.md')

# ---- 1. the tools: sd-release first, from the x64-modern tree ------------------------------

$x64modern = Join-Path $BuildRoot 'beta-x64-modern'
New-BetaTree $x64modern 'x64-modern'
Invoke-Checked 'build sd-release' $cmake @('--build', $x64modern, '--config', 'Release', '--target', 'sd-release')
$sdRelease = Join-Path $x64modern 'bin\Release\sd-release.exe'
if (-not (Test-Path $sdRelease)) { Fail ("sd-release.exe not found after the build: " + $sdRelease) }

# ---- 2. the Dokany files: verified against the lock, never downloaded ----------------------

Write-Host 'verifying the Dokany files against installer/dokany/dokany.lock ...'
& $sdRelease dokany verify --lock $dokanyLock --dir $DokanyDir
if ($LASTEXITCODE -ne 0) {
  Fail ("the Dokany files in '" + $DokanyDir + "' do not match the lock (exit $LASTEXITCODE); a mismatched file is never embedded (TM-R23)")
}

# ---- 3. the fresh beta build trees ---------------------------------------------------------

foreach ($f in $flavours) {
  if (-not $f.Setup -and (-not $f.Msi -or -not $script:HaveWix)) { continue }
  New-BetaTree (Join-Path $BuildRoot ('beta-' + $f.Preset)) $f.Preset
}

# ---- 4. round 1: the payloads and their tables, unsigned -----------------------------------

$tables = @{}
foreach ($f in $flavours | Where-Object { $_.Setup }) {
  $tree = Join-Path $BuildRoot ('beta-' + $f.Preset)
  Invoke-Checked ("build shelldrive-setup ($($f.Preset))") $cmake @('--build', $tree, '--config', 'Release', '--target', 'shelldrive-setup')
  $cab = Join-Path $tree ("payload\$($f.Flavour)\payload.cab")
  if (-not (Test-Path $cab)) { Fail ("payload CAB not found after the build: " + $cab) }
  $table = Join-Path $work ("tables\$($f.Flavour).txt")
  Invoke-Checked ("payload table ($($f.Flavour))") $sdRelease @('table', '--channel', 'beta', '--flavour', $f.Flavour, '--cab', $cab, '--out', $table)
  Invoke-Checked ("check-table ($($f.Flavour))") $sdRelease @('check-table', '--table', $table, '--cab', $cab)
  $tables[$f.Flavour] = @{ Table = $table; Cab = $cab; Tree = $tree }
}
foreach ($f in $flavours | Where-Object { $_.Msi -and $script:HaveWix }) {
  $tree = Join-Path $BuildRoot ('beta-' + $f.Preset)
  Invoke-Checked ("build msi ($($f.Preset))") $cmake @('--build', $tree, '--config', 'Release', '--target', 'msi')
}

# Collect the unsigned artifacts under their release names.
$unsigned = Join-Path $work 'unsigned'
New-Item -ItemType Directory -Force $unsigned | Out-Null
$msiFiles = @{}
$msiSources = @{}
foreach ($f in $flavours) {
  $tree = Join-Path $BuildRoot ('beta-' + $f.Preset)
  if ($f.Setup) {
    $exe = Join-Path $tree 'bin\Release\shelldrive-setup.exe'
    if (-not (Test-Path $exe)) { Fail ("shelldrive-setup.exe not found: " + $exe) }
    [void]$script:ReleaseFiles.Add("ShellDrive-$Version-setup-$($f.Flavour).exe")
  }
  if ($f.Msi -and $script:HaveWix) {
    $msis = @(Get-ChildItem -Path (Join-Path $tree 'msi\Release') -Filter '*.msi' -File -ErrorAction SilentlyContinue)
    if ($msis.Count -eq 0) { Fail ("no MSI built in " + (Join-Path $tree 'msi\Release')) }
    $msiFiles[$f.Flavour] = "ShellDrive-$Version-$($f.Flavour).msi"
    $msiSources[$f.Flavour] = $msis[0].FullName
    [void]$script:ReleaseFiles.Add($msiFiles[$f.Flavour])
  }
}
foreach ($name in $script:ReleaseFiles) {
  $src = Join-Path $unsigned $name
  if ($name -like '*.exe') {
    $flavour = $name -replace [regex]::Escape("ShellDrive-$Version-setup-"), '' -replace '\.exe$', ''
    $src = Join-Path (Join-Path $BuildRoot ('beta-' + $flavour)) 'bin\Release\shelldrive-setup.exe'
  } elseif ($name -like '*.msi') {
    $src = $msiSources[($name -replace [regex]::Escape("ShellDrive-$Version-"), '' -replace '\.msi$', '')]
  }
  Copy-Item $src (Join-Path $unsigned $name) -Force
}
# payload-tables.txt: the table of every setup EXE - what an offline session verifies and signs (D42).
$tablesParts = @($tables.Keys | Sort-Object | ForEach-Object { Get-Content -Raw $tables[$_].Table })
$tablesTxt = Join-Path $work 'payload-tables.txt'
Write-LfText $tablesTxt ($tablesParts -join '')
Copy-Item $tablesTxt (Join-Path $unsigned 'payload-tables.txt') -Force

# ---- 5. without the seed: stop here, the signing happens elsewhere -------------------------

if ($Seed -eq '') {
  foreach ($name in @($script:ReleaseFiles) + @('payload-tables.txt')) {
    Copy-Item (Join-Path $unsigned $name) $OutDir -Force
  }
  Write-Host ''
  Write-Host 'UNSIGNED beta packaging finished (no -Seed given):'
  foreach ($name in @($script:ReleaseFiles) + @('payload-tables.txt')) {
    $p = Get-Item (Join-Path $OutDir $name)
    Write-Host ("  " + $name + "  " + $p.Length + " bytes")
  }
  Write-Host 'The setups refuse to run (no PAYLOAD_SIG, TM-R38). Sign each table elsewhere:'
  Write-Host '  sd-release sign --kind payload --seed <release-beta.seed> --in <table> --out <sig> --sig-only --gates <release-gates.txt> --version <V> --commit <C>'
  Write-Host 'and re-run this script with -Seed to attach the signatures and finish the release.'
  if ($script:Skipped.Count -gt 0) {
    Write-Host 'Skipped:'
    foreach ($s in $script:Skipped) { Write-Host ("  - " + $s) }
  }
  exit 0
}

# ---- 6. with the seed: gates, the beta key check, the payload signatures -------------------

if (-not (Test-Path $Seed)) { Fail ("-Seed not found: " + $Seed) }
$gatesArgs = @('--gates', $Gates, '--version', $Version, '--commit', $Commit)
Invoke-Checked 'gates check' $sdRelease @('gates', 'check', $Gates, '--version', $Version, '--commit', $Commit)

# The seed must be the beta release key of the keyset compiled into these stubs; anything else would produce
# setups that refuse their own payload.
$pubOut = @(& $sdRelease pubkey --seed $Seed)
if ($LASTEXITCODE -ne 0) { Fail 'cannot read the seed file (64 hex digits)' }
$pubText = ($pubOut -join "`n")
if ($pubText -notmatch 'pub ([0-9a-f]{64}) kid ([0-9a-f]{16})') { Fail ("unexpected pubkey output: " + $pubText) }
$betaPub = $Matches[1]; $betaKid = $Matches[2]
Write-Host ("release-beta key id " + $betaKid)
$pubFile = Join-Path $work 'release-beta.pub'
Write-LfText $pubFile ($betaPub + "`n")
if (-not (Select-String -Path $keysetTxt -Pattern ('^key ' + $betaKid + ' beta ') -Quiet)) {
  Fail ("the seed's key $betaKid is not a beta release key of installer/keys/keyset.txt: the stubs would refuse the payload")
}

$sigs = @{}
foreach ($flavour in $tables.Keys) {
  $sig = Join-Path $work ("tables\$flavour.sig")
  Invoke-Checked ("sign the payload table ($flavour)") $sdRelease (@('sign', '--kind', 'payload', '--seed', $Seed, '--in', $tables[$flavour].Table, '--out', $sig, '--sig-only') + $gatesArgs)
  $sigs[$flavour] = $sig
}

# ---- 7. round 2: the payloads reattached with PAYLOAD_SIG (and the Dokany resources) -------

$dokany64 = Join-Path $DokanyDir 'Dokan_x64.msi'
$dokany86 = Join-Path $DokanyDir 'Dokan_x86.msi'
foreach ($f in $flavours | Where-Object { $_.Setup }) {
  $tree = Join-Path $BuildRoot ('beta-' + $f.Preset)
  $reconfArgs = @('-S', $repo, '-B', $tree, ("-DSD_PAYLOAD_SIG=" + $sigs[$f.Flavour]))
  if ($f.Dokany) {
    $reconfArgs += @("-DSD_PAYLOAD_DOKANY_X64=$dokany64", "-DSD_PAYLOAD_DOKANY_X86=$dokany86")
  }
  Invoke-Checked ("reconfigure with PAYLOAD_SIG ($($f.Preset))") $cmake $reconfArgs
  Invoke-Checked ("reattach the payload ($($f.Preset))") $cmake @('--build', $tree, '--config', 'Release', '--target', 'shelldrive-setup')
}

# ---- 8. the release set, SHA256SUMS, the manifest ------------------------------------------

foreach ($name in $script:ReleaseFiles) {
  $src = Join-Path $unsigned $name
  if ($name -like '*.exe') {
    $flavour = $name -replace [regex]::Escape("ShellDrive-$Version-setup-"), '' -replace '\.exe$', ''
    $src = Join-Path (Join-Path $BuildRoot ('beta-' + $flavour)) 'bin\Release\shelldrive-setup.exe'
  }
  Copy-Item $src (Join-Path $OutDir $name) -Force
}
$releasePaths = @($script:ReleaseFiles | ForEach-Object { Join-Path $OutDir $_ })
$sumsPath = Join-Path $OutDir 'SHA256SUMS'
Invoke-Checked 'SHA256SUMS' $sdRelease (@('sums', '--out', $sumsPath) + $releasePaths)
$sumsSig = Join-Path $OutDir 'SHA256SUMS.sig'
Invoke-Checked 'sign SHA256SUMS' $sdRelease (@('sign', '--kind', 'sums', '--seed', $Seed, '--in', $sumsPath, '--out', $sumsSig, '--sig-only') + $gatesArgs)

# The update manifest of the beta channel (04 section 9.2; TM-R36: beta expires within 14 days).
$keysetVersion = '1'
foreach ($line in (Get-Content $keysetTxt)) {
  if ($line -match '^version (\d+)$') { $keysetVersion = $Matches[1] }
}
$now = [DateTimeOffset]::UtcNow
$culture = [System.Globalization.CultureInfo]::InvariantCulture
$released = $now.ToString('yyyy-MM-ddTHH:mm:ss', $culture) + 'Z'
$expires = $now.AddDays(13).ToString('yyyy-MM-ddTHH:mm:ss', $culture) + 'Z'
$serial = $now.ToString('yyyyMMdd', $culture) + '01'
$tag = "v$Version-beta"
$specParts = @(
  'product com.librestatic.shelldrive',
  'channel beta',
  "keyset $keysetVersion",
  "serial $serial",
  "version $Version",
  "released $released",
  "expires $expires",
  "notes https://github.com/LibreStatic/ShellDrive/releases/tag/$tag"
)
$shipped = @()
foreach ($flavour in ($setupFlavours + @($msiFiles.Keys))) {
  if ($shipped -contains $flavour) { continue }
  $hasFile = ($script:ReleaseFiles -contains "ShellDrive-$Version-setup-$flavour.exe") -or
             ($script:ReleaseFiles -contains "ShellDrive-$Version-$flavour.msi")
  if ($hasFile) {
    $shipped += $flavour
    $specParts += "min-os $flavour $(Get-MinOs $flavour)"
  }
}
foreach ($name in $script:ReleaseFiles) {
  if ($name -like '*.exe') {
    $id = $name -replace [regex]::Escape("ShellDrive-$Version-setup-"), 'setup-' -replace '\.exe$', ''
  } else {
    $id = $name -replace [regex]::Escape("ShellDrive-$Version-"), 'msi-' -replace '\.msi$', ''
  }
  $specParts += "file $id $name $name"
}
$specParts += "base https://github.com/LibreStatic/ShellDrive/releases/download/$tag/"
$specPath = Join-Path $work 'manifest-spec.txt'
Write-LfText $specPath (($specParts -join "`n") + "`n")
$manifestBody = Join-Path $work 'manifest-body.txt'
Invoke-Checked 'manifest' $sdRelease @('manifest', '--spec', $specPath, '--root', $OutDir, '--out', $manifestBody)
$manifestPath = Join-Path $OutDir 'manifest.txt'
Invoke-Checked 'sign manifest' $sdRelease (@('sign', '--kind', 'manifest', '--seed', $Seed, '--in', $manifestBody, '--out', $manifestPath) + $gatesArgs)

# ---- 9. verify everything ------------------------------------------------------------------

foreach ($flavour in $tables.Keys) {
  Invoke-Checked ("verify payload ($flavour)") $sdRelease @('verify', '--kind', 'payload', '--pub', $pubFile, '--in', $tables[$flavour].Table, '--sig', $sigs[$flavour])
}
Invoke-Checked 'verify SHA256SUMS' $sdRelease @('verify', '--kind', 'sums', '--pub', $pubFile, '--in', $sumsPath, '--sig', $sumsSig)
Invoke-Checked 'verify manifest' $sdRelease @('verify', '--kind', 'manifest', '--pub', $pubFile, '--in', $manifestPath)

# The final setup EXEs themselves: their embedded PAYLOAD_TABLE and PAYLOAD_SIG must be exactly the bytes that were
# signed (PAYLOAD_SIG covers the exact PAYLOAD_TABLE bytes, TM-R38), verify against the release-beta key that is in
# the compiled-in keyring (checked against keyset.txt above), and the embedded Dokany files must be the lock's.
foreach ($flavour in $tables.Keys) {
  $exe = Join-Path $OutDir ("ShellDrive-$Version-setup-$flavour.exe")
  $resTable = Get-ExeResource $exe 'PAYLOAD_TABLE'
  $resSig = Get-ExeResource $exe 'PAYLOAD_SIG'
  if (-not (Test-BytesEqual $resTable ([IO.File]::ReadAllBytes($tables[$flavour].Table)))) {
    Fail ("PAYLOAD_TABLE inside $exe is not the signed table of $flavour")
  }
  if (-not (Test-BytesEqual $resSig ([IO.File]::ReadAllBytes($sigs[$flavour])))) {
    Fail ("PAYLOAD_SIG inside $exe is not the signature made over the table of $flavour")
  }
  $xTable = Join-Path $work "embedded-$flavour.table"
  $xSig = Join-Path $work "embedded-$flavour.sig"
  [IO.File]::WriteAllBytes($xTable, $resTable)
  [IO.File]::WriteAllBytes($xSig, $resSig)
  Invoke-Checked ("verify the PAYLOAD_SIG embedded in the setup EXE ($flavour)") $sdRelease @('verify', '--kind', 'payload', '--pub', $pubFile, '--in', $xTable, '--sig', $xSig)
  $hasD64 = $null -ne (Get-ExeResource $exe 'DOKANY_X64')
  $hasD86 = $null -ne (Get-ExeResource $exe 'DOKANY_X86')
  $wantDokany = ($flavour -eq 'x86-ia32')
  if ($wantDokany) {
    if (-not (Test-BytesEqual (Get-ExeResource $exe 'DOKANY_X64') ([IO.File]::ReadAllBytes($dokany64))) -or
        -not (Test-BytesEqual (Get-ExeResource $exe 'DOKANY_X86') ([IO.File]::ReadAllBytes($dokany86)))) {
      Fail ("the Dokany resources inside $exe are not the verified lock files")
    }
  } elseif ($hasD64 -or $hasD86) {
    Fail ("$exe embeds a Dokany resource it must not carry")
  }
}

# ---- 10. the release notes ------------------------------------------------------------------

$notes = New-Object System.Collections.Generic.List[string]
[void]$notes.Add('Pre-release: the cryptography in this version has not yet been reviewed externally (D38, D48). Binaries are not Authenticode-signed; verify SHA256SUMS against SHA256SUMS.sig and the keys in README.md before running anything.')
[void]$notes.Add('')
[void]$notes.Add('## Verifying this release')
[void]$notes.Add('')
[void]$notes.Add('1. Download SHA256SUMS, SHA256SUMS.sig and the files you want.')
[void]$notes.Add('2. Check every downloaded file against SHA256SUMS (the hash is the first field of its line):')
[void]$notes.Add('')
[void]$notes.Add("    certutil -hashfile ShellDrive-$Version-setup-x86-ia32.exe SHA256")
[void]$notes.Add('')
[void]$notes.Add('3. Check the signatures with a build of the release tools and the release-beta public key:')
[void]$notes.Add('')
[void]$notes.Add('    sd-release verify --kind sums --pub <release-beta.pub> --in SHA256SUMS --sig SHA256SUMS.sig')
[void]$notes.Add('    sd-release verify --kind manifest --pub <release-beta.pub> --in manifest.txt')
[void]$notes.Add('')
[void]$notes.Add('manifest.txt carries the same files with their SHA-256, signed by the release-beta key of keyset')
[void]$notes.Add("version $keysetVersion, released $released, expires $expires (TM-R36).")
[void]$notes.Add('')
[void]$notes.Add('## Files')
[void]$notes.Add('')
foreach ($name in $script:ReleaseFiles) { [void]$notes.Add('- ' + $name) }
[void]$notes.Add('- SHA256SUMS, SHA256SUMS.sig')
[void]$notes.Add('- manifest.txt (signed beta update manifest)')
[void]$notes.Add('')
[void]$notes.Add('## Known limitations of this pre-release')
[void]$notes.Add('')
[void]$notes.Add('- The setups are beta-channel builds: the welcome page carries the pre-release notice and the payload')
[void]$notes.Add('  tables are signed with the release-beta key (channel beta).')
foreach ($s in $script:Skipped) { [void]$notes.Add('- Skipped: ' + $s) }
[void]$notes.Add('- The x86-ia32 setup embeds the upstream Dokan_x64.msi and Dokan_x86.msi (DOKANY_X64/DOKANY_X86),')
[void]$notes.Add('  verified against installer/dokany/dokany.lock. The stub does not chain them yet (nothing calls')
[void]$notes.Add('  sd_setup_dokany_run); until that wiring lands, Dokany is used when already installed and otherwise')
[void]$notes.Add('  the install continues with WebDAV only.')
[void]$notes.Add('- The ARM64 setup embeds no Dokany installer: the lock pins none upstream (04 section 7.1).')
Write-LfText (Join-Path $OutDir 'release-notes.md') (($notes -join "`n") + "`n")

# ---- summary --------------------------------------------------------------------------------

Invoke-Summary
exit 0
