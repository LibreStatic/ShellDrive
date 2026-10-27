<#
.SYNOPSIS
  Reproducible-build check (04 §12.2): builds one preset twice, into two separate build directories, from the
  same source tree, and compares the outputs byte for byte. Exit 0 when identical, 1 when any file differs or is
  missing from one side, 2 on a setup error.

.DESCRIPTION
  Both builds read the source through a subst drive (the first free letter from S: upward), so __FILE__ and
  the source paths the compiler records are the same in both (04 §12.2: builds run from a fixed path). The
  build directories are build\repro-a\<preset> and build\repro-b\<preset>, so the output location differs
  between the two runs, which is what the check must not depend on.

  Compared, relative to each build directory:
  - bin\<Config>\*.exe and *.dll (the unsigned PEs; /Brepro, /PDBALTPATH and no __DATE__/__TIME__);
  - the static libraries are not compared: they are intermediate, not shipped, and their object debug info records
    build-directory paths (generated headers, object names) that /Brepro does not remove;
  - generated\policy\** (ShellDrive.admx, the ADML files and the policy headers).
  PDB files are not compared: they hold the object paths of the build directory. Each PE carries only the PDB
  file name (/PDBALTPATH), so the PE comparison covers the debug directory too.

  Signing is not part of this check (04 §12.3 signs after the comparison).

.PARAMETER Preset
  Configure preset to build, e.g. x64-modern or x86-ia32.

.PARAMETER Config
  Configuration to build; Release by default, the configuration the release builds compare.

.PARAMETER KeepBuilds
  Keep build\repro-a and build\repro-b (they are large); by default they are removed after a passing run.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tools\check-repro.ps1 -Preset x64-modern
  powershell -ExecutionPolicy Bypass -File tools\check-repro.ps1 -Preset x86-ia32
#>
[CmdletBinding()]
param(
  [string]$Preset = 'x64-modern',
  [string]$Config = 'Release',
  [switch]$KeepBuilds
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

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

function Find-FreeDrive {
  foreach ($code in [int][char]'S'..[int][char]'Z') {
    $letter = [char]$code
    if (-not (Test-Path ("{0}:\" -f $letter))) { return ("{0}:" -f $letter) }
  }
  throw 'no free drive letter from S: to Z: for the subst mapping'
}

function Get-OutputFiles([string]$buildDir) {
  $patterns = @(
    @{ Dir = Join-Path $buildDir "bin\$Config"; Filter = @('*.exe', '*.dll') },
    @{ Dir = Join-Path $buildDir 'generated\policy'; Filter = @('*') }
  )
  $found = @{}
  foreach ($p in $patterns) {
    if (-not (Test-Path -LiteralPath $p.Dir)) { continue }
    foreach ($filter in $p.Filter) {
      Get-ChildItem -LiteralPath $p.Dir -Recurse -File -Filter $filter | ForEach-Object {
        $rel = $_.FullName.Substring($buildDir.Length).TrimStart('\')
        $found[$rel] = $_.FullName
      }
    }
  }
  return $found
}

$bin = Find-CMakeBin
$cmake = Join-Path $bin 'cmake.exe'
$drive = Find-FreeDrive
$dirA = Join-Path $root "build\repro-a\$Preset"
$dirB = Join-Path $root "build\repro-b\$Preset"
$mapped = $false

try {
  & subst $drive $root
  if ($LASTEXITCODE) { throw "subst $drive failed" }
  $mapped = $true
  $source = "$drive\"

  foreach ($dir in @($dirA, $dirB)) {
    if (Test-Path $dir) { Remove-Item -Recurse -Force $dir }
  }

  foreach ($dir in @($dirA, $dirB)) {
    Write-Host "== [$Preset] configure $dir (source $source)"
    Push-Location $source
    try {
      & $cmake --preset $Preset -B $dir | Out-Host
      if ($LASTEXITCODE) { throw "configure failed in $dir" }
    } finally {
      Pop-Location
    }
    Write-Host "== [$Preset] build $Config in $dir"
    & $cmake --build $dir --config $Config --parallel | Out-Host
    if ($LASTEXITCODE) { throw "build failed in $dir" }
  }

  $filesA = Get-OutputFiles $dirA
  $filesB = Get-OutputFiles $dirB
  $names = @($filesA.Keys + $filesB.Keys | Sort-Object -Unique)
  $differ = @()
  $checked = 0
  foreach ($name in $names) {
    if (-not $filesA.ContainsKey($name)) { $differ += "$name (only in repro-b)"; continue }
    if (-not $filesB.ContainsKey($name)) { $differ += "$name (only in repro-a)"; continue }
    $checked++
    $ha = (Get-FileHash -LiteralPath $filesA[$name] -Algorithm SHA256).Hash
    $hb = (Get-FileHash -LiteralPath $filesB[$name] -Algorithm SHA256).Hash
    if ($ha -ne $hb) { $differ += "$name ($ha vs $hb)" }
  }
  if ($checked -eq 0) { throw 'no output files found to compare' }

  if ($differ.Count -gt 0) {
    Write-Host "== [$Preset] NOT reproducible: $($differ.Count) of $($names.Count) file(s) differ"
    foreach ($d in $differ) { Write-Host "  differs: $d" }
    $exit = 1
  } else {
    Write-Host "== [$Preset] reproducible: $checked file(s) byte-identical across two builds"
    $exit = 0
  }
} catch {
  Write-Host "check-repro: $($_.Exception.Message)"
  $exit = 2
} finally {
  if ($mapped) { & subst $drive /D | Out-Null }
}

if (-not $KeepBuilds -and $exit -eq 0) {
  foreach ($dir in @($dirA, $dirB)) {
    if (Test-Path $dir) { Remove-Item -Recurse -Force $dir }
  }
}
exit $exit
