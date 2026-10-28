# e2e.shipping_has_no_test_hooks: the shipping executables must not contain any SHELLDRIVE_TEST_* name, in ASCII or
# UTF-16LE (at either byte alignment). The test seams are compiled only under SD_CLI_TEST_HOOKS / SD_HOST_TEST_HOOKS /
# SD_SVC_TEST_HOOKS, so a shipping build that still carries the name has an unguarded read of the environment.
param([Parameter(Mandatory = $true)][string]$BinDir)

$ErrorActionPreference = 'Stop'
$needle = 'SHELLDRIVE_TEST_'
$files = @('shelldrive.exe', 'shelldrive-host.exe')
$bad = @()

foreach ($f in $files) {
  $path = Join-Path $BinDir $f
  if (-not (Test-Path -LiteralPath $path)) {
    Write-Output "missing shipping binary: $path"
    exit 1
  }
  $data = [System.IO.File]::ReadAllBytes($path)
  $even = $data.Length - ($data.Length % 2)
  $found = [System.Text.Encoding]::ASCII.GetString($data).Contains($needle) -or
           [System.Text.Encoding]::Unicode.GetString($data, 0, $even).Contains($needle) -or
           [System.Text.Encoding]::Unicode.GetString($data, 1, $even - 1).Contains($needle)
  if ($found) { $bad += $f }
  Write-Output ("checked {0} ({1} bytes)" -f $f, $data.Length)
}

if ($bad.Count -gt 0) {
  Write-Output ("test hook names in shipping binaries: " + ($bad -join ', '))
  exit 1
}
Write-Output 'no SHELLDRIVE_TEST_* name in the shipping binaries'
exit 0
