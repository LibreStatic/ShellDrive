# Fails when a ShellDrive process outlives the test run (tests/apps/CMakeLists.txt, apps.no_leftover_processes).
# A test agent must never start the real prompt UI or the real agent (see SHELLDRIVE_TEST_UI_LAUNCH in
# apps/shelldrive-host/agent.c), so anything found here is a leak of an earlier test. Only processes started from
# this build tree count, so test runs in other trees and an installed ShellDrive do not fail it.
param([Parameter(Mandatory = $true)][string]$BuildDir)
$root = [IO.Path]::GetFullPath($BuildDir).TrimEnd('\', '/') + '\'
$names = @('shelldrive', 'shelldrive-host', 'shelldrive-ui', 'sd-test-host-fake', 'sd-test-cli', 'sd-test-apps')
$left = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $names -contains $_.ProcessName -and $_.Path -and $_.Path.StartsWith($root, [StringComparison]::OrdinalIgnoreCase) })
foreach ($p in $left) {
  Write-Output ("leftover process {0} ({1}) {2}" -f $p.ProcessName, $p.Id, $p.Path)
}
if ($left.Count -gt 0) { exit 1 }
Write-Output 'no ShellDrive process left'
exit 0
