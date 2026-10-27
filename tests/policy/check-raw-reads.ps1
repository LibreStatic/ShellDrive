<#
.SYNOPSIS
  Fails when a source file other than src/sd_policy reads the Group Policy key or a policy value by its
  literal name (03 §3.5). Every read goes through sd_policy, whose names come from the generated table, so
  the reader cannot drift from the ADMX.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File tests\policy\check-raw-reads.ps1 -Root . -Table res\policy\policies.txt
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$Root,
  [Parameter(Mandatory)][string]$Table
)

$ErrorActionPreference = 'Stop'
$names = @(Get-Content -LiteralPath $Table -Encoding UTF8 |
  Where-Object { $_.Trim() -ne '' -and -not $_.StartsWith('#') -and -not $_.StartsWith('@') } |
  ForEach-Object { $_.Split('|')[0] })

$rootFull = (Resolve-Path -LiteralPath $Root).ProviderPath
$roots = @((Join-Path $rootFull 'src'), (Join-Path $rootFull 'apps'))
$allowed = [IO.Path]::Combine($rootFull, 'src', 'sd_policy')
$problems = New-Object System.Collections.Generic.List[string]

$files = foreach ($r in $roots) { Get-ChildItem -LiteralPath $r -Recurse -File }
$files = @($files | Where-Object {
  $_.Extension -in @('.c', '.h', '.cpp', '.rc') -and
  -not $_.FullName.StartsWith($allowed, [StringComparison]::OrdinalIgnoreCase)
})

foreach ($file in $files) {
  $text = Get-Content -LiteralPath $file.FullName -Raw
  if ($text -match 'Policies\\+LibreStatic') {
    $problems.Add("$($file.FullName): reads the policy key directly (use sd_policy)")
  }
  foreach ($name in $names) {
    if ($text -match ('L"' + [regex]::Escape($name) + '"')) {
      $problems.Add("$($file.FullName): uses the policy value name '$name' as a literal (use SD_POLICY_*)")
    }
  }
}

if ($problems.Count -gt 0) {
  foreach ($p in $problems) { Write-Host "check-raw-reads: error: $p" }
  exit 1
}
Write-Host "check-raw-reads: $($files.Count) files, no raw policy reads outside src/sd_policy"
exit 0
