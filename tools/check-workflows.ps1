# Workflow lint (docs/design/04 §11.2 "workflow-lint"; TM-R39, TST-32). Read-only: it reads .github/ and prints findings.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\check-workflows.ps1 [-RequireCodeowners]
#
# Rules (failures exit 1):
#   1. Every `uses:` is an in-repo action (./...) or a first-party action (actions/...) pinned by a 40-hex commit SHA.
#   2. No workflow uses pull_request_target.
#   3. Every workflow declares a top-level `permissions:` block with `contents: read`; jobs widen it only per job.
#   4. release.yml and resign.yml contain no actions/cache and no actions/download-artifact (no restore of other
#      workflows' artifacts, TM-R39).
# Warnings (exit 0 unless -RequireCodeowners): .github/CODEOWNERS (or CODEOWNERS at the root) must cover .github/ and
# installer/ (TM-R39). Until the maintainer's review owner is recorded, the file is an open item and only a warning.
[CmdletBinding()]
param(
  [switch]$RequireCodeowners
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$wfDir = Join-Path $root '.github/workflows'
$errors = New-Object System.Collections.ArrayList
$warnings = New-Object System.Collections.ArrayList

function Add-Problem([System.Collections.ArrayList]$list, [string]$text) {
  [void]$list.Add($text)
}

$files = @(Get-ChildItem -Path $wfDir -Filter '*.yml' -File)
if ($files.Count -eq 0) {
  Add-Problem $errors "no workflows in $wfDir"
}

foreach ($f in $files) {
  $name = $f.Name
  $lines = @(Get-Content -Path $f.FullName)

  for ($i = 0; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]
    $code = ($line -replace '#.*$', '')
    if ($code -match 'pull_request_target') {
      Add-Problem $errors "${name}:$($i + 1): pull_request_target is not allowed"
    }
    if ($code -match '^\s*(-\s*)?uses:\s*(\S+)') {
      $ref = $Matches[2].Trim('"', "'")
      if ($ref.StartsWith('./')) {
        if (-not (Test-Path (Join-Path $root $ref))) {
          Add-Problem $errors "${name}:$($i + 1): in-repo action $ref does not exist"
        }
        continue
      }
      if ($ref -notmatch '^actions/[A-Za-z0-9_.-]+@([0-9a-f]{40})$') {
        Add-Problem $errors "${name}:$($i + 1): $ref is not a first-party action pinned by a 40-hex commit SHA"
      }
    }
  }

  # Rule 3: a top-level permissions block with contents: read.
  $top = -1
  for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match '^permissions:\s*$') {
      $top = $i
      break
    }
  }
  if ($top -lt 0) {
    Add-Problem $errors "${name}: no top-level permissions block"
  } else {
    $ok = $false
    for ($j = $top + 1; $j -lt $lines.Count; $j++) {
      if ($lines[$j] -match '^\S') { break }
      if ($lines[$j] -match '^\s+contents:\s*read\s*$') { $ok = $true }
    }
    if (-not $ok) {
      Add-Problem $errors "${name}: the top-level permissions must contain 'contents: read'"
    }
  }

  # Rule 4: release and resign workflows restore nothing.
  if ($name -eq 'release.yml' -or $name -eq 'resign.yml') {
    for ($i = 0; $i -lt $lines.Count; $i++) {
      $code = ($lines[$i] -replace '#.*$', '')
      if ($code -match 'actions/cache|actions/download-artifact') {
        Add-Problem $errors "${name}:$($i + 1): caches and artifact restores are not allowed in release workflows"
      }
    }
  }
}

# Warning: CODEOWNERS coverage.
$owners = @()
foreach ($p in @((Join-Path $root '.github/CODEOWNERS'), (Join-Path $root 'CODEOWNERS'))) {
  if (Test-Path $p) { $owners += Get-Content -Path $p }
}
if ($owners.Count -eq 0) {
  Add-Problem $warnings 'CODEOWNERS: no file (needs the maintainer review owner; .github/ and installer/ must be covered)'
} else {
  $text = $owners -join "`n"
  foreach ($need in @('.github/', 'installer/')) {
    if ($text -notmatch [regex]::Escape($need)) {
      Add-Problem $warnings "CODEOWNERS: $need is not covered"
    }
  }
}

foreach ($w in $warnings) { Write-Output "WARN  $w" }
foreach ($e in $errors) { Write-Output "ERROR $e" }
if ($errors.Count -gt 0) {
  Write-Output "workflow-lint: $($errors.Count) error(s)"
  exit 1
}
if ($RequireCodeowners -and $warnings.Count -gt 0) {
  Write-Output 'workflow-lint: CODEOWNERS required and missing or incomplete'
  exit 1
}
Write-Output "workflow-lint: $($files.Count) workflow(s) checked, $($warnings.Count) warning(s)"
exit 0
