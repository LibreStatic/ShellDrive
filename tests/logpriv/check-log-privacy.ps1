<#
.SYNOPSIS
  Log privacy source check (03 §10.1, TM-R31). Scans src/ and apps/ for logging calls (SD_LOGE/W/I/D, sd_log and
  ssh_log) and fails when:
    1. a %s conversion formats an argument whose identifiers name a host, user, lookup name or path (host, hostname,
       user, username, lookup, path, home, as a word of the identifier). Those must use the typed specifier: %Hs host
       and lookup names, %Us user names, %Rs remote paths. Local paths and error names stay %s.
    2. a call has a format the restricted language does not know (see src/sd_platform/include/sd_platform/sd_log.h),
       or the number of arguments differs from the number of conversions.
  Calls whose format is not a string literal (wrappers) are skipped. /analyze does not check these calls, because
  sd_log is not annotated _Printf_format_string_, so this script is the check for them.

  Exceptions go in allow-list.txt as "relative/path.c|identifier|reason" (the reason is required).

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File tests\logpriv\check-log-privacy.ps1 -Root .
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$Root,
  [string]$AllowList = ''
)

$ErrorActionPreference = 'Stop'
if (-not $AllowList) { $AllowList = Join-Path $PSScriptRoot 'allow-list.txt' }

$rootFull = (Resolve-Path -LiteralPath $Root).ProviderPath
$allowed = @{}
if (Test-Path -LiteralPath $AllowList) {
  foreach ($line in Get-Content -LiteralPath $AllowList -Encoding UTF8) {
    $t = $line.Trim()
    if ($t -eq '' -or $t.StartsWith('#')) { continue }
    $parts = $t.Split('|')
    if ($parts.Count -lt 3 -or $parts[2].Trim() -eq '') { throw "allow-list entry without a reason: $t" }
    $allowed[$parts[0].Trim() + '|' + $parts[1].Trim()] = $parts[2].Trim()
  }
}

# Files that define the logger or its macros are not call sites.
$skip = @(
  [IO.Path]::Combine($rootFull, 'src', 'sd_platform', 'log.c'),
  [IO.Path]::Combine($rootFull, 'src', 'sd_platform', 'include', 'sd_platform', 'sd_log.h')
)
$files = @()
foreach ($dir in @('src', 'apps')) {
  $p = Join-Path $rootFull $dir
  if (Test-Path -LiteralPath $p) {
    $files += @(Get-ChildItem -LiteralPath $p -Recurse -File | Where-Object {
      $_.Extension -in @('.c', '.h') -and $skip -notcontains $_.FullName
    })
  }
}

$sensitiveWords = @('host', 'hostname', 'user', 'username', 'lookup', 'path', 'home')
$specRx = [regex]'%(%|[HUR]s|ls|zu|ll[dux]|[scdupx])'
$literalRx = [regex]'"((?:\\.|[^"\\])*)"'
$callRx = [regex]'\b(SD_LOG[EWID]|sd_log|ssh_log)\s*\('
$fmtIndex = @{ 'sd_log' = 3; 'ssh_log' = 2 }

# Index of the ')' that closes the '(' at $open, skipping string and char literals; -1 when unbalanced.
function Find-CallEnd([string]$t, [int]$open) {
  $depth = 0
  $q = [char]0
  $i = $open
  while ($i -lt $t.Length) {
    $c = $t[$i]
    if ($q -ne [char]0) {
      if ($c -eq [char]92) { $i += 2; continue }
      if ($c -eq $q) { $q = [char]0 }
    } elseif ($c -eq [char]34 -or $c -eq [char]39) {
      $q = $c
    } elseif ($c -eq '(') {
      $depth++
    } elseif ($c -eq ')') {
      $depth--
      if ($depth -eq 0) { return $i }
    }
    $i++
  }
  return -1
}

# [start, end) offsets of the top-level comma-separated arguments of t[a:b].
function Split-Args([string]$t, [int]$a, [int]$b) {
  $out = New-Object System.Collections.Generic.List[object]
  $depth = 0
  $q = [char]0
  $start = $a
  $i = $a
  while ($i -lt $b) {
    $c = $t[$i]
    if ($q -ne [char]0) {
      if ($c -eq [char]92) { $i += 2; continue }
      if ($c -eq $q) { $q = [char]0 }
    } elseif ($c -eq [char]34 -or $c -eq [char]39) {
      $q = $c
    } elseif ($c -eq '(' -or $c -eq '[' -or $c -eq '{') {
      $depth++
    } elseif ($c -eq ')' -or $c -eq ']' -or $c -eq '}') {
      $depth--
    } elseif ($c -eq ',' -and $depth -eq 0) {
      $out.Add(@($start, $i))
      $start = $i + 1
    }
    $i++
  }
  $out.Add(@($start, $b))
  return ,$out
}

# Text of an argument with its string literals removed (so words inside messages do not count).
function Strip-Literals([string]$s) {
  return $literalRx.Replace($s, '""')
}

$problems = New-Object System.Collections.Generic.List[string]
$scanned = 0
$literal = 0

foreach ($file in $files) {
  $t = [IO.File]::ReadAllText($file.FullName)
  $rel = $file.FullName.Substring($rootFull.Length).TrimStart('\', '/').Replace('\', '/')
  foreach ($m in $callRx.Matches($t)) {
    $lineStart = $t.LastIndexOf([char]10, [Math]::Max(0, $m.Index - 1)) + 1
    if ($m.Index -gt 0 -and $t.Substring($lineStart, $m.Index - $lineStart) -match '^\s*#') { continue }
    $scanned++
    $name = $m.Groups[1].Value
    $open = $m.Index + $m.Length - 1
    $end = Find-CallEnd $t $open
    if ($end -lt 0) { throw "${rel}: unbalanced call at offset $($m.Index)" }
    $line = ([regex]::Matches($t.Substring(0, $m.Index), [string][char]10)).Count + 1
    $segs = Split-Args $t ($open + 1) $end
    $fi = if ($name -clike 'SD_LOG*') { 1 } else { $fmtIndex[$name] }
    if ($segs.Count -le $fi) { continue }

    $fs = $segs[$fi][0]
    $fraw = $t.Substring($fs, $segs[$fi][1] - $fs)
    if (($literalRx.Replace($fraw, '')).Trim() -ne '') { continue }
    $literal++
    $fmt = ''
    foreach ($lm in $literalRx.Matches($fraw)) { $fmt += $lm.Groups[1].Value }

    # Every '%' must start a known conversion.
    $pctAll = ($fmt.ToCharArray() | Where-Object { $_ -eq '%' }).Count
    $pctKnown = 0
    $consuming = @()
    foreach ($sm in $specRx.Matches($fmt)) {
      $pctKnown += ($sm.Value.ToCharArray() | Where-Object { $_ -eq '%' }).Count
      if ($sm.Value -ne '%%') { $consuming += $sm.Value }
    }
    if ($pctKnown -ne $pctAll) {
      $problems.Add("${rel}:${line}: $name has a conversion the restricted language does not know: '$fmt'")
      continue
    }
    $rest = @()
    for ($k = $fi + 1; $k -lt $segs.Count; $k++) { $rest += ,@($segs[$k][0], $segs[$k][1]) }
    if ($rest.Count -ne $consuming.Count) {
      $problems.Add("${rel}:${line}: $name has $($consuming.Count) conversion(s) and $($rest.Count) argument(s): '$fmt'")
      continue
    }
    for ($k = 0; $k -lt $consuming.Count; $k++) {
      if ($consuming[$k] -ne '%s') { continue }
      $expr = Strip-Literals ($t.Substring($rest[$k][0], $rest[$k][1] - $rest[$k][0]))
      foreach ($im in [regex]::Matches($expr, '[A-Za-z_][A-Za-z0-9_]*')) {
        $id = $im.Value
        $words = @($id.Split('_') | ForEach-Object { $_ -replace '\d+$', '' })
        $hit = @($words | Where-Object { $sensitiveWords -contains $_ })
        if ($hit.Count -eq 0) { continue }
        if ($allowed.ContainsKey("$rel|$id")) { continue }
        $problems.Add("${rel}:${line}: $name formats '$id' with %s; use %Hs (host, lookup name), %Us (user) or %Rs (remote path), or allow-list it (03 10.1)")
        break
      }
    }
  }
}

if ($problems.Count -gt 0) {
  foreach ($p in $problems) { Write-Host "check-log-privacy: error: $p" }
  Write-Host "check-log-privacy: $($problems.Count) problem(s) in $scanned call(s)"
  exit 1
}
Write-Host "check-log-privacy: $scanned call(s) in $($files.Count) file(s), $literal with a literal format, no problems"
exit 0
