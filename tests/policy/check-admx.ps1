<#
.SYNOPSIS
  Structural checks of the generated ShellDrive.admx and its ADML files against res/policy/policies.txt
  (03 §3.5, 04 §8.6). Offline: no PolicyDefinitions schema is used, only well-formedness and consistency.

.DESCRIPTION
  Checks, each failure printed on its own line:
  - every file parses as XML; the policyDefinitions and policyDefinitionResources roots are right;
  - the policies are exactly the table lines, in order, with the table's key, valueName, class, supportedOn and
    kind (boolean: enabled/disabled values, no presentation; enum: one item per value with the value's type;
    text: maxLength; decimal: min and max);
  - every category, supportedOn definition, presentation and $(string.*) / $(presentation.*) reference resolves,
    and every presentation is used;
  - every id and name in the ADMX is unique;
  - each culture (en-US es-ES fr-FR pt-BR it-IT de-DE) has a ShellDrive.adml whose stringTable holds exactly the
    strings the ADMX uses, with no empty text, and whose presentations each refer to an element of the ADMX.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File tests\policy\check-admx.ps1 -Dir build\x64-modern\generated\policy -Table res\policy\policies.txt
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$Dir,
  [Parameter(Mandatory)][string]$Table
)

$ErrorActionPreference = 'Stop'
$ns = 'http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions'
$cultures = @('en-US', 'es-ES', 'fr-FR', 'pt-BR', 'it-IT', 'de-DE')
$classMap = @{ both = 'Both'; machine = 'Machine'; user = 'User' }
$script:problems = New-Object System.Collections.Generic.List[string]

function Add-Problem([string]$message) { $script:problems.Add($message) }

function Read-Xml([string]$path) {
  if (-not (Test-Path -LiteralPath $path)) { Add-Problem "missing file: $path"; return $null }
  try {
    $doc = New-Object System.Xml.XmlDocument
    $doc.Load($path)
    return $doc
  } catch {
    Add-Problem "not well-formed: ${path}: $($_.Exception.Message)"
    return $null
  }
}

function New-Nsm($doc) {
  $nsm = New-Object System.Xml.XmlNamespaceManager($doc.NameTable)
  $nsm.AddNamespace('p', $script:ns)
  return ,$nsm
}

# Returns the key of a "$(string.X)" or "$(presentation.X)" reference, or $null.
function Get-Ref([string]$value, [string]$kind) {
  $m = [regex]::Match($value, '^\$\(' + $kind + '\.([^)]+)\)$')
  if ($m.Success) { return $m.Groups[1].Value }
  return $null
}

# ---- the table ----
$key = $null
$rows = New-Object System.Collections.Generic.List[object]
foreach ($line in @(Get-Content -LiteralPath $Table -Encoding UTF8)) {
  $t = $line.Trim()
  if ($t -eq '' -or $t.StartsWith('#')) { continue }
  if ($t.StartsWith('@key ')) { $key = $t.Substring(5).Trim(); continue }
  $f = $t.Split('|')
  if ($f.Count -ne 6) { Add-Problem "table line is not 6 fields: $t"; continue }
  $rows.Add([pscustomobject]@{ Name = $f[0]; Class = $f[1]; Type = $f[2]; Params = $f[3]; Supported = $f[4]; Category = $f[5] })
}
if ($null -eq $key) { Add-Problem 'table has no @key line' }
if ($rows.Count -eq 0) { Add-Problem 'table has no policies' }

# Strings and element ids the ADMX needs from the ADML files.
$admxStrings = New-Object System.Collections.Generic.HashSet[string]
$admxPresentationRefs = New-Object System.Collections.Generic.HashSet[string]
$admxElementIds = New-Object System.Collections.Generic.HashSet[string]

# ---- ADMX ----
$admx = Read-Xml (Join-Path $Dir 'ShellDrive.admx')
if ($admx) {
  $root = $admx.DocumentElement
  if ($root.LocalName -ne 'policyDefinitions' -or $root.NamespaceURI -ne $ns) {
    Add-Problem 'ADMX root is not policyDefinitions in the PolicyDefinitions namespace'
  }
  $nsm = New-Nsm $admx

  $target = $admx.SelectSingleNode('//p:policyNamespaces/p:target', $nsm)
  if (-not $target -or $target.GetAttribute('namespace') -ne 'com.librestatic.shelldrive.policies' -or
      $target.GetAttribute('prefix') -ne 'shelldrive') {
    Add-Problem 'ADMX target is not com.librestatic.shelldrive.policies with prefix shelldrive'
  }

  # Ids of elements and presentations, names of categories, supportedOn definitions and policies: unique.
  $ids = @{}
  foreach ($node in $admx.SelectNodes('//*[@id]', $nsm)) {
    $v = $node.GetAttribute('id')
    if ($ids.ContainsKey($v)) { Add-Problem "duplicate id '$v' in the ADMX" } else { $ids[$v] = $true }
  }
  $names = @{}
  foreach ($node in $admx.SelectNodes('//p:categories/p:category | //p:supportedOn/p:definitions/p:definition | //p:policies/p:policy', $nsm)) {
    $v = $node.GetAttribute('name')
    if ($names.ContainsKey($v)) { Add-Problem "duplicate name '$v' in the ADMX" } else { $names[$v] = $true }
  }

  $categories = @{}
  foreach ($c in $admx.SelectNodes('//p:categories/p:category', $nsm)) {
    $categories[$c.GetAttribute('name')] = $true
    $ref = Get-Ref $c.GetAttribute('displayName') 'string'
    if ($ref) { [void]$admxStrings.Add($ref) } else { Add-Problem "category '$($c.GetAttribute('name'))' has no string reference" }
  }
  $supported = @{}
  foreach ($d in $admx.SelectNodes('//p:supportedOn/p:definitions/p:definition', $nsm)) {
    $supported[$d.GetAttribute('name')] = $true
    $ref = Get-Ref $d.GetAttribute('displayName') 'string'
    if ($ref) { [void]$admxStrings.Add($ref) } else { Add-Problem "supportedOn '$($d.GetAttribute('name'))' has no string reference" }
  }
  $presentations = @{}
  foreach ($p in $admx.SelectNodes('//p:presentations/p:presentation', $nsm)) { $presentations[$p.GetAttribute('id')] = $true }

  $policyNodes = @($admx.SelectNodes('//p:policies/p:policy', $nsm))
  if ($policyNodes.Count -ne $rows.Count) {
    Add-Problem "ADMX has $($policyNodes.Count) policies, the table has $($rows.Count)"
  }

  $count = [Math]::Min($policyNodes.Count, $rows.Count)
  for ($i = 0; $i -lt $count; $i++) {
    $pol = $policyNodes[$i]
    $row = $rows[$i]
    $n = $row.Name
    if ($pol.GetAttribute('name') -ne $n) {
      Add-Problem "policy $($i + 1) is '$($pol.GetAttribute('name'))', the table says '$n'"
      continue
    }
    if ($pol.GetAttribute('class') -ne $classMap[$row.Class]) {
      Add-Problem "${n}: class is '$($pol.GetAttribute('class'))', the table says $($row.Class)"
    }
    if ($pol.GetAttribute('key') -ne $key) { Add-Problem "${n}: key is '$($pol.GetAttribute('key'))', expected '$key'" }
    if ($pol.GetAttribute('valueName') -ne $n) { Add-Problem "${n}: valueName is '$($pol.GetAttribute('valueName'))'" }

    foreach ($attr in @('displayName', 'explainText')) {
      $ref = Get-Ref $pol.GetAttribute($attr) 'string'
      if ($ref) { [void]$admxStrings.Add($ref) } else { Add-Problem "${n}: $attr is not a string reference" }
    }
    $cat = $pol.SelectSingleNode('p:parentCategory', $nsm)
    if (-not $cat -or -not $categories.ContainsKey($cat.GetAttribute('ref'))) { Add-Problem "${n}: parentCategory does not resolve" }
    $sup = $pol.SelectSingleNode('p:supportedOn', $nsm)
    $wantSup = if ($row.Supported -eq 'win11') { 'SD_SUPPORTED_WIN11' } else { 'SD_SUPPORTED_XP' }
    if (-not $sup -or $sup.GetAttribute('ref') -ne $wantSup) { Add-Problem "${n}: supportedOn is not $wantSup" }
    elseif (-not $supported.ContainsKey($wantSup)) { Add-Problem "${n}: supportedOn definition $wantSup is missing" }

    $pres = Get-Ref $pol.GetAttribute('presentation') 'presentation'
    switch ($row.Type) {
      'boolean' {
        if ($pol.HasAttribute('presentation')) { Add-Problem "${n}: boolean policy has a presentation" }
        if (-not $pol.SelectSingleNode('p:enabledValue', $nsm) -or -not $pol.SelectSingleNode('p:disabledValue', $nsm)) {
          Add-Problem "${n}: boolean policy lacks enabledValue or disabledValue"
        }
      }
      'enum' {
        if (-not $pres) { Add-Problem "${n}: enum policy has no presentation reference" } else { [void]$admxPresentationRefs.Add($pres) }
        $en = $pol.SelectSingleNode('p:elements/p:enum', $nsm)
        if (-not $en) { Add-Problem "${n}: enum element missing"; break }
        if ($en.GetAttribute('valueName') -ne $n) { Add-Problem "${n}: enum valueName differs" }
        [void]$admxElementIds.Add($en.GetAttribute('id'))
        $values = @($row.Params.Split(','))
        $items = @($en.SelectNodes('p:item', $nsm))
        if ($items.Count -ne $values.Count) { Add-Problem "${n}: $($items.Count) enum items, the table has $($values.Count) values" }
        for ($k = 0; $k -lt [Math]::Min($items.Count, $values.Count); $k++) {
          $item = $items[$k]
          $want = $values[$k]
          if ($want -match '^[0-9]+$') {
            $dec = $item.SelectSingleNode('p:value/p:decimal', $nsm)
            if (-not $dec -or $dec.GetAttribute('value') -ne $want) { Add-Problem "${n}: enum item $k is not decimal $want" }
          } else {
            $str = $item.SelectSingleNode('p:value/p:string', $nsm)
            if (-not $str -or $str.InnerText -ne $want) { Add-Problem "${n}: enum item $k is not the string $want" }
          }
          $ref = Get-Ref $item.GetAttribute('displayName') 'string'
          if ($ref) { [void]$admxStrings.Add($ref) } else { Add-Problem "${n}: enum item $k has no string reference" }
        }
      }
      'text' {
        if (-not $pres) { Add-Problem "${n}: text policy has no presentation reference" } else { [void]$admxPresentationRefs.Add($pres) }
        $tx = $pol.SelectSingleNode('p:elements/p:text', $nsm)
        if (-not $tx) { Add-Problem "${n}: text element missing"; break }
        [void]$admxElementIds.Add($tx.GetAttribute('id'))
        if ($tx.GetAttribute('maxLength') -ne $row.Params) {
          Add-Problem "${n}: maxLength is '$($tx.GetAttribute('maxLength'))', the table says $($row.Params)"
        }
      }
      'decimal' {
        if (-not $pres) { Add-Problem "${n}: decimal policy has no presentation reference" } else { [void]$admxPresentationRefs.Add($pres) }
        $dec = $pol.SelectSingleNode('p:elements/p:decimal', $nsm)
        if (-not $dec) { Add-Problem "${n}: decimal element missing"; break }
        [void]$admxElementIds.Add($dec.GetAttribute('id'))
        $range = $row.Params.Split(',')
        if ($dec.GetAttribute('minValue') -ne $range[0] -or $dec.GetAttribute('maxValue') -ne $range[1]) {
          Add-Problem "${n}: decimal range differs from the table"
        }
      }
    }
  }

  foreach ($ref in $admxPresentationRefs) {
    if (-not $presentations.ContainsKey($ref)) { Add-Problem "presentation '$ref' is not defined in the ADMX" }
  }
  foreach ($presId in $presentations.Keys) {
    if (-not $admxPresentationRefs.Contains($presId)) { Add-Problem "presentation '$presId' is not used by any policy" }
  }
}

# ---- ADML per culture ----
foreach ($culture in $cultures) {
  $adml = Read-Xml (Join-Path (Join-Path $Dir $culture) 'ShellDrive.adml')
  if (-not $adml) { continue }
  if ($adml.DocumentElement.LocalName -ne 'policyDefinitionResources') { Add-Problem "${culture}: ADML root is not policyDefinitionResources" }
  $nsm = New-Nsm $adml

  $have = New-Object System.Collections.Generic.HashSet[string]
  foreach ($s in $adml.SelectNodes('//p:stringTable/p:string', $nsm)) {
    $sid = $s.GetAttribute('id')
    if (-not $have.Add($sid)) { Add-Problem "${culture}: duplicate string id '$sid'" }
    if ([string]::IsNullOrWhiteSpace($s.InnerText)) { Add-Problem "${culture}: string '$sid' is empty" }
  }
  foreach ($need in $admxStrings) {
    if (-not $have.Contains($need)) { Add-Problem "${culture}: string '$need' used by the ADMX is missing" }
  }
  foreach ($extra in $have) {
    if (-not $admxStrings.Contains($extra)) { Add-Problem "${culture}: string '$extra' is not used by the ADMX" }
  }

  $display = $adml.SelectSingleNode('//p:displayName', $nsm)
  if (-not $display -or [string]::IsNullOrWhiteSpace($display.InnerText)) { Add-Problem "${culture}: displayName is empty" }

  $presIds = New-Object System.Collections.Generic.HashSet[string]
  foreach ($pr in $adml.SelectNodes('//p:presentationTable/p:presentation', $nsm)) {
    $presId = $pr.GetAttribute('id')
    if (-not $presIds.Add($presId)) { Add-Problem "${culture}: duplicate presentation '$presId'" }
    $refId = $null
    foreach ($ctl in $pr.SelectNodes('*', $nsm)) { $refId = $ctl.GetAttribute('refId') }
    if (-not $refId) { Add-Problem "${culture}: presentation '$presId' has no control with a refId" }
    elseif (-not $admxElementIds.Contains($refId)) { Add-Problem "${culture}: presentation '$presId' refers to '$refId', which the ADMX does not define" }
  }
  foreach ($need in $admxPresentationRefs) {
    if (-not $presIds.Contains($need)) { Add-Problem "${culture}: presentation '$need' is missing" }
  }
}

if ($script:problems.Count -gt 0) {
  foreach ($p in $script:problems) { Write-Host "check-admx: error: $p" }
  Write-Host "check-admx: $($script:problems.Count) problem(s)"
  exit 1
}
Write-Host "check-admx: $($rows.Count) policies, $($cultures.Count) cultures, all references resolve"
exit 0
