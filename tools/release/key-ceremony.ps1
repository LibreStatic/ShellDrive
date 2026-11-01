# key-ceremony.ps1 - the first key ceremony for the ShellDrive update trust (04-build-install-update.md
# section 9.3, section 12.3 step 11, D42, D48).
#
# Generates the two offline root keys and the release-beta key, builds keyset.txt (keyset format version 1,
# listing the beta release key and both roots) signed by BOTH roots, verifies the signatures with sd-release,
# and writes roots.txt and the fingerprints block for README.md. The three private seeds are written only
# into -SecretDir and are never printed or copied elsewhere.
#
# Run this ONLY on the offline signing machine (Windows PowerShell 5.1 or later):
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File key-ceremony.ps1 ^
#     -ToolsDir  E:\tools   -SecretDir E:\keys   -PublicDir E:\public  [-Date 2026-11-01]
#   (^ continues the line in cmd.exe; join the lines when invoking from a PowerShell prompt.)
#
#   -ToolsDir  folder holding sd-updsign.exe and sd-release.exe copied from a build
#   -SecretDir empty folder on removable media; receives root-a.seed, root-b.seed, release-beta.seed
#   -PublicDir output folder; receives roots.txt, keyset.txt, fingerprints.md
#   -Date      ceremony date, UTC, YYYY-MM-DD (default: today)
#
# The script refuses to run when a network adapter is active, when -SecretDir is on the system drive or a
# network path, when -SecretDir already holds *.seed files, or when the public outputs already exist. If it
# aborts mid-way, fix the cause and start again with an empty -SecretDir (a half-generated key set must
# never survive). File formats follow docs/design/04-build-install-update.md section 9.3 and the parser in
# src/sd_update/update_verify.c (strict: no blank lines, sig lines only as the trailing block).

param(
    [Parameter(Mandatory = $true)][string]$ToolsDir,
    [Parameter(Mandatory = $true)][string]$SecretDir,
    [Parameter(Mandatory = $true)][string]$PublicDir,
    [string]$Date = ((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd'))
)

$ErrorActionPreference = 'Stop'
$culture = [System.Globalization.CultureInfo]::InvariantCulture
$script:WorkDir = $null

function Fail([string]$Message) {
    Write-Host ("key-ceremony: ERROR: " + $Message) -ForegroundColor Red
    exit 1
}

# Refuse a networked machine. Get-NetAdapter is authoritative on Windows 8+; any adapter reporting Up
# (including virtual switches) counts as active. On Windows 7 the fallback scans ipconfig for routable
# IPv4 addresses (language-neutral: addresses are digits everywhere; loopback, APIPA and subnet masks are
# ignored). A static address on an unplugged adapter can false-positive there; disable the adapter.
function Assert-Offline {
    if (Get-Command Get-NetAdapter -ErrorAction SilentlyContinue) {
        $up = @(Get-NetAdapter | Where-Object { $_.Status -eq 'Up' })
        if ($up.Count -gt 0) {
            $names = (@($up | ForEach-Object { $_.Name })) -join ', '
            Fail ("active network adapter(s): " + $names + " - disconnect every network and disable the adapters")
        }
        return
    }
    $text = (ipconfig.exe | Out-String)
    $ips = @([regex]::Matches($text, '(\d{1,3}\.){3}\d{1,3}') | ForEach-Object { $_.Value } | Select-Object -Unique)
    foreach ($ip in $ips) {
        if ($ip -like '127.*' -or $ip -like '169.254.*' -or $ip -like '255.*' -or $ip -eq '0.0.0.0') { continue }
        Fail ("ipconfig shows the address " + $ip + " - disconnect every network first")
    }
}

# Generates one key in -SecretDir and returns its public facts (never the seed). Checks the key id three
# ways: sd-updsign prints it, it must equal the first 8 bytes of SHA-256 of the public key (section 9.3),
# and sd-release must report the same public key hex and key id for the same seed.
function New-Key([string]$Name) {
    $seed = Join-Path $SecretDir ($Name + '.seed')
    $out = @(& $script:SdUpdsign keygen --seed $seed)
    if ($LASTEXITCODE -ne 0) { Fail ("sd-updsign keygen failed for " + $Name + " (exit " + $LASTEXITCODE + ")") }
    $pub = $null
    $kid = $null
    foreach ($line in $out) {
        if ($line -match '^pubkey ([A-Za-z0-9+/]{43}=)\s*$') { $pub = $Matches[1] }
        elseif ($line -match '^key-id ([0-9a-f]{16})\s*$') { $kid = $Matches[1] }
    }
    if (-not $pub -or -not $kid) { Fail ("unexpected sd-updsign keygen output for " + $Name) }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $pubBytes = [Convert]::FromBase64String($pub)
    $idHex = ([BitConverter]::ToString($sha.ComputeHash($pubBytes), 0, 8)).Replace('-', '').ToLowerInvariant()
    $sha.Dispose()
    if ($idHex -ne $kid) { Fail ("key id mismatch for " + $Name + " (tool " + $kid + ", SHA-256 says " + $idHex + ")") }
    $rel = @(& $script:SdRelease pubkey --seed $seed)
    if ($LASTEXITCODE -ne 0) { Fail ("sd-release pubkey failed for " + $Name + " (exit " + $LASTEXITCODE + ")") }
    $relPub = $null
    $relKid = $null
    foreach ($line in $rel) {
        if ($line -match '^pub ([0-9a-f]{64}) kid ([0-9a-f]{16})\s*$') { $relPub = $Matches[1]; $relKid = $Matches[2] }
    }
    if (-not $relPub) { Fail ("unexpected sd-release pubkey output for " + $Name) }
    $pubHex = ([BitConverter]::ToString($pubBytes)).Replace('-', '').ToLowerInvariant()
    if ($relPub -ne $pubHex -or $relKid -ne $kid) { Fail ("sd-release disagrees with sd-updsign for " + $Name) }
    # sd-release verify reads the public key from a file of 64 hex digits (sd-release.c read_key_hex),
    # while sd-updsign prints base64; write the hex form for the verification step below.
    $hexPath = Join-Path $script:WorkDir ($Name + '.hexpub')
    [System.IO.File]::WriteAllBytes($hexPath, [System.Text.Encoding]::ASCII.GetBytes($pubHex + "`n"))
    Write-Host ("key " + $Name + ": key-id " + $kid)
    return @{ Seed = $seed; PubB64 = $pub; PubHex = $pubHex; Id = $kid; HexPubPath = $hexPath }
}

function Assert-Verify([string]$PubPath, [string]$File, [string]$ExpectedId, [string]$What) {
    $out = @(& $script:SdRelease verify --kind keyset --pub $PubPath --in $File)
    if ($LASTEXITCODE -ne 0) { Fail ("sd-release verify FAILED for " + $What + " (exit " + $LASTEXITCODE + ")") }
    $ok = $false
    foreach ($line in $out) {
        if ($line -match ('^OK keyset key ' + $ExpectedId + '\s*$')) { $ok = $true }
    }
    if (-not $ok) { Fail ("sd-release verify did not confirm key " + $ExpectedId + " for " + $What) }
    Write-Host ("verified " + $What)
}

# --- preflight checks -------------------------------------------------------

Assert-Offline

try { $ceremonyDate = [datetime]::ParseExact($Date, 'yyyy-MM-dd', $culture) } catch {
    Fail "-Date must be a UTC date in YYYY-MM-DD form"
}
$validTo = $ceremonyDate.AddYears(1).ToString('yyyy-MM-dd', $culture)
# The keyset parser accepts exactly YYYY-MM-DDTHH:MM:SSZ (20 characters) for "issued".
$issued = $Date + 'T00:00:00Z'

$script:SdUpdsign = Join-Path $ToolsDir 'sd-updsign.exe'
$script:SdRelease = Join-Path $ToolsDir 'sd-release.exe'
if (-not (Test-Path $script:SdUpdsign -PathType Leaf)) { Fail ("missing " + $script:SdUpdsign) }
if (-not (Test-Path $script:SdRelease -PathType Leaf)) { Fail ("missing " + $script:SdRelease) }
Write-Host ("tool sd-updsign.exe SHA-256 " + (Get-FileHash $script:SdUpdsign -Algorithm SHA256).Hash)
Write-Host ("tool sd-release.exe SHA-256 " + (Get-FileHash $script:SdRelease -Algorithm SHA256).Hash)

if ($SecretDir -like '\\*') { Fail "-SecretDir must be a local drive (removable media), not a network path" }
$secretRoot = [System.IO.Path]::GetPathRoot([System.IO.Path]::GetFullPath($SecretDir))
$sysRoot = $env:SystemDrive
if (-not $sysRoot.EndsWith('\')) { $sysRoot = $sysRoot + '\' }
if ($secretRoot -ieq $sysRoot) { Fail ("-SecretDir is on the system drive " + $sysRoot + " - use removable media") }
if (-not (Test-Path $SecretDir)) { New-Item -ItemType Directory -Path $SecretDir | Out-Null }
$existingSeeds = @(Get-ChildItem -Path $SecretDir -Filter '*.seed' -File)
if ($existingSeeds.Count -gt 0) {
    Fail ("-SecretDir already holds seed file(s): " + (($existingSeeds | ForEach-Object { $_.Name }) -join ', ') +
          " - start the ceremony from an empty folder")
}
$volume = Get-CimInstance Win32_LogicalDisk |
    Where-Object { $_.DeviceID -ieq $secretRoot.TrimEnd('\') } |
    Select-Object -First 1
if ($volume -and $volume.DriveType -ne 2) {
    Write-Warning ("-SecretDir drive " + $volume.DeviceID + " is not removable media (DriveType " +
                   $volume.DriveType + "); 04 section 9.3 wants the roots on encrypted removable media")
}

if (-not (Test-Path $PublicDir)) { New-Item -ItemType Directory -Path $PublicDir | Out-Null }
foreach ($name in @('roots.txt', 'keyset.txt', 'fingerprints.md')) {
    if (Test-Path (Join-Path $PublicDir $name)) { Fail ("-PublicDir already contains " + $name + " - choose an empty output folder") }
}

# Scratch space for the keyset body, the hex public keys and the partial keyset copy. Only public
# material ever lands here; it is removed at the end.
$script:WorkDir = Join-Path ([System.IO.Path]::GetTempPath()) ('key-ceremony-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $script:WorkDir | Out-Null

try {
    # --- 1. generate the three keys ----------------------------------------

    Write-Host "generating root-a, root-b and release-beta keys ..."
    $rootA = New-Key 'root-a'
    $rootB = New-Key 'root-b'
    $beta = New-Key 'release-beta'

    # --- 2. build the unsigned keyset body (version 1) ----------------------

    # Grammar per section 9.3 and update_verify.c: header line, product, version, issued, then records.
    # Root lines mark a root change, which requires signatures by both roots - that is exactly what the
    # first keyset is. No blank lines; the body must end with LF and carry no sig line.
    $bodyLines = @(
        'shelldrive-keyset 1',
        'product com.librestatic.shelldrive',
        'version 1',
        ('issued ' + $issued),
        ('key ' + $beta.Id + ' beta ' + $beta.PubB64 + ' ' + $Date + ' ' + $validTo),
        ('root ' + $rootA.Id + ' ' + $rootA.PubB64),
        ('root ' + $rootB.Id + ' ' + $rootB.PubB64)
    )
    $bodyPath = Join-Path $script:WorkDir 'keyset.body'
    [System.IO.File]::WriteAllBytes($bodyPath, [System.Text.Encoding]::ASCII.GetBytes((($bodyLines -join "`n") + "`n")))

    # --- 3. sign the keyset with both roots ---------------------------------

    $keysetPath = Join-Path $PublicDir 'keyset.txt'
    Write-Host "signing the keyset with root-a and root-b ..."
    & $script:SdUpdsign sign-keyset --in $bodyPath --root $rootA.Seed --root $rootB.Seed --out $keysetPath
    if ($LASTEXITCODE -ne 0) { Fail ("sd-updsign sign-keyset failed (exit " + $LASTEXITCODE + ")") }
    # The signed file is body + sig(root-a) + sig(root-b); the last sig line is root-b's.

    # --- 4. verify both signatures with sd-release ---------------------------

    # Both roots sign the same body (everything before the sig block). sd-release verify checks the LAST sig
    # line of a file against everything before it, so each signature is verified on body + that one line.
    $keysetBytes = [System.IO.File]::ReadAllBytes($keysetPath)
    $sigLineLen = 118   # "sig ed25519 " (12) + key id (16) + ' ' + signature (88) + LF = RL_SIG_LINE_LEN
    if ($keysetBytes.Length -le (2 * $sigLineLen)) { Fail "the signed keyset is implausibly short" }
    $bodyLen = $keysetBytes.Length - 2 * $sigLineLen
    $slices = @(@{ Key = $rootA; Offset = $bodyLen; What = 'root-a signature' },
                @{ Key = $rootB; Offset = $bodyLen + $sigLineLen; What = 'root-b signature' })
    foreach ($s in $slices) {
        $slice = New-Object byte[] ($bodyLen + $sigLineLen)
        [Array]::Copy($keysetBytes, 0, $slice, 0, $bodyLen)
        [Array]::Copy($keysetBytes, $s.Offset, $slice, $bodyLen, $sigLineLen)
        $slicePath = Join-Path $script:WorkDir ('keyset.' + $s.Key.Id + '.txt')
        [System.IO.File]::WriteAllBytes($slicePath, $slice)
        Assert-Verify $s.Key.HexPubPath $slicePath $s.Key.Id $s.What
    }

    # --- 5. write roots.txt and the fingerprints block ------------------------

    $rootsLines = @(
        '# ShellDrive update trust roots (docs/design/04-build-install-update.md, section 9.3).',
        '# Format: root <key-id> <pubkey-base64>; the key id is the first 8 bytes of SHA-256 of the public key.',
        ('root ' + $rootA.Id + ' ' + $rootA.PubB64),
        ('root ' + $rootB.Id + ' ' + $rootB.PubB64)
    )
    [System.IO.File]::WriteAllBytes((Join-Path $PublicDir 'roots.txt'),
        [System.Text.Encoding]::ASCII.GetBytes((($rootsLines -join "`n") + "`n")))

    $fpLines = @(
        '## Release keys',
        '',
        'Update signatures are checked against the keys below (docs/design/04-build-install-update.md, section 9.3).',
        'The key id is the first 8 bytes of the SHA-256 of the public key, as printed by `sd-updsign pubkey`.',
        'The keyset current at build time is committed at `installer/keys/keyset.txt`, signed by both roots.',
        '',
        '| Role | Name | Key id | Public key (base64) |',
        '|---|---|---|---|',
        ('| root | root-a | ' + $rootA.Id + ' | `' + $rootA.PubB64 + '` |'),
        ('| root | root-b | ' + $rootB.Id + ' | `' + $rootB.PubB64 + '` |'),
        ('| release-beta | release-beta | ' + $beta.Id + ' | `' + $beta.PubB64 + '` |'),
        '',
        ('Keyset version 1, issued ' + $issued + '; the beta release key is valid ' + $Date + ' through ' + $validTo + '.'),
        ''
    )
    [System.IO.File]::WriteAllBytes((Join-Path $PublicDir 'fingerprints.md'),
        [System.Text.Encoding]::ASCII.GetBytes(($fpLines -join "`n")))

    # --- 6. summary ----------------------------------------------------------

    Write-Host ''
    Write-Host 'Public files (compare these SHA-256 values against what you commit):'
    foreach ($name in @('roots.txt', 'keyset.txt', 'fingerprints.md')) {
        $p = Join-Path $PublicDir $name
        Write-Host ('  SHA-256 ' + (Get-FileHash $p -Algorithm SHA256).Hash + '  ' + $p)
    }
    Write-Host ''
    Write-Host ('keyset version 1 issued ' + $issued + '; beta release key valid ' + $Date + ' through ' + $validTo)
    Write-Host ('secrets: three .seed files in ' + $SecretDir +
                ' - keep two copies on separate encrypted media, stored apart, never on a networked machine')
}
finally {
    if ($script:WorkDir -and (Test-Path $script:WorkDir)) {
        Remove-Item $script:WorkDir -Recurse -Force
    }
}

exit 0
