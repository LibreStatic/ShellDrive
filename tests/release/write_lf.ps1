# Writes OUT as a copy of IN with every CR LF pair replaced by LF (byte exact otherwise). The ctest script helpers
# (keyring_flow.cmake) need it because file(WRITE) is text mode on Windows and turns "\n" into CRLF, while the
# keyset verifier takes the exact file bytes and refuses CR (docs/design/04 §9.3).
param([string]$In, [string]$Out)
$bytes = [IO.File]::ReadAllBytes($In)
$lf = New-Object System.Collections.Generic.List[byte]
for ($i = 0; $i -lt $bytes.Length; $i++) {
  if ($bytes[$i] -eq 13 -and $i + 1 -lt $bytes.Length -and $bytes[$i + 1] -eq 10) { continue }
  $lf.Add($bytes[$i])
}
[IO.File]::WriteAllBytes($Out, $lf.ToArray())
