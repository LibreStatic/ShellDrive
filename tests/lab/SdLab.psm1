# Shared helpers for the ShellDrive test lab (04 section 11.4). Windows PowerShell 5.1 compatible.
# Imported by the scripts in this folder; nothing here downloads anything.

Set-StrictMode -Version 2.0

$script:RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

function Import-LabConfig {
  param([Parameter(Mandatory)] [string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    throw "Lab config '$Path' not found. Copy tests\lab\lab.example.psd1 and edit the image paths."
  }
  $cfg = Import-PowerShellDataFile -LiteralPath $Path
  foreach ($k in 'LabRoot', 'VMs') { if (-not $cfg.ContainsKey($k)) { throw "Lab config lacks '$k'." } }
  return $cfg
}

function Get-LabVMConfig {
  param([Parameter(Mandatory)] $Config, [Parameter(Mandatory)] [string]$Name)
  if ($Config.ContainsKey('Qemu') -and $Config.Qemu.Name -eq $Name) { return $Config.Qemu }
  $vm = @($Config.VMs | Where-Object { $_.Name -eq $Name })
  if ($vm.Count -ne 1) { throw "VM '$Name' is not defined in the lab config." }
  return $vm[0]
}

function Get-LabPipeName {
  param([Parameter(Mandatory)] [string]$Name)
  return "sd-lab-$Name"
}

function Assert-HyperV {
  if (-not (Get-Command Get-VM -ErrorAction SilentlyContinue)) {
    throw 'The Hyper-V PowerShell module is missing (enable Microsoft-Hyper-V-Management-PowerShell).'
  }
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object Security.Principal.WindowsPrincipal($id)
  $hvAdmins = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-578')   # Hyper-V Administrators
  if (-not ($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or $p.IsInRole($hvAdmins))) {
    throw 'Run from an elevated shell or as a member of "Hyper-V Administrators".'
  }
}

function Find-Oscdimg {
  $cmd = Get-Command oscdimg.exe -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  $kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\Assessment and Deployment Kit\Deployment Tools'
  foreach ($arch in 'amd64', 'x86', 'arm64') {
    $p = Join-Path $kits "$arch\Oscdimg\oscdimg.exe"
    if (Test-Path -LiteralPath $p) { return $p }
  }
  return $null
}

$script:IsoWriterType = @'
using System;
using System.IO;
using System.Runtime.InteropServices.ComTypes;
public static class SdLabIsoWriter {
  public static void Write(object comStream, string path) {
    IStream s = (IStream)comStream;
    byte[] buf = new byte[1 << 20];
    IntPtr pRead = System.Runtime.InteropServices.Marshal.AllocHGlobal(4);
    try {
      using (FileStream f = File.Create(path)) {
        while (true) {
          s.Read(buf, buf.Length, pRead);
          int n = System.Runtime.InteropServices.Marshal.ReadInt32(pRead);
          if (n <= 0) break;
          f.Write(buf, 0, n);
        }
      }
    } finally {
      System.Runtime.InteropServices.Marshal.FreeHGlobal(pRead);
    }
  }
}
'@

# Builds an ISO 9660 + Joliet image from a folder (readable by XP's CDFS). Uses oscdimg (Windows ADK
# Deployment Tools) when present, else the IMAPI2 file-system COM objects built into Windows.
function New-LabIso {
  param([Parameter(Mandatory)] [string]$Source, [Parameter(Mandatory)] [string]$OutIso,
        [string]$Label = 'SDLAB')
  if (Test-Path -LiteralPath $OutIso) { Remove-Item -LiteralPath $OutIso -Force }
  $osc = Find-Oscdimg
  if ($osc) {
    & $osc -m -o -j1 "-l$Label" $Source $OutIso | Out-Host
    if ($LASTEXITCODE) { throw "oscdimg failed ($LASTEXITCODE)" }
    return 'oscdimg'
  }
  if (-not ('SdLabIsoWriter' -as [type])) { Add-Type -TypeDefinition $script:IsoWriterType }
  $fs = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
  $fs.FileSystemsToCreate = 3        # FsiFileSystemISO9660 | FsiFileSystemJoliet
  $fs.VolumeName = $Label
  $fs.Root.AddTree((Resolve-Path -LiteralPath $Source).Path, $false)
  $img = $fs.CreateResultImage()
  [SdLabIsoWriter]::Write($img.ImageStream, [IO.Path]::GetFullPath($OutIso))
  [void][Runtime.InteropServices.Marshal]::ReleaseComObject($fs)
  return 'imapi2'
}

# Payload layout on the ISO:
#   \sdlab\           smoke.cmd, sysinfo.vbs, install-runner.cmd, sdlab-runner.cmd, expect.txt
#   \<flavour>\       shipping executables of that flavour (Release)
#   \<flavour>\tests\ unit-test executables (with -IncludeTests), run by smoke.cmd one by one
function New-LabPayload {
  param([Parameter(Mandatory)] [string[]]$Flavours, [Parameter(Mandatory)] [string]$OutIso,
        [string]$BuildRoot = (Join-Path $script:RepoRoot 'build'), [string]$Configuration = 'Release',
        [switch]$IncludeTests, [Nullable[bool]]$ExpectSse2 = $null)
  $stage = Join-Path ([IO.Path]::GetTempPath()) ("sdlab-payload-" + [Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Force (Join-Path $stage 'sdlab') | Out-Null
  try {
    # The repository stores text with LF (.gitattributes); XP's cmd.exe needs CRLF batch files (labels
    # and goto misbehave otherwise), so the guest scripts are rewritten with CRLF here.
    Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'guest') -File | ForEach-Object {
      $text = [IO.File]::ReadAllText($_.FullName) -replace "`r?`n", "`r`n"
      [IO.File]::WriteAllText((Join-Path $stage "sdlab\$($_.Name)"), $text, [Text.Encoding]::ASCII)
    }
    $expect = @()
    if ($null -ne $ExpectSse2) { $expect += "expect_sse2=$([int][bool]$ExpectSse2)" }
    foreach ($f in $Flavours) {
      $bin = Join-Path $BuildRoot "$f\bin\$Configuration"
      if (-not (Test-Path -LiteralPath (Join-Path $bin 'shelldrive.exe'))) {
        throw "No $Configuration build of $f under $bin (cmake --build --preset $f)."
      }
      $dst = Join-Path $stage $f
      New-Item -ItemType Directory -Force $dst | Out-Null
      foreach ($exe in 'shelldrive.exe', 'shelldrive-host.exe') {
        $p = Join-Path $bin $exe
        if (Test-Path -LiteralPath $p) { Copy-Item -LiteralPath $p -Destination $dst }
      }
      if ($IncludeTests) {
        $t = Join-Path $dst 'tests'
        New-Item -ItemType Directory -Force $t | Out-Null
        # Interop and Dokany tests need the WSL fixture or a driver. sd-test-host-fake and sd-test-cli are
        # helpers that sd-test-apps starts from its own folder; smoke.cmd does not run them directly.
        Get-ChildItem -LiteralPath $bin -Filter 'sd-test-*.exe' |
          Where-Object { $_.Name -notmatch 'interop|dokany' } |
          ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $t }
      }
      $expect += "flavour=$f"
    }
    Set-Content -LiteralPath (Join-Path $stage 'sdlab\expect.txt') -Value $expect -Encoding Ascii
    $tool = New-LabIso -Source $stage -OutIso $OutIso
    Write-Host "Payload ISO $OutIso ($tool): $($Flavours -join ', ')"
  } finally {
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
  }
}

# Reads the guest's COM1 through a named pipe (Hyper-V COM port or QEMU -serial pipe:) until the
# "SDLAB END" line or the timeout. Returns the lines; writes them to $LogPath as they arrive.
function Read-LabSerialPipe {
  param([Parameter(Mandatory)] [string]$PipeName, [int]$TimeoutSec = 900, [string]$LogPath)
  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  $lines = New-Object Collections.Generic.List[string]
  $pipe = $null
  while (-not $pipe -and (Get-Date) -lt $deadline) {
    $c = New-Object IO.Pipes.NamedPipeClientStream('.', $PipeName, [IO.Pipes.PipeDirection]::In)
    try { $c.Connect(2000); $pipe = $c } catch { $c.Dispose(); Start-Sleep -Milliseconds 500 }
  }
  if (-not $pipe) { throw "Could not connect to \\.\pipe\$PipeName within $TimeoutSec s." }
  try {
    $reader = New-Object IO.StreamReader($pipe, [Text.Encoding]::GetEncoding(437))
    $pending = $null
    while ((Get-Date) -lt $deadline) {
      if (-not $pending) { $pending = $reader.ReadLineAsync() }
      if (-not $pending.Wait(1000)) { continue }
      $line = $pending.Result
      $pending = $null
      if ($null -eq $line) { break }                       # VM closed the pipe (powered off)
      $line = $line.TrimEnd("`r", "`n", [char]0)
      if (-not $line) { continue }
      $lines.Add($line)
      if ($LogPath) { Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8 }
      Write-Host "  serial> $line"
      if ($line -eq 'SDLAB END') { break }
    }
  } finally {
    $pipe.Dispose()
  }
  return , $lines.ToArray()
}

# Judges a smoke transcript. Lines: "SDLAB RESULT <flavour> <step> <exitcode>".
#   x86-sse2 on a CPU without SSE2 must exit with STATUS_ILLEGAL_INSTRUCTION (-1073741795) from the
#   entry thunk; every other step must exit 0.
function Test-LabTranscript {
  param([Parameter(Mandatory)] [AllowEmptyCollection()] [string[]]$Lines, [Nullable[bool]]$ExpectSse2 = $null)
  $fail = New-Object Collections.Generic.List[string]
  if (-not ($Lines -contains 'SDLAB BEGIN')) { $fail.Add('no SDLAB BEGIN (smoke script did not start)') }
  if (-not ($Lines -contains 'SDLAB END')) { $fail.Add('no SDLAB END (smoke script did not finish)') }
  $results = 0
  foreach ($l in $Lines) {
    if ($l -notmatch '^SDLAB RESULT (\S+) (\S+) (-?\d+)$') { continue }
    $results++
    $flavour = $Matches[1]; $step = $Matches[2]; $code = [int64]$Matches[3]
    $want = 0
    if ($flavour -eq 'x86-sse2' -and $null -ne $ExpectSse2 -and -not $ExpectSse2 -and $step -notlike 'test-*') {
      $want = -1073741795
    }
    if ($flavour -eq 'x86-sse2' -and $null -ne $ExpectSse2 -and -not $ExpectSse2 -and $step -like 'test-*') {
      continue   # unit tests are not built with the entry thunk; they may fault on a non-SSE2 CPU
    }
    if ($code -ne $want) { $fail.Add("$flavour $step exited $code, expected $want") }
  }
  if ($results -eq 0) { $fail.Add('no SDLAB RESULT lines') }
  return [pscustomobject]@{ Passed = ($fail.Count -eq 0); Results = $results; Failures = $fail.ToArray() }
}

Export-ModuleMember -Function Import-LabConfig, Get-LabVMConfig, Get-LabPipeName, Assert-HyperV, Find-Oscdimg,
  New-LabIso, New-LabPayload, Read-LabSerialPipe, Test-LabTranscript
