# M1 acceptance run

Acceptance of the M1 milestone (00 §6, row "M1 — Resilience and WebDAV") on this Windows 11 machine with
the real stack, from the uncommitted M1 integration tree. The lab parts of the row (XP SP3 x86 with
`x86-ia32` on the Pentium III VM, `x86-sse2` elsewhere, Windows 7) need the lab images and are not covered
here; see "Not covered".

## Environment

| Item | Value |
|---|---|
| Machine | AMD Ryzen 7 2700X, Windows 11 IoT Enterprise LTSC 2024 (10.0.26100), x64, non-elevated user |
| Dokany | 2.3.1 |
| WebClient | installed, Manual (trigger start), started on demand by ShellDrive |
| SSH server | WSL fixture `tests/fixtures/wsl-sshd` (OpenSSH, Ubuntu 24.04), port 2222, user `<wsl-user>`, key `state/client_ed25519`, reached at the fixture's `direct_host` (the WSL VM address from `state/env`, written `<direct_host>` below) instead of the localhost relay (see m1-notes, sd_ssh section) |
| Fault injection | `tests/fixtures/wsl-sshd/ctl.ps1 kill` / `start` / `freeze` |
| Binaries | `build/x64-modern/bin/Release/shelldrive.exe` + `shelldrive-host.exe` (agent started by the CLI); x86 part: `build/x86-sse2/bin/Release/` (32-bit, WOW64) |
| Host key | answered `o` (once) at every mount, so `%APPDATA%\LibreStatic\ShellDrive\known_hosts` was not changed |
| Logging | `%APPDATA%\LibreStatic\ShellDrive\settings.ini` with `[log] level = debug` during the run (removed afterwards); server requests are read from `%LOCALAPPDATA%\LibreStatic\ShellDrive\logs\agent.log` (`webdav request <METHOD> -> <status>`; the path is never logged) |

Drive letters: `X:` (Dokany) and `P:` (WebDAV); many other letters are in use on this machine.

Outage procedure used for every "kill" step: start the copy (a `Start-Job` running `Copy-Item`), about 1 s
later `ctl.ps1 kill` (listener and all session processes), wait 10 s, `ctl.ps1 start`, then poll
`shelldrive list --json` until the mount is `mounted` with `connection.session = ready`.

## Results

| Check | Result |
|---|---|
| Dokany mount via the CLI | pass (0.24 s) |
| 1 GiB copy **into** the drive, sshd killed | copy fails cleanly; mount recovers by itself; retry matches SHA-256 |
| 1 GiB copy **out of** the drive, sshd killed | copy fails cleanly; mount recovers; retry matches SHA-256 |
| Cached reads while sshd is down | pass (32 MiB file read and hashed from cache in 0.35 s) |
| `shelldrive list` while down | `reconnecting`; JSON `state: offline`, `connection.session` |
| Write-behind, outage within the grace period | queued 8 MiB retransmitted after the reconnect, SHA-256 matches |
| Write-behind, grace expired | `write_failed` raised (log, IPC `warning`, `list` line and JSON) |
| WebDAV mount (`--backend webdav`) | pass (0.32 s) |
| WebDAV Win32 file operations | pass after a fix (case-only rename was 403) |
| WebDAV 40 MB round trip | pass, SHA-256 equal (upload, cached and uncached download) |
| Office save pattern (LOCK, temp, MOVE over original, UNLOCK) | pass (all statuses as expected) |
| LibreOffice 26.8.1 headless | save to the WebDAV drive: pass with LOCK/UNLOCK; opening a file from it: **fails** (LibreOffice's own WebDAV client, see below) |
| x86-sse2 CLI + host (WOW64), WebDAV mount + 100 MB round trip | pass, SHA-256 equal |
| QEMU for the no-SSE2 VM | `qemu-system-i386` 11.1.0 lists `pentium3`; no XP disk image yet, so no VM run |
| Identity cache (D10) | after the first create, `cache\<id>\identity.ini` holds host key + uid/gid; the next mount logs `using the cached remote identity 1000:1000` (after the vfs `IDENTITY` fix) |
| Cleanup | no mappings, mounts, agents, profiles or test files left |

### 1. Dokany: copy into the drive while sshd dies (write-through, default)

```
[13:30:32.625] kill sshd
[13:30:35.526] state while down: offline/connecting
Drive    State          Server                           Profile
X:       reconnecting   <wsl-user>@<direct_host>:2222    <direct_host>
[13:30:35.890] cached read while down: hash matches in 0.35 s
[13:30:35.900] write while down: The specified network name is no longer available.
[13:30:43.455] start sshd
[13:30:44.455] recovered to mounted/ready 0.3 s after the restart
[13:30:44.480] copy during outage: ERR 1.6 s System.IO.IOException: The specified network name is no longer available.
[13:30:48.704] retry: OK 4.2 s
local  D5048C2427A778D101C2DA9EBD0CA4CE49B31B95142B6522DB29452B10300BE1
server D5048C2427A778D101C2DA9EBD0CA4CE49B31B95142B6522DB29452B10300BE1   (sha256sum in WSL)
```

- The error `Copy-Item` shows is `The specified network name is no longer available.` (the vfs returns
  `STATUS_CONNECTION_DISCONNECTED`; Win32 error 64). It comes 1 s after the kill; `Copy-Item` removed its
  partial target (the delete during cleanup also failed with "disconnected" and was logged).
- The agent log shows the loop: `session lost: disconnected`, attempts 1-3 (840 ms, 1.8 s, 3.6 s backoff,
  `conn_refused` while the listener was down), then `ready: generation 3 channels=2` and
  `mount X: state mounted`. The mount never lost its drive letter.
- The retried 1 GiB copy took 4.2 s (about 240 MiB/s; M0 was 65 MiB/s).
- `list --json` after the recovery:
  `{"mount_id":"m-1",...,"backend":"dokany","state":"mounted",...,"connection":{"session":"ready","generation":3,"reconnects":2},"write_failed":0}`
- A first attempt with the kill 4 s after the start was too late: the whole 1 GiB copy had finished in
  4.0 s. The recovery from that kill took 1.4 s and the hashes matched as well.

### 2. Dokany: copy out of the drive while sshd dies

The 1 GiB source was written on the server with `head -c 1G /dev/urandom`.

```
[13:31:08.390] kill sshd
[13:31:11.325] state while down: offline/connecting
[13:31:19.277] start sshd
[13:31:20.222] recovered to mounted/ready 0.3 s after the restart
[13:31:20.243] copy during outage: ERR 7.7 s System.IO.IOException: The specified network name is no longer available.
[13:31:25.251] retry: OK 5.0 s
server 284872DDECD2AC8198C3FC4E07AE037C89D2A47EE9C46EB375F604890A17001D
local  284872DDECD2AC8198C3FC4E07AE037C89D2A47EE9C46EB375F604890A17001D
```

The read side fails later than the write side: blocks already fetched (read-ahead) are served, then the
first miss waits `offline_wait` (3 s) and returns `STATUS_CONNECTION_DISCONNECTED`. The retry ran at about
205 MiB/s.

### 3. Write-behind (`mount.write_mode = behind`)

A temporary profile `sd-m1-wb` (`%APPDATA%\LibreStatic\ShellDrive\profiles\`, removed afterwards) with
`write_mode = behind`, mounted with `shelldrive mount sd-m1-wb --letter X:`.

- **1 GiB copy into the drive with the kill**: same as write-through: `Copy-Item` fails with
  `The specified network name is no longer available.` 1.7 s after its start (writes issued while the
  session is down fail at once, 02 §5.2), the mount recovered 1.3 s after the restart, the retry matched
  SHA-256 (`D5048C24...0BE1`). `write_failed` stayed 0: `Copy-Item` deleted the partial file, so the data
  queued at the moment of the loss belonged to a deleted file.
- **Grace retransmit** (`wb.ps1`): open a file, `ctl.ps1 freeze` (sessions SIGSTOPped: nothing is
  acknowledged), `WriteFile` 8 MiB (accepted in 13 ms: queued), `ctl.ps1 kill`, wait 10 s, `start`, then
  close the handle (cleanup drains):

  ```
  [13:33:31.376] 8 MiB accepted by WriteFile in 13 ms (queued, not acknowledged)
  [13:33:31.378] kill sshd
  X:       reconnecting   <wsl-user>@<direct_host>:2222   sd-m1-wb
  [13:33:42.049] start sshd
  [13:33:43.921] close (drain) returned after 1.2 s
  local  A0BBC05A58ED27E7017B4B780A51B4819DCF9B806D1A12F92CE4AA2278579011
  server A0BBC05A58ED27E7017B4B780A51B4819DCF9B806D1A12F92CE4AA2278579011
  ```

  The unacknowledged extents waited within the 60 s grace and were retransmitted after the identity check
  of the new generation; `write_failed` stayed 0.
- **Grace expiry** (same procedure, profile with `reconnect_grace = 3s`): the data is lost and reported.

  ```
  agent.log  WARN  vfs  reconnect grace expired with write-behind data queued
             WARN  vfs  write-behind data lost: 8388608 bytes (17)
             WARN  mount X: write_failed, 8388608 bytes lost (disconnected)
             WARN  agent m-4: write_failed (disconnected, 8388608 bytes)
  > shelldrive list
  X:       mounted        <wsl-user>@<direct_host>:2222   sd-m1-wb
  1 drive mounted.
  On X:, 1 file could not be saved on the server (last: \sd-m1-accept\wb2.bin).
  > shelldrive list --json
  ..."connection":{"session":"ready","generation":2,"reconnects":1},"write_failed":1,"last_write_failed":"\\sd-m1-accept\\wb2.bin"
  ```

  The agent also broadcast `warning {code:"write_failed", mount_id, data:{target, path, bytes, status}}`
  on the `mount` and `warning` IPC topics (no long-running CLI subscriber exists yet to print it; the tray
  is M3). The server file was empty (SHA-256 of zero bytes): the failure is reported, not hidden.
  The run found a cosmetic bug in the `list` line (`X::` because the target already ends in `:`); the
  string was reworded in all six locales ("On X:, ...") and the output above is from the fixed text.

### 4. WebDAV backend (`--backend webdav`)

`shelldrive mount --host <wsl-user>@<direct_host>:2222 --identity <key> --letter P: --backend webdav`:
mounted in 0.32 s (WebClient started through its trigger), `net use` shows
`P:  \\localhost@<port>\s-<token>`.

**Win32 file operations** (PowerShell and cmd in `P:\sd-m1-accept`): create, `Move-Item` rename, `ren`,
`New-Item`/`mkdir`, copy into a subdirectory, directory rename, read back, case-only rename
(`Case.txt` -> `case.TXT`), replacing rename (`Move-Item -Force`), a non-ASCII name (`ñandú €.txt`),
recursive delete, `rmdir`, `del`. All results matched `ls` on the server; the sequence took 0.92 s.

- **Bug found and fixed:** the case-only rename failed with `A device attached to the system is not
  functioning.` (the server answered the redirector's `MOVE` with 403). See m1-notes, Integration, "Other
  fixes". After the fix the rename works.
- **Redirector caching seen:** after the failed first attempt, a later `Move-Item sub1 sub1-renamed`
  succeeded on the server (PROPFIND shows the file) but `P:\...\sub1-renamed\inner.txt` stayed "not found"
  for about 60 s without any request reaching the server: WebClient's negative cache
  (`FileNotFoundCacheLifeTimeInSec`, 60 s by default) kept the earlier 404. A fresh run with new names had
  no such delay. Likewise a file created directly on the server became visible on `P:` after about 52 s
  (vfs `dir_ttl` 30 s plus the redirector's own caches).

**40 MB round trip** (40 000 000 random bytes; below the redirector's download limit):

| Step | Time | SHA-256 |
|---|---|---|
| upload `Copy-Item <local> P:\...\rt.bin` | 0.94 s | `5EBC629C...355F5C` (local) |
| download right after (served by the redirector's local cache) | 0.08 s | `5EBC629C...355F5C` |
| server (`sha256sum`) | | `5EBC629C...355F5C` |
| uncached download of a 40 MB file created on the server | 0.68 s | `9D753F86...C6BCE1`, equal to `sha256sum` |

**Download limit:** WebClient's `FileSizeLimitInBytes` is 50 000 000 here (the default). Copying the 1 GiB
file out of `P:` fails with `The file size exceeds the limit allowed and cannot be saved.` (error 223);
uploads are not limited. The installer's `webdav-tune` (M4) raises the limit.

**Office save pattern** (`locktest.ps1`, raw HTTP to the mount's server with the caller's Negotiate
credentials, `If` headers as Office sends them):

```
PUT doc.docx (initial content)                         -> 201
LOCK doc.docx (exclusive write)                        -> 200   Lock-Token: <opaquelocktoken:...>
second LOCK without the token                          -> 423
PUT doc.docx without the token                         -> 423
DELETE doc.docx without the token                      -> 423
PUT ~WRL0001.tmp (temp save)                           -> 201
MOVE temp over doc.docx without the token              -> 423
MOVE temp over doc.docx with If: (<token>)             -> 204
PROPFIND lockdiscovery after the MOVE                  -> 207   (lock no longer listed)
UNLOCK doc.docx                                        -> 409
GET doc.docx                                           -> 200   content = the temp file (SHA-256 equal)
PUT doc.docx after UNLOCK                              -> 204
PUT while a Win32 handle holds doc.docx (redirector)   -> 423
PUT after the Win32 handle closed                      -> 204
```

Locks protect the document against other writers, deletes and replacing moves, the token admits the
holder, and a Win32 open without sharing makes the redirector take its own LOCK. Note: replacing a locked
resource with `MOVE` drops the destination's lock, so the final `UNLOCK` gets 409. Real Office clients
were not available; whether they mind the 409 is open (`[lab-verify]` with Office).

**LibreOffice 26.8.1** (`soffice --headless --convert-to docx`, profile under `%TEMP%`):

- Saving a new `.docx` onto `P:` (input local, `--outdir P:\sd-m1-accept`): pass, 3.2 s. Server requests
  during the run: `3 x LOCK -> 200`, `3 x PUT -> 201`, `3 x PUT -> 204`, `3 x UNLOCK -> 204`,
  `2 x DELETE -> 204` (LibreOffice's `.~lock.*#` file), `5 x PROPPATCH`, `5 x PROPFIND -> 207`,
  `3 x PROPFIND -> 404`, `3 x HEAD`, `1 x GET`. The file on the server is a valid 5 060-byte `.docx`.
- Opening a `.docx` from `P:` (and saving it again): **fails**, exit code 1. LibreOffice recognizes the
  `\\localhost@<port>\DavWWWRoot\...` UNC behind the mapped drive and uses its own WebDAV client instead
  of Win32: the server saw `OPTIONS -> 200` and `4 x PROPFIND -> 401 (unauthenticated)` and no
  Negotiate/NTLM answer. Same with a `file:///P:/...` URL. Open item: either LibreOffice's client must
  complete Negotiate/NTLM, or the server needs the token-only fallback for loopback clients that cannot
  authenticate (TM-R19); a GUI LibreOffice may instead prompt for credentials (not tried).
- Unrelated to ShellDrive: with the profile (`-env:UserInstallation`) in a very long scratch path,
  `soffice.bin` crashed in `ucrtbase.dll` (0xC0000409) even for a local conversion; a short path works.

### 5. x86-sse2 on WOW64

The x64 agent was stopped (one agent per session), then the 32-bit `x86-sse2` CLI started its own 32-bit
`shelldrive-host.exe`:

```
> build\x86-sse2\bin\Release\shelldrive.exe mount --host <wsl-user>@<direct_host>:2222 --identity <key> --letter P: --backend webdav
Mounted <direct_host> on P:.          (0.42 s)
100000000 bytes: in 2.88 s, out 0.25 s
local  FF748E3FAC22DFFECA721B42FA1709E8C96BC8674013563D3A7D3A93872FF67C
back   FF748E3FAC22DFFECA721B42FA1709E8C96BC8674013563D3A7D3A93872FF67C
server FF748E3FAC22DFFECA721B42FA1709E8C96BC8674013563D3A7D3A93872FF67C
```

The 100 MB download came from the redirector's cache of the file just uploaded; an uncached 100 MB
download is above the 50 MB limit (section 4). Dokany is not usable from WOW64 by design.

### 6. QEMU (no-SSE2 VM prerequisite)

`C:\Program Files\qemu\qemu-system-i386.exe --version`: 11.1.0; `-cpu help` lists `pentium3` and
`pentium3-v1`. No XP SP3 disk image exists yet, so `tests/lab/qemu/Start-QemuPentium3.ps1` was not run.

### Cleanup

Unmounted every drive, stopped both agents (`shelldrive agent stop`), removed `~/sd-m1-accept` on the
fixture, the local work files, the temporary profile, `settings.ini`, the LibreOffice profile and the
per-source cache folder the agent created (`%LOCALAPPDATA%\LibreStatic\ShellDrive\cache`). Afterwards
`net use` lists no connections, no `MountPoints2\##localhost@...` keys remain and no `shelldrive-host`
runs. The fixture sshd was left running with its original host key.

## Fixes made during acceptance

Each has a regression test; details in m1-notes, "Integration".

- `sd_webdav`: case-only MOVE answered 403 (section 4).
- `sd_vfs`: `IDENTITY` was not raised when the first create only confirmed the provisional uid, so the
  agent never cached the identity (seen as an empty cache folder after the run; verified afterwards with
  `identity.ini` written and reused on the next mount).
- CLI: the `write_failed` line printed `X::` (string reworded in all six locales).

## Build and test status

`tools\ci-local.ps1 -Clean` (clean build trees, WSL fixture running, Dokany 2.3.1), every preset Release
and Debug, final tree:

| Preset | Build (Release + Debug) | CTest Release / Debug |
|---|---|---|
| `x64-modern` | 0 warnings | 30/30 / 30/30 passed |
| `x64-xp` | 0 warnings (only the known `mt.exe` 81010002 note) | 30/30 / 30/30 passed |
| `x86-ia32` | 0 warnings (same note), import, ISA and constant-time gates pass | 39/40 passed, `dokany.mount` skipped (WOW64, expected) |
| `x86-sse2` | 0 warnings (same note), gates pass | 39/40 passed, `dokany.mount` skipped (WOW64, expected) |
| `x64-analysis` (Debug, `/analyze`) | 0 warnings | 30/30 passed |

`interop.ssh` / `interop_rekey_bulk` on `x86-ia32-debug`: 20 key exchanges for 32 MB (at least 14 required).
In the last full run `unit.vfs` `vfs_cache_coherency_by_validator` failed once on `x64-modern` Release: its
5 ms pauses are below the 15.6 ms `sd_tick_ms()` step, so the "1 ms" revalidation age could read 0. The
pauses are now 40 ms; `x64-modern` was re-run clean (pass) and `unit.vfs` was rebuilt and re-run on every
other preset and configuration (pass).

## Not covered (M1 row items that need the lab)

- XP SP3 x86 (`x86-ia32` on the QEMU Pentium III VM, `x86-sse2` elsewhere) and Windows 7 WebDAV mounts:
  no OS images on this machine (lab harness ready, m1-notes).
- Office (Word) itself: not installed; the save pattern was simulated and LibreOffice tried.
- WebDAV under the outage procedure: only the Dokany backend was killed during copies.
