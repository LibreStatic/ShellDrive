# M0 acceptance run

Acceptance of the M0 milestone (00 §6, row "M0 — x64 Win10 vertical slice") on a real Windows
machine with the real stack. Run on 2026-10-25 from the uncommitted M0 integration tree (base commit
`852368c`).

## Environment

| Item | Value |
|---|---|
| Machine | AMD Ryzen 7 2700X, Windows 11 IoT Enterprise LTSC 2024 (10.0.26100), x64 |
| Dokany | 2.3.1 (installed driver and `dokan2.dll`) |
| SSH server | WSL fixture `tests/fixtures/wsl-sshd` (OpenSSH in Ubuntu 24.04, WSL2 kernel 6.18), `127.0.0.1:2222`, user `<wsl-user>` (the WSL account running the fixture), key `tests/fixtures/wsl-sshd/state/client_ed25519` |
| Binaries | `build/x64-modern/bin/Release/shelldrive.exe` and `shelldrive-host.exe` (agent auto-started by the CLI) |
| Known hosts | `%APPDATA%\LibreStatic\ShellDrive\known_hosts`, empty before the run |

**Deviation: drive `X:` instead of `Z:`.** `Z:` is a local NTFS volume on this machine
(`W11X64inst`). The CLI refused it correctly (`The drive letter Z: is already in use.`, exit 10), so
the run used `--letter X:`. Everything else follows the acceptance text.

## Results

| Check | Result |
|---|---|
| TOFU prompt on first connect, answered over `--stdin` | pass |
| Drive appears and lists (`dir X:\`) | pass |
| `shelldrive list --json` while mounted | pass |
| 1 GiB random file in and out, SHA-256 equal | pass (in 65.1 MiB/s, out 53.4 MiB/s) |
| Rename / delete through Win32 (PowerShell, cmd), directory create/delete | pass |
| Explorer lists the drive (Shell.Application, no screenshots) | pass |
| Clean unmount, letter gone, no leaked agent handles | pass |
| Host key mismatch: hard block, exit 6, no override | pass |
| Original fixture host key restored | done |

### 1. Mount with the TOFU prompt

```powershell
$key = '<repo>\tests\fixtures\wsl-sshd\state\client_ed25519'
"yes" | build\x64-modern\bin\Release\shelldrive.exe mount --host <wsl-user>@127.0.0.1:2222 --identity $key --letter X: --stdin
```

Exit code 0, 0.23 s including the agent start. The prompt goes to stderr, the result to stdout
(output of the re-run with the fixed CLI, known_hosts emptied first):

```
stderr:
Connecting to 127.0.0.1...
The authenticity of host '127.0.0.1' (port 2222) can't be established.
ssh-ed25519 key fingerprint: SHA256:B1tQ1nxJtfNQumYUZBIsP+7jBiY8NBy8hYsi+9L6BdI
Compare the fingerprint with the one the server's administrator gave you.
Trust this key? [y]es, [o]nce, [N]o:
stdout:
Mounted 127.0.0.1 on X:.
```

The fingerprint equals the SHA-256 of the fixture host key in `state/env`. The answer stored the key
in the user store (`[127.0.0.1]:2222 ssh-ed25519 AAAA...Pk # added=2026-10-25`). Later mounts of the
same server did not ask again (`--prompt none` succeeded).

Bug found here and fixed: the first run printed `(port 2,222)`; the port went through the
locale-grouped integer formatter. See "Fixes made during acceptance".

`dir X:\` listed the remote home directory (volume label `127.0.0.1`, 17 files, 39 directories).

### 2. `shelldrive list --json` while mounted

```
{"ok":true,"result":{"mounts":[{"mount_id":"m-1","profile":"127.0.0.1","target":"X:","backend":"dokany","state":"mounted","host":"127.0.0.1","port":2222,"user":"<wsl-user>","read_only":false}]}}
```

Text form: `X:  mounted  <wsl-user>@127.0.0.1:2222  127.0.0.1` / `1 drive mounted.`

### 3. 1 GiB copy in and out

Source: 1 073 741 824 random bytes (`RandomNumberGenerator`, written locally).

| Step | Command | Time | Throughput |
|---|---|---|---|
| in | `Copy-Item <local>\rand1g.bin X:\sd-m0-accept\rand1g.bin` | 15.73 s | 65.1 MiB/s |
| out | `Copy-Item X:\sd-m0-accept\rand1g.bin <local>\back1g.bin` | 19.17 s | 53.4 MiB/s |

SHA-256 (`Get-FileHash`):

| File | SHA-256 |
|---|---|
| local source | `FECF653E345250BD6522A199BD6F3EEA98DC8DF2DF17918EF09054F087DD7441` |
| copied back | `FECF653E345250BD6522A199BD6F3EEA98DC8DF2DF17918EF09054F087DD7441` |
| `Get-FileHash` directly on `X:\...` | `FECF653E345250BD6522A199BD6F3EEA98DC8DF2DF17918EF09054F087DD7441` |
| `sha256sum` on the server (WSL) | `fecf653e345250bd6522a199bd6f3eea98dc8df2df17918ef09054f087dd7441` |

Observation: `Get-FileHash` straight from `X:` took 228.6 s (4.5 MiB/s). It reads in 4 KiB
requests and M0 has no read-ahead, so each small read is one SFTP round trip. Large-buffer readers
(Explorer, `Copy-Item`, robocopy) are not affected. Read-ahead is later work (see "Remaining gaps").

### 4. Rename, delete, directories

Run in `X:\sd-m0-accept`:

```powershell
"hello m0" | Set-Content -Encoding ascii a.txt
Move-Item a.txt b.txt                       # a.txt gone, b.txt present
cmd /c "ren b.txt c.txt && dir /b"          # c.txt
New-Item -ItemType Directory sub1; cmd /c "mkdir sub2"
Copy-Item c.txt sub1\inner.txt
Move-Item sub1 sub1-renamed                 # directory rename; inner.txt reads "hello m0"
Remove-Item sub1-renamed -Recurse; cmd /c "rmdir sub2"; cmd /c "del c.txt"
"x" | Set-Content Case.txt; Rename-Item Case.txt case.TXT    # case-only rename
"y" | Set-Content other.txt; Move-Item -Force other.txt case.TXT   # replacing rename, content "y"
Move-Item rand1g.bin big.bin                # rename of the 1 GiB file
Remove-Item case.TXT; Remove-Item X:\sd-m0-accept\big.bin
```

Every step gave the expected listing; `ls -la` on the server matched (after the renames only
`big.bin`, 1 073 741 824 bytes, was left; then it was deleted).

### 5. Explorer

```powershell
Start-Process explorer.exe X:\sd-m0-accept
$sh = New-Object -ComObject Shell.Application
$sh.NameSpace("X:\").Items().Count                     # 57 (17 files + 39 directories + sd-m0-accept)
$sh.NameSpace("X:\sd-m0-accept").Items()               # big.bin 1073741824
$sh.Windows() | ? LocationURL -like 'file:///X:*'      # file:///X:/sd-m0-accept, Folder.Items().Count = 1
```

The window was closed with `.Quit()` before the unmount.

### 6. Unmount and handles

```
> shelldrive unmount X:
Unmounted X:.                                (exit 0, 0.04 s)
> Test-Path X:\                              False
> shelldrive list --json
{"ok":true,"result":{"mounts":[]}}
```

Leak check on the agent (handle counts per object type from `NtQuerySystemInformation`, agent kept
running between cycles):

| Cycles | Total handles | By type |
|---|---|---|
| 20 failing mounts (SSH up to user auth) | +0 | all types unchanged |
| 20 `list` calls (IPC only) | +0 | unchanged |
| 20 full mount + unmount cycles | +6 (279 to 285) | Event +3, Thread +3; File, Key, Semaphore, IoCompletion unchanged |

No per-mount leak: the small growth is in thread-pool worker threads (Dokany and the work items of
sd_ssh run on the system pool) and their events; the number of thread handles (21) stays below the
number of live threads (23). Over 41 earlier cycles the growth flattened in the same way.

### 7. Host key mismatch

The fixture host key was replaced (`ssh-keygen -t ed25519` in
`~/.local/state/shelldrive-wsl-sshd/`, original kept aside) and the fixture sshd restarted. New key
`SHA256:uTn/IQMCqlLXFFVRgyfgPyTm7qY3qm1UP597jhnQbjI`.

```powershell
"yes`nyes" | shelldrive mount --host <wsl-user>@127.0.0.1:2222 --identity $key --letter X: --stdin
```

```
Connecting to 127.0.0.1...
The identity of 127.0.0.1 has changed. ShellDrive stopped the connection.
Stored key: ssh-ed25519 SHA256:B1tQ1nxJtfNQumYUZBIsP+7jBiY8NBy8hYsi+9L6BdI (%APPDATA%\LibreStatic\ShellDrive\known_hosts, line 1)
Key offered now: ssh-ed25519 SHA256:uTn/IQMCqlLXFFVRgyfgPyTm7qY3qm1UP597jhnQbjI
If the server's key really changed, remove the old key from that file and connect again.
```

Exit code 6, no question asked although `yes` was waiting on stdin, `X:` not created, known_hosts
unchanged. JSON form (`--json ... --prompt none`):
`{"ok":false,"error":{"code":"host_key_mismatch","detail":"session failed","exit_code":6}}`, exit 6.

The original key was put back, the fixture restarted (`state/env` again shows the original
`hostkey=`), and a mount without prompts succeeded again.

## Fixes made during acceptance

- CLI (`apps/shelldrive/cli_cmds.c`): ports and known_hosts line numbers were formatted with
  `SD_ARG_INT`, which applies the user's digit grouping (`port 2,222`). They are now plain decimal
  strings. Regression: `tests/apps/test_smoke.c` mounts `carol@new.test:2222` and expects
  `(port 2222)`.

## Build and test status

Clean build trees, `Visual Studio 17 2022` generator, WSL fixture running, Dokany 2.3.1 installed.

| Preset | Build | CTest |
|---|---|---|
| `x64-modern` (Release) | 0 warnings | 26/26 passed, 0 skipped |
| `x64-modern-debug` | 0 warnings | 26/26 passed, 0 skipped |
| `x64-xp` (Release) | 0 warnings (only the known `mt.exe` 81010002 note) | 26/26 passed, 0 skipped |
| `x64-xp-debug` | 0 warnings (same note) | 26/26 passed, 0 skipped |
| `x64-analysis` (Debug, `/analyze`) | 0 warnings | 26/26 passed, 0 skipped |

`interop.ssh`, `interop.sftp` (WSL fixture) and `dokany.mount` (real Dokany 2.3.1 mount) ran and
passed in every preset; none reported "Skipped". The x64-xp import audit of `shelldrive-host.exe`
now passes: the WinSock ordinal imports are reported by name, e.g. `ws2_32.dll!closesocket (by
ordinal #3)`.

## Remaining gaps

- No read-ahead in `sd_vfs`: 4 KiB sequential readers get about 4.5 MiB/s over loopback (each read
  is one round trip). Bulk copies are fine (53-65 MiB/s).
- The JSON error of a host key mismatch carries only `code`/`detail`; the stored and offered
  fingerprints are printed by the text output only.
- `Z:` could not be tested on this machine (local volume); `X:` was used.
- The empty test directory `~/sd-m0-accept` on the WSL fixture account was left behind: the agent
  harness of this run refused to remove that path. Remove it by hand (`rmdir ~/sd-m0-accept` in WSL).
