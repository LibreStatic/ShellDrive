# M2 acceptance run

Acceptance of the M2 milestone (00 §6, row "M2 — Authentication breadth and transport") on this Windows 11
machine with the real interop stack, from the `wip/m2-backend` tree at `147ca33` plus the uncommitted
acceptance doc. The M2 row also names a lab part and a review gate that this run does not cover; see
"Not covered".

## Environment

| Item | Value |
|---|---|
| Machine | AMD Ryzen 7 2700X, Windows 11 IoT Enterprise LTSC 2024 (10.0.26100), x64, non-elevated user |
| Build | `x64-modern` Debug (`cmake --build --preset x64-modern-debug`); `shelldrive.exe` and `shelldrive-host.exe` import-audited |
| Matrix fixtures | WSL, OpenSSH 9.6p1 / 10.x instances, Python stdlib HTTP and SOCKS5 proxies (`tests/fixtures/matrix`); endpoints from `tests/fixtures/matrix/state/endpoints.env` |
| wsl-sshd fixture | `tests/fixtures/wsl-sshd`, port 2222 (already running; `start.ps1` reported it up) |
| Squid | not listening (the fixture reports `squid: stopped`; the Squid package needs the one-time sudo step, see m2-notes) |
| Dante | running on port 2292 (the row needs no username auth, so it ran) |
| Dokany / WebDAV | not used by this run (the interop tests are protocol-level, not mount-level) |

Matrix output directory: `build/x64-modern/interop-matrix/` (`matrix.txt`, `matrix.json`, one CTest log and
JUnit file per row). Scratch logs of this run: `build/m2-matrix-run1.txt`, `build/m2-filter.txt`,
`build/ctest-full.txt`, `build/ctest-sftp-ssh-rerun.txt`.

## Results

### Interop matrix (`tests/interop/run-matrix.ps1`)

Command (reviewer):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests\interop\run-matrix.ps1 -BuildDir build\x64-modern -Config Debug
```

Fixture self-test (stock OpenSSH clients inside WSL): **57 pass, 0 fail, 1 skip** (`otp.login`, the
interactive TOTP login, is exercised by the ShellDrive tests instead).

| Row | Endpoint | Tests run (label `interop`) | Result |
|---|---|---|---|
| `modern` | 2222 | `interop.ssh`, `interop.sftp`, `interop.sftp_ssh`, `interop.ssh_matrix_connect`, `interop.ssh_matrix_kex` | pass (5/5) |
| `ossh10` | 2230 | `ssh_matrix_connect`, `ssh_matrix_kex`, `ssh_matrix_auth_keys` | pass (3/3) |
| `ossh10pq` | 2239 | `ssh_matrix_connect`, `ssh_matrix_kex`, `ssh_matrix_pq` | pass (3/3) |
| `legacy` | 2231 | `ssh_matrix_connect`, `ssh_matrix_kex` | pass (2/2) |
| `legacy3des` | 2238 | `ssh_matrix_connect`, `ssh_matrix_kex` | pass (2/2) |
| `cert` | 2235 | `ssh_matrix_connect`, `ssh_matrix_kex`, `ssh_matrix_auth_certs` | pass (3/3) |
| `rotate` | 2236 | `ssh_matrix_connect`, `ssh_matrix_update` | pass (2/2) |
| `jump2` | 127.0.0.2:2234 via bastion1 | `ssh_matrix_connect` | pass |
| `jump3` | 127.0.0.2:2234 via bastion1, bastion2 | `ssh_matrix_connect` | pass |
| `http-proxy` | ossh10 via HTTP CONNECT 2280 | `ssh_matrix_connect` | pass |
| `http-proxy-auth` | ossh10 via HTTP CONNECT 2281 (Basic) | `ssh_matrix_connect` | pass |
| `socks5` | ossh10 via SOCKS5 2290 | `ssh_matrix_connect` | pass |
| `socks5-auth` | ossh10 via SOCKS5 2291 (RFC 1929) | `ssh_matrix_connect` | pass |
| `dante` | ossh10 via SOCKS5 2292 | `ssh_matrix_connect` | pass |
| `otp` | 2237 (TOTP keyboard-interactive) | `ssh_matrix_connect` | pass |
| `demo` | SOCKS5 auth 2291 -> OTP bastion 2237 -> target, PPK v3 key, ML-KEM expected | `ssh_matrix_connect` | pass |
| `squid` | ossh10 via Squid 2282 | not run | fixture-down (squid not listening) |

Totals: 16 rows ran, 0 failures, 0 skips in the matrix proper; 1 row not run (`squid`). The matrix exit status
was 0 for the row set that ran.

The runner's own log lines per row are in `build/x64-modern/interop-matrix/<row>.log`; the modern row also
ran the M1 `interop.sftp_ssh` (passed, 78.6 s).

### Striping and pool (`sd-test-sftp-ssh-interop --filter m2_`)

Command (reviewer; needs the wsl-sshd fixture up):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests\fixtures\wsl-sshd\start.ps1
build\x64-modern\bin\Debug\sd-test-sftp-ssh-interop.exe --filter m2_
```

| Test | Result |
|---|---|
| `m2_pool_admits_members` | pass (3 connections admitted, `POOL member 1 -> 2`, `2 -> 3`) |
| `m2_pool_interactive_stays_at_one` | pass (a passphrase answered by the user keeps the pool at 1) |
| `m2_striping_end_to_end` | pass (32 MiB striped write and read-back over 3 connections, SHA-256 verified) |
| `m2_striping_member_lost_mid_transfer` | pass (one member dropped mid-transfer; the primary read recovers byte-exact, the session stays READY, a follow-up striped transfer succeeds on the survivor) |

Result: 4 tests, 0 failed. Same binary in the full CTest run: see "Plain CTest" below.

Unit side, from the same CTest run: `unit.sftp` (fake transport, 22 striping tests among the suite) passed
in 37.9 s; `unit.vfs` (striping policy, 5 tests in `test_vfs_stripe.c`) passed in 6.2 s.

**Striping and pool numbers** (from m2-notes, measured 2026-10-26 on the same `x64-modern` Debug fixture,
1 GiB through `sd_vfs`, not re-measured in this run):

| Pattern | Write | Read |
|---|---|---|
| `connections = 1` | 52.2 MB/s | 49.9 MB/s |
| `connections = 3` striped | 53.4 MB/s | 92.2 MB/s |

Read scales 1.85x with three connections; write does not (1.02x) on this fixture, because the primary bulk
channel is already saturated with `max_write` at 256 KiB. The bench is opt-in:
`SD_IT_BENCH=1 build\x64-modern\bin\Debug\sd-test-vfs-bench.exe` (label `bench`, not run here).

### Plain CTest (`ctest -C Debug -LE "matrix|bench"`)

Command (reviewer):

```powershell
ctest --test-dir build\x64-modern -C Debug -LE "matrix|bench" --output-on-failure
```

Result: **33 of 34 passed**. All unit suites (`unit.*`, `importcheck.*`, `l10n.*`, `isacheck.selftest`,
`webdav.redirector`, `dokany.mount`) passed, plus `interop.ssh`, `interop.sftp` and `unit.crypto_pk`
(135 s).

The one failure was `interop.sftp_ssh` (exit 8). Its failing check was the write-side member loss,
`m2_striping_member_lost_mid_transfer`: during a frozen-link 24 MiB write burst, 9 of 24 burst writes
failed with error 18 (expected: `SD_E_DISCONNECTED` for the dropped member), but the session left READY
(state 3, then 4 "disconnected, retry 1") and the pool reported 1 connection instead of 2. The other
striping tests in the same binary passed.

Classification (one re-run of the single CTest entry, as the runner's rule requires):

```powershell
ctest --test-dir build\x64-modern -C Debug -R "^interop\.sftp_ssh$" --output-on-failure
```

Re-run: **pass** (76.3 s, all four `m2_` tests). The same test also passed in the matrix's `modern` row and in
the `--filter m2_` run. Verdict: **flake, not reproduced**. The mechanism (the session leaving READY after a
single member loss during a write burst) is a timing-dependent path and is a candidate for a race; it is not
confirmed as a defect and is listed under "Known gaps" for follow-up. No product code was changed.

## Known gaps

- **`squid` row not run.** Squid is not running (needs `sudo apt install squid`, the one-time step in
  `tests/fixtures/matrix/README.md`). The row is fixture-down, not failed.
- **`interop.sftp_ssh` flake.** One of three runs of `m2_striping_member_lost_mid_transfer` failed in the full
  CTest run and passed on re-run and in the other two runs. Needs a repeat-run loop (e.g. 20x) and a look at
  why the session leaves READY after a single member drop in a write burst before it counts as closed.
- **Striping numbers not re-measured.** The 1 GiB table above is the 2026-10-26 measurement; the bench was
  not run in this acceptance.
- **Not covered by this run:** the M2 row's lab parts (x86-ia32 and x86-sse2 CLI tests on the Pentium III VM,
  Win7 and XP images), the `ci-local.ps1 -Clean` milestone gate, the D38 external crypto review pass 1 (the
  M2 gate in 00 §6), and the per-feature checks the row lists (Pageant, Credential Manager, DPAPI, PuTTY and
  OpenSSH importers, the CLI demo recording). They are covered by unit and interop suites elsewhere, not by
  this matrix run.
- **Matrix ran in Debug.** The M1 acceptance used Release; the interop tests are the same source, but a
  Release matrix run is not part of this record.

## Not in this document

Fixture credentials, the OTP secret and host-specific paths are not recorded here. The OTP row was run with the
fixture's TOTP secret read by the test binary in-process; nothing was printed.
