# Interop matrix runner

`run-matrix.ps1` starts the WSL fixtures (`tests/fixtures/wsl-sshd`, `tests/fixtures/matrix`), runs the fixture
self-test, then runs the `interop`-labelled CTest set of a build directory once per **row** (a server, a jump
chain or a proxy path) with the row's endpoints in `SD_IT_*` environment variables, and prints a
test x row table (`pass` / `fail` / `skip`, `.` = not selected for that row). Test infrastructure only (D21).

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests\interop\run-matrix.ps1 -BuildDir build\x64-modern
#   -Config Debug  -Rows ossh10,jump2,demo  -Keep (leave fixtures running)  -NoStart  -NoSelfTest  -Ctest <path>
```

- Fixtures that were already running are left alone; the ones the run started are stopped at the end unless `-Keep`.
- Results: `<build>/interop-matrix/` (`matrix.txt`, `matrix.json`, one CTest log and JUnit file per row).
- Exit status 1 if any test or self-test check failed.

## Label convention (for test owners)

| Labels on the test | Rows it runs in |
|--------------------|-----------------|
| `interop` only (M1 tests) | `modern` |
| `interop;srv_<row>[;srv_<row2>...]` | the named rows |
| `interop;srv_all` | every row whose fixtures are up |

A test that cannot do anything useful in a row (for example a direct-connect test in a `jump2` row) exits 77
(`SKIP_RETURN_CODE 77`), shown as `skip`. Tests that kill or restart fixtures keep `RESOURCE_LOCK`.

## Rows and the per-row variables

Every row sets `SD_IT_SERVER` (row name), `SD_IT_HOST`, `SD_IT_PORT`, `SD_IT_KEY`, and as needed `SD_IT_CERT`,
`SD_IT_JUMP` (OpenSSH `ProxyJump` syntax `user@host:port[,user@host:port]`, hops in order), `SD_IT_PROXY`
(`http://[user:pass@]host:port` or `socks5://[user:pass@]host:port`, applies to the **first** hop),
`SD_IT_EXPECT_KEX`, `SD_IT_EXPECT_LEGACY=1` (the client must raise its legacy-algorithm warning), `SD_IT_OTP`
(`1` = keyboard-interactive TOTP on the first hop) and `SD_IT_FEATURES` (comma list, informative). All global
`SD_IT_*` variables from `tests/fixtures/matrix/state/endpoints.env` are set too (`SD_IT_ENV_FILE` points at it);
see `docs/dev/m2-notes.md`.

| Row | Endpoint | Notes |
|-----|----------|-------|
| `modern` | 2222 | M1 fixture, key `tests/fixtures/wsl-sshd/state/client_ed25519` |
| `ossh10`, `ossh10pq` | 2230, 2239 | `SD_IT_EXPECT_KEX=mlkem768x25519-sha256` |
| `legacy`, `legacy3des` | 2231, 2238 | RSA key; `SD_IT_EXPECT_LEGACY=1` |
| `cert` | 2235 | `SD_IT_CERT` = ed25519 user certificate; host CA in `SD_IT_HOST_CA` / `known_hosts` |
| `rotate` | 2236 | drive rotation with `wsl.exe -e sh $env:SD_IT_FIXTURE_SH rotate ab` etc. |
| `jump2`, `jump3` | 127.0.0.2:2234 | via bastion1 (and bastion2) |
| `http-proxy`, `http-proxy-auth`, `socks5`, `socks5-auth` | ossh10 via 2280/2281/2290/2291 | |
| `squid`, `dante` | ossh10 via 2282/2292 | only when installed (sudo) |
| `otp` | 2237 | only after the one-time sudo step (`tests/fixtures/matrix/README.md`) |
| `demo` | SOCKS5 (auth) -> otp bastion (bastion1 without the sudo step, `SD_IT_OTP=0`) -> target | PPK v3 key, ML-KEM expected: the M2 demo path |

Rows whose fixtures are down are listed as `fixture-down (...)` under the table and not run.
