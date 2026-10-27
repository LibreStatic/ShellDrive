# M4 notes: updater engine (sd_update)

Scope of this branch (`wip/m4-updater`): the updater engine of 04 §9, the agent methods `update.check` and
`update.apply`, the offline signing tool `sd-updsign`, and the tests. The Settings update group in the UI is a
later change; it uses the IPC described below. Design decisions taken here are recorded in 04 §9.7.

## Files

| Path | What |
|---|---|
| `src/sd_update/include/sd_update/sd_update.h` | public API: result codes, versions, keys, keyset and manifest types, state, transport, engine |
| `src/sd_update/update_verify.c` | pure part: strict manifest and keyset syntax, the signature chain, base64, dates, version compare |
| `src/sd_update/update_state.c` | `last_serial.<channel>`, `last_verified.<channel>`, `keyset`, `roots`, `manifest.<channel>` (atomic writes) |
| `src/sd_update/update_winhttp.c` | WinHTTP transport, every entry point resolved at run time; redirect allow list; size limits |
| `src/sd_update/update_engine.c` | check, stage, apply (setup run, file swap with rollback), flavour detection, staging cleanup |
| `apps/shelldrive-host/update_ipc.c` | `update.check`, `update.apply`, events, policy and settings reads |
| `tools/sd-updsign/sd-updsign.c` | offline signing tool (release pipeline only, never shipped) |
| `tests/unit/sd_update/` | unit tests: pure verification, state, engine over a loopback server (`sd-test-update.exe`) |

## Signing tool (`sd-updsign`)

The tool is built with the rest of the tree (`build/<preset>/bin/Debug/sd-updsign.exe`). It is not in any
installer and the product never calls it. Commands:

```
sd-updsign keygen   --seed <file> [--pub <file>]         new ed25519 key: prints "pubkey <base64>" and "key-id <16 hex>"
sd-updsign pubkey   --seed <file>                        public key and key id of an existing seed file
sd-updsign sign-keyset   --in <body> --root <seed> [--root <seed>] --out keyset.txt
sd-updsign sign-manifest --in <body> --key <seed> --out manifest.txt
sd-updsign hash     --file <path> [--alg 256|512]        "sha256:<hex>" for a `file` line
```

- `<body>` is the unsigned text: it ends with LF and has no `sig` line. The tool appends one `sig ed25519 <key-id>
  <base64>` line per signer (keyset: one per root; manifest: one). The signed bytes are the domain string of
  `sd_update.h` followed by the body.
- Seed files hold 32 bytes as 64 hex digits. The production seeds are created and kept on the offline signing
  machine in an encrypted volume (04 §9.3); the root keys never touch a networked machine or CI. The tool writes the
  seed in clear text, so use it only on that machine or in a test directory.
- Release order (04 §12.3): sign the keyset with both current roots only when the roots change, otherwise with one
  root; sign the manifest with the channel key whose id the keyset lists for that channel; re-sign the current
  manifest of each channel every two weeks with a new serial (TM-R36).
- Manifest lines for an artifact: `file <id> <name> <size> sha256:<hex>` (size in bytes, the digest from `hash`).
  `base` lines are the download prefixes (HTTPS first, then the HTTP mirror), each ending with `/`.
- Example (test-style, one root for brevity):

```
sd-updsign keygen --seed C:\secure\root-a.seed --pub C:\secure\root-a.pub
sd-updsign keygen --seed C:\secure\stable.seed
sd-updsign hash --file dist\ShellDrive-1.1.0-setup.exe
sd-updsign sign-manifest --in manifest.body --key C:\secure\stable.seed --out manifest.txt
```

## Client configuration (agent)

- Settings (`settings.ini`, 03 §3.4): `[update] enabled`, `channel` (`stable` or `beta`), `manifest_url`
  (https or http). Machine values in `%ProgramData%\LibreStatic\ShellDrive\settings.ini`, user values in
  `%APPDATA%\LibreStatic\ShellDrive\settings.ini`, portable values in `<exe dir>\data\settings.ini`.
- Policy (`HKLM` wins over `HKCU`, `Software\Policies\LibreStatic\ShellDrive`): `DisableUpdateCheck` (DWORD),
  `UpdateChannel`, `UpdateUrl` (REG_SZ).
- State: `%LOCALAPPDATA%\LibreStatic\ShellDrive\state\` (per user), `%ProgramData%\LibreStatic\ShellDrive\state\`
  (per machine, read only for the agent), staging `%LOCALAPPDATA%\LibreStatic\ShellDrive\updates\<version>\`.

## Contract changes (IPC, 03 §2.8)

Proto stays 1. Additive changes only.

Methods:

| Method | Params | Reply | Notes |
|---|---|---|---|
| `update.check` | none | `{enabled, reason?, available, channel, stale, version?, notes?, size?, file_id?, serial?}` | deferred (network). Disabled by policy or settings: `enabled: false`, `reason` `policy` or `settings`, no network |
| `update.apply` | `{consent: true}` | `{applied, state: "applied" or "up_to_date", version?}` | deferred. `consent` is required. Refused for portable installs and when disabled |

Errors (IPC codes, exit code in brackets): `consent_required` (1), `update_disabled` (1), `busy` (1),
`update_verify_failed` (17, existing), `update_unavailable` (1, no base reachable or redirect refused),
`update_no_target` (1), `update_apply_failed` (1), `selftest_failed` (17, existing).

Features in `hello`: `update`, `update.check`, `update.apply` (the Settings group is greyed out while they are absent).

Events (topic: every client that completed hello, like `config.changed`):

| Event | Data | When |
|---|---|---|
| `update.available` | `{version, channel, notes, size, file_id}` | a verified manifest offers a newer version |
| `update.progress` | `{stage: "downloading" or "applying" or "done" or "failed", version}` | during `update.apply` |
| `update.stale` | `{days}` | a check failed and the last verified manifest is older than 14 days |

The M3 test that expected `update.check` to be absent was updated (tests/apps/test_agent_m3.c).

## Tests

`ctest --preset x64-modern-debug -R update -LE "matrix|bench|interop"` runs `sd-test-update.exe` (34 tests). Fixtures are
made at test time by `sd-updsign` in a temporary directory (test keys only, removed afterwards). The engine tests run a
winsock server bound to `127.0.0.1` on an ephemeral port; no test connects anywhere else. The "new binaries" are copies of
`sd-test-update-fakeapp.exe`, whose `--selftest` (and `/update`) exit code is read from a `selftest.code` file next to it.

Covered: valid chain; manifest byte flip; wrong key (unknown key id); beta key on stable and stable key on beta; expired
keyset key; revoked key; expired manifest; freshness limits (30/14 days); serial rollback and same-serial-other-bytes;
channel mismatch; product mismatch; unknown format major; oversized manifest; sig line not last; keyset tampering;
keyset rollback; keyset signed by an unknown root; rotation with one root (refused) and both roots (accepted); per-channel
serials and the legacy migration; check, stage, apply and rollback in a temporary install directory; `--selftest` failure
restoring the old files byte for byte; HTTPS to HTTP fallback; redirect to a foreign host refused without connecting;
Content-Length above the manifest size; digest mismatch with nothing kept; setup exit code; staging cleanup.

## Open decisions

- **Release roots:** no root public key is compiled into this build. The release build must add the two root keys and
  the keyset current at build time (`installer/keys/`, 04 §9.3); until then every verification fails closed
  (`update_verify_failed`). The `k_trust` table in `update_ipc.c` is the single place to change.
- **Bootstrap URLs:** only the GitHub URL is the default. The HTTP mirror (`http://dl.<our-domain>/...`) needs the domain
  (D30, an operational choice); until then, testers set `manifest_url`. The `manifest_alt` slot exists for it.
- **Beta:** there is no default beta manifest URL; a beta user sets `manifest_url` and `channel = beta`.
- **Install mode:** the agent always uses setup mode. MSI installs (`msi-<flavour>`) and the detection of an MSI
  install are not implemented; the engine supports the mode.
- **Portable updates:** check only. Unpacking a portable archive is not implemented (no zip reader in the product).
- **Per-machine updates:** the elevated stages of 04 §6.4 and §9.6 (admin-only copy, re-verification in stage 2) are the
  setup program's job and are not in the agent.
- **Progress granularity:** the events report stages, not byte counts.
- **Trust state:** `state\keyset` and `state\roots` are trusted as local files (see 04 §9.7).
