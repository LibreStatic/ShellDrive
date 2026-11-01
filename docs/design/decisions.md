# Design decisions (accepted 2026-10-24)

Authoritative record of the user's answers to `00-integration-review.md` → "Decisions for the user".
Where this file differs from the review's recommendation, this file wins.

| Id | Decision | Notes / consequences |
|---|---|---|
| D1 | **Zero third-party code**, crypto included. No fiat-crypto, no Monocypher, no BearSSL. | Field arithmetic for curve25519/P-256/P-384/P-521, bignum, ML-KEM, SHA-3 are all ours. Compensate with Wycheproof + RFC vectors, differential testing against CNG (Vista+/10+) in CI, fuzzing, constant-time checks (dudect-style timing tests), and an external crypto review before 1.0. Reference designs may be *read* (papers, RFCs, specs); no code is copied. Amendment A6 is replaced by "no exception". |
| D2 | Hashes/HMAC always own code; CNG only as a differential-test reference. | |
| D3 | Four binaries: `shelldrive.exe`, `shelldrive-host.exe` (agent + service modes), `shelldrive-ui.exe`, `shelldrive-shellext.dll`. | |
| D4 | **Two x86 builds**: `x86-ia32` (`/arch:IA32`, no SSE2, Pentium Pro/III/Athlon XP class) and `x86-sse2`. The setup stub picks via `IsProcessorFeaturePresent(PF_XMMI64_INSTRUCTIONS_AVAILABLE)`. | The setup stub itself is built IA32. Crypto has portable scalar paths for both; SSE2/SHA-NI/AES-NI fast paths only in the SSE2 build (runtime-detected). CI matrix gains one x86 flavour. Amendment A8 becomes "x86 ships IA32 and SSE2 builds". |
| D5 | ARM32 best effort: CI build, CLI + agent + WebDAV only, dropped if the toolchain breaks. | Amendment A7. |
| D6 | **Service enabled by default** on per-machine installs. | Per-user installs never install a service. Corporate MSI keeps a property to turn it off. Changes 03/04 defaults. |
| D7 | `~/.ssh/known_hosts` and PuTTY as live read-only trust sources, on by default; matches copied into our file with a source comment; mismatches in any source block. | |
| D8 | Our `known_hosts` is written plain. | |
| D9 | **Write mode configurable per profile; default is synchronous (write-through).** Write-behind (16 MiB window, 60 s grace retransmit, always-on `write_failed` notification) is opt-in. | Amendment A5 rewritten: "By default every write is acknowledged by the server before it completes for the application. Profiles may opt into write-behind, in which case …". Performance targets in 02 §11 must state which mode they assume. |
| D10 | uid/gid without exec: owner of home + first created file; `identity_probe = exec` optional per profile. | |
| D11 | **Attempt global WebDAV drives.** Investigate in the lab whether a LocalSystem-hosted WebDAV mount can be made visible globally (XP/2003 documented behavior, Vista+ unknown). Dokany global drives remain the primary path. | Lab spike scheduled early in M5 with a go/no-go; if no-go on an OS, that OS falls back to per-user attach at logon. Amendment A4 rewritten accordingly. |
| D12 | **Symlink reparse points postponed** (no fork, no upstream work for now). v1: `follow` or `hide` (default superseded by D40: `follow_inside`). Revisit after 1.0. | Amendment A3. A self-built Dokany fork was rejected: it would need our own EV cert + attestation signing, which only loads on Win10+, and conflicts with an existing official Dokany install. |
| D13 | Amendments A1–A9 accepted **as adjusted by this file** (A3, A4, A5, A6, A8 changed above). | |
| D14 | **"Add network location" (Network Shortcuts) in v1.** | Moves from M7 into M3. |
| D15 | **ML-KEM hybrid KEX (`mlkem768x25519-sha256`) in v1, milestone M2.** No sntrup761. | Own ML-KEM-768 and SHA-3/SHAKE (D1). |
| D16 | **UpdateHostKeys (`hostkeys-00@openssh.com` + `hostkeys-prove-00`) in v1.** | New keys are only accepted when proven and announced over a connection authenticated with an already-trusted key; never for the machine store without admin policy. |
| D17 | No SSH agents in the service context; service uses its own DPAPI-protected keys. | |
| D18 | **Parallel SSH connections per mount in v1** (pool of 1–4, default 1, profile option). | Extra connections are opened only when authentication is non-interactive (key, agent, stored password/passphrase) so the user never gets repeated 2FA prompts; otherwise the pool stays at 1. Bulk transfers are striped across connections; metadata stays on the primary. Reconnect logic is per connection. |
| D19 | Two SFTP channels (metadata + bulk) on the primary connection, auto-degrade to one. Extra pool connections (D18) open a bulk channel only. | |
| D20 | **HTTP CONNECT and SOCKS5 proxies in v1** (per profile and per ProxyJump hop, with optional proxy auth: Basic for HTTP — NTLM/Negotiate via SSPI optional —, username/password for SOCKS5). **No ProxyCommand.** | Also honor the system proxy (WinHTTP/WinINet settings) as an opt-in source. |
| D21 | Linux/OpenSSH allowed as test infrastructure only (WSL sshd on runners, self-hosted lab, optional Linux fuzz job). Nothing of it ships. | |
| D22 | `FILE_ATTRIBUTE_OFFLINE` thumbnail suppression on WebDAV: profile option, default off. | |
| D23 | Dokany reports `NTFS` by default, configurable. | |
| D24 | `EnableLinkedConnections` as MSI property, default 0. | |
| D25 | Per-user overrides of machine templates: target (letter/folder) and autostart only. | |
| D26 | **Full CLDR plural categories** for every locale. | Message catalog and `sdl10n` must support zero/one/two/few/many/other; es/fr/it/pt use `many` per CLDR. |
| D27 | Windows 11 modern context menu (sparse MSIX) in v1 **if** the code-signing certificate exists in time; otherwise 1.0 ships the classic menu and the modern one lands in 1.x. | |
| D28 | **Ship a second x64 flavour in 1.0**: `x64-modern` (v143, `/guard:cf`, CET shadow stack compatible, Win10+) alongside `x64-xp` (v141_xp). Setup stub picks by OS version. | Doubles x64 test runs. |
| D29 | Code signing: SignPath Foundation, else Certum OSS, obtained before a public 1.0. | |
| D30 | Update mirror: static plain-HTTP object storage, integrity via ed25519 manifest. | |
| D31 | **Ship an ARM32 MSI** too. | |
| D32 | Dokany redistributable: official per-arch MSIs if `dokan2.dll` has no VC++ runtime dependency; otherwise the official `DokanSetup.exe` bundle in offline EXEs. | |
| D33 | **Legacy algorithms stay as decided (maximum compatibility)**: enabled by default, ranked last, UI warning only. Threat-model Q01 (ask + 2048-bit floor) rejected. | Includes DH group1 and small GEX groups. The UI warning and `legacy_mask` remain; profiles/policy can still restrict. |
| D34 | **Terrapin: choose the cipher after the server's KEXINIT (TM-R01).** If the server lacks strict KEX, avoid chacha20-poly1305 and CBC+ETM and prefer AES-GCM/CTR; if only affected ciphers exist, connect with the exposure flag and warning. | Q02 not needed. |
| D35 | **No implicit `service_access` default for global drives**: the admin must choose who can access when creating a service profile; non-admins are read-only unless granted write. | Replaces the `BUILTIN\Users` default. |
| D36 | **Dokany install is an explicit, pre-checked option** on the setup page (7 SP1+), explaining it installs a signed third-party kernel driver; unchecking leaves WebDAV only. An MSI property mirrors it. | |
| D37 | **`identities_only = yes` by default when a profile configures an identity**: only that key (and its certificate) is offered. | |
| D38 | **External crypto review in two passes**: pass 1 at the end of M2 (all SSH + crypto), pass 2 before 1.0. No public betas before pass 1. | |
| D39 | **All other threat-model recommendations TM-R02..R39 accepted**, adjusted by D33. | |
| D40 | **Symlinks default to `follow_inside`** (links resolving outside the mount root appear dangling); `follow` and `hide` remain profile options. Supersedes the "follow (default)" part of D12. | |
| D41 | **Shell-active files (`.library-ms`, `.url`, `.scf`, `.lnk`, remote-icon `desktop.ini`, …) are gated by profile trust**: `security.trust = untrusted` (the default) blocks them for every process; `trusted` allows them. `shell_active_files` can override per profile. | |
| D42 | **Stable releases use two offline signing sessions** (payload tables first, then the update manifest over the final EXEs). | |
| D43 | **Keep 03's additions** (`service repair-data`, hidden `--watch-elevated-view`, service-pipe `attention` topic and `reserved_letters`, `security.trust`) **except `--include-secret-stacks`, which is removed**: crash dumps never include secret-bearing stacks. | |
| D45 | **Everything is labeled under the LibreStatic organization.** Repository `github.com/LibreStatic/ShellDrive`. Publisher / `CompanyName` / ARP publisher: `LibreStatic`. Reverse-DNS id `com.librestatic.shelldrive` for every free-form identifier: AppUserModelID, MSIX package name, update channel/product ids, signing key ids, ETW provider name, Credential Manager target prefix (`com.librestatic.shelldrive:`), named pipes (`\\.\pipe\com.librestatic.shelldrive.<role>.<SID>.<session>`), kernel object names (`Global\com.librestatic.shelldrive.<name>`), ADMX namespace (`com.librestatic.shelldrive.policies`). Registry: `HKCU\|HKLM\SOFTWARE\LibreStatic\ShellDrive`, policies `SOFTWARE\Policies\LibreStatic\ShellDrive`. Folders: `%APPDATA%\LibreStatic\ShellDrive`, `%LOCALAPPDATA%\LibreStatic\ShellDrive`, `%ProgramData%\LibreStatic\ShellDrive`, `%ProgramFiles%\LibreStatic\ShellDrive`, per-user `%LOCALAPPDATA%\Programs\LibreStatic\ShellDrive`. C symbols keep the `sd_` prefix; the service name stays `ShellDriveSvc`; product and binary names stay `ShellDrive` / `shelldrive*`. | Set 2026-10-24 at the user's request. |
| D46 | **The repository is public** (`github.com/LibreStatic/ShellDrive`), so GitHub Actions minutes are free; 04 §9.5 "private repository (interim)" no longer applies. Local CI (`tools/ci-local.ps1`) stays the authority for interop and Dokany tests. | Set 2026-10-25 at the user's request. |
| D44 | **`mark_of_the_web` defaults to `off`, independent of `security.trust`** (confirmed by the user 2026-10-24). | Tying it to the `untrusted` default (D41) would tag every file on a Dokany drive with Mark-of-the-Web. |
| D47 | **OS-tiered UI (06-ui-tiers.md), option B**: one binary per flavour picks Classic (XP), Aero (Vista/7, glass band) or Fluent (8–11: flat on 8–10, Mica on 11 22H2+) at run time; full dark mode on Windows 11 and on 10 from 1809 through the undocumented uxtheme helpers behind an allow-list and a kill switch (`[ui] dark_helpers`, policy `UiDarkHelpers`); the menu bar becomes a "···" overflow on 10/11; Windows 11 tray flyout and Aero wizard in the first slice. | Set 2026-10-31 by the user from the mock-ups. Supersedes 03 §7.4's "no undocumented uxtheme ordinals". |

## Resulting build flavours

| Flavour | Toolset / SDK | Min OS | Notes |
|---|---|---|---|
| `x86-ia32` | v141_xp, 7.1A, `/arch:IA32` | XP SP3 | no-SSE2 CPUs |
| `x86-sse2` | v141_xp, 7.1A, `/arch:SSE2` | XP SP3 | default x86 |
| `x64-xp` | v141_xp, 7.1A | XP x64 SP2 / Vista+ | |
| `x64-modern` | v143, 10.0.26100, CFG + CET | Windows 10 | picked on Win10+ |
| `arm32` | v143, 10.0.22621 | Windows 10 on ARM / Windows 11 ≤ 23H2 (ARM32 app support) | best effort; Windows RT 8.1 runs no unsigned code, 10 IoT Core has no Windows Installer, 11 24H2+ dropped ARM32 |
| `arm64` | v143, 10.0.26100 | Windows 10 on ARM | |
