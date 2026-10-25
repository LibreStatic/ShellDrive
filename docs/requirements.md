# ShellDrive requirements

ShellDrive mounts remote hosts over SSH (SFTP) on Windows as virtual drives, the way SMB shares are mapped.

Design decisions that refine these requirements are recorded in `docs/design/decisions.md` (accepted 2026-10-24).

## Hard constraints
- No WinFsp, no sshfs-win, no Cygwin/MSYS, no ported Unix code (no OpenSSH, libssh, libssh2, OpenSSL ports).
  Everything is native Win32. The SSH client, SFTP client and the crypto that Windows lacks are our own code.
- **Zero third-party code, crypto included** (no fiat-crypto, Monocypher, BearSSL or similar). Field arithmetic,
  bignum, ML-KEM, SHA-3 and every other primitive are written by us. Papers, RFCs and specs may be read; no code
  is copied. Assurance comes from Wycheproof and RFC vectors, differential tests against CNG in CI, fuzzing,
  constant-time timing tests and an external crypto review before 1.0.
- Never break Windows signing policy: no test-signing, no unsigned drivers. The only allowed kernel component is
  an existing, already-signed, open-source driver: **Dokany** (redistributed as published upstream, never forked).
- Self-installing. Also runs portable.
- Language: plain C (C11 where the toolchain allows; must also build with the MSVC v141_xp toolset). Win32 API only.
  No heavy CRT dependencies; static linking.
- Minimum OS: Windows XP SP3 (x86). Target matrix: x86, x64, ARM32 (best effort) and ARM64, shipped as the
  flavours listed under "Build flavours".
- License: MIT. Dokany (LGPL/MIT) is loaded dynamically and shipped unmodified.

## Build flavours
| Flavour | Toolset / SDK | Min OS | Notes |
|---|---|---|---|
| `x86-ia32` | v141_xp, 7.1A, `/arch:IA32` | XP SP3 | no-SSE2 CPUs (Pentium Pro/III, Athlon XP class) |
| `x86-sse2` | v141_xp, 7.1A, `/arch:SSE2` | XP SP3 | default x86 |
| `x64-xp` | v141_xp, 7.1A | XP x64 SP2 / Vista+ | |
| `x64-modern` | v143, 10.0.26100, CFG + CET | Windows 10 | picked on Win10+ |
| `arm32` | v143, 10.0.22621 | Windows 10 on ARM / Windows 11 ≤ 23H2 (ARM32 app support) | best effort; Windows RT 8.1 runs no unsigned code, 10 IoT Core has no Windows Installer, 11 24H2+ dropped ARM32 |
| `arm64` | v143, 10.0.26100 | Windows 10 on ARM | |

- x86 ships both IA32 and SSE2 builds. The setup stub (itself built IA32) picks via
  `IsProcessorFeaturePresent(PF_XMMI64_INSTRUCTIONS_AVAILABLE)`. Crypto has portable scalar paths in both;
  SSE2/SHA-NI/AES-NI fast paths exist only in the SSE2 build and are runtime-detected.
- x64 ships `x64-xp` and `x64-modern` in 1.0; the setup stub picks by OS version.
- ARM32 is best effort: built in CI, supported only as CLI + agent with the WebDAV backend where WebClient exists,
  shipped as EXE and MSI, and dropped if the toolchain breaks.

## Binaries
- `shelldrive.exe` (CLI), `shelldrive-host.exe` (agent and service modes), `shelldrive-ui.exe` (tray and main
  window), `shelldrive-shellext.dll` (Explorer integration).

## Mount backends (hybrid)
1. **WebDAV backend (no driver):** available where the Windows WebClient (WebDAV redirector) feature is present
   and not disabled. WebClient has been deprecated since November 2023, so Dokany is the primary backend on
   Windows 7 SP1+. ShellDrive runs a local WebDAV server bridging to SFTP and maps it with the built-in redirector
   (WebClient service / MiniRedir; XP+). Must handle redirector quirks per OS version (file size limit registry
   value, authentication on loopback: Negotiate/NTLM via SSPI plus a per-mount path token, `BasicAuthLevel` is
   never changed; XP vs Vista+ behavior, WebClient service start, `\\host@port\DavWWWRoot` style paths, drive
   letter via WNetAddConnection2).
2. **Dokany backend (optional, Windows 7 SP1+, x86/x64/ARM64):** real drive with better semantics and performance.
   Auto-selected when available; the user can force either backend per profile.

## Connectivity
- ProxyJump with multiple hops.
- HTTP CONNECT and SOCKS5 proxies, per profile and per ProxyJump hop, with optional proxy auth (Basic for HTTP,
  optionally NTLM/Negotiate via SSPI; username/password for SOCKS5). The system proxy (WinHTTP/WinINet) is an
  opt-in source. **No ProxyCommand.**
- Connection pool per mount: 1–4 SSH connections (default 1, profile option). Extra connections are opened only
  when authentication is non-interactive (key, agent, stored password/passphrase), so the user never gets repeated
  2FA prompts; otherwise the pool stays at 1. Bulk transfers are striped across connections; metadata stays on
  the primary. Reconnection is per connection.

## Authentication
- Password and keyboard-interactive (including OTP/2FA prompts).
- Public keys: ed25519, ECDSA (nistp256/384/521), RSA (rsa-sha2-256/512 and legacy ssh-rsa). Read OpenSSH
  private key format (encrypted with bcrypt-pbkdf too), PEM/PKCS#8 and PuTTY `.ppk` (v2 and v3).
- SSH agents: Pageant (WM_COPYDATA, XP+) and the Windows OpenSSH agent named pipe (Windows 10+). Not used in the
  service context; the service uses its own DPAPI-protected keys.
- OpenSSH user certificates.

## Host key verification
- TOFU with fingerprint prompt, stored in our own `known_hosts` (OpenSSH-compatible format), block on mismatch.
- PuTTY (registry `SshHostKeys`) and `%USERPROFILE%\.ssh\known_hosts` are live read-only trust sources, on by
  default; a mismatch in any source blocks.
- UpdateHostKeys (`hostkeys-00@openssh.com` and `hostkeys-prove-00@openssh.com`): new keys are accepted only when
  proven and announced over a connection authenticated with an already-trusted key, and never written to the
  machine store without admin policy.

## Crypto policy
- Maximum compatibility: modern algorithms preferred (curve25519, ed25519, chacha20-poly1305, AES-GCM, AES-CTR,
  ETM MACs), and legacy algorithms (3DES-CBC, AES-CBC, DH group1/group14-sha1, ssh-rsa SHA-1, hmac-sha1) enabled
  by default but always ranked last. The UI warns when a session negotiates a legacy algorithm.
- Post-quantum hybrid key exchange `mlkem768x25519-sha256` in v1 (own ML-KEM-768 and SHA-3/SHAKE). No sntrup761.
- The full algorithm set exists in our own constant-time code (XP has no CNG). Hashes and HMAC always use our code;
  CNG serves as a differential-test reference.
- CNG is part of Windows, not third-party code: at runtime it may still be used for AES (CBC/ECB/GCM), ECDSA, RSA
  and ECDH where a runtime probe confirms the exact construction (see `docs/design/01-ssh-sftp-crypto.md`);
  our own code is the fallback everywhere else.

## Credentials
- Windows Credential Manager (CredWrite/CredRead, XP+) for passwords and passphrases; DPAPI for stored private keys.

## Interface
- CLI (`shelldrive.exe`), tray app, Explorer integration (context menu, entries in "This PC"), and a full main
  window (connection manager).
- "Add network location" (Network Shortcuts) in v1.
- Windows 11 modern context menu (sparse MSIX) in v1 only if the code-signing certificate is available in time;
  otherwise 1.0 ships the classic menu and the modern one follows in 1.x.

## Mount lifecycle
- Per-user mounts (drive letters are per logon session), with remount at logon for marked profiles.
- A system service that mounts global drives visible to all users, available before logon. Dokany global drives
  are the primary path. Global WebDAV drives (LocalSystem-hosted mount) are attempted, subject to an early lab
  go/no-go per OS; where it is a no-go, that OS falls back to per-user attach at logon.
- The service is enabled by default on per-machine installs (the MSI has a property to turn it off). Per-user
  installs never install a service.
- Multiple simultaneous mounts.

## Resilience
- Automatic reconnection with backoff and keepalive. Memory/disk cache for metadata and reads.
- Write mode is configurable per profile. By default every write is acknowledged by the server before it completes
  for the application (synchronous, write-through). Profiles may opt into write-behind (16 MiB window), in which
  case data accepted before a disconnect is retransmitted after a reconnect within a 60 s grace period if the
  remote file is unchanged; otherwise the loss is reported to the user (`write_failed` notification, always on).
- Operations started while disconnected fail immediately. There is no offline write queue.

## Mount options
- Read-only per profile.
- Map POSIX permissions and uid/gid to Windows attributes and ACLs (read-only, hidden for dot-files, +x hint).
- Symlinks: follow them (default) or hide them (both backends). Exposing them as reparse points is postponed until
  after 1.0 (no Dokany fork).
- Mount on an NTFS folder in addition to drive letters (Dokany backend only).

## Distribution and updates
- Self-installing EXE (per architecture, or universal with an x86 stub), which can embed the signed Dokany installer.
- An MSI for corporate deployment (GPO/Intune), including ARM32. XP needs Windows Installer 3.1+.
- Update check that asks before applying. Releases are verified with our own ed25519 signature (not relying on XP's
  old TLS stack). The update mirror is static plain-HTTP object storage; integrity comes from an ed25519-signed
  manifest.
- Code signing via SignPath Foundation, else Certum OSS, obtained before a public 1.0.

## Project
- Private GitHub repository for now, GitHub Actions CI building every flavour listed under "Build flavours".
- Localization rules: see `AGENTS.md` (en/es/fr/pt/it/de). Plural messages support the full CLDR plural
  categories (zero/one/two/few/many/other) for every locale.
