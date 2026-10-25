# 05 — Threat model

Status: design, first version (2026-10-24). Requested by `00-integration-review.md` §4 ("Threat model") and §8
("Not yet written"); it is to be reviewed again at the M5 threat-model review (00 §6) together with the external
crypto review (01 §2.7.6). It does not edit 01–04. Where it finds a gap it states a **new mitigation or required
test** and collects the design changes as `TM-Rxx` (section 8). Decisions the user should look at again are
`TM-Qxx` (section 9).

Inputs: `docs/requirements.md`, `decisions.md` (authoritative), `00-integration-review.md`, `01`–`04`.
References like "01 §7.1" point into those documents. Threat ids are `T-xx`, tests are `TST-xx`, assets `A-xx`,
trust boundaries `TB-xx`, attackers `AT-xx`.

Precedence follows `README.md`: `decisions.md`, then 00's resolutions, then the owning document. This document
owns nothing normative except the test list in section 7. Every `TM-R` has to be accepted into the owning
document before it binds.

---

## 1. Scope and method

**In scope:** the four binaries (D3) in all six flavours (D4, D5, D28), both mount backends, the per-user agent and
the LocalSystem service (D6), IPC, configuration and secret stores, Explorer integration, setup EXE, MSI, Dokany
redistribution, updater, the HTTP mirror (D30), and the CI/release pipeline that produces signed artifacts.

**Method:** assets → trust boundaries and data flows → attackers → STRIDE per component and per boundary
(S spoofing, T tampering, R repudiation, I information disclosure, D denial of service, E elevation of
privilege). Each threat lists the affected design sections, the existing mitigation as designed, the residual
risk (H/M/L), and what is missing.

**Explicitly out of scope** (stated once; no threat below relies on them):
- **Malware running as the same user** (same SID, medium integrity or higher) in the user's session. It can read
  the user's DPAPI data, Credential Manager entries, process memory, key files and config, and can impersonate the
  agent. This matches 03 §13.1 item 6. Exception: we still keep **lower-integrity** processes of the same user
  (protected-mode browser, AppContainer) and **other users** out (AT-04, AT-10).
- **Local administrators and SYSTEM**, kernel code, and anyone with physical access to a running unlocked machine.
  Admins can take ownership of `service\secrets\` (03 §3.2) and decrypt SYSTEM DPAPI data; that is accepted.
- **Bugs in Windows components** (WebClient/MiniRedir, SSPI, DPAPI, Explorer parsers), except where our design
  starts, enables or feeds them (T-32, T-43).
- **The remote server's control of its own data.** A malicious server can serve any content, lose writes and lie
  about metadata; we only defend the client machine and the other servers and users against it.
- Denial of service by a network attacker on the path (they can always drop packets).

---

## 2. Assets

| Id | Asset | Where it lives (design ref) | Security property |
|---|---|---|---|
| A-01 | SSH private keys (user files, DPAPI-kept `keys\*.sdkey`, service keys) | user paths; `%APPDATA%\ShellDrive\keys`; `%ProgramData%\ShellDrive\service\keys` (03 §3.2, §4.4, §4.5); decrypted in `sd_secbuf` (01 §7.4) | C, I |
| A-02 | Passwords, key passphrases, OTP/kbd-interactive answers | Credential Manager / DPAPI files (03 §4.2, §4.3), reconnect cache (01 §7.4), IPC prompt answers (03 §2.5) | C |
| A-03 | Proxy credentials (Basic, SOCKS5, Windows logon via SSPI) | Credential Manager `ShellDrive:proxy:*` (03 §3.8), SSPI (01 §5.2) | C |
| A-04 | Host-key trust stores and live sources | machine/user `known_hosts`, `~/.ssh/known_hosts`, PuTTY `SshHostKeys` (01 §7.2, 03 §5.1) | I |
| A-05 | Remote file data and metadata (names, sizes, paths) | in flight, memory and disk cache (02 §4.2), WebDAV redirector cache (02 §7.6) | C, I |
| A-06 | Local caches and state (`cache\`, `state\`, menu cache, snapshot section) | `%LOCALAPPDATA%`, `%ProgramData%\ShellDrive\service\cache` (03 §3.2) | C, I |
| A-07 | Profiles, settings, policies, machine templates | `%APPDATA%`/`%ProgramData%` INI, `HKLM/HKCU\Software\Policies\ShellDrive` (03 §3.2–§3.5) | I |
| A-08 | WebDAV per-mount path token, SSPI-authenticated connections | agent/service memory, UNC strings (02 §7.3, §7.4) | C |
| A-09 | Update signing keys (`release-primary`, `release-backup`, `beta`) and the anti-rollback state | maintainer offline machine, CI secret, `state\last_serial` (04 §9.2, §9.3) | C, I |
| A-10 | Release pipeline and artifacts (source, toolchain, CI, Authenticode, mirror) | GitHub, runners, HTTP mirror (04 §11, §12) | I |
| A-11 | The machine's privilege boundary (installer, service, MSI, Dokany kernel driver) | SYSTEM, kernel (03 §1.3, 04 §6–§8) | I, E |
| A-12 | Windows logon credentials of the user (NTLM/Kerberos) | used by SSPI towards proxies and our loopback server (01 §5.2, 02 §7.4) | C |
| A-13 | Availability of Explorer and of mounted drives | Explorer process, shell DLL (03 §1.6) | A |
| A-14 | Privacy metadata: host names, user names, remote paths, installed version | logs (03 §10.1), known_hosts plain (D8), update requests (04 §9.4) | C |

---

## 3. Trust boundaries and data flow

| Id | Boundary | Crossing |
|---|---|---|
| TB-01 | Network ↔ host process | TCP to hop 0 or proxy; everything before host-key verification is untrusted |
| TB-02 | Each SSH hop ↔ the next | direct-tcpip through a hop that may be hostile (01 §5.1) |
| TB-03 | Proxy ↔ host | HTTP CONNECT / SOCKS5 handshake in clear (01 §5.2) |
| TB-04 | Remote server content ↔ `sd_sftp`/`sd_vfs` | names, attributes, file bytes, symlinks (after authentication, still untrusted) |
| TB-05 | Loopback TCP ↔ `sd_webdav` | WebClient (LocalService), other local users, browsers |
| TB-06 | Kernel (Dokany driver, I/O manager) ↔ host | callbacks carrying the requestor token (02 §6.7) |
| TB-07 | Named pipes and named kernel objects ↔ agent/service | CLI, UI, other users, lower-integrity processes (03 §2) |
| TB-08 | User process ↔ LocalSystem service | service pipe, `mount.attach_info`, global drives (03 §1.3, §2.6) |
| TB-09 | Process ↔ secret stores | Credential Manager, DPAPI, file ACLs (03 §4) |
| TB-10 | Explorer and file dialogs ↔ shell DLL and mounted content | snapshot section, drive content parsed by shell handlers |
| TB-11 | Non-elevated ↔ elevated token (linked logon sessions) | `--elevated-view`, `EnableLinkedConnections` (03 §1.7.2) |
| TB-12 | Unprivileged user ↔ installer/MSI/service install | setup stub, elevated child, MSI custom actions (04 §6, §8) |
| TB-13 | Mirror/GitHub ↔ updater | manifest and artifacts over HTTPS or plain HTTP (04 §9) |
| TB-14 | Source/CI ↔ signed release | GitHub Actions, maintainer's offline signing (04 §12.3) |
| TB-15 | Disk at rest ↔ offline attacker | caches, stores, logs, dumps, hiberfil/pagefile |

```
   Remote SFTP server <====SSH(e2e)====+                     Mirror / GitHub (TB-13)
          ^  (TB-04 content)           |                          |  manifest.txt + files (ed25519)
          |                       [hop N-1] ... [hop 0]           v
          |                        ^  TB-02    ^                 sd_update (agent)
          |                        |  direct-  |  TB-01/03        |  staging -> setup (elevated, TB-12)
          |                        |  tcpip    |  TCP / proxy     |
+---------+------------------------+-----------+------------------+---------------------------------+
| shelldrive-host.exe agent (user, medium IL, per SID+session)     |                                 |
|   sd_ssh (transport, kex, auth, agents, known_hosts) <-- Pageant WM_COPYDATA / openssh-ssh-agent   |
|   sd_sftp (pool 1..4)                                             |   TB-09: CredMan / DPAPI files  |
|   sd_vfs (nodes, caches) --- disk cache %LOCALAPPDATA% (TB-15)    |                                 |
|   sd_webdav 127.0.0.1/::1:port ----TB-05----> WebClient (LocalService) + mrxdav.sys -> drive X:    |
|   sd_dokan  <----TB-06---- dokan2.sys (kernel) <---- any process opening X: (requestor token)      |
|   IPC pipe \\.\pipe\ShellDrive.agent.<SID>.<sess>  <--TB-07--  CLI, UI (tray, dialogs)             |
|   snapshot Local\ShellDrive.state.<SID> ----TB-10----> shelldrive-shellext.dll in Explorer         |
+-----------------------------------------------------------------+---------------------------------+
          ^ TB-08 (list, attach_info)                              Explorer shell handlers parse
+---------+-------------------------------------+                  remote files on X: (TB-10)
| ShellDriveSvc = shelldrive-host.exe service   |
| (LocalSystem): global Dokany / WebDAV mounts, |---- %ProgramData%\ShellDrive\service\{keys,secrets,cache}
| machine known_hosts, SYSTEM-DPAPI secrets     |     (SYSTEM-only ACLs)
| \\.\pipe\ShellDrive.service  <-- IU read-only, elevated admins mutate
+-----------------------------------------------+
```

---

## 4. Attackers

| Id | Attacker | Capabilities assumed | In scope |
|---|---|---|---|
| AT-01 | Network MITM | read/modify/inject on any network path; DNS spoofing; WPAD/LLMNR poisoning on the LAN | yes |
| AT-02 | Malicious or compromised SSH server (target) | full control of SSH and SFTP responses after authentication | yes (client side only) |
| AT-03 | Malicious ProxyJump hop or HTTP/SOCKS proxy | sees inner metadata, controls where direct-tcpip goes, answers proxy auth | yes |
| AT-04 | Other local unprivileged user (multi-user, RDP, fast user switching) | own session(s), can create global pipe names, bind loopback ports, write `%ProgramData%` subfolders it creates | yes |
| AT-05 | Same-user malware | everything the user can do | **no** (section 1), except lower-IL processes (AT-10) |
| AT-06 | Local administrator / SYSTEM | everything | **no** |
| AT-07 | Malicious update mirror or network on the update path | serve any bytes over plain HTTP, replay old files | yes |
| AT-08 | Supply chain / build compromise | third-party Actions, runner images, cache poisoning, stolen CI secret, toolchain download | yes |
| AT-09 | Malicious remote content | names, sizes, symlinks, huge directories, shell-active files, crafted documents | yes |
| AT-10 | Web page or other local process talking to the loopback WebDAV port; low-IL processes | browser JS (fetch/forms/img), port scans, DNS rebinding, low-IL object creation | yes |
| AT-11 | Elevation-boundary abuse | medium-IL code influencing elevated processes via linked drives | partly (UAC is not a security boundary for Microsoft; we avoid making it worse) |
| AT-12 | Physical/offline disk theft | reads the powered-off disk or a lost USB stick (portable mode) | yes, documentation-level |

---

## 5. Threats

Format: **T-xx [STRIDE] title.** *Docs:* sections. *Have:* existing mitigation. *Residual:* H/M/L and why.
*New:* missing mitigation (`TM-R`) or test (`TST`).

### 5.1 Transport and crypto (`sd_crypto`, `sd_ssh`; TB-01)

**T-01 [T,I] Terrapin prefix truncation with servers that lack strict KEX.** *Docs:* 01 §4.2, §4.3,
§4.5; 03 §3.4.1 (`refuse_terrapin_exposed = no`). *Have:* strict KEX always offered; `SD_LEGACY_TERRAPIN_EXPOSED`
warning; opt-in reconnect without the exposed ciphers. *Residual:* **M**. Our first cipher is
`chacha20-poly1305@openssh.com`, which Terrapin breaks on every connection without strict KEX; CBC-EtM is
exploitable probabilistically and CTR-EtM is vulnerable in theory but fails at the application layer
([USENIX'24 slides](https://usenix.org/system/files/usenixsecurity24_slides-baumer.pdf),
[IETF 122 slides](https://datatracker.ietf.org/meeting/122/materials/slides-122-sshm-terrapin-attack-and-strict-kex-00)).
For us the practical effect is that an attacker can drop `EXT_INFO`, so `server-sig-algs` is lost and 01 §4.5
falls back to `ssh-rsa` (SHA-1) user signatures on non-OpenSSH servers. The default is warn-only.
*New:* **TM-R01** (pick the cipher after seeing the server's KEXINIT) and TST-12.

**T-02 [I] Legacy algorithms enabled by default (requirements "Crypto policy", 01 §4.3, 03 §3.4.1
`legacy_algorithms = warn`).** *Have:* legacy always ranked last; KEXINITs are covered by the exchange hash H that
the host key signs, so an **active** MITM cannot downgrade negotiation without the host key; `legacy_mask`
warning; 1 GiB rekey also for 3DES (Sweet32 bound); GEX < 1024 refused; CBC non-ETM countermeasure (01 §4.1).
*Residual:* **M** for servers that only offer legacy: `diffie-hellman-group1-sha1` (1024-bit, a shared
precomputable group) and GEX 1024–2047 give passive decryption to a well-resourced adversary, and the user sees
only a warning, which trains users to ignore warnings. *New:* **TM-Q01**; TST-13 (no legacy algorithm is ever
chosen when the server offers any modern one in each category, including after a Terrapin-style KEXINIT drop).

**T-03 [I] Timing side channels in our own 32-bit arithmetic.** *Docs:* 01 §2.3, §2.4 rule 3, §2.8, §14. *Have:*
masks with value barriers, `__emulu`, disassembly checks, dudect on every flavour including `x86-ia32`. *Residual:*
**M**. 01 §2.4 rule 3 states that 64×64 multiplication through `_allmul` is constant time. BearSSL's survey says
the MSVC library routine for 64-bit multiplication on 32-bit x86 "returns early if the top words are all-zeros or
all-ones" ([BearSSL ctmul](https://www.bearssl.org/ctmul.html)). The same survey rates 32×32→64 `MUL` constant time
on the P6 family (Pentium Pro to Pentium III) and AMD K7 (Athlon), so the `x86-ia32` floor CPUs are fine **if**
only `__emulu` is used. *New:* **TM-R02** (forbid `uint64_t * uint64_t` and every `_all*`/`_aull*` helper except
`_aullshr`/`_allshl` with public counts in constant-time code on x86 and ARM32; extend the disassembly check to
calls), TST-03.

**T-04 [T,I] Correctness bugs in our own primitives and protocol code (D1).** *Docs:* 01 §2.5, §2.7, §14.
*Have:* six verification layers, two reviewers, external review before 1.0 (M6). *Residual:* **M**: the external
review lands in M6, but M2–M5 builds (betas, D29 "before public 1.0") already handle real keys. *New:* **TM-Q09**
(review in two passes) and TST-03/TST-04.

**T-05 [I] RNG quality on XP and after VM cloning.** *Docs:* 01 §2.2 (CSPRNG row). *Have:* `RtlGenRandom` on XP,
`BCryptGenRandom` on Vista+, failures fatal, ECDSA nonces RFC 6979 hedged. *Residual:* **L**. The analysis of the
Windows 2000 generator, which Microsoft acknowledged also applies to XP, shows the state lives in user mode per
process ([Dorrendorf et al., ePrint 2007/419](https://eprint.iacr.org/2007/419)). Microsoft is reported to have
fixed it in XP SP3, our floor **[verify]**. A restored VM snapshot repeats RNG state. Ed25519 and hedged ECDSA
keep signatures safe in that case; ephemeral KEX keys might repeat. *New:* none beyond documenting "restore of a
running VM snapshot" in the admin guide.

**T-06 [T,D,E] Memory-safety bugs in network parsers (packets, KEX, auth, channels, SFTP, agent, proxy replies).**
*Docs:* 01 §12.1, §12.2; 04 §11.2 `fuzz.yml`. *Have:* one bounded reader with sticky errors, semantic maximums,
checked arithmetic, libFuzzer+ASan targets for every parser, WinAFL against shipping x86 binaries, stateful mock
server fuzzing. *Residual:* **M**: v141_xp builds have no CFG (04 §1 "Hardening"), so XP/`x64-xp` users get only
`/GS`/DEP/ASLR. *New:* TST-01/TST-02. Also TST-30: the test-only `none` encryption flag of 01 §12.2 must be
absent from release binaries.

**T-07 [D] Pre-authentication resource abuse by a malicious server.** *Docs:* 01 §4.1 (64 KiB banner, 256 KiB
packets), §4.2 (GEX up to 8192 bits), §2.2 (RSA up to 16384 bits). *Have:* caps; KDF/RSA work on workers.
*Residual:* **L**: an 8192-bit GEX or a 16384-bit RSA host key costs seconds on a Pentium III; the server can do
that anyway by being slow. *New:* none.

### 5.2 Host-key trust (`sd_known_hosts`; TB-01, TB-02)

**T-08 [S] TOFU on first contact.** *Docs:* 01 §7.1, 03 §5.2–§5.3, §2.6 rule 2 (service has no TOFU), policy
`StrictHostKeyChecking`. *Have:* SHA-256 fingerprints, hop shown, "Connect once", strict policy, no TOFU in the
service. *Residual:* **M**: "Trust and connect" is the default button, so Enter accepts (03 §5.2); first
contact through a hostile network or hop is a full MITM. *New:* **TM-R03** (no default button in the TOFU dialog,
CLI default is "no"; dialog states "reached through jump host X" for inner hops).

**T-09 [S] An unknown key type for a known host becomes a prompt instead of a block.** *Docs:* 01 §4.3 (known
types moved first), §7.1 `SD_HK_NEW_TYPE`, 03 §5.2. *Have:* reordering makes a legitimate NEW_TYPE rare; pool
members drop on NEW_TYPE (01 §10.9). *Residual:* **H**: a MITM without the host key simply offers only a key
type that is not stored (our KEXINIT lists every type), and the user sees a TOFU-style dialog, also during
automatic reconnect (01 §8). OpenSSH avoids this when it knows keys for the host by restricting its host key
algorithms to those types. *New:* **TM-R04**, TST-11.

**T-10 [I] Stored secrets auto-answered after a re-trusted (possibly MITM) key.** *Docs:* 03 §4.2, §5.4 (remove
old key, then TOFU again), 01 §6.4 `may_autofill`, §7.4 reconnect cache. *Have:* mismatch blocks hard; removal
warns about MITM. *Residual:* **M**: right after "remove old key and reconnect", the new key is TOFU-accepted and
the saved password for `user@host:port` is sent at once from Credential Manager. That is exactly the flow a MITM
provokes. *New:* **TM-R05**, TST-11.

**T-11 [T] Trust injection through live read-only sources (D7).** *Docs:* 01 §7.2, 03 §5.1, §13.1 item 11.
*Have:* a mismatch in any source blocks; policy `DisableKnownHostsSources`; matches are copied with a source
comment; UpdateHostKeys never extends wildcard entries (01 §7.5 precondition 3). *Residual:* **M**: on a
redirected profile, a Cygwin/MSYS-created `.ssh` folder or a portable FAT stick, `~/.ssh/known_hosts` may be
writable by other users. A wildcard line (`* ssh-ed25519 …`) in a source matches every host. *New:* **TM-R06**
(ACL check of source files, and wildcard-only lines from live sources are not honored for MATCH), TST-14.

**T-12 [T] UpdateHostKeys abuse.** *Docs:* 01 §7.5, 03 §5.6, policy `UpdateHostKeys`. *Have:* only proven keys,
only on connections verified against a key trusted before this connection, never after TOFU/once/CA, one
announcement per connection, ≤ 16 keys, primary only, removals only after review, machine store only with
policy 2, `ask` default, fuzzed. *Residual:* **L**: with `update_host_keys = yes`, a compromised server leaves keys
behind after it is rebuilt; this is inherent to the feature. *New:* TST-15 (negative tests: unproven key, proof
over another session id, `ssh-rsa` proof with legacy refused, announcement after TOFU, wildcard entry, secondary
pool member).

**T-13 [T,I] Tampering with or reading our own stores.** *Docs:* 01 §7.2 (temp file + `MoveFileExW`, named
mutex), 03 §3.2 (machine ACLs; explicit DACL only on `keys\` and `secrets\`), D8 plain entries. *Residual:* **L**:
the user `known_hosts` and `profiles\` inherit `%APPDATA%` ACLs, which may be loose on a redirected share. Plain
entries disclose host names to whoever reads the file (A-14). *New:* **TM-R07**.

**T-14 [S] Pool members reaching a different server.** *Docs:* 01 §10.9, 02 §5.6. *Have:* members accept only
`MATCH`/`MATCH_CA` per hop without prompts, must equal the primary's host key fingerprint and `realpath(".")`,
and a mismatch disables the pool. *Residual:* **L**. *New:* TST-16.

### 5.3 Authentication, agents (TB-01, TB-07)

**T-15 [I] Agent keys offered to every hop and target.** *Docs:* 01 §6.2 (agent keys after the configured ones
unless `identities_only`), 03 §3.4.1 (`identities_only = no`). *Have:* query-before-sign, 6-attempt limit, no
agent forwarding, inbound channel opens refused (01 §4.8), signatures bound to the session id. *Residual:* **L**:
every hop and server learns all public keys in Pageant/ssh-agent (tracking across servers; a malicious server can
confirm whether a user holds a given key). The agent itself cannot be misused by the server. *New:* **TM-Q07**.

**T-16 [S,I] Pageant spoofing.** *Docs:* 01 §6.5 (`FindWindowW("Pageant")`, mapping owner = our SID). *Have:*
the mapping owner check protects Pageant from us, not us from a fake Pageant. *Residual:* **L**: any window in the
same desktop, including a lower-integrity process or another user started with `runas`, can register the class.
It then receives our sign requests (user name, public key, session id) and can stall or refuse them. Signatures
cannot be replayed (session id). *New:* **TM-R08** (verify that the window's process token has our user SID and
an integrity level ≥ ours before sending).

**T-17 [S,I,D] `openssh-ssh-agent` pipe squatting.** *Docs:* 01 §6.5 (`SECURITY_IDENTIFICATION` set). *Residual:*
**M** on multi-user machines: the ssh-agent service is often stopped, so any local user (AT-04) can create
`\\.\pipe\openssh-ssh-agent` and receive our identity queries and sign requests, offer its own keys, or hang
us for 120 s per request. *New:* **TM-R08** (check that the pipe server owner is SYSTEM, or our own SID when
`SSH_AUTH_SOCK` names a user pipe, with `GetSecurityInfo` and `GetNamedPipeServerProcessId`, as 03 §2.2 does for
our own pipes), TST-17.

**T-18 [S] Prompt spoofing by a server or hop.** *Docs:* 01 §6.1 (banner sanitized), §6.4, 03 §2.5 (server text
marked, 2 KiB caps). *Residual:* **L**: kbd-interactive text such as "Enter your Windows password", or Unicode
bidi controls (U+202A–U+202E, U+2066–U+2069) that reorder the host name, can mislead. *New:* **TM-R09** (strip
bidi and zero-width controls from server text and from host names shown in prompts; always show the hop host
outside the server-text box).

### 5.4 ProxyJump hops and network proxies (TB-02, TB-03)

**T-19 [I,D,S] Hostile ProxyJump hop.** *Docs:* 01 §5.1, 03 §3.4.1. *Have:* each hop authenticates the next
end-to-end by host key, hop i ≥ 1 names are resolved by hop i−1 and still verified, no agent forwarding.
*Residual:* **L/M**: the hop sees inner targets, timing and volume, can redirect direct-tcpip to an impostor
(stopped by host-key verification except at first contact, T-08), and can deny service. *New:* covered by TM-R03.

**T-20 [I] Windows credentials harvested by a proxy through SSPI.** *Docs:* 01 §5.2 (`proxy_auth = auto` answers
`407 Negotiate/NTLM` with the logon credentials), 03 §3.8. *Residual:* **M**: the proxy connection is plain TCP, so
an on-path attacker (AT-01) or a WPAD-discovered proxy (`proxy = system`) can answer `407 NTLM` and collect a
NetNTLMv2 response for offline cracking or relay. *New:* **TM-R10**, TST-18.

**T-21 [I] Clear-text proxy passwords (Basic, SOCKS5).** *Docs:* 01 §5.2, 03 §3.8 (`warning proxy_cleartext`).
*Have:* warning, `proxy_auth = negotiate|none`, no password in specs. *Residual:* **L** (accepted by D20).

**T-22 [S,D] System-proxy and WPAD poisoning.** *Docs:* 01 §5.2, 03 §3.8. *Have:* `proxy = system` is opt-in,
`proxy_fallback_direct = no`, SSH stays authenticated. *Residual:* **L**: metadata and DoS only, plus T-20.

### 5.5 Remote content against `sd_sftp`, `sd_vfs` and Explorer (TB-04, TB-10)

**T-23 [T,E] Stage-2 inverse mapping produces `/` or NUL (path traversal on the remote).** *Docs:* 02 §1.2 ("A
Windows name that contains a character in U+F000..U+F07F is decoded back to the original ASCII character"),
01 §10.7. *Residual:* **H**: the forward map only produces U+F000+c for `\ : * ? " < > |`, U+0001–U+001F and the
trailing dot/space. If the inverse decodes the whole range, a Windows name containing U+F02F becomes `/`, so
`a\uF02F..\uF02Fb` turns into `a/../b` after the lexical `..` check of 02 §1.1, and U+F000 becomes a NUL that
truncates the remote path. A web download, an archive extractor or any app can create such a name, which
escapes the mount root on the server. *New:* **TM-R11**, TST-05.

**T-24 [T] Malformed directory entries.** *Docs:* 01 §10.3 ("never contains '/' or NUL"), 02 §6.5 (`.`/`..`
added by us). *Residual:* **M**: the design states the invariant but not what happens when the server breaks it
(`a/b`, embedded NUL, `.`, `..`, empty names, the same name twice, names that map to the same Windows name).
*New:* **TM-R12**, TST-05.

**T-25 [T] WebDAV URL decoding tricks.** *Docs:* 02 §7.5 ("percent-decoded as UTF-8, mapped via 1.2"). *Residual:*
**M**: `%2F` or `%5C` inside a segment, `%00`, `%2e%2e`, overlong UTF-8, and `Destination` headers of MOVE/COPY
need the same rules as Dokany paths. *New:* **TM-R12**, TST-06.

**T-26 [E,I] Symlinks lead outside the mount root.** *Docs:* 02 §6.9 (`follow` default, resolved by the
server), 03 §3.4.1 `remote_path`. *Have:* lexical `..` cannot climb (02 §1.1); delete/rename act on the link.
*Residual:* **M** for `scope = service` and `scope = users` profiles where an admin set `remote_path` to a
subtree and expects users to be confined to it: any symlink created on the server (by another account) exposes
whatever the service's remote account can read. For per-user mounts it is **L** (the user can reach those paths
with SFTP anyway). *New:* **TM-R13** (`symlinks = follow_inside`), TST-07.

**T-27 [T,D] Reserved device names and confusing names.** *Docs:* 02 §1.2 item 3 (`CON`, `NUL`, `COM1` left as is),
§1.3 (`~cN` mangling), D7 no normalization. *Residual:* **L**: `Z:\dir\COM1` opened through Win32 reaches the
local device, not the remote file (a hang or wrong data for scripts). NFC/NFD twins and `README`/`readme~c2` pairs
look alike. *New:* TST-05 covers reserved names. Document both.

**T-28 [I,E] Shell-active files and parser exposure in Explorer.** *Docs:* 02 §3.1 (directories never get
READONLY, so `desktop.ini` customization is not honored), §4.1 probe suppression, §6.4 network drive type, §7.6
thumbnails. *Residual:* **H** for untrusted servers. Explorer, the thumbnail cache, preview and property handlers
parse remote files as soon as a folder is shown. `.library-ms`, `.searchConnector-ms`, `.url` and `.lnk` files can
point icons at `\\attacker\share`, making Explorer authenticate over SMB and leak the user's NTLM hash just by
navigating to the folder (CVE-2025-24054, exploited in the wild:
[Check Point](https://research.checkpoint.com/2025/cve-2025-24054-ntlm-exploit-in-the-wild/)). Before ShellDrive a
remote SFTP server could not put files into Explorer's view; now it can. *New:* **TM-R14**, TST-20.

**T-29 [E] Mark-of-the-Web is lost on files from the remote.** *Docs:* 02 §1.1 (streams rejected, no
`DOKAN_OPTION_ALT_STREAM`), §6.4. *Residual:* **M**: executables and Office documents opened directly from the
drive carry no `Zone.Identifier`, so SmartScreen and Office Protected View may not apply. The zone of
`\\localhost@port\DavWWWRoot` is Local intranet (dotless name, 02 FS-10); a Dokany drive is a local or
`\\shelldrive\` UNC path. *New:* **TM-R15** (lab-measure the zone per backend; optional synthetic read-only
`Zone.Identifier` for profiles marked untrusted), TST-21.

**T-30 [D] Resource exhaustion by a malicious server.** *Docs:* 02 §1.4 (`max_nodes`), §6.6 (`DokanResetTimeout`
"listing a huge directory"), §6.9 (pipelined `stat` per symlink), §6.5 statvfs multiplication, 01 §10.1 (64
extended pairs). *Residual:* **M**: a READDIR that never reaches EOF, millions of entries, or 10^5 symlinks per
listing keep a Dokany thread busy indefinitely (each batch counts as progress) and grow memory without a per-listing
cap. `f_blocks × f_frsize` can overflow. *New:* **TM-R16**, TST-08.

### 5.6 Loopback WebDAV server and the redirector (TB-05, TB-11)

**T-31 [S,I] Another local user or process connects to the port.** *Docs:* 02 FS-9, §7.3, §7.4. *Have:* bind to
loopback only, 130-bit token, unknown prefixes return 404 **before** authentication, SSPI Negotiate with an owner
SID check, 403 otherwise, `PROPFIND /` lists nothing. *Residual:* **L**. *New:* TST-09 (second user, `Guest`,
anonymous NTLM, wrong SID, NETWORK SERVICE).

**T-32 [S,I] Port squatting after the agent dies, and port hijacking on XP.** *Docs:* 02 §7.3 (ephemeral port,
mapping not persistent), 03 §1.2 (shutdown sequence unmaps), §10.4 (crash). *Residual:* **H** on multi-user
machines. After a crash or kill of the agent, the drive letter stays mapped in the user's logon session and the
port is free. Another local user binds it, and the victim's applications then send writes, Office lock
sequences and NTLM authentication to the attacker's server (data theft, content forgery, relay attempts). On XP,
without `SO_EXCLUSIVEADDRUSE`, a second socket can bind a port that is in use with `SO_REUSEADDR`: XP and 2000
lack "enhanced socket security", which arrived with Server 2003
([Microsoft Learn](https://learn.microsoft.com/en-us/previous-versions/ms740618(v=vs.85)); a PuTTY advisory
describes the same issue for listeners: [vuln-win-exclusiveaddruse](https://putty.cs.utah.edu/wishlist/vuln-win-exclusiveaddruse.html)).
*New:* **TM-R17**, TST-10.

**T-33 [S,T] Browser-origin requests, CSRF and DNS rebinding.** *Docs:* 02 §7.3 (Host header allow-list, no CORS,
token), §7.5 (POST → 405). *Residual:* **L**: a page cannot learn the token. Simple cross-origin requests
(GET, POST `text/plain`) reach the server and get 404/405. Browsers that send integrated auth to Local intranet
hosts send it to `localhost` too, but the 404-before-auth rule means no SSPI exchange happens on unknown
prefixes. A page can still detect that ShellDrive is listening (privacy). *New:* TST-09 (Chrome, Edge, Firefox:
`fetch` with `no-cors`, form POST, `<img>`, rebinding host name to 127.0.0.1, `Host: evil:port`).

**T-34 [I] Cross-session reuse of authenticated connections by WebClient.** *Docs:* 02 §7.7 G2 (service servers
only). *Residual:* **M**: WebClient is one LocalService process for every user. If it ever reuses a TCP connection
authenticated as user A for user B, then for **per-user** servers the token is the only remaining barrier, so
token secrecy matters there too (03 §10.1 already never logs it). *New:* **TM-R18** (run G2 against per-user
servers too), TST-09.

**T-35 [S,I] Token-only fallback.** *Docs:* 02 §7.4 (self-test failure, or an automatic switch "on the next start"
after a redirector credential prompt). *Residual:* **M** on Terminal Services hosts: the token then is the only
secret, and it appears in the user's `net use` output, MRU lists, `.lnk` targets and Office recent files.
*New:* **TM-R19**.

**T-36 [D] Connection exhaustion and slowloris by local users.** *Docs:* 02 §7.3 (64 connections, 120 s idle),
00 §4.1 rule 5. *Residual:* **M**: unauthenticated connections from AT-04 can hold all 64 slots and the redirector
then times out the user's drive. *New:* **TM-R20**, TST-09.

**T-37 [T,E] HTTP and XML parsing.** *Docs:* 00 §4 (XML: no DTD, depth ≤ 32, body ≤ 1 MiB), 04 §11.2 fuzz targets.
*Residual:* **L/M**: the request line, headers, `If:`, `Range`, `Destination`, `Timeout`, chunked bodies and XML are
reachable by every local user before authentication if bodies are read before the auth check. *New:* **TM-R20**
(parse no body and no `If:`/`Destination` before the token and SSPI checks pass), TST-02.

**T-38 [E] WebClient as attack surface for the machine.** *Docs:* 02 §7.2 (we start WebClient, also through
the ETW trigger), 03 §10.5 `--fix webclient`. *Residual:* **M** on domain-joined machines: a running WebClient lets
attackers turn NTLM coercion into HTTP and relay it to LDAP even where SMB relay is blocked
([SpecterOps](https://specterops.io/blog/2026/01/14/wait-why-is-my-webclient-started-sccm-hierarchy-takeover-via-ntlm-relay-to-ldap/)).
Any user can trigger it already, but we make it routinely running. *New:* **TM-R21**.

**T-39 [I] Redirector local file cache.** *Docs:* 02 §7.6, §13 Q4 (location and ACL unknown). *Residual:* **M until
measured**: whole-file copies of every user's WebDAV files may sit in one LocalService cache. *New:* TST-22 (find
location and ACL per OS; if other users can read it, state it in the UI and the admin guide, and prefer Dokany on
multi-user machines).

**T-40 [E] Elevated view and linked connections.** *Docs:* 03 §1.7.2, D24. *Residual:* **L**: elevated processes
read files served by the medium-IL agent (a medium-to-high channel, which Microsoft does not treat as a boundary),
and the elevated mapping goes stale but stays mapped (T-32 applies to it as well). *New:* TM-R17 covers stale
elevated mappings; document.

### 5.7 Dokany backend (TB-06, TB-11)

**T-41 [I,E] Other users and SYSTEM services reaching a per-user mount.** *Docs:* 02 §6.4, §6.7, §3.3 (DACL with
an `Everyone` ACE from the `o` bits, `allow_system` on). *Have:* requestor-token check on every create, cached 60 s;
Dokany 2.2.0 isolates network drives between users. *Residual:* **L/M**: SYSTEM services that act for other users
(search indexer, backup, AV, print spooler) pass the check with `allow_system`, and the advisory DACL tells them
"Everyone may read", so security trimming (for example in search results) exposes the content to other users.
*New:* **TM-R22**, TST-19.

**T-42 [E] The Dokany driver as kernel attack surface.** *Docs:* 02 §6.1–§6.3, 04 §7.3 (pinned 2.3.1, SHA-256,
existing ≥ 2.1.0 used as is). *Have:* unmodified signed upstream, loaded by full System32 path, version gate.
*Residual:* **M**: installing Dokany exposes a kernel driver to every local user whether or not they use ShellDrive.
Dokan 1.x had a locally exploitable kernel stack overflow (CVE-2018-5410, CVSS 7.8,
[CERT VU#741315](https://kb.cert.org/vuls/id/741315)). An older 2.x already on the machine is kept forever.
*New:* **TM-R23**, **TM-Q06**.

**T-43 [I,E] Global Dokany drives give every local user the service's remote identity.** *Docs:* 02 §6.4
(`VolumeSecurityDescriptor`: `service_access` read/execute), §6.7, 03 §3.4.1 (`service_access` default
`BUILTIN\Users`). *Residual:* **M**: by default every local and RDP user reads and writes the remote as the service
account, with no per-user attribution on the server (R: repudiation). The volume SD says read/execute while the
vfs check allows writes, so the intended right is unclear. *New:* **TM-R24**, **TM-Q05**.

### 5.8 IPC and named kernel objects (TB-07, TB-08)

**T-44 [S,D] Pipe name squatting.** *Docs:* 03 §2.2 (`FILE_FLAG_FIRST_PIPE_INSTANCE`, client owner check, SQOS
identification, PID/session check logged on Vista+). *Have:* a spoofed server never gets secrets and can impersonate
only at identification level. *Residual:* **L**: another user can pre-create
`\\.\pipe\ShellDrive.agent.<SID>.<session>` and the agent exits (DoS), or squat `ShellDrive.service` while the
service restarts (03 §1.3 recovery). *New:* TST-23 (squat by a second user on XP and 10; clients refuse; the
service logs Event 3100-class errors).

**T-45 [E] Server-side identity checks fail open.** *Docs:* 03 §2.2 (impersonate, open thread token, compare
SID/elevation). *Residual:* **L** if implemented as written. A client connecting with `SECURITY_ANONYMOUS` gives
an anonymous impersonation token. *New:* TST-23 (anonymous and identification-level clients are refused for
every mutating method; `OpenThreadToken` failure means deny).

**T-46 [E,D,I] The service pipe is pre-authentication SYSTEM attack surface.** *Docs:* 03 §2.2 (`IU` may connect),
§2.4 (read-only methods, `subscribe`), §2.6 rule 3 (`prompt.request` published to service-pipe subscribers), 32
instances. *Residual:* **M**: every interactive user feeds JSON (≤ 1 MiB) to a LocalSystem parser. Any of them can
hold all 32 instances (admins cannot connect) and, as a subscriber, read prompt contents, host names and user names
of global mounts. *New:* **TM-R25**, TST-02 (`sd_json` and method dispatch fuzzing), TST-23.

**T-47 [T,E] Squatting the snapshot section that Explorer reads.** *Docs:* 03 §1.6, §2.1
(`Local\ShellDrive.state.<SID>`), §8.2. *Residual:* **M**: objects in the session's `Local\` namespace can be created
first by another user in the same session (`runas`) or by a lower-integrity process, and the shell DLL then parses
attacker-controlled offsets **inside Explorer and inside elevated processes' file dialogs**. The ready event
and the agent mutex can be squatted the same way (DoS). *New:* **TM-R26**, TST-24.

**T-48 [S,T] `WM_COPYDATA` command forwarding into the UI.** *Docs:* 03 §1.4. *Residual:* **L**: any window in the
same desktop (UIPI blocks lower IL) can send `--action` verbs (mount, unmount, show). *New:* **TM-R26** (check the
sender's process user SID, accept only the documented verbs).

**T-49 [I] `mount.attach_info` disclosure.** *Docs:* 02 §7.4, §7.7, 03 §2.4. *Have:* agent answers only its own
SID; the service only to SIDs in `service_access`; it returns the UNC with the token, never a credential.
*Residual:* **L**. *New:* TST-23 (schema test: the reply contains only `unc`, `letter`, `label`; non-members get
`access_denied`).

### 5.9 The LocalSystem service and global drives (TB-08)

**T-50 [E] The service is on by default (D6).** *Docs:* 03 §1.3 (idle without service profiles: one pipe, no
network, no listener, no Dokany code). *Residual:* **L/M**: the idle surface is the service pipe (T-46). *New:*
none beyond TM-R25. **TM-Q04** records that the decision can stay.

**T-51 [E,I] The service reads inputs that users influence.** *Docs:* 03 §2.6 rule 1 (unencrypted key file
"readable only by SYSTEM/Administrators", checked at save and start), §3.3 (`%VAR%` and `~\` expansion), 04 §8.4
`DEFAULTPROFILES`. *Residual:* **M**: an ACL check on the path at start followed by a later open is a TOCTOU, and a
junction in a parent folder redirects it. *New:* **TM-R27**, TST-25.

**T-52 [I,S] Global WebDAV drives (D11).** *Docs:* 02 §7.7 (mechanisms A/B, criteria G1–G6), 03 §1.3. *Have:* SSPI
group check with no impersonation, token-only refused, per-request auth fallback, per-user attach fallback.
*Residual:* **M until the M5 spike**: with mechanism A, accesses may authenticate as SYSTEM or the machine, which
voids per-user access control (G2 catches it). The drive letter and label are visible to non-members (metadata).
*New:* **TM-R18** adds G7 (negative tests), TST-26.

### 5.10 Secrets at rest and in memory, caches, logs, dumps (TB-09, TB-15)

**T-53 [I] DPAPI and Credential Manager scope.** *Docs:* 03 §4.2–§4.5. *Have:* `CRED_TYPE_GENERIC`, local persistence
by default, DPAPI fallback where Home SKUs lack persistence (03 §4.2), protected DACL on `keys\`/`secrets\`, entropy
per target, SYSTEM-scope DPAPI for the service. *Residual:* **L** (same-user and admin are out of scope). Offline:
user DPAPI is only as strong as the Windows password, so accounts without a password (common on XP Home) give
effectively plain secrets on a stolen disk. `CRED_PERSIST_ENTERPRISE` spreads SSH passwords to every machine the
profile roams to (opt-in). *New:* document (TM-R31).

**T-54 [I] Secrets left behind at uninstall.** *Docs:* 04 §6.7 (user secrets and Credential Manager entries removed
only when "Also remove my settings" is checked; service secrets only with `REMOVEDATA=1`). *Residual:* **M**: by
default a per-machine uninstall leaves SYSTEM-DPAPI-protected SSH private keys and passwords for every global mount
on disk, and other users' Credential Manager entries remain. *New:* **TM-R28**, TST-27.

**T-55 [I] Plaintext disk cache.** *Docs:* 02 §4.2 (off by default, UI states it, `NOT_CONTENT_INDEXED`), 03 §3.2.
*Residual:* **M** in portable mode on FAT/exFAT (no ACLs) and on stolen disks without BitLocker. *New:*
**TM-R29**.

**T-56 [I] Secrets in process memory, pagefile and hibernation file.** *Docs:* 01 §2.4 rule 8, §7.4, 03 §4.6.
*Have:* `sd_secbuf` zeroized, `VirtualLock` best effort, reconnect cache encrypted with `CryptProtectMemory` /
`RtlEncryptMemory`. *Residual:* **L/M**: session keys and decrypted private keys stay in plain memory for the
session lifetime by necessity; `VirtualLock` does not keep pages out of `hiberfil.sys`. *New:* document
full-disk encryption (TM-R31).

**T-57 [I] Secrets in crash dumps.** *Docs:* 03 §10.4 (`MiniDumpNormal | MiniDumpWithThreadInfo`, no full memory,
never uploaded, bundle excludes dumps unless asked). *Residual:* **M**: a normal minidump still contains every
thread's stack, where passwords being forwarded from IPC, key schedules and KDF state can sit. If our filter
returns `EXCEPTION_CONTINUE_SEARCH`, WER also runs and, depending on consent settings, may send data
([WER settings](https://learn.microsoft.com/en-us/windows/win32/wer/wer-settings)); admins may also enable
LocalDumps full dumps. *New:* **TM-R30**, TST-28.

**T-58 [I] Privacy of logs and diagnostics.** *Docs:* 03 §10.1 (host, user names and remote paths logged at info;
anonymization optional in the bundle), §3.2 (`logs\` ACL), D8. *Residual:* **L/M**: file names can be sensitive.
Logs are readable by the user and admins only. *New:* **TM-R31** (remote paths at debug level only, except in
error records; `diag --bundle` anonymizes by default).

**T-59 [T] Portable mode on removable media.** *Docs:* 03 §1.9, 04 §6.8. *Residual:* **M**: on a FAT stick,
`data\known_hosts`, profiles and the cache are writable by every user of every machine the stick is plugged into
(trust-store tampering, T-11 class), and lost sticks leak host names and cached data. *New:* **TM-R29**.

### 5.11 Explorer integration (TB-10)

**T-60 [D,E] Shell DLL crashes, hangs or is abused inside Explorer and elevated dialogs.** *Docs:* 03 §1.6, §8.2,
§8.5 (no network, no IPC, no threads, `__try` at entry points, versioned directories). *Residual:* **L/M**: the
snapshot parser is the one place where data from another process meets Explorer's address space (T-47). For
per-user installs, the DLL lives in a user-writable folder and loads into elevated processes' file dialogs
(UAC is not a boundary; noted, not fixed). *New:* TST-24.

**T-61 [S] `.sdmount` files and Network-location placeholders.** *Docs:* 03 §8.1, §8.7. *Residual:* **L**: a
downloaded `.sdmount` (from mail or the web) triggers a mount. It names only a profile id today. *New:*
**TM-R32** (accept exactly `profile = <32 hex>` naming an existing profile; ignore everything else; never ad-hoc
hosts; no auto-open of the drive from a file that carries Mark-of-the-Web).

### 5.12 Installer and Dokany installation (TB-12)

**T-62 [E] DLL planting against the setup stub, the elevated child and `uninstall.exe`.** *Docs:* 04 §6.1, §6.4
(the elevated child is the **same EXE**, relaunched with `runas` from wherever the user ran it, usually
`Downloads`), §6.7 (`uninstall.exe` copies itself to `%TEMP%`), §9.6. *Have:* `sd_platform_resolve` and Dokany load
by full path (01 §1, 02 §6.2); hash checks. *Residual:* **H**: the loader resolves static imports, and DLLs that
system DLLs load on our behalf (for example `cryptbase.dll`, `version.dll`, `uxtheme.dll`, `dwmapi.dll`), from the
application directory first unless they are KnownDLLs. A DLL dropped into `Downloads` by an earlier drive-by
download then runs in the **elevated** child before any of our code. *New:* **TM-R33**, TST-29.

**T-63 [E] `%ProgramData%\ShellDrive` pre-created by a standard user.** *Docs:* 04 §6.4 (extraction into
`%ProgramData%\ShellDrive\setup\<random>` "a directory it creates with an Administrators/SYSTEM-only DACL"),
03 §3.2 (the service re-applies ACLs at start, after setup). *Residual:* **H**: standard users can create
subfolders of `%ProgramData%`. An attacker who creates `ShellDrive` before the first per-machine install owns
it, keeps `WRITE_DAC` and can swap the child `setup\<random>` folder, plant junctions, or pre-seed `profiles\`,
`known_hosts` and `settings.ini` (`manifest_url`!). *New:* **TM-R34**, TST-29.

**T-64 [E] MSI repair as a standard user runs our SYSTEM custom actions.** *Docs:* 04 §8.3 (`signal-shutdown`
deferred `NoImpersonate`; `webdav-tune` writes HKLM, so also as SYSTEM; `modern-menu`). *Residual:* **M**: a
standard user can run `msiexec /fa` on the cached package and deferred custom actions then run as SYSTEM; abuse of
this has produced many vendor CVEs ([Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/privileges-third-party-windows-installers/),
[Doyensec](https://blog.doyensec.com/2024/07/18/custom-actions.html)). Our hooks are GUI-subsystem (no console
window, which closes the conhost vector), but the hook host must not read anything a user can write while
running as SYSTEM. *New:* **TM-R35**, TST-29.

**T-65 [T,E] Dokany installer integrity and the privileged driver install.** *Docs:* 04 §7.3 (SHA-256 pinned in
`dokany.lock`, download on demand from GitHub then our HTTP mirror, upstream MSI or bundle unmodified). *Residual:*
**L/M**: the pin is compiled into a stub that stays unsigned until the certificate arrives (T-71). The CI caches
Dokany MSIs (04 §11.2), so a poisoned cache entry is only caught if the hash is checked **when used**. *New:*
**TM-R23** (verify SHA-256 at embed and at install, plus `WinVerifyTrust` with the expected upstream signer name),
TST-29.

### 5.13 Updater, signing and release pipeline (TB-13, TB-14)

**T-66 [T] Rollback and freeze by a mirror.** *Docs:* 04 §9.2 (`serial` > `last_serial`, `expires`). *Have:*
anti-rollback, freeze limited by `expires`. *Residual:* **L/M**: the example manifest expires after 90 days, so a
hostile mirror or network can hide a security fix for about three months. *New:* **TM-R36** (`expires` ≤ 30 days
for stable, ≤ 14 days for beta; the release workflow re-signs the current manifest regularly; the UI shows "update
information is N days old" after 14 days).

**T-67 [S,E] Key compromise and channel confusion.** *Docs:* 04 §9.3 (primary and backup of equal power;
"compromise of one key: release with the other key that removes it"; beta key held by CI). *Residual:* **M**:
whoever holds a compromised key can also ship a key set that removes the other key first. A CI compromise can sign
beta manifests, and if `last_serial` is shared across channels, a beta manifest with a huge serial blocks stable
updates forever. *New:* **TM-R37**, TST-31.

**T-68 [I] Privacy of plain-HTTP update checks (D30).** *Docs:* 04 §9.4. *Residual:* **L** (accepted): an on-path
observer learns that the machine runs ShellDrive, its version and flavour, and can target known-vulnerable
versions. *New:* none. Document it.

**T-69 [T] Redirect and download handling.** *Docs:* 04 §9.4 step 3 (redirects only to manifest bases or GitHub
asset hosts; size and hash checked before use). *Residual:* **L**. *New:* TST-31.

**T-70 [E] Staging and elevation in the update path.** *Docs:* 04 §9.6 (per-machine: copied into an admin-only
directory and re-verified before execution). *Residual:* **L** if TM-R33/TM-R34 are applied; otherwise T-62
applies to the elevated setup started from the user's staging folder. *New:* TST-29 includes the update path.

**T-71 [S] Unsigned binaries until the certificate exists (D29).** *Docs:* 04 §10 (SmartScreen, Smart App Control
blocks unsigned code with no override). *Residual:* **M** during betas: users learn to click through "Windows
protected your PC", and a trojaned look-alike installer is indistinguishable from ours. *New:* **TM-R38**,
**TM-Q09**.

**T-72 [T,E] Build and supply-chain compromise.** *Docs:* 04 §11 (GitHub-hosted `windows-2022`, toolset installed
per job from Microsoft, caches for corpora/WSL rootfs/Dokany MSIs), §12.2 (two builds on two GitHub runners,
compared), §12.3 (maintainer verifies `SHA256SUMS` against the draft, then signs offline). *Residual:* **M**: both
"independent" builds run the same workflow on the same provider, so a compromised Action, runner image or workflow
file produces identical malicious outputs, and the maintainer's check confirms consistency, not provenance.
*New:* **TM-R39**, TST-32.

### 5.14 Physical and offline (TB-15)

**T-73 [I] Disk theft.** *Docs:* 02 §4.2, 03 §3.2, §4, §10. *Residual:* **M** without full-disk encryption:
plaintext disk cache, plain `known_hosts` and profiles (host names, users), logs, crash dumps,
`hiberfil.sys`/pagefile; DPAPI blobs fall to offline password cracking. *New:* **TM-R31** (admin guide and first-run
note: use BitLocker/device encryption on machines that store keys or enable the disk cache).

---

## 6. Top risks (ranked)

| Rank | Threat | Why first | Fix |
|---|---|---|---|
| 1 | T-23 stage-2 inverse yields `/` and NUL | remote path traversal from any Windows name; trivial to trigger | TM-R11 |
| 2 | T-62, T-63, T-64 installer elevation (DLL planting, `%ProgramData%` pre-creation, MSI repair) | standard user → SYSTEM on every per-machine install | TM-R33–R35 |
| 3 | T-09, T-10 NEW_TYPE prompt and auto-filled secrets after re-TOFU | turns a blocked MITM into a prompt the user accepts, then hands over the password | TM-R04, TM-R05 |
| 4 | T-32 WebDAV port squatting after agent death; XP port hijack | other local users receive file data and NTLM auth | TM-R17 |
| 5 | T-28, T-29 shell-active remote files and missing MotW | a malicious server can leak the user's NTLM hash and bypass SmartScreen | TM-R14, TM-R15 |
| 6 | T-01, T-02 Terrapin with ChaCha20 first; legacy enabled by default | weakest default against legacy and unpatched servers | TM-R01, TM-Q01 |
| 7 | T-03, T-04 own-crypto timing on 32-bit and unreviewed betas | `_allmul` assumption is wrong; review comes late | TM-R02, TM-Q09 |
| 8 | T-46, T-47 service pipe and snapshot squatting | SYSTEM parser reachable by all users; Explorer parses foreign data | TM-R25, TM-R26 |
| 9 | T-67, T-72 update key roles and CI provenance | one stolen key or Action compromises every install | TM-R37, TM-R39 |
| 10 | T-20 NTLM sent to proxies; T-43 global drives open to `BUILTIN\Users` | credential exposure; confused deputy by default | TM-R10, TM-R24 |

---

## 7. Required security tests (mapped to milestones, 00 §6)

Priority: P1 blocks the milestone demo, P2 blocks the next milestone, P3 blocks 1.0.

| Id | M | P | Test | Covers |
|---|---|---|---|---|
| TST-01 | M0 | P1 | All 01 §12.2 fuzz targets present on day one for the M0 parsers (packet, kexinit, kex reply, userauth, channel, SFTP reply, attrs, OpenSSH key file, known_hosts), 5 min per PR; WinAFL on the `x64-xp` binary from M0 and the x86 flavours from M1 | T-06 |
| TST-02 | M1 | P1 | New fuzz targets missing from 01 §12.2 / 04 §11.2: `sd_json` + IPC dispatch (agent and service), `sd_ini` (profiles, settings, overrides), the snapshot reader of the shell DLL, `.sdmount` parser, HTTP request line/headers incl. `If:`, `Range`, `Destination`, `Timeout`, chunked decoder, percent-decoder + name map stage 2; `ssh_config` and PuTTY session importers in M2 | T-37, T-46, T-47, T-61 |
| TST-03 | M0 | P1 | Constant-time: disassembly check fails on any call to `_allmul`, `_aullmul`, `_alldiv`, `_aulldiv`, `_allrem`, `_aullrem` from `*_ct_*`, field, scalar, ladder, bignum-ct and ML-KEM code on `x86-ia32`, `x86-sse2`, `arm32`; dudect classes include "high word zero" inputs on 32-bit flavours (from M1) | T-03 |
| TST-04 | M0 | P1 | Crypto KAT/Wycheproof/CNG-differential per primitive as in 01 §2.7, plus negative transcripts: all-zero X25519 output, invalid ECDH points, non-canonical Ed25519 S, Poly1305/GCM tag single-bit flips, decryption output never released before MAC (01 §2.4 rule 7) | T-04 |
| TST-05 | M0 | P1 | Name mapping property tests: for every UTF-16 string, `from_wide(to_wide(x))` never yields `/`, NUL, or a component `.`/`..`; inverse of U+F000..U+F07F outside the forward set is rejected; mock-server dirents with `/`, NUL, `.`, `..`, empty, duplicates, colliding mappings, 64 KiB names, reserved device names | T-23, T-24, T-27 |
| TST-06 | M1 | P1 | WebDAV path tests: `%2F`, `%5C`, `%00`, `%2e%2e`, overlong UTF-8, mixed-case escapes, `Destination` with another authority/token/port, `..` beyond the prefix; all → 400/403/502, never a remote call outside the root | T-25 |
| TST-07 | M2 | P2 | Symlink tests on the WSL fixture: links to `/`, `../..`, loops, FIFO, `/dev/zero`; `follow`, `hide` and (after TM-R13) `follow_inside` | T-26 |
| TST-08 | M1 | P2 | Malicious-server DoS corpus in the mock `sd_sftp` and a patched test sshd: READDIR without EOF, 10^7 entries, 10^5 symlinks, 2^64−1 sizes, statvfs overflow values, 25 s drip-fed replies; assert caps, deadlines, bounded memory | T-30 |
| TST-09 | M1 | P1 | Loopback WebDAV attack suite: second local user (SSPI 403), anonymous/Guest NTLM, wrong token (404 before 401), browser-origin requests from Chrome/Edge/Firefox (fetch `no-cors`, form POST, `<img>`, DNS rebinding to 127.0.0.1, wrong `Host`), 64 idle/slowloris connections from another user while the owner copies a file, body sent before auth; WebClient connection reuse across sessions for per-user servers (lab, M1 on 7/10, XP in M1 lab) | T-31, T-33, T-34, T-36, T-37 |
| TST-10 | M1 | P1 | Port squat: kill the agent (`TerminateProcess`) with a mapped WebDAV drive; a second user binds the port; assert the drive is unmapped within 5 s (TM-R17) and no request reaches the squatter; on XP, a second user's `SO_REUSEADDR` bind fails | T-32 |
| TST-11 | M0 | P1 | Host-key negatives: mismatch blocks (M0 demo); NEW_TYPE for a known host fails without prompt after TM-R04 (M0 for ed25519 vs ecdsa as soon as ECDSA exists, M2); after "remove old key + TOFU", stored password is not auto-sent (M2); reconnect with a changed key never prompts without `is_reconnect` UI | T-08, T-09, T-10 |
| TST-12 | M2 | P1 | Terrapin interop: a test MITM proxy (test-only, never shipped) that performs the published prefix truncation against a non-strict server; with TM-R01 the connection uses a non-affected cipher or fails; with strict KEX the injection is fatal | T-01 |
| TST-13 | M2 | P1 | Legacy policy matrix on lab servers (3DES/group1/old OpenSSH): `allow/warn/ask/refuse` behave as documented; no legacy algorithm is chosen when a modern one is offered; GEX < 2048 handling per TM-Q01 | T-02 |
| TST-14 | M2 | P2 | Live sources: `~/.ssh/known_hosts` writable by another user is ignored with a warning; wildcard-only lines do not yield MATCH; mismatch in a source blocks | T-11 |
| TST-15 | M2 | P1 | UpdateHostKeys negatives (list in T-12) | T-12 |
| TST-16 | M2 | P2 | Pool: DNS round robin to two servers with different keys or homes; member dropped, pool disabled, primary unaffected | T-14 |
| TST-17 | M2 | P2 | Agent squatting: second user creates `\\.\pipe\openssh-ssh-agent`; Pageant window class registered by a low-IL process; client refuses both | T-16, T-17 |
| TST-18 | M2 | P1 | Proxy NTLM harvesting: a test proxy answering `407 NTLM` without being configured for SSPI, and a WPAD-discovered proxy; no SSPI token leaves unless TM-R10 conditions hold; Squid Kerberos path still works in the lab domain | T-20 |
| TST-19 | M0/M5 | P2 | Dokany isolation: second user (RDP/FUS) opens `\\?\Z:` and the device of a per-user mount → denied; SYSTEM-context service with another user's request; synthesized DACL contains no `Everyone` ACE for per-user mounts (TM-R22) | T-41 |
| TST-20 | M3 | P1 | Explorer content lab: remote folder with `.library-ms`, `.searchConnector-ms`, `.url`, `.lnk` whose icons point at `\\<lab-smb>\x`, plus `desktop.ini` in a mode-0555 directory; capture outbound SMB/NTLM on both backends, XP–11; verify TM-R14 behavior | T-28 |
| TST-21 | M3 | P2 | Zone and MotW lab: zone of files on each backend; SmartScreen on an unsigned EXE and Office Protected View on a `.docm` opened from the drive; with TM-R15 option on/off | T-29 |
| TST-22 | M1 | P2 | WebClient cache: location and ACL per OS (XP, 7, 10, 11) with two users | T-39 |
| TST-23 | M5 | P1 | IPC ACL suite (XP, 7, 10, 11): pipe squat by a second user (agent and service), anonymous/identification clients, non-elevated admin on mutating service methods, low-IL and AppContainer clients refused, 32-instance exhaustion by a non-admin while an elevated admin still connects (TM-R25), `prompt`/`log` topics refused to non-admins, `attach_info` schema and membership | T-44–T-46, T-49 |
| TST-24 | M3 | P1 | Snapshot squat: second user in the same session (`runas`) and a low-IL process pre-create `Local\ShellDrive.state.<SID>`, the ready event and the mutex; agent refuses, shell DLL ignores foreign-owned sections; fuzzed snapshot never crashes the DLL (run inside a test host and inside Explorer in the lab) | T-47, T-60 |
| TST-25 | M5 | P1 | Service inputs: service profile key file replaced through a junction between check and use; key file with a user-writable ACL; profile in a user-writable folder → refused | T-51 |
| TST-26 | M5 | P1 | Global WebDAV G1–G7 per OS (02 §7.7 + TM-R18 G7 negatives) | T-52 |
| TST-27 | M4 | P2 | Uninstall residue: per-user and per-machine (EXE, ARP, `msiexec /x`, SYSTEM/Intune), with and without "remove data"; list every remaining secret, cache and registry value; compare with TM-R28 | T-54 |
| TST-28 | M3 | P2 | Dump hygiene: crash host/UI/CLI during a password prompt, during KEX and during a KDF with a known test password and key; scan the dump for those bytes; verify WER is not invoked after our dump | T-57 |
| TST-29 | M4 | P1 | Installer elevation lab (XP, 7, 10, 11): Procmon "NAME NOT FOUND" in the stub's directory for setup, elevated child, uninstall and update setup; planted-DLL canaries in `Downloads`, `%TEMP%` and the staging folder must not load; `%ProgramData%\ShellDrive` pre-created by a standard user (owner, DACL, junctions) before install and before service start; `msiexec /fa` and `/fu` as a standard user with Procmon (no SYSTEM process touches user-writable paths); Dokany MSI hash/signer mismatch refused | T-62–T-65, T-70 |
| TST-30 | M0 | P2 | Release-binary checks: no `none` cipher, no fuzz hooks, no test certificates, no `__DATE__`; `sd-importcheck` lists only KnownDLLs as static imports of the setup stub | T-06, T-62 |
| TST-31 | M4 | P1 | Updater: tampered manifest/file, replayed old manifest (rollback), expired manifest (freeze), beta-signed manifest on stable, beta serial poisoning, redirect to a foreign host, oversized responses, interrupted downloads, key-set rotation and revocation per TM-R37 | T-66, T-67, T-69 |
| TST-32 | M4 | P2 | Provenance: maintainer rebuilds the tag on the lab machine from a clean checkout and toolchain and compares hashes with CI before signing stable; workflow lint: Actions pinned by SHA, no `pull_request_target`, release job reads no caches | T-72 |
| TST-33 | M6 | P1 | External crypto review findings closed (01 §2.7.6); nightly fuzzing at scale; a black-box penetration test of the WebDAV server, IPC and installer by someone outside the team | all |

---

## 8. Recommended design changes (`TM-Rxx`)

Format: id, document § to change, change, rationale.

- **TM-R01** — 01 §4.2/§4.3; 03 §3.4.1. Send our KEXINIT only after the server's KEXINIT has arrived (RFC 4253
  allows either order; servers send theirs right after the version exchange, so the delay is at most half an RTT).
  If the server lacks `kex-strict-s-v00@openssh.com`, remove `chacha20-poly1305@openssh.com` and the CBC + `*-etm`
  combinations from our lists for that connection, preferring AES-GCM, then AES-CTR. Keep `refuse_terrapin_exposed`
  for servers that offer nothing else. *Rationale:* T-01 without a reconnect dance and without user action.
- **TM-R02** — 01 §2.4 rule 3, §2.7.5. Replace "64x64 multiplication on x86 goes through `_allmul`, which is constant
  time" with: on 32-bit targets constant-time code uses only `__emulu` (x86) / `UMULL` intrinsics (ARM32); 64×64
  products are built from 32×32 pieces; calls to `_all*`/`_aull*` helpers are forbidden in secret-handling code
  except shifts with public counts; the disassembly check fails on such calls. *Rationale:* T-03, BearSSL ctmul.
- **TM-R03** — 03 §5.2, §5.3. The TOFU dialog has no default button (Enter does nothing until a button has focus);
  the CLI default answer is "no"; for hop i ≥ 1 the dialog says "reached through jump host <hop i−1>". *Rationale:*
  T-08, T-19.
- **TM-R04** — 01 §4.3, §7.1; 03 §5.2. When any key is stored for the lookup name (any store or live source),
  offer only the stored key types (plus their cert variants with a matching `@cert-authority`) in the host-key list.
  `SD_HK_NEW_TYPE` then cannot occur through negotiation; if it still does (server lacks every stored type), fail
  with `host_key_type_unavailable` and point to the host key manager. New types are learned through UpdateHostKeys
  or an explicit "add key" action. *Rationale:* T-09 (matches OpenSSH behavior for known hosts).
- **TM-R05** — 03 §4.2, §2.5; 01 §6.7. If the host key of any hop was accepted by TOFU or "Connect once" in this
  connection, `sd_mount` does not answer password, passphrase-for-server or kbd-int prompts from stored secrets or
  the reconnect cache for that connection. The prompt is shown with a note ("this server's identity was just
  accepted"). *Rationale:* T-10.
- **TM-R06** — 01 §7.2; 03 §5.1. Live sources are read only if the file's DACL grants write to nobody but the user,
  SYSTEM and Administrators (otherwise skipped with `warning hostkey_source_insecure`); lines whose host pattern is
  only wildcards (`*`, `*.*`, `?*`) are ignored for MATCH from live sources (still counted for MISMATCH).
  *Rationale:* T-11.
- **TM-R07** — 03 §3.2. Apply the protected per-user DACL (user + SYSTEM) also to `%APPDATA%\ShellDrive\`,
  `profiles\`, `overrides\` and `known_hosts` at creation, as already done for `keys\` and `secrets\`.
  *Rationale:* T-13 on redirected profiles.
- **TM-R08** — 01 §6.5. Before talking to an agent: for Pageant, resolve the window's process with
  `GetWindowThreadProcessId` and require its token user SID = ours and integrity ≥ ours; for the OpenSSH pipe,
  require pipe owner `S-1-5-18` (default pipe) or our SID (a user pipe from `SSH_AUTH_SOCK`), using the same helper
  as 03 §2.2. *Rationale:* T-16, T-17.
- **TM-R09** — 01 §6.1/§6.4; 03 §2.5. Sanitization of server text and displayed host names also removes bidi
  controls (U+202A–U+202E, U+2066–U+2069, U+200E/F) and zero-width characters; the hop host is rendered outside the
  server-text area. *Rationale:* T-18.
- **TM-R10** — 01 §5.2; 03 §3.8. SSPI to a proxy is used only when the proxy host was configured explicitly in the
  profile or policy (`ProxyServer`), never for a WPAD/PAC-discovered proxy unless policy `AllowSystemProxySspi = 1`;
  `auto` uses Negotiate restricted to Kerberos (package list excluding NTLM via `SEC_WINNT_AUTH_IDENTITY_EX`), NTLM
  only with `proxy_auth = negotiate`. *Rationale:* T-20.
- **TM-R11** — 02 §1.2 (normative change). The stage-2 inverse maps back **only** the code points the forward map
  produces: U+F001–U+F01F, U+F022, U+F02A, U+F03A, U+F03C, U+F03E, U+F03F, U+F05C, U+F07C, and U+F020/U+F02E in
  trailing position. Every other code point in U+F000..U+F07F passes through unchanged as UTF-8 (in particular
  U+F000 and U+F02F never become NUL or `/`). After the inverse, `sd_vfs` asserts that no component contains `/`
  or NUL and is not `.`/`..`. Add a sentence to 01 §10.7 that the composed mapping must keep that invariant.
  *Rationale:* T-23.
- **TM-R12** — 01 §10.3/§10.5; 02 §1.1, §6.5, §7.5. Specify dirent handling: entries with `/` or NUL, empty names
  and the server's own `.`/`..` are dropped and logged once per directory; duplicate raw names keep the first;
  entries whose Windows names collide after stage 2 go through the `~cN` rule. WebDAV: split the path on `/` before
  percent-decoding; reject `%2F`, `%5C`, `%00` and any decoded `\` in a segment with 400; the same lexical rules
  apply to `Destination`. *Rationale:* T-24, T-25.
- **TM-R13** — 02 §6.9; 03 §3.4.1. New value `symlinks = follow_inside`: the pipelined `stat` of a link is followed
  by `realpath`; targets outside the mount root's realpath are shown as dangling (0-byte `HIDDEN|SYSTEM`) and cannot
  be opened. Default for `scope = service` and `scope = users` profiles with a non-empty `remote_path`; `follow`
  stays the default otherwise. Document that the mount root is not a confinement boundary in `follow` mode.
  *Rationale:* T-26.
- **TM-R14** — 02 §4.1, §6.4; 03 §3.4.1. New profile key `shell_active_files = show | block` (default `block` for
  profiles marked `trust = untrusted`, else `show`): with `block`, `.library-ms`, `.searchConnector-ms`, `.url`,
  `.lnk`, `.scf` and `desktop.ini` are listed but opening them for read from Explorer (`explorer.exe` requestor on
  Dokany; WebDAV GET) returns access denied. Admin guide: recommend "Restrict NTLM: outgoing NTLM traffic to remote
  servers" where possible. *Rationale:* T-28. (Exact extension list confirmed by TST-20.)
- **TM-R15** — 02 §1.1, §6.4. After TST-21, add the profile option `mark_of_the_web = off | internet` (Dokany only):
  with `internet`, mount with `DOKAN_OPTION_ALT_STREAM` and expose a synthetic read-only `:Zone.Identifier` stream
  (`ZoneId=3`, `HostUrl=sftp://host/path`) on every regular file; all other stream names stay rejected.
  *Rationale:* T-29.
- **TM-R16** — 02 §1.4, §6.6, §6.9, §6.5. Per-listing caps: 1,000,000 entries or 256 MiB of names, and a total
  listing deadline (120 s) after which `DokanResetTimeout` is no longer called and the listing fails with
  `TOO_LARGE`; symlink `stat` batch capped (4,096 per listing; the rest shown as links of unknown type until opened);
  statvfs products use checked multiplication and saturate. *Rationale:* T-30.
- **TM-R17** — 02 §7.3; 03 §1.2, §1.4, §10.4. (a) Every listener sets `SO_EXCLUSIVEADDRUSE` before `bind` (XP+).
  (b) The crash filter's last step, after the dump, cancels this process's WebDAV mappings
  (`WNetCancelConnection2W(…, TRUE)`) before `TerminateProcess`. (c) The tray UI and any long-running CLI hold a
  handle to the agent process; when it exits unexpectedly they cancel mappings to `\\localhost@<port>` of that
  agent and notify. (d) At start the agent removes stale `localhost@port` mappings of its logon session before
  binding. (e) Elevated-view mappings are removed by the same watchers. *Rationale:* T-32, T-40.
- **TM-R18** — 02 §7.7. Run criterion G2 also against per-user servers (two users mapping each other's port with
  the correct token must fail SSPI). Add G7 "negative access": a user outside `service_access` sees no data through
  any session; removing a user from `service_access` takes effect within 60 s; a session-0 process other than
  SYSTEM with `allow_system` is refused. *Rationale:* T-34, T-52.
- **TM-R19** — 02 §7.4. Token-only mode is never switched on automatically: it needs an explicit user confirmation
  each time it is enabled, is refused when the machine has the Remote Desktop Session Host role or more than one
  active interactive session, and can be disabled by policy (`AllowWebDavTokenOnly = 0`). *Rationale:* T-35.
- **TM-R20** — 02 §7.3, §7.5. Connection limits: unauthenticated connections ≤ 8 and must complete the request
  headers within 10 s and authentication within 30 s; at most 4 concurrent unauthenticated connections per remote
  port tuple; authenticated connections get the remaining slots. Request bodies, `If:`, `Destination`, `Lock-Token`
  and XML are parsed only after the token prefix and SSPI checks pass. *Rationale:* T-36, T-37.
- **TM-R21** — 02 §7.2, §10.1; 03 §10.5. Never start WebClient for a profile that resolved to Dokany; `diag` reports
  "WebClient running" as a security note on domain-joined machines; the admin guide recommends `AllowedBackends =
  dokany` and a disabled WebClient on servers and domain machines that have Dokany. *Rationale:* T-38.
- **TM-R22** — 02 §3.3. For per-user mounts, the synthesized DACL contains the mount owner, SYSTEM (if
  `allow_system`) and Administrators only; the POSIX `g`/`o` bits are reported through extra ACEs only on global
  mounts. *Rationale:* T-41 (security trimming by SYSTEM services).
- **TM-R23** — 02 §6.3; 04 §7.3, §9.2. The signed update manifest carries a `dokany-deny <version-range> <reason>`
  list; the host warns and disables the Dokany backend for listed versions; setup verifies the SHA-256 at embed time
  and at install time and checks the MSI's Authenticode signer name against `dokany.lock`. *Rationale:* T-42, T-65.
- **TM-R24** — 03 §3.4.1; 02 §6.4, §7.7. `service_access` has no implicit default: the editor pre-fills
  `BUILTIN\Users` with a warning but saving requires the field; add `service_access_write` (SID list, default
  empty = read-only for non-admins) so the volume SD and the vfs check agree; the Event Log records the user SID of
  each mutating operation at info level (repudiation). *Rationale:* T-43.
- **TM-R25** — 03 §2.2, §2.4, §2.6. Service pipe: per-SID instance quota of 4 and two instances reserved for elevated
  administrators; topics `prompt`, `log` and `hostkeys` and the `status` details (host, user, proxy legs) only for
  elevated admins, non-admins see letter, label and state of mounts they are in `service_access` for.
  *Rationale:* T-46.
- **TM-R26** — 03 §1.2, §1.4, §1.6, §2.1, §8.2. The agent creates the snapshot section, ready event and mutex with
  an explicit DACL and treats `ERROR_ALREADY_EXISTS` with a foreign owner as squatting (log, run without the
  object, tray warning). The shell DLL maps the section only if its owner is the user SID and its integrity label is
  ≥ medium; every offset and length is bounds-checked against the mapped size. The UI checks the `WM_COPYDATA`
  sender's process SID and accepts only the documented verbs. *Rationale:* T-47, T-48.
- **TM-R27** — 03 §2.6 rule 1, §3.2. The service opens key files with `FILE_FLAG_OPEN_REPARSE_POINT`, refuses reparse
  points in the path, checks owner and DACL **on the opened handle** (`GetSecurityInfo`), and reads only from
  `%ProgramData%\ShellDrive\service\` or paths whose every component is admin-owned; it never reads HKCU or user
  profile paths. *Rationale:* T-51.
- **TM-R28** — 04 §6.7, §8.4; 03 §4. Per-machine uninstall removes `service\secrets\` and `service\keys\` by default
  (`REMOVESECRETS=1` default; machine profiles and settings still follow `REMOVEDATA`); every uninstall deletes the
  cache directories; the uninstall summary lists what was kept. *Rationale:* T-54.
- **TM-R29** — 02 §4.2; 03 §1.9; 04 §6.8. If the data or cache directory is on a volume without persistent ACLs
  (`FILE_PERSISTENT_ACLS` absent), the disk cache is refused, and portable mode shows a one-time warning that host
  keys and profiles on this medium can be changed by anyone who has it. *Rationale:* T-55, T-59.
- **TM-R30** — 03 §10.4; 01 §2.4 rule 8. Use a `MiniDumpCallback` that drops the stacks of SSH I/O threads and KDF
  workers (`IncludeThreadCallback`/`ThreadCallback`), or writes them only with `--include-secret-stacks`; crypto and
  prompt-handling functions wipe stack buffers holding secrets before return; after our dump the filter calls
  `TerminateProcess` so WER does not collect a second report. *Rationale:* T-57.
- **TM-R31** — 03 §10.1, §10.5; admin guide (00 §4 "User documentation"). Remote paths only at debug level except in
  error records; `diag --bundle` anonymizes by default (`--no-anonymize` to opt out); the admin guide and first-run
  page recommend full-disk encryption when keys are kept or the disk cache is on, and describe DPAPI's dependence on
  the Windows password and the effect of `CRED_PERSIST_ENTERPRISE`. *Rationale:* T-53, T-56, T-58, T-73.
- **TM-R32** — 03 §8.1, §8.7. `.sdmount` grammar fixed to one key `profile = <32 hex>`; unknown keys make the file
  invalid; never ad-hoc hosts; a file carrying Mark-of-the-Web asks before mounting. *Rationale:* T-61.
- **TM-R33** — 04 §6.1, §6.4, §6.7, §2.4. The setup stub and `uninstall.exe` statically import only KnownDLLs
  (kernel32, user32, advapi32, shell32, ole32, gdi32 and similar; enforced by `sd-importcheck`), use no delay-load,
  call `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` first thing where available, load `cabinet.dll`,
  `msi.dll`, `wintrust.dll` and every other module by full System32 path, and link v143 builds with
  `/DEPENDENTLOADFLAG:0x800`. The elevated child copies itself into the admin-only staging directory (TM-R34) and
  the unelevated parent launches **that copy** with `runas`, never the copy in `Downloads`; `uninstall.exe` for
  per-machine installs runs from `%ProgramFiles%`, never from `%TEMP%`. *Rationale:* T-62, T-70.
- **TM-R34** — 04 §6.4; 03 §3.2. Elevated setup, before using `%ProgramData%\ShellDrive`, checks its owner; if it is
  not Administrators/SYSTEM it renames the folder aside (`ShellDrive.untrusted-<n>`), logs it, and creates a fresh
  one with the 03 §3.2 DACL; no reparse points are followed (`FILE_FLAG_OPEN_REPARSE_POINT` on every component).
  Extraction goes to a new directory created with `CreateDirectoryW` and an explicit SD in the same call (fails if it
  exists). Imported content of a renamed folder is never reused. *Rationale:* T-63.
- **TM-R35** — 04 §8.3. Custom actions running as SYSTEM are conditioned so they never run during repair
  (`REINSTALL` set) except `webdav-tune`, which is idempotent; while running as SYSTEM the hook host loads no user
  configuration, resolves no environment-relative paths, opens no window and starts no child process. A CI check
  dumps the `InstallExecuteSequence` conditions of all six MSIs. *Rationale:* T-64.
- **TM-R36** — 04 §9.2. `expires` ≤ 30 days (stable) and ≤ 14 days (beta); the release workflow re-signs the current
  manifest every two weeks (stable re-signing needs the offline key, so plan a fixed cadence); UI warning when the
  last verified manifest is older than 14 days. *Rationale:* T-66.
- **TM-R37** — 04 §9.2, §9.3. Split roles: an offline **root** key pair (the current backup plus a second offline
  key, signature by either) signs a `keyset` record listing the release keys (stable, beta) with validity and
  revocations; release keys sign manifests only and cannot change the key set. Manifests carry `channel`; a client
  accepts a manifest only if its channel equals the configured one and the signing key is authorized for that
  channel; `last_serial` is stored per channel. *Rationale:* T-67.
- **TM-R38** — 04 §10, §12.3. Until Authenticode exists: no public download links; beta builds go to named
  testers with the ed25519-signed `SHA256SUMS.sig` and the release key fingerprint published in the repository
  README; the setup stub verifies its own payload table against the compiled-in release key and refuses on
  mismatch. *Rationale:* T-71.
- **TM-R39** — 04 §11.2, §12.2, §12.3. Release workflow: only first-party Actions pinned by commit SHA, no caches,
  minimal `GITHUB_TOKEN` permissions, signed and protected tags, CODEOWNERS on `.github/` and `installer/`;
  integration fixtures (WSL rootfs, sshd) run in jobs that cannot write release artifacts; before signing stable,
  the maintainer reproduces the build on the self-hosted lab machine (or another clean machine) and compares hashes
  with CI (TST-32). *Rationale:* T-72.

---

## 9. Requirements and decisions to revisit (`TM-Qxx`)

| Id | Current | Concern | Recommendation |
|---|---|---|---|
| TM-Q01 | Requirements "Crypto policy": legacy enabled by default; 03 §3.4.1 `legacy_algorithms = warn` | Passive weakness against legacy-only servers; repeated warnings train users to ignore them (T-02) | Keep "enabled by default" but make the default `ask` (one acknowledgement per host and algorithm set, remembered in `legacy_accepted`, 03 §7.6), and refuse `diffie-hellman-group1-sha1` and GEX groups < 2048 bits unless the profile sets `legacy_algorithms = allow` explicitly. |
| TM-Q02 | 03 §3.4.1 `refuse_terrapin_exposed = no` | T-01 | Accept TM-R01; with it the default can stay `no`. Without TM-R01, change the default to `yes`. |
| TM-Q03 | D7 live sources on by default | T-11 | Keep, with TM-R06. |
| TM-Q04 | D6 service on by default | T-50 | Keep; the idle design is sound if TM-R25 is applied. |
| TM-Q05 | 03 §3.4.1 `service_access` default `BUILTIN\Users` | T-43: every local and RDP user acts as the service account | No implicit default (TM-R24); read-only for non-admins unless `service_access_write` is set. |
| TM-Q06 | 04 §6.3 per-machine EXE installs Dokany by default (`/dokany=auto`) | T-42: a kernel driver for every local user | Keep, but the option page states that a kernel driver is installed and offers WebDAV-only; silent installs keep `/dokany=auto` only when the admin passes it. |
| TM-Q07 | 03 §3.4.1 `identities_only = no` | T-15: all agent keys offered to every hop | Default `identities_only = yes` when the profile (or hop profile) names an identity; agent keys are then used only when selected by fingerprint. |
| TM-Q08 | 03 §3.4.1 `cache_secrets_for_reconnect = yes` | Longer secret lifetime (03 §13.1 item 7) | Keep (reconnect UX), with TM-R05. |
| TM-Q09 | D1 external crypto review before 1.0 (M6); D29 certificate before public 1.0 | T-04, T-71: betas handle real keys before review and unsigned | Split the review: pass 1 at the end of M2 (field arithmetic, X25519/Ed25519, ChaCha20-Poly1305, AES/GHASH, packet protection, KEX), pass 2 in M6 (P-curves, RSA/DH bignum, ML-KEM, KDFs). No public beta before pass 1 and TM-R38. |

---

## 10. Platform facts used (sources)

- Terrapin: ChaCha20-Poly1305 and EtM affected; CBC-EtM exploitable with limited success rate; CTR-EtM fails at
  the application layer; strict KEX is the fix: [USENIX Security '24 slides](https://usenix.org/system/files/usenixsecurity24_slides-baumer.pdf),
  [IETF 122 SSHM slides](https://datatracker.ietf.org/meeting/122/materials/slides-122-sshm-terrapin-attack-and-strict-kex-00).
- MSVC 64-bit multiplication helper on 32-bit x86 is not constant time; 32×32→64 `MUL` is constant time on P6 and
  K7: [BearSSL constant-time multiplication](https://www.bearssl.org/ctmul.html).
- Windows RNG analysis (Windows 2000, acknowledged for XP): [ePrint 2007/419](https://eprint.iacr.org/2007/419);
  the XP SP3 fix is **[verify]**.
- `SO_EXCLUSIVEADDRUSE`; enhanced socket security only from Server 2003:
  [Microsoft Learn](https://learn.microsoft.com/en-us/previous-versions/ms740618(v=vs.85)); PuTTY listener issue:
  [vuln-win-exclusiveaddruse](https://putty.cs.utah.edu/wishlist/vuln-win-exclusiveaddruse.html).
- NTLM hash disclosure by browsing a folder with a crafted `.library-ms` (CVE-2025-24054):
  [Check Point Research](https://research.checkpoint.com/2025/cve-2025-24054-ntlm-exploit-in-the-wild/).
- WebClient turns NTLM coercion into HTTP and enables relay to LDAP:
  [SpecterOps, 2026-01](https://specterops.io/blog/2026/01/14/wait-why-is-my-webclient-started-sccm-hierarchy-takeover-via-ntlm-relay-to-ldap/);
  any user can trigger-start WebClient (cited in 02 §7.1).
- MSI repair by standard users runs SYSTEM custom actions:
  [Mandiant / Google Cloud](https://cloud.google.com/blog/topics/threat-intelligence/privileges-third-party-windows-installers/),
  [Doyensec](https://blog.doyensec.com/2024/07/18/custom-actions.html).
- Dokan kernel driver local privilege escalation precedent (CVE-2018-5410): [CERT VU#741315](https://kb.cert.org/vuls/id/741315).
- WER consent and settings: [Microsoft Learn: WER settings](https://learn.microsoft.com/en-us/windows/win32/wer/wer-settings).
- Facts already cited in 01–04 (WebDAV redirector parameters, intranet credential rules, Dokany versions and
  options, Credential Manager persistence on Home SKUs, SmartScreen and Smart App Control) are not repeated here.
