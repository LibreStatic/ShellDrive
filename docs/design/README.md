# ShellDrive design

Status: design, decisions accepted 2026-10-24 ([`decisions.md`](decisions.md)) and folded into 01–04; the
documents were reconciled with each other on 2026-10-24 (`00-integration-review.md` §8). The threat model
(`05-threat-model.md`) was decided in D33–D43 and applied to 01–04 the same day (05 §11 maps each TM-R to its
section). Remaining items are lab verifications.

| Doc | Scope |
|---|---|
| [`../requirements.md`](../requirements.md) | Product requirements and hard constraints |
| [`decisions.md`](decisions.md) | The user's accepted decisions D1–D43 and the resulting build flavours (authoritative) |
| [`00-integration-review.md`](00-integration-review.md) | Cross-document conflicts and resolutions (historical record), requirement amendments, module dependency graph, milestones M0–M7, reconciliation status |
| [`01-ssh-sftp-crypto.md`](01-ssh-sftp-crypto.md) | `sd_crypto`, `sd_ssh`, `sd_sftp`: transport, KEX, auth, agents, ProxyJump, proxies, host keys, SFTP client API, connection pool |
| [`02-filesystem.md`](02-filesystem.md) | `sd_vfs`, `sd_webdav`, `sd_dokan`: VFS core, caches, write modes, reconnect, WebDAV redirector server, global WebDAV, Dokany adapter, backend selection |
| [`03-apps-platform.md`](03-apps-platform.md) | Processes, IPC, profiles and policies, credentials, CLI, tray/main window, Explorer integration, localization, logging |
| [`04-build-install-update.md`](04-build-install-update.md) | Toolchains, flavours, CRT, CI, test lab, setup EXE, MSI, Dokany redistribution, updater, signing, releases |
| [`05-threat-model.md`](05-threat-model.md) | Assets, trust boundaries, STRIDE threats T-01..T-73, security tests per milestone, recommended changes TM-R01..R39 and decisions TM-Q01..Q09 (decided in D33–D43; status in §11) |
| [`06-ui-tiers.md`](06-ui-tiers.md) | Proposal (not accepted): OS-tiered UI rendering (Classic on XP, Aero on Vista/7, Fluent with dark mode and Mica on 10/11), mechanisms, screens per tier, tests and options |

Precedence when documents disagree: `decisions.md`, then the resolutions in `00-integration-review.md`, then the
document that owns the topic (01: SSH/SFTP/crypto/known_hosts I/O; 02: VFS/WebDAV/Dokany; 03: processes, IPC,
profiles, UI, localization, policies; 04: build, install, update, CI). `05-threat-model.md` owns only its
security test list (TST-xx); its TM-R recommendations bind as decided in `decisions.md` and applied in the owning
documents.

Changelog: Final reconciliation (threat model) 2026-10-24: status, D1–D43, 05 scope and precedence updated.
