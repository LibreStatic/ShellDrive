# ShellDrive test-lab results (04 §11.4)

VM creation state and per-VM run results. One section per VM and run: date, commit, image,
flavours, pass/fail per item, log file name. The host config lives outside the repo at
`D:\sdlab\lab.psd1`; base images go to `D:\images\`.

## 2026-10-28: harness generation-2 support + VM creation (no runs yet)

Commit: `c58dc99` ("lab: support generation 2 VMs with Secure Boot and vTPM", on `wip/m2-backend`,
not pushed; local gate not rerun — PowerShell-only change, syntax-checked).

- `tests/lab/New-LabVM.ps1` reads `Generation` (default 1) and `Tpm` per VM: Secure Boot on with
  the MicrosoftWindows template on generation 2, local key protector plus `Enable-VMTPM` when asked,
  SCSI DVD and synthetic NIC on generation 2, DVD-first boot order for fresh installs on both
  generations. Generation-1 behavior for XP/7 is unchanged.
- `tests/lab/lab.example.psd1` documents `Generation`/`Tpm`.
- `D:\sdlab\lab.psd1` (host only): `Generation = 2; Tpm = $true` on sd-win11-23h2-x64,
  `Generation = 2` on sd-srv2022-x64; all other VMs stay generation 1.

All six first-batch VMs created with empty 20 GB disks and their setup ISOs attached, verified Off:

| VM | Gen | Secure Boot | TPM | Install ISO (verified present) |
|---|---|---|---|---|
| sd-xp-sp3-x86 | 1 | — | — | `W:\Fold4\en_windows_xp_professional_with_service_pack_3_x86_cd_vl_x14-73974.iso` |
| sd-win7-sp1-x86 | 1 | — | — | `W:\Fold4\en_windows_7_with_sp1_x86_dvd_u_677460.iso` |
| sd-win7-sp1-x64 | 1 | — | — | `C:\Users\facum\Downloads\Windows 7 x64 SP1 RTM.iso` |
| sd-win10-ltsc21-x64 | 1 | — | — | `D:\Otros\Downloads\en-us_windows_10_iot_enterprise_ltsc_2021_x64_dvd_257ad90f.iso` |
| sd-win11-23h2-x64 | 2 | On (MicrosoftWindows) | enabled | `D:\Win11_23H2_English_x64v2.iso` (DVD first: SCSI0:1 before SCSI0:0) |
| sd-srv2022-x64 | 2 | On (MicrosoftWindows) | — | `C:\Users\facum\Downloads\en-us_windows_server_2022_x64_dvd_620d7eac.iso` |

COM1 on every VM points at `\\.\pipe\sd-lab-<vm>` (COM 1 verified on sd-win11-23h2-x64 and
sd-xp-sp3-x86). `D:\images\` created (empty).

Next (needs the maintainer): install Windows on each VM, type the keys, create a local
administrator, shut down; move/copy each disk to `D:\images\<vm>.vhdx`, set `BaseVhdx` in
`D:\sdlab\lab.psd1`, clear `InstallIso`, rerun `New-LabVM.ps1`, boot the payload ISO, run
`\sdlab\install-runner.cmd` as administrator, shut down, take `base`. Then smoke runs with
`Invoke-SdLab.ps1` and the security lab runs (05 §7: TST-29, TST-27, TST-31, TST-19/TST-26, D11).

Still blocked: product keys, QEMU install for `sd-p3-xp`, second-batch media, code-signing
certificate (see the hand-off).

## 2026-10-28: pre-run validation (still no guest OS, no runs yet)

- QEMU is now installed: `C:\Program Files\qemu\qemu-system-i386.exe`, version 11.1.0.
  Empty P3 disk created with `qemu-img create -f qcow2 D:\images\xp-pro-sp3-x86-p3.qcow2 8G`
  (still needs the XP SP3 install under QEMU per `tests/lab/qemu/Start-QemuPentium3.ps1`).
- Payload ISO path validated against the current `build\` tree (all four shippable flavours
  have Release `shelldrive.exe`, plus the full `sd-test-*.exe` set): `New-PayloadIso.ps1`
  for `x86-ia32,x86-sse2` produced a 3465216-byte ISO via oscdimg with the expected 9 files
  in 4 directories (5 guest scripts + 2 binaries x 2 flavours). Validation ISO discarded.
- `D:\images\` now holds only the empty `xp-pro-sp3-x86-p3.qcow2`; all six `BaseVhdx` are still
  empty and no `base` checkpoints exist, so no smoke or security runs are possible yet.

Maintainer checklist to unblock the runs (hand-off §"Procedure per VM" step 2): start each VM
(`Hyper-V Manager` or `vmconnect localhost <vm>`), install Windows, enter the key, create a
local administrator, shut down; on 7 SP1 x64 optionally make two bases (without/with
KB4490628 + KB4474419 + KB3140245 — `.msu` files carry valid Microsoft signatures, install in
that order plus the `DefaultSecureProtocols` value). Then per VM: copy the disk to
`D:\images\<vm>.vhdx`, set `BaseVhdx` / clear `InstallIso` in `D:\sdlab\lab.psd1`, rerun
`New-LabVM.ps1`, attach the payload ISO, boot, run `\sdlab\install-runner.cmd` as administrator,
shut down, take `base` with `New-LabVM.ps1 -Checkpoint`. Suggested order: sd-xp-sp3-x86 first
(minimum OS, import floor capture), then sd-win7-sp1-x64, sd-win7-sp1-x86, sd-win10-ltsc21-x64,
sd-win11-23h2-x64, sd-srv2022-x64; plus the XP SP3 install inside the QEMU P3 disk.

## 2026-10-28 (evening): Win7 bases done, two mysteries open — see `D:\sdlab\handoff-lab.md`

- Win7 x86 + x64 installed fully unattended (Professional, `SD-7-X86` hostname seen in guest log),
  `base` checkpoints taken, read-only backups in `D:\images\` (5380 MB / 7588 MB), `BaseVhdx` set.
- Setup ISOs rebuilt 5× (all now carry `\autounattend.xml`, `\sdlab-seed\`, `\$OEM$` SetupComplete).
- P1 (blocks smoke): `SdLabSmoke` ONSTART/SYSTEM task is registered in the guests (verified offline
  via qemu-img + WSL forensics) but never fires — no transcript in a 30 min `Invoke-SdLab` run
  (FAIL, log-less). Fix staged: XML-defined task (power conditions off) via `SetupComplete.cmd`;
  needs a reinstall to test.
- P2 (blocks trio): Win10/Win11/Server never start setup (0% CPU from boot). ISOs verified
  structurally perfect (El Torito, RBA→etfsboot hash match, exact WIM names). Ruled out: disk resize,
  DVD drive object, host load. E4 datum: Win7 ISO in the Win10 VM reached `WIMApplyImage` then hung
  silently (`setuperr.log` empty) — forensics in `D:\sdlab\staging\e4-*.log`.
- Reinstall rule learned: a VM with a bootable HDD will not boot the setup DVD hands-free — wipe the
  disk (delete + recreate the VM; backups exist) before reinstalling.
- XP x86 + QEMU P3 still need the maintainer (product-key wall). Full detail, evidence, forensic
  playbook and ordered next steps: `D:\sdlab\handoff-lab.md` (host-only, never commit).

## 2026-10-29: Win7 x86 post-BIOS smoke — P1 still open, host stable

Host: rebooted clean 23:25 on 2026-10-28 after the BIOS fix (Power Supply Idle
Control = Typical Current Idle). The fix is a firmware setting, no repo commit.
Pre-run baseline: newest System 1001/41 at 22:05:28 / 22:05:06, nothing after the reboot.

VM state at run start: `sd-win7-sp1-x86` Off, Gen 1, 2 vCPU, compat off,
AutomaticStartAction = Nothing; `base` checkpoint from 21:56:48; `lab.psd1` has
`BaseVhdx = 'D:\images\sd-win7-sp1-x86.vhdx'`, `InstallIso = ''`. No other VM touched.

Plain smoke (`Invoke-SdLab.ps1 -Config D:\sdlab\lab.psd1 -Name sd-win7-sp1-x86`, no
`-IncludeTests`), 23:36:58 to about 00:07: restored `base`, attached a fresh payload ISO
(`D:\sdlab\payload-sd-win7-sp1-x86.iso`, oscdimg, 3465216 bytes, x86-ia32 + x86-sse2),
booted, read COM1 for the full 1800 s window. Result: FAIL, exit code 1 — `no SDLAB
BEGIN`, `no SDLAB END`, `no SDLAB RESULT lines`. Zero bytes arrived on the serial pipe,
so no transcript file was created (`D:\sdlab\logs\` stayed empty). P1 verdict: still
open; guest untouched per protocol (no guest-side changes). The harness powered the VM
off by itself afterwards (Off confirmed, no manual stop needed).

`-IncludeTests` rerun: skipped — it is conditional on a PASS that did not happen.

Host stability: no new System 1001/41 during the run — newest events still 22:05:28
(1001) / 22:05:06 (41), unchanged from baseline. No freeze or crash.

Notes: AutomaticStartAction = Nothing confirmed on `sd-win7-sp1-x86`, so a host reboot
will not auto-boot it; start-action settings on the other VMs were not audited here.
After the run `sd-srv2022-x64` was found Running (uptime about 5.5 min at 00:09); it was
not started by this task and was left untouched. Per-VM op timestamps:
`...\scratchpad\win7-smoke-ops.log` (session scratchpad, host-only).

## 2026-10-29 (night): P2 root cause — host virtual-DVD reads fail beyond 4 GiB

All tests 2026-10-28 23:xx to 2026-10-29 01:19 local, on the post-BIOS-fix host (Ryzen
C-state fix, clean reboot 23:25): host stable throughout, no new System 1001/41 (newest
remain the 22:05 baseline). This closes P2's diagnosis as a host defect — not lab
config, media or the remaster pipeline; remediation is recorded below, not executed.
Supersedes the P2 "mystery" framing in the 2026-10-28 (evening) section above, which is
left as the historical record.

Evidence matrix:

- Gen2 (`sd-win11-23h2-x64`, `sd-srv2022-x64`): remastered AND original Microsoft ISOs
  fail identically — Hyper-V event 18603 ("failed to boot an operating system") within
  3–5 s of start, then 0% CPU, heartbeat No Contact, static 4 MB disk. Secure Boot On and
  Off identical (template toggles only stick on `sd-srv2022-x64`; see notes). A bare
  scratch Gen2 VM (host defaults, original ISO, no lab config) fails identically (18603
  at 00:20:24) — the lab configuration is exonerated.
- Event 18603 EventData `VmBootSourceResultDetail` (13 occurrences): the firmware FINDS
  `\EFI\BOOT\BOOTX64.EFI`, then the media read fails ~1.05 MB (~530 sectors of 2048 B)
  before the END of each ISO, tracking each file's own end: Win11 remaster
  (6,812,749,824 B) fails at LBA 3,326,002–3,326,011 of 3,326,538; Server remaster
  (5,550,723,072 B) at LBA ~2,709,773 of 2,710,314; original Win11 (6,812,706,816 B) at
  LBA 3,326,000 of 3,326,517. DVD entry Status 0x00010003, ExtendedStatus 0x00000013.
- Gen1 (`sd-win10-ltsc21-x64`): remaster on a wiped disk stalls (disk 4 MB → 37,748,736 B
  in minute 1, then 0% CPU + No Contact + static for 12+ min, no 18603); original
  Microsoft ISO on a wiped disk: identical stall at the byte-identical 37,748,736 B
  footprint (Start 01:05:54, TurnOff 01:19:26). The original x partial-disk cell is
  confounded (partial HDD present). Remaster exonerated on Gen1 too.
- Working counterexamples (2026-10-28 evening): Win7 x86 remaster (2,445,730,176 B) and
  Win7 x64 remaster (3,688,050,688 B) installed FULLY unattended from the same pipeline —
  deep reads included.

Root cause: every ISO whose boot-required content extends beyond 4 GiB fails on this
host; every ISO entirely under 4 GiB works. Consistent with a 32-bit byte-offset
truncation in the Hyper-V virtual DVD read path (both Gen1 IDE and Gen2 SCSI) on host
build 26100.9711: Gen2 UEFI dies reading the UDF end-of-medium structures (anchor at
N-256), so 18603 fires before any code runs; Gen1 BIOS El Torito boots WinPE from the
early sectors, then setup hangs applying `install.wim`, whose data lies beyond 4 GiB
(silent stall, empty `setuperr.log` — matches the E4 datum re-examined; E4 itself ran in
the first host-crash window and is attributed to the C-state freeze, not to this).

Exonerated: the remaster pipeline (originals fail identically; El Torito BIOS+EFI entries
and boot images byte-identical to Microsoft media, verified byte-level), Secure
Boot/template state, boot order, VM configuration version (12.0 = host default),
ACLs/locking, host RAM/CPU load, and the lab scripts (`New-LabVM.ps1` audited
line-by-line, correct).

Notes for the record:

- The payload ISO has no El Torito by design (never bootable) — unaffected by this bug.
- vTPM blocks SecureBootTemplate changes on `sd-win11-23h2-x64` (VMMS 12802); template
  toggles are only meaningful on `sd-srv2022-x64`.
- `New-LabVM.ps1` still does not set AutomaticStartAction (recreated VMs revert to the
  default).
- The Win10 remaster is BIOS-only El Torito (fine for its Gen1 VM); the remaster pipeline
  may drop EFI entries — worth fixing in `New-PayloadIso`/setup remaster tooling later.

Remediation options (recorded, NOT executed):

- Host-side: `Restart-Service vmms` (elevated) plus a Windows Update check — component
  skew vmms 10.0.26100.8115 vs vmwp 10.0.26100.8457 on build 26100.9711.
- Lab-side: rebuild the setup ISOs keeping all boot-required content under 4 GiB
  (re-compressed/split WIM on a second medium referenced by unattend `InstallFrom`).

Retest after either.

## 2026-10-29: P1 fixed and smoke PASS; setup-media lessons; P2 status

Morning session 2026-10-29 (01:xx–11:3x local). Host stable throughout — no new System
1001/41; the crash baseline is still 2026-10-28 22:05:28 (1001) / 22:05:06 (41).

P1 root cause — two layers, both proven:

(a) Win7 IBS ignores `$OEM$` at the DVD root; it reads only `\Sources\$OEM$`
(`setupact.log`: "CopyOEMFolderToLocalSourcesFolder:$OEM$ folder does not exist under
[D:\Sources]"). The staged `SetupComplete.cmd` + `SdLabSmoke.xml` path therefore never
executed; what ran was the specialize `seed.cmd`, which registered the task via the
legacy CLI — that yields `DisallowStartIfOnBatteries=true` and `StartWhenAvailable=false`,
and the task never fired (TaskCache DynamicInfo showed no runs). Fix: `seed.cmd` now
registers the task from the ISO's `\sdlab-seed\SdLabSmoke.xml` via
`schtasks /create /xml`; the CLI create is kept only as a fallback.

(b) The 01:41 ISO rebuild had been built WITHOUT `-u2`: plain ISO9660 with 8.3 names
(`AUTOUN~1.XML`), no UDF view. Setup booted but could not discover `autounattend.xml` and
idled at the language screen — a 0%-CPU/static-disk signature masquerading as a hang,
exposed by a WMI guest thumbnail capture (`GetVirtualSystemThumbnailImage`, RGB565 with a
4-byte header, decoded host-side). Rebuilding with `-u2 -udfver102` (structure identical
to the working x64 ISO: ISO9660 stub + UDF 1.02 bridge; `autounattend.xml` byte-identical
at the UDF root) restored the full unattended install.

Win7 x86 result — P1 CLOSED:

Reinstall completed unattended in ~13 min (boot 10:44:30, done ~10:57:30; seed ran —
Administrator desktop with the sdlab icons). Base backup refreshed:
`D:\images\sd-win7-sp1-x86.vhdx` (5,641,338,880 B); `base` checkpoint 11:17:05;
`lab.psd1` restored to the `BaseVhdx` posture. SMOKE PASS: exit 0, transcript
`D:\sdlab\logs\sd-win7-sp1-x86-20261029-111921.log` with `SDLAB BEGIN` + 8 `SDLAB RESULT`
lines (all 0) + `SDLAB END`; `os=Windows 7 Professional SP1 x86 6.1.7601`.

IncludeTests run (protocol complete: BEGIN + 71 RESULTs + END, log
`D:\sdlab\logs\sd-win7-sp1-x86-20261029-112116.log`, overall exit 1):

- Exit 1 on BOTH flavours (x86-ia32, x86-sse2), 28 test binaries across: test-config,
  test-crypto, test-crypto_pk, test-crypto_pq, test-ipc, test-ssh, test-ssh_auth,
  test-ssh_transport, test-svc, test-update, test-webdav.
- `test-msi` exit 2 (x86-ia32 only; printed usage; absent from the sse2 run);
  `test-shellext` exit 3 (both); `test-vfs-bench` exit 77 (both; "skipped: set
  SD_IT_BENCH=1" — expected).
- Passing on both flavours: apps, base, dokan, e2e, engine, l10n, mount, platform,
  policy, secret, sftp, ssh_window, state, ui, update-fakeapp, vfs, webdav-redirector,
  zlib; plus cli-version / cli-help / host-version / host-selftest.
- OPEN for the repo: are the failures fresh-Win7-SP1 environment gaps (TLS 1.2, crypto
  providers, WebDAV client, …) or genuine x86 portability bugs? Needs maintainer triage,
  not lab work.

P2 status (the night section above stands as the diagnosis — host virtual-DVD reads fail
beyond 4 GiB; updates):

- The `vmms` restart at 01:22 (verified by fresh PID) did NOT fix it; the next host-side
  hope is a cumulative update.
- Gen1 workaround in progress: small boot ISO (<4 GiB) + `install.wim` on a data VHDX.
  Lessons: the wimdisk MUST be partitioned — a whole-disk NTFS "superfloppy" never gets a
  drive letter in WinPE, `InstallFrom` stays unresolvable and `WillShowUI=OnError` idles
  on a dialog (the first attempt died exactly there); and the staged VHDX must NOT carry
  the SparseFile attribute (Hyper-V 0xC03A001A; a dense copy via `Copy-Item` fixes it).
- The partitioned-wimdisk + `subst W:` retry (03:48) still stalled at the same 36 MiB
  pre-partition plateau — now suspected to be ANOTHER waiting-for-input dialog, not a
  hang; screen-capture diagnosis pending (standard procedure now: WMI thumbnail on any
  0%-CPU stall).
- Win10/Win11/Server installs therefore still open.

Process notes:

- Orchestrator-side 60 s watchdog (exit on HEARTBEAT_OK / STALL / SHUTDOWN) + WMI
  thumbnail captures are now the standard stall diagnostics; subagents act-and-return
  with short windows.
- oscdimg lesson: setup media must always be built `-u2 -udfver102` — 8.3-only builds
  silently break `autounattend` discovery.

Correction (same day): screen-diagnosis of the Win10 stall — at "Setup is starting" the
dialog reads "Windows cannot read the <ProductKey> setting from the unattend answer file.",
i.e. the autounattend WAS found and parsed (the -u2 ISO is fine) and setup died validating
UserData/ProductKey in WinPE, before any disk work. This weakens the night section's Gen1
inference for Win10 (the big-ISO stalls most likely showed this same dialog — same answer
file); the host >4 GiB DVD-read defect stands independently (Gen2 18603 on original media,
byte-mapped read failures, scratch-VM reproduction). Win10 fix chain in progress
(ProductKey node removal/generic key + `-u2` rebuild + partitioned wimdisk), results next.

## 2026-10-29 (afternoon): Win10 LTSC installed via split media — P2 Gen1 CLOSED

Afternoon session 2026-10-29 (11:5x–17:2x local). Host stable throughout — no new System
1001/41 (checked 17:16:48 and again after all runs); the crash baseline remains
2026-10-28 22:05:28 (1001) / 22:05:06 (41).

Win10 stall root cause — the ProductKey dialog, two layers, both fixed:

(a) Schema element-order violation: the split-media `autounattend.xml` had `RunSynchronous`
sitting BEFORE `ImageInstall` inside `Microsoft-Windows-Setup`. Removing the (invalid)
`ProductKey` node alone did NOT clear the dialog — a rebuild with the node provably gone
from the ISO (UDF-view hash match) still stalled at the same 36 MiB plateau with the same
"Windows cannot read the <ProductKey> setting" dialog (WMI thumbnail). Restoring schema
order — `DiskConfiguration`, `ImageInstall`, `RunSynchronous`, `UserData` — was the decisive
fix.

(b) Belt-and-braces: the generic KMS client key for Windows 10 IoT Enterprise LTSC 2021
(`QPM6N-7J2WJ-P88HH-P3YRH-YY74H`) added under `UserData/ProductKey`, so the node validates
silently instead of being absent.

Result — full unattended install via split media (small boot ISO + partitioned NTFS wimdisk
on IDE 0:1, `InstallFrom W:\sources\install.wim` via `RunSynchronous` subst):

- Boot ISO rebuilt 16:47:43 (909,799,424 B, `-u2 -udfver102`, BIOS+EFI El Torito); booted
  once 16:49:31 and never stalled — past the 37,748,736 B plateau in minute 1, OS up at
  +9.3 min, desktop ~+20 min (WMI thumbnail: Explorer + Edge first-run). Disk settled at
  8,829,009,920 B. Guest reported `os=Microsoft Windows 10 IoT Enterprise LTSC,
  os_version=10.0.19044`.
- Graceful stop; base backup `D:\images\sd-win10-ltsc21-x64.vhdx` (8,829,009,920 B, dense);
  `base` checkpoint 17:15:34; `lab.psd1` restored (`BaseVhdx` set, `InstallIso` cleared).
- SMOKE PASS: exit 0, `D:\sdlab\logs\sd-win10-ltsc21-x64-20261029-171632.log` — `SDLAB
  BEGIN` + 12 `SDLAB RESULT` (all 0: cli-version/cli-help/host-version/host-selftest
  across x86-sse2 + x64-xp + x64-modern) + `SDLAB END`; `cpu=AMD Ryzen 7 2700X`.
- IncludeTests (protocol complete: BEGIN + 106 RESULTs + END, log
  `D:\sdlab\logs\sd-win10-ltsc21-x64-20261029-172216.log`): 40 nonzero results. Failing on
  ALL three flavours (13 binaries): config, crypto, crypto_pk, crypto_pq, ipc, shellext
  (exit 3), ssh, ssh_auth, ssh_transport, svc, update, vfs-bench (77; `SD_IT_BENCH` skip),
  webdav; `test-msi` exit 2 (usage) on x64-modern only, absent from the others. Passing:
  apps, base, dokan, e2e, engine, l10n, mount, platform, policy, secret, sftp, ssh_window,
  state, ui, update-fakeapp, vfs, webdav-redirector, zlib + the four cli/host selftests —
  the same pattern as the Win7 fresh-base runs. Same OPEN question: fresh-base environment
  gaps vs genuine bugs — maintainer triage, not lab work.

Notes for the record:

- The WinPE COM1 drive report (`subst W:` diagnostics) never printed on Win10 even though
  the subst demonstrably worked (the boot ISO carries no `install.wim`, so setup could only
  have applied the image from the wimdisk). Diagnostics-only miss; the payload runner's
  COM1 output works fine. Worth a look someday.
- Split-media posture is dismantled for daily use: `lab.psd1` points at the base backup and
  the wimdisk is only needed for future reinstalls (dense `D:\sdlab\staging\sd-win10-wimdisk.vhdx`
  + its AVHDX remain attached to the VM's IDE 0:1 chain; the sparse `.sparse.bak` copy was
  deleted after the install was verified).
- P2 residual: the host virtual-DVD read failure beyond 4 GiB stands for Gen2 (Win11 and
  Server 2022 still can't boot their media — 18603 before any code runs). Options unchanged:
  host cumulative update, or replicate the split-media approach (small boot ISO + wimdisk +
  `InstallFrom`) for Win11/Server.
- New-LabVM.ps1 still does not set AutomaticStartAction; it was set manually on the
  recreated VM.

## 2026-10-30: first live run — M5 global Dokany mount on Win10 LTSC (attempt 13)

Attempt 13, log `D:\sdlab\logs\m5-20261030-233947.log` (2026-10-30, 23:39 local). Guest `sd-win10-ltsc21-x64`
(Windows 10 IoT Enterprise LTSC 2021, build 19044, generation 1), now on the NVMe SSD (`C:\sdlab-vms`) — boots
in about 1 min instead of about 8. Payload: x64-modern Release built from this branch with the svc_scm fix
`58d6b68` (the banner reports b413bf0), Dokany 2.1 (`dokan2` RUNNING). Machine profile `global10.ini`:
`scope = service`, `backend = dokany`, `letter = Z`, `label = GlobalDokan`, `autostart = boot`,
`service_access = sduser1, sduser2`, `service_access_write = sduser1`; fixture sshd at `[172.20.128.1]:2222`.
The harness lives in `D:\sdlab\m5` (host-only, not in the repo). Phases: A (install, batch logons), B1/B2
(reboot + console logon, B2 with a concurrent batch session), final (G7 mutation, G3, uninstall). Results per
acceptance item, step names as the run log prints them:

- Service install/start as SYSTEM: OK — `service-install-start OK ShellDriveSvc RUNNING`. Before `58d6b68` (the
  service is opened with SERVICE_START so its restart actions can be set) every install rolled back with
  ACCESS_DENIED surfaced as "needs an elevated console", exit 9.
- Machine profile load and machine host key add (`--from-server --expect`): OK — the service log shows
  `service starting; 1 machine profiles`; `hostkey-add OK [172.20.128.1]:2222 ssh-ed25519 …`.
- Global Dokany mount Z: — `service status` (admin) answers `Z:  GlobalDokan  mounted`; Event 1100 `Global drive
  for profile 9e1a0c5d3b7f4e2a8c6d1f0b2a4c6e81 is mounted at Z:.`.
- G1, batch logon of `sduser1` (standard, not elevated): `dir Z:` rc=0 with no mount command run ("Volume in
  drive Z is GlobalDokan"); write, rename and delete all rc=0; one Event 1200 audit entry per change carrying
  the user SID: `… by SD-10-X64\sduser1 (SID S-1-5-21-159632063-432193879-889666275-1002): write_open \big.bin.`.
- G5, 1 GiB through Z:: write 74.6 s, read 17.6 s, `hash_match=True` (attempt 13's own values; attempt 12,
  `m5-20261030-230247.log`, measured 79.9 s / 17.7 s).
- G7, read-only member: `sduser2`'s write is denied (`write_rc=1 (want nonzero) [cmd : Access is denied. …]`) and
  it cannot read `sduser1`'s file. G7 mutation: profile edited to drop `sduser2`, service restart to reload —
  `g7-u2-denied OK` (`dir Z:` now `Access is denied.`) and `g7-u1-still-ok OK`; profile restored, remount rc=0.
- Console logons: B1 — the `sduser1` console session sees Z: (`dirZ_rc=0`). B2 — the `sduser2` console session
  plus a concurrent `sduser1` batch session (two live sessions) both see and use Z:, 1 GiB round trip OK
  (write 69.7 s, read 18 s, hash match).
- G3: service stop removes Z: cleanly (`dirZ-after-stop=[The system cannot find the path specified.]`), start +
  remount OK; VM save/resume (sleep proxy) keeps the mount.
- Uninstall: `uninstall OK … ShellDrive service removed.`; `sc query` answers 1060 (no such service) and Z: is
  gone (`dirZ-after-uninstall=[The system cannot find the path specified.]`).
- Expected by design: SYSTEM itself gets Access denied on Z: (it is not in `service_access`) — the run log marks
  this probe `service-mount FAIL Z: not readable: Access is denied.`.

Defects and gaps found by the run are listed under the M5 "Left" items of `docs/dev/m5-notes.md` (Part 14 §5):
the service does not apply `autostart = boot`, a standard user's `shelldrive service list` exits 8 while the
service runs, `service mount` for an unknown profile prints an empty name placeholder, `scm_error` maps every
ACCESS_DENIED to "needs an elevated console", and Get-Volume does not list the Dokany Z: (`dir`/Explorer work).
Not covered: RDP/FUS second interactive session (G2 proper), Server 2022 + Secure Boot (the Gen2 media problem
of the 2026-10-29 night section), pre-logon mount at boot (blocked by the `autostart` gap).

## Appendix: procedure for the live global Dokany mount (M5; first run 2026-10-30, see above)

Written 2026-10-30 while `sd-win10-ltsc21-x64` was still held by the M3 acceptance run; executed the same day
(attempt 13, results in the 2026-10-30 section above, which supersedes this appendix wherever they differ —
step 8's pre-logon mount is exactly the `autostart = boot` gap recorded there). The sequence is kept as written
for future runs. It closes the "a real global mount seen by a second session" item of `docs/dev/m5-notes.md`
(M5 rows 2 and "Left") and the M5 demo (a) of `docs/design/00-integration-review.md` §6 for Windows 10 (Server 2022
needs a Gen2 guest, still blocked by the host DVD defect of this file's 2026-10-29 night section; Gen1 validates the
code but not Secure Boot).

Preconditions

- `sd-win10-ltsc21-x64` restored to its `base` checkpoint (`Invoke-SdLab.ps1` restores before a run). Two local
  accounts exist: `sduser1` and `sduser2` (create them with `net user ... /add` inside the guest if the base lacks
  them; both standard users, distinct passwords).
- The payload ISO of the build under test is attached (`Invoke-SdLab.ps1` convention: IDE 1:0).
- Dokany 2.1+ is installed in the base (the payload installs it). `sc query dokan2` in the guest reports RUNNING.
- A test service profile. Write `%ProgramData%\LibreStatic\ShellDrive\profiles\global10.ini` on the guest:
  `scope = service`, `user = svc`, `backend = dokany`, one `service_access` entry per account
  (`service_access = sduser1, sduser2` — resolved to SIDs by the service), `service_access_write` optional,
  `letter = Z`, `autostart = boot`, and a `[host]` that reaches the WSL sshd fixture (host-side port forwarded into
  the guest, as the M0 smoke runs already do).
- Elevation for the service install and for the two `net user` calls; the mount and the check itself are unelevated.

Steps

1. Install the payload from the ISO (`D:\sdlab\staging\sd-win10-wimdisk.vhdx` style staging is not needed; the
   payload ISO installs over the base). Record `sc query ShellDriveSvc`: STOPPED before the profile exists.
2. Start the service (`sc start ShellDriveSvc`) and read the Application log for Event 1000/1001 (started) and the
   mount events. Expect Event 1001 with the profile count.
3. Confirm the drive at the service side: `shelldrive list --machine` as an elevated administrator shows `Z:` with
   state `mounted`; as a non-admin in `service_access` it shows the letter and label but no host/user.
4. Log on as `sduser1` (console). In `cmd`: `dir Z:\` must list the remote directory with no prompt and no
   elevation. In Explorer, `Z:` shows the label. Record `whoami`.
5. Fast user switch to `sduser2`. Same check. The drive must already be there (G1), and the server (the WSL sshd
   fixture's log) must show **two different remote sessions** for the same service identity — that is the expected
   result: the remote identity is shared (T-43), the local access control is `service_access` (G7).
6. Negative access (G7): from `sduser2`, remove `sduser2` from `service_access` in the profile and run
   `shelldrive config reload --machine` (elevated). Within 60 s `dir Z:\` must fail with access denied; the audit
   Event 1200 names the SID of each mutating operation before the change.
7. Write test: create, rename and delete one file as `sduser1` through `Z:` (with `service_access_write` naming
   `sduser1` only, `sduser2` must get access denied on the write).
8. Reboot the guest. After the boot, before any interactive logon, the service must have mounted `Z:` (Event 1001 +
   the mount events). Verify at the first logon that the letter is present and usable without user action.
9. Uninstall check: `sc stop ShellDriveSvc` then `sc delete`; confirm no orphaned drive letter remains in either
   session (the Dokany volume disappears with the service).
10. Collect: `%ProgramData%\LibreStatic\ShellDrive\logs\*` and the Application log export, and append a result
    section to this file (per-OS table: G1/G2/G5/G7 pass/fail, the two remote session identities seen by sshd).

What would fail the acceptance: the drive absent before logon, a mount that only appears after a user runs
`shelldrive mount`, a `dir Z:` prompt or 403 for a `service_access` member, data visible to a removed member after
the 60 s window, or writes accepted from a member outside `service_access_write`.
