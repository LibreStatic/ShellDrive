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
