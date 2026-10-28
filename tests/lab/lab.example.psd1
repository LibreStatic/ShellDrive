# ShellDrive test lab configuration (04 section 11.4). Copy to lab.psd1 (git-ignored by name is not
# needed: keep it outside the repo, e.g. D:\sdlab\lab.psd1) and pass it with -Config.
#
# Nothing here is downloaded. Every image path points to media YOU provide (licensed Windows images);
# see docs/dev/m1-notes.md "Lab harness" for the exact list.
@{
  # Working folder for differencing disks, payload ISOs and serial logs. Needs ~5 GB per VM.
  LabRoot    = 'D:\sdlab'

  # Optional Hyper-V virtual switch for the VMs. Empty = no network adapter (the smoke run needs none).
  # XP has no synthetic NIC driver: a legacy (emulated DEC 21140) adapter is added instead.
  SwitchName = ''

  # Hyper-V VMs. All are generation 1 (BIOS): XP and 7 x86 cannot boot UEFI.
  #   BaseVhdx   an installed, shut-down system disk; the lab never writes to it (a differencing disk
  #              is created on top). Leave empty to install from InstallIso into a new 20 GB disk.
  #   InstallIso Windows setup ISO, used only when BaseVhdx is empty.
  #   Generation 1 (default, BIOS: XP and 7 x86) or 2 (UEFI: Windows 11 needs it, Server 2022
  #              wants Secure Boot). Generation 2 always enables Secure Boot (MicrosoftWindows
  #              template); Tpm = $true adds a virtual TPM (Windows 11).
  #   Flavours   build flavours copied to the payload ISO for this VM.
  #   ExpectSse2 $true if the (virtual) CPU has SSE2: then x86-sse2 must start; if $false it must refuse.
  VMs = @(
    @{
      Name = 'sd-xp-sp3-x86'; MemoryMB = 512; Cpus = 1
      BaseVhdx = 'D:\images\xp-pro-sp3-x86.vhdx'; InstallIso = ''
      Flavours = @('x86-ia32', 'x86-sse2'); ExpectSse2 = $true
    },
    @{
      Name = 'sd-win7-sp1-x86'; MemoryMB = 1024; Cpus = 1
      BaseVhdx = 'D:\images\win7-sp1-x86.vhdx'; InstallIso = ''
      Flavours = @('x86-ia32', 'x86-sse2'); ExpectSse2 = $true
    },
    @{
      Name = 'sd-win7-sp1-x64'; MemoryMB = 2048; Cpus = 2
      BaseVhdx = 'D:\images\win7-sp1-x64.vhdx'; InstallIso = ''
      Flavours = @('x64-xp', 'x86-ia32', 'x86-sse2'); ExpectSse2 = $true
    }
  )

  # QEMU VM without SSE2 (qemu-system-i386 -cpu pentium3, TCG). Disk = qcow2 with XP SP3 x86 installed
  # under QEMU (see tests/lab/qemu/Start-QemuPentium3.ps1). Runs with -snapshot, so it is never modified.
  Qemu = @{
    Name = 'sd-p3-xp'; MemoryMB = 512
    Disk = 'D:\images\xp-pro-sp3-x86-p3.qcow2'
    QemuDir = 'C:\Program Files\qemu'
    Flavours = @('x86-ia32', 'x86-sse2'); ExpectSse2 = $false
  }
}
