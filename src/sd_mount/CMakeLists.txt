# sd_mount (03 §1.11: profile -> session -> vfs -> backend; host only). Placeholder so the host agent
# can add it without touching the top-level CMakeLists.txt. Add SOURCES and HEADERS here.

sd_add_module(sd_mount
  DEPS
    sd_dokan
    sd_vfs
    sd_sftp
    sd_ssh
    sd_ipc
    sd_config
    sd_l10n
    sd_base
    sd_platform)
