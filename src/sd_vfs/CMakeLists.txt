# sd_vfs (02 §1-§5, §8). Owned by the VFS agent (together with sd_dokan).

sd_add_module(sd_vfs
  DEPS
    sd_sftp
    sd_base
    sd_platform
  HEADERS
    include/sd_vfs/sd_vfs.h)
