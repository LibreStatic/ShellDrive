# sd_dokan (02 §6). Owned by the VFS agent. dokan2.dll is never linked: GetProcAddress only.

sd_add_module(sd_dokan
  DEPS
    sd_vfs
    sd_base
    sd_platform
  HEADERS
    include/sd_dokan/sd_dokan.h
  PRIVATE_HEADERS
    dokan_abi.h)
