# sd_ssh (01 §3-§9). Owned by the SSH agent. Keep keyfile_*.c and known_hosts*.c free of transport
# dependencies: the CLI and UI link only those translation units (00 §5).

sd_add_module(sd_ssh
  DEPS
    sd_crypto
    sd_base
    sd_platform
  SYSTEM_LIBS
    ws2_32
  HEADERS
    include/sd_ssh/sd_keyfile.h
    include/sd_ssh/sd_known_hosts.h
    include/sd_ssh/sd_prompt.h
    include/sd_ssh/sd_ssh.h)
