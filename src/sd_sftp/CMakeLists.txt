# sd_sftp (01 §10-§11). Owned by the SFTP agent.

sd_add_module(sd_sftp
  DEPS
    sd_ssh
    sd_base
    sd_platform
  HEADERS
    include/sd_sftp/sd_sftp.h)
