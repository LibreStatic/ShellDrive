# sd_sftp (01 §10-§11). Owned by the SFTP agent.
# sftp_ssh.c is the only translation unit that calls into sd_ssh (production transport); tests that
# use sd_sftp_session_create_transport() never pull it in.

sd_add_module(sd_sftp
  SOURCES
    sftp_proto.c
    sftp_session.c
    sftp_sync.c
    sftp_ssh.c
  DEPS
    sd_ssh
    sd_base
    sd_platform
  HEADERS
    include/sd_sftp/sd_sftp.h
    include/sd_sftp/sd_sftp_transport.h
  PRIVATE_HEADERS
    sftp_proto.h
    sftp_internal.h)
