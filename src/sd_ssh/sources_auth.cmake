# sd_ssh sources of the M2 `auth` area (01 §6): key files, certificates, DPAPI-kept keys, agents.
# keyfile_*.c stay free of transport dependencies (the CLI and UI link only them, 00 §5).
list(APPEND SD_SSH_SOURCES
  keyfile.c
  keyfile_cert.c
  keyfile_der.c
  keyfile_dpapi.c
  keyfile_pem.c
  keyfile_ppk.c
  keyfile_sign.c
  auth_cfg.c)
list(APPEND SD_SSH_PRIVATE_HEADERS_AUTH keyfile_internal.h)
list(APPEND SD_SSH_SOURCES
  agent.c
  agent_pageant.c
  agent_pipe.c)
list(APPEND SD_SSH_SOURCES_HEADERS include/sd_ssh/sd_agent.h)
