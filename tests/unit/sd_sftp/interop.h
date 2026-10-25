/* Shared state of the interop test binary. */
#ifndef SFTP_INTEROP_H
#define SFTP_INTEROP_H

#include "sftp_test_tp.h"
#include "test_util.h"

#define SFTP_SERVER   "/usr/lib/openssh/sftp-server"
#define SFTP_SERVER_W L"/usr/lib/openssh/sftp-server"

extern sd_sftp_session *g_s;
extern proc_tp *g_proc;
extern char g_dir[128];
extern evlog g_ev;

/* Runs `sh -c shell_cmd` in WSL; returns the exit code or -1. */
int interop_wsl(const char *shell_cmd, uint32_t timeout_ms);

#endif
