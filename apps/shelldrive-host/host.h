/* shelldrive-host internals shared by main.c, agent.c and the backend selection unit. */
#ifndef SD_HOST_H
#define SD_HOST_H

#include <windows.h>

#include "sd_mount/sd_mount.h"

/* Mount backend of this binary: real modules, "unavailable", or a test fake (tests/apps). */
const sd_mount_backend *host_backend(void);

typedef struct host_agent_opts {
  int logon;              /* started by the Run key: stay resident */
  uint32_t idle_exit_ms;  /* on-demand agents exit after this long without mounts/clients */
} host_agent_opts;

/* Runs the agent until shutdown; returns the process exit code. */
int host_agent_run(const host_agent_opts *opts);

#endif /* SD_HOST_H */
