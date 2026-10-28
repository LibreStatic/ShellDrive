/* In-test fake SSH agents (pipe agent via SSH_AUTH_SOCK, Pageant window) for the auth tests. */
#ifndef SD_SSH_TEST_AGENT_H
#define SD_SSH_TEST_AGENT_H

#include <windows.h>

#include "sd_platform/sd_thread.h"
#include "sd_ssh/sd_keyfile.h"

#define TA_MAX_KEYS 8

typedef struct ta_agent {
  sd_ssh_key *keys[TA_MAX_KEYS];
  uint32_t nkeys;
  uint8_t cert[4096]; size_t cert_len;   /* optional certificate listed first (for keys[0]) */
  volatile LONG requests, list_requests, sign_requests;
  uint32_t last_flags;
  int refuse_sign;
} ta_agent;

/* Loads fixtures/keys/<name> (unencrypted) for each key. */
sd_err ta_agent_init(ta_agent *a, const char *const *keys, uint32_t n);
void   ta_agent_free(ta_agent *a);

typedef struct ta_pipe_agent {
  ta_agent agent;
  wchar_t name[128];
  sd_thread thread;
  HANDLE ready;
  volatile int stop;
} ta_pipe_agent;

/* Serves the agent on a fresh pipe and points SSH_AUTH_SOCK (process environment) at it. */
sd_err ta_pipe_start(ta_pipe_agent *pa);
void   ta_pipe_stop(ta_pipe_agent *pa);

typedef struct ta_pageant {
  ta_agent agent;
  sd_thread thread;
  HANDLE ready;
  HWND hwnd;
  DWORD tid;
  wchar_t name[64];   /* window class and title: unique per process (FindWindow is machine-global) */
} ta_pageant;

sd_err ta_pageant_start(ta_pageant *pg);
void   ta_pageant_stop(ta_pageant *pg);

#endif
