/* Private declarations of the agent clients (agent.c, agent_pageant.c, agent_pipe.c; 01 §6.5). */
#ifndef SD_SSH_AGENT_INTERNAL_H
#define SD_SSH_AGENT_INTERNAL_H

#include <windows.h>

#include "sd/base.h"
#include "sd_base/sd_err.h"
#include "sd_ssh/sd_agent.h"

enum {
  SSH_AGENT_FAILURE = 5, SSH_AGENTC_REQUEST_IDENTITIES = 11, SSH_AGENT_IDENTITIES_ANSWER = 12,
  SSH_AGENTC_SIGN_REQUEST = 13, SSH_AGENT_SIGN_RESPONSE = 14
};

/* One request/response exchange. req is the message body (type byte first, no length prefix); *resp
   (sd_alloc'ed) is the reply body. SD_E_NOT_FOUND: agent not running; SD_E_ACCESS_DENIED: the
   authenticity check failed (TM-R08); SD_E_TIMEOUT; SD_E_PROTOCOL: malformed or oversized reply. */
sd_err ssh_pageant_transact(const uint8_t *req, size_t n, uint8_t **resp, size_t *resp_len);
sd_err ssh_pageant_probe(void);
/* Unit-test seam only (tests/unit/sd_ssh): the window class and title the Pageant client looks for. NULL
   restores the protocol name "Pageant". Nothing in the product calls it. Pageant's name is a machine-global
   FindWindow key, so a test fake must use its own unique name. */
void ssh_pageant_test_set_window_name(const wchar_t *name);
sd_err ssh_agent_pipe_transact(const uint8_t *req, size_t n, uint8_t **resp, size_t *resp_len);
sd_err ssh_agent_pipe_probe(void);

/* Token helpers (agent_pageant.c): our process token's user SID (sd_alloc'ed copy), and the
   integrity RID of a token (Vista+; 0 when unavailable). */
sd_err   ssh_agent_self_sid(PSID *out);
uint32_t ssh_agent_token_integrity(HANDLE token);
/* Token user SID of process pid (sd_alloc'ed copy) and its integrity RID. */
sd_err   ssh_agent_process_sid(DWORD pid, PSID *out, uint32_t *integrity);
/* Logs "agent_untrusted" once per process and kind. */
void     ssh_agent_warn_untrusted(uint32_t kind, PSID found);

/* 1 when the process runs as LocalSystem (no agents there, D17). */
int ssh_agent_in_service_context(void);

#endif /* SD_SSH_AGENT_INTERNAL_H */
