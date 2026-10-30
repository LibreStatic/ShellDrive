/* SSH agent clients (01 §6.5; draft-miller-ssh-agent): Pageant (WM_COPYDATA + named file mapping,
 * XP+) and the Windows OpenSSH agent (\\.\pipe\openssh-ssh-agent, or SSH_AUTH_SOCK naming a
 * \\.\pipe\ path; Windows 10+). Used by sd_ssh's publickey authentication and by the UI/CLI to list
 * agent keys (for SD_ID_AGENT_KEY selection by fingerprint).
 *
 * Authenticity (TM-R08): before the first request to an agent the client checks who serves it.
 * Pageant: the window's process token must carry our user SID and (Vista+) an integrity level >= ours.
 * OpenSSH pipe: the pipe owner and the server process user must be LocalSystem for the default pipe,
 * or our own SID for a pipe named by SSH_AUTH_SOCK. A failed check is SD_E_ACCESS_DENIED (logged once
 * per process and agent as "agent_untrusted") and no request is sent.
 *
 * No agent is used in the service context (decisions.md D17): sd_ssh rejects agents in a LocalSystem
 * process.
 *
 * Every call blocks (up to 120 s per request: agents may wait for user confirmation); never call them
 * on an I/O thread. Reentrant; no global state except the once-per-process warning flags. */
#ifndef SD_AGENT_H
#define SD_AGENT_H

#include "sd/base.h"
#include "sd_base/sd_err.h"

/* Agent kinds are the SD_AGENT_* bits of sd_ssh.h: SD_AGENT_PAGEANT (1), SD_AGENT_OPENSSH (2). */

enum { SD_AGENT_SIGN_RSA_SHA2_256 = 2u, SD_AGENT_SIGN_RSA_SHA2_512 = 4u };

#define SD_AGENT_MAX_REPLY   (256u * 1024u)
#define SD_AGENT_TIMEOUT_MS  120000u

typedef struct sd_agent_identity {
  uint32_t agent;               /* SD_AGENT_PAGEANT or SD_AGENT_OPENSSH */
  uint8_t *blob; size_t blob_len;   /* public key or certificate blob, as the agent returned it */
  char type[64];                /* algorithm name of the blob (may be unknown to us, e.g. sk-*) */
  char comment[256];            /* sanitized, truncated */
  char fp_sha256[64];           /* "SHA256:..." of the blob */
} sd_agent_identity;

typedef struct sd_agent_list {
  sd_agent_identity *ids;
  uint32_t count;
} sd_agent_list;

/* SD_OK when the agent is present and passes the authenticity check; SD_E_NOT_FOUND when it is not
   running; SD_E_ACCESS_DENIED when the check fails; SD_E_UNSUPPORTED for SD_AGENT_OPENSSH before
   Windows 10 or in the service context. */
sd_err sd_agent_probe(uint32_t agent);

/* REQUEST_IDENTITIES. At most 1024 identities are kept. */
sd_err sd_agent_list_identities(uint32_t agent, sd_agent_list **out);
void   sd_agent_list_free(sd_agent_list *l);

/* SIGN_REQUEST with flags (SD_AGENT_SIGN_*). *sig (sd_alloc'ed, free with sd_free) is the SSH
   signature blob the agent returned. SD_E_AUTH_FAILED when the agent refuses (FAILURE). */
sd_err sd_agent_sign(uint32_t agent, const uint8_t *blob, size_t blob_len, const uint8_t *data,
                     size_t data_len, uint32_t flags, uint8_t **sig, size_t *sig_len);

#endif /* SD_AGENT_H */
