/* SSH agent protocol (draft-miller-ssh-agent; 01 §6.5) over the Pageant and OpenSSH-pipe transports.
 * Replies are capped at SD_AGENT_MAX_REPLY and parsed with the bounded reader. Keys of types we do not
 * know (e.g. sk-ssh-ed25519@openssh.com) are listed as opaque blobs. */
#include <windows.h>
#include <sddl.h>
#include <string.h>

#include "sd_base/sd_buf.h"
#include "sd_base/sd_mem.h"
#include "sd_base/sd_utf.h"
#include "sd_platform/sd_log.h"
#include "sd_ssh/sd_known_hosts.h"
#include "sd_ssh/sd_ssh.h"
#include "agent_internal.h"
#include "ssh_internal.h"

#define AGENT_MAX_IDS 1024u

int ssh_agent_in_service_context(void)
{
  PSID me = NULL, sys = NULL;
  SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
  int r = 0;
  if (ssh_agent_self_sid(&me) != SD_OK) return 0;
  if (AllocateAndInitializeSid(&nt, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &sys)) {
    r = EqualSid(me, sys) ? 1 : 0;
    FreeSid(sys);
  }
  sd_free(me);
  return r;
}

void ssh_agent_warn_untrusted(uint32_t kind, PSID found)
{
  static volatile LONG warned[3];
  wchar_t *s = NULL;
  uint32_t i = kind == SD_AGENT_PAGEANT ? 1u : 2u;
  if (InterlockedExchange(&warned[i], 1) != 0) return;
  if (found && ConvertSidToStringSidW(found, &s)) {
    SD_LOGW("ssh", "agent_untrusted agent=%s owner=%ls", kind == SD_AGENT_PAGEANT ? "pageant" : "openssh", s);
    LocalFree(s);
  } else {
    SD_LOGW("ssh", "agent_untrusted agent=%s owner=unknown", kind == SD_AGENT_PAGEANT ? "pageant" : "openssh");
  }
}

static sd_err transact(uint32_t agent, const uint8_t *req, size_t n, uint8_t **resp, size_t *resp_len)
{
  if (agent == SD_AGENT_PAGEANT) return ssh_pageant_transact(req, n, resp, resp_len);
  if (agent == SD_AGENT_OPENSSH) return ssh_agent_pipe_transact(req, n, resp, resp_len);
  return SD_E_INVALID_PARAM;
}

sd_err sd_agent_probe(uint32_t agent)
{
  if (ssh_agent_in_service_context()) return SD_E_UNSUPPORTED;   /* D17 */
  if (agent == SD_AGENT_PAGEANT) return ssh_pageant_probe();
  if (agent == SD_AGENT_OPENSSH) return ssh_agent_pipe_probe();
  return SD_E_INVALID_PARAM;
}

void sd_agent_list_free(sd_agent_list *l)
{
  uint32_t i;
  if (!l) return;
  for (i = 0; i < l->count; i++) sd_free(l->ids[i].blob);
  sd_free(l->ids);
  sd_free(l);
}

sd_err sd_agent_list_identities(uint32_t agent, sd_agent_list **out)
{
  uint8_t req = SSH_AGENTC_REQUEST_IDENTITIES;
  uint8_t *resp = NULL;
  size_t rl = 0;
  sd_rd r;
  uint32_t n, i;
  sd_agent_list *l;
  sd_err e;
  if (!out) return SD_E_INVALID_PARAM;
  *out = NULL;
  if (ssh_agent_in_service_context()) return SD_E_UNSUPPORTED;
  e = transact(agent, &req, 1, &resp, &rl);
  if (e != SD_OK) return e;
  sd_rd_init(&r, resp, rl);
  if (sd_rd_u8(&r) != SSH_AGENT_IDENTITIES_ANSWER) { sd_free(resp); return SD_E_PROTOCOL; }
  n = sd_rd_u32(&r);
  if (!sd_rd_ok(&r) || n > rl / 8) { sd_free(resp); return SD_E_PROTOCOL; }
  l = (sd_agent_list *)sd_calloc(1, sizeof(*l));
  if (!l) { sd_free(resp); return SD_E_NO_MEMORY; }
  if (n) {
    l->ids = (sd_agent_identity *)sd_calloc(SD_MIN(n, AGENT_MAX_IDS), sizeof(sd_agent_identity));
    if (!l->ids) { sd_free(l); sd_free(resp); return SD_E_NO_MEMORY; }
  }
  for (i = 0; i < n; i++) {
    sd_span blob = sd_rd_string(&r, 16384), comment = sd_rd_string(&r, 4096);
    sd_span t;
    sd_agent_identity *id;
    size_t ol = 0;
    if (!sd_rd_ok(&r)) { sd_agent_list_free(l); sd_free(resp); return SD_E_PROTOCOL; }
    t = ssh_blob_key_type(blob.p, blob.n);
    if (!t.n || l->count >= AGENT_MAX_IDS) continue;
    id = &l->ids[l->count];
    id->agent = agent;
    id->blob = (uint8_t *)sd_alloc(blob.n);
    if (!id->blob) { sd_agent_list_free(l); sd_free(resp); return SD_E_NO_MEMORY; }
    memcpy(id->blob, blob.p, blob.n);
    id->blob_len = blob.n;
    if (!ssh_span_copy(t, id->type, sizeof(id->type))) id->type[0] = '\0';
    if (sd_text_sanitize_server((const char *)comment.p, SD_MIN(comment.n, (size_t)80), id->comment,
                                sizeof(id->comment) - 1, &ol) != SD_OK)
      ol = 0;
    id->comment[ol] = '\0';
    if (sd_hostkey_fingerprint_sha256(blob.p, blob.n, id->fp_sha256) != SD_OK) id->fp_sha256[0] = '\0';
    l->count++;
  }
  sd_free(resp);
  if (!sd_rd_done(&r)) { sd_agent_list_free(l); return SD_E_PROTOCOL; }
  *out = l;
  return SD_OK;
}

sd_err sd_agent_sign(uint32_t agent, const uint8_t *blob, size_t blob_len, const uint8_t *data, size_t data_len,
                     uint32_t flags, uint8_t **sig, size_t *sig_len)
{
  sd_wr w;
  uint8_t *resp = NULL;
  size_t rl = 0;
  sd_rd r;
  uint8_t type;
  sd_span s;
  sd_err e;
  if (!blob || !blob_len || (!data && data_len) || !sig || !sig_len) return SD_E_INVALID_PARAM;
  *sig = NULL;
  *sig_len = 0;
  if (ssh_agent_in_service_context()) return SD_E_UNSUPPORTED;
  sd_wr_init(&w, 64 * 1024);
  sd_wr_u8(&w, SSH_AGENTC_SIGN_REQUEST);
  sd_wr_string(&w, blob, blob_len);
  sd_wr_string(&w, data, data_len);
  sd_wr_u32(&w, flags);
  if (!sd_wr_ok(&w)) { sd_wr_free(&w); return SD_E_INVALID_PARAM; }
  e = transact(agent, w.p, w.len, &resp, &rl);
  sd_wr_free(&w);
  if (e != SD_OK) return e;
  sd_rd_init(&r, resp, rl);
  type = sd_rd_u8(&r);
  if (sd_rd_ok(&r) && type == SSH_AGENT_FAILURE) { sd_free(resp); return SD_E_AUTH_FAILED; }
  s = sd_rd_string(&r, 16384);
  if (type != SSH_AGENT_SIGN_RESPONSE || !sd_rd_done(&r) || !ssh_blob_key_type(s.p, s.n).n) {
    sd_free(resp);
    return SD_E_PROTOCOL;
  }
  *sig = (uint8_t *)sd_alloc(s.n);
  if (!*sig) { sd_free(resp); return SD_E_NO_MEMORY; }
  memcpy(*sig, s.p, s.n);
  *sig_len = s.n;
  sd_free(resp);
  return SD_OK;
}
