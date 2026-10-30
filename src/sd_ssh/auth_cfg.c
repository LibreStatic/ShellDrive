/* Authentication configuration of one hop (01 §6.2, §9): validation and deep copies of identities,
 * agents and identities_only. Called by ssh_hop_init (conn.c). */
#include <windows.h>
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_base/sd_utf.h"
#include "agent_internal.h"
#include "conn_internal.h"

#define AUTH_MAX_IDENTITIES 64u

sd_err ssh_auth_cfg_check(const sd_ssh_auth_cfg *a)
{
  uint32_t i;
  if (a->identity_count && !a->identities) return SD_E_INVALID_PARAM;
  if (a->identity_count > AUTH_MAX_IDENTITIES) return SD_E_INVALID_PARAM;
  if (a->agents & ~(uint32_t)(SD_AGENT_PAGEANT | SD_AGENT_OPENSSH)) return SD_E_INVALID_PARAM;
  if (a->agents && ssh_agent_in_service_context()) return SD_E_UNSUPPORTED;   /* D17 */
  for (i = 0; i < a->identity_count; i++) {
    const sd_ssh_identity *id = &a->identities[i];
    if (id->kind == SD_ID_FILE && (!id->path || !id->path[0])) return SD_E_INVALID_PARAM;
    if (id->kind == SD_ID_BLOB && (!id->blob || !id->blob_len)) return SD_E_INVALID_PARAM;
    if (id->kind == SD_ID_AGENT_KEY) {
      if (!id->agent_fingerprint || strncmp(id->agent_fingerprint, "SHA256:", 7) != 0 ||
          strlen(id->agent_fingerprint) >= 64)
        return SD_E_INVALID_PARAM;
      if (!a->agents) return SD_E_INVALID_PARAM;
    }
    if (id->kind != SD_ID_FILE && id->kind != SD_ID_BLOB && id->kind != SD_ID_AGENT_KEY) return SD_E_INVALID_PARAM;
    if (id->cert_blob && !id->cert_blob_len) return SD_E_INVALID_PARAM;
  }
  return SD_OK;
}

static wchar_t *dup_w(const wchar_t *s)
{
  size_t n = wcslen(s);
  wchar_t *d = (wchar_t *)sd_alloc((n + 1) * sizeof(wchar_t));
  if (d) memcpy(d, s, (n + 1) * sizeof(wchar_t));
  return d;
}

static char *dup_s(const char *s)
{
  size_t n = strlen(s);
  char *d = (char *)sd_alloc(n + 1);
  if (d) memcpy(d, s, n + 1);
  return d;
}

sd_err ssh_auth_cfg_copy(sd_ssh_conn *c, const sd_ssh_auth_cfg *a)
{
  uint32_t i;
  sd_err e;
  c->agents = a->agents;
  c->identities_only = a->identities_only != 0;
  if (!a->identity_count) return SD_OK;
  c->ids = (ssh_ident *)sd_calloc(a->identity_count, sizeof(ssh_ident));
  if (!c->ids) return SD_E_NO_MEMORY;
  for (i = 0; i < a->identity_count; i++) {
    const sd_ssh_identity *id = &a->identities[i];
    ssh_ident *d = &c->ids[i];
    c->id_count = i + 1;
    d->kind = id->kind;
    if (id->kind == SD_ID_FILE) {
      d->path = dup_w(id->path);
      if (!d->path || sd_wide_to_utf8_alloc(id->path, (size_t)-1, SD_UTF_REPLACE, &d->path_utf8) != SD_OK)
        return SD_E_NO_MEMORY;
    } else if (id->kind == SD_ID_BLOB) {
      e = sd_secbuf_from(id->blob, id->blob_len, &d->blob);
      if (e != SD_OK) { d->blob = NULL; return e; }
      d->label = dup_s(id->label ? id->label : "");
      if (!d->label) return SD_E_NO_MEMORY;
    } else {
      memcpy(d->agent_fp, id->agent_fingerprint, strlen(id->agent_fingerprint) + 1);
    }
    if (id->cert_path && id->cert_path[0]) {
      d->cert_path = dup_w(id->cert_path);
      if (!d->cert_path) return SD_E_NO_MEMORY;
    }
    if (id->cert_blob) {
      d->cert_blob = (uint8_t *)sd_alloc(id->cert_blob_len);
      if (!d->cert_blob) return SD_E_NO_MEMORY;
      memcpy(d->cert_blob, id->cert_blob, id->cert_blob_len);
      d->cert_len = id->cert_blob_len;
    }
  }
  return SD_OK;
}

void ssh_auth_cfg_free(sd_ssh_conn *c)
{
  uint32_t i;
  for (i = 0; i < c->id_count; i++) {
    sd_free(c->ids[i].path);
    sd_free(c->ids[i].path_utf8);
    sd_secbuf_free(c->ids[i].blob);
    sd_free(c->ids[i].label);
    sd_free(c->ids[i].cert_path);
    sd_free(c->ids[i].cert_blob);
  }
  sd_free(c->ids);
  c->ids = NULL;
  c->id_count = 0;
}
