/* Service access rules (see svc_access.h). Pure logic: no Win32 calls except string helpers. */
#include <windows.h>
#include <string.h>

#include "svc_access.h"

void svc_decide(const svc_member *m, svc_rights *out)
{
  int in_access = m && m->in_access;
  int in_write = m && m->in_write;
  int admin = m && m->admin_elevated;
  memset(out, 0, sizeof(*out));
  out->see_letter = 1;                       /* 2.2: the letter is visible to every session anyway */
  out->see_state = admin || in_access;       /* label and state: members of service_access and admins */
  out->see_details = admin;                  /* host, user, remote path, last error: elevated admins only */
  out->use = in_access;                      /* D35: no implicit default, nobody outside the list uses the drive */
  /* 03 §3.4.1: BUILTIN\Administrators always gets write (elevated, and in the list), others only when listed */
  out->write = in_access && (in_write || admin);
  out->manage = admin;                       /* mount, unmount, secret.set, prompt.answer (2.2, TM-R25) */
}

/* "S-1-" followed by digits and dashes only. */
static int sid_shape_ok(const char *s)
{
  size_t i, n = strlen(s);
  if (n < 5 || n >= SVC_SID_MAX || s[0] != 'S' || s[1] != '-' || s[2] != '1' || s[3] != '-')
    return 0;
  for (i = 4; i < n; i++)
    if (!((s[i] >= '0' && s[i] <= '9') || s[i] == '-'))
      return 0;
  return 1;
}

/* Copies the next comma-separated entry of list (trimmed) into out; returns the position after it, or NULL at the end. */
static const char *next_entry(const char *list, char *out, size_t cap, int *empty)
{
  const char *p = list, *e;
  size_t n;
  while (*p == ' ' || *p == '\t') p++;
  e = p;
  while (*e && *e != ',') e++;
  n = (size_t)(e - p);
  while (n > 0 && (p[n - 1] == ' ' || p[n - 1] == '\t')) n--;
  *empty = (n == 0);
  if (n >= cap)
    n = cap - 1;
  memcpy(out, p, n);
  out[n] = 0;
  return *e == ',' ? e + 1 : NULL;
}

static int acl_has(const char list[][SVC_SID_MAX], uint32_t n, const char *sid)
{
  uint32_t i;
  for (i = 0; i < n; i++)
    if (_stricmp(list[i], sid) == 0)
      return 1;
  return 0;
}

static sd_err add_sid(char list[][SVC_SID_MAX], uint32_t *n, const char *sid)
{
  if (acl_has(list, *n, sid))
    return SD_OK;
  if (*n >= SVC_ACL_MAX)
    return SD_E_INVALID_PARAM;
  strcpy_s(list[*n], SVC_SID_MAX, sid);
  (*n)++;
  return SD_OK;
}

static sd_err resolve_list(const char *csv, svc_resolve_fn resolve, void *ctx, char list[][SVC_SID_MAX], uint32_t *n)
{
  const char *p = csv;
  char entry[512], sid[SVC_SID_MAX];
  int empty = 0;
  *n = 0;
  if (csv == NULL || csv[0] == 0)
    return SD_OK;
  while (p != NULL) {
    sd_err e;
    p = next_entry(p, entry, sizeof(entry), &empty);
    if (empty)
      continue;
    if (sid_shape_ok(entry))
      strcpy_s(sid, sizeof(sid), entry);
    else if (resolve == NULL || !resolve(ctx, entry, sid, sizeof(sid)) || !sid_shape_ok(sid))
      return SD_E_NOT_FOUND;                  /* unresolved name: the drive is not mounted (fail closed) */
    e = add_sid(list, n, sid);
    if (e != SD_OK)
      return e;
  }
  return SD_OK;
}

sd_err svc_acl_build(const sd_profile *p, svc_resolve_fn resolve, void *ctx, svc_acl *out)
{
  uint32_t i;
  sd_err e;
  if (p == NULL || out == NULL)
    return SD_E_INVALID_PARAM;
  memset(out, 0, sizeof(*out));
  e = resolve_list(p->service_access, resolve, ctx, out->access, &out->n_access);
  if (e != SD_OK)
    return e;
  e = resolve_list(p->service_access_write, resolve, ctx, out->write, &out->n_write);
  if (e != SD_OK)
    return e;
  /* write must be a subset of access, compared by SID (names and SIDs may both appear) */
  for (i = 0; i < out->n_write; i++)
    if (!acl_has(out->access, out->n_access, out->write[i]))
      return SD_E_INVALID_PARAM;
  return SD_OK;
}

sd_err svc_chain_hop_check(const sd_chain_hop *h, const char **bad_key, const char **why)
{
  const char *k = NULL, *w = NULL;
  if (h == NULL)
    return SD_E_INVALID_PARAM;
  if (h->identity_count > 1) {
    k = "auth.identity";
    w = "one identity file per service hop (the hop takes one key blob)";
  } else if (h->certificate[0] != 0) {
    k = "auth.certificate";
    w = "certificate files are not loaded for service profiles";
  } else if (h->identity_store[0] != 0) {
    k = "auth.identity_store";
    w = "a user-kept key cannot be used by the service (service secrets only)";
  } else if (h->agent == SD_PROFILE_AGENT_PAGEANT || h->agent == SD_PROFILE_AGENT_OPENSSH) {
    k = "auth.agent";
    w = "agents are not available to the service (D17)";
  } else if (h->agent_keys[0] != 0) {
    k = "auth.agent_keys";
    w = "agent keys are not available to the service (D17)";
  } else if (h->auth_methods & SD_PROFILE_AUTH_KBDINT) {
    k = "auth.methods";
    w = "keyboard-interactive needs a user at the console (2.6)";
  } else if ((h->auth_methods & (SD_PROFILE_AUTH_PUBLICKEY | SD_PROFILE_AUTH_PASSWORD)) == 0) {
    k = "auth.methods";
    w = "no non-interactive authentication method";
  }
  if (k != NULL) {
    if (bad_key) *bad_key = k;
    if (why) *why = w;
    return SD_E_INVALID_PARAM;
  }
  if (bad_key) *bad_key = NULL;
  if (why) *why = NULL;
  return SD_OK;
}

sd_err svc_proxy_leg_check(const sd_proxy_spec *x, int proxy_auth, int secret_present, const char **bad_key,
                           const char **why)
{
  const char *k = NULL, *w = NULL;
  int needs_secret;
  if (x == NULL)
    return SD_E_INVALID_PARAM;
  if (x->kind == SD_PROFILE_PROXY_SYSTEM) {
    if (proxy_auth == SD_PROFILE_PROXY_AUTH_BASIC || proxy_auth == SD_PROFILE_PROXY_AUTH_NEGOTIATE) {
      k = "proxy.proxy_auth";
      w = "the system proxy has no credentials (TM-R10): use auto or none";
    }
  } else if (x->kind == SD_PROFILE_PROXY_HTTP || x->kind == SD_PROFILE_PROXY_SOCKS5) {
    if (proxy_auth == SD_PROFILE_PROXY_AUTH_BASIC && x->user[0] == 0) {
      k = "proxy.proxy_auth";
      w = "basic proxy authentication needs a user";
    }
    /* SOCKS5 username/password, and HTTP with a user unless auth is none, sends a password: a service secret only */
    needs_secret = x->user[0] != 0 &&
                   (x->kind == SD_PROFILE_PROXY_SOCKS5 || proxy_auth != SD_PROFILE_PROXY_AUTH_NONE);
    if (k == NULL && needs_secret && !secret_present) {
      k = "proxy.proxy_auth";
      w = "this proxy needs a password: store a proxy secret in the service secret store";
    }
  }
  if (k != NULL) {
    if (bad_key) *bad_key = k;
    if (why) *why = w;
    return SD_E_INVALID_PARAM;
  }
  if (bad_key) *bad_key = NULL;
  if (why) *why = NULL;
  return SD_OK;
}

sd_err svc_validate_profile(const sd_profile *p, const char **bad_key, const char **why)
{
  const char *k = NULL, *w = NULL;
  if (p == NULL)
    return SD_E_INVALID_PARAM;
  if (p->scope != SD_PROFILE_SCOPE_SERVICE) {
    k = "profile.scope";
    w = "not a service profile";
  } else if (p->user[0] == 0) {
    k = "profile.user";
    w = "a service profile needs an explicit user name (no current user exists in the service)";
  } else if (p->service_access[0] == 0) {
    k = "profile.service_access";
    w = "no service_access list (D35)";
  } else if (p->agent == SD_PROFILE_AGENT_PAGEANT || p->agent == SD_PROFILE_AGENT_OPENSSH) {
    k = "auth.agent";
    w = "agents are not available to the service (D17)";
  } else if (p->auth_methods & SD_PROFILE_AUTH_KBDINT) {
    k = "auth.methods";
    w = "keyboard-interactive needs a user at the console (2.6)";
  }
  if (k != NULL) {
    if (bad_key) *bad_key = k;
    if (why) *why = w;
    return SD_E_INVALID_PARAM;
  }
  if (bad_key) *bad_key = NULL;
  if (why) *why = NULL;
  return SD_OK;
}

static int sddl_append(char *out, size_t cap, size_t *len, const char *s)
{
  size_t n = strlen(s);
  if (*len + n + 1 > cap)
    return 0;
  memcpy(out + *len, s, n + 1);
  *len += n;
  return 1;
}

sd_err svc_volume_sddl(const svc_acl *acl, char *out, size_t cap)
{
  size_t len = 0;
  uint32_t i;
  if (acl == NULL || out == NULL || cap == 0)
    return SD_E_INVALID_PARAM;
  out[0] = 0;
  if (!sddl_append(out, cap, &len, "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"))
    return SD_E_NO_SPACE;
  for (i = 0; i < acl->n_access; i++) {
    if (!sddl_append(out, cap, &len, "(A;OICI;FRFX;;;") || !sddl_append(out, cap, &len, acl->access[i]) ||
        !sddl_append(out, cap, &len, ")"))
      return SD_E_NO_SPACE;
  }
  for (i = 0; i < acl->n_write; i++) {
    if (!sddl_append(out, cap, &len, "(A;OICI;FA;;;") || !sddl_append(out, cap, &len, acl->write[i]) ||
        !sddl_append(out, cap, &len, ")"))
      return SD_E_NO_SPACE;
  }
  return SD_OK;
}

/* Substring test without wcsstr: the CRT wcsstr uses SSE2/SSE3 code, which the x86-ia32 flavour forbids (04 §3.2). */
static int wcs_has(const wchar_t *s, const wchar_t *pat)
{
  size_t n = wcslen(pat), i;
  if (n == 0)
    return 1;
  for (i = 0; s[i] != 0; i++)
    if (wcsncmp(s + i, pat, n) == 0)
      return 1;
  return 0;
}

int svc_path_under(const wchar_t *path, const wchar_t *folder)
{
  size_t fl;
  if (path == NULL || folder == NULL)
    return 0;
  fl = wcslen(folder);
  if (fl == 0 || wcsncmp(path, folder, fl) != 0)
    return 0;
  if (path[fl] != L'\\')
    return 0;
  /* no parent segments and no forward slashes after the folder prefix */
  if (wcs_has(path + fl, L"\\..\\"))
    return 0;
  if (wcslen(path) >= fl + 3 && wcscmp(path + wcslen(path) - 3, L"\\..") == 0)
    return 0;
  if (wcschr(path, L'/') != NULL)
    return 0;
  return 1;
}

/* ---- Event 3101 throttle (10.3, TM-R25) ---- */

int svc_refuse_log_due(svc_refuse_entry *tab, size_t n, const wchar_t *sid, uint64_t now_ms)
{
  size_t i, victim = 0;
  if (tab == NULL || n == 0 || sid == NULL)
    return 0;
  for (i = 0; i < n; i++) {
    if (tab[i].used && lstrcmpW(tab[i].sid, sid) == 0) {
      if (now_ms >= tab[i].last_ms && now_ms - tab[i].last_ms < SVC_REFUSE_WINDOW_MS)
        return 0;
      tab[i].last_ms = now_ms;
      return 1;
    }
  }
  /* not seen in the window: take a free slot, else the entry that was logged longest ago */
  for (i = 0; i < n; i++) {
    if (!tab[i].used) {
      victim = i;
      break;
    }
    if (tab[i].last_ms < tab[victim].last_ms)
      victim = i;
  }
  tab[victim].used = 1;
  tab[victim].last_ms = now_ms;
  wcsncpy_s(tab[victim].sid, SD_COUNTOF(tab[victim].sid), sid, _TRUNCATE);
  return 1;
}
