/* sd_webdav: Negotiate/NTLM server authentication via SSPI (02 §7.4).
 *
 * secur32.dll is loaded by full System32 path and only InitSecurityInterfaceW is resolved (XP+); the
 * dispatch table gives AcceptSecurityContext and friends without an import. The credential handle
 * (package "Negotiate", inbound, process credentials) is acquired once. Each TCP connection owns one
 * security context; on SEC_E_OK the token user SID is taken from QuerySecurityContextToken and the
 * context is deleted (the connection stays authenticated, 02 §7.4). */
#define SECURITY_WIN32
#include <windows.h>
#include <security.h>
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_platform.h"
#include "sd_platform/sd_thread.h"
#include "wd_server.h"

#define MAX_TOKEN (48u * 1024u)

typedef PSecurityFunctionTableW (SEC_ENTRY *pfn_InitSecurityInterfaceW)(void);

static sd_once g_once = SD_ONCE_INIT;
static PSecurityFunctionTableW g_ft;
static CredHandle g_cred;
static int g_ok;

static void init_once(void *arg)
{
  pfn_InitSecurityInterfaceW init;
  TimeStamp exp;
  SECURITY_STATUS ss;
  SD_UNUSED(arg);
  init = (pfn_InitSecurityInterfaceW)sd_platform_resolve_by_name(L"secur32.dll", "InitSecurityInterfaceW");
  if (init == NULL) {
    SD_LOGE(WD_LOG, "secur32!InitSecurityInterfaceW unavailable");
    return;
  }
  g_ft = init();
  if (g_ft == NULL || g_ft->AcceptSecurityContext == NULL || g_ft->AcquireCredentialsHandleW == NULL ||
      g_ft->QuerySecurityContextToken == NULL || g_ft->DeleteSecurityContext == NULL ||
      g_ft->FreeContextBuffer == NULL) {
    SD_LOGE(WD_LOG, "SSPI dispatch table incomplete");
    return;
  }
  ss = g_ft->AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)L"Negotiate", SECPKG_CRED_INBOUND, NULL, NULL, NULL,
                                       NULL, &g_cred, &exp);
  if (ss != SEC_E_OK) {
    SD_LOGE(WD_LOG, "AcquireCredentialsHandle(Negotiate) failed: 0x%x", (unsigned)ss);
    return;
  }
  g_ok = 1;
}

int wd_auth_available(void)
{
  sd_once_run(&g_once, init_once, NULL);
  return g_ok;
}

void wd_auth_reset(wd_auth *a)
{
  if (a->have && a->ctx) {
    g_ft->DeleteSecurityContext((PCtxtHandle)a->ctx);
  }
  sd_free(a->ctx);
  a->ctx = NULL;
  a->have = 0;
}

static PSID token_user(HANDLE tok)
{
  uint8_t buf[512];
  DWORD len = 0, sl;
  PSID copy = NULL;
  if (GetTokenInformation(tok, TokenUser, buf, sizeof(buf), &len)) {
    PSID s = ((TOKEN_USER *)buf)->User.Sid;
    sl = GetLengthSid(s);
    copy = sd_alloc(sl);
    if (copy && !CopySid(sl, copy, s)) {
      sd_free(copy);
      copy = NULL;
    }
  }
  return copy;
}

void wd_groups_free(PSID *groups, UINT n_groups)
{
  UINT i;
  if (groups == NULL)
    return;
  for (i = 0; i < n_groups; i++)
    sd_free(groups[i]);
  sd_free(groups);
}

/* Enabled, non-deny-only groups of the token (02 §7.7: service_access may name a group). A failure to copy one
   entry drops that entry, never the whole set: the user SID still matches a user entry, and a missing group can
   only deny. Returns 0 when the group set could not be read at all (out stays empty). */
static int token_groups(HANDLE tok, PSID **out, UINT *n_out)
{
  DWORD len = 0, i, n = 0;
  BYTE *buf;
  TOKEN_GROUPS *tg;
  PSID *arr;
  *out = NULL;
  *n_out = 0;
  if (!GetTokenInformation(tok, TokenGroups, NULL, 0, &len) && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
    return 0;
  if (len == 0)
    return 0;
  buf = (BYTE *)sd_alloc(len);
  if (buf == NULL)
    return 0;
  if (!GetTokenInformation(tok, TokenGroups, buf, len, &len)) {
    sd_free(buf);
    return 0;
  }
  tg = (TOKEN_GROUPS *)buf;
  arr = (PSID *)sd_calloc(tg->GroupCount ? tg->GroupCount : 1, sizeof(PSID));
  if (arr == NULL) {
    sd_free(buf);
    return 0;
  }
  for (i = 0; i < tg->GroupCount; i++) {
    DWORD a = tg->Groups[i].Attributes, sl;
    PSID s;
    if (!(a & SE_GROUP_ENABLED) || (a & SE_GROUP_USE_FOR_DENY_ONLY))
      continue;
    s = tg->Groups[i].Sid;
    sl = GetLengthSid(s);
    arr[n] = sd_alloc(sl);
    if (arr[n] == NULL || !CopySid(sl, arr[n], s)) {
      sd_free(arr[n]);
      continue;
    }
    n++;
  }
  sd_free(buf);
  *out = arr;
  *n_out = n;
  return 1;
}

int wd_auth_step(wd_auth *a, const char *value, size_t n, char *out, size_t cap, PSID *user,
                 PSID **groups, UINT *n_groups)
{
  size_t sl = 0, tl = 0;
  const char *scheme;
  uint8_t *in = NULL;
  SecBuffer ib, ob;
  SecBufferDesc ibd, obd;
  ULONG attrs = 0;
  TimeStamp exp;
  SECURITY_STATUS ss;
  int rc = WD_AUTH_FAIL;
  out[0] = 0;
  *user = NULL;
  if (groups)
    *groups = NULL;
  if (n_groups)
    *n_groups = 0;
  if (!wd_auth_available())
    return WD_AUTH_FAIL;
  while (sl < n && value[sl] != ' ')
    sl++;
  if (wd_ieq(value, sl, "Negotiate")) scheme = "Negotiate";
  else if (wd_ieq(value, sl, "NTLM")) scheme = "NTLM";
  else return WD_AUTH_FAIL;
  while (sl < n && value[sl] == ' ')
    sl++;
  if (sl >= n || n - sl > 4u * (MAX_TOKEN / 3u))
    return WD_AUTH_FAIL;
  in = (uint8_t *)sd_alloc(MAX_TOKEN);
  if (in == NULL || wd_b64_decode(value + sl, n - sl, in, MAX_TOKEN, &tl) != 0 || tl == 0)
    goto out;
  if (a->ctx == NULL) {
    a->ctx = sd_calloc(1, sizeof(CtxtHandle));
    if (a->ctx == NULL)
      goto out;
  }
  ib.BufferType = SECBUFFER_TOKEN;
  ib.cbBuffer = (ULONG)tl;
  ib.pvBuffer = in;
  ibd.ulVersion = SECBUFFER_VERSION;
  ibd.cBuffers = 1;
  ibd.pBuffers = &ib;
  ob.BufferType = SECBUFFER_TOKEN;
  ob.cbBuffer = 0;
  ob.pvBuffer = NULL;
  obd.ulVersion = SECBUFFER_VERSION;
  obd.cBuffers = 1;
  obd.pBuffers = &ob;
  ss = g_ft->AcceptSecurityContext(&g_cred, a->have ? (PCtxtHandle)a->ctx : NULL, &ibd,
                                   ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_CONNECTION, SECURITY_NATIVE_DREP,
                                   (PCtxtHandle)a->ctx, &obd, &attrs, &exp);
  if (ss == SEC_E_OK || ss == SEC_I_CONTINUE_NEEDED)
    a->have = 1;
  if (ob.pvBuffer && ob.cbBuffer) {
    size_t hl = strlen(scheme);
    if (hl + 2 + ((ob.cbBuffer + 2) / 3) * 4 + 1 <= cap) {
      memcpy(out, scheme, hl);
      out[hl] = ' ';
      wd_b64_encode((const uint8_t *)ob.pvBuffer, ob.cbBuffer, out + hl + 1, cap - hl - 1);
    }
    g_ft->FreeContextBuffer(ob.pvBuffer);
  }
  if (ss == SEC_I_CONTINUE_NEEDED) {
    rc = out[0] ? WD_AUTH_CONTINUE : WD_AUTH_FAIL;
  } else if (ss == SEC_E_OK) {
    HANDLE tok = NULL;
    if (g_ft->QuerySecurityContextToken((PCtxtHandle)a->ctx, &tok) == SEC_E_OK && tok) {
      *user = token_user(tok);
      if (*user && groups && n_groups)
        (void)token_groups(tok, groups, n_groups);
      CloseHandle(tok);
    }
    rc = *user ? WD_AUTH_OK : WD_AUTH_FAIL;
    wd_auth_reset(a);
  } else {
    SD_LOGI(WD_LOG, "AcceptSecurityContext: 0x%x", (unsigned)ss);
    wd_auth_reset(a);
  }
out:
  if (in) sd_secure_free(in, MAX_TOKEN);
  return rc;
}
