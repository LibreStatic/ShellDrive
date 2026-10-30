/* SSPI client tokens for HTTP proxy authentication (01 §5.2, TM-R10).
 *
 * secur32.dll is loaded by full System32 path and only InitSecurityInterfaceW is resolved (XP+); the
 * dispatch table provides AcquireCredentialsHandleW / InitializeSecurityContextW without a static
 * import. Credentials are the current logon (outbound, no explicit user). kerberos_only restricts
 * the Negotiate package with a SEC_WINNT_AUTH_IDENTITY_EX whose PackageList is "!ntlm", so a proxy
 * that would only get an NTLM response gets nothing (profile proxy_auth = auto). The target name is
 * always HTTP/<proxy host as configured>. Calls block (Kerberos may contact a KDC): workers only. */
#define SECURITY_WIN32
#include <windows.h>
#include <security.h>
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_platform.h"
#include "sd_platform/sd_thread.h"
#include "proxy_internal.h"

typedef PSecurityFunctionTableW (SEC_ENTRY *pfn_InitSecurityInterfaceW)(void);

static sd_once g_sspi_once = SD_ONCE_INIT;
static PSecurityFunctionTableW g_ft;

static void sspi_init(void *arg)
{
  pfn_InitSecurityInterfaceW init;
  SD_UNUSED(arg);
  init = (pfn_InitSecurityInterfaceW)sd_platform_resolve_by_name(L"secur32.dll", "InitSecurityInterfaceW");
  if (!init) return;
  g_ft = init();
  if (g_ft && (!g_ft->AcquireCredentialsHandleW || !g_ft->InitializeSecurityContextW ||
               !g_ft->DeleteSecurityContext || !g_ft->FreeCredentialsHandle || !g_ft->FreeContextBuffer))
    g_ft = NULL;
}

struct ssh_sspi {
  CredHandle cred;
  CtxtHandle ctx;
  int have_cred, have_ctx;
  wchar_t target[300];
};

sd_err ssh_sspi_create(const wchar_t *package, int kerberos_only, const wchar_t *target, ssh_sspi **out)
{
  ssh_sspi *s;
  SECURITY_STATUS ss;
  TimeStamp exp;
  SEC_WINNT_AUTH_IDENTITY_EXW id;
  size_t tl;
  *out = NULL;
  sd_once_run(&g_sspi_once, sspi_init, NULL);
  if (!g_ft) return SD_E_UNSUPPORTED;
  tl = wcslen(target);
  if (tl >= 300) return SD_E_INVALID_PARAM;
  s = (ssh_sspi *)sd_calloc(1, sizeof(*s));
  if (!s) return SD_E_NO_MEMORY;
  memcpy(s->target, target, (tl + 1) * sizeof(wchar_t));
  memset(&id, 0, sizeof(id));
  id.Version = SEC_WINNT_AUTH_IDENTITY_VERSION;
  id.Length = (unsigned long)sizeof(id);
  id.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
  id.PackageList = (unsigned short *)L"!ntlm";
  id.PackageListLength = 5;
  ss = g_ft->AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)package, SECPKG_CRED_OUTBOUND, NULL,
                                       kerberos_only ? &id : NULL, NULL, NULL, &s->cred, &exp);
  if (ss != SEC_E_OK) {
    sd_log(SD_LOG_WARN, "ssh", NULL, "AcquireCredentialsHandle(%ls) failed: 0x%x", package, (unsigned)ss);
    sd_free(s);
    return SD_E_PROXY_AUTH;
  }
  s->have_cred = 1;
  *out = s;
  return SD_OK;
}

sd_err ssh_sspi_step(ssh_sspi *s, const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len)
{
  SecBuffer ib, ob;
  SecBufferDesc id, od;
  ULONG attrs = 0;
  TimeStamp exp;
  SECURITY_STATUS ss;
  *out = NULL;
  *out_len = 0;
  if (!g_ft || !s->have_cred) return SD_E_UNSUPPORTED;
  if (in_len > SSH_PX_TOKEN_MAX) return SD_E_INVALID_PARAM;
  ib.BufferType = SECBUFFER_TOKEN;
  ib.cbBuffer = (unsigned long)in_len;
  ib.pvBuffer = (void *)(uintptr_t)in;
  id.ulVersion = SECBUFFER_VERSION;
  id.cBuffers = 1;
  id.pBuffers = &ib;
  ob.BufferType = SECBUFFER_TOKEN;
  ob.cbBuffer = 0;
  ob.pvBuffer = NULL;
  od.ulVersion = SECBUFFER_VERSION;
  od.cBuffers = 1;
  od.pBuffers = &ob;
  ss = g_ft->InitializeSecurityContextW(&s->cred, s->have_ctx ? &s->ctx : NULL, (SEC_WCHAR *)s->target,
                                        ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONNECTION, 0, SECURITY_NATIVE_DREP,
                                        (in && in_len) ? &id : NULL, 0, &s->ctx, &od, &attrs, &exp);
  if (ss == SEC_E_OK || ss == SEC_I_CONTINUE_NEEDED) s->have_ctx = 1;
  if (ss == SEC_I_COMPLETE_NEEDED || ss == SEC_I_COMPLETE_AND_CONTINUE) {
    /* CompleteAuthToken is only needed by Digest-like packages; Negotiate/NTLM do not return these */
    ss = SEC_E_UNSUPPORTED_FUNCTION;
  }
  if (ss != SEC_E_OK && ss != SEC_I_CONTINUE_NEEDED) {
    if (ob.pvBuffer) g_ft->FreeContextBuffer(ob.pvBuffer);
    sd_log(SD_LOG_WARN, "ssh", NULL, "InitializeSecurityContext for the proxy failed: 0x%x", (unsigned)ss);
    return SD_E_PROXY_AUTH;
  }
  if (ob.pvBuffer && ob.cbBuffer) {
    if (ob.cbBuffer > SSH_PX_TOKEN_MAX) { g_ft->FreeContextBuffer(ob.pvBuffer); return SD_E_PROXY_AUTH; }
    *out = (uint8_t *)sd_alloc(ob.cbBuffer);
    if (!*out) { g_ft->FreeContextBuffer(ob.pvBuffer); return SD_E_NO_MEMORY; }
    memcpy(*out, ob.pvBuffer, ob.cbBuffer);
    *out_len = ob.cbBuffer;
  }
  if (ob.pvBuffer) g_ft->FreeContextBuffer(ob.pvBuffer);
  return *out_len ? SD_OK : SD_E_PROXY_AUTH;
}

void ssh_sspi_free(ssh_sspi *s)
{
  if (!s) return;
  if (g_ft) {
    if (s->have_ctx) g_ft->DeleteSecurityContext(&s->ctx);
    if (s->have_cred) g_ft->FreeCredentialsHandle(&s->cred);
  }
  sd_free(s);
}
