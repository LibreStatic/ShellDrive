/* Per-user attach of a global WebDAV drive (apps/shelldrive-host/svc_gw_attach.h). */
#include <windows.h>
#include <winnetwk.h>
#include <string.h>

#include "svc_gw_attach.h"

#define GW_TOKEN_LEN 26

static const wchar_t k_vista_prefix[] = L"\\\\localhost@";
static const wchar_t k_vista_mid[] = L"\\DavWWWRoot\\s-";
static const wchar_t k_xp_prefix[] = L"http://localhost:";
static const wchar_t k_xp_mid[] = L"/s-";
static const wchar_t k_xp_provider[] = L"Web Client Network";

/* Matches the literal at *p and advances; 0 when it does not match. */
static int lit(const wchar_t **p, const wchar_t *lit_s)
{
  const wchar_t *q = *p;
  size_t i;
  for (i = 0; lit_s[i] != 0; i++) {
    if (q[i] != lit_s[i])
      return 0;
  }
  *p = q + i;
  return 1;
}

/* One to five decimal digits, no leading zero, value 1..65535. */
static int port(const wchar_t **p)
{
  const wchar_t *q = *p;
  unsigned long v = 0;
  int n = 0;
  if (*q == L'0')
    return 0;
  while (q[n] >= L'0' && q[n] <= L'9') {
    if (n >= 5)
      return 0;
    v = v * 10u + (unsigned long)(q[n] - L'0');
    n++;
  }
  if (n == 0 || v == 0 || v > 65535u)
    return 0;
  *p = q + n;
  return 1;
}

/* RFC 4648 base32, lower case: a-z and 2-7. */
static int token(const wchar_t **p)
{
  const wchar_t *q = *p;
  int i;
  for (i = 0; i < GW_TOKEN_LEN; i++) {
    wchar_t c = q[i];
    if (!((c >= L'a' && c <= L'z') || (c >= L'2' && c <= L'7')))
      return 0;
  }
  *p = q + GW_TOKEN_LEN;
  return 1;
}

int svc_gw_attach_remote_ok(const wchar_t *remote, int xp_form)
{
  const wchar_t *p = remote;
  if (remote == NULL)
    return 0;
  if (xp_form) {
    if (!lit(&p, k_xp_prefix) || !port(&p) || !lit(&p, k_xp_mid) || !token(&p))
      return 0;
  } else {
    if (!lit(&p, k_vista_prefix) || !port(&p) || !lit(&p, k_vista_mid) || !token(&p))
      return 0;
  }
  return *p == 0;
}

static int letter_ok(wchar_t letter)
{
  return letter >= L'A' && letter <= L'Z';
}

sd_err svc_gw_attach_map(const svc_gw_attach_ops *ops, wchar_t letter, const wchar_t *remote, int xp_form,
                         DWORD *win32_error)
{
  DWORD rc;
  if (win32_error)
    *win32_error = NO_ERROR;
  if (ops == NULL || ops->add == NULL || !letter_ok(letter) || !svc_gw_attach_remote_ok(remote, xp_form))
    return SD_E_INVALID_PARAM;
  rc = ops->add(ops->ctx, letter, remote, xp_form);
  if (win32_error)
    *win32_error = rc;
  if (rc == NO_ERROR)
    return SD_OK;
  if (rc == ERROR_ALREADY_ASSIGNED || rc == ERROR_DEVICE_ALREADY_REMEMBERED)
    return SD_E_EXISTS;
  return SD_E_FAILURE;
}

sd_err svc_gw_attach_unmap(const svc_gw_attach_ops *ops, wchar_t letter, DWORD *win32_error)
{
  DWORD rc;
  if (win32_error)
    *win32_error = NO_ERROR;
  if (ops == NULL || ops->cancel == NULL || !letter_ok(letter))
    return SD_E_INVALID_PARAM;
  rc = ops->cancel(ops->ctx, letter);
  if (win32_error)
    *win32_error = rc;
  return rc == NO_ERROR ? SD_OK : SD_E_FAILURE;
}

/* ---- real seam (mpr.dll, on the XP floor list: tests/os-imports) ---- */

static DWORD real_add(void *ctx, wchar_t letter, const wchar_t *remote, int xp_form)
{
  NETRESOURCEW nr;
  wchar_t local[3];
  (void)ctx;
  local[0] = letter;
  local[1] = L':';
  local[2] = 0;
  memset(&nr, 0, sizeof(nr));
  nr.dwType = RESOURCETYPE_DISK;
  nr.lpLocalName = local;
  nr.lpRemoteName = (LPWSTR)remote;
  nr.lpProvider = xp_form ? (LPWSTR)k_xp_provider : NULL;
  /* no CONNECT_UPDATE_PROFILE: the mapping is not persistent (02 §7.3) */
  return WNetAddConnection2W(&nr, NULL, NULL, 0);
}

static DWORD real_cancel(void *ctx, wchar_t letter)
{
  wchar_t local[3];
  (void)ctx;
  local[0] = letter;
  local[1] = L':';
  local[2] = 0;
  return WNetCancelConnection2W(local, 0, TRUE);
}

const svc_gw_attach_ops svc_gw_attach_real_ops = { NULL, real_add, real_cancel };
