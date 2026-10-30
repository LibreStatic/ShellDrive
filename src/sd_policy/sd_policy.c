/* sd_policy: reads the Group Policy values through the generated table (see sd_policy.h). */
#include <windows.h>

#include "sd_policy/sd_policy.h"
#include "sd_policy_table.h"   /* generated: SD_POLICY_REGKEY and sd_policy_defs[] */

const wchar_t *sd_policy_key(void)
{
  return SD_POLICY_REGKEY;
}

const sd_policy_def *sd_policy_def_of(sd_policy_id id)
{
  if ((int)id < 0 || (int)id >= (int)SD_POLICY_ID_COUNT)
    return NULL;
  return &sd_policy_defs[(size_t)id];
}

static int read_dword(HKEY root, const wchar_t *name, DWORD *value)
{
  HKEY k;
  DWORD type = 0, v = 0, cb = sizeof(v);
  int ok = 0;
  if (RegOpenKeyExW(root, SD_POLICY_REGKEY, 0, KEY_QUERY_VALUE, &k) != ERROR_SUCCESS)
    return 0;
  if (RegQueryValueExW(k, name, NULL, &type, (LPBYTE)&v, &cb) == ERROR_SUCCESS && type == REG_DWORD &&
      cb == sizeof(v)) {
    *value = v;
    ok = 1;
  }
  RegCloseKey(k);
  return ok;
}

static int read_sz(HKEY root, const wchar_t *name, wchar_t *buf, size_t cch)
{
  HKEY k;
  DWORD type = 0, cb = (DWORD)(cch * sizeof(wchar_t));
  int ok = 0;
  if (buf == NULL || cch == 0)
    return 0;
  if (RegOpenKeyExW(root, SD_POLICY_REGKEY, 0, KEY_QUERY_VALUE, &k) != ERROR_SUCCESS)
    return 0;
  buf[0] = 0;
  if (RegQueryValueExW(k, name, NULL, &type, (LPBYTE)buf, &cb) == ERROR_SUCCESS && type == REG_SZ) {
    buf[cch - 1] = 0;
    ok = 1;
  }
  RegCloseKey(k);
  return ok;
}

int sd_policy_get_dword(sd_policy_id id, DWORD *value)
{
  const sd_policy_def *d = sd_policy_def_of(id);
  if (d == NULL || value == NULL || d->reg != SD_POLICY_REG_DWORD)
    return 0;
  return read_dword(HKEY_LOCAL_MACHINE, d->name, value) || read_dword(HKEY_CURRENT_USER, d->name, value);
}

int sd_policy_get_sz(sd_policy_id id, wchar_t *buf, size_t cch)
{
  const sd_policy_def *d = sd_policy_def_of(id);
  if (d == NULL || buf == NULL || cch == 0 || d->reg != SD_POLICY_REG_SZ)
    return 0;
  return read_sz(HKEY_LOCAL_MACHINE, d->name, buf, cch) || read_sz(HKEY_CURRENT_USER, d->name, buf, cch);
}

int sd_policy_machine_get_dword(sd_policy_id id, DWORD *value)
{
  const sd_policy_def *d = sd_policy_def_of(id);
  if (d == NULL || value == NULL || d->reg != SD_POLICY_REG_DWORD)
    return 0;
  return read_dword(HKEY_LOCAL_MACHINE, d->name, value);
}

int sd_policy_machine_get_sz(sd_policy_id id, wchar_t *buf, size_t cch)
{
  const sd_policy_def *d = sd_policy_def_of(id);
  if (d == NULL || buf == NULL || cch == 0 || d->reg != SD_POLICY_REG_SZ)
    return 0;
  return read_sz(HKEY_LOCAL_MACHINE, d->name, buf, cch);
}
