/* sd_vfs per-request access check (M5, 02 §6.7, §7.7, TM-R24, D35).
 *
 * Per-user mounts: the caller must be the mount owner (02 §6.7 and 7.4 allow the owner only). A NULL caller is
 * accepted for host-internal use, as before M5.
 *
 * Global mounts (scope = service): the lists come from the profile (service_access, service_access_write) and
 * are copied once at mount, so a request costs one EqualSid per list entry and token group. The decision:
 *   - no caller or no sid: refused;
 *   - a write needs caller->can_write (the frontend may restrict) and the write rule below;
 *   - LocalSystem is allowed in full when allow_system is on (Defender, the indexer);
 *   - any access needs the caller (sid or an enabled group) in access_sids; membership alone grants read;
 *   - a write needs the caller in write_sids, or an enabled BUILTIN\Administrators group (a UAC-filtered admin
 *     token has it deny-only, so it does not count: admins write from an elevated process or are listed).
 * Empty access_sids is refused at mount (no default audience). Empty write_sids: members are read-only.
 *
 * Group matching uses the groups the frontend passed. WebDAV has no token groups on the service path yet (only
 * per-user mounts exist there), so it matches by user SID only; see docs/dev/m5-notes.md. */
#include <string.h>

#include "sd_base/sd_mem.h"
#include "vfs_internal.h"

static BOOL sid_eq(PSID a, PSID b)
{
  return a && b && IsValidSid(a) && IsValidSid(b) && EqualSid(a, b);
}

/* Deep copy of a SID list (fails closed on any copy error). */
static sd_vfs_status copy_list(const PSID *in, UINT n, PSID **out, uint32_t *nout)
{
  PSID *arr;
  UINT i;
  *out = NULL;
  *nout = 0;
  if (n == 0)
    return SD_VFS_OK;
  if (in == NULL)
    return SD_VFS_E_INVALID_NAME;
  arr = (PSID *)sd_calloc(n, sizeof(PSID));
  if (arr == NULL)
    return SD_VFS_E_NO_MEMORY;
  for (i = 0; i < n; i++) {
    DWORD len;
    if (in[i] == NULL || !IsValidSid(in[i]))
      goto bad;
    len = GetLengthSid(in[i]);
    arr[i] = sd_alloc(len);
    if (arr[i] == NULL || !CopySid(len, arr[i], in[i]))
      goto bad;
  }
  *out = arr;
  *nout = (uint32_t)n;
  return SD_VFS_OK;
bad:
  for (; i > 0; i--)
    sd_free(arr[i - 1]);                /* entries 0 .. i-1 are copied; arr[i] (if any) is freed below */
  sd_free(arr[i]);
  sd_free(arr);
  return SD_VFS_E_NO_MEMORY;
}

static void free_list(PSID **list, uint32_t *n)
{
  uint32_t i;
  if (*list) {
    for (i = 0; i < *n; i++)
      sd_free((*list)[i]);
    sd_free(*list);
  }
  *list = NULL;
  *n = 0;
}

static PSID well_known(BYTE auth, DWORD sub0, DWORD sub1)
{
  SID_IDENTIFIER_AUTHORITY ia;
  PSID s = NULL;
  memset(&ia, 0, sizeof(ia));
  ia.Value[5] = auth;
  if (sub1 == 0)
    AllocateAndInitializeSid(&ia, 1, sub0, 0, 0, 0, 0, 0, 0, 0, &s);
  else
    AllocateAndInitializeSid(&ia, 2, sub0, sub1, 0, 0, 0, 0, 0, 0, &s);
  return s;
}

sd_vfs_status vfs_access_init(sd_vfs *v, const sd_vfs_options *o)
{
  sd_vfs_status st;
  v->global = o->global_mount ? TRUE : FALSE;
  if (!v->global)
    return SD_VFS_OK;                   /* per-user: owner only, nothing to copy */
  if (o->n_access == 0)
    return SD_VFS_E_ACCESS_DENIED;      /* scope = service without service_access (D35): not mounted */
  st = copy_list(o->access_sids, o->n_access, &v->acc_sids, &v->n_acc);
  if (st != SD_VFS_OK)
    return st;
  st = copy_list(o->write_sids, o->n_write, &v->wrt_sids, &v->n_wrt);
  if (st != SD_VFS_OK)
    return st;
  /* S-1-5-18 (LocalSystem) and S-1-5-32-544 (BUILTIN\Administrators) */
  v->sid_system = well_known(5, 18, 0);
  v->sid_admins = well_known(5, 32, 544);
  if (v->sid_system == NULL || v->sid_admins == NULL)
    return SD_VFS_E_NO_MEMORY;
  return SD_VFS_OK;
}

void vfs_access_free(sd_vfs *v)
{
  free_list(&v->acc_sids, &v->n_acc);
  free_list(&v->wrt_sids, &v->n_wrt);
  if (v->sid_system) FreeSid(v->sid_system);
  if (v->sid_admins) FreeSid(v->sid_admins);
  v->sid_system = v->sid_admins = NULL;
}

/* TRUE when the caller (its SID or one of its enabled groups) matches an entry of the list. */
static BOOL caller_in(const sd_vfs_caller *c, PSID const *list, uint32_t n)
{
  uint32_t i, g;
  for (i = 0; i < n; i++) {
    if (sid_eq(c->sid, list[i]))
      return TRUE;
    for (g = 0; c->groups && g < c->n_groups; g++) {
      if (sid_eq(c->groups[g], list[i]))
        return TRUE;
    }
  }
  return FALSE;
}

static BOOL caller_has_group(const sd_vfs_caller *c, PSID sid)
{
  UINT g;
  for (g = 0; c->groups && g < c->n_groups; g++) {
    if (sid_eq(c->groups[g], sid))
      return TRUE;
  }
  return FALSE;
}

sd_vfs_status vfs_access_check(const sd_vfs *v, const sd_vfs_caller *c, BOOL write)
{
  if (!v->global) {
    if (c == NULL)
      return SD_VFS_OK;                 /* host-internal (no requestor) */
    if (!sid_eq(c->sid, v->owner_sid))
      return SD_VFS_E_ACCESS_DENIED;    /* per-user mount: the owner only (02 6.7) */
    return SD_VFS_OK;
  }
  if (c == NULL || c->sid == NULL || !IsValidSid(c->sid))
    return SD_VFS_E_ACCESS_DENIED;
  if (write && !c->can_write)
    return SD_VFS_E_ACCESS_DENIED;
  if (v->allow_system && sid_eq(c->sid, v->sid_system))
    return SD_VFS_OK;
  if (!caller_in(c, v->acc_sids, v->n_acc))
    return SD_VFS_E_ACCESS_DENIED;      /* outside service_access: no data, no listing (G7) */
  if (!write)
    return SD_VFS_OK;
  if (caller_in(c, v->wrt_sids, v->n_wrt) || caller_has_group(c, v->sid_admins))
    return SD_VFS_OK;
  return SD_VFS_E_ACCESS_DENIED;        /* a member without the write right (TM-R24) */
}
