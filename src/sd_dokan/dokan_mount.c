/* Dokany mount and the DOKAN_OPERATIONS -> sd_vfs mapping (02 §6.4-§6.7).
 *
 * Callbacks run concurrently on Dokany worker threads and only call sd_vfs request functions. The
 * Unmounted callback only notifies the host (C33): DokanCloseHandle, sd_vfs_unmount and
 * sd_sftp_session_destroy are never called from a Dokany thread. */
#include <windows.h>
#include <stdio.h>

#include "dokan_cache.h"
#include "dokan_internal.h"
#include "sd_base/sd_mem.h"
#include "sd_platform/sd_log.h"

#ifndef FILE_SUPPORTS_REMOTE_STORAGE
#define FILE_SUPPORTS_REMOTE_STORAGE 0x00000100
#endif
#ifndef FILE_READ_ONLY_VOLUME
#define FILE_READ_ONLY_VOLUME 0x00080000
#endif

#define DOKAN_LOG "dokan"

struct sd_dokan_mount {
  sd_vfs *vfs;
  SD_DOKAN_OPTIONS opt;                 /* must stay valid while mounted */
  SD_DOKAN_OPERATIONS ops;
  SD_DOKAN_HANDLE inst;
  WCHAR mount_point[MAX_PATH];
  WCHAR unc[96];
  sd_dokan_unmounted_cb cb; void *cb_ctx;
  volatile LONG unmounted;
  sd_vfs_volume vol;
  BOOL global;                          /* M5: service mount; the vfs checks the requestor per create */
  dk_cache *cache;                      /* M5: requestor identities of a global mount (02 6.7); NULL otherwise */
};

static sd_dokan_mount *M(SD_DOKAN_FILE_INFO *fi)
{
  return (sd_dokan_mount *)(ULONG_PTR)fi->DokanOptions->GlobalContext;
}

static sd_vfs_handle *H(SD_DOKAN_FILE_INFO *fi) { return (sd_vfs_handle *)(ULONG_PTR)fi->Context; }

/* ---- requestor check (02 §6.7) ---- */

static BOOL is_local_system(PSID sid)
{
  SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
  PSID sys = NULL;
  BOOL r = FALSE;
  if (AllocateAndInitializeSid(&nt, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &sys)) {
    r = EqualSid(sid, sys);
    FreeSid(sys);
  }
  return r;
}

static BOOL requestor_allowed(sd_dokan_mount *m, SD_DOKAN_FILE_INFO *fi)
{
  const sd_dokan_api *api = sd_dokan_api_get();
  HANDLE tok;
  BYTE buf[256];
  DWORD n = 0;
  BOOL ok = FALSE;
  tok = api->OpenRequestorToken(fi);
  if (tok == INVALID_HANDLE_VALUE || tok == NULL)
    return fi->ProcessId == 4 || fi->ProcessId == 0;   /* kernel-originated (System) requests */
  if (GetTokenInformation(tok, TokenUser, buf, sizeof(buf), &n)) {
    PSID sid = ((TOKEN_USER *)buf)->User.Sid;
    if (m->vol.owner_sid && EqualSid(sid, m->vol.owner_sid))
      ok = TRUE;
    else if (m->vol.allow_system && is_local_system(sid))
      ok = TRUE;                            /* Defender, the indexer */
  }
  CloseHandle(tok);
  return ok;
}

/* Requestor identity of a global mount (02 6.7, 7.7): the token user and its enabled, non-deny-only groups.
   The buffers back the caller's pointers until sd_vfs_create returns (requestor_free). A request without a
   token (kernel-originated) gets no identity and is refused: global mounts have no implicit audience. */
typedef struct requestor_ident {
  BYTE *user, *groups;                  /* token buffers, read on a cache miss */
  PSID *gsids; UINT n_gsids;            /* enabled groups: into groups, or owned copies from the cache */
  BOOL gsids_owned;
  sd_vfs_caller caller;
} requestor_ident;

static void requestor_free(requestor_ident *r)
{
  sd_free(r->user);
  sd_free(r->groups);
  if (r->gsids_owned)
    dk_groups_free(r->gsids, r->n_gsids);
  else
    sd_free(r->gsids);
  memset(r, 0, sizeof(*r));
}

/* Requestor identity (02 6.7, 7.7), cached per token object: the key is TOKEN_STATISTICS (TokenId, ModifiedId) and the
   user SID (dokan_cache.h). Each create reads the statistics and the user; the groups are read only on a miss. The
   TokenId separates filtered, restricted and duplicated tokens of one logon, so no restriction check is needed.
   Every token query that fails returns FALSE and stores nothing. */
static BOOL requestor_identity(sd_dokan_mount *m, SD_DOKAN_FILE_INFO *fi, requestor_ident *r)
{
  const sd_dokan_api *api = sd_dokan_api_get();
  HANDLE tok;
  DWORD n = 0, i, ng = 0, now;
  TOKEN_STATISTICS stats;
  TOKEN_GROUPS *tg;
  BOOL ok = FALSE, hit = FALSE;
  memset(r, 0, sizeof(*r));
  tok = api->OpenRequestorToken(fi);
  if (tok == INVALID_HANDLE_VALUE || tok == NULL)
    return FALSE;
  if (!GetTokenInformation(tok, TokenStatistics, &stats, sizeof(stats), &n))
    goto out;
  if (!GetTokenInformation(tok, TokenUser, NULL, 0, &n) && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
    goto out;
  r->user = (BYTE *)sd_alloc(n);
  if (r->user == NULL || !GetTokenInformation(tok, TokenUser, r->user, n, &n))
    goto out;
#pragma warning(suppress: 28159)   /* deliberate: XP has no GetTickCount64; the cache's expiry test is wrap-safe */
  now = GetTickCount();
  if (m->cache != NULL && dk_cache_get(m->cache, &stats.TokenId, &stats.ModifiedId,
                                       ((TOKEN_USER *)r->user)->User.Sid, now, &r->gsids, &r->n_gsids)) {
    r->gsids_owned = TRUE;
    hit = TRUE;
  }
  if (!hit) {
    n = 0;
    if (!GetTokenInformation(tok, TokenGroups, NULL, 0, &n) && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
      goto out;
    r->groups = (BYTE *)sd_alloc(n);
    if (r->groups == NULL || !GetTokenInformation(tok, TokenGroups, r->groups, n, &n))
      goto out;
    tg = (TOKEN_GROUPS *)r->groups;
    r->gsids = (PSID *)sd_calloc(tg->GroupCount ? tg->GroupCount : 1, sizeof(PSID));
    if (r->gsids == NULL)
      goto out;
    for (i = 0; i < tg->GroupCount; i++) {
      DWORD a = tg->Groups[i].Attributes;
      if ((a & SE_GROUP_ENABLED) && !(a & SE_GROUP_USE_FOR_DENY_ONLY))
        r->gsids[ng++] = tg->Groups[i].Sid;
    }
    r->n_gsids = ng;
    if (m->cache != NULL)
      dk_cache_put(m->cache, &stats.TokenId, &stats.ModifiedId, ((TOKEN_USER *)r->user)->User.Sid, r->gsids, ng, now);
  }
  r->caller.sid = ((TOKEN_USER *)r->user)->User.Sid;
  r->caller.can_write = TRUE;           /* the vfs applies the write rule (TM-R24) */
  r->caller.groups = r->gsids;
  r->caller.n_groups = r->n_gsids;
  ok = TRUE;
out:
  CloseHandle(tok);
  if (!ok)
    requestor_free(r);
  return ok;
}

/* ---- callbacks ---- */

static SD_DOKAN_NTSTATUS WINAPI cb_create(LPCWSTR name, SD_DOKAN_IO_SECURITY_CONTEXT *sc, ACCESS_MASK access,
                                          ULONG attrs, ULONG share, ULONG disp, ULONG opts, SD_DOKAN_FILE_INFO *fi)
{
  sd_dokan_mount *m = M(fi);
  sd_vfs_caller caller;
  requestor_ident ident;
  sd_vfs_handle *h = NULL;
  BOOL existed = FALSE, is_dir = FALSE;
  sd_vfs_status st;
  SD_UNUSED(sc);
  memset(&ident, 0, sizeof(ident));
  if (m->global) {
    /* M5 (02 6.7, 7.7): the vfs decides from the requestor's SID and groups; no token, no access */
    if (!requestor_identity(m, fi, &ident))
      return SD_STATUS_ACCESS_DENIED;
    caller = ident.caller;
  } else {
    if (!requestor_allowed(m, fi))
      return SD_STATUS_ACCESS_DENIED;
    memset(&caller, 0, sizeof(caller));
    caller.sid = m->vol.owner_sid;
    caller.can_write = TRUE;                 /* per-user mount: the owner may write */
  }
  if (fi->IsDirectory)
    opts |= SD_VFS_FILE_DIRECTORY_FILE;
  st = sd_vfs_create(m->vfs, name, &caller, access, share, disp, opts, attrs, &h, &existed, &is_dir);
  requestor_free(&ident);
  if (st != SD_VFS_OK)
    return sd_vfs_to_ntstatus(st);
  fi->Context = (ULONG64)(ULONG_PTR)h;
  fi->IsDirectory = is_dir ? 1 : 0;
  if (existed && (disp == SD_VFS_FILE_OPEN_IF || disp == SD_VFS_FILE_OVERWRITE_IF || disp == SD_VFS_FILE_SUPERSEDE))
    return SD_STATUS_OBJECT_NAME_COLLISION;  /* "opened existing" (02 §2.2) */
  return SD_STATUS_SUCCESS;
}

static void WINAPI cb_cleanup(LPCWSTR name, SD_DOKAN_FILE_INFO *fi)
{
  SD_UNUSED(name);
  if (H(fi))
    sd_vfs_cleanup(H(fi), fi->DeletePending != 0);
}

static void WINAPI cb_close(LPCWSTR name, SD_DOKAN_FILE_INFO *fi)
{
  SD_UNUSED(name);
  if (H(fi)) {
    sd_vfs_close(H(fi));
    fi->Context = 0;
  }
}

static SD_DOKAN_NTSTATUS WINAPI cb_read(LPCWSTR name, LPVOID buf, DWORD len, LPDWORD got, LONGLONG off,
                                        SD_DOKAN_FILE_INFO *fi)
{
  UINT32 g = 0;
  sd_vfs_status st;
  SD_UNUSED(name);
  if (got) *got = 0;
  if (!H(fi) || off < 0)
    return SD_STATUS_INVALID_PARAMETER;
  st = sd_vfs_read(H(fi), (UINT64)off, buf, len, &g);
  if (got) *got = g;
  return sd_vfs_to_ntstatus(st);
}

static SD_DOKAN_NTSTATUS WINAPI cb_write(LPCWSTR name, LPCVOID buf, DWORD len, LPDWORD done, LONGLONG off,
                                         SD_DOKAN_FILE_INFO *fi)
{
  UINT32 d = 0;
  sd_vfs_status st;
  SD_UNUSED(name);
  if (done) *done = 0;
  if (!H(fi))
    return SD_STATUS_INVALID_PARAMETER;
  st = sd_vfs_write(H(fi), fi->WriteToEndOfFile ? SD_VFS_EOF : (UINT64)off, buf, len, &d, fi->PagingIo != 0);
  if (done) *done = d;
  return sd_vfs_to_ntstatus(st);
}

static SD_DOKAN_NTSTATUS WINAPI cb_flush(LPCWSTR name, SD_DOKAN_FILE_INFO *fi)
{
  SD_UNUSED(name);
  return H(fi) ? sd_vfs_to_ntstatus(sd_vfs_flush(H(fi))) : SD_STATUS_SUCCESS;
}

static void ft_copy(FILETIME *dst, const FILETIME *src) { *dst = *src; }

static SD_DOKAN_NTSTATUS WINAPI cb_getinfo(LPCWSTR name, LPBY_HANDLE_FILE_INFORMATION b, SD_DOKAN_FILE_INFO *fi)
{
  sd_dokan_mount *m = M(fi);
  sd_vfs_info info;
  sd_vfs_status st;
  SD_UNUSED(name);
  if (!H(fi))
    return SD_STATUS_INVALID_PARAMETER;
  st = sd_vfs_getattr(H(fi), &info);
  if (st != SD_VFS_OK)
    return sd_vfs_to_ntstatus(st);
  memset(b, 0, sizeof(*b));
  b->dwFileAttributes = info.win_attrs;
  ft_copy(&b->ftCreationTime, &info.ctime);
  ft_copy(&b->ftLastAccessTime, &info.atime);
  ft_copy(&b->ftLastWriteTime, &info.mtime);
  b->dwVolumeSerialNumber = m->vol.serial;
  b->nFileSizeHigh = (DWORD)(info.size >> 32);
  b->nFileSizeLow = (DWORD)info.size;
  b->nNumberOfLinks = 1;
  b->nFileIndexHigh = (DWORD)(info.file_id >> 32);
  b->nFileIndexLow = (DWORD)info.file_id;
  return SD_STATUS_SUCCESS;
}

typedef struct find_ctx { SD_DOKAN_FILL_FIND_DATA fill; SD_DOKAN_FILE_INFO *fi; } find_ctx;

static void fill_one(find_ctx *c, const WCHAR *name, const sd_vfs_info *info)
{
  WIN32_FIND_DATAW d;
  size_t n = wcslen(name);
  if (n >= SD_COUNTOF(d.cFileName))
    return;                                  /* listed by the vfs, not representable in Win32 */
  memset(&d, 0, sizeof(d));
  d.dwFileAttributes = info->win_attrs;
  d.ftCreationTime = info->ctime;
  d.ftLastAccessTime = info->atime;
  d.ftLastWriteTime = info->mtime;
  d.nFileSizeHigh = (DWORD)(info->size >> 32);
  d.nFileSizeLow = (DWORD)info->size;
  memcpy(d.cFileName, name, (n + 1) * sizeof(WCHAR));
  c->fill(&d, c->fi);
}

static BOOL find_cb(void *ctx, const WCHAR *name, const sd_vfs_info *info)
{
  fill_one((find_ctx *)ctx, name, info);
  return TRUE;
}

static SD_DOKAN_NTSTATUS WINAPI cb_find(LPCWSTR path, SD_DOKAN_FILL_FIND_DATA fill, SD_DOKAN_FILE_INFO *fi)
{
  find_ctx c;
  sd_vfs_info self;
  sd_vfs_status st;
  if (!H(fi))
    return SD_STATUS_INVALID_PARAMETER;
  c.fill = fill;
  c.fi = fi;
  if (!(path[0] == L'\\' && path[1] == 0) && sd_vfs_getattr(H(fi), &self) == SD_VFS_OK) {
    fill_one(&c, L".", &self);              /* our own . and .. for non-root directories (02 §6.5) */
    fill_one(&c, L"..", &self);
  }
  st = sd_vfs_readdir(H(fi), find_cb, &c);
  return sd_vfs_to_ntstatus(st);
}

static SD_DOKAN_NTSTATUS WINAPI cb_setattrs(LPCWSTR name, DWORD attrs, SD_DOKAN_FILE_INFO *fi)
{
  SD_UNUSED(name);
  return H(fi) ? sd_vfs_to_ntstatus(sd_vfs_set_winattrs(H(fi), attrs)) : SD_STATUS_INVALID_PARAMETER;
}

static SD_DOKAN_NTSTATUS WINAPI cb_settime(LPCWSTR name, CONST FILETIME *c, CONST FILETIME *a, CONST FILETIME *w,
                                           SD_DOKAN_FILE_INFO *fi)
{
  SD_UNUSED(name);
  return H(fi) ? sd_vfs_to_ntstatus(sd_vfs_set_times(H(fi), c, a, w)) : SD_STATUS_INVALID_PARAMETER;
}

/* Dokany 2.3 validates here and deletes in Cleanup when DeletePending is set (02 §2.4). */
static SD_DOKAN_NTSTATUS WINAPI cb_delete(LPCWSTR name, SD_DOKAN_FILE_INFO *fi)
{
  SD_UNUSED(name);
  if (!H(fi))
    return SD_STATUS_INVALID_PARAMETER;
  if (!fi->DeletePending)
    return SD_STATUS_SUCCESS;                /* the request clears the disposition */
  return sd_vfs_to_ntstatus(sd_vfs_can_delete(H(fi)));
}

static SD_DOKAN_NTSTATUS WINAPI cb_move(LPCWSTR name, LPCWSTR new_name, BOOL replace, SD_DOKAN_FILE_INFO *fi)
{
  SD_UNUSED(name);
  return H(fi) ? sd_vfs_to_ntstatus(sd_vfs_rename(H(fi), new_name, replace)) : SD_STATUS_INVALID_PARAMETER;
}

static SD_DOKAN_NTSTATUS WINAPI cb_seteof(LPCWSTR name, LONGLONG off, SD_DOKAN_FILE_INFO *fi)
{
  SD_UNUSED(name);
  if (!H(fi) || off < 0)
    return SD_STATUS_INVALID_PARAMETER;
  return sd_vfs_to_ntstatus(sd_vfs_truncate(H(fi), (UINT64)off));
}

static SD_DOKAN_NTSTATUS WINAPI cb_setalloc(LPCWSTR name, LONGLONG alloc, SD_DOKAN_FILE_INFO *fi)
{
  sd_vfs_info info;
  sd_vfs_status st;
  SD_UNUSED(name);
  if (!H(fi) || alloc < 0)
    return SD_STATUS_INVALID_PARAMETER;
  st = sd_vfs_getattr(H(fi), &info);
  if (st == SD_VFS_OK && (UINT64)alloc < info.size)
    st = sd_vfs_truncate(H(fi), (UINT64)alloc);   /* growing the allocation is a no-op */
  return sd_vfs_to_ntstatus(st);
}

static SD_DOKAN_NTSTATUS WINAPI cb_diskfree(PULONGLONG avail, PULONGLONG total, PULONGLONG free_, SD_DOKAN_FILE_INFO *fi)
{
  sd_vfs_statfs fs;
  sd_vfs_status st = sd_vfs_statfs_get(M(fi)->vfs, &fs);
  if (st != SD_VFS_OK)
    return sd_vfs_to_ntstatus(st);
  if (avail) *avail = fs.avail;
  if (total) *total = fs.total;
  if (free_) *free_ = fs.free;
  return SD_STATUS_SUCCESS;
}

static void copy_w(LPWSTR dst, DWORD cap, const WCHAR *a, const WCHAR *b)
{
  if (!dst || cap == 0)
    return;
  wcsncpy_s(dst, cap, a ? a : L"", _TRUNCATE);
  if (b && *b)
    wcsncat_s(dst, cap, b, _TRUNCATE);
}

static SD_DOKAN_NTSTATUS WINAPI cb_volinfo(LPWSTR label, DWORD label_cap, LPDWORD serial, LPDWORD maxcomp,
                                           LPDWORD flags, LPWSTR fsname, DWORD fsname_cap, SD_DOKAN_FILE_INFO *fi)
{
  sd_dokan_mount *m = M(fi);
  sd_vfs_volume vol;
  DWORD f = FILE_CASE_PRESERVED_NAMES | FILE_UNICODE_ON_DISK | FILE_PERSISTENT_ACLS | FILE_SUPPORTS_REMOTE_STORAGE;
  sd_vfs_get_volume(m->vfs, &vol);
  copy_w(label, label_cap, vol.label, vol.online ? NULL : vol.offline_suffix);
  if (serial) *serial = vol.serial;
  if (maxcomp) *maxcomp = 255;
  if (vol.case_sensitive_view) f |= FILE_CASE_SENSITIVE_SEARCH;
  if (vol.read_only) f |= FILE_READ_ONLY_VOLUME;
  if (flags) *flags = f;
  copy_w(fsname, fsname_cap, vol.fs_name, NULL);   /* "NTFS" by default (D23) */
  return SD_STATUS_SUCCESS;
}

static SD_DOKAN_NTSTATUS WINAPI cb_mounted(LPCWSTR mount_point, SD_DOKAN_FILE_INFO *fi)
{
  SD_UNUSED(fi);
  SD_LOGI(DOKAN_LOG, "mounted at %ls", mount_point);
  return SD_STATUS_SUCCESS;
}

static SD_DOKAN_NTSTATUS WINAPI cb_unmounted(SD_DOKAN_FILE_INFO *fi)
{
  sd_dokan_mount *m = M(fi);
  /* Post-only (C33): the host's control thread does the teardown. */
  if (InterlockedCompareExchange(&m->unmounted, 1, 0) == 0 && m->cb)
    m->cb(m->cb_ctx, m);
  return SD_STATUS_SUCCESS;
}

static SD_DOKAN_NTSTATUS WINAPI cb_getsec(LPCWSTR name, PSECURITY_INFORMATION si, PSECURITY_DESCRIPTOR sd, ULONG len,
                                          PULONG needed, SD_DOKAN_FILE_INFO *fi)
{
  ULONG n = 0;
  sd_vfs_status st;
  SD_UNUSED(name);
  if (!H(fi))
    return SD_STATUS_INVALID_PARAMETER;
  st = sd_vfs_get_sd(H(fi), *si, sd, len, &n);
  if (st != SD_VFS_OK)
    return sd_vfs_to_ntstatus(st);
  if (needed) *needed = n;
  return n > len ? SD_STATUS_BUFFER_OVERFLOW : SD_STATUS_SUCCESS;
}

static SD_DOKAN_NTSTATUS WINAPI cb_setsec(LPCWSTR name, PSECURITY_INFORMATION si, PSECURITY_DESCRIPTOR sd, ULONG len,
                                          SD_DOKAN_FILE_INFO *fi)
{
  SD_UNUSED(name);
  SD_UNUSED(len);
  return H(fi) ? sd_vfs_to_ntstatus(sd_vfs_set_sd(H(fi), *si, sd)) : SD_STATUS_INVALID_PARAMETER;
}

/* ---- mount / unmount ---- */

sd_err sd_dokan_mount_start(sd_vfs *vfs, const sd_dokan_mount_cfg *cfg, sd_dokan_unmounted_cb cb, void *ctx,
                            sd_dokan_mount **out)
{
  const sd_dokan_api *api = sd_dokan_api_get();
  sd_dokan_mount *m;
  int r;
  if (out) *out = NULL;
  if (!vfs || !cfg || !out || cfg->struct_size < sizeof(*cfg) || !cfg->mount_point)
    return SD_E_INVALID_PARAM;
  if (!api)
    return SD_E_UNSUPPORTED;                 /* sd_dokan_probe() first */
  /* M5: a global mount (service, D35) has no per-session flag and must carry the volume security descriptor that
     encodes service_access and service_access_write; without it the volume would get Dokany's default. */
  if (cfg->global_mount && (!cfg->volume_sd || cfg->volume_sd_len == 0))
    return SD_E_INVALID_PARAM;
  if (cfg->volume_sd_len > SD_DOKAN_VOLUME_SECURITY_DESCRIPTOR_MAX_SIZE)
    return SD_E_INVALID_PARAM;
  m = (sd_dokan_mount *)sd_calloc(1, sizeof(*m));
  if (!m)
    return SD_E_NO_MEMORY;
  m->vfs = vfs;
  m->cb = cb;
  m->cb_ctx = ctx;
  sd_vfs_get_volume(vfs, &m->vol);
  m->global = cfg->global_mount ? TRUE : FALSE;
  wcsncpy_s(m->mount_point, SD_COUNTOF(m->mount_point), cfg->mount_point, _TRUNCATE);

  m->opt.Version = (USHORT)SD_MIN(SD_DOKAN_VERSION, api->lib_version);
  m->opt.SingleThread = FALSE;
  m->opt.GlobalContext = (ULONG64)(ULONG_PTR)m;
  m->opt.MountPoint = m->mount_point;
  m->opt.Timeout = cfg->timeout_ms ? cfg->timeout_ms : 30000;
  m->opt.AllocationUnitSize = 4096;
  m->opt.SectorSize = 512;
  if (cfg->current_session) m->opt.Options |= SD_DOKAN_OPTION_CURRENT_SESSION;
  if (cfg->read_only || m->vol.read_only) m->opt.Options |= SD_DOKAN_OPTION_WRITE_PROTECT;
  if (cfg->case_sensitive) m->opt.Options |= SD_DOKAN_OPTION_CASE_SENSITIVE;
  if (cfg->network && cfg->unc_share && cfg->unc_share[0]) {
    _snwprintf_s(m->unc, SD_COUNTOF(m->unc), _TRUNCATE, L"\\shelldrive\\%s", cfg->unc_share);
    m->opt.UNCName = m->unc;
    m->opt.Options |= SD_DOKAN_OPTION_NETWORK | SD_DOKAN_OPTION_ENABLE_UNMOUNT_NETWORK_DRIVE;
  }
  if (cfg->volume_sd && cfg->volume_sd_len) {
    memcpy(m->opt.VolumeSecurityDescriptor, cfg->volume_sd, cfg->volume_sd_len);
    m->opt.VolumeSecurityDescriptorLength = cfg->volume_sd_len;
  }

  m->ops.ZwCreateFile = cb_create;
  m->ops.Cleanup = cb_cleanup;
  m->ops.CloseFile = cb_close;
  m->ops.ReadFile = cb_read;
  m->ops.WriteFile = cb_write;
  m->ops.FlushFileBuffers = cb_flush;
  m->ops.GetFileInformation = cb_getinfo;
  m->ops.FindFiles = cb_find;
  m->ops.FindFilesWithPattern = NULL;        /* Dokany filters FindFiles with DokanIsNameInExpression */
  m->ops.SetFileAttributes = cb_setattrs;
  m->ops.SetFileTime = cb_settime;
  m->ops.DeleteFile = cb_delete;
  m->ops.DeleteDirectory = cb_delete;
  m->ops.MoveFile = cb_move;
  m->ops.SetEndOfFile = cb_seteof;
  m->ops.SetAllocationSize = cb_setalloc;
  m->ops.LockFile = NULL;                    /* byte-range locks stay in the kernel */
  m->ops.UnlockFile = NULL;
  m->ops.GetDiskFreeSpace = cb_diskfree;
  m->ops.GetVolumeInformation = cb_volinfo;
  m->ops.Mounted = cb_mounted;
  m->ops.Unmounted = cb_unmounted;
  m->ops.GetFileSecurity = cb_getsec;
  m->ops.SetFileSecurity = cb_setsec;
  m->ops.FindStreams = NULL;                 /* only the unnamed stream (mark_of_the_web: M1) */

  if (m->global)
    m->cache = dk_cache_new();          /* NULL on OOM: every create then reads the token (correct, just slower) */
  r = api->CreateFileSystem(&m->opt, &m->ops, &m->inst);
  if (r != SD_DOKAN_SUCCESS) {
    SD_LOGW(DOKAN_LOG, "DokanCreateFileSystem failed: %d", r);
    dk_cache_free(m->cache);
    sd_free(m);
    return r == SD_DOKAN_DRIVE_LETTER_ERROR || r == SD_DOKAN_MOUNT_POINT_ERROR ? SD_E_EXISTS
         : r == SD_DOKAN_VERSION_ERROR ? SD_E_UNSUPPORTED : SD_E_FAILURE;
  }
  *out = m;
  return SD_OK;
}

sd_err sd_dokan_mount_stop(sd_dokan_mount *m)
{
  const sd_dokan_api *api = sd_dokan_api_get();
  if (!m)
    return SD_OK;
  /* Host control thread only: DokanCloseHandle unmounts and waits for every running callback. */
  if (api && m->inst)
    api->CloseHandle(m->inst);
  dk_cache_free(m->cache);              /* after CloseHandle: no callback can still be reading the cache */
  sd_free(m);
  return SD_OK;
}
