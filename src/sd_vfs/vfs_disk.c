/* Disk tier of the data cache (02 §4.2, TM-R29, T-55, T-59).
 *
 * One sparse data file per remote file plus a small header file (validator, block bitmap, last
 * use), both named by the hex SHA-256 of (host key fingerprint, remote absolute path), in the
 * directory the host chose (sd_vfs_options.disk_cache_dir). Nothing is created outside it. The
 * directory is checked before the tier is enabled: no reparse point, the expected owner, a DACL
 * that grants nobody else read or write, and a volume with persistent ACLs (FAT/exFAT and most
 * portable media are refused). Files are created without a security descriptor, so they inherit
 * the directory's protected DACL. Hot blocks are never written here (the caller decides). Writes
 * are best effort: an I/O error disables the tier for the session.
 *
 * Threading: each entry has its own lock, taken after v->lock is released or with it held
 * (v->lock < entry lock). Entries are opened and closed by vfs threads; the trim runs on the
 * background timer and at mount and only touches files that no entry holds open (data files are
 * opened without FILE_SHARE_DELETE, so deleting an open one fails and is skipped). */
#include <windows.h>
#include <winioctl.h>
#include <aclapi.h>
#include <stdlib.h>

#include "sd_base/sd_mem.h"
#include "sd_crypto/sd_crypto.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_time.h"
#include "vfs_internal.h"

#define VDC_MAGIC   0x31434453u              /* "SDC1" */
#define VDC_VERSION 1u
#define VDC_NAME    64                       /* hex SHA-256 */

typedef struct dc_hdr {
  uint32_t magic, version;
  uint64_t size;
  int64_t  mtime, last_use;
  uint32_t nblocks, reserved;
} dc_hdr;

struct vfs_disk {
  WCHAR   *dir;                             /* with a trailing backslash */
  uint64_t limit;
  volatile LONG disabled;
  char    *fp;                              /* host key fingerprint ("" when unknown) */
};

struct vfs_dc {
  sd_mutex lock;
  HANDLE   data, hdr;
  uint32_t vgen;
  uint64_t size;
  int64_t  mtime;
  uint32_t nbits;
  uint8_t *bits;
  BOOL     broken;
};

/* ---- notices ---- */

static void refuse(sd_vfs *v, const WCHAR *dir, const char *why)
{
  sd_vfs_event ev;
  memset(&ev, 0, sizeof(ev));
  ev.kind = SD_VFS_EV_NOTICE;
  ev.code = "disk_cache_refused";
  ev.path = dir;
  ev.detail = why;
  SD_LOGW(VFS_LOG, "disk cache refused: %s", why);
  vfs_event(v, &ev);
}

static void disable(sd_vfs *v, const char *why, DWORD err)
{
  if (v->disk && InterlockedExchange(&v->disk->disabled, 1) == 0)
    SD_LOGW(VFS_LOG, "disk cache disabled for this session: %s (error %u)", why, (unsigned)err);
}

BOOL vfs_disk_enabled(sd_vfs *v) { return v->disk && !InterlockedCompareExchange(&v->disk->disabled, 0, 0); }

/* ---- directory checks (TM-R29) ---- */

static PSID well_known(BYTE auth5, BYTE n, DWORD r0, DWORD r1)
{
  SID_IDENTIFIER_AUTHORITY a = { { 0, 0, 0, 0, 0, 0 } };
  PSID s = NULL;
  a.Value[5] = auth5;
  if (!AllocateAndInitializeSid(&a, n, r0, r1, 0, 0, 0, 0, 0, 0, &s))
    return NULL;
  return s;
}

/* Volume root of a drive or UNC path ("C:\", "\\server\share\"); FALSE for other forms. */
static BOOL volume_root(const WCHAR *dir, WCHAR *out, size_t cap)
{
  size_t n = wcslen(dir), i, seps = 0;
  if (n >= 3 && dir[1] == L':' && dir[2] == L'\\') {
    if (cap < 4) return FALSE;
    out[0] = dir[0]; out[1] = L':'; out[2] = L'\\'; out[3] = 0;
    return TRUE;
  }
  if (n > 2 && dir[0] == L'\\' && dir[1] == L'\\' && dir[2] != L'?' && dir[2] != L'.') {
    for (i = 2; i < n; i++) {
      if (dir[i] == L'\\' && ++seps == 2) break;
    }
    if (i + 2 > cap) return FALSE;
    memcpy(out, dir, i * sizeof(WCHAR));
    out[i] = L'\\';
    out[i + 1] = 0;
    return seps >= 1;
  }
  return FALSE;
}

static const char *check_dacl(PACL dacl, PSID owner_ok, PSID system, PSID admins, PSID creator, BOOL allow_admins)
{
  DWORD i;
  ACL_SIZE_INFORMATION si;
  if (!dacl)
    return "the directory has no DACL (everyone has access)";
  if (!GetAclInformation(dacl, &si, sizeof(si), AclSizeInformation))
    return "the directory DACL cannot be read";
  for (i = 0; i < si.AceCount; i++) {
    ACE_HEADER *hd = NULL;
    ACCESS_MASK mask;
    PSID sid;
    if (!GetAce(dacl, i, (LPVOID *)&hd) || !hd)
      return "the directory DACL cannot be read";
    if (hd->AceType == ACCESS_DENIED_ACE_TYPE || hd->AceType == SYSTEM_AUDIT_ACE_TYPE)
      continue;                             /* denies and audits grant nothing */
    if (hd->AceType != ACCESS_ALLOWED_ACE_TYPE)
      return "the directory DACL has an unsupported allow entry";
    mask = ((ACCESS_ALLOWED_ACE *)hd)->Mask;
    sid = (PSID)&((ACCESS_ALLOWED_ACE *)hd)->SidStart;
    if (!(mask & ~(ACCESS_MASK)(SYNCHRONIZE | READ_CONTROL | FILE_READ_ATTRIBUTES)))
      continue;                             /* no read or write of data */
    if (EqualSid(sid, owner_ok) || EqualSid(sid, system) || (allow_admins && EqualSid(sid, admins)))
      continue;
    if (EqualSid(sid, creator) && (hd->AceFlags & INHERIT_ONLY_ACE))
      continue;                             /* CREATOR OWNER on children: that is us */
    return "the directory DACL grants access to another account";
  }
  return NULL;
}

static const char *check_dir(sd_vfs *v, const WCHAR *dir, BOOL service)
{
  HANDLE h;
  BY_HANDLE_FILE_INFORMATION bi;
  PSID owner = NULL, system = NULL, admins = NULL, creator = NULL;
  PACL dacl = NULL;
  PSECURITY_DESCRIPTOR sd = NULL;
  const char *why = NULL;
  WCHAR root[MAX_PATH + 2];
  DWORD flags = 0;

  h = CreateFileW(dir, FILE_READ_ATTRIBUTES | READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                  NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  if (h == INVALID_HANDLE_VALUE)
    return "the directory cannot be opened";
  if (!GetFileInformationByHandle(h, &bi)) {
    CloseHandle(h);
    return "the directory cannot be queried";
  }
  if (bi.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
    why = "the directory is a reparse point (junction or symbolic link)";
  else if (!(bi.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
    why = "the path is not a directory";
  if (!why && GetSecurityInfo(h, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner,
                              NULL, &dacl, NULL, &sd) != ERROR_SUCCESS)
    why = "the directory security cannot be read";
  CloseHandle(h);
  if (!why) {
    system = well_known(5, 1, SECURITY_LOCAL_SYSTEM_RID, 0);
    admins = well_known(5, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS);
    creator = well_known(3, 1, SECURITY_CREATOR_OWNER_RID, 0);
    if (!system || !admins || !creator || !owner || !v->owner_sid)
      why = "the directory owner cannot be checked";
    else if (service ? !(EqualSid(owner, system) || EqualSid(owner, admins)) : !EqualSid(owner, v->owner_sid))
      why = "the directory has an unexpected owner";
    else
      why = check_dacl(dacl, service ? system : v->owner_sid, system, admins, creator, service);
  }
  if (!why) {
    if (!volume_root(dir, root, SD_COUNTOF(root)))
      why = "the directory is not on a drive or share root path";
    else if (!GetVolumeInformationW(root, NULL, 0, NULL, NULL, &flags, NULL, 0))
      why = "the volume cannot be queried";
    else if (!(flags & FILE_PERSISTENT_ACLS))
      why = "the volume has no persistent ACLs (FAT, exFAT or portable media)";
  }
  if (sd) LocalFree(sd);
  if (system) FreeSid(system);
  if (admins) FreeSid(admins);
  if (creator) FreeSid(creator);
  return why;
}

void vfs_disk_open(sd_vfs *v, const sd_vfs_options *o, const char *host_fp)
{
  struct vfs_disk *d;
  const char *why;
  size_t n;
  if (!o->disk_cache_mb)
    return;
  if (!o->disk_cache_dir || !o->disk_cache_dir[0]) {
    refuse(v, NULL, "no cache directory was given");
    return;
  }
  why = check_dir(v, o->disk_cache_dir, o->global_mount);
  if (why) {
    refuse(v, o->disk_cache_dir, why);
    return;
  }
  d = (struct vfs_disk *)sd_calloc(1, sizeof(*d));
  n = wcslen(o->disk_cache_dir);
  if (d) d->dir = (WCHAR *)sd_alloc((n + 2) * sizeof(WCHAR));
  if (d) d->fp = vfs_strndup(host_fp ? host_fp : "", host_fp ? strlen(host_fp) : 0);
  if (!d || !d->dir || !d->fp) {
    if (d) { sd_free(d->dir); sd_free(d->fp); sd_free(d); }
    refuse(v, o->disk_cache_dir, "out of memory");
    return;
  }
  memcpy(d->dir, o->disk_cache_dir, n * sizeof(WCHAR));
  if (n && d->dir[n - 1] != L'\\') d->dir[n++] = L'\\';
  d->dir[n] = 0;
  d->limit = (uint64_t)o->disk_cache_mb << 20;
  v->disk = d;
  vfs_disk_trim(v);                         /* at startup (02 §4.2) */
  SD_LOGI(VFS_LOG, "disk cache enabled (%u MB)", (unsigned)o->disk_cache_mb);
}

void vfs_disk_close(sd_vfs *v)
{
  if (!v->disk)
    return;
  sd_free(v->disk->dir);
  sd_free(v->disk->fp);
  sd_free(v->disk);
  v->disk = NULL;
}

/* ---- trim (LRU by last use, 02 §4.2) ---- */

typedef struct trim_ent { WCHAR name[VDC_NAME + 1]; int64_t last_use; uint64_t bytes; } trim_ent;

static int cmp_last_use(const void *a, const void *b)
{
  const trim_ent *x = (const trim_ent *)a, *y = (const trim_ent *)b;
  return x->last_use < y->last_use ? -1 : x->last_use > y->last_use ? 1 : 0;
}

static WCHAR *path_of(const struct vfs_disk *d, const WCHAR *name, const WCHAR *ext)
{
  size_t a = wcslen(d->dir), b = wcslen(name), c = wcslen(ext);
  WCHAR *p = (WCHAR *)sd_alloc((a + b + c + 1) * sizeof(WCHAR));
  if (p) {
    memcpy(p, d->dir, a * sizeof(WCHAR));
    memcpy(p + a, name, b * sizeof(WCHAR));
    memcpy(p + a + b, ext, (c + 1) * sizeof(WCHAR));
  }
  return p;
}

static uint64_t file_size(const WCHAR *path)
{
  WIN32_FILE_ATTRIBUTE_DATA fa;
  if (!GetFileAttributesExW(path, GetFileExInfoStandard, &fa))
    return 0;
  return ((uint64_t)fa.nFileSizeHigh << 32) | fa.nFileSizeLow;
}

void vfs_disk_trim(sd_vfs *v)
{
  struct vfs_disk *d = v->disk;
  WIN32_FIND_DATAW fd;
  HANDLE fh;
  WCHAR *pat;
  trim_ent *list = NULL;
  uint32_t n = 0, cap = 0, i;
  uint64_t total = 0;
  if (!d)
    return;
  pat = path_of(d, L"*", L".hdr");
  if (!pat)
    return;
  fh = FindFirstFileExW(pat, FindExInfoStandard, &fd, FindExSearchNameMatch, NULL, 0);
  sd_free(pat);
  if (fh == INVALID_HANDLE_VALUE)
    return;
  do {
    size_t nl = wcslen(fd.cFileName);
    WCHAR *hp, *dp;
    HANDLE h;
    dc_hdr hdr;
    DWORD got = 0;
    trim_ent *e;
    if (nl != VDC_NAME + 4 || (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
      continue;
    if (n == cap) {
      uint32_t nc = cap ? cap * 2 : 64;
      trim_ent *nlst = (trim_ent *)sd_realloc(list, (size_t)nc * sizeof(*nlst));
      if (!nlst) break;
      list = nlst;
      cap = nc;
    }
    e = &list[n];
    memcpy(e->name, fd.cFileName, VDC_NAME * sizeof(WCHAR));
    e->name[VDC_NAME] = 0;
    e->last_use = 0;
    hp = path_of(d, e->name, L".hdr");
    dp = path_of(d, e->name, L".dat");
    if (hp) {
      h = CreateFileW(hp, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
      if (h != INVALID_HANDLE_VALUE) {
        if (ReadFile(h, &hdr, sizeof(hdr), &got, NULL) && got == sizeof(hdr) && hdr.magic == VDC_MAGIC)
          e->last_use = hdr.last_use;
        CloseHandle(h);
      }
    }
    /* Logical size: the allocated size of a sparse file is smaller, so this trims conservatively. */
    e->bytes = (hp ? file_size(hp) : 0) + (dp ? file_size(dp) : 0);
    total += e->bytes;
    sd_free(hp);
    sd_free(dp);
    n++;
  } while (FindNextFileW(fh, &fd));
  FindClose(fh);
  if (total > d->limit && n > 0) {
    qsort(list, n, sizeof(*list), cmp_last_use);
    for (i = 0; i < n && total > d->limit; i++) {
      WCHAR *dp = path_of(d, list[i].name, L".dat"), *hp = path_of(d, list[i].name, L".hdr");
      if (dp && hp && (DeleteFileW(dp) || GetLastError() == ERROR_FILE_NOT_FOUND) && DeleteFileW(hp))
        total -= list[i].bytes;             /* an entry in use fails the first delete: skipped */
      sd_free(dp);
      sd_free(hp);
    }
  }
  sd_free(list);
}

/* ---- entries ---- */

static void hex_name(const struct vfs_disk *d, const char *rpath, WCHAR out[VDC_NAME + 1])
{
  static const char hx[] = "0123456789abcdef";
  sd_hash_ctx c;
  uint8_t h[32];
  uint32_t i;
  sd_hash_init(&c, SD_HASH_SHA256);
  sd_hash_update(&c, d->fp, strlen(d->fp) + 1);   /* NUL separates the two parts */
  sd_hash_update(&c, rpath, strlen(rpath));
  sd_hash_final(&c, h);
  for (i = 0; i < 32; i++) {
    out[i * 2] = (WCHAR)hx[h[i] >> 4];
    out[i * 2 + 1] = (WCHAR)hx[h[i] & 15];
  }
  out[VDC_NAME] = 0;
}

static BOOL write_at(HANDLE h, uint64_t off, const void *p, DWORD n)
{
  OVERLAPPED ov;
  DWORD done = 0;
  memset(&ov, 0, sizeof(ov));
  ov.Offset = (DWORD)off;
  ov.OffsetHigh = (DWORD)(off >> 32);
  return WriteFile(h, p, n, &done, &ov) && done == n;
}

static BOOL read_at(HANDLE h, uint64_t off, void *p, DWORD n)
{
  OVERLAPPED ov;
  DWORD done = 0;
  memset(&ov, 0, sizeof(ov));
  ov.Offset = (DWORD)off;
  ov.OffsetHigh = (DWORD)(off >> 32);
  return ReadFile(h, p, n, &done, &ov) && done == n;
}

static uint32_t bitmap_bytes(uint32_t nbits) { return (nbits + 7) / 8; }

/* dc->lock held */
static void hdr_write(sd_vfs *v, struct vfs_dc *dc)
{
  dc_hdr hd;
  uint32_t nb = bitmap_bytes(dc->nbits);
  LARGE_INTEGER z;
  if (dc->broken)
    return;
  memset(&hd, 0, sizeof(hd));
  hd.magic = VDC_MAGIC;
  hd.version = VDC_VERSION;
  hd.size = dc->size;
  hd.mtime = dc->mtime;
  hd.last_use = sd_unix_time_now();
  hd.nblocks = dc->nbits;
  z.QuadPart = (LONGLONG)(sizeof(hd) + nb);
  if (!write_at(dc->hdr, 0, &hd, sizeof(hd)) || (nb && !write_at(dc->hdr, sizeof(hd), dc->bits, nb)) ||
      !SetFilePointerEx(dc->hdr, z, NULL, FILE_BEGIN) || !SetEndOfFile(dc->hdr)) {
    dc->broken = TRUE;
    disable(v, "cache header write failed", GetLastError());
  }
}

/* dc->lock held: forgets every block and truncates the data file. */
static void dc_reset(sd_vfs *v, struct vfs_dc *dc, uint64_t size, int64_t mtime)
{
  LARGE_INTEGER z;
  z.QuadPart = 0;
  if (!SetFilePointerEx(dc->data, z, NULL, FILE_BEGIN) || !SetEndOfFile(dc->data)) {
    dc->broken = TRUE;
    disable(v, "cache truncate failed", GetLastError());
  }
  sd_free(dc->bits);
  dc->bits = NULL;
  dc->nbits = 0;
  dc->size = size;
  dc->mtime = mtime;
  hdr_write(v, dc);
}

static BOOL bit_get(const struct vfs_dc *dc, uint64_t blk)
{
  return blk < dc->nbits && (dc->bits[blk >> 3] & (1u << (blk & 7))) != 0;
}

static void bit_clear(struct vfs_dc *dc, uint64_t blk)
{
  if (blk < dc->nbits)
    dc->bits[blk >> 3] &= (uint8_t)~(1u << (blk & 7));
}

static BOOL bit_set(struct vfs_dc *dc, uint64_t blk)
{
  if (blk >= 0x7FFFFFF0u)
    return FALSE;
  if (blk >= dc->nbits) {
    uint32_t nbits = (uint32_t)blk + 1, nb = bitmap_bytes(nbits), ob = bitmap_bytes(dc->nbits);
    uint8_t *b = (uint8_t *)sd_realloc(dc->bits, nb);
    if (!b)
      return FALSE;
    memset(b + ob, 0, nb - ob);
    dc->bits = b;
    dc->nbits = nbits;
  }
  dc->bits[blk >> 3] |= (uint8_t)(1u << (blk & 7));
  return TRUE;
}

static uint32_t block_len(const struct vfs_dc *dc, uint64_t blk)
{
  uint64_t bo = blk << VFS_BLK_SHIFT;
  if (bo >= dc->size)
    return 0;
  return (uint32_t)SD_MIN((uint64_t)VFS_BLK, dc->size - bo);
}

struct vfs_dc *vfs_dc_open(sd_vfs *v, const char *rpath, uint64_t size, int64_t mtime, uint32_t vgen)
{
  struct vfs_disk *d = v->disk;
  struct vfs_dc *dc;
  WCHAR name[VDC_NAME + 1], *dp, *hp;
  dc_hdr hd;
  DWORD got = 0, err;
  BOOL fresh, keep = FALSE;
  if (!vfs_disk_enabled(v) || !rpath)
    return NULL;
  hex_name(d, rpath, name);
  dp = path_of(d, name, L".dat");
  hp = path_of(d, name, L".hdr");
  dc = (struct vfs_dc *)sd_calloc(1, sizeof(*dc));
  if (!dp || !hp || !dc) {
    sd_free(dp); sd_free(hp); sd_free(dc);
    return NULL;
  }
  dc->data = CreateFileW(dp, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS,
                         FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, NULL);
  err = GetLastError();
  fresh = dc->data != INVALID_HANDLE_VALUE && err != ERROR_ALREADY_EXISTS;
  if (dc->data != INVALID_HANDLE_VALUE)
    dc->hdr = CreateFileW(hp, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS,
                          FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, NULL);
  sd_free(dp);
  sd_free(hp);
  if (dc->data == INVALID_HANDLE_VALUE || dc->hdr == INVALID_HANDLE_VALUE || !dc->hdr) {
    /* In use by another mount of the same profile, or an I/O problem: no disk tier for this file. */
    if (dc->data != INVALID_HANDLE_VALUE) CloseHandle(dc->data);
    sd_free(dc);
    return NULL;
  }
  if (fresh) {
    DWORD br = 0;
    DeviceIoControl(dc->data, FSCTL_SET_SPARSE, NULL, 0, NULL, 0, &br, NULL);   /* FAT: plain file */
  }
  sd_mutex_init(&dc->lock);
  dc->vgen = vgen;
  if (!fresh && ReadFile(dc->hdr, &hd, sizeof(hd), &got, NULL) && got == sizeof(hd) && hd.magic == VDC_MAGIC &&
      hd.version == VDC_VERSION && hd.size == size && hd.mtime == mtime && hd.nblocks < 0x7FFFFFF0u) {
    uint32_t nb = bitmap_bytes(hd.nblocks);
    dc->bits = nb ? (uint8_t *)sd_alloc(nb) : NULL;
    if (!nb || (dc->bits && ReadFile(dc->hdr, dc->bits, nb, &got, NULL) && got == nb)) {
      dc->nbits = hd.nblocks;
      dc->size = size;
      dc->mtime = mtime;
      keep = TRUE;
    }
  }
  sd_mutex_lock(&dc->lock);
  if (keep)
    hdr_write(v, dc);                       /* refresh last use */
  else
    dc_reset(v, dc, size, mtime);           /* validator changed (or new): truncate (02 §4.2) */
  sd_mutex_unlock(&dc->lock);
  return dc;
}

void vfs_dc_close(sd_vfs *v, struct vfs_dc *dc)
{
  if (!dc)
    return;
  sd_mutex_lock(&dc->lock);
  hdr_write(v, dc);
  sd_mutex_unlock(&dc->lock);
  CloseHandle(dc->data);
  CloseHandle(dc->hdr);
  sd_mutex_destroy(&dc->lock);
  sd_free(dc->bits);
  sd_free(dc);
}

int vfs_dc_read(sd_vfs *v, struct vfs_dc *dc, uint32_t vgen, uint64_t blk, uint8_t *buf, uint32_t *len, int *eof)
{
  int r = 0;
  if (!dc || !vfs_disk_enabled(v))
    return 0;
  sd_mutex_lock(&dc->lock);
  if (!dc->broken && dc->vgen == vgen && bit_get(dc, blk)) {
    uint32_t n = block_len(dc, blk);
    if (n && read_at(dc->data, blk << VFS_BLK_SHIFT, buf, n)) {
      *len = n;
      *eof = ((blk << VFS_BLK_SHIFT) + n == dc->size);
      r = 1;
    } else {
      bit_clear(dc, blk);
    }
  }
  sd_mutex_unlock(&dc->lock);
  return r;
}

void vfs_dc_write(sd_vfs *v, struct vfs_dc *dc, uint32_t vgen, uint64_t blk, const uint8_t *buf, uint32_t len)
{
  if (!dc || !vfs_disk_enabled(v))
    return;
  sd_mutex_lock(&dc->lock);
  /* Only whole blocks that agree with the recorded size (the last one may be short). */
  if (!dc->broken && dc->vgen == vgen && len && len == block_len(dc, blk) && !bit_get(dc, blk)) {
    if (write_at(dc->data, blk << VFS_BLK_SHIFT, buf, len)) {
      if (bit_set(dc, blk))
        hdr_write(v, dc);
    } else {
      dc->broken = TRUE;
      disable(v, "cache data write failed", GetLastError());
    }
  }
  sd_mutex_unlock(&dc->lock);
}

int vfs_dc_has(struct vfs_dc *dc, uint32_t vgen, uint64_t blk)
{
  int r;
  if (!dc)
    return 0;
  sd_mutex_lock(&dc->lock);
  r = !dc->broken && dc->vgen == vgen && bit_get(dc, blk);
  sd_mutex_unlock(&dc->lock);
  return r;
}

void vfs_dc_drop_range(sd_vfs *v, struct vfs_dc *dc, uint64_t off, uint64_t end)
{
  uint64_t b, last;
  BOOL any = FALSE;
  if (!dc || end <= off)
    return;
  sd_mutex_lock(&dc->lock);
  last = (end - 1) >> VFS_BLK_SHIFT;
  for (b = off >> VFS_BLK_SHIFT; b <= last && b < dc->nbits; b++) {
    if (bit_get(dc, b)) {
      bit_clear(dc, b);
      any = TRUE;
    }
  }
  if (any)
    hdr_write(v, dc);
  sd_mutex_unlock(&dc->lock);
}

void vfs_dc_set_validator(sd_vfs *v, struct vfs_dc *dc, uint32_t vgen, uint64_t size, int64_t mtime)
{
  if (!dc)
    return;
  sd_mutex_lock(&dc->lock);
  if (dc->vgen != vgen) {
    dc->vgen = vgen;
    dc_reset(v, dc, size, mtime);
  } else if (dc->size != size || dc->mtime != mtime) {
    /* Our own writes: their blocks were dropped already; the blocks that hold the old and the new
       end of file change length, so they go too. */
    uint64_t b, lo = SD_MIN(dc->size, size) >> VFS_BLK_SHIFT;
    for (b = lo; b < dc->nbits; b++)
      if (b >= lo) bit_clear(dc, b);
    dc->size = size;
    dc->mtime = mtime;
    hdr_write(v, dc);
  }
  sd_mutex_unlock(&dc->lock);
}
