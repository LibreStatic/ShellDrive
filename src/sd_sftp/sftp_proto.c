/* SFTP v3 codec (01 §10.1, §10.2). */
#include <string.h>

#include "sftp_proto.h"

/* ---- status mapping (01 §10.2) ---- */

sd_err sd_sftp_status_to_err(uint32_t st)
{
  switch (st) {
  case 0:  return SD_OK;
  case 1:  return SD_E_EOF;
  case 2: case 10: return SD_E_NOT_FOUND;
  case 3: case 22: return SD_E_ACCESS_DENIED;
  case 4:  return SD_E_FAILURE;
  case 5:  return SD_E_PROTOCOL;
  case 6: case 7: return SD_E_DISCONNECTED;
  case 8:  return SD_E_UNSUPPORTED;
  case 9:  return SD_E_STALE_HANDLE;
  case 11: return SD_E_EXISTS;
  case 12: return SD_E_READ_ONLY;
  case 14: return SD_E_NO_SPACE;
  case 15: return SD_E_QUOTA;
  case 17: case 25: return SD_E_LOCK_CONFLICT;
  case 18: return SD_E_NOT_EMPTY;
  case 19: return SD_E_NOT_A_DIRECTORY;
  case 20: return SD_E_INVALID_NAME;
  case 21: return SD_E_LINK_LOOP;
  case 16: case 23: case 31: case 32: return SD_E_INVALID_PARAM;
  case 24: return SD_E_IS_A_DIRECTORY;
  default: return SD_E_FAILURE;
  }
}

/* ---- attributes ---- */

#define SFTP_ATTR_KNOWN (SD_SFTP_ATTR_SIZE | SD_SFTP_ATTR_UIDGID | SD_SFTP_ATTR_PERM | SD_SFTP_ATTR_TIMES | \
                         SD_SFTP_ATTR_EXTENDED)

static uint32_t clamp_time(int64_t t)
{
  if (t < 0) return 0;
  if (t > (int64_t)UINT32_MAX) return UINT32_MAX;
  return (uint32_t)t;
}

void sftp_enc_attrs(sd_wr *w, const sd_sftp_attrs *a)
{
  uint32_t f = a ? (a->valid & (SD_SFTP_ATTR_SIZE | SD_SFTP_ATTR_UIDGID | SD_SFTP_ATTR_PERM | SD_SFTP_ATTR_TIMES)) : 0;
  sd_wr_u32(w, f);
  if (f & SD_SFTP_ATTR_SIZE) sd_wr_u64(w, a->size);
  if (f & SD_SFTP_ATTR_UIDGID) { sd_wr_u32(w, a->uid); sd_wr_u32(w, a->gid); }
  if (f & SD_SFTP_ATTR_PERM) sd_wr_u32(w, a->perm);
  if (f & SD_SFTP_ATTR_TIMES) { sd_wr_u32(w, clamp_time(a->atime)); sd_wr_u32(w, clamp_time(a->mtime)); }
}

int sftp_dec_attrs(sd_rd *r, sd_sftp_attrs *a, sd_sftp_extattr *ext, uint32_t ext_cap)
{
  uint32_t f;
  memset(a, 0, sizeof(*a));
  f = sd_rd_u32(r);
  if (!sd_rd_ok(r) || (f & ~(uint32_t)SFTP_ATTR_KNOWN)) return -1;
  a->valid = f & ~(uint32_t)SD_SFTP_ATTR_EXTENDED;
  if (f & SD_SFTP_ATTR_SIZE) a->size = sd_rd_u64(r);
  if (f & SD_SFTP_ATTR_UIDGID) { a->uid = sd_rd_u32(r); a->gid = sd_rd_u32(r); }
  if (f & SD_SFTP_ATTR_PERM) a->perm = sd_rd_u32(r);
  if (f & SD_SFTP_ATTR_TIMES) { a->atime = (int64_t)sd_rd_u32(r); a->mtime = (int64_t)sd_rd_u32(r); }
  if (f & SD_SFTP_ATTR_EXTENDED) {
    uint32_t i, count = sd_rd_u32(r);
    size_t total = 0;
    if (!sd_rd_ok(r) || count > SFTP_MAX_EXT_PAIRS) return -1;
    for (i = 0; i < count; i++) {
      sd_span t = sd_rd_string(r, SFTP_MAX_EXT_BYTES);
      sd_span d = sd_rd_string(r, SFTP_MAX_EXT_BYTES);
      if (!sd_rd_ok(r)) return -1;
      total += t.n + d.n;
      if (total > SFTP_MAX_EXT_BYTES) return -1;
      if (ext && i < ext_cap) {
        ext[i].type = (const char *)t.p; ext[i].type_len = (uint32_t)t.n;
        ext[i].data = d.p;               ext[i].data_len = (uint32_t)d.n;
      }
    }
    if (ext) {
      a->ext = ext;
      a->ext_count = count < ext_cap ? count : ext_cap;
      if (a->ext_count == 0) a->ext = NULL;
    }
  }
  return sd_rd_ok(r) ? 0 : -1;
}

int sftp_count_attr_ext(const sd_rd *r, uint32_t *pairs)
{
  sd_rd c = *r;
  sd_sftp_attrs a;
  uint32_t f;
  sd_rd peek = *r;
  *pairs = 0;
  f = sd_rd_u32(&peek);
  if (!sd_rd_ok(&peek)) return -1;
  if (sftp_dec_attrs(&c, &a, NULL, 0) != 0) return -1;
  if (f & SD_SFTP_ATTR_EXTENDED) {
    if (f & SD_SFTP_ATTR_SIZE) (void)sd_rd_u64(&peek);
    if (f & SD_SFTP_ATTR_UIDGID) (void)sd_rd_u64(&peek);
    if (f & SD_SFTP_ATTR_PERM) (void)sd_rd_u32(&peek);
    if (f & SD_SFTP_ATTR_TIMES) (void)sd_rd_u64(&peek);
    *pairs = sd_rd_u32(&peek);
  }
  return 0;
}

int sftp_dirent_name_ok(const uint8_t *name, size_t len)
{
  size_t i;
  if (len == 0) return 0;
  if (len == 1 && name[0] == '.') return 0;
  if (len == 2 && name[0] == '.' && name[1] == '.') return 0;
  for (i = 0; i < len; i++)
    if (name[i] == 0 || name[i] == '/') return 0;
  return 1;
}

/* ---- VERSION and extensions ---- */

typedef struct ext_def { const char *name; const char *version; uint32_t bit; } ext_def;
static const ext_def k_exts[] = {
  { "posix-rename@openssh.com",       "1", SD_SFTP_EXT_POSIX_RENAME },
  { "statvfs@openssh.com",            "2", SD_SFTP_EXT_STATVFS },
  { "fstatvfs@openssh.com",           "2", SD_SFTP_EXT_FSTATVFS },
  { "hardlink@openssh.com",           "1", SD_SFTP_EXT_HARDLINK },
  { "fsync@openssh.com",              "1", SD_SFTP_EXT_FSYNC },
  { "lsetstat@openssh.com",           "1", SD_SFTP_EXT_LSETSTAT },
  { "limits@openssh.com",             "1", SD_SFTP_EXT_LIMITS },
  { "expand-path@openssh.com",        "1", SD_SFTP_EXT_EXPAND_PATH },
  { "copy-data",                      "1", SD_SFTP_EXT_COPY_DATA },
  { "home-directory",                 "1", SD_SFTP_EXT_HOME_DIRECTORY },
  { "users-groups-by-id@openssh.com", "1", SD_SFTP_EXT_USERS_GROUPS_BY_ID },
};

static int span_eq(const uint8_t *p, size_t n, const char *s)
{
  size_t l = strlen(s);
  return l == n && memcmp(p, s, n) == 0;
}

uint32_t sftp_ext_bit(const uint8_t *name, size_t nlen, const uint8_t *ver, size_t vlen)
{
  size_t i;
  for (i = 0; i < SD_COUNTOF(k_exts); i++)
    if (span_eq(name, nlen, k_exts[i].name))
      return span_eq(ver, vlen, k_exts[i].version) ? k_exts[i].bit : 0;
  return 0;
}

int sftp_parse_version(const uint8_t *p, size_t n, sftp_version_info *out)
{
  sd_rd r;
  static const char suffix[] = "@openssh.com";
  memset(out, 0, sizeof(*out));
  sd_rd_init(&r, p, n);
  out->version = sd_rd_u32(&r);
  if (!sd_rd_ok(&r)) return -1;
  while (sd_rd_remaining(&r) > 0) {
    sd_span nm = sd_rd_string(&r, 4096), vr = sd_rd_string(&r, 4096);
    if (!sd_rd_ok(&r)) return -1;
    if (out->ext_count >= SFTP_MAX_EXTENSIONS) continue;   /* keep the first 256, ignore the rest */
    out->names[out->ext_count] = nm;
    out->versions[out->ext_count] = vr;
    out->ext_count++;
    out->ext |= sftp_ext_bit(nm.p, nm.n, vr.p, vr.n);
    if (nm.n > sizeof(suffix) - 1 && memcmp(nm.p + nm.n - (sizeof(suffix) - 1), suffix, sizeof(suffix) - 1) == 0)
      out->any_openssh = 1;
  }
  return 0;
}

int sftp_parse_limits(sd_rd *r, uint64_t v[4])
{
  int i;
  for (i = 0; i < 4; i++) v[i] = sd_rd_u64(r);
  return sd_rd_ok(r) ? 0 : -1;
}

int sftp_parse_statvfs(sd_rd *r, sd_sftp_statvfs *v)
{
  v->bsize = sd_rd_u64(r);  v->frsize = sd_rd_u64(r); v->blocks = sd_rd_u64(r);
  v->bfree = sd_rd_u64(r);  v->bavail = sd_rd_u64(r); v->files = sd_rd_u64(r);
  v->ffree = sd_rd_u64(r);  v->favail = sd_rd_u64(r); v->fsid = sd_rd_u64(r);
  v->flag = sd_rd_u64(r);   v->namemax = sd_rd_u64(r);
  return sd_rd_ok(r) ? 0 : -1;
}

void sftp_effective_limits(const uint64_t raw[4], sd_sftp_limits *out)
{
  uint64_t pkt = raw[0] ? raw[0] : SFTP_DEFAULT_PACKET;
  uint64_t rd = raw[1] ? raw[1] : SFTP_DEFAULT_CHUNK;
  uint64_t wr = raw[2] ? raw[2] : SFTP_DEFAULT_CHUNK;
  if (pkt < 4096) pkt = 4096;                       /* nonsense values: stay workable */
  if (pkt > 16u * 1024u * 1024u) pkt = 16u * 1024u * 1024u;
  if (rd > SFTP_MAX_CHUNK) rd = SFTP_MAX_CHUNK;
  if (wr > SFTP_MAX_CHUNK) wr = SFTP_MAX_CHUNK;
  if (wr > pkt - 1024) wr = pkt - 1024;             /* room for header, handle and offset */
  if (rd < 512) rd = 512;
  if (wr < 512) wr = 512;
  out->max_packet = pkt;
  out->max_read = rd;
  out->max_write = wr;
  out->max_open_handles = raw[3] ? raw[3] : UINT32_MAX;
}

/* ---- framing ---- */

size_t sftp_pkt_begin(sd_wr *w, uint8_t type, int id_present, uint32_t id)
{
  size_t start = w->len;
  sd_wr_u32(w, 0);
  sd_wr_u8(w, type);
  if (id_present) sd_wr_u32(w, id);
  return start;
}

void sftp_pkt_end(sd_wr *w, size_t start)
{
  if (sd_wr_ok(w)) sd_wr_patch_u32(w, start, (uint32_t)(w->len - start - 4));
}

int sftp_is_win_drive_path(const char *p, size_t n)
{
  if (n < 3 || p[0] != '/' || p[2] != ':') return 0;
  if (!((p[1] >= 'A' && p[1] <= 'Z') || (p[1] >= 'a' && p[1] <= 'z'))) return 0;
  return n == 3 || p[3] == '/';
}
