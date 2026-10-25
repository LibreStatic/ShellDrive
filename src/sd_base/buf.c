#include "sd_base/sd_buf.h"
#include "sd_base/sd_checked.h"
#include "sd_base/sd_mem.h"

#include <string.h>

enum { SD_WR_F_FIXED = 1, SD_WR_F_SECRET = 2 };

/* ---- reader ---- */

static void rd_fail(sd_rd *r)
{
  r->err = 1;
  r->n = 0;
}

void sd_rd_init(sd_rd *r, const void *p, size_t n)
{
  r->p = (const uint8_t *)p;
  r->n = p ? n : 0;
  r->err = 0;
}

static const uint8_t *rd_take(sd_rd *r, size_t n)
{
  const uint8_t *q;
  if (r->err || n > r->n) {
    rd_fail(r);
    return NULL;
  }
  q = r->p;
  r->p += n;
  r->n -= n;
  return q;
}

uint8_t sd_rd_u8(sd_rd *r)
{
  const uint8_t *q = rd_take(r, 1);
  return q ? q[0] : 0;
}

uint32_t sd_rd_u32(sd_rd *r)
{
  const uint8_t *q = rd_take(r, 4);
  return q ? sd_load_be32(q) : 0;
}

uint64_t sd_rd_u64(sd_rd *r)
{
  const uint8_t *q = rd_take(r, 8);
  return q ? sd_load_be64(q) : 0;
}

int sd_rd_bool(sd_rd *r)
{
  return sd_rd_u8(r) != 0;
}

sd_span sd_rd_bytes(sd_rd *r, size_t n)
{
  sd_span s = { NULL, 0 };
  const uint8_t *q = rd_take(r, n);
  if (q) {
    s.p = q;
    s.n = n;
  }
  return s;
}

sd_span sd_rd_string(sd_rd *r, size_t max_len)
{
  sd_span s = { NULL, 0 };
  uint32_t len = sd_rd_u32(r);
  if (r->err)
    return s;
  if (len > max_len) {
    rd_fail(r);
    return s;
  }
  return sd_rd_bytes(r, len);
}

sd_span sd_rd_mpint(sd_rd *r, size_t max_bytes)
{
  sd_span s = sd_rd_string(r, max_bytes);
  sd_span empty = { NULL, 0 };
  if (r->err)
    return empty;
  if (s.n == 0)
    return s;                                   /* zero */
  if (s.p[0] & 0x80) {                          /* negative */
    rd_fail(r);
    return empty;
  }
  if (s.p[0] == 0) {
    if (s.n == 1 || (s.p[1] & 0x80) == 0) {     /* zero as "00", or an unneeded sign byte */
      rd_fail(r);
      return empty;
    }
    s.p++;
    s.n--;
  }
  return s;
}

static int namelist_valid(sd_span s)
{
  size_t i, name_len = 0;
  if (s.n == 0)
    return 1;
  for (i = 0; i < s.n; i++) {
    uint8_t c = s.p[i];
    if (c == ',') {
      if (name_len == 0)
        return 0;
      name_len = 0;
    } else if (c < 0x21 || c > 0x7E) {
      return 0;
    } else {
      name_len++;
    }
  }
  return name_len != 0;
}

sd_span sd_rd_name_list(sd_rd *r, size_t max_len)
{
  sd_span s = sd_rd_string(r, max_len);
  sd_span empty = { NULL, 0 };
  if (r->err)
    return empty;
  if (!namelist_valid(s)) {
    rd_fail(r);
    return empty;
  }
  return s;
}

sd_rd sd_rd_sub(sd_rd *r, size_t max_len)
{
  sd_rd sub;
  sd_span s = sd_rd_string(r, max_len);
  sd_rd_init(&sub, s.p, s.n);
  sub.err = r->err;
  return sub;
}

size_t sd_rd_remaining(const sd_rd *r)
{
  return r->err ? 0 : r->n;
}

int sd_rd_ok(const sd_rd *r)
{
  return !r->err;
}

int sd_rd_done(const sd_rd *r)
{
  return !r->err && r->n == 0;
}

int sd_namelist_next(sd_span *list, sd_span *name)
{
  size_t i;
  if (list->n == 0)
    return 0;
  for (i = 0; i < list->n && list->p[i] != ','; i++)
    ;
  name->p = list->p;
  name->n = i;
  if (i < list->n)
    i++;                                        /* skip the comma */
  list->p += i;
  list->n -= i;
  return 1;
}

int sd_namelist_contains(sd_span list, const char *name)
{
  sd_span it;
  size_t n = strlen(name);
  while (sd_namelist_next(&list, &it)) {
    if (it.n == n && memcmp(it.p, name, n) == 0)
      return 1;
  }
  return 0;
}

/* ---- writer ---- */

void sd_wr_init(sd_wr *w, size_t max)
{
  memset(w, 0, sizeof(*w));
  w->max = max;
}

void sd_wr_init_secret(sd_wr *w, size_t max)
{
  sd_wr_init(w, max);
  w->flags = SD_WR_F_SECRET;
}

void sd_wr_init_fixed(sd_wr *w, void *buf, size_t cap)
{
  memset(w, 0, sizeof(*w));
  w->p = (uint8_t *)buf;
  w->cap = buf ? cap : 0;
  w->max = w->cap;
  w->flags = SD_WR_F_FIXED;
}

void sd_wr_free(sd_wr *w)
{
  if (!(w->flags & SD_WR_F_FIXED) && w->p) {
    if (w->flags & SD_WR_F_SECRET)
      sd_secure_free(w->p, w->cap);
    else
      sd_free(w->p);
  }
  w->p = NULL;
  w->len = w->cap = 0;
}

void sd_wr_reset(sd_wr *w)
{
  if ((w->flags & SD_WR_F_SECRET) && w->p)
    sd_secure_zero(w->p, w->len);
  w->len = 0;
  w->err = 0;
}

int sd_wr_ok(const sd_wr *w)
{
  return !w->err;
}

static int wr_grow(sd_wr *w, size_t need)
{
  size_t want, ncap;
  uint8_t *np;
  if (sd_add_ovf(w->len, need, &want) || want > w->max)
    return 0;
  if (want <= w->cap)
    return 1;
  if (w->flags & SD_WR_F_FIXED)
    return 0;
  ncap = w->cap < 64 ? 64 : w->cap;
  while (ncap < want)
    ncap = (ncap > w->max / 2) ? w->max : ncap * 2;
  if (ncap > w->max)
    ncap = w->max;
  if (w->flags & SD_WR_F_SECRET) {
    np = (uint8_t *)sd_alloc(ncap);
    if (np == NULL)
      return 0;
    if (w->p) {
      memcpy(np, w->p, w->len);
      sd_secure_free(w->p, w->cap);
    }
  } else {
    np = (uint8_t *)sd_realloc(w->p, ncap);
    if (np == NULL)
      return 0;
  }
  w->p = np;
  w->cap = ncap;
  return 1;
}

uint8_t *sd_wr_reserve(sd_wr *w, size_t n)
{
  uint8_t *q;
  if (w->err)
    return NULL;
  if (!wr_grow(w, n)) {
    w->err = 1;
    return NULL;
  }
  q = w->p + w->len;
  w->len += n;
  return q;
}

void sd_wr_bytes(sd_wr *w, const void *p, size_t n)
{
  uint8_t *q;
  if (n == 0)
    return;
  q = sd_wr_reserve(w, n);
  if (q)
    memcpy(q, p, n);
}

void sd_wr_u8(sd_wr *w, uint8_t v)
{
  sd_wr_bytes(w, &v, 1);
}

void sd_wr_u32(sd_wr *w, uint32_t v)
{
  uint8_t *q = sd_wr_reserve(w, 4);
  if (q)
    sd_store_be32(q, v);
}

void sd_wr_u64(sd_wr *w, uint64_t v)
{
  uint8_t *q = sd_wr_reserve(w, 8);
  if (q)
    sd_store_be64(q, v);
}

void sd_wr_bool(sd_wr *w, int v)
{
  sd_wr_u8(w, (uint8_t)(v ? 1 : 0));
}

void sd_wr_string(sd_wr *w, const void *p, size_t n)
{
  if (n > UINT32_MAX) {
    w->err = 1;
    return;
  }
  sd_wr_u32(w, (uint32_t)n);
  sd_wr_bytes(w, p, n);
}

void sd_wr_cstring(sd_wr *w, const char *s)
{
  sd_wr_string(w, s, s ? strlen(s) : 0);
}

void sd_wr_mpint(sd_wr *w, const uint8_t *be, size_t n)
{
  int pad;
  while (n > 0 && be[0] == 0) {
    be++;
    n--;
  }
  pad = (n > 0 && (be[0] & 0x80)) ? 1 : 0;
  if (n + (size_t)pad > UINT32_MAX) {
    w->err = 1;
    return;
  }
  sd_wr_u32(w, (uint32_t)(n + (size_t)pad));
  if (pad)
    sd_wr_u8(w, 0);
  sd_wr_bytes(w, be, n);
}

void sd_wr_name_list(sd_wr *w, const char *const *names, size_t count)
{
  size_t i, total = 0, part;
  for (i = 0; i < count; i++) {
    part = strlen(names[i]);
    if (part == 0 || sd_add_ovf(total, part + (i ? 1u : 0u), &total)) {
      w->err = 1;
      return;
    }
  }
  if (total > UINT32_MAX) {
    w->err = 1;
    return;
  }
  sd_wr_u32(w, (uint32_t)total);
  for (i = 0; i < count; i++) {
    if (i)
      sd_wr_u8(w, ',');
    sd_wr_bytes(w, names[i], strlen(names[i]));
  }
}

void sd_wr_patch_u32(sd_wr *w, size_t off, uint32_t v)
{
  if (w->err || off > w->len || w->len - off < 4) {
    w->err = 1;
    return;
  }
  sd_store_be32(w->p + off, v);
}
