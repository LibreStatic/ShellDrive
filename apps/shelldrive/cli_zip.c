/* Stored ZIP writer (see cli_zip.h). No I/O of its own: every byte goes through the sink, so the unit tests
 * check the exact layout from memory. */
#include <windows.h>
#include <string.h>

#include "cli_zip.h"
#include "sd_base/sd_mem.h"

#define ZIP_MAX_ENTRIES   65535u
#define ZIP_MAX_BYTES     0xFFFFFFFFull
#define ZIP_MAX_NAME      255u
#define ZIP_FLAGS         0x0808u     /* bit 3: data descriptor, bit 11: UTF-8 names */
#define ZIP_VERSION       20u         /* 2.0: stored entries, data descriptors */

#define ZIP_SIG_LOCAL     0x04034b50u
#define ZIP_SIG_DESC      0x08074b50u
#define ZIP_SIG_CENTRAL   0x02014b50u
#define ZIP_SIG_END       0x06054b50u

typedef struct zip_entry {
  char *name;
  uint32_t crc, size, offset;
  uint16_t dos_time, dos_date;
} zip_entry;

struct zip_writer {
  zip_sink_fn sink;
  void *ctx;
  uint64_t written;
  zip_entry *entries;
  uint32_t count, cap;
  int open;                    /* an entry is being written */
  int finished;
  zip_entry cur;               /* the open entry */
  uint32_t cur_crc;
  uint64_t cur_size;
  sd_err err;                  /* sticky: the sink failed or a limit was reached */
};

/* ---- CRC-32 ---- */

static uint32_t crc_table[256];
static volatile LONG crc_ready;     /* read and written only through the Interlocked functions */

static void crc_init(void)
{
  uint32_t i, k;
  if (InterlockedCompareExchange(&crc_ready, 0, 0) != 0)
    return;
  for (i = 0; i < 256; i++) {
    uint32_t c = i;
    for (k = 0; k < 8; k++)
      c = (c & 1u) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
    crc_table[i] = c;
  }
  InterlockedExchange(&crc_ready, 1);
}

uint32_t zip_crc32(uint32_t crc, const void *p, size_t n)
{
  const unsigned char *b = (const unsigned char *)p;
  size_t i;
  crc_init();
  crc = ~crc;
  for (i = 0; i < n; i++)
    crc = crc_table[(crc ^ b[i]) & 0xFFu] ^ (crc >> 8);
  return ~crc;
}

/* ---- little-endian output ---- */

static sd_err emit(zip_writer *w, const void *p, size_t n)
{
  if (w->err != SD_OK)
    return w->err;
  if ((uint64_t)n > ZIP_MAX_BYTES - w->written) {
    w->err = SD_E_FAILURE;
    return w->err;
  }
  if (w->sink(w->ctx, p, n) != 0) {
    w->err = SD_E_FAILURE;
    return w->err;
  }
  w->written += n;
  return SD_OK;
}

static void put16(zip_writer *w, uint16_t v)
{
  unsigned char b[2];
  b[0] = (unsigned char)(v & 0xFF);
  b[1] = (unsigned char)(v >> 8);
  emit(w, b, 2);
}

static void put32(zip_writer *w, uint32_t v)
{
  unsigned char b[4];
  b[0] = (unsigned char)(v & 0xFF);
  b[1] = (unsigned char)((v >> 8) & 0xFF);
  b[2] = (unsigned char)((v >> 16) & 0xFF);
  b[3] = (unsigned char)(v >> 24);
  emit(w, b, 4);
}

/* MS-DOS time and date of a SYSTEMTIME; years outside 1980..2107 are clamped. */
static void dos_stamp(const SYSTEMTIME *st, uint16_t *time_out, uint16_t *date_out)
{
  WORD year = st ? st->wYear : 1980, month = st ? st->wMonth : 1, day = st ? st->wDay : 1;
  WORD hour = st ? st->wHour : 0, minute = st ? st->wMinute : 0, second = st ? st->wSecond : 0;
  if (year < 1980) year = 1980;
  if (year > 2107) year = 2107;
  if (month < 1 || month > 12) month = 1;
  if (day < 1 || day > 31) day = 1;
  if (hour > 23) hour = 23;
  if (minute > 59) minute = 59;
  if (second > 59) second = 59;
  *time_out = (uint16_t)((hour << 11) | (minute << 5) | (second / 2));
  *date_out = (uint16_t)(((year - 1980) << 9) | (month << 5) | day);
}

/* ---- API ---- */

zip_writer *zip_open(zip_sink_fn sink, void *ctx)
{
  zip_writer *w;
  if (sink == NULL)
    return NULL;
  w = (zip_writer *)sd_alloc(sizeof(*w));
  if (w == NULL)
    return NULL;
  memset(w, 0, sizeof(*w));
  w->sink = sink;
  w->ctx = ctx;
  return w;
}

void zip_free(zip_writer *w)
{
  uint32_t i;
  if (w == NULL)
    return;
  for (i = 0; i < w->count; i++)
    sd_free(w->entries[i].name);
  sd_free(w->entries);
  sd_free(w->cur.name);
  sd_free(w);
}

static int name_ok(const char *name)
{
  size_t n = name ? strlen(name) : 0;
  if (n == 0 || n > ZIP_MAX_NAME || name[0] == '/')
    return 0;
  if (strstr(name, "..") != NULL || strchr(name, '\\') != NULL)
    return 0;
  return 1;
}

sd_err zip_add_begin(zip_writer *w, const char *name, const SYSTEMTIME *when)
{
  size_t n;
  if (w == NULL || w->finished || w->open)
    return SD_E_INVALID_PARAM;
  if (w->err != SD_OK)
    return w->err;
  if (!name_ok(name))
    return SD_E_INVALID_PARAM;
  if (w->count >= ZIP_MAX_ENTRIES || w->written > ZIP_MAX_BYTES - 64)
    return (w->err = SD_E_FAILURE);
  n = strlen(name);
  sd_free(w->cur.name);
  memset(&w->cur, 0, sizeof(w->cur));
  w->cur.name = (char *)sd_alloc(n + 1);
  if (w->cur.name == NULL)
    return (w->err = SD_E_NO_MEMORY);
  memcpy(w->cur.name, name, n + 1);
  dos_stamp(when, &w->cur.dos_time, &w->cur.dos_date);
  w->cur.offset = (uint32_t)w->written;
  w->cur_crc = 0;
  w->cur_size = 0;
  /* local file header: sizes and CRC are zero, the data descriptor carries them */
  put32(w, ZIP_SIG_LOCAL);
  put16(w, ZIP_VERSION);
  put16(w, ZIP_FLAGS);
  put16(w, 0);                 /* stored */
  put16(w, w->cur.dos_time);
  put16(w, w->cur.dos_date);
  put32(w, 0);
  put32(w, 0);
  put32(w, 0);
  put16(w, (uint16_t)n);
  put16(w, 0);
  emit(w, w->cur.name, n);
  if (w->err != SD_OK)
    return w->err;
  w->open = 1;
  return SD_OK;
}

sd_err zip_add_data(zip_writer *w, const void *p, size_t n)
{
  if (w == NULL || !w->open)
    return SD_E_INVALID_PARAM;
  if (n == 0)
    return w->err;
  if (w->cur_size > ZIP_MAX_BYTES - n)
    return (w->err = SD_E_FAILURE);
  w->cur_crc = zip_crc32(w->cur_crc, p, n);
  w->cur_size += n;
  return emit(w, p, n);
}

sd_err zip_add_end(zip_writer *w)
{
  zip_entry *e;
  if (w == NULL || !w->open)
    return SD_E_INVALID_PARAM;
  w->open = 0;
  if (w->err != SD_OK)
    return w->err;
  put32(w, ZIP_SIG_DESC);
  put32(w, w->cur_crc);
  put32(w, (uint32_t)w->cur_size);
  put32(w, (uint32_t)w->cur_size);
  if (w->err != SD_OK)
    return w->err;
  if (w->count == w->cap) {
    uint32_t nc = w->cap ? w->cap * 2 : 16;
    zip_entry *ne = (zip_entry *)sd_realloc(w->entries, nc * sizeof(zip_entry));
    if (ne == NULL)
      return (w->err = SD_E_NO_MEMORY);
    w->entries = ne;
    w->cap = nc;
  }
  e = &w->entries[w->count++];
  *e = w->cur;
  e->crc = w->cur_crc;
  e->size = (uint32_t)w->cur_size;
  memset(&w->cur, 0, sizeof(w->cur));   /* the name now belongs to the entry */
  return SD_OK;
}

sd_err zip_finish(zip_writer *w)
{
  uint32_t i;
  uint64_t cd_start, cd_size;
  if (w == NULL || w->open || w->finished)
    return SD_E_INVALID_PARAM;
  if (w->err != SD_OK)
    return w->err;
  cd_start = w->written;
  for (i = 0; i < w->count; i++) {
    const zip_entry *e = &w->entries[i];
    size_t n = strlen(e->name);
    put32(w, ZIP_SIG_CENTRAL);
    put16(w, ZIP_VERSION);       /* made by */
    put16(w, ZIP_VERSION);       /* needed to extract */
    put16(w, ZIP_FLAGS);
    put16(w, 0);
    put16(w, e->dos_time);
    put16(w, e->dos_date);
    put32(w, e->crc);
    put32(w, e->size);
    put32(w, e->size);
    put16(w, (uint16_t)n);
    put16(w, 0);                 /* extra */
    put16(w, 0);                 /* comment */
    put16(w, 0);                 /* disk */
    put16(w, 0);                 /* internal attributes */
    put32(w, 0);                 /* external attributes */
    put32(w, e->offset);
    emit(w, e->name, n);
    if (w->err != SD_OK)
      return w->err;
  }
  cd_size = w->written - cd_start;
  if (w->written > ZIP_MAX_BYTES - 22)
    return (w->err = SD_E_FAILURE);
  put32(w, ZIP_SIG_END);
  put16(w, 0);
  put16(w, 0);
  put16(w, (uint16_t)w->count);
  put16(w, (uint16_t)w->count);
  put32(w, (uint32_t)cd_size);
  put32(w, (uint32_t)cd_start);
  put16(w, 0);
  if (w->err != SD_OK)
    return w->err;
  w->finished = 1;
  return SD_OK;
}

uint32_t zip_entry_count(const zip_writer *w)
{
  return w ? w->count : 0;
}

uint64_t zip_bytes(const zip_writer *w)
{
  return w ? w->written : 0;
}
