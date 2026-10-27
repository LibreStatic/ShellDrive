/* sd_state codec (03 §8.2.1): encoding and copy-then-validate decoding of the snapshot layout. Pure
 * functions over byte buffers; no kernel objects here (state_section.c maps the section).
 *
 * Every field is read and written at its byte offset, little-endian, so the code does not depend on
 * struct padding or byte order. Offsets are the normative table of 03 §8.2.1. */
#include <windows.h>
#include <string.h>

#include "sd_state/sd_state.h"
#include "sd_base/sd_mem.h"

/* ---- header offsets ---- */
#define H_MAGIC       0u
#define H_LAYOUT      4u    /* u16 */
#define H_HDR_SIZE    6u    /* u16 */
#define H_TOTAL       8u
#define H_ENTRY_SIZE  12u
#define H_COUNT       16u
#define H_SEQ         20u
#define H_PID         24u
#define H_SESSION     28u
#define H_FILETIME    32u   /* u64 */
#define H_FLAGS       40u
#define H_MAX_ENTRIES 44u

/* ---- entry offsets (v1, relative to the entry start) ---- */
#define E_FLAGS       0u
#define E_STATE       4u
#define E_BACKEND     8u
#define E_MOUNT_NUM   12u
#define E_LETTER      16u   /* u16 */
#define E_MOUNT_ID    24u   /* WCHAR[32] */
#define E_PROFILE_ID  88u   /* WCHAR[32] */
#define E_PROFILE_NM  152u  /* WCHAR[128] */
#define E_TARGET      408u  /* WCHAR[260] */
#define E_LABEL       928u  /* WCHAR[64] */
#define E_REMOTE_URL  1056u /* WCHAR[320] */
#define E_RESERVED    1696u /* 96 bytes, zero */

/* the string slots of the v1 entry, in code units */
typedef struct str_slot { uint32_t off; uint32_t cch; } str_slot;
static const str_slot k_slots[] = {
  { E_MOUNT_ID, SD_STATE_ID_CCH }, { E_PROFILE_ID, SD_STATE_ID_CCH }, { E_PROFILE_NM, SD_STATE_NAME_CCH },
  { E_TARGET, SD_STATE_TARGET_CCH }, { E_LABEL, SD_STATE_LABEL_CCH }, { E_REMOTE_URL, SD_STATE_URL_CCH }
};

#define KNOWN_ENTRY_FLAGS (SD_STATE_EF_IN_USE | SD_STATE_EF_GLOBAL | SD_STATE_EF_READ_ONLY | \
                           SD_STATE_EF_HAS_REMOTE_URL | SD_STATE_EF_TRUNCATED | SD_STATE_EF_NEEDS_ADMIN | \
                           SD_STATE_EF_NETWORK_LOCATION)

/* ---- little-endian field access ---- */

static uint32_t rd16(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8); }

static uint32_t rd32(const uint8_t *p)
{
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t rd64(const uint8_t *p) { return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32); }

static void wr16(uint8_t *p, uint32_t v)
{
  p[0] = (uint8_t)v;
  p[1] = (uint8_t)(v >> 8);
}

static void wr32(uint8_t *p, uint32_t v)
{
  p[0] = (uint8_t)v;
  p[1] = (uint8_t)(v >> 8);
  p[2] = (uint8_t)(v >> 16);
  p[3] = (uint8_t)(v >> 24);
}

static void wr64(uint8_t *p, uint64_t v)
{
  wr32(p, (uint32_t)v);
  wr32(p + 4, (uint32_t)(v >> 32));
}

static void wr_unit(uint8_t *p, wchar_t u)
{
  p[0] = (uint8_t)((uint32_t)u & 0xFFu);
  p[1] = (uint8_t)(((uint32_t)u >> 8) & 0xFFu);
}

static wchar_t rd_unit(const uint8_t *p) { return (wchar_t)rd16(p); }

/* ---- seqlock access to the seq word ---- */

/* Reads on the reader side never write: a read-only mapping cannot take an interlocked operation. */
static uint32_t seq_read(const uint8_t *base)
{
  uint32_t v = *(const volatile uint32_t *)(base + H_SEQ);
  MemoryBarrier();
  return v;
}

/* ---- writer ---- */

static int is_high(wchar_t u) { return u >= 0xD800 && u <= 0xDBFF; }
static int is_low(wchar_t u) { return u >= 0xDC00 && u <= 0xDFFF; }

int sd_state_set_string(wchar_t *dst, uint32_t cch, const wchar_t *src)
{
  uint32_t len = 0, n;
  if (dst == NULL || cch == 0)
    return 0;
  if (src)
    while (src[len] != 0)
      len++;
  n = len;
  if (len > cch) {
    n = cch - 1u;
    if (n > 0 && is_high(src[n - 1]))
      n--;
  }
  if (src && n)
    memcpy(dst, src, n * sizeof(wchar_t));
  dst[n] = 0;
  return len > cch;
}

/* Writes one string into a slot of cch code units. A string of at most cch units fits (a full slot
   without NUL means the slot length, 03 §8.2.1). A longer one is cut to cch - 1 units, never between a
   surrogate pair, NUL-terminated and reported. src is NUL-terminated within cch + 1 units (decoded
   entries carry the NUL of their array). */
static void put_string(uint8_t *slot, uint32_t cch, const wchar_t *src, int *cut)
{
  uint32_t len = 0, n, i;
  if (src)
    while (len <= cch && src[len] != 0)
      len++;
  n = len;
  if (len > cch) {
    n = cch - 1u;
    if (n > 0 && is_high(src[n - 1]))
      n--;
    *cut = 1;
  }
  for (i = 0; i < n; i++)
    wr_unit(slot + 2u * i, src[i]);
  for (; i < cch; i++)
    wr_unit(slot + 2u * i, 0);
}

static int entry_has_bad_state(uint32_t v) { return v >= SD_STATE_S_UNMOUNTED + 1u; }

sd_err sd_state_publish_layout(void *base, size_t size, const sd_state_publish *in, uint32_t layout_version,
                               uint32_t entry_size, uint32_t *truncated_entries)
{
  uint8_t *b = (uint8_t *)base;
  uint64_t total;
  uint32_t i, cuts = 0, flags, pid, session, s;
  uint64_t ft;
  LONG *pseq;

  if (truncated_entries) *truncated_entries = 0;
  if (b == NULL || in == NULL || layout_version == 0 || layout_version > 0xFFFFu)
    return SD_E_INVALID_PARAM;
  if (in->entry_count > SD_STATE_MAX_ENTRIES || (in->entry_count != 0 && in->entries == NULL))
    return SD_E_INVALID_PARAM;
  if (entry_size < SD_STATE_ENTRY_SIZE || entry_size > SD_STATE_ENTRY_SIZE_MAX || (entry_size & 7u))
    return SD_E_INVALID_PARAM;
  total = (uint64_t)SD_STATE_HEADER_SIZE + (uint64_t)in->entry_count * entry_size;
  if (total > (uint64_t)size || total > SD_STATE_MAX_BYTES)
    return SD_E_INVALID_PARAM;
  if (((uintptr_t)b & 3u) != 0)
    return SD_E_INVALID_PARAM;

  pid = in->writer_pid ? in->writer_pid : GetCurrentProcessId();
  session = in->writer_session;
  if (session == 0) {
    DWORD sid = 0;
    if (ProcessIdToSessionId(GetCurrentProcessId(), &sid))
      session = sid;
  }
  ft = in->published_filetime;
  if (ft == 0) {
    FILETIME now;
    GetSystemTimeAsFileTime(&now);
    ft = ((uint64_t)now.dwHighDateTime << 32) | now.dwLowDateTime;
  }

  pseq = (LONG *)(b + H_SEQ);
  /* A stale odd seq (a writer died mid-write) is made even by one increment; then one more makes it odd. */
  s = (uint32_t)InterlockedCompareExchange(pseq, 0, 0);
  if (s & 1u)
    (void)InterlockedIncrement(pseq);
  (void)InterlockedIncrement(pseq);           /* odd: write in progress */
  MemoryBarrier();

  /* header (seq is not touched here) */
  wr32(b + H_MAGIC, SD_STATE_MAGIC);
  wr16(b + H_LAYOUT, layout_version);
  wr16(b + H_HDR_SIZE, SD_STATE_HEADER_SIZE);
  wr32(b + H_TOTAL, (uint32_t)total);
  wr32(b + H_ENTRY_SIZE, entry_size);
  wr32(b + H_COUNT, in->entry_count);
  wr32(b + H_PID, pid);
  wr32(b + H_SESSION, session);
  wr64(b + H_FILETIME, ft);
  wr32(b + H_FLAGS, in->flags & SD_STATE_HF_SHUTTING_DOWN);
  wr32(b + H_MAX_ENTRIES, SD_STATE_MAX_ENTRIES);
  memset(b + 48, 0, 16);

  for (i = 0; i < in->entry_count; i++) {
    const sd_state_entry *src = &in->entries[i];
    uint8_t *e = b + SD_STATE_HEADER_SIZE + (size_t)i * entry_size;
    int cut = 0;
    memset(e, 0, entry_size);
    flags = (src->flags & KNOWN_ENTRY_FLAGS) | SD_STATE_EF_IN_USE;
    if (src->remote_url[0] != 0)
      flags |= SD_STATE_EF_HAS_REMOTE_URL;
    wr32(e + E_FLAGS, flags);
    wr32(e + E_STATE, entry_has_bad_state(src->state) ? SD_STATE_S_UNKNOWN : src->state);
    wr32(e + E_BACKEND, src->backend > SD_STATE_B_DOKANY ? SD_STATE_B_UNKNOWN : src->backend);
    wr32(e + E_MOUNT_NUM, src->mount_num);
    wr16(e + E_LETTER, src->letter);
    put_string(e + k_slots[0].off, k_slots[0].cch, src->mount_id, &cut);
    put_string(e + k_slots[1].off, k_slots[1].cch, src->profile_id, &cut);
    put_string(e + k_slots[2].off, k_slots[2].cch, src->profile_name, &cut);
    put_string(e + k_slots[3].off, k_slots[3].cch, src->target, &cut);
    put_string(e + k_slots[4].off, k_slots[4].cch, src->label, &cut);
    put_string(e + k_slots[5].off, k_slots[5].cch, src->remote_url, &cut);
    if (cut) {
      wr32(e + E_FLAGS, rd32(e + E_FLAGS) | SD_STATE_EF_TRUNCATED);
      cuts++;
    }
  }

  MemoryBarrier();
  (void)InterlockedIncrement(pseq);           /* even: stable */
  if (truncated_entries) *truncated_entries = cuts;
  return SD_OK;
}

sd_err sd_state_publish_buffer(void *base, size_t size, const sd_state_publish *in, uint32_t *truncated_entries)
{
  return sd_state_publish_layout(base, size, in, SD_STATE_LAYOUT_V1, SD_STATE_ENTRY_SIZE, truncated_entries);
}

/* ---- reader ---- */

/* Decodes one string slot. Returns 0 when the UTF-16 is invalid (unpaired surrogate). An unterminated
   full slot is its slot length (03 §8.2.1). */
static int get_string(const uint8_t *slot, uint32_t cch, wchar_t *dst)
{
  uint32_t n = 0, i;
  while (n < cch && rd_unit(slot + 2u * n) != 0)
    n++;
  for (i = 0; i < n; i++) {
    wchar_t u = rd_unit(slot + 2u * i);
    if (is_high(u)) {
      if (i + 1 >= n || !is_low(rd_unit(slot + 2u * (i + 1))))
        return 0;
      i++;
    } else if (is_low(u)) {
      return 0;
    }
  }
  for (i = 0; i < n; i++)
    dst[i] = rd_unit(slot + 2u * i);
  dst[n] = 0;
  return 1;
}

/* profile_id: empty, or exactly SD_STATE_ID_CCH lowercase hex digits (03 §8.2.1). */
static int profile_id_ok(const wchar_t *id)
{
  uint32_t i;
  if (id[0] == 0)
    return 1;
  for (i = 0; i < SD_STATE_ID_CCH; i++) {
    wchar_t c = id[i];
    if (!((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f')))
      return 0;
  }
  return id[SD_STATE_ID_CCH] == 0;
}

/* Decodes one v1-stride entry. Returns 0 when the entry must be dropped. */
static int decode_entry(const uint8_t *e, sd_state_entry *d)
{
  uint32_t flags = rd32(e + E_FLAGS), st, bk, letter;
  size_t i;
  memset(d, 0, sizeof(*d));
  if (!(flags & SD_STATE_EF_IN_USE))
    return 0;
  d->flags = flags & KNOWN_ENTRY_FLAGS;
  st = rd32(e + E_STATE);
  d->state = st > SD_STATE_S_UNMOUNTED ? SD_STATE_S_UNKNOWN : st;
  bk = rd32(e + E_BACKEND);
  d->backend = bk > SD_STATE_B_DOKANY ? SD_STATE_B_UNKNOWN : bk;
  d->mount_num = rd32(e + E_MOUNT_NUM);
  letter = rd16(e + E_LETTER);
  if (letter != 0 && (letter < L'A' || letter > L'Z'))
    return 0;
  d->letter = (uint16_t)letter;
  for (i = 0; i < sizeof(k_slots) / sizeof(k_slots[0]); i++) {
    wchar_t *dst = NULL;
    switch (i) {
    case 0: dst = d->mount_id; break;
    case 1: dst = d->profile_id; break;
    case 2: dst = d->profile_name; break;
    case 3: dst = d->target; break;
    case 4: dst = d->label; break;
    default: dst = d->remote_url; break;
    }
    if (!get_string(e + k_slots[i].off, k_slots[i].cch, dst))
      return 0;
  }
  if (!profile_id_ok(d->profile_id))
    return 0;
  return 1;
}

/* Validates the header of a complete copy and decodes its entries. */
static sd_err parse_copy(const uint8_t *c, uint64_t avail, sd_state_snapshot *snap)
{
  uint32_t layout, hsize, total, esize, count, i, n = 0;
  uint64_t need;
  if (avail < SD_STATE_HEADER_SIZE)
    return SD_E_INVALID_PARAM;
  if (rd32(c + H_MAGIC) != SD_STATE_MAGIC)
    return SD_E_INVALID_PARAM;
  layout = rd16(c + H_LAYOUT);
  if (layout < SD_STATE_LAYOUT_V1 || layout > SD_STATE_LAYOUT_READER_MAX)
    return SD_E_INVALID_PARAM;
  hsize = rd16(c + H_HDR_SIZE);
  total = rd32(c + H_TOTAL);
  esize = rd32(c + H_ENTRY_SIZE);
  count = rd32(c + H_COUNT);
  if (hsize < SD_STATE_HEADER_SIZE || hsize > total)
    return SD_E_INVALID_PARAM;
  if (esize < SD_STATE_ENTRY_SIZE || esize > SD_STATE_ENTRY_SIZE_MAX || (esize & 7u))
    return SD_E_INVALID_PARAM;
  if (count > SD_STATE_MAX_ENTRIES)
    return SD_E_INVALID_PARAM;
  need = (uint64_t)hsize + (uint64_t)count * esize;
  if (need != total || total > SD_STATE_MAX_BYTES || total > avail)
    return SD_E_INVALID_PARAM;

  memset(&snap->header, 0, sizeof(snap->header));
  snap->header.layout_version = layout;
  snap->header.header_size = hsize;
  snap->header.total_size = total;
  snap->header.entry_size = esize;
  snap->header.entry_count = count;
  snap->header.seq = rd32(c + H_SEQ);
  snap->header.writer_pid = rd32(c + H_PID);
  snap->header.writer_session = rd32(c + H_SESSION);
  snap->header.published_filetime = rd64(c + H_FILETIME);
  snap->header.flags = rd32(c + H_FLAGS);
  snap->header.max_entries = rd32(c + H_MAX_ENTRIES);

  snap->dropped = 0;
  for (i = 0; i < count; i++) {
    const uint8_t *e = c + hsize + (size_t)i * esize;
    if (decode_entry(e, &snap->entries[n]))
      n++;
    else
      snap->dropped++;
  }
  snap->count = n;
  return SD_OK;
}

sd_err sd_state_read_buffer(const void *base, size_t size, sd_state_snapshot *snap)
{
  const uint8_t *b = (const uint8_t *)base;
  uint32_t t, s1, s2;
  if (b == NULL || snap == NULL || snap->entries == NULL || snap->copy == NULL || size < SD_STATE_HEADER_SIZE)
    return SD_E_INVALID_PARAM;
  for (t = 1; t <= SD_STATE_READ_TRIES; t++) {
    uint32_t total, copy_len;
    s1 = seq_read(b);
    if (s1 & 1u)
      continue;                                  /* a write is in progress */
    /* the header first, to learn the length; a torn header only makes this copy fail the seq check */
    memcpy(snap->copy, b, SD_STATE_HEADER_SIZE);
    MemoryBarrier();
    total = rd32(snap->copy + H_TOTAL);
    copy_len = SD_STATE_HEADER_SIZE;
    if (total >= SD_STATE_HEADER_SIZE && total <= SD_STATE_MAX_BYTES && total <= size) {
      memcpy(snap->copy, b, total);
      copy_len = total;
    }
    MemoryBarrier();
    s2 = seq_read(b);
    if (s1 != s2)
      continue;                                  /* changed while copying: retry */
    snap->attempts = t;
    if (copy_len != total)
      return SD_E_INVALID_PARAM;                 /* header length invalid, stable */
    return parse_copy(snap->copy, copy_len, snap);
  }
  snap->attempts = SD_STATE_READ_TRIES;
  snap->count = 0;
  return SD_E_BUSY;
}

sd_err sd_state_snapshot_new(sd_state_snapshot **out)
{
  sd_state_snapshot *s;
  if (out == NULL)
    return SD_E_INVALID_PARAM;
  *out = NULL;
  s = (sd_state_snapshot *)sd_calloc(1, sizeof(*s));
  if (s == NULL)
    return SD_E_NO_MEMORY;
  s->entries = (sd_state_entry *)sd_calloc(SD_STATE_MAX_ENTRIES, sizeof(sd_state_entry));
  s->copy = (uint8_t *)sd_alloc(SD_STATE_MAX_BYTES);
  if (s->entries == NULL || s->copy == NULL) {
    sd_free(s->entries);
    sd_free(s->copy);
    sd_free(s);
    return SD_E_NO_MEMORY;
  }
  *out = s;
  return SD_OK;
}

void sd_state_snapshot_free(sd_state_snapshot *s)
{
  if (s == NULL)
    return;
  sd_free(s->entries);
  sd_free(s->copy);
  sd_free(s);
}

const char *sd_state_state_name(uint32_t state)
{
  static const char *const names[] = {
    "unknown", "connecting", "authenticating", "mounted", "offline", "auth_required", "failed", "unmounting",
    "unmounted"
  };
  return state < sizeof(names) / sizeof(names[0]) ? names[state] : "unknown";
}
