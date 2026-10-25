/* Memory tier of the data cache (02 §4.2): global per process, shared by all mounts, 256 KiB
 * blocks, LRU in 16 shards with one lock each. Key: (mount id, file id, validator generation, block
 * index). A validator change bumps the node's generation, so stale blocks are never found again;
 * vc_drop_file reclaims them at once.
 *
 * Locking: a shard lock is the innermost vfs lock (02 §5.5): callers may hold v->lock, and nothing
 * is called with a shard lock held. sd_sftp completions never come here (review §4.1 rule 1); a
 * reader copying a block under the shard lock stalls only that shard. */
#include <windows.h>

#include "sd_base/sd_mem.h"
#include "sd_platform/sd_thread.h"
#include "sd_platform/sd_time.h"
#include "vfs_internal.h"

#define VC_SHARDS    16u
#define VC_MIN_BYTES (16ull << 20)
#define VC_MAX_DEF   (256ull << 20)

typedef struct vc_ent {
  struct vc_ent *hnext, *prev, *next;   /* hash chain; LRU (head = oldest) */
  vc_key   k;
  uint32_t hash;
  uint32_t len;
  uint8_t  eof, hot;
  uint64_t tick;                        /* fetch time, for hot blocks */
  uint8_t *data;                        /* VFS_BLK bytes */
} vc_ent;

typedef struct vc_shard {
  sd_mutex cs;
  vc_ent **tab; uint32_t nb, count;
  vc_ent *head, *tail;
  uint64_t bytes;
} vc_shard;

static vc_shard g_sh[VC_SHARDS];
static sd_once  g_once = SD_ONCE_INIT;
static volatile LONG64 g_budget, g_hits, g_misses, g_evictions, g_mount_ids;

static uint64_t default_budget(void)
{
  MEMORYSTATUSEX ms;
  uint64_t b = VC_MAX_DEF;
  memset(&ms, 0, sizeof(ms));
  ms.dwLength = sizeof(ms);
  if (GlobalMemoryStatusEx(&ms) && ms.ullTotalPhys / 16 < b)
    b = ms.ullTotalPhys / 16;
  return b < VC_MIN_BYTES ? VC_MIN_BYTES : b;
}

static void set64(volatile LONG64 *p, LONG64 v)
{
  LONG64 old;
  do {
    old = sd_atomic_load64(p);
  } while (_InterlockedCompareExchange64(p, v, old) != old);
}

static void init_once(void *arg)
{
  uint32_t i;
  SD_UNUSED(arg);
  for (i = 0; i < VC_SHARDS; i++)
    sd_mutex_init(&g_sh[i].cs);
  if (sd_atomic_load64(&g_budget) == 0)
    set64(&g_budget, (LONG64)default_budget());
}

static void vc_init(void) { sd_once_run(&g_once, init_once, NULL); }

static uint32_t key_hash(const vc_key *k)
{
  uint64_t h = k->mount_id * 0x9E3779B97F4A7C15ull;
  h ^= k->file_id + 0x632BE59BD9B4E019ull + (h << 6) + (h >> 2);
  h ^= k->blk * 0xC2B2AE3D27D4EB4Full + (h << 6) + (h >> 2);
  h ^= (uint64_t)k->vgen * 0x165667B19E3779F9ull;
  h ^= h >> 31;
  return (uint32_t)(h ^ (h >> 32));
}

static BOOL key_eq(const vc_key *a, const vc_key *b)
{
  return a->mount_id == b->mount_id && a->file_id == b->file_id && a->blk == b->blk && a->vgen == b->vgen;
}

static vc_shard *shard_of(uint32_t h) { return &g_sh[(h >> 24) % VC_SHARDS]; }

static uint64_t shard_budget(void)
{
  uint64_t b = (uint64_t)sd_atomic_load64(&g_budget) / VC_SHARDS;
  return b < VFS_BLK ? VFS_BLK : b;
}

/* ---- shard internals (shard lock held) ---- */

static vc_ent *find(vc_shard *s, const vc_key *k, uint32_t h)
{
  vc_ent *e;
  if (!s->nb)
    return NULL;
  for (e = s->tab[h & (s->nb - 1)]; e; e = e->hnext)
    if (e->hash == h && key_eq(&e->k, k))
      return e;
  return NULL;
}

static void lru_unlink(vc_shard *s, vc_ent *e)
{
  if (e->prev) e->prev->next = e->next; else s->head = e->next;
  if (e->next) e->next->prev = e->prev; else s->tail = e->prev;
  e->prev = e->next = NULL;
}

static void lru_append(vc_shard *s, vc_ent *e)
{
  e->prev = s->tail;
  e->next = NULL;
  if (s->tail) s->tail->next = e; else s->head = e;
  s->tail = e;
}

static void remove_ent(vc_shard *s, vc_ent *e)
{
  vc_ent **pp;
  for (pp = &s->tab[e->hash & (s->nb - 1)]; *pp; pp = &(*pp)->hnext) {
    if (*pp == e) {
      *pp = e->hnext;
      break;
    }
  }
  lru_unlink(s, e);
  s->count--;
  s->bytes -= VFS_BLK;
  sd_free(e->data);
  sd_free(e);
}

static void grow(vc_shard *s)
{
  uint32_t nb = s->nb ? s->nb * 2 : 64, i;
  vc_ent **t = (vc_ent **)sd_calloc(nb, sizeof(*t));
  if (!t)
    return;                                 /* longer chains; still correct */
  for (i = 0; i < s->nb; i++) {
    vc_ent *e = s->tab[i], *next;
    for (; e; e = next) {
      next = e->hnext;
      e->hnext = t[e->hash & (nb - 1)];
      t[e->hash & (nb - 1)] = e;
    }
  }
  sd_free(s->tab);
  s->tab = t;
  s->nb = nb;
}

static void evict_to(vc_shard *s, uint64_t limit)
{
  while (s->head && s->bytes > limit) {
    remove_ent(s, s->head);
    sd_atomic_inc64(&g_evictions);
  }
}

/* ---- API ---- */

int vc_read(const vc_key *k, uint32_t rel, void *dst, uint32_t want, uint32_t *got, int *eof, uint32_t hot_ttl)
{
  uint32_t h = key_hash(k);
  vc_shard *s;
  vc_ent *e;
  int hit = 0;
  vc_init();
  *got = 0;
  *eof = 0;
  s = shard_of(h);
  sd_mutex_lock(&s->cs);
  e = find(s, k, h);
  if (e && e->hot && sd_tick_ms() - e->tick > hot_ttl) {
    remove_ent(s, e);                       /* hot blocks are not trusted past attr_ttl (02 §4.2) */
    e = NULL;
  }
  if (e) {
    if (rel < e->len) {
      uint32_t n = SD_MIN(want, e->len - rel);
      memcpy(dst, e->data + rel, n);
      *got = n;
      *eof = (n < want) && e->eof;
      hit = (n == want) || e->eof;
    } else if (e->eof) {
      *eof = 1;
      hit = 1;
    }
    if (hit) {
      lru_unlink(s, e);
      lru_append(s, e);
    }
  }
  sd_mutex_unlock(&s->cs);
  sd_atomic_inc64(hit ? &g_hits : &g_misses);
  return hit;
}

int vc_contains(const vc_key *k, uint32_t hot_ttl)
{
  uint32_t h = key_hash(k);
  vc_shard *s;
  vc_ent *e;
  int r;
  vc_init();
  s = shard_of(h);
  sd_mutex_lock(&s->cs);
  e = find(s, k, h);
  r = e && !(e->hot && sd_tick_ms() - e->tick > hot_ttl) && (e->len == VFS_BLK || e->eof);
  sd_mutex_unlock(&s->cs);
  return r;
}

void vc_put(const vc_key *k, const void *data, uint32_t len, int eof, int hot)
{
  uint32_t h = key_hash(k);
  vc_shard *s;
  vc_ent *e;
  uint8_t *d;
  vc_init();
  if (len > VFS_BLK)
    return;
  s = shard_of(h);
  sd_mutex_lock(&s->cs);
  e = find(s, k, h);
  if (!e) {
    uint64_t limit = shard_budget();
    sd_mutex_unlock(&s->cs);
    /* Allocate outside the lock; a concurrent put of the same key is resolved below. */
    d = (uint8_t *)sd_alloc(VFS_BLK);
    e = d ? (vc_ent *)sd_calloc(1, sizeof(*e)) : NULL;
    if (!e) {
      sd_free(d);
      return;                               /* best effort */
    }
    e->data = d;
    e->k = *k;
    e->hash = h;
    sd_mutex_lock(&s->cs);
    if (find(s, k, h)) {
      sd_mutex_unlock(&s->cs);
      sd_free(e->data);
      sd_free(e);
      vc_put(k, data, len, eof, hot);       /* replace the winner's content */
      return;
    }
    evict_to(s, limit > VFS_BLK ? limit - VFS_BLK : 0);
    if (s->count + 1 > s->nb)
      grow(s);
    if (!s->nb) {
      sd_mutex_unlock(&s->cs);
      sd_free(e->data);
      sd_free(e);
      return;
    }
    e->hnext = s->tab[h & (s->nb - 1)];
    s->tab[h & (s->nb - 1)] = e;
    s->count++;
    s->bytes += VFS_BLK;
    lru_append(s, e);
  } else {
    lru_unlink(s, e);
    lru_append(s, e);
  }
  memcpy(e->data, data, len);
  e->len = len;
  e->eof = (uint8_t)(eof ? 1 : 0);
  e->hot = (uint8_t)(hot ? 1 : 0);
  e->tick = sd_tick_ms();
  sd_mutex_unlock(&s->cs);
}

void vc_write(const vc_key *k, uint32_t rel, const void *data, uint32_t n)
{
  uint32_t h = key_hash(k);
  vc_shard *s;
  vc_ent *e;
  vc_init();
  s = shard_of(h);
  sd_mutex_lock(&s->cs);
  e = find(s, k, h);
  if (e) {
    if (rel > e->len || (uint64_t)rel + n > VFS_BLK) {
      remove_ent(s, e);                     /* would leave a gap: drop rather than guess */
    } else {
      memcpy(e->data + rel, data, n);
      if (rel + n > e->len) {
        e->len = rel + n;                   /* extends the file inside this block */
        if (e->len == VFS_BLK) e->eof = 0;
      }
    }
  }
  sd_mutex_unlock(&s->cs);
}

void vc_drop(const vc_key *k)
{
  uint32_t h = key_hash(k);
  vc_shard *s;
  vc_ent *e;
  vc_init();
  s = shard_of(h);
  sd_mutex_lock(&s->cs);
  e = find(s, k, h);
  if (e)
    remove_ent(s, e);
  sd_mutex_unlock(&s->cs);
}

static void drop_where(uint64_t mount_id, BOOL all_files, uint64_t file_id)
{
  uint32_t i;
  vc_init();
  for (i = 0; i < VC_SHARDS; i++) {
    vc_shard *s = &g_sh[i];
    vc_ent *e, *next;
    sd_mutex_lock(&s->cs);
    for (e = s->head; e; e = next) {
      next = e->next;
      if (e->k.mount_id == mount_id && (all_files || e->k.file_id == file_id))
        remove_ent(s, e);
    }
    sd_mutex_unlock(&s->cs);
  }
}

void vc_drop_file(uint64_t mount_id, uint64_t file_id) { drop_where(mount_id, FALSE, file_id); }
void vc_drop_mount(uint64_t mount_id) { drop_where(mount_id, TRUE, 0); }

uint64_t vc_new_mount_id(void) { return (uint64_t)sd_atomic_inc64(&g_mount_ids); }

void sd_vfs_cache_set_budget(UINT64 bytes)
{
  uint32_t i;
  uint64_t b = bytes ? bytes : default_budget();
  if (b < VC_MIN_BYTES)
    b = VC_MIN_BYTES;
  set64(&g_budget, (LONG64)b);
  vc_init();
  for (i = 0; i < VC_SHARDS; i++) {
    sd_mutex_lock(&g_sh[i].cs);
    evict_to(&g_sh[i], shard_budget());
    sd_mutex_unlock(&g_sh[i].cs);
  }
}

void sd_vfs_cache_get_stats(sd_vfs_cache_stats *out)
{
  uint32_t i;
  if (!out)
    return;
  memset(out, 0, sizeof(*out));
  vc_init();
  out->budget = (UINT64)sd_atomic_load64(&g_budget);
  for (i = 0; i < VC_SHARDS; i++) {
    sd_mutex_lock(&g_sh[i].cs);
    out->used += g_sh[i].bytes;
    out->blocks += g_sh[i].count;
    sd_mutex_unlock(&g_sh[i].cs);
  }
  out->hits = (UINT64)sd_atomic_load64(&g_hits);
  out->misses = (UINT64)sd_atomic_load64(&g_misses);
  out->evictions = (UINT64)sd_atomic_load64(&g_evictions);
}
