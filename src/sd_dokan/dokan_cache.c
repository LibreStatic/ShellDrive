/* Requestor identity cache (dokan_cache.h, 02 6.7). */
#include <windows.h>
#include <string.h>

#include "dokan_cache.h"
#include "sd_base/sd_mem.h"

typedef struct dk_entry {
  BOOL used;
  LUID luid;
  DWORD elev;
  PSID user;                            /* owned */
  PSID *groups;                         /* owned array of owned SIDs */
  UINT n_groups;
  DWORD stored;                         /* GetTickCount when stored */
  DWORD seq;                            /* insertion order: the eviction victim is the lowest */
} dk_entry;

struct dk_cache {
  CRITICAL_SECTION lock;
  dk_entry e[DK_CACHE_SLOTS];
  DWORD next_seq;
};

static PSID sid_copy(PSID s)
{
  DWORD len;
  PSID c;
  if (s == NULL || !IsValidSid(s))
    return NULL;
  len = GetLengthSid(s);
  c = sd_alloc(len);
  if (c == NULL)
    return NULL;
  if (!CopySid(len, c, s)) {
    sd_free(c);
    return NULL;
  }
  return c;
}

void dk_groups_free(PSID *groups, UINT n)
{
  UINT i;
  if (groups == NULL)
    return;
  for (i = 0; i < n; i++)
    sd_free(groups[i]);
  sd_free(groups);
}

/* Copies of n SIDs in a new array; NULL on failure with nothing left allocated. */
static PSID *groups_copy(PSID const *src, UINT n)
{
  PSID *out = (PSID *)sd_calloc(n ? n : 1, sizeof(PSID));
  UINT i;
  if (out == NULL)
    return NULL;
  for (i = 0; i < n; i++) {
    out[i] = sid_copy(src[i]);
    if (out[i] == NULL) {
      dk_groups_free(out, i);           /* entries 0 .. i-1 are owned; i itself was not allocated */
      return NULL;
    }
  }
  return out;
}

static void entry_clear(dk_entry *d)
{
  sd_free(d->user);
  dk_groups_free(d->groups, d->n_groups);
  memset(d, 0, sizeof(*d));
}

static BOOL entry_matches(const dk_entry *d, const LUID *luid, DWORD elev, PSID user)
{
  return d->used && d->luid.LowPart == luid->LowPart && d->luid.HighPart == luid->HighPart && d->elev == elev &&
         EqualSid(d->user, user);
}

dk_cache *dk_cache_new(void)
{
  dk_cache *c = (dk_cache *)sd_calloc(1, sizeof(*c));
  if (c == NULL)
    return NULL;
  InitializeCriticalSection(&c->lock);
  return c;
}

void dk_cache_free(dk_cache *c)
{
  UINT i;
  if (c == NULL)
    return;
  for (i = 0; i < DK_CACHE_SLOTS; i++) {
    if (c->e[i].used)
      entry_clear(&c->e[i]);
  }
  DeleteCriticalSection(&c->lock);
  sd_free(c);
}

BOOL dk_cache_get(dk_cache *c, const LUID *luid, DWORD elev, PSID user, DWORD now, PSID **groups, UINT *n_groups)
{
  UINT i;
  BOOL hit = FALSE;
  *groups = NULL;
  *n_groups = 0;
  if (c == NULL || luid == NULL || user == NULL || !IsValidSid(user))
    return FALSE;
  EnterCriticalSection(&c->lock);
  for (i = 0; i < DK_CACHE_SLOTS; i++) {
    dk_entry *d = &c->e[i];
    if (!entry_matches(d, luid, elev, user))
      continue;
    if (now - d->stored < DK_CACHE_TTL_MS) {  /* unsigned: wrap-safe */
      PSID *g = groups_copy(d->groups, d->n_groups);
      if (g != NULL) {
        *groups = g;
        *n_groups = d->n_groups;
        hit = TRUE;
      }
    } else {
      entry_clear(d);                   /* expired: drop it, the caller reads the token */
    }
    break;
  }
  LeaveCriticalSection(&c->lock);
  return hit;
}

void dk_cache_put(dk_cache *c, const LUID *luid, DWORD elev, PSID user, PSID const *groups, UINT n_groups, DWORD now)
{
  dk_entry fresh;
  UINT i, victim = DK_CACHE_SLOTS;
  if (c == NULL || luid == NULL || user == NULL || !IsValidSid(user))
    return;
  memset(&fresh, 0, sizeof(fresh));
  fresh.user = sid_copy(user);
  fresh.groups = groups_copy(groups, n_groups);
  if (fresh.user == NULL || fresh.groups == NULL) {
    sd_free(fresh.user);
    dk_groups_free(fresh.groups, n_groups);
    return;                             /* nothing stored: a later open reads the token again */
  }
  fresh.used = TRUE;
  fresh.luid = *luid;
  fresh.elev = elev;
  fresh.n_groups = n_groups;
  fresh.stored = now;
  EnterCriticalSection(&c->lock);
  for (i = 0; i < DK_CACHE_SLOTS; i++) {
    if (entry_matches(&c->e[i], luid, elev, user)) {
      victim = i;                       /* refresh the same requestor in place */
      break;
    }
  }
  if (victim == DK_CACHE_SLOTS) {
    for (i = 0; i < DK_CACHE_SLOTS; i++) {
      if (!c->e[i].used) {
        victim = i;                     /* a free slot is always preferred */
        break;
      }
    }
  }
  if (victim == DK_CACHE_SLOTS) {       /* full: evict the oldest insertion (sequence numbers, not times) */
    victim = 0;
    for (i = 1; i < DK_CACHE_SLOTS; i++) {
      if (c->e[i].seq < c->e[victim].seq)
        victim = i;
    }
  }
  if (c->e[victim].used)
    entry_clear(&c->e[victim]);
  fresh.seq = ++c->next_seq;
  c->e[victim] = fresh;
  LeaveCriticalSection(&c->lock);
}
