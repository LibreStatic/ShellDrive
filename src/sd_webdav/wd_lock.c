/* sd_webdav: in-memory WebDAV write locks per export (02 §7.5 "Lock manager").
 *
 * Exclusive and shared write locks with timeouts (<= 3600 s). Keyed by vfs path (case-insensitive,
 * like the default case-insensitive view); MOVE re-keys them so renames carry locks. Expired locks are
 * dropped lazily on every access. Not propagated to SFTP. */
#include <windows.h>
#include <string.h>
#include <wchar.h>

#include "sd_base/sd_mem.h"
#include "sd_platform/sd_time.h"
#include "wd_server.h"

static void lock_free(wd_lock *l)
{
  sd_free(l->path);
  sd_free(l->owner);
  sd_free(l);
}

void wd_locks_free(sd_webdav_export *ex)
{
  while (ex->locks) {
    wd_lock *n = ex->locks->next;
    lock_free(ex->locks);
    ex->locks = n;
  }
}

static void sweep(sd_webdav_export *ex)
{
  wd_lock **pp = &ex->locks;
  uint64_t now = sd_tick_ms();
  while (*pp) {
    if ((*pp)->expires <= now) {
      wd_lock *d = *pp;
      *pp = d->next;
      lock_free(d);
    } else {
      pp = &(*pp)->next;
    }
  }
}

/* Is p equal to or below base? */
static int under(const WCHAR *p, const WCHAR *base)
{
  size_t bl = wcslen(base);
  if (bl == 1 && base[0] == L'\\')
    return 1;
  if (_wcsnicmp(p, base, bl) != 0)
    return 0;
  return p[bl] == 0 || p[bl] == L'\\';
}

static int covers(const wd_lock *l, const WCHAR *path, int with_children)
{
  if (_wcsicmp(l->path, path) == 0)
    return 1;
  if (l->depth_inf && under(path, l->path))
    return 1;
  if (with_children && under(l->path, path))
    return 1;
  return 0;
}

static int submitted(const wd_lock *l, char toks[][80], uint32_t ntok)
{
  uint32_t i;
  for (i = 0; i < ntok; i++)
    if (strcmp(toks[i], l->token) == 0)
      return 1;
  return 0;
}

/* A shared lock is satisfied when any shared lock on the same resource was submitted. */
static int shared_submitted(const wd_lock *head, const WCHAR *lpath, char toks[][80], uint32_t ntok)
{
  const wd_lock *o;
  for (o = head; o != NULL; o = o->next)
    if (!o->exclusive && _wcsicmp(o->path, lpath) == 0 && submitted(o, toks, ntok))
      return 1;
  return 0;
}

int wd_lock_conflict(sd_webdav_export *ex, const WCHAR *path, int with_children, char toks[][80], uint32_t ntok)
{
  wd_lock *l;
  int conflict = 0;
  sd_mutex_lock(&ex->lock_mu);
  sweep(ex);
  for (l = ex->locks; l != NULL && !conflict; l = l->next) {
    if (covers(l, path, with_children) && !submitted(l, toks, ntok) &&
        (l->exclusive || !shared_submitted(ex->locks, l->path, toks, ntok)))
      conflict = 1;
  }
  sd_mutex_unlock(&ex->lock_mu);
  return conflict;
}

int wd_lock_create(sd_webdav_export *ex, const WCHAR *path, int exclusive, int depth_inf, uint32_t timeout_s,
                   const char *owner, char token_out[64])
{
  wd_lock *l, *n;
  char uuid[37];
  size_t pl = wcslen(path);
  sd_mutex_lock(&ex->lock_mu);
  sweep(ex);
  for (l = ex->locks; l; l = l->next) {
    if (covers(l, path, depth_inf) && (exclusive || l->exclusive)) {
      sd_mutex_unlock(&ex->lock_mu);
      return 423;
    }
  }
  n = (wd_lock *)sd_calloc(1, sizeof(*n));
  if (n) n->path = (WCHAR *)sd_alloc((pl + 1) * sizeof(WCHAR));
  if (n && owner && owner[0]) {
    size_t ol = strlen(owner);
    n->owner = (char *)sd_alloc(ol + 1);
    if (n->owner) memcpy(n->owner, owner, ol + 1);
  }
  if (n == NULL || n->path == NULL || (owner && owner[0] && n->owner == NULL)) {
    if (n) lock_free(n);
    sd_mutex_unlock(&ex->lock_mu);
    return 500;
  }
  memcpy(n->path, path, (pl + 1) * sizeof(WCHAR));
  wd_uuid(uuid);
  memcpy(n->token, "opaquelocktoken:", 16);
  memcpy(n->token + 16, uuid, 37);
  n->exclusive = exclusive;
  n->depth_inf = depth_inf;
  n->timeout_s = timeout_s;
  n->expires = sd_tick_ms() + (uint64_t)timeout_s * 1000u;
  n->next = ex->locks;
  ex->locks = n;
  memcpy(token_out, n->token, sizeof(n->token));
  sd_mutex_unlock(&ex->lock_mu);
  return 0;
}

int wd_lock_refresh(sd_webdav_export *ex, const WCHAR *path, char toks[][80], uint32_t ntok, uint32_t timeout_s,
                    char token_out[64])
{
  wd_lock *l;
  int rc = 412;
  sd_mutex_lock(&ex->lock_mu);
  sweep(ex);
  for (l = ex->locks; l; l = l->next) {
    if (covers(l, path, 0) && submitted(l, toks, ntok)) {
      l->timeout_s = timeout_s;
      l->expires = sd_tick_ms() + (uint64_t)timeout_s * 1000u;
      memcpy(token_out, l->token, sizeof(l->token));
      rc = 0;
      break;
    }
  }
  sd_mutex_unlock(&ex->lock_mu);
  return rc;
}

int wd_lock_remove(sd_webdav_export *ex, const WCHAR *path, const char *token)
{
  wd_lock **pp;
  int rc = 409;
  sd_mutex_lock(&ex->lock_mu);
  sweep(ex);
  for (pp = &ex->locks; *pp; pp = &(*pp)->next) {
    if (strcmp((*pp)->token, token) == 0 && covers(*pp, path, 0)) {
      wd_lock *d = *pp;
      *pp = d->next;
      lock_free(d);
      rc = 0;
      break;
    }
  }
  sd_mutex_unlock(&ex->lock_mu);
  return rc;
}

void wd_lock_move(sd_webdav_export *ex, const WCHAR *from, const WCHAR *to)
{
  wd_lock *l;
  size_t fl = wcslen(from), tl = wcslen(to);
  sd_mutex_lock(&ex->lock_mu);
  for (l = ex->locks; l; l = l->next) {
    if (under(l->path, from)) {
      size_t rest = wcslen(l->path) - fl;
      WCHAR *np = (WCHAR *)sd_alloc((tl + rest + 1) * sizeof(WCHAR));
      if (np) {
        memcpy(np, to, tl * sizeof(WCHAR));
        memcpy(np + tl, l->path + fl, (rest + 1) * sizeof(WCHAR));
        sd_free(l->path);
        l->path = np;
      }
    }
  }
  sd_mutex_unlock(&ex->lock_mu);
}

void wd_lock_drop_tree(sd_webdav_export *ex, const WCHAR *path)
{
  wd_lock **pp = &ex->locks;
  sd_mutex_lock(&ex->lock_mu);
  while (*pp) {
    if (under((*pp)->path, path)) {
      wd_lock *d = *pp;
      *pp = d->next;
      lock_free(d);
    } else {
      pp = &(*pp)->next;
    }
  }
  sd_mutex_unlock(&ex->lock_mu);
}

void wd_lock_discovery(sd_webdav_export *ex, const WCHAR *path, wd_sb *b, const char *only_token)
{
  wd_lock *l;
  uint64_t now = sd_tick_ms();
  wd_sb_str(b, "<D:lockdiscovery>");
  sd_mutex_lock(&ex->lock_mu);
  sweep(ex);
  for (l = ex->locks; l; l = l->next) {
    uint64_t left;
    if (only_token ? strcmp(l->token, only_token) != 0 : !covers(l, path, 0))
      continue;
    left = l->expires > now ? (l->expires - now + 999u) / 1000u : 0;
    wd_sb_str(b, "<D:activelock><D:locktype><D:write/></D:locktype><D:lockscope>");
    wd_sb_str(b, l->exclusive ? "<D:exclusive/>" : "<D:shared/>");
    wd_sb_str(b, "</D:lockscope>");
    wd_sb_str(b, l->depth_inf ? "<D:depth>infinity</D:depth>" : "<D:depth>0</D:depth>");
    if (l->owner) {
      wd_sb_str(b, "<D:owner><D:href>");
      wd_sb_xml(b, l->owner, strlen(l->owner));
      wd_sb_str(b, "</D:href></D:owner>");
    }
    wd_sb_fmt(b, "<D:timeout>Second-%llu</D:timeout>", (unsigned long long)left);
    wd_sb_str(b, "<D:locktoken><D:href>");
    wd_sb_str(b, l->token);
    wd_sb_str(b, "</D:href></D:locktoken></D:activelock>");
  }
  sd_mutex_unlock(&ex->lock_mu);
  wd_sb_str(b, "</D:lockdiscovery>");
}
