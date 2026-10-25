/* sd_vfs core: mount/unmount, node table, path resolution, listings, attribute mapping
 * (02 §1, §3.1, §3.4, §4.1, §5). Locking rules: vfs_internal.h. */
#include <windows.h>

#include "sd_base/sd_checked.h"
#include "sd_base/sd_mem.h"
#include "sd_base/sd_utf.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_time.h"
#include "vfs_internal.h"

/* ---- error table (02 §8, C13) ---- */

sd_vfs_status sd_vfs_status_from_err(sd_err e)
{
  switch (e) {
    case SD_OK:                return SD_VFS_OK;
    case SD_E_EOF:             return SD_VFS_E_END_OF_FILE;
    case SD_E_NOT_FOUND:       return SD_VFS_E_NOT_FOUND;
    case SD_E_ACCESS_DENIED:
    case SD_E_LOCK_CONFLICT:   return SD_VFS_E_ACCESS_DENIED;
    case SD_E_EXISTS:          return SD_VFS_E_EXISTS;
    case SD_E_NOT_EMPTY:       return SD_VFS_E_NOT_EMPTY;
    case SD_E_NOT_A_DIRECTORY: return SD_VFS_E_NOT_DIR;
    case SD_E_IS_A_DIRECTORY:  return SD_VFS_E_IS_DIR;
    case SD_E_NO_SPACE:        return SD_VFS_E_NO_SPACE;
    case SD_E_QUOTA:           return SD_VFS_E_QUOTA;
    case SD_E_READ_ONLY:       return SD_VFS_E_READ_ONLY;
    case SD_E_INVALID_NAME:    return SD_VFS_E_INVALID_NAME;
    case SD_E_LINK_LOOP:       return SD_VFS_E_NOT_FOUND;
    case SD_E_NAME_TOO_LONG:   return SD_VFS_E_NAME_TOO_LONG;
    case SD_E_UNSUPPORTED:     return SD_VFS_E_UNSUPPORTED;
    case SD_E_DISCONNECTED:
    case SD_E_SHUTDOWN:
    case SD_E_AUTH_REQUIRED:   return SD_VFS_E_DISCONNECTED;
    case SD_E_STALE_HANDLE:    return SD_VFS_E_STALE;   /* re-opened internally first (vfs_get_fh, 02 §5.3) */
    case SD_E_TIMEOUT:         return SD_VFS_E_TIMEOUT;
    case SD_E_CANCELLED:       return SD_VFS_E_CANCELLED;
    case SD_E_BUSY:            return SD_VFS_E_IO;      /* never surfaced by the vfs: retried as backpressure */
    case SD_E_NO_MEMORY:       return SD_VFS_E_NO_MEMORY;
    default:                   return SD_VFS_E_IO;
  }
}

sd_vfs_status vfs_map_err(sd_err e) { return sd_vfs_status_from_err(e); }

/* ---- small helpers ---- */

uint64_t vfs_deadline(sd_vfs *v) { return sd_tick_ms() + v->req_timeout; }

BOOL vfs_online(sd_vfs *v) { return sd_sftp_session_state(v->s) == SD_SFTP_ST_READY; }

void vfs_event(sd_vfs *v, const sd_vfs_event *ev)
{
  if (v->cb)
    v->cb(v->cb_ctx, ev);
}

void vfs_notice(sd_vfs *v, const char *code, const WCHAR *path)
{
  sd_vfs_event ev;
  memset(&ev, 0, sizeof(ev));
  ev.kind = SD_VFS_EV_NOTICE;
  ev.code = code;
  ev.path = path;
  SD_LOGI(VFS_LOG, "notice %s", code);
  vfs_event(v, &ev);
}

void vfs_attr_from_sftp(vfs_attr *a, const sd_sftp_attrs *s)
{
  memset(a, 0, sizeof(*a));
  a->valid = s->valid & ~SD_SFTP_ATTR_EXTENDED;
  if (s->valid & SD_SFTP_ATTR_SIZE) a->size = s->size;
  if (s->valid & SD_SFTP_ATTR_UIDGID) { a->uid = s->uid; a->gid = s->gid; }
  if (s->valid & SD_SFTP_ATTR_PERM) a->mode = s->perm;
  if (s->valid & SD_SFTP_ATTR_TIMES) { a->atime = s->atime; a->mtime = s->mtime; }
}

sd_vfs_status vfs_join(sd_vfs *v, const char *parent, const char *raw, uint32_t raw_len, char **out)
{
  size_t pl = strlen(parent), n;
  int sep = !(pl > 0 && parent[pl - 1] == '/');
  char *r;
  SD_UNUSED(v);
  *out = NULL;
  /* Wire invariant (TM-R11): asserted here, in the one place that builds remote paths. */
  if (sd_name_component_check(raw, raw_len) != SD_OK) {
    SD_LOGE(VFS_LOG, "bug: remote path component violates the wire invariant; refused");
    return SD_VFS_E_INVALID_NAME;
  }
  if (sd_add_ovf(pl, (size_t)raw_len + 2, &n))
    return SD_VFS_E_NAME_TOO_LONG;
  r = (char *)sd_alloc(n);
  if (!r)
    return SD_VFS_E_NO_MEMORY;
  memcpy(r, parent, pl);
  if (sep) r[pl++] = '/';
  memcpy(r + pl, raw, raw_len);
  r[pl + raw_len] = 0;
  *out = r;
  return SD_VFS_OK;
}

sd_vfs_status vfs_join_under(sd_vfs *v, vfs_node *n, const char *raw, uint32_t raw_len, char **out)
{
  sd_vfs_status st;
  sd_mutex_lock(&v->lock);
  st = vfs_join(v, n->epath, raw, raw_len, out);
  sd_mutex_unlock(&v->lock);
  return st;
}

WCHAR *vfs_wname_copy(sd_vfs *v, vfs_node *n)
{
  WCHAR *r;
  sd_mutex_lock(&v->lock);
  r = vfs_wcsdup(n->wname);
  sd_mutex_unlock(&v->lock);
  return r;
}

BOOL vfs_node_is_dir(const vfs_node *n)
{
  if (n->flags & VFS_NF_ROOT)
    return TRUE;
  if (n->eflags & VFS_EF_LINK_BAD)
    return FALSE;
  return (n->attr.mode & VFS_S_IFMT) == VFS_S_IFDIR;
}

WCHAR *vfs_key_join(const WCHAR *parent_key, const WCHAR *child_key)
{
  size_t a = wcslen(parent_key), b = wcslen(child_key);
  WCHAR *r = (WCHAR *)sd_alloc((a + b + 2) * sizeof(WCHAR));
  if (r) {
    memcpy(r, parent_key, a * sizeof(WCHAR));
    r[a] = L'\\';
    memcpy(r + a + 1, child_key, b * sizeof(WCHAR));
    r[a + b + 1] = 0;
  }
  return r;
}

/* ---- listings ---- */

static void listing_free(vfs_listing *l)
{
  uint32_t i;
  if (!l)
    return;
  for (i = 0; i < l->n; i++) {
    sd_free(l->e[i].raw);
    sd_free(l->e[i].wname);
    sd_free(l->e[i].key);
    sd_free(l->e[i].target);
  }
  sd_free(l->e);
  sd_free(l->idx);
  sd_free(l);
}

static void listing_index(vfs_listing *l)
{
  uint32_t cap = 16, i;
  sd_free(l->idx);
  l->idx = NULL;
  l->idx_cap = 0;
  while (cap < l->n * 2 + 16) cap <<= 1;
  l->idx = (uint32_t *)sd_alloc((size_t)cap * sizeof(uint32_t));
  if (!l->idx)
    return;                                 /* linear search fallback */
  memset(l->idx, 0xFF, (size_t)cap * sizeof(uint32_t));
  l->idx_cap = cap;
  for (i = 0; i < l->n; i++) {
    uint32_t h = vfs_hash_w(l->e[i].key) & (cap - 1);
    while (l->idx[h] != UINT32_MAX) h = (h + 1) & (cap - 1);
    l->idx[h] = i;
  }
}

/* Exact display-name match first, then key match (02 §1.3 step 1). */
static vfs_dirent *listing_find(vfs_listing *l, const WCHAR *wname, const WCHAR *key)
{
  vfs_dirent *by_key = NULL;
  uint32_t i;
  if (l->idx) {
    uint32_t h = vfs_hash_w(key) & (l->idx_cap - 1);
    while (l->idx[h] != UINT32_MAX) {
      vfs_dirent *e = &l->e[l->idx[h]];
      if (wcscmp(e->key, key) == 0) {
        if (wcscmp(e->wname, wname) == 0)
          return e;
        if (!by_key) by_key = e;
      }
      h = (h + 1) & (l->idx_cap - 1);
    }
    return by_key;
  }
  for (i = 0; i < l->n; i++) {
    if (wcscmp(l->e[i].key, key) == 0) {
      if (wcscmp(l->e[i].wname, wname) == 0)
        return &l->e[i];
      if (!by_key) by_key = &l->e[i];
    }
  }
  return by_key;
}

/* ---- node table ---- */

static void node_free(vfs_node *n)
{
  vfs_data_node_free(n);
  if (n->fh)
    sd_sftp_file_release(n->fh);
  listing_free(n->list);
  sd_free(n->key);
  sd_free(n->wname);
  sd_free(n->raw);
  sd_free(n->lpath);
  if (n->epath != n->lpath)
    sd_free(n->epath);
  sd_free(n->wext);
  sd_free(n);
}

/* Idle-node LRU: nodes in the table with no reference, oldest first. Eviction pops from the head
   instead of sweeping the whole table. v->lock held. */
static void lru_remove(sd_vfs *v, vfs_node *n)
{
  if (!n->in_lru)
    return;
  if (n->lru_prev) n->lru_prev->lru_next = n->lru_next; else v->lru_head = n->lru_next;
  if (n->lru_next) n->lru_next->lru_prev = n->lru_prev; else v->lru_tail = n->lru_prev;
  n->lru_prev = n->lru_next = NULL;
  n->in_lru = FALSE;
}

static void lru_append(sd_vfs *v, vfs_node *n)
{
  if (n->in_lru || (n->flags & VFS_NF_ROOT))
    return;
  n->lru_prev = v->lru_tail;
  n->lru_next = NULL;
  if (v->lru_tail) v->lru_tail->lru_next = n; else v->lru_head = n;
  v->lru_tail = n;
  n->in_lru = TRUE;
}

void vfs_node_ref(sd_vfs *v, vfs_node *n)
{
  if (n->refs++ == 0)
    lru_remove(v, n);
}

void vfs_node_unref(sd_vfs *v, vfs_node *n)
{
  if (--n->refs != 0)
    return;
  if (n->flags & VFS_NF_IN_TABLE)
    lru_append(v, n);
  else
    node_free(n);
}

vfs_node *vfs_table_find(sd_vfs *v, const WCHAR *key)
{
  uint32_t h = vfs_hash_w(key);
  vfs_node *n;
  if (!v->nodes.nb)
    return NULL;
  for (n = v->nodes.b[h & (v->nodes.nb - 1)]; n; n = n->hnext) {
    if (n->hash == h && wcscmp(n->key, key) == 0)
      return n;
  }
  return NULL;
}

static void table_grow(sd_vfs *v)
{
  uint32_t nb = v->nodes.nb ? v->nodes.nb * 2 : 1024, i;
  vfs_node **b = (vfs_node **)sd_calloc(nb, sizeof(*b));
  if (!b)
    return;
  for (i = 0; i < v->nodes.nb; i++) {
    vfs_node *n = v->nodes.b[i], *next;
    for (; n; n = next) {
      next = n->hnext;
      n->hnext = b[n->hash & (nb - 1)];
      b[n->hash & (nb - 1)] = n;
    }
  }
  sd_free(v->nodes.b);
  v->nodes.b = b;
  v->nodes.nb = nb;
}

void vfs_table_remove(sd_vfs *v, vfs_node *n)
{
  vfs_node **pp;
  if (!(n->flags & VFS_NF_IN_TABLE))
    return;
  for (pp = &v->nodes.b[n->hash & (v->nodes.nb - 1)]; *pp; pp = &(*pp)->hnext) {
    if (*pp == n) {
      *pp = n->hnext;
      break;
    }
  }
  n->hnext = NULL;
  n->flags &= ~VFS_NF_IN_TABLE;
  v->nodes.count--;
  lru_remove(v, n);
  if (n->refs == 0)
    node_free(n);
}

/* Evicts the oldest idle nodes when the table is over its cap (02 §1.4). */
static void table_evict(sd_vfs *v)
{
  while (v->lru_head && v->nodes.count > VFS_MAX_NODES / 2)
    vfs_table_remove(v, v->lru_head);
}

static void table_insert(sd_vfs *v, vfs_node *n)
{
  uint32_t i;
  if (v->nodes.count >= VFS_MAX_NODES)
    table_evict(v);
  if (v->nodes.count + 1 > v->nodes.nb * 2 || !v->nodes.nb)
    table_grow(v);
  n->hash = vfs_hash_w(n->key);
  i = n->hash & (v->nodes.nb - 1);
  n->hnext = v->nodes.b[i];
  v->nodes.b[i] = n;
  n->flags |= VFS_NF_IN_TABLE;
  v->nodes.count++;
  if (n->refs == 0)
    lru_append(v, n);
}

void vfs_table_readd(sd_vfs *v, vfs_node *n)
{
  if (!(n->flags & VFS_NF_IN_TABLE))
    table_insert(v, n);
}

vfs_node *vfs_parent_of(sd_vfs *v, vfs_node *n)
{
  const WCHAR *sl;
  WCHAR *pk;
  vfs_node *p;
  if (n->flags & VFS_NF_ROOT)
    return NULL;
  sl = wcsrchr(n->key, L'\\');
  if (!sl)
    return NULL;
  if (sl == n->key)
    return v->root;
  pk = vfs_wcsndup(n->key, (size_t)(sl - n->key));
  if (!pk)
    return NULL;
  p = vfs_table_find(v, pk);
  sd_free(pk);
  return (p && !(p->flags & VFS_NF_NEG)) ? p : NULL;
}

void vfs_make_negative(sd_vfs *v, vfs_node *n)
{
  /* Detach the positive node (open handles keep it alive), then cache a negative entry. */
  WCHAR *key = vfs_wcsdup(n->key);
  vfs_node *neg;
  vfs_table_remove(v, n);
  if (!key)
    return;
  neg = (vfs_node *)sd_calloc(1, sizeof(*neg));
  if (!neg) {
    sd_free(key);
    return;
  }
  neg->key = key;
  neg->flags = VFS_NF_NEG;
  neg->attr_time = sd_tick_ms();
  neg->neg_ttl = v->neg_ttl;
  table_insert(v, neg);
}

static void insert_negative(sd_vfs *v, const WCHAR *key, const WCHAR *leaf)
{
  vfs_node *n = vfs_table_find(v, key), *neg;
  if (n && !(n->flags & VFS_NF_NEG))
    return;                                 /* a concurrent create won */
  if (n) {
    n->attr_time = sd_tick_ms();
    return;
  }
  neg = (vfs_node *)sd_calloc(1, sizeof(*neg));
  if (!neg)
    return;
  neg->key = vfs_wcsdup(key);
  if (!neg->key) {
    sd_free(neg);
    return;
  }
  neg->flags = VFS_NF_NEG;
  neg->attr_time = sd_tick_ms();
  neg->neg_ttl = vfs_is_probe_name(leaf) ? VFS_PROBE_NEG_TTL : v->neg_ttl;
  table_insert(v, neg);
}

/* v->lock held. Creates or updates the child node; returns it referenced, or NULL (no memory). */
vfs_node *vfs_child_insert(sd_vfs *v, vfs_node *parent, const WCHAR *wname, const char *raw,
                           uint32_t raw_len, const vfs_attr *a, uint32_t eflags, const char *target)
{
  WCHAR *fk = v->case_view_sensitive ? vfs_wcsdup(wname) : vfs_fold(wname, (uint32_t)wcslen(wname));
  WCHAR *key = fk ? vfs_key_join(parent->key, fk) : NULL;
  vfs_node *n;
  char *lpath = NULL;
  sd_free(fk);
  if (!key)
    return NULL;
  n = vfs_table_find(v, key);
  if (n && (n->flags & VFS_NF_NEG)) {
    vfs_table_remove(v, n);
    n = NULL;
  }
  if (n && (n->raw_len != raw_len || memcmp(n->raw, raw, raw_len) != 0 ||
            ((n->eflags ^ eflags) & (VFS_EF_LINK | VFS_EF_LINK_BAD)) != 0 ||
            (target && (n->epath == n->lpath || strcmp(n->epath, target) != 0)))) {
    /* The name now refers to another remote object (or a link changed): replace the node; open
       handles keep the old one. */
    vfs_table_remove(v, n);
    n = NULL;
  }
  if (n) {
    sd_free(key);
    vfs_node_set_attr(v, n, a);             /* validator rule for the data cache (02 §4.2) */
    n->attr_time = sd_tick_ms();
    n->eflags = eflags;
    vfs_node_ref(v, n);
    return n;
  }
  if (vfs_join(v, parent->epath, raw, raw_len, &lpath) != SD_VFS_OK) {
    sd_free(key);
    return NULL;
  }
  n = (vfs_node *)sd_calloc(1, sizeof(*n));
  if (!n) {
    sd_free(key);
    sd_free(lpath);
    return NULL;
  }
  n->key = key;
  n->wname = vfs_wcsdup(wname);
  n->raw = vfs_strndup(raw, raw_len);
  n->raw_len = raw_len;
  n->lpath = lpath;
  n->epath = target ? vfs_strndup(target, strlen(target)) : lpath;
  if (!n->wname || !n->raw || !n->epath) {
    n->flags = 0;
    node_free(n);
    return NULL;
  }
  n->attr = *a;
  n->attr_time = sd_tick_ms();
  n->eflags = eflags;
  n->file_id = ++v->next_file_id;
  n->cv_valid = (a->valid & SD_SFTP_ATTR_SIZE) && (a->valid & SD_SFTP_ATTR_TIMES);
  n->cv_size = n->srv_size = a->size;
  n->cv_mtime = a->mtime;
  table_insert(v, n);
  vfs_node_ref(v, n);
  return n;
}

void vfs_listing_sync(sd_vfs *v, vfs_node *n)
{
  vfs_node *p = vfs_parent_of(v, n);
  uint32_t i;
  if (!p || !p->list)
    return;
  for (i = 0; i < p->list->n; i++) {
    if (wcscmp(p->list->e[i].wname, n->wname) == 0) {
      p->list->e[i].attr = n->attr;
      return;
    }
  }
}

WCHAR *vfs_node_path(sd_vfs *v, vfs_node *n)
{
  /* Display names of the ancestors (keys may be folded); a missing ancestor falls back to its key
     component. */
  const WCHAR *parts[256];
  vfs_node *chain[256];
  uint32_t np = 0, i;
  size_t total = 1;
  WCHAR *r, *pk = NULL;
  vfs_node *cur = n;
  while (cur && !(cur->flags & VFS_NF_ROOT) && np < SD_COUNTOF(parts)) {
    chain[np] = cur;
    parts[np++] = cur->wname;
    total += wcslen(cur->wname) + 1;
    cur = vfs_parent_of(v, cur);
  }
  if (cur == NULL && np > 0 && wcschr(chain[np - 1]->key + 1, L'\\')) {
    /* An ancestor left the table: use the key path for the part above. */
    const WCHAR *k = chain[np - 1]->key, *sl = wcsrchr(k, L'\\');
    pk = vfs_wcsndup(k, (size_t)(sl - k));
    if (pk) total += wcslen(pk);
  }
  r = (WCHAR *)sd_alloc(total * sizeof(WCHAR));
  if (!r) {
    sd_free(pk);
    return NULL;
  }
  r[0] = 0;
  if (pk) wcscat_s(r, total, pk);
  for (i = np; i > 0; i--) {
    wcscat_s(r, total, L"\\");
    wcscat_s(r, total, parts[i - 1]);
  }
  if (np == 0) wcscpy_s(r, total, L"\\");
  sd_free(pk);
  return r;
}

/* ---- Windows attributes (02 §3.1) ---- */

BOOL vfs_writable_by_us(sd_vfs *v, const vfs_attr *a)
{
  uint32_t m = a->mode;
  if (!(a->valid & SD_SFTP_ATTR_PERM))
    return TRUE;
  if (!v->uid_known || !(a->valid & SD_SFTP_ATTR_UIDGID))
    return (m & 0222u) != 0;
  if (v->uid == 0)
    return TRUE;                            /* root owns everything */
  if (a->uid == v->uid)
    return (m & 0200u) != 0;
  if (a->gid == v->gid)
    return (m & 0020u) != 0;
  return (m & 0022u) != 0;                  /* supplementary groups unknown (default) */
}

uint32_t vfs_win_attrs(sd_vfs *v, const WCHAR *name, const vfs_attr *a, uint32_t eflags, BOOL is_root)
{
  uint32_t r;
  BOOL dir;
  if (eflags & VFS_EF_LINK_BAD)
    return FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM;
  dir = is_root || (a->mode & VFS_S_IFMT) == VFS_S_IFDIR;
  r = dir ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_ARCHIVE;
  if (eflags & VFS_EF_SPECIAL)
    r = FILE_ATTRIBUTE_SYSTEM;
  if (v->hide_dotfiles && !is_root && name && name[0] == L'.')
    r |= FILE_ATTRIBUTE_HIDDEN;
  /* Never READONLY or SYSTEM on directories (customized-folder semantics, T-28). */
  if (!dir && (v->read_only || (v->map_readonly && !vfs_writable_by_us(v, a))))
    r |= FILE_ATTRIBUTE_READONLY;
  return r;
}

static FILETIME ft_from_unix(int64_t t)
{
  uint64_t f = sd_unix_to_filetime(t);
  FILETIME r;
  r.dwLowDateTime = (DWORD)f;
  r.dwHighDateTime = (DWORD)(f >> 32);
  return r;
}

void vfs_info_from(sd_vfs *v, const vfs_node *n, const WCHAR *name, const vfs_attr *a, uint32_t eflags,
                   sd_vfs_info *out)
{
  BOOL is_root = n && (n->flags & VFS_NF_ROOT);
  BOOL dir;
  memset(out, 0, sizeof(*out));
  out->win_attrs = vfs_win_attrs(v, name, a, eflags, is_root);
  dir = (out->win_attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
  out->size = (dir || (eflags & (VFS_EF_LINK_BAD | VFS_EF_SPECIAL))) ? 0 : a->size;
  /* Allocation rounded to 4 KiB, saturating (TM-R16). */
  out->alloc = out->size > UINT64_MAX - 4095 ? UINT64_MAX : (out->size + 4095) & ~(uint64_t)4095;
  out->file_id = n ? n->file_id : 0;
  out->mtime = ft_from_unix(a->mtime);
  out->ctime = out->mtime;                  /* SFTP v3 has no birth time (02 §3.2) */
  out->atime = ft_from_unix(a->atime);
  out->posix.valid = a->valid;
  out->posix.uid = a->uid;
  out->posix.gid = a->gid;
  out->posix.mode = a->mode;
  out->posix.atime = a->atime;
  out->posix.mtime = a->mtime;
}

/* ---- identity (02 §3.4) ---- */

void vfs_learn_identity(sd_vfs *v, const vfs_attr *created, const vfs_attr *parent)
{
  BOOL changed;
  if (created && (created->valid & SD_SFTP_ATTR_TIMES))
    v->skew = created->mtime - sd_unix_time_now();   /* server clock estimate for hot blocks (02 §4.2) */
  if (!created || !(created->valid & SD_SFTP_ATTR_UIDGID) || v->uid_definitive)
    return;
  changed = !v->uid_known || v->uid != created->uid;
  v->uid = created->uid;
  if (!parent || !(parent->mode & VFS_S_ISGID))
    v->gid = created->gid;
  v->uid_known = TRUE;
  v->uid_definitive = TRUE;
  {
    /* Raised also when the provisional uid is merely confirmed: the host caches the identity once it
       is definitive (02 §3.4 step 2), so it must hear about that moment. */
    sd_vfs_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.kind = SD_VFS_EV_IDENTITY;
    SD_LOGI(VFS_LOG, "remote uid %s: %u", changed ? "learned" : "confirmed", (unsigned)v->uid);
    vfs_event(v, &ev);
  }
}

/* ---- path parsing ---- */

void vfs_path_free(vfs_path *p)
{
  uint32_t i;
  for (i = 0; i < p->n; i++)
    sd_free(p->comp[i]);
  sd_free(p->comp);
  sd_free(p->key);
  memset(p, 0, sizeof(*p));
}

sd_vfs_status vfs_path_parse(sd_vfs *v, const WCHAR *path, vfs_path *out)
{
  size_t len = path ? wcslen(path) : 0, i = 0, cap = 8;
  sd_vfs_status st = SD_VFS_OK;
  memset(out, 0, sizeof(*out));
  out->comp = (WCHAR **)sd_calloc(cap, sizeof(WCHAR *));
  if (!out->comp)
    return SD_VFS_E_NO_MEMORY;
  while (i < len) {
    size_t j = i;
    while (j < len && path[j] != L'\\') j++;
    if (j > i) {
      size_t cl = j - i;
      if (cl == 1 && path[i] == L'.') {
        /* "." : no-op */
      } else if (cl == 2 && path[i] == L'.' && path[i + 1] == L'.') {
        if (out->n == 0) {                  /* may not climb above the root (02 §1.1) */
          vfs_path_free(out);
          return SD_VFS_E_INVALID_NAME;
        }
        sd_free(out->comp[--out->n]);
      } else {
        if (cl > 0xFFFF || (st = vfs_name_check_input(path + i, (uint32_t)cl)) != SD_VFS_OK) {
          vfs_path_free(out);
          return cl > 0xFFFF ? SD_VFS_E_NAME_TOO_LONG : st;
        }
        if (out->n == cap) {
          WCHAR **nc = (WCHAR **)sd_realloc(out->comp, cap * 2 * sizeof(WCHAR *));
          if (!nc) {
            vfs_path_free(out);
            return SD_VFS_E_NO_MEMORY;
          }
          out->comp = nc;
          cap *= 2;
        }
        out->comp[out->n] = vfs_wcsndup(path + i, cl);
        if (!out->comp[out->n]) {
          vfs_path_free(out);
          return SD_VFS_E_NO_MEMORY;
        }
        out->n++;
      }
    }
    i = j + 1;
  }
  SD_UNUSED(v);
  return SD_VFS_OK;
}

/* ---- remote lookups ---- */

static BOOL path_inside_root(sd_vfs *v, const char *p)
{
  if (v->root_len == 1 && v->root_path[0] == '/')
    return p[0] == '/';
  return strncmp(p, v->root_path, v->root_len) == 0 && (p[v->root_len] == 0 || p[v->root_len] == '/');
}

static BOOL is_special_mode(uint32_t mode)
{
  uint32_t t = mode & VFS_S_IFMT;
  return t != 0 && t != VFS_S_IFDIR && t != VFS_S_IFREG && t != VFS_S_IFLNK;
}

static void bad_link_attr(vfs_attr *a, const vfs_attr *link)
{
  vfs_attr r;
  memset(&r, 0, sizeof(r));
  r.valid = SD_SFTP_ATTR_SIZE | SD_SFTP_ATTR_PERM | (link->valid & (SD_SFTP_ATTR_TIMES | SD_SFTP_ATTR_UIDGID));
  r.mode = VFS_S_IFREG | 0444u;
  r.atime = link->atime;
  r.mtime = link->mtime;
  r.uid = link->uid;
  r.gid = link->gid;
  *a = r;
}

/* Lstat one object and apply the symlink policy (02 §6.9). *target is allocated for good links in
   follow_inside mode. Returns SD_VFS_E_NOT_FOUND for hidden objects. */
static sd_vfs_status stat_entry(sd_vfs *v, const char *path, uint64_t dl, vfs_attr *a, uint32_t *eflags,
                                char **target)
{
  sd_sftp_attrs sa;
  sd_err e;
  *eflags = 0;
  *target = NULL;
  e = vr_lstat(v, path, dl, &sa);
  if (e != SD_OK)
    return vfs_map_err(e);
  vfs_attr_from_sftp(a, &sa);
  if (SD_SFTP_IS_LNK(&sa)) {
    vfs_attr link = *a;
    sd_sftp_attrs ta;
    *eflags |= VFS_EF_LINK;
    if (v->symlinks == SD_SYMLINK_HIDE)
      return SD_VFS_E_NOT_FOUND;
    e = vr_stat(v, path, dl, &ta);
    if (e == SD_OK && v->symlinks == SD_SYMLINK_FOLLOW_INSIDE) {
      char *rp = NULL;
      if (vr_realpath(v, path, dl, &rp) == SD_OK && path_inside_root(v, rp)) {
        *target = rp;
      } else {
        sd_free(rp);
        e = SD_E_ACCESS_DENIED;             /* outside the root, or realpath failed: "outside" */
        vfs_notice(v, "symlink_outside_root", NULL);
      }
    }
    if (e == SD_OK) {
      vfs_attr_from_sftp(a, &ta);
    } else if (e == SD_E_DISCONNECTED || e == SD_E_TIMEOUT) {
      return vfs_map_err(e);
    } else {
      bad_link_attr(a, &link);
      *eflags |= VFS_EF_LINK_BAD;
    }
  } else if (is_special_mode(a->mode)) {
    if (!v->show_special)
      return SD_VFS_E_NOT_FOUND;
    *eflags |= VFS_EF_SPECIAL;
  }
  if (!(a->valid & SD_SFTP_ATTR_PERM)) {
    a->mode = VFS_S_IFREG | 0644u;          /* unknown type: regular file (02 §1.6) */
    a->valid |= SD_SFTP_ATTR_PERM;
  }
  if (!(*eflags & VFS_EF_LINK_BAD) && (a->mode & VFS_S_IFMT) == VFS_S_IFDIR)
    *eflags |= VFS_EF_DIR;
  return SD_VFS_OK;
}

/* v->lock held: node for a listing entry, referenced. Unresolved links are resolved by the caller. */
static vfs_node *child_from_entry(sd_vfs *v, vfs_node *parent, const vfs_dirent *e, uint64_t time)
{
  vfs_node *n = vfs_child_insert(v, parent, e->wname, e->raw, e->raw_len, &e->attr, e->eflags, e->target);
  if (n)
    n->attr_time = time;
  return n;
}

/* Looks up one component under parent (02 §1.3 strategy). */
static sd_vfs_status lookup_child(sd_vfs *v, vfs_node *parent, const WCHAR *comp, const WCHAR *ckey,
                                  const WCHAR *fkey, uint64_t dl, int64_t max_age, vfs_node **out)
{
  vfs_node *n;
  uint64_t now;
  char *raw = NULL, *path = NULL, *target = NULL;
  uint32_t raw_len = 0, eflags = 0;
  vfs_attr a;
  sd_vfs_status st;
  BOOL online = vfs_online(v), tried_listing = FALSE;
  *out = NULL;

  sd_mutex_lock(&v->lock);
  now = sd_tick_ms();
  n = vfs_table_find(v, ckey);
  if (n) {
    if (n->flags & VFS_NF_NEG) {
      if (now - n->attr_time < n->neg_ttl || !online) {
        sd_mutex_unlock(&v->lock);
        sd_atomic_inc64(&v->cache_hits);
        return SD_VFS_E_NOT_FOUND;
      }
      vfs_table_remove(v, n);
      n = NULL;
    } else if (!online || max_age < 0 || (int64_t)(now - n->attr_time) <= max_age) {
      vfs_node_ref(v, n);
      sd_mutex_unlock(&v->lock);
      sd_atomic_inc64(&v->cache_hits);
      *out = n;
      return SD_VFS_OK;
    }
  }
  if (parent->list && (!online || now - parent->list->time <= v->dir_ttl)) {
    vfs_dirent *e = listing_find(parent->list, comp, fkey);
    if (e && !(e->eflags & VFS_EF_LINK && !(e->eflags & VFS_EF_DIR) && e->attr.valid == 0) &&
        (!online || max_age < 0 || (int64_t)(now - parent->list->time) <= max_age)) {
      vfs_node *c = child_from_entry(v, parent, e, parent->list->time);
      sd_mutex_unlock(&v->lock);
      sd_atomic_inc64(&v->cache_hits);
      if (!c)
        return SD_VFS_E_NO_MEMORY;
      *out = c;
      return SD_VFS_OK;
    }
    if (e) {
      raw = vfs_strndup(e->raw, e->raw_len);   /* revalidate this exact remote name */
      raw_len = e->raw_len;
    } else {
      insert_negative(v, ckey, comp);
      sd_mutex_unlock(&v->lock);
      sd_atomic_inc64(&v->cache_hits);
      return SD_VFS_E_NOT_FOUND;
    }
  } else if (n) {
    raw = vfs_strndup(n->raw, n->raw_len);
    raw_len = n->raw_len;
  }
  sd_mutex_unlock(&v->lock);
  sd_atomic_inc64(&v->cache_misses);

  if (!online)
    return SD_VFS_E_DISCONNECTED;           /* unknown while offline: never NOT_FOUND (02 §5.2) */
  if (!raw) {
    st = vfs_name_from_display(comp, (uint32_t)wcslen(comp), &raw, &raw_len);
    if (st != SD_VFS_OK)
      return st;
  }
  st = vfs_join_under(v, parent, raw, raw_len, &path);
  if (st == SD_VFS_OK)
    st = stat_entry(v, path, dl, &a, &eflags, &target);
  sd_free(path);
  if (st == SD_VFS_E_NOT_FOUND) {
    /* Case-sensitive remote under an insensitive view, or a PUA name: the listing decides. */
    if ((!v->remote_insensitive && !v->case_view_sensitive) || vfs_has_pua(comp, (uint32_t)wcslen(comp))) {
      tried_listing = TRUE;
      st = vfs_listing_get(v, parent, dl, FALSE);
      if (st == SD_VFS_OK) {
        vfs_dirent *e;
        sd_mutex_lock(&v->lock);
        e = parent->list ? listing_find(parent->list, comp, fkey) : NULL;
        if (e && (e->raw_len != raw_len || memcmp(e->raw, raw, raw_len) != 0)) {
          vfs_node *c = child_from_entry(v, parent, e, parent->list->time);
          sd_mutex_unlock(&v->lock);
          sd_free(raw);
          if (!c)
            return SD_VFS_E_NO_MEMORY;
          *out = c;
          return SD_VFS_OK;
        }
        insert_negative(v, ckey, comp);
        sd_mutex_unlock(&v->lock);
        st = SD_VFS_E_NOT_FOUND;
      }
    }
    if (!tried_listing) {
      sd_mutex_lock(&v->lock);
      insert_negative(v, ckey, comp);
      sd_mutex_unlock(&v->lock);
    }
    sd_free(raw);
    return st;
  }
  if (st != SD_VFS_OK) {
    sd_free(raw);
    return st;
  }
  sd_mutex_lock(&v->lock);
  {
    /* Display name: the listing's (mangled) name when known, else the requested one. */
    vfs_dirent *e = parent->list ? listing_find(parent->list, comp, fkey) : NULL;
    const WCHAR *wn = (e && e->raw_len == raw_len && memcmp(e->raw, raw, raw_len) == 0) ? e->wname : comp;
    *out = vfs_child_insert(v, parent, wn, raw, raw_len, &a, eflags, target);
  }
  sd_mutex_unlock(&v->lock);
  sd_free(raw);
  sd_free(target);
  return *out ? SD_VFS_OK : SD_VFS_E_NO_MEMORY;
}

sd_vfs_status vfs_resolve(sd_vfs *v, const WCHAR *path, uint64_t dl, int64_t max_age_ms,
                          vfs_node **node, vfs_node **parent_out, WCHAR **leaf)
{
  vfs_path p;
  vfs_node *cur;
  sd_vfs_status st;
  uint32_t i;
  *node = NULL;
  if (parent_out) *parent_out = NULL;
  if (leaf) *leaf = NULL;
  st = vfs_path_parse(v, path, &p);
  if (st != SD_VFS_OK)
    return st;
  sd_mutex_lock(&v->lock);
  cur = v->root;
  vfs_node_ref(v, cur);
  sd_mutex_unlock(&v->lock);
  for (i = 0; i < p.n; i++) {
    BOOL last = (i + 1 == p.n);
    WCHAR *fk = v->case_view_sensitive ? vfs_wcsdup(p.comp[i]) : vfs_fold(p.comp[i], (uint32_t)wcslen(p.comp[i]));
    WCHAR *ck = fk ? vfs_key_join(cur->key, fk) : NULL;
    vfs_node *child = NULL;
    if (!ck) {
      sd_free(fk);
      st = SD_VFS_E_NO_MEMORY;
      break;
    }
    st = lookup_child(v, cur, p.comp[i], ck, fk, dl, last ? max_age_ms : (int64_t)v->attr_ttl, &child);
    sd_free(fk);
    sd_free(ck);
    if (st == SD_VFS_E_NOT_FOUND) {
      if (!last) {
        st = SD_VFS_E_PATH_NOT_FOUND;
      } else if (parent_out) {
        *parent_out = cur;
        cur = NULL;
        if (leaf) *leaf = vfs_wcsdup(p.comp[i]);
      }
      break;
    }
    if (st != SD_VFS_OK)
      break;
    if (!last && !vfs_node_is_dir(child)) {
      sd_mutex_lock(&v->lock);
      vfs_node_unref(v, child);
      sd_mutex_unlock(&v->lock);
      st = SD_VFS_E_PATH_NOT_FOUND;
      break;
    }
    sd_mutex_lock(&v->lock);
    vfs_node_unref(v, cur);
    sd_mutex_unlock(&v->lock);
    cur = child;
  }
  if (st == SD_VFS_OK) {
    *node = cur;
    cur = NULL;
  }
  if (cur) {
    sd_mutex_lock(&v->lock);
    vfs_node_unref(v, cur);
    sd_mutex_unlock(&v->lock);
  }
  vfs_path_free(&p);
  return st;
}

/* ---- directory listing (02 §1.4, §1.6, §6.9) ---- */

typedef struct raw_list { vfs_rawent *e; uint32_t n, cap; uint64_t bytes; } raw_list;

static int raw_list_take(raw_list *l, vfs_slot *s)
{
  uint32_t i;
  if (l->n + s->nents > l->cap) {
    uint32_t cap = l->cap ? l->cap : 256;
    vfs_rawent *ne;
    while (cap < l->n + s->nents) cap *= 2;
    ne = (vfs_rawent *)sd_realloc(l->e, (size_t)cap * sizeof(*ne));
    if (!ne)
      return 0;
    l->e = ne;
    l->cap = cap;
  }
  for (i = 0; i < s->nents; i++)
    l->e[l->n++] = s->ents[i];
  l->bytes += s->raw_bytes;
  sd_free(s->ents);                        /* names now owned by l */
  s->ents = NULL;
  s->nents = 0;
  return 1;
}

static void raw_list_free(raw_list *l)
{
  uint32_t i;
  for (i = 0; i < l->n; i++)
    sd_free(l->e[i].name);
  sd_free(l->e);
}

static sd_vfs_status fetch_raw(sd_vfs *v, const char *path, uint64_t dl, raw_list *out, uint32_t *dropped)
{
  vfs_batch *b;
  vfs_slot *s;
  sd_sftp_file *dir = NULL;
  sd_err e;
  uint64_t max_bytes = (uint64_t)v->list_bytes;
  memset(out, 0, sizeof(*out));
  *dropped = 0;
  b = vb_new(1);
  if (!b)
    return SD_VFS_E_NO_MEMORY;
  s = vb_slot(b, 0);
  vb_submitted(b, 0, sd_sftp_opendir(v->s, path, vb_opt(b, 0, dl), vb_cb_open(), s));
  vb_wait(b, dl);
  e = s->err;
  dir = s->file;
  s->file = NULL;
  vb_free(b);
  if (e != SD_OK)
    return vfs_map_err(e);
  for (;;) {
    int eof;
    if (sd_tick_ms() >= dl) {
      e = SD_E_TIMEOUT;
      break;
    }
    b = vb_new(1);
    if (!b) {
      e = SD_E_NO_MEMORY;
      break;
    }
    s = vb_slot(b, 0);
    vb_submitted(b, 0, sd_sftp_readdir(dir, vb_opt(b, 0, dl), vb_cb_readdir(), s));
    vb_wait(b, dl);
    e = s->err;
    eof = s->eof;
    *dropped += s->dropped;
    if (e == SD_OK && !raw_list_take(out, s))
      e = SD_E_NO_MEMORY;
    vb_free(b);
    if (e != SD_OK)
      break;
    if (out->n > v->list_entries || out->bytes > max_bytes) {
      SD_LOGW(VFS_LOG, "listing cap hit (entries %u, bytes %llu)", (unsigned)out->n,
              (unsigned long long)out->bytes);
      sd_sftp_file_release(dir);
      raw_list_free(out);
      memset(out, 0, sizeof(*out));
      return SD_VFS_E_TOO_LARGE;
    }
    if (eof)
      break;
  }
  sd_sftp_file_release(dir);                /* sends CLOSE in the background */
  if (e != SD_OK) {
    raw_list_free(out);
    memset(out, 0, sizeof(*out));
    if (e == SD_E_TIMEOUT && v->list_deadline < v->req_timeout)
      return SD_VFS_E_TOO_LARGE;
    return vfs_map_err(e);
  }
  return SD_VFS_OK;
}

/* Pipelined stat (+ realpath in follow_inside) of the links of a listing (02 §6.9). */
static void resolve_links(sd_vfs *v, const char *dir_path, vfs_dirent *e, uint32_t n, uint64_t dl)
{
  uint32_t i, nl = 0, k;
  uint32_t *which;
  vfs_batch *b;
  BOOL inside = v->symlinks == SD_SYMLINK_FOLLOW_INSIDE;
  BOOL noticed = FALSE;
  for (i = 0; i < n; i++)
    if (e[i].eflags & VFS_EF_LINK) nl++;
  if (nl == 0)
    return;
  nl = SD_MIN(nl, v->link_stats);
  which = (uint32_t *)sd_alloc((size_t)nl * sizeof(uint32_t));
  b = which ? vb_new(nl * 2) : NULL;
  if (!b) {
    sd_free(which);
    return;                                 /* links stay unresolved: resolved on lookup */
  }
  for (i = 0, k = 0; i < n && k < nl; i++) {
    char *path = NULL;
    if (!(e[i].eflags & VFS_EF_LINK))
      continue;
    which[k] = i;
    if (vfs_join(v, dir_path, e[i].raw, e[i].raw_len, &path) == SD_VFS_OK) {
      vb_submitted(b, k * 2, sd_sftp_stat(v->s, path, vb_opt(b, k * 2, dl), vb_cb_attrs(), vb_slot(b, k * 2)));
      if (inside)
        vb_submitted(b, k * 2 + 1, sd_sftp_realpath(v->s, path, vb_opt(b, k * 2 + 1, dl), vb_cb_name(),
                                                    vb_slot(b, k * 2 + 1)));
      sd_free(path);
    }
    k++;
  }
  vb_wait(b, dl);
  for (k = 0; k < nl; k++) {
    vfs_dirent *d = &e[which[k]];
    vfs_slot *st = vb_slot(b, k * 2), *rp = vb_slot(b, k * 2 + 1);
    vfs_attr link = d->attr;
    BOOL ok = st->err == SD_OK;
    if (ok && inside) {
      ok = rp->err == SD_OK && rp->name && path_inside_root(v, rp->name);
      if (!ok && !noticed) {
        noticed = TRUE;
        vfs_notice(v, "symlink_outside_root", NULL);
      }
    }
    if (ok) {
      vfs_attr_from_sftp(&d->attr, &st->attrs);
      if (!(d->attr.valid & SD_SFTP_ATTR_PERM)) {
        d->attr.mode = VFS_S_IFREG | 0644u;
        d->attr.valid |= SD_SFTP_ATTR_PERM;
      }
      if ((d->attr.mode & VFS_S_IFMT) == VFS_S_IFDIR)
        d->eflags |= VFS_EF_DIR;
      if (inside) {
        d->target = rp->name;
        rp->name = NULL;
      }
    } else {
      bad_link_attr(&d->attr, &link);
      d->eflags |= VFS_EF_LINK_BAD;
    }
  }
  /* Links beyond the cap keep attr.valid == 0 and are resolved individually on lookup. */
  vb_free(b);
  sd_free(which);
}

/* Builds the Windows view of a raw listing: TM-R12 filtering, mapping, policy, keys. */
static sd_vfs_status build_listing(sd_vfs *v, const char *dir_path, raw_list *rl, uint64_t dl,
                                   vfs_listing **out, uint32_t *dropped)
{
  vfs_listing *l = (vfs_listing *)sd_calloc(1, sizeof(*l));
  uint32_t i, j;
  if (!l)
    return SD_VFS_E_NO_MEMORY;
  l->e = (vfs_dirent *)sd_calloc(rl->n ? rl->n : 1, sizeof(vfs_dirent));
  if (!l->e) {
    sd_free(l);
    return SD_VFS_E_NO_MEMORY;
  }
  for (i = 0; i < rl->n; i++) {
    vfs_rawent *r = &rl->e[i];
    vfs_dirent *d;
    BOOL dup = FALSE;
    if (!r->name || r->len == 0 || r->len > VFS_MAX_RAW_NAME || memchr(r->name, '/', r->len) || memchr(r->name, 0, r->len) ||
        (r->len == 1 && r->name[0] == '.') || (r->len == 2 && r->name[0] == '.' && r->name[1] == '.')) {
      (*dropped)++;
      continue;
    }
    /* Same raw name twice: keep the first (O(n^2) only over equal-length names already kept). */
    for (j = 0; j < l->n && !dup; j++)
      dup = (l->e[j].raw_len == r->len && memcmp(l->e[j].raw, r->name, r->len) == 0);
    if (dup) {
      (*dropped)++;
      continue;
    }
    d = &l->e[l->n];
    vfs_attr_from_sftp(&d->attr, &r->attrs);
    if (SD_SFTP_IS_LNK(&r->attrs)) {
      if (v->symlinks == SD_SYMLINK_HIDE)
        continue;
      d->eflags = VFS_EF_LINK;
      d->attr.valid = 0;                    /* filled by resolve_links */
    } else if (is_special_mode(d->attr.mode)) {
      if (!v->show_special)
        continue;
      d->eflags = VFS_EF_SPECIAL;
    } else {
      if (!(d->attr.valid & SD_SFTP_ATTR_PERM)) {
        d->attr.mode = VFS_S_IFREG | 0644u;
        d->attr.valid |= SD_SFTP_ATTR_PERM;
      }
      if (!(d->attr.valid & SD_SFTP_ATTR_SIZE))
        d->attr.size = 0;
      if ((d->attr.mode & VFS_S_IFMT) == VFS_S_IFDIR)
        d->eflags = VFS_EF_DIR;
    }
    if (vfs_name_to_display(r->name, r->len, &d->wname, &d->wlen) != SD_VFS_OK) {
      (*dropped)++;
      memset(d, 0, sizeof(*d));
      continue;
    }
    d->key = v->case_view_sensitive ? vfs_wcsdup(d->wname) : vfs_fold(d->wname, d->wlen);
    d->raw = r->name;                       /* ownership moves to the listing */
    d->raw_len = r->len;
    r->name = NULL;
    if (!d->key) {
      sd_free(d->wname);
      memset(d, 0, sizeof(*d));
      listing_free(l);
      return SD_VFS_E_NO_MEMORY;
    }
    l->n++;
  }
  if (v->symlinks != SD_SYMLINK_HIDE)
    resolve_links(v, dir_path, l->e, l->n, dl);
  for (i = 0; i < l->n; i++) {
    /* Links left unresolved (over the stat cap): shown as unknown 0-byte SYSTEM files until opened. */
    if ((l->e[i].eflags & VFS_EF_LINK) && l->e[i].attr.valid == 0) {
      l->e[i].attr.mode = VFS_S_IFREG;
      l->e[i].eflags |= VFS_EF_SPECIAL;
    }
  }
  {
    uint32_t renamed = vfs_mangle_collisions(l->e, l->n, !v->case_view_sensitive);
    if (renamed == (uint32_t)-1) {
      listing_free(l);
      return SD_VFS_E_NO_MEMORY;
    }
    if (renamed > 0)
      SD_LOGI(VFS_LOG, "case/name collisions in a directory: %u entries renamed with ~cN", (unsigned)renamed);
  }
  listing_index(l);
  *out = l;
  return SD_VFS_OK;
}

sd_vfs_status vfs_listing_get(sd_vfs *v, vfs_node *d, uint64_t dl, BOOL force)
{
  char *path;
  raw_list rl;
  vfs_listing *l = NULL;
  uint32_t dropped = 0, i;
  sd_vfs_status st;
  uint64_t ldl;
  BOOL online = vfs_online(v);
  sd_mutex_lock(&v->lock);
  if (d->list && ((!force && sd_tick_ms() - d->list->time <= v->dir_ttl) || !online)) {
    sd_mutex_unlock(&v->lock);
    return SD_VFS_OK;
  }
  path = vfs_strndup(d->epath, strlen(d->epath));
  sd_mutex_unlock(&v->lock);
  if (!path)
    return SD_VFS_E_NO_MEMORY;
  if (!online) {
    sd_free(path);
    return SD_VFS_E_DISCONNECTED;
  }
  /* The listing budget is the request budget (no DokanResetTimeout progress hook in M0), capped
     by list_deadline_ms (TM-R16). */
  ldl = sd_tick_ms() + SD_MIN(v->list_deadline, v->req_timeout);
  if (dl < ldl) ldl = dl;
  st = fetch_raw(v, path, ldl, &rl, &dropped);
  if (st == SD_VFS_OK) {
    st = build_listing(v, path, &rl, ldl, &l, &dropped);
    raw_list_free(&rl);
  }
  sd_free(path);
  if (st != SD_VFS_OK)
    return st;
  if (dropped > 0) {
    SD_LOGW(VFS_LOG, "directory listing: %u malformed entries dropped", (unsigned)dropped);
    vfs_notice(v, "dirent_dropped", NULL);
  }
  l->time = sd_tick_ms();
  sd_mutex_lock(&v->lock);
  listing_free(d->list);
  d->list = l;
  /* Purge negative entries the listing contradicts and refresh cached children. */
  for (i = 0; i < l->n; i++) {
    WCHAR *ck = vfs_key_join(d->key, l->e[i].key);
    vfs_node *c = ck ? vfs_table_find(v, ck) : NULL;
    sd_free(ck);
    if (!c)
      continue;
    if (c->flags & VFS_NF_NEG) {
      vfs_table_remove(v, c);
    } else if (c->raw_len == l->e[i].raw_len && memcmp(c->raw, l->e[i].raw, c->raw_len) == 0 &&
               !(l->e[i].eflags & VFS_EF_LINK) && c->nwext == 0 && !c->wq_head) {
      vfs_node_set_attr(v, c, &l->e[i].attr);
      c->attr_time = l->time;
    }
  }
  sd_mutex_unlock(&v->lock);
  return SD_VFS_OK;
}

/* v->lock held: adds child to its parent's cached listing (local mutations update in place). */
void vfs_listing_add(sd_vfs *v, vfs_node *parent, vfs_node *child)
{
  vfs_listing *l = parent ? parent->list : NULL;
  vfs_dirent *ne, *d;
  if (!l)
    return;
  vfs_listing_del(v, parent, child->wname);
  ne = (vfs_dirent *)sd_realloc(l->e, ((size_t)l->n + 1) * sizeof(vfs_dirent));
  if (!ne) {
    listing_free(parent->list);             /* drop rather than keep a wrong listing */
    parent->list = NULL;
    return;
  }
  l->e = ne;
  d = &l->e[l->n];
  memset(d, 0, sizeof(*d));
  d->raw = vfs_strndup(child->raw, child->raw_len);
  d->raw_len = child->raw_len;
  d->wname = vfs_wcsdup(child->wname);
  d->wlen = (uint32_t)wcslen(child->wname);
  d->key = v->case_view_sensitive ? vfs_wcsdup(child->wname) : vfs_fold(child->wname, d->wlen);
  d->attr = child->attr;
  d->eflags = child->eflags;
  if (child->epath != child->lpath)
    d->target = vfs_strndup(child->epath, strlen(child->epath));
  if (!d->raw || !d->wname || !d->key) {
    sd_free(d->raw); sd_free(d->wname); sd_free(d->key); sd_free(d->target);
    listing_free(parent->list);
    parent->list = NULL;
    return;
  }
  l->n++;
  listing_index(l);
}

void vfs_listing_del(sd_vfs *v, vfs_node *parent, const WCHAR *wname)
{
  vfs_listing *l = parent ? parent->list : NULL;
  uint32_t i;
  SD_UNUSED(v);
  if (!l)
    return;
  for (i = 0; i < l->n; i++) {
    if (wcscmp(l->e[i].wname, wname) == 0) {
      sd_free(l->e[i].raw);
      sd_free(l->e[i].wname);
      sd_free(l->e[i].key);
      sd_free(l->e[i].target);
      l->e[i] = l->e[l->n - 1];
      l->n--;
      listing_index(l);
      return;
    }
  }
}

/* ---- mount / unmount ---- */

static PSID copy_sid(PSID s)
{
  DWORD n;
  PSID r;
  if (!s || !IsValidSid(s))
    return NULL;
  n = GetLengthSid(s);
  r = sd_alloc(n);
  if (r && !CopySid(n, r, s)) {
    sd_free(r);
    r = NULL;
  }
  return r;
}

static PSID process_user_sid(void)
{
  HANDLE tok;
  BYTE buf[256];
  DWORD n = 0;
  PSID r = NULL;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok))
    return NULL;
  if (GetTokenInformation(tok, TokenUser, buf, sizeof(buf), &n))
    r = copy_sid(((TOKEN_USER *)buf)->User.Sid);
  CloseHandle(tok);
  return r;
}

static uint32_t def_u(UINT x, uint32_t d) { return x ? (uint32_t)x : d; }

static void vfs_free_all(sd_vfs *v)
{
  uint32_t i;
  for (i = 0; i < v->nodes.nb; i++) {
    vfs_node *n;
    for (n = v->nodes.b[i]; n; n = n->hnext) {
      if (n->dc) {
        vfs_dc_close(v, n->dc);
        n->dc = NULL;
      }
    }
  }
  while (v->handles) {
    sd_vfs_handle *h = v->handles;
    v->handles = h->next;
    vfs_node_unref(v, h->node);
    sd_free(h);
  }
  for (i = 0; i < v->nodes.nb; i++) {
    vfs_node *n = v->nodes.b[i], *next;
    for (; n; n = next) {
      next = n->hnext;
      n->flags &= ~VFS_NF_IN_TABLE;
      n->refs = 0;
      node_free(n);
    }
  }
  sd_free(v->nodes.b);
  sd_free(v->root_path);
  sd_free(v->label);
  sd_free(v->fs_name);
  sd_free(v->offline_suffix);
  sd_free(v->owner_sid);
  vfs_disk_close(v);
  sd_mutex_destroy(&v->lock);
  sd_free(v);
}

/* Remote case detection (02 §1.3): lstat the root's last component with its case inverted. */
static BOOL detect_insensitive(sd_vfs *v, const sd_sftp_attrs *root_attrs, uint64_t dl)
{
  char *inv = vfs_strndup(v->root_path, v->root_len);
  size_t i, last = v->root_len;
  BOOL changed = FALSE, r = FALSE;
  sd_sftp_attrs a;
  if (!inv)
    return FALSE;
  while (last > 0 && inv[last - 1] != '/') last--;
  for (i = last; i < v->root_len; i++) {
    char c = inv[i];
    if (c >= 'a' && c <= 'z') { inv[i] = (char)(c - 32); changed = TRUE; }
    else if (c >= 'A' && c <= 'Z') { inv[i] = (char)(c + 32); changed = TRUE; }
  }
  if (changed && vr_stat(v, inv, dl, &a) == SD_OK)
    r = a.size == root_attrs->size && a.mtime == root_attrs->mtime && a.perm == root_attrs->perm &&
        a.uid == root_attrs->uid;
  sd_free(inv);
  return r;
}

sd_vfs_status sd_vfs_mount(sd_sftp_session *s, const sd_vfs_options *o, sd_vfs_event_cb cb, void *cb_ctx,
                           sd_vfs **out)
{
  sd_vfs *v;
  sd_sftp_server_info info;
  char home[1024];
  char *rp = NULL;
  sd_sftp_attrs ra;
  sd_err e;
  uint64_t dl;
  if (out) *out = NULL;
  if (!s || !o || !out || o->struct_size < sizeof(sd_vfs_options))
    return SD_VFS_E_UNSUPPORTED;
  /* Later-milestone features (M1 scope). */
  if ((o->write_mode != SD_VFS_WRITE_THROUGH && o->write_mode != SD_VFS_WRITE_BEHIND) || o->global_mount ||
      o->mark_of_the_web || o->remote_codepage || o->symlinks < SD_SYMLINK_FOLLOW_INSIDE ||
      o->symlinks > SD_SYMLINK_HIDE || o->remote_case < SD_VFS_CASE_AUTO || o->remote_case > SD_VFS_CASE_INSENSITIVE)
    return SD_VFS_E_UNSUPPORTED;
  if (sd_sftp_session_state(s) != SD_SFTP_ST_READY)
    return SD_VFS_E_DISCONNECTED;
  v = (sd_vfs *)sd_calloc(1, sizeof(*v));
  if (!v)
    return SD_VFS_E_NO_MEMORY;
  sd_mutex_init(&v->lock);
  v->s = s;
  v->cb = cb;
  v->cb_ctx = cb_ctx;
  v->read_only = o->read_only;
  v->hide_dotfiles = o->hide_dotfiles;
  v->map_readonly = o->map_readonly;
  v->case_view_sensitive = o->case_sensitive_view;
  v->show_special = o->show_special;
  v->allow_system = o->allow_system;
  v->block_shell_active = o->block_shell_active;
  v->fsync_on_flush = o->fsync_on_flush;
  v->symlinks = o->symlinks;
  v->umask = o->umask ? (uint32_t)(o->umask & 0777u) : VFS_DEF_UMASK;
  v->attr_ttl = def_u(o->attr_ttl_ms, VFS_DEF_ATTR_TTL);
  v->dir_ttl = def_u(o->dir_ttl_ms, VFS_DEF_DIR_TTL);
  v->neg_ttl = def_u(o->neg_ttl_ms, VFS_DEF_NEG_TTL);
  v->revalidate = o->open_revalidate_ms ? o->open_revalidate_ms : VFS_DEF_REVALIDATE;
  v->req_timeout = def_u(o->request_timeout_ms, VFS_DEF_REQ_TIMEOUT);
  v->list_entries = def_u(o->max_list_entries, VFS_DEF_LIST_ENTRIES);
  v->list_bytes = def_u(o->max_list_mb, VFS_DEF_LIST_MB) > 4095 ? 0xFFFFFFFFu
                  : def_u(o->max_list_mb, VFS_DEF_LIST_MB) * 1024u * 1024u;
  v->list_deadline = def_u(o->list_deadline_ms, VFS_DEF_LIST_DEADLINE);
  v->link_stats = def_u(o->max_link_stats, VFS_DEF_LINK_STATS);
  v->write_behind = o->write_mode == SD_VFS_WRITE_BEHIND;
  v->max_readahead = def_u(o->max_readahead, VFS_DEF_MAX_RA);
  v->wb_window = def_u(o->wb_window, VFS_DEF_WB_WINDOW);
  v->wb_window_mount = def_u(o->wb_window_mount, VFS_DEF_WB_MOUNT);
  if (v->wb_window_mount < v->wb_window) v->wb_window_mount = v->wb_window;
  v->grace = o->reconnect_grace_ms == 0xFFFFFFFFu ? 0 : def_u(o->reconnect_grace_ms, VFS_DEF_GRACE);
  v->offline_wait = def_u(o->offline_wait_ms, VFS_DEF_OFFLINE_WAIT);
  v->mount_id = vc_new_mount_id();
  v->label = vfs_wcsdup(o->volume_label ? o->volume_label : L"ShellDrive");
  v->fs_name = vfs_wcsdup(o->volume_fs_name ? o->volume_fs_name : L"NTFS");
  v->offline_suffix = vfs_wcsdup(o->offline_label_suffix ? o->offline_label_suffix : L"");
  v->owner_sid = o->owner_sid ? copy_sid(o->owner_sid) : process_user_sid();
  if (!v->label || !v->fs_name || !v->offline_suffix) {
    vfs_free_all(v);
    return SD_VFS_E_NO_MEMORY;
  }

  memset(&info, 0, sizeof(info));
  e = sd_sftp_session_info(s, &info, home, sizeof(home));
  if (e != SD_OK) {
    vfs_free_all(v);
    return vfs_map_err(e);
  }
  v->max_read = (LONG)SD_MIN(info.limits.max_read ? info.limits.max_read : 32768u, (uint64_t)VFS_BLK);
  v->max_write = (LONG)SD_MIN(info.limits.max_write ? info.limits.max_write : 32768u, (uint64_t)VFS_BLK);
  v->gen = (LONG)(info.generation ? info.generation : sd_sftp_session_generation(s));
  if (o->known_identity && o->known_identity->uid_known && o->known_identity->definitive) {
    v->uid_known = v->uid_definitive = TRUE;   /* cached by the host per server identity (02 §3.4 step 2) */
    v->uid = o->known_identity->uid;
    v->gid = o->known_identity->gid;
  } else if (info.identity.source == SD_SFTP_ID_EXEC) {
    v->uid_known = v->uid_definitive = TRUE;
    v->uid = info.identity.uid;
    v->gid = info.identity.gid;
  } else if (info.identity.source == SD_SFTP_ID_HOME_OWNER && info.identity.uid != 0) {
    v->uid_known = TRUE;                    /* provisional (02 §3.4 steps 1, 3) */
    v->uid = info.identity.uid;
    v->gid = info.identity.gid;
  }
  {
    char fp[160];
    fp[0] = 0;
    if (info.ssh && info.ssh->hostkey_fp_sha256)
      strncpy_s(fp, sizeof(fp), info.ssh->hostkey_fp_sha256, _TRUNCATE);
    vfs_disk_open(v, o, fp);                /* TM-R29 checks; refused -> memory tier only */
  }

  dl = vfs_deadline(v);
  e = vr_realpath(v, o->remote_root ? o->remote_root : ".", dl, &rp);
  if (e != SD_OK) {
    vfs_free_all(v);
    return vfs_map_err(e);
  }
  v->root_len = strlen(rp);
  while (v->root_len > 1 && rp[v->root_len - 1] == '/')
    rp[--v->root_len] = 0;
  v->root_path = rp;
  e = vr_stat(v, rp, dl, &ra);
  if (e != SD_OK || !SD_SFTP_IS_DIR(&ra)) {
    vfs_free_all(v);
    return e != SD_OK ? vfs_map_err(e) : SD_VFS_E_NOT_DIR;
  }
  if (o->remote_case == SD_VFS_CASE_INSENSITIVE)
    v->remote_insensitive = TRUE;
  else if (o->remote_case == SD_VFS_CASE_AUTO)
    v->remote_insensitive = (info.quirks & SD_SFTP_QUIRK_WIN_DRIVE_PATHS) ? TRUE : detect_insensitive(v, &ra, dl);

  v->root = (vfs_node *)sd_calloc(1, sizeof(vfs_node));
  if (v->root) {
    v->root->key = vfs_wcsdup(L"");
    v->root->wname = vfs_wcsdup(L"");
    v->root->raw = vfs_strndup("", 0);
    v->root->lpath = vfs_strndup(rp, v->root_len);
  }
  if (!v->root || !v->root->key || !v->root->wname || !v->root->raw || !v->root->lpath) {
    if (v->root) node_free(v->root);
    v->root = NULL;
    vfs_free_all(v);
    return SD_VFS_E_NO_MEMORY;
  }
  v->root->epath = v->root->lpath;
  v->root->flags = VFS_NF_ROOT;
  vfs_attr_from_sftp(&v->root->attr, &ra);
  v->root->attr_time = sd_tick_ms();
  v->root->eflags = VFS_EF_DIR;
  v->root->file_id = ++v->next_file_id;
  v->root->refs = 1;                        /* the mount's own reference */
  table_insert(v, v->root);
  {
    uint32_t h = 2166136261u;
    size_t i;
    for (i = 0; i < v->root_len; i++) { h ^= (uint8_t)rp[i]; h *= 16777619u; }
    v->serial = h ^ vfs_hash_w(v->label);
  }
  SD_LOGI(VFS_LOG, "mounted: case %s, symlinks %d, read-only %d, write %s, disk cache %d",
          v->remote_insensitive ? "insensitive" : "sensitive", v->symlinks, (int)v->read_only,
          v->write_behind ? "behind" : "through", (int)vfs_disk_enabled(v));
  vfs_timer_start(v);
  *out = v;
  return SD_VFS_OK;
}

void sd_vfs_get_identity(sd_vfs *v, sd_vfs_identity *out)
{
  if (!out)
    return;
  memset(out, 0, sizeof(*out));
  if (!v)
    return;
  sd_mutex_lock(&v->lock);
  out->uid_known = v->uid_known;
  out->definitive = v->uid_definitive;
  out->uid = v->uid;
  out->gid = v->gid;
  sd_mutex_unlock(&v->lock);
}

void sd_vfs_quiesce(sd_vfs *v, DWORD budget_ms)
{
  uint64_t end;
  if (!v)
    return;
  InterlockedExchange(&v->quiescing, 1);
  end = sd_tick_ms() + budget_ms;
  /* Write-behind data drains within the budget; what is left is reported (02 §4.4, §6.6). */
  vfs_data_quiesce(v, end);
  /* Requests in flight finish by their own deadline. */
  while (InterlockedCompareExchange(&v->busy, 0, 0) != 0 && sd_tick_ms() < end)
    Sleep(10);
}

void sd_vfs_unmount(sd_vfs *v)
{
  uint64_t end;
  if (!v)
    return;
  InterlockedExchange(&v->quiescing, 1);
  vfs_timer_stop(v);
  vfs_data_quiesce(v, sd_tick_ms() + v->req_timeout);
  end = sd_tick_ms() + v->req_timeout + VFS_WAIT_GRACE_MS * 2;
  while (InterlockedCompareExchange(&v->busy, 0, 0) != 0 && sd_tick_ms() < end)
    Sleep(10);
  if (InterlockedCompareExchange(&v->busy, 0, 0) != 0) {
    SD_LOGE(VFS_LOG, "unmount with requests still running; leaking the mount state");
    return;
  }
  vc_drop_mount(v->mount_id);
  vfs_free_all(v);
}
