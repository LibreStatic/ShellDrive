/* sd_webdav: WebDAV methods over sd_vfs (02 §7.5, §7.6). Runs on connection threads after the gate in
 * wd_server.c (authenticated, owner SID checked, target decoded into q->vpath). */
#include "wd_server.h"

#include <stdio.h>
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_base/sd_utf.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_time.h"

#define WD_NS_DAV "DAV:"
#define WD_NS_MS  "urn:schemas-microsoft-com:"
#define MULTISTATUS_MAX (128u << 20)

#define ALLOW_RO "OPTIONS, GET, HEAD, PROPFIND, LOCK, UNLOCK"
#define ALLOW_RW "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK"

static const char k_xml_head[] = "<?xml version=\"1.0\" encoding=\"utf-8\"?>";
static const char k_ctype_xml[] = "application/xml; charset=\"utf-8\"";

int wd_status_from_vfs(sd_vfs_status st)
{
  switch (st) {
  case SD_VFS_OK: return 200;
  case SD_VFS_E_NOT_FOUND: case SD_VFS_E_PATH_NOT_FOUND: case SD_VFS_E_DELETE_PENDING: return 404;
  case SD_VFS_E_EXISTS: return 405;
  case SD_VFS_E_ACCESS_DENIED: case SD_VFS_E_READ_ONLY: case SD_VFS_E_CANNOT_DELETE: return 403;
  case SD_VFS_E_SHARING: return 423;
  case SD_VFS_E_NO_SPACE: case SD_VFS_E_QUOTA: return 507;
  case SD_VFS_E_DISCONNECTED: return 503;
  case SD_VFS_E_TIMEOUT: return 504;
  case SD_VFS_E_STALE: case SD_VFS_E_NOT_EMPTY: case SD_VFS_E_IS_DIR: case SD_VFS_E_NOT_DIR: return 409;
  case SD_VFS_E_TOO_LARGE: return 413;
  case SD_VFS_E_INVALID_NAME: case SD_VFS_E_NAME_TOO_LONG: return 400;
  case SD_VFS_E_UNSUPPORTED: return 501;
  default: return 500;
  }
}

static void fail_vfs(wd_rq *q, sd_vfs_status st, int missing_parent_409)
{
  int status = wd_status_from_vfs(st);
  if (missing_parent_409 && st == SD_VFS_E_PATH_NOT_FOUND)
    status = 409;
  if (status == 503)
    wd_respond(q, 503, "Retry-After: 10\r\n", NULL, NULL, 0);
  else
    wd_respond(q, status, NULL, NULL, NULL, 0);
}

static int method_is(const wd_rq *q, const char *m) { return strcmp(q->r.method, m) == 0; }

static int is_write_method(const wd_rq *q)
{
  return method_is(q, "PUT") || method_is(q, "DELETE") || method_is(q, "PROPPATCH") || method_is(q, "MKCOL") ||
         method_is(q, "MOVE") || method_is(q, "COPY") || method_is(q, "LOCK");
}

void wd_options(wd_rq *q)
{
  char extra[512];
  BOOL ro = q->ex ? q->ex->read_only : FALSE;
  _snprintf_s(extra, sizeof(extra), _TRUNCATE, "DAV: 1, 2\r\nMS-Author-Via: DAV\r\nAllow: %s\r\n",
              ro ? ALLOW_RO : ALLOW_RW);
  wd_respond(q, 200, extra, NULL, NULL, 0);
}

static uint32_t if_tokens(const wd_rq *q, char toks[][80])
{
  const wd_hdr *h = wd_req_header(&q->r, "If", NULL);
  return h ? wd_if_tokens(h->val, h->vlen, toks, WD_MAX_IF_TOKENS) : 0;
}

static int locked(wd_rq *q, const WCHAR *path, int with_children)
{
  char toks[WD_MAX_IF_TOKENS][80];
  uint32_t n = if_tokens(q, toks);
  return wd_lock_conflict(q->ex, path, with_children, toks, n);
}

/* ---- hrefs ---- */

/* prefix + the decoded segments [1..nseg) re-encoded; collections get a trailing slash. */
static void href_of(wd_sb *b, const sd_webdav_export *ex, const wd_path *p, BOOL dir)
{
  uint32_t i;
  if (ex == NULL) {
    wd_sb_str(b, "/");
    return;
  }
  wd_sb_str(b, ex->prefix);
  for (i = 1; i < p->nseg; i++) {
    wd_sb_str(b, "/");
    wd_href_seg(b, p->seg[i], strlen(p->seg[i]));
  }
  if (dir || p->nseg <= 1)
    wd_sb_str(b, "/");
}

/* ---- PROPFIND ---- */

enum { PF_ALLPROP, PF_PROP, PF_PROPNAME };

typedef struct pf_req { const char *ns, *name; } pf_req;

typedef struct pf_ctx {
  wd_rq *q;
  wd_sb *out;
  int mode;
  pf_req props[64]; uint32_t nprops;
  const char *base_href; size_t base_n;  /* collection href with trailing slash */
  int root;                               /* target is the mount root */
  const WCHAR *dir_vpath;
  int oom;
} pf_ctx;

static uint64_t ft64(const FILETIME *f) { return ((uint64_t)f->dwHighDateTime << 32) | f->dwLowDateTime; }

static void etag_of(const sd_vfs_info *in, char out[48])
{
  _snprintf_s(out, 48, _TRUNCATE, "\"%llx-%llx\"", (unsigned long long)ft64(&in->mtime), (unsigned long long)in->size);
}

/* Value of one live property into b; returns 0 when unknown. */
static int live_prop(pf_ctx *c, wd_sb *b, const char *ns, const char *name, const sd_vfs_info *in,
                     const char *display, const WCHAR *vpath, int self)
{
  char t[48];
  BOOL dir = (in->win_attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
  if (strcmp(ns, WD_NS_DAV) == 0) {
    if (strcmp(name, "resourcetype") == 0) {
      wd_sb_str(b, dir ? "<D:resourcetype><D:collection/></D:resourcetype>" : "<D:resourcetype/>");
    } else if (strcmp(name, "getcontentlength") == 0) {
      if (dir) return 0;
      wd_sb_fmt(b, "<D:getcontentlength>%llu</D:getcontentlength>", (unsigned long long)in->size);
    } else if (strcmp(name, "getlastmodified") == 0) {
      wd_rfc1123(ft64(&in->mtime), t);
      wd_sb_fmt(b, "<D:getlastmodified>%s</D:getlastmodified>", t);
    } else if (strcmp(name, "creationdate") == 0) {
      wd_rfc3339(ft64(&in->ctime), t);
      wd_sb_fmt(b, "<D:creationdate>%s</D:creationdate>", t);
    } else if (strcmp(name, "getetag") == 0) {
      if (dir) return 0;
      etag_of(in, t);
      wd_sb_str(b, "<D:getetag>");
      wd_sb_xml(b, t, strlen(t));
      wd_sb_str(b, "</D:getetag>");
    } else if (strcmp(name, "getcontenttype") == 0) {
      if (dir) return 0;
      wd_sb_str(b, "<D:getcontenttype>application/octet-stream</D:getcontenttype>");
    } else if (strcmp(name, "displayname") == 0) {
      wd_sb_str(b, "<D:displayname>");
      wd_sb_xml(b, display, strlen(display));
      wd_sb_str(b, "</D:displayname>");
    } else if (strcmp(name, "supportedlock") == 0) {
      wd_sb_str(b, "<D:supportedlock><D:lockentry><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/>"
                   "</D:locktype></D:lockentry><D:lockentry><D:lockscope><D:shared/></D:lockscope><D:locktype>"
                   "<D:write/></D:locktype></D:lockentry></D:supportedlock>");
    } else if (strcmp(name, "lockdiscovery") == 0) {
      if (c->q->ex) wd_lock_discovery(c->q->ex, vpath, b, NULL);
      else wd_sb_str(b, "<D:lockdiscovery/>");
    } else if ((strcmp(name, "quota-available-bytes") == 0 || strcmp(name, "quota-used-bytes") == 0) &&
               c->root && self && c->q->ex) {
      sd_vfs_statfs fs;
      memset(&fs, 0, sizeof(fs));
      sd_vfs_statfs_get(c->q->ex->vfs, &fs);
      if (name[6] == 'a')
        wd_sb_fmt(b, "<D:quota-available-bytes>%llu</D:quota-available-bytes>", (unsigned long long)fs.avail);
      else
        wd_sb_fmt(b, "<D:quota-used-bytes>%llu</D:quota-used-bytes>",
                  (unsigned long long)(fs.total >= fs.free ? fs.total - fs.free : 0));
    } else {
      return 0;
    }
    return 1;
  }
  if (strcmp(ns, WD_NS_MS) == 0) {
    if (strcmp(name, "Win32FileAttributes") == 0) {
      wd_sb_fmt(b, "<Z:Win32FileAttributes>%08X</Z:Win32FileAttributes>", (unsigned)in->win_attrs);
    } else if (strcmp(name, "Win32CreationTime") == 0) {
      wd_rfc1123(ft64(&in->ctime), t);
      wd_sb_fmt(b, "<Z:Win32CreationTime>%s</Z:Win32CreationTime>", t);
    } else if (strcmp(name, "Win32LastAccessTime") == 0) {
      wd_rfc1123(ft64(&in->atime), t);
      wd_sb_fmt(b, "<Z:Win32LastAccessTime>%s</Z:Win32LastAccessTime>", t);
    } else if (strcmp(name, "Win32LastModifiedTime") == 0) {
      wd_rfc1123(ft64(&in->mtime), t);
      wd_sb_fmt(b, "<Z:Win32LastModifiedTime>%s</Z:Win32LastModifiedTime>", t);
    } else {
      return 0;
    }
    return 1;
  }
  return 0;
}

static void empty_prop(wd_sb *b, const char *ns, const char *name)
{
  if (strcmp(ns, WD_NS_DAV) == 0) {
    wd_sb_fmt(b, "<D:%s/>", name);
  } else if (strcmp(ns, WD_NS_MS) == 0) {
    wd_sb_fmt(b, "<Z:%s/>", name);
  } else {
    wd_sb_str(b, "<X:");
    wd_sb_str(b, name);
    wd_sb_str(b, " xmlns:X=\"");
    wd_sb_xml(b, ns, strlen(ns));
    wd_sb_str(b, "\"/>");
  }
}

static const char *const k_all_dav[] = { "resourcetype", "getcontentlength", "getlastmodified", "creationdate",
                                         "getetag", "getcontenttype" };
static const char *const k_all_ms[] = { "Win32FileAttributes", "Win32CreationTime", "Win32LastAccessTime",
                                        "Win32LastModifiedTime" };

static void pf_entry(pf_ctx *c, const char *href, size_t href_n, const sd_vfs_info *in, const char *display,
                     const WCHAR *vpath, int self)
{
  wd_sb *b = c->out;
  uint32_t i;
  wd_sb_str(b, "<D:response><D:href>");
  wd_sb_xml(b, href, href_n);
  wd_sb_str(b, "</D:href><D:propstat><D:prop>");
  if (c->mode == PF_PROPNAME) {
    for (i = 0; i < SD_COUNTOF(k_all_dav); i++) wd_sb_fmt(b, "<D:%s/>", k_all_dav[i]);
    for (i = 0; i < SD_COUNTOF(k_all_ms); i++) wd_sb_fmt(b, "<Z:%s/>", k_all_ms[i]);
    wd_sb_str(b, "<D:supportedlock/><D:lockdiscovery/><D:displayname/>");
    wd_sb_str(b, "</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>");
    return;
  }
  if (c->mode == PF_ALLPROP) {
    for (i = 0; i < SD_COUNTOF(k_all_dav); i++) live_prop(c, b, WD_NS_DAV, k_all_dav[i], in, display, vpath, self);
    for (i = 0; i < SD_COUNTOF(k_all_ms); i++) live_prop(c, b, WD_NS_MS, k_all_ms[i], in, display, vpath, self);
    if (self) live_prop(c, b, WD_NS_DAV, "supportedlock", in, display, vpath, self);
    if (c->q->ex) {
      wd_sb tmp;
      wd_sb_init(&tmp, 1u << 20);
      wd_lock_discovery(c->q->ex, vpath, &tmp, NULL);
      if (!tmp.oom && tmp.n > strlen("<D:lockdiscovery></D:lockdiscovery>"))
        wd_sb_add(b, tmp.p, tmp.n);
      wd_sb_free(&tmp);
    }
    wd_sb_str(b, "</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>");
    return;
  }
  /* PF_PROP: found props in a 200 propstat, the rest in a 404 propstat */
  {
    int missing = 0;
    for (i = 0; i < c->nprops; i++)
      if (!live_prop(c, b, c->props[i].ns, c->props[i].name, in, display, vpath, self))
        missing = 1;
    wd_sb_str(b, "</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>");
    if (missing) {
      wd_sb tmp;
      wd_sb_str(b, "<D:propstat><D:prop>");
      wd_sb_init(&tmp, 1u << 20);
      for (i = 0; i < c->nprops; i++) {
        tmp.n = 0;
        if (!live_prop(c, &tmp, c->props[i].ns, c->props[i].name, in, display, vpath, self))
          empty_prop(b, c->props[i].ns, c->props[i].name);
      }
      wd_sb_free(&tmp);
      wd_sb_str(b, "</D:prop><D:status>HTTP/1.1 404 Not Found</D:status></D:propstat>");
    }
    wd_sb_str(b, "</D:response>");
  }
}

static BOOL pf_dirent(void *ctx, const WCHAR *name, const sd_vfs_info *info)
{
  pf_ctx *c = (pf_ctx *)ctx;
  char u8[1024];
  size_t ul = 0, nl = wcslen(name), cl;
  wd_sb href;
  WCHAR *child;
  BOOL dir = (info->win_attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
  if (sd_utf16_to_utf8(name, nl, u8, sizeof(u8) - 1, &ul, SD_UTF_STRICT) != SD_OK)
    return TRUE;                           /* not representable: skip */
  u8[ul] = 0;
  wd_sb_init(&href, 8192);
  wd_sb_add(&href, c->base_href, c->base_n);
  wd_href_seg(&href, u8, ul);
  if (dir) wd_sb_str(&href, "/");
  cl = wcslen(c->dir_vpath);
  child = (WCHAR *)sd_alloc((cl + nl + 2) * sizeof(WCHAR));
  if (child && !href.oom) {
    memcpy(child, c->dir_vpath, cl * sizeof(WCHAR));
    if (cl == 0 || c->dir_vpath[cl - 1] != L'\\') child[cl++] = L'\\';
    memcpy(child + cl, name, (nl + 1) * sizeof(WCHAR));
    pf_entry(c, href.p, href.n, info, u8, child, 0);
  } else {
    c->oom = 1;
  }
  sd_free(child);
  wd_sb_free(&href);
  return !c->out->oom && !c->oom;
}

static int pf_parse_body(wd_rq *q, pf_ctx *c)
{
  wd_sb body;
  wd_xdoc d;
  int rc, root, k;
  c->mode = PF_ALLPROP;
  wd_sb_init(&body, WD_MAX_XML);
  rc = wd_body_read_all(q, &body, WD_MAX_XML);
  if (rc != 0) {
    wd_sb_free(&body);
    return rc;
  }
  if (body.n == 0) {
    wd_sb_free(&body);
    return 0;                              /* empty body = allprop */
  }
  rc = wd_xml_parse(body.p, body.n, &d);
  wd_sb_free(&body);
  if (rc != 0)
    return rc;
  root = wd_xml_child(&d, -1, WD_NS_DAV, "propfind");
  if (root < 0) {
    wd_xml_free(&d);
    return 400;
  }
  if (wd_xml_child(&d, root, WD_NS_DAV, "propname") >= 0) {
    c->mode = PF_PROPNAME;
  } else if ((k = wd_xml_child(&d, root, WD_NS_DAV, "prop")) >= 0) {
    int i;
    c->mode = PF_PROP;
    for (i = d.n[k].child; i >= 0 && c->nprops < SD_COUNTOF(c->props); i = d.n[i].next) {
      if (d.n[i].ns[0] == 0)
        continue;                          /* no-namespace properties cannot be echoed compactly */
      c->props[c->nprops].ns = d.n[i].ns;
      c->props[c->nprops].name = d.n[i].name;
      c->nprops++;
    }
  }
  /* allprop (with or without include) is the default. The names are copied: the doc is freed here. */
  {
    uint32_t i;
    for (i = 0; i < c->nprops; i++) {
      size_t nl = strlen(c->props[i].ns), ml = strlen(c->props[i].name);
      char *s = (char *)sd_alloc(nl + ml + 2);
      if (s == NULL) {
        c->nprops = i;
        break;
      }
      memcpy(s, c->props[i].ns, nl + 1);
      memcpy(s + nl + 1, c->props[i].name, ml + 1);
      c->props[i].ns = s;
      c->props[i].name = s + nl + 1;
    }
  }
  wd_xml_free(&d);
  return 0;
}

static void m_propfind(wd_rq *q)
{
  const wd_hdr *dh = wd_req_header(&q->r, "Depth", NULL);
  int depth, rc;
  uint32_t i;
  pf_ctx c;
  wd_sb out, href;
  sd_vfs_info info;
  sd_vfs_status st;
  BOOL dir;
  if (dh && wd_ieq(dh->val, dh->vlen, "0")) depth = 0;
  else if (dh && wd_ieq(dh->val, dh->vlen, "1")) depth = 1;
  else {
    static const char body[] = "<?xml version=\"1.0\" encoding=\"utf-8\"?><D:error xmlns:D=\"DAV:\">"
                               "<D:propfind-finite-depth/></D:error>";
    wd_respond(q, 403, NULL, k_ctype_xml, body, sizeof(body) - 1);
    return;
  }
  memset(&c, 0, sizeof(c));
  c.q = q;
  rc = pf_parse_body(q, &c);
  if (rc != 0) {
    wd_respond(q, rc, NULL, NULL, NULL, 0);
    return;
  }
  wd_sb_init(&out, MULTISTATUS_MAX);
  wd_sb_init(&href, 64u * 1024u);
  c.out = &out;
  wd_sb_str(&out, k_xml_head);
  wd_sb_str(&out, "<D:multistatus xmlns:D=\"DAV:\" xmlns:Z=\"urn:schemas-microsoft-com:\">");
  if (q->ex == NULL) {
    /* "/": the server root, with no members (02 §7.4) */
    memset(&info, 0, sizeof(info));
    info.win_attrs = FILE_ATTRIBUTE_DIRECTORY;
    *(uint64_t *)&info.mtime = sd_filetime_now();
    info.ctime = info.atime = info.mtime;
    pf_entry(&c, "/", 1, &info, "", L"\\", 1);
  } else {
    c.root = q->path.nseg <= 1;
    st = sd_vfs_stat_path(q->ex->vfs, q->vpath, &info);
    if (st != SD_VFS_OK) {
      fail_vfs(q, st, 0);
      goto out;
    }
    dir = (info.win_attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
    href_of(&href, q->ex, &q->path, dir);
    {
      const char *disp = q->path.nseg > 1 ? q->path.seg[q->path.nseg - 1] : "";
      pf_entry(&c, href.p, href.n, &info, disp, q->vpath, 1);
    }
    if (depth == 1 && dir) {
      sd_vfs_handle *h = NULL;
      BOOL ex_, isd;
      st = sd_vfs_create(q->ex->vfs, q->vpath, &q->caller, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, SD_VFS_FILE_OPEN,
                         SD_VFS_FILE_DIRECTORY_FILE, 0, &h, &ex_, &isd);
      if (st == SD_VFS_OK) {
        c.base_href = href.p;
        c.base_n = href.n;
        c.dir_vpath = q->vpath;
        st = sd_vfs_readdir(h, pf_dirent, &c);
        sd_vfs_cleanup(h, FALSE);
        sd_vfs_close(h);
      }
      if (st != SD_VFS_OK) {
        fail_vfs(q, st, 0);
        goto out;
      }
    }
  }
  wd_sb_str(&out, "</D:multistatus>");
  if (out.oom || c.oom || href.oom) {
    SD_LOGW(WD_LOG, "PROPFIND response too large or out of memory");
    wd_respond(q, out.oom ? 507 : 500, NULL, NULL, NULL, 0);
  } else {
    wd_respond(q, 207, NULL, k_ctype_xml, out.p, out.n);
  }
out:
  for (i = 0; i < c.nprops; i++)
    sd_free((void *)c.props[i].ns);
  wd_sb_free(&out);
  wd_sb_free(&href);
}

/* ---- PROPPATCH ---- */

static int parse_hex32(const char *s, uint32_t *out)
{
  uint32_t v = 0, n = 0;
  for (; *s == ' '; s++) {}
  for (; *s && *s != ' '; s++, n++) {
    int c = (unsigned char)*s, d;
    if (c >= '0' && c <= '9') d = c - '0';
    else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
    else return -1;
    if (n >= 8) return -1;
    v = (v << 4) | (uint32_t)d;
  }
  if (n == 0) return -1;
  *out = v;
  return 0;
}

static void m_proppatch(wd_rq *q)
{
  wd_sb body, out, href;
  wd_xdoc d;
  int rc, root, op, ok_status = 200;
  FILETIME at, mt;
  BOOL have_at = FALSE, have_mt = FALSE, have_attr = FALSE;
  uint32_t attrs = 0;
  sd_vfs_handle *h = NULL;
  BOOL ex_, isd;
  sd_vfs_status st;
  if (q->ex == NULL || q->ex->read_only) {
    wd_respond(q, 403, NULL, NULL, NULL, 0);
    return;
  }
  if (locked(q, q->vpath, 0)) {
    wd_respond(q, 423, NULL, NULL, NULL, 0);
    return;
  }
  wd_sb_init(&body, WD_MAX_XML);
  rc = wd_body_read_all(q, &body, WD_MAX_XML);
  if (rc == 0)
    rc = body.n ? wd_xml_parse(body.p, body.n, &d) : 400;
  wd_sb_free(&body);
  if (rc != 0) {
    wd_respond(q, rc, NULL, NULL, NULL, 0);
    return;
  }
  root = wd_xml_child(&d, -1, WD_NS_DAV, "propertyupdate");
  if (root < 0) {
    wd_xml_free(&d);
    wd_respond(q, 400, NULL, NULL, NULL, 0);
    return;
  }
  for (op = d.n[root].child; op >= 0; op = d.n[op].next) {
    int pr, p;
    BOOL set = wd_xml_is(&d, op, WD_NS_DAV, "set");
    if (!set && !wd_xml_is(&d, op, WD_NS_DAV, "remove"))
      continue;
    pr = wd_xml_child(&d, op, WD_NS_DAV, "prop");
    for (p = pr >= 0 ? d.n[pr].child : -1; p >= 0; p = d.n[p].next) {
      uint64_t ft;
      if (!set || strcmp(d.n[p].ns, WD_NS_MS) != 0)
        continue;                          /* dead properties: accepted and discarded */
      if (strcmp(d.n[p].name, "Win32LastAccessTime") == 0 && wd_parse_rfc1123(d.n[p].text, strlen(d.n[p].text), &ft) == 0) {
        at.dwLowDateTime = (DWORD)ft; at.dwHighDateTime = (DWORD)(ft >> 32); have_at = TRUE;
      } else if (strcmp(d.n[p].name, "Win32LastModifiedTime") == 0 &&
                 wd_parse_rfc1123(d.n[p].text, strlen(d.n[p].text), &ft) == 0) {
        mt.dwLowDateTime = (DWORD)ft; mt.dwHighDateTime = (DWORD)(ft >> 32); have_mt = TRUE;
      } else if (strcmp(d.n[p].name, "Win32FileAttributes") == 0 && parse_hex32(d.n[p].text, &attrs) == 0) {
        have_attr = TRUE;
      }
    }
  }
  if (have_at || have_mt || have_attr) {
    st = sd_vfs_create(q->ex->vfs, q->vpath, &q->caller, FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, SD_VFS_FILE_OPEN, 0, 0, &h, &ex_, &isd);
    if (st == SD_VFS_OK) {
      if (have_at || have_mt) {
        sd_vfs_status s2 = sd_vfs_set_times(h, NULL, have_at ? &at : NULL, have_mt ? &mt : NULL);
        if (s2 != SD_VFS_OK) st = s2;
      }
      if (have_attr) {
        sd_vfs_status s2 = sd_vfs_set_winattrs(h, attrs);
        if (s2 != SD_VFS_OK && st == SD_VFS_OK) st = s2;
      }
      sd_vfs_cleanup(h, FALSE);
      sd_vfs_close(h);
    }
    if (st == SD_VFS_E_NOT_FOUND || st == SD_VFS_E_PATH_NOT_FOUND) {
      wd_xml_free(&d);
      fail_vfs(q, st, 0);
      return;
    }
    if (st != SD_VFS_OK)
      ok_status = wd_status_from_vfs(st);
  }
  wd_sb_init(&out, 4u << 20);
  wd_sb_init(&href, 64u * 1024u);
  href_of(&href, q->ex, &q->path, q->path.trailing_slash);
  wd_sb_str(&out, k_xml_head);
  wd_sb_str(&out, "<D:multistatus xmlns:D=\"DAV:\" xmlns:Z=\"urn:schemas-microsoft-com:\"><D:response><D:href>");
  wd_sb_xml(&out, href.p ? href.p : "", href.n);
  wd_sb_str(&out, "</D:href>");
  for (op = d.n[root].child; op >= 0; op = d.n[op].next) {
    int pr, p;
    pr = wd_xml_child(&d, op, WD_NS_DAV, "prop");
    for (p = pr >= 0 ? d.n[pr].child : -1; p >= 0; p = d.n[p].next) {
      int s = (strcmp(d.n[p].ns, WD_NS_MS) == 0) ? ok_status : 200;
      wd_sb_str(&out, "<D:propstat><D:prop>");
      if (d.n[p].ns[0])
        empty_prop(&out, d.n[p].ns, d.n[p].name);
      wd_sb_fmt(&out, "</D:prop><D:status>HTTP/1.1 %d %s</D:status></D:propstat>", s, wd_status_text(s));
    }
  }
  wd_sb_str(&out, "</D:response></D:multistatus>");
  wd_xml_free(&d);
  if (out.oom)
    wd_respond(q, 500, NULL, NULL, NULL, 0);
  else
    wd_respond(q, 207, NULL, k_ctype_xml, out.p, out.n);
  wd_sb_free(&out);
  wd_sb_free(&href);
}

/* ---- GET / HEAD ---- */

static int etag_match(const wd_hdr *h, const char *etag)
{
  size_t el = strlen(etag), i = 0;
  if (h == NULL)
    return 0;
  while (i < h->vlen) {
    size_t s, e;
    while (i < h->vlen && (h->val[i] == ' ' || h->val[i] == ',')) i++;
    s = i;
    while (i < h->vlen && h->val[i] != ',') i++;
    e = i;
    while (e > s && h->val[e - 1] == ' ') e--;
    if (e - s == 1 && h->val[s] == '*') return 1;
    if (e - s >= 2 && h->val[s] == 'W' && h->val[s + 1] == '/') s += 2;
    if (e - s == el && memcmp(h->val + s, etag, el) == 0) return 1;
  }
  return 0;
}

static void m_get(wd_rq *q, BOOL head)
{
  sd_vfs_handle *h = NULL;
  sd_vfs_info info;
  BOOL ex_, isd;
  sd_vfs_status st;
  char etag[48], lm[32], extra[512];
  uint64_t first = 0, last = 0, len, off;
  int range = 0;
  const wd_hdr *rh;
  char *buf;
  if (q->ex == NULL) {
    static const char page[] = "<html><body>ShellDrive</body></html>";
    wd_respond(q, 200, NULL, "text/html; charset=utf-8", head ? NULL : page, head ? 0 : sizeof(page) - 1);
    return;
  }
  st = sd_vfs_stat_path(q->ex->vfs, q->vpath, &info);
  if (st == SD_VFS_OK && (info.win_attrs & FILE_ATTRIBUTE_DIRECTORY)) {
    static const char page[] = "<html><body>ShellDrive folder</body></html>";
    wd_respond(q, 200, NULL, "text/html; charset=utf-8", head ? NULL : page, head ? 0 : sizeof(page) - 1);
    return;
  }
  if (st == SD_VFS_OK)
    st = sd_vfs_create(q->ex->vfs, q->vpath, &q->caller, FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, SD_VFS_FILE_OPEN,
                       SD_VFS_FILE_NON_DIRECTORY_FILE | SD_VFS_FILE_SEQUENTIAL_ONLY, 0, &h, &ex_, &isd);
  if (st == SD_VFS_OK)
    st = sd_vfs_getattr(h, &info);
  if (st != SD_VFS_OK) {
    if (h) { sd_vfs_cleanup(h, FALSE); sd_vfs_close(h); }
    fail_vfs(q, st, 0);
    return;
  }
  etag_of(&info, etag);
  wd_rfc1123(ft64(&info.mtime), lm);
  if (etag_match(wd_req_header(&q->r, "If-None-Match", NULL), etag)) {
    sd_vfs_cleanup(h, FALSE);
    sd_vfs_close(h);
    _snprintf_s(extra, sizeof(extra), _TRUNCATE, "ETag: %s\r\nLast-Modified: %s\r\n", etag, lm);
    wd_respond(q, 304, extra, NULL, NULL, 0);
    return;
  }
  {
    const wd_hdr *ims = wd_req_header(&q->r, "If-Modified-Since", NULL);
    uint64_t t;
    if (ims && !wd_req_header(&q->r, "If-None-Match", NULL) && wd_parse_rfc1123(ims->val, ims->vlen, &t) == 0 &&
        ft64(&info.mtime) / 10000000u <= t / 10000000u) {
      sd_vfs_cleanup(h, FALSE);
      sd_vfs_close(h);
      _snprintf_s(extra, sizeof(extra), _TRUNCATE, "ETag: %s\r\nLast-Modified: %s\r\n", etag, lm);
      wd_respond(q, 304, extra, NULL, NULL, 0);
      return;
    }
  }
  rh = wd_req_header(&q->r, "Range", NULL);
  if (rh) {
    const wd_hdr *ir = wd_req_header(&q->r, "If-Range", NULL);
    if (ir == NULL || (ir->vlen == strlen(etag) && memcmp(ir->val, etag, ir->vlen) == 0) ||
        (ir->vlen == strlen(lm) && memcmp(ir->val, lm, ir->vlen) == 0))
      range = wd_range_parse(rh->val, rh->vlen, info.size, &first, &last);
  }
  if (range == 416) {
    sd_vfs_cleanup(h, FALSE);
    sd_vfs_close(h);
    _snprintf_s(extra, sizeof(extra), _TRUNCATE, "Content-Range: bytes */%llu\r\n", (unsigned long long)info.size);
    wd_respond(q, 416, extra, NULL, NULL, 0);
    return;
  }
  if (range == 1) {
    len = last - first + 1;
    _snprintf_s(extra, sizeof(extra), _TRUNCATE,
                "ETag: %s\r\nLast-Modified: %s\r\nAccept-Ranges: bytes\r\nContent-Range: bytes %llu-%llu/%llu\r\n",
                etag, lm, (unsigned long long)first, (unsigned long long)last, (unsigned long long)info.size);
  } else {
    first = 0;
    len = info.size;
    _snprintf_s(extra, sizeof(extra), _TRUNCATE, "ETag: %s\r\nLast-Modified: %s\r\nAccept-Ranges: bytes\r\n", etag, lm);
  }
  /* headers go out as soon as the attributes are known (60 s SendReceiveTimeoutInSec, 02 §7.5) */
  if (wd_respond_head(q, range == 1 ? 206 : 200, extra, "application/octet-stream", len) != 0 || head) {
    sd_vfs_cleanup(h, FALSE);
    sd_vfs_close(h);
    return;
  }
  buf = (char *)sd_alloc(WD_IO_CHUNK);
  off = first;
  while (buf && len > 0) {
    UINT32 want = (UINT32)SD_MIN(len, (uint64_t)WD_IO_CHUNK), got = 0;
    st = sd_vfs_read(h, off, buf, want, &got);
    if ((st != SD_VFS_OK && st != SD_VFS_E_END_OF_FILE) || got == 0)
      break;
    if (wd_send_all(q->c, buf, got) != 0)
      break;
    off += got;
    len -= got;
  }
  if (len > 0) {
    SD_LOGW(WD_LOG, "GET aborted with %llu bytes left (%d)", (unsigned long long)len, (int)st);
    q->close_after = 1;                    /* the length was announced: the only signal is closing */
  }
  sd_free(buf);
  sd_vfs_cleanup(h, FALSE);
  sd_vfs_close(h);
}

/* ---- PUT ---- */

static void m_put(wd_rq *q)
{
  sd_vfs_handle *h = NULL;
  BOOL existed = FALSE, isd = FALSE;
  sd_vfs_status st;
  uint32_t disp = SD_VFS_FILE_OVERWRITE_IF;
  const wd_hdr *inm = wd_req_header(&q->r, "If-None-Match", NULL);
  uint64_t off = 0;
  if (q->ex == NULL || q->path.nseg <= 1 || q->path.trailing_slash) {
    wd_respond(q, q->ex == NULL ? 405 : 409, NULL, NULL, NULL, 0);
    return;
  }
  if (q->ex->read_only) {
    wd_respond(q, 403, NULL, NULL, NULL, 0);
    return;
  }
  if (locked(q, q->vpath, 0)) {
    wd_respond(q, 423, NULL, NULL, NULL, 0);
    return;
  }
  if (inm && inm->vlen == 1 && inm->val[0] == '*')
    disp = SD_VFS_FILE_CREATE;
  st = sd_vfs_create(q->ex->vfs, q->vpath, &q->caller,
                     FILE_WRITE_DATA | FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
                     FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, disp, SD_VFS_FILE_NON_DIRECTORY_FILE,
                     FILE_ATTRIBUTE_ARCHIVE, &h, &existed, &isd);
  if (st != SD_VFS_OK) {
    if (st == SD_VFS_E_EXISTS)
      wd_respond(q, 412, NULL, NULL, NULL, 0);
    else if (st == SD_VFS_E_IS_DIR)
      wd_respond(q, 405, NULL, NULL, NULL, 0);
    else
      fail_vfs(q, st, 1);
    return;
  }
  /* streamed into vfs writes as it arrives; TCP backpressure bounds the window */
  for (;;) {
    const char *p;
    size_t n;
    if (wd_body_next(q, &p, &n) != 0) {
      st = SD_VFS_E_IO;
      break;
    }
    if (n == 0)
      break;
    while (n > 0) {
      UINT32 done = 0;
      st = sd_vfs_write(h, off, p, (UINT32)SD_MIN(n, (size_t)WD_IO_CHUNK), &done, FALSE);
      if (st != SD_VFS_OK || done == 0) {
        if (st == SD_VFS_OK) st = SD_VFS_E_IO;
        break;
      }
      off += done;
      p += done;
      n -= done;
    }
    if (st != SD_VFS_OK)
      break;
  }
  if (st == SD_VFS_OK)
    st = sd_vfs_flush(h);
  {
    sd_vfs_status cs = sd_vfs_cleanup(h, FALSE);
    if (st == SD_VFS_OK) st = cs;
  }
  sd_vfs_close(h);
  if (st != SD_VFS_OK) {
    SD_LOGW(WD_LOG, "PUT failed after %llu bytes (%d)", (unsigned long long)off, (int)st);
    if (!q->body_done) q->close_after = 1;
    fail_vfs(q, st == SD_VFS_E_IO && q->body_error ? SD_VFS_E_IO : st, 1);
    return;
  }
  wd_respond(q, existed ? 204 : 201, NULL, NULL, NULL, 0);
}

/* ---- DELETE / MKCOL ---- */

static void m_delete(wd_rq *q)
{
  sd_vfs_status st;
  if (q->ex == NULL || q->path.nseg <= 1 || q->ex->read_only) {
    wd_respond(q, 403, NULL, NULL, NULL, 0);
    return;
  }
  if (locked(q, q->vpath, 1)) {
    wd_respond(q, 423, NULL, NULL, NULL, 0);
    return;
  }
  st = sd_vfs_delete_path(q->ex->vfs, &q->caller, q->vpath, TRUE);
  if (st != SD_VFS_OK) {
    fail_vfs(q, st, 0);
    return;
  }
  wd_lock_drop_tree(q->ex, q->vpath);
  wd_respond(q, 204, NULL, NULL, NULL, 0);
}

static sd_vfs_status mkdir_path(wd_rq *q, const WCHAR *path)
{
  sd_vfs_handle *h = NULL;
  BOOL ex_, isd;
  sd_vfs_status st = sd_vfs_create(q->ex->vfs, path, &q->caller, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, SD_VFS_FILE_CREATE,
                                   SD_VFS_FILE_DIRECTORY_FILE, FILE_ATTRIBUTE_DIRECTORY, &h, &ex_, &isd);
  if (st == SD_VFS_OK) {
    sd_vfs_cleanup(h, FALSE);
    sd_vfs_close(h);
  }
  return st;
}

static void m_mkcol(wd_rq *q)
{
  sd_vfs_status st;
  if (q->ex == NULL || q->path.nseg <= 1) {
    wd_respond(q, 405, NULL, NULL, NULL, 0);
    return;
  }
  if (q->ex->read_only) {
    wd_respond(q, 403, NULL, NULL, NULL, 0);
    return;
  }
  if (wd_has_body(q)) {
    wd_respond(q, 415, NULL, NULL, NULL, 0);
    return;
  }
  if (locked(q, q->vpath, 0)) {
    wd_respond(q, 423, NULL, NULL, NULL, 0);
    return;
  }
  st = mkdir_path(q, q->vpath);
  if (st == SD_VFS_E_EXISTS) {
    wd_respond(q, 405, NULL, NULL, NULL, 0);
    return;
  }
  if (st != SD_VFS_OK) {
    fail_vfs(q, st, 1);
    return;
  }
  wd_respond(q, 201, NULL, NULL, NULL, 0);
}

/* ---- MOVE / COPY ---- */

typedef struct name_list { WCHAR **v; uint32_t n, cap; int oom; } name_list;

static BOOL collect(void *ctx, const WCHAR *name, const sd_vfs_info *info)
{
  name_list *l = (name_list *)ctx;
  size_t nl = wcslen(name);
  SD_UNUSED(info);
  if (l->n == l->cap) {
    uint32_t nc = l->cap ? l->cap * 2 : 32;
    WCHAR **nv = (WCHAR **)sd_realloc(l->v, nc * sizeof(WCHAR *));
    if (nv == NULL) { l->oom = 1; return FALSE; }
    l->v = nv;
    l->cap = nc;
  }
  l->v[l->n] = (WCHAR *)sd_alloc((nl + 1) * sizeof(WCHAR));
  if (l->v[l->n] == NULL) { l->oom = 1; return FALSE; }
  memcpy(l->v[l->n], name, (nl + 1) * sizeof(WCHAR));
  l->n++;
  return TRUE;
}

static WCHAR *join(const WCHAR *a, const WCHAR *b)
{
  size_t la = wcslen(a), lb = wcslen(b);
  WCHAR *r = (WCHAR *)sd_alloc((la + lb + 2) * sizeof(WCHAR));
  if (r) {
    memcpy(r, a, la * sizeof(WCHAR));
    if (la == 0 || a[la - 1] != L'\\') r[la++] = L'\\';
    memcpy(r + la, b, (lb + 1) * sizeof(WCHAR));
  }
  return r;
}

static sd_vfs_status copy_file(wd_rq *q, const WCHAR *from, const WCHAR *to)
{
  sd_vfs *v = q->ex->vfs;
  sd_vfs_handle *src = NULL, *dst = NULL;
  BOOL ex_, isd;
  sd_vfs_status st;
  char *buf = NULL;
  uint64_t off = 0;
  sd_vfs_info info;
  st = sd_vfs_create(v, from, &q->caller, FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                     FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, SD_VFS_FILE_OPEN,
                     SD_VFS_FILE_NON_DIRECTORY_FILE, 0, &src, &ex_, &isd);
  if (st == SD_VFS_OK)
    st = sd_vfs_getattr(src, &info);
  if (st == SD_VFS_OK)
    st = sd_vfs_create(v, to, &q->caller, FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, SD_VFS_FILE_CREATE,
                       SD_VFS_FILE_NON_DIRECTORY_FILE, FILE_ATTRIBUTE_ARCHIVE, &dst, &ex_, &isd);
  if (st == SD_VFS_OK) {
    buf = (char *)sd_alloc(WD_IO_CHUNK);
    if (buf == NULL) st = SD_VFS_E_NO_MEMORY;
  }
  while (st == SD_VFS_OK) {
    UINT32 got = 0, done = 0;
    st = sd_vfs_read(src, off, buf, WD_IO_CHUNK, &got);
    if (st == SD_VFS_E_END_OF_FILE || (st == SD_VFS_OK && got == 0)) {
      st = SD_VFS_OK;
      break;
    }
    if (st != SD_VFS_OK)
      break;
    st = sd_vfs_write(dst, off, buf, got, &done, FALSE);
    if (st == SD_VFS_OK && done != got) st = SD_VFS_E_IO;
    off += got;
  }
  if (st == SD_VFS_OK && dst)
    st = sd_vfs_set_times(dst, NULL, NULL, &info.mtime);
  sd_free(buf);
  if (dst) {
    sd_vfs_status cs = sd_vfs_cleanup(dst, FALSE);
    if (st == SD_VFS_OK) st = cs;
    sd_vfs_close(dst);
  }
  if (src) {
    sd_vfs_cleanup(src, FALSE);
    sd_vfs_close(src);
  }
  return st;
}

static sd_vfs_status copy_tree(wd_rq *q, const WCHAR *from, const WCHAR *to, BOOL recursive, uint32_t level)
{
  sd_vfs_info info;
  sd_vfs_status st = sd_vfs_stat_path(q->ex->vfs, from, &info);
  sd_vfs_handle *h = NULL;
  name_list l;
  BOOL ex_, isd;
  uint32_t i;
  if (st != SD_VFS_OK)
    return st;
  if (!(info.win_attrs & FILE_ATTRIBUTE_DIRECTORY))
    return copy_file(q, from, to);
  if (level > 64)
    return SD_VFS_E_NAME_TOO_LONG;
  st = mkdir_path(q, to);
  if (st != SD_VFS_OK || !recursive)
    return st;
  memset(&l, 0, sizeof(l));
  st = sd_vfs_create(q->ex->vfs, from, &q->caller, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                     FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, SD_VFS_FILE_OPEN,
                     SD_VFS_FILE_DIRECTORY_FILE, 0, &h, &ex_, &isd);
  if (st == SD_VFS_OK) {
    st = sd_vfs_readdir(h, collect, &l);
    if (l.oom) st = SD_VFS_E_NO_MEMORY;
    sd_vfs_cleanup(h, FALSE);
    sd_vfs_close(h);
  }
  for (i = 0; i < l.n; i++) {
    if (st == SD_VFS_OK) {
      WCHAR *f = join(from, l.v[i]), *t = join(to, l.v[i]);
      st = (f && t) ? copy_tree(q, f, t, TRUE, level + 1) : SD_VFS_E_NO_MEMORY;
      sd_free(f);
      sd_free(t);
    }
    sd_free(l.v[i]);
  }
  sd_free(l.v);
  return st;
}

static void m_move_copy(wd_rq *q, BOOL move)
{
  const wd_hdr *dh = wd_req_header(&q->r, "Destination", NULL);
  const wd_hdr *oh = wd_req_header(&q->r, "Overwrite", NULL);
  wd_path dest;
  WCHAR *dv = NULL;
  BOOL overwrite = TRUE, existed;
  sd_vfs_info di;
  sd_vfs_status st;
  int rc, recursive = 1;
  if (q->ex == NULL || q->path.nseg <= 1) {
    wd_respond(q, 403, NULL, NULL, NULL, 0);
    return;
  }
  if (dh == NULL) {
    wd_respond(q, 400, NULL, NULL, NULL, 0);
    return;
  }
  rc = wd_destination_parse(dh->val, dh->vlen, q->host, q->host_n, &dest);
  if (rc != 0) {
    wd_respond(q, rc, NULL, NULL, NULL, 0);
    return;
  }
  if (dest.nseg < 1 || strcmp(dest.seg[0], q->path.seg[0]) != 0) {
    wd_path_free(&dest);
    wd_respond(q, 502, NULL, NULL, NULL, 0);   /* another token: another server for the client */
    return;
  }
  if (dest.nseg < 2) {
    wd_path_free(&dest);
    wd_respond(q, 403, NULL, NULL, NULL, 0);
    return;
  }
  dv = wd_path_to_vfs(&dest, 1);
  wd_path_free(&dest);
  if (dv == NULL) {
    wd_respond(q, 400, NULL, NULL, NULL, 0);
    return;
  }
  if (oh && oh->vlen == 1 && (oh->val[0] == 'F' || oh->val[0] == 'f')) overwrite = FALSE;
  else if (oh && !(oh->vlen == 1 && (oh->val[0] == 'T' || oh->val[0] == 't'))) {
    sd_free(dv);
    wd_respond(q, 400, NULL, NULL, NULL, 0);
    return;
  }
  if (!move) {
    const wd_hdr *dep = wd_req_header(&q->r, "Depth", NULL);
    if (dep && wd_ieq(dep->val, dep->vlen, "0")) recursive = 0;
    else if (dep && !wd_ieq(dep->val, dep->vlen, "infinity")) {
      sd_free(dv);
      wd_respond(q, 400, NULL, NULL, NULL, 0);
      return;
    }
  }
  if (q->ex->read_only) {
    sd_free(dv);
    wd_respond(q, 403, NULL, NULL, NULL, 0);
    return;
  }
  if (_wcsicmp(dv, q->vpath) == 0) {
    /* The same resource (RFC 4918 §9.9.4: 403), except a case-only MOVE: in the case-insensitive view
       that is a rename of the resource onto itself, which Explorer sends for "Case.txt" -> "case.TXT". */
    if (!move || wcscmp(dv, q->vpath) == 0) {
      sd_free(dv);
      wd_respond(q, 403, NULL, NULL, NULL, 0);
      return;
    }
    if (locked(q, q->vpath, 1)) {
      sd_free(dv);
      wd_respond(q, 423, NULL, NULL, NULL, 0);
      return;
    }
    st = sd_vfs_rename_path(q->ex->vfs, &q->caller, q->vpath, dv, TRUE);
    if (st == SD_VFS_OK)
      wd_lock_move(q->ex, q->vpath, dv);
    sd_free(dv);
    if (st == SD_VFS_OK)
      wd_respond(q, 201, NULL, NULL, NULL, 0);
    else
      fail_vfs(q, st, 1);
    return;
  }
  if ((move && locked(q, q->vpath, 1)) || locked(q, dv, 1)) {
    sd_free(dv);
    wd_respond(q, 423, NULL, NULL, NULL, 0);
    return;
  }
  existed = sd_vfs_stat_path(q->ex->vfs, dv, &di) == SD_VFS_OK;
  if (existed && !overwrite) {
    sd_free(dv);
    wd_respond(q, 412, NULL, NULL, NULL, 0);
    return;
  }
  if (move) {
    st = sd_vfs_rename_path(q->ex->vfs, &q->caller, q->vpath, dv, overwrite);
    if (st != SD_VFS_OK && existed && overwrite && st != SD_VFS_E_NOT_FOUND && st != SD_VFS_E_PATH_NOT_FOUND) {
      /* Overwrite: T means "delete the destination first" (RFC 4918 §9.9.3), e.g. a folder */
      if (sd_vfs_delete_path(q->ex->vfs, &q->caller, dv, TRUE) == SD_VFS_OK)
        st = sd_vfs_rename_path(q->ex->vfs, &q->caller, q->vpath, dv, FALSE);
    }
    if (st == SD_VFS_OK)   /* the destination URL keeps its lock (Office save, 02 §7.5) */
      wd_lock_replace(q->ex, q->vpath, dv);
  } else {
    st = SD_VFS_OK;
    if (existed)
      st = sd_vfs_delete_path(q->ex->vfs, &q->caller, dv, TRUE);
    if (st == SD_VFS_OK)
      st = copy_tree(q, q->vpath, dv, recursive, 0);
    if (st == SD_VFS_OK && existed)   /* the replaced tree's children are gone; the destination URL keeps its lock */
      wd_lock_drop_below(q->ex, dv);
  }
  sd_free(dv);
  if (st == SD_VFS_E_EXISTS) {
    wd_respond(q, 412, NULL, NULL, NULL, 0);
    return;
  }
  if (st != SD_VFS_OK) {
    fail_vfs(q, st, 1);
    return;
  }
  wd_respond(q, existed ? 204 : 201, NULL, NULL, NULL, 0);
}

/* ---- LOCK / UNLOCK ---- */

static void m_lock(wd_rq *q)
{
  const wd_hdr *th = wd_req_header(&q->r, "Timeout", NULL);
  const wd_hdr *dh = wd_req_header(&q->r, "Depth", NULL);
  uint32_t timeout = th ? wd_timeout_parse(th->val, th->vlen) : 3600u;
  char token[64], extra[160];
  wd_sb body, out;
  int rc, created = 0, depth_inf = 1, exclusive = 1;
  sd_vfs_info info;
  sd_vfs_status st;
  char owner[512];
  if (q->ex == NULL || q->ex->read_only) {
    wd_respond(q, 403, NULL, NULL, NULL, 0);   /* Office then opens read-only */
    return;
  }
  if (dh && wd_ieq(dh->val, dh->vlen, "0")) depth_inf = 0;
  else if (dh && !wd_ieq(dh->val, dh->vlen, "infinity")) {
    wd_respond(q, 400, NULL, NULL, NULL, 0);
    return;
  }
  wd_sb_init(&body, WD_MAX_XML);
  rc = wd_body_read_all(q, &body, WD_MAX_XML);
  if (rc != 0) {
    wd_sb_free(&body);
    wd_respond(q, rc, NULL, NULL, NULL, 0);
    return;
  }
  owner[0] = 0;
  if (body.n == 0) {
    /* refresh */
    char toks[WD_MAX_IF_TOKENS][80];
    uint32_t n = if_tokens(q, toks);
    wd_sb_free(&body);
    if (n == 0 || wd_lock_refresh(q->ex, q->vpath, toks, n, timeout, token) != 0) {
      wd_respond(q, 412, NULL, NULL, NULL, 0);
      return;
    }
  } else {
    wd_xdoc d;
    int root, k;
    rc = wd_xml_parse(body.p, body.n, &d);
    wd_sb_free(&body);
    if (rc != 0) {
      wd_respond(q, rc, NULL, NULL, NULL, 0);
      return;
    }
    root = wd_xml_child(&d, -1, WD_NS_DAV, "lockinfo");
    k = root >= 0 ? wd_xml_child(&d, root, WD_NS_DAV, "lockscope") : -1;
    if (root < 0 || k < 0) {
      wd_xml_free(&d);
      wd_respond(q, 400, NULL, NULL, NULL, 0);
      return;
    }
    exclusive = wd_xml_child(&d, k, WD_NS_DAV, "shared") < 0;
    k = wd_xml_child(&d, root, WD_NS_DAV, "owner");
    if (k >= 0) {
      int hr = wd_xml_child(&d, k, WD_NS_DAV, "href");
      const char *t = hr >= 0 ? d.n[hr].text : d.n[k].text;
      size_t tl = strlen(t);
      if (tl < sizeof(owner)) memcpy(owner, t, tl + 1);
    }
    wd_xml_free(&d);
    st = sd_vfs_stat_path(q->ex->vfs, q->vpath, &info);
    if (st == SD_VFS_E_NOT_FOUND) {
      /* LOCK on an unmapped URL creates a locked empty resource (RFC 4918 §7.3) */
      sd_vfs_handle *h = NULL;
      BOOL ex_, isd;
      if (q->path.trailing_slash) {
        wd_respond(q, 409, NULL, NULL, NULL, 0);
        return;
      }
      if (locked(q, q->vpath, 0)) {
        wd_respond(q, 423, NULL, NULL, NULL, 0);
        return;
      }
      st = sd_vfs_create(q->ex->vfs, q->vpath, &q->caller, FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, SD_VFS_FILE_CREATE,
                         SD_VFS_FILE_NON_DIRECTORY_FILE, FILE_ATTRIBUTE_ARCHIVE, &h, &ex_, &isd);
      if (st == SD_VFS_OK) {
        sd_vfs_cleanup(h, FALSE);
        sd_vfs_close(h);
        created = 1;
        depth_inf = 0;
      }
    } else if (st == SD_VFS_OK && !(info.win_attrs & FILE_ATTRIBUTE_DIRECTORY)) {
      depth_inf = 0;
    }
    if (st != SD_VFS_OK) {
      fail_vfs(q, st, 1);
      return;
    }
    rc = wd_lock_create(q->ex, q->vpath, exclusive, depth_inf, timeout, owner, token);
    if (rc != 0) {
      wd_respond(q, rc, NULL, NULL, NULL, 0);
      return;
    }
  }
  wd_sb_init(&out, 1u << 20);
  wd_sb_str(&out, k_xml_head);
  wd_sb_str(&out, "<D:prop xmlns:D=\"DAV:\">");
  wd_lock_discovery(q->ex, q->vpath, &out, token);
  wd_sb_str(&out, "</D:prop>");
  _snprintf_s(extra, sizeof(extra), _TRUNCATE, "Lock-Token: <%s>\r\n", token);
  if (out.oom)
    wd_respond(q, 500, NULL, NULL, NULL, 0);
  else
    wd_respond(q, created ? 201 : 200, extra, k_ctype_xml, out.p, out.n);
  wd_sb_free(&out);
}

static void m_unlock(wd_rq *q)
{
  const wd_hdr *lh = wd_req_header(&q->r, "Lock-Token", NULL);
  char tok[80];
  if (q->ex == NULL) {
    wd_respond(q, 409, NULL, NULL, NULL, 0);
    return;
  }
  if (lh == NULL || lh->vlen < 3 || lh->vlen - 2 >= sizeof(tok) || lh->val[0] != '<' || lh->val[lh->vlen - 1] != '>') {
    wd_respond(q, 400, NULL, NULL, NULL, 0);
    return;
  }
  memcpy(tok, lh->val + 1, lh->vlen - 2);
  tok[lh->vlen - 2] = 0;
  wd_respond(q, wd_lock_remove(q->ex, q->vpath, tok) == 0 ? 204 : 409, NULL, NULL, NULL, 0);
}

/* ---- dispatch ---- */

void wd_dispatch(wd_rq *q)
{
  if (q->ex == NULL && is_write_method(q)) {
    wd_respond(q, 403, NULL, NULL, NULL, 0);
    return;
  }
  if (method_is(q, "PROPFIND")) m_propfind(q);
  else if (method_is(q, "GET")) m_get(q, FALSE);
  else if (method_is(q, "HEAD")) m_get(q, TRUE);
  else if (method_is(q, "PUT")) m_put(q);
  else if (method_is(q, "PROPPATCH")) m_proppatch(q);
  else if (method_is(q, "DELETE")) m_delete(q);
  else if (method_is(q, "MKCOL")) m_mkcol(q);
  else if (method_is(q, "MOVE")) m_move_copy(q, TRUE);
  else if (method_is(q, "COPY")) m_move_copy(q, FALSE);
  else if (method_is(q, "LOCK")) m_lock(q);
  else if (method_is(q, "UNLOCK")) m_unlock(q);
  else if (method_is(q, "POST") || method_is(q, "PATCH") || method_is(q, "TRACE") || method_is(q, "CONNECT"))
    wd_respond(q, 405, "Allow: " ALLOW_RW "\r\n", NULL, NULL, 0);
  else
    wd_respond(q, 501, NULL, NULL, NULL, 0);
}
