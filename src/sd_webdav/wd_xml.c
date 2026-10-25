/* sd_webdav: minimal namespace-aware XML parser for PROPFIND/PROPPATCH/LOCK bodies (02 §7.5).
 *
 * Supports elements, attributes (only xmlns declarations are interpreted), character data with the
 * five predefined entities and numeric references, CDATA, comments and processing instructions.
 * Rejects DOCTYPE/DTDs (no entity expansion at all), other entity references, depth > 32,
 * > 8192 elements, input > 1 MiB, invalid UTF-8, mismatched tags and trailing content. */
#include <windows.h>
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_base/sd_utf.h"
#include "wd_proto.h"

#define MAX_NS 128

typedef struct ns_decl { const char *prefix; uint32_t plen; const char *uri; uint32_t depth; } ns_decl;

typedef struct xp {
  const char *p; size_t n, i;
  wd_xdoc *d;
  char *arena; size_t an, acap;
  ns_decl ns[MAX_NS]; uint32_t nns;
  int stack[WD_MAX_XML_DEPTH + 1]; const char *qn[WD_MAX_XML_DEPTH + 1]; uint32_t qlen[WD_MAX_XML_DEPTH + 1];
  uint32_t depth;
  int last_child[WD_MAX_XML_DEPTH + 1];
  /* per-node text accumulation: text of node stack[depth-1] */
  size_t text_start[WD_MAX_XML_DEPTH + 1];
  int text_open[WD_MAX_XML_DEPTH + 1];
} xp;

/* Arena: strings are appended; offsets are converted to pointers at the end (the arena may move). */
static int arena_add(xp *x, const char *s, size_t n, size_t *off)
{
  if (x->an + n + 1 > x->acap)
    return -1;                             /* sized up front: never grows */
  if (off) *off = x->an;
  memcpy(x->arena + x->an, s, n);
  x->an += n;
  return 0;
}

static int is_name_char(unsigned char c)
{
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' ||
         c == '.' || c == ':' || c >= 0x80;
}

static int is_ws(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

static void skip_ws(xp *x)
{
  while (x->i < x->n && is_ws(x->p[x->i]))
    x->i++;
}

static int starts(xp *x, const char *s)
{
  size_t l = strlen(s);
  return x->n - x->i >= l && memcmp(x->p + x->i, s, l) == 0;
}

static int find(xp *x, const char *s)
{
  size_t l = strlen(s);
  while (x->n - x->i >= l) {
    if (memcmp(x->p + x->i, s, l) == 0) {
      x->i += l;
      return 0;
    }
    x->i++;
  }
  return -1;
}

static int read_name(xp *x, const char **name, uint32_t *len)
{
  size_t s = x->i;
  while (x->i < x->n && is_name_char((unsigned char)x->p[x->i]))
    x->i++;
  if (x->i == s || (x->p[s] >= '0' && x->p[s] <= '9') || x->p[s] == '-' || x->p[s] == '.')
    return -1;
  *name = x->p + s;
  *len = (uint32_t)(x->i - s);
  return 0;
}

/* Decodes character data [s, e) with entity references into the arena (appending). */
static int decode_text(xp *x, const char *s, size_t n)
{
  size_t i = 0;
  while (i < n) {
    if (s[i] == '&') {
      size_t j = i + 1;
      while (j < n && s[j] != ';' && j - i < 12) j++;
      if (j >= n || s[j] != ';')
        return -1;
      if (j - i - 1 == 2 && memcmp(s + i + 1, "lt", 2) == 0) { if (arena_add(x, "<", 1, NULL)) return -1; }
      else if (j - i - 1 == 2 && memcmp(s + i + 1, "gt", 2) == 0) { if (arena_add(x, ">", 1, NULL)) return -1; }
      else if (j - i - 1 == 3 && memcmp(s + i + 1, "amp", 3) == 0) { if (arena_add(x, "&", 1, NULL)) return -1; }
      else if (j - i - 1 == 4 && memcmp(s + i + 1, "quot", 4) == 0) { if (arena_add(x, "\"", 1, NULL)) return -1; }
      else if (j - i - 1 == 4 && memcmp(s + i + 1, "apos", 4) == 0) { if (arena_add(x, "'", 1, NULL)) return -1; }
      else if (s[i + 1] == '#') {
        uint32_t cp = 0, k = (uint32_t)i + 2, base = 10;
        wchar_t w[2];
        char u8[8];
        size_t wl, ul;
        if (k < j && s[k] == 'x') { base = 16; k++; }
        if (k >= j) return -1;
        for (; k < j; k++) {
          int c = (unsigned char)s[k], v;
          if (c >= '0' && c <= '9') v = c - '0';
          else if (base == 16 && c >= 'a' && c <= 'f') v = c - 'a' + 10;
          else if (base == 16 && c >= 'A' && c <= 'F') v = c - 'A' + 10;
          else return -1;
          cp = cp * base + (uint32_t)v;
          if (cp > 0x10FFFF) return -1;
        }
        if (cp == 0 || (cp >= 0xD800 && cp <= 0xDFFF)) return -1;
        if (cp < 0x10000) { w[0] = (wchar_t)cp; wl = 1; }
        else { cp -= 0x10000; w[0] = (wchar_t)(0xD800 + (cp >> 10)); w[1] = (wchar_t)(0xDC00 + (cp & 0x3FF)); wl = 2; }
        if (sd_utf16_to_utf8(w, wl, u8, sizeof(u8), &ul, SD_UTF_STRICT) != SD_OK) return -1;
        if (arena_add(x, u8, ul, NULL)) return -1;
      } else {
        return -1;                         /* undeclared entity: never expanded */
      }
      i = j + 1;
    } else {
      size_t j = i;
      while (j < n && s[j] != '&') j++;
      if (arena_add(x, s + i, j - i, NULL)) return -1;
      i = j;
    }
  }
  return 0;
}

static const char *ns_lookup(xp *x, const char *prefix, uint32_t plen)
{
  uint32_t k = x->nns;
  while (k-- > 0) {
    if (x->ns[k].plen == plen && memcmp(x->ns[k].prefix, prefix, plen) == 0)
      return x->ns[k].uri;
  }
  if (plen == 0)
    return "";
  return NULL;
}

static int add_text_to_current(xp *x, const char *s, size_t n, int raw)
{
  uint32_t d = x->depth;
  if (d == 0) {
    size_t k;
    for (k = 0; k < n; k++)
      if (!is_ws(s[k])) return -1;         /* character data outside the root */
    return 0;
  }
  if (!x->text_open[d]) {
    /* text is accumulated contiguously only until the first child element; later text segments
       of mixed content are ignored (WebDAV bodies have no meaningful mixed content) */
    return 0;
  }
  return raw ? arena_add(x, s, n, NULL) : decode_text(x, s, n);
}

static int parse_attrs_and_open(xp *x, const char *qn, uint32_t qlen)
{
  uint32_t ns_before = x->nns;
  int self_close = 0, idx;
  const char *colon, *uri;
  wd_xnode *nd;
  size_t off;
  /* the parent's text run ends at its first child (before any arena write for this element) */
  if (x->depth && x->text_open[x->depth]) {
    if (arena_add(x, "", 1, NULL)) return -1;
    x->d->n[x->stack[x->depth - 1]].text = x->arena + x->text_start[x->depth];
    x->text_open[x->depth] = 0;
  }
  for (;;) {
    const char *an, *av;
    uint32_t al;
    size_t vs;
    char q;
    skip_ws(x);
    if (x->i >= x->n) return -1;
    if (x->p[x->i] == '/') {
      if (x->i + 1 >= x->n || x->p[x->i + 1] != '>') return -1;
      x->i += 2;
      self_close = 1;
      break;
    }
    if (x->p[x->i] == '>') {
      x->i++;
      break;
    }
    if (read_name(x, &an, &al)) return -1;
    skip_ws(x);
    if (x->i >= x->n || x->p[x->i] != '=') return -1;
    x->i++;
    skip_ws(x);
    if (x->i >= x->n || (x->p[x->i] != '"' && x->p[x->i] != '\'')) return -1;
    q = x->p[x->i++];
    vs = x->i;
    while (x->i < x->n && x->p[x->i] != q) {
      if (x->p[x->i] == '<') return -1;
      x->i++;
    }
    if (x->i >= x->n) return -1;
    av = x->p + vs;
    if ((al == 5 && memcmp(an, "xmlns", 5) == 0) || (al > 6 && memcmp(an, "xmlns:", 6) == 0)) {
      size_t uoff, start = x->an;
      if (x->nns >= MAX_NS) return -1;
      if (decode_text(x, av, x->i - vs) || arena_add(x, "", 1, &uoff)) return -1;
      x->ns[x->nns].prefix = al == 5 ? "" : an + 6;
      x->ns[x->nns].plen = al == 5 ? 0 : al - 6;
      x->ns[x->nns].uri = x->arena + start;          /* arena never moves (sized up front) */
      x->ns[x->nns].depth = x->depth + 1;
      x->nns++;
      SD_UNUSED(uoff);
    }
    x->i++;
  }
  if (x->d->count >= WD_MAX_XML_NODES || x->depth >= WD_MAX_XML_DEPTH)
    return -1;
  colon = (const char *)memchr(qn, ':', qlen);
  uri = colon ? ns_lookup(x, qn, (uint32_t)(colon - qn)) : ns_lookup(x, "", 0);
  if (uri == NULL)
    return -1;                             /* undeclared prefix */
  idx = (int)x->d->count++;
  nd = &x->d->n[idx];
  nd->ns = uri;
  if (arena_add(x, colon ? colon + 1 : qn, colon ? qlen - (uint32_t)(colon + 1 - qn) : qlen, &off) ||
      arena_add(x, "", 1, NULL))
    return -1;
  nd->name = x->arena + off;
  nd->text = "";
  nd->parent = x->depth ? x->stack[x->depth - 1] : -1;
  nd->child = nd->next = -1;
  if (x->depth) {
    int pi = x->stack[x->depth - 1];
    if (x->last_child[x->depth] >= 0) x->d->n[x->last_child[x->depth]].next = idx;
    else x->d->n[pi].child = idx;
    x->last_child[x->depth] = idx;
  } else if (x->d->count > 1) {
    return -1;                             /* second root */
  }
  if (self_close) {
    x->nns = ns_before;
    return 0;
  }
  x->stack[x->depth] = idx;
  x->qn[x->depth] = qn;
  x->qlen[x->depth] = qlen;
  x->depth++;
  x->last_child[x->depth] = -1;
  x->text_start[x->depth] = x->an;
  x->text_open[x->depth] = 1;
  return 0;
}

static int close_elem(xp *x)
{
  const char *qn;
  uint32_t ql;
  int idx;
  if (read_name(x, &qn, &ql)) return -1;
  skip_ws(x);
  if (x->i >= x->n || x->p[x->i] != '>') return -1;
  x->i++;
  if (x->depth == 0 || x->qlen[x->depth - 1] != ql || memcmp(x->qn[x->depth - 1], qn, ql) != 0)
    return -1;
  idx = x->stack[x->depth - 1];
  if (x->text_open[x->depth]) {
    if (arena_add(x, "", 1, NULL)) return -1;
    x->d->n[idx].text = x->arena + x->text_start[x->depth];
  }
  x->depth--;
  while (x->nns && x->ns[x->nns - 1].depth > x->depth)
    x->nns--;
  return 0;
}

int wd_xml_parse(const char *p, size_t n, wd_xdoc *out)
{
  xp *x;
  int rc = 400;
  memset(out, 0, sizeof(*out));
  if (n > WD_MAX_XML || !sd_utf8_valid(p, n))
    return 400;
  x = (xp *)sd_calloc(1, sizeof(*x));
  if (x == NULL)
    return 500;
  x->p = p;
  x->n = n;
  x->d = out;
  /* every arena write is bounded by input size plus a NUL per string and node */
  x->acap = 2 * n + 64 + 3u * WD_MAX_XML_NODES;
  x->arena = (char *)sd_alloc(x->acap);
  out->n = (wd_xnode *)sd_calloc(WD_MAX_XML_NODES, sizeof(wd_xnode));
  if (x->arena == NULL || out->n == NULL) {
    sd_free(x->arena);
    sd_free(out->n);
    sd_free(x);
    memset(out, 0, sizeof(*out));
    return 500;
  }
  out->arena = x->arena;
  if (n >= 3 && (unsigned char)p[0] == 0xEF && (unsigned char)p[1] == 0xBB && (unsigned char)p[2] == 0xBF)
    x->i = 3;
  while (x->i < x->n) {
    if (x->p[x->i] == '<') {
      if (starts(x, "<?")) {
        if (find(x, "?>")) goto fail;
      } else if (starts(x, "<!--")) {
        x->i += 4;
        if (find(x, "-->")) goto fail;
      } else if (starts(x, "<![CDATA[")) {
        size_t s;
        x->i += 9;
        s = x->i;
        if (find(x, "]]>")) goto fail;
        if (x->depth == 0 || add_text_to_current(x, x->p + s, x->i - 3 - s, 1)) goto fail;
      } else if (starts(x, "<!")) {
        goto fail;                         /* DOCTYPE / DTD: never */
      } else if (starts(x, "</")) {
        x->i += 2;
        if (close_elem(x)) goto fail;
        if (x->depth == 0) {
          /* after the root: only whitespace, comments, PIs */
          for (;;) {
            skip_ws(x);
            if (x->i >= x->n) break;
            if (starts(x, "<!--")) { x->i += 4; if (find(x, "-->")) goto fail; continue; }
            if (starts(x, "<?")) { if (find(x, "?>")) goto fail; continue; }
            goto fail;
          }
        }
      } else {
        const char *qn;
        uint32_t ql;
        x->i++;
        if (read_name(x, &qn, &ql) || parse_attrs_and_open(x, qn, ql)) goto fail;
      }
    } else {
      size_t s = x->i;
      while (x->i < x->n && x->p[x->i] != '<') x->i++;
      if (add_text_to_current(x, x->p + s, x->i - s, 0)) goto fail;
    }
  }
  if (x->depth != 0 || out->count == 0)
    goto fail;
  sd_free(x);
  return 0;
fail:
  sd_free(x);
  wd_xml_free(out);
  return rc;
}

void wd_xml_free(wd_xdoc *d)
{
  sd_free(d->n);
  sd_free(d->arena);
  memset(d, 0, sizeof(*d));
}

int wd_xml_is(const wd_xdoc *d, int i, const char *ns, const char *name)
{
  return i >= 0 && (uint32_t)i < d->count && strcmp(d->n[i].ns, ns) == 0 && strcmp(d->n[i].name, name) == 0;
}

int wd_xml_child(const wd_xdoc *d, int i, const char *ns, const char *name)
{
  int c;
  if (i < 0)
    return d->count && wd_xml_is(d, 0, ns, name) ? 0 : -1;
  for (c = d->n[i].child; c >= 0; c = d->n[c].next)
    if (wd_xml_is(d, c, ns, name))
      return c;
  return -1;
}
