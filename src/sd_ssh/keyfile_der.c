/* Minimal strict DER reader for key files (01 §6.6): single-byte tags, definite minimal lengths,
 * canonical INTEGERs, nesting depth <= 8. BER forms (indefinite lengths, long tags) are rejected. */
#include <string.h>

#include "keyfile_internal.h"

#define DER_MAX_DEPTH 8

void ssh_der_init(ssh_der *d, const uint8_t *p, size_t n)
{
  d->p = p;
  d->n = p ? n : 0;
  d->err = 0;
  d->depth = 0;
}

int ssh_der_ok(const ssh_der *d) { return !d->err; }
int ssh_der_done(const ssh_der *d) { return !d->err && d->n == 0; }

static sd_span empty_span(void)
{
  sd_span s;
  s.p = NULL;
  s.n = 0;
  return s;
}

/* Reads tag and length; returns contents. */
static sd_span read_tlv(ssh_der *d, uint8_t *tag_out)
{
  size_t len, i, hdr;
  sd_span s;
  if (d->err || d->n < 2) { d->err = 1; return empty_span(); }
  *tag_out = d->p[0];
  if ((d->p[0] & 0x1F) == 0x1F) { d->err = 1; return empty_span(); }   /* high tag numbers */
  if (d->p[1] < 0x80) {
    len = d->p[1];
    hdr = 2;
  } else {
    size_t nb = d->p[1] & 0x7F;
    if (nb == 0 || nb > 4 || d->n < 2 + nb || d->p[2] == 0) { d->err = 1; return empty_span(); }
    len = 0;
    for (i = 0; i < nb; i++) len = (len << 8) | d->p[2 + i];
    if (len < 0x80) { d->err = 1; return empty_span(); }               /* not minimal */
    hdr = 2 + nb;
  }
  if (len > d->n - hdr) { d->err = 1; return empty_span(); }
  s.p = d->p + hdr;
  s.n = len;
  d->p += hdr + len;
  d->n -= hdr + len;
  return s;
}

int ssh_der_peek(const ssh_der *d, uint8_t tag) { return !d->err && d->n > 0 && d->p[0] == tag; }

sd_span ssh_der_tlv(ssh_der *d, uint8_t tag)
{
  uint8_t t = 0;
  sd_span s;
  if (!ssh_der_peek(d, tag)) { d->err = 1; return empty_span(); }
  s = read_tlv(d, &t);
  if (d->err) return empty_span();
  return s;
}

ssh_der ssh_der_enter(ssh_der *d, uint8_t tag)
{
  ssh_der sub;
  sd_span s;
  ssh_der_init(&sub, NULL, 0);
  if (d->depth >= DER_MAX_DEPTH) { d->err = 1; sub.err = 1; return sub; }
  s = ssh_der_tlv(d, tag);
  if (d->err) { sub.err = 1; return sub; }
  ssh_der_init(&sub, s.p, s.n);
  sub.depth = d->depth + 1;
  return sub;
}

sd_span ssh_der_uint(ssh_der *d)
{
  sd_span s = ssh_der_tlv(d, SSH_DER_INTEGER);
  if (d->err) return empty_span();
  if (s.n == 0) { d->err = 1; return empty_span(); }
  if (s.n > 1 && ((s.p[0] == 0x00 && !(s.p[1] & 0x80)) || (s.p[0] == 0xFF && (s.p[1] & 0x80)))) {
    d->err = 1;   /* non-canonical */
    return empty_span();
  }
  if (s.p[0] & 0x80) { d->err = 1; return empty_span(); }               /* negative */
  if (s.p[0] == 0x00) { s.p++; s.n--; }                                /* sign byte (or zero) */
  return s;
}

uint32_t ssh_der_small(ssh_der *d)
{
  sd_span s = ssh_der_uint(d);
  uint32_t v = 0;
  size_t i;
  if (d->err) return 0;
  if (s.n > 4 || (s.n == 4 && (s.p[0] & 0x80))) { d->err = 1; return 0; }
  for (i = 0; i < s.n; i++) v = (v << 8) | s.p[i];
  return v;
}

int ssh_der_oid_is(sd_span oid, const char *dotted)
{
  uint8_t enc[64];
  size_t n = 0;
  uint32_t arcs[24], na = 0, i;
  const char *s = dotted;
  while (*s && na < SD_COUNTOF(arcs)) {
    uint32_t v = 0;
    if (*s < '0' || *s > '9') return 0;
    while (*s >= '0' && *s <= '9') v = v * 10u + (uint32_t)(*s++ - '0');
    arcs[na++] = v;
    if (*s == '.') s++;
  }
  if (na < 2 || *s) return 0;
  arcs[1] += arcs[0] * 40u;
  for (i = 1; i < na; i++) {
    uint8_t tmp[5];
    int k = 0;
    uint32_t v = arcs[i];
    do { tmp[k++] = (uint8_t)(v & 0x7F); v >>= 7; } while (v);
    while (k > 0) {
      uint8_t b;
      if (n >= sizeof(enc)) return 0;
      k--;
      b = tmp[k];
      if (k) b |= 0x80;
      enc[n++] = b;
    }
  }
  return oid.n == n && memcmp(oid.p, enc, n) == 0;
}
