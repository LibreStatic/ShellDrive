/* OpenSSH certificates (PROTOCOL.certkeys; 01 §6.3) and public key files (01 §6.6): OpenSSH one-line
 * format (also *-cert.pub) and RFC 4716. Structure only: the CA signature is the server's job.
 * No transport dependency. */
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_base/sd_utf.h"
#include "sd_ssh/sd_known_hosts.h"
#include "keyfile_internal.h"
#include "ssh_internal.h"

static const char k_cert_suffix[] = "-cert-v01@openssh.com";

int ssh_cert_type_base(sd_span type, char *base, size_t cap)
{
  size_t sl = sizeof(k_cert_suffix) - 1, bl;
  if (type.n <= sl || memcmp(type.p + type.n - sl, k_cert_suffix, sl) != 0) return 0;
  bl = type.n - sl;
  if (bl >= cap) return 0;
  memcpy(base, type.p, bl);
  base[bl] = '\0';
  return !strcmp(base, "ssh-ed25519") || !strcmp(base, "ssh-rsa") || !strcmp(base, "ecdsa-sha2-nistp256") ||
         !strcmp(base, "ecdsa-sha2-nistp384") || !strcmp(base, "ecdsa-sha2-nistp521");
}

typedef struct cert_parts {
  char base[48];
  sd_span type;
  sd_wr *plain;               /* receives the plain public blob */
  uint64_t serial;
  uint32_t ctype;
  sd_span key_id, principals, crit, ext, sigkey;
  uint64_t va, vb;
} cert_parts;

static sd_err cert_split(const uint8_t *cert, size_t len, cert_parts *cp)
{
  sd_rd r;
  sd_rd_init(&r, cert, len);
  cp->type = sd_rd_string(&r, 64);
  if (!sd_rd_ok(&r) || !ssh_cert_type_base(cp->type, cp->base, sizeof(cp->base))) return SD_E_KEY_FORMAT;
  (void)sd_rd_string(&r, 256);   /* nonce */
  sd_wr_cstring(cp->plain, cp->base);
  if (!strcmp(cp->base, "ssh-ed25519")) {
    sd_span pk = sd_rd_string(&r, 64);
    if (pk.n != 32) return SD_E_KEY_FORMAT;
    sd_wr_string(cp->plain, pk.p, pk.n);
  } else if (!strcmp(cp->base, "ssh-rsa")) {
    sd_span e = sd_rd_mpint(&r, 64), n = sd_rd_mpint(&r, SSH_RSA_MAX_BYTES + 1);
    sd_wr_mpint(cp->plain, e.p, e.n);
    sd_wr_mpint(cp->plain, n.p, n.n);
  } else {
    sd_span cn = sd_rd_string(&r, 64), q = sd_rd_string(&r, 256);
    sd_wr_string(cp->plain, cn.p, cn.n);
    sd_wr_string(cp->plain, q.p, q.n);
  }
  cp->serial = sd_rd_u64(&r);
  cp->ctype = sd_rd_u32(&r);
  cp->key_id = sd_rd_string(&r, 4096);
  cp->principals = sd_rd_string(&r, 65536);
  cp->va = sd_rd_u64(&r);
  cp->vb = sd_rd_u64(&r);
  cp->crit = sd_rd_string(&r, 65536);
  cp->ext = sd_rd_string(&r, 65536);
  (void)sd_rd_string(&r, 65536);   /* reserved */
  cp->sigkey = sd_rd_string(&r, 16384);
  (void)sd_rd_string(&r, 16384);   /* signature */
  if (!sd_rd_done(&r) || !sd_wr_ok(cp->plain) || cp->sigkey.n == 0) return SD_E_KEY_FORMAT;
  if (ssh_pubblob_info(cp->plain->p, cp->plain->len, NULL, NULL, NULL) != SD_OK) return SD_E_KEY_FORMAT;
  return SD_OK;
}

sd_err ssh_cert_plain_pub(const uint8_t *cert, size_t len, uint8_t *out, size_t cap, size_t *out_len)
{
  cert_parts cp;
  sd_wr w;
  sd_err e;
  memset(&cp, 0, sizeof(cp));
  sd_wr_init_fixed(&w, out, cap);
  cp.plain = &w;
  e = cert_split(cert, len, &cp);
  if (e != SD_OK) return e;
  *out_len = w.len;
  return SD_OK;
}

static void sanitize_into(sd_span s, char *out, size_t cap)
{
  size_t ol = 0;
  size_t n = SD_MIN(s.n, cap / 3);
  if (cap == 0) return;
  if (sd_text_sanitize_server((const char *)s.p, n, out, cap - 1, &ol) != SD_OK) ol = 0;
  out[ol] = '\0';
}

sd_err sd_ssh_cert_parse(const uint8_t *blob, size_t len, sd_ssh_cert_info *out)
{
  cert_parts cp;
  sd_wr w;
  sd_rd pr;
  sd_err e;
  size_t pos = 0;
  if (!blob || !out) return SD_E_INVALID_PARAM;
  memset(out, 0, sizeof(*out));
  memset(&cp, 0, sizeof(cp));
  sd_wr_init_fixed(&w, out->key_blob, sizeof(out->key_blob));
  cp.plain = &w;
  e = cert_split(blob, len, &cp);
  if (e != SD_OK) return e;
  out->key_len = w.len;
  ssh_span_copy(cp.type, out->type, sizeof(out->type));
  memcpy(out->key_type, cp.base, strlen(cp.base) + 1);
  out->serial = cp.serial;
  out->cert_type = cp.ctype;
  out->valid_after = cp.va;
  out->valid_before = cp.vb;
  sanitize_into(cp.key_id, out->key_id, sizeof(out->key_id));
  sd_rd_init(&pr, cp.principals.p, cp.principals.n);
  while (sd_rd_remaining(&pr) && sd_rd_ok(&pr)) {
    sd_span p = sd_rd_string(&pr, 1024);
    char one[256];
    size_t l;
    if (!sd_rd_ok(&pr)) return SD_E_KEY_FORMAT;
    out->principal_count++;
    sanitize_into(p, one, sizeof(one));
    l = strlen(one);
    if (pos + l + 2 < sizeof(out->principals)) {
      if (pos) out->principals[pos++] = ',';
      memcpy(out->principals + pos, one, l);
      pos += l;
      out->principals[pos] = '\0';
    }
  }
  if (sd_hostkey_fingerprint_sha256(cp.sigkey.p, cp.sigkey.n, out->ca_fp_sha256) != SD_OK) out->ca_fp_sha256[0] = '\0';
  return SD_OK;
}

int sd_ssh_cert_valid_at(const sd_ssh_cert_info *ci, uint64_t now)
{
  return ci && now >= ci->valid_after && (ci->valid_before == SD_CERT_FOREVER || now < ci->valid_before);
}

/* ---- public key files ---- */

static int is_b64(uint8_t c)
{
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
}

static sd_err finish_blob(const uint8_t *blob, size_t bl, const char *expect_type, size_t tl, char *type,
                          size_t type_cap)
{
  sd_span t = ssh_blob_key_type(blob, bl);
  char base[48];
  if (!t.n) return SD_E_KEY_FORMAT;
  if (expect_type && (t.n != tl || memcmp(t.p, expect_type, tl) != 0)) return SD_E_KEY_FORMAT;
  if (ssh_cert_type_base(t, base, sizeof(base))) {
    uint8_t plain[1024];
    size_t pl;
    if (ssh_cert_plain_pub(blob, bl, plain, sizeof(plain), &pl) != SD_OK) return SD_E_KEY_FORMAT;
  } else {
    sd_err e = ssh_pubblob_info(blob, bl, NULL, NULL, NULL);
    if (e != SD_OK) return e;
  }
  if (type && !ssh_span_copy(t, type, type_cap)) return SD_E_INVALID_PARAM;
  return SD_OK;
}

sd_err sd_ssh_pubkey_parse(const uint8_t *bytes, size_t len, uint8_t *blob, size_t blob_cap, size_t *blob_len,
                           char *type, size_t type_cap)
{
  size_t i = 0;
  if (!bytes || !blob || !blob_len) return SD_E_INVALID_PARAM;
  *blob_len = 0;
  if (type && type_cap) type[0] = '\0';
  if (len > SSH_KEY_MAX_FILE) return SD_E_KEY_FORMAT;
  if (len >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF) i = 3;
  while (i < len && (bytes[i] == ' ' || bytes[i] == '\t' || bytes[i] == '\r' || bytes[i] == '\n')) i++;
  if (len - i >= 31 && memcmp(bytes + i, "---- BEGIN SSH2 PUBLIC KEY ----", 31) == 0) {
    /* RFC 4716: header lines ("Tag: value", "\" continues), then base64 until the END line */
    static const char k_end[] = "---- END SSH2 PUBLIC KEY ----";
    size_t pos = i + 31, b64s = 0, b64e = 0;
    int cont = 0;
    while (pos < len && (bytes[pos] == '\r' || bytes[pos] == '\n')) pos++;
    while (pos < len) {
      size_t ls = pos, le, k;
      int has_colon = 0;
      while (pos < len && bytes[pos] != '\n') pos++;
      le = pos;
      if (pos < len) pos++;
      if (le > ls && bytes[le - 1] == '\r') le--;
      if (le - ls >= sizeof(k_end) - 1 && memcmp(bytes + ls, k_end, sizeof(k_end) - 1) == 0) {
        b64e = ls;
        break;
      }
      if (cont) { cont = le > ls && bytes[le - 1] == '\\'; continue; }
      if (!b64s) {
        for (k = ls; k < le; k++) if (bytes[k] == ':') { has_colon = 1; break; }
        if (has_colon) { cont = le > ls && bytes[le - 1] == '\\'; continue; }
        b64s = ls;
      }
      for (k = ls; k < le; k++)
        if (!is_b64(bytes[k])) return SD_E_KEY_FORMAT;
    }
    if (!b64s || !b64e || b64e < b64s) return SD_E_KEY_FORMAT;
    if (ssh_b64_decode((const char *)bytes + b64s, b64e - b64s, blob, blob_cap, blob_len, 1) != SD_OK)
      return SD_E_KEY_FORMAT;
    return finish_blob(blob, *blob_len, NULL, 0, type, type_cap);
  }
  {
    /* one line: type SP base64 [SP comment] */
    size_t ts = i, te, bs, be;
    while (i < len && bytes[i] > ' ') i++;
    te = i;
    while (i < len && (bytes[i] == ' ' || bytes[i] == '\t')) i++;
    bs = i;
    while (i < len && is_b64(bytes[i])) i++;
    be = i;
    if (te == ts || be == bs || te - ts > 64) return SD_E_KEY_FORMAT;
    if (i < len && bytes[i] != ' ' && bytes[i] != '\t' && bytes[i] != '\r' && bytes[i] != '\n') return SD_E_KEY_FORMAT;
    if (ssh_b64_decode((const char *)bytes + bs, be - bs, blob, blob_cap, blob_len, 0) != SD_OK) return SD_E_KEY_FORMAT;
    return finish_blob(blob, *blob_len, (const char *)bytes + ts, te - ts, type, type_cap);
  }
}
