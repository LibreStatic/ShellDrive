/* OpenSSH v1 private key files (01 §6.6; PROTOCOL.key). M0: ssh-ed25519, unencrypted or
 * bcrypt + aes{128,192,256}-ctr / aes256-cbc. Other formats are recognized and reported as
 * SD_E_KEY_UNSUPPORTED. No transport dependency: the CLI and UI link this unit. */
#include <string.h>

#include "sd_base/sd_buf.h"
#include "sd_base/sd_mem.h"
#include "sd_platform/sd_secbuf.h"
#include "sd_ssh/sd_keyfile.h"
#include "sd_ssh/sd_known_hosts.h"
#include "ssh_internal.h"

#define KEY_MAX_FILE (1024u * 1024u)
#define KEY_MAX_ROUNDS 1024u
static const char k_magic[] = "openssh-key-v1";   /* followed by a NUL on the wire (15 bytes) */
static const char k_begin[] = "-----BEGIN OPENSSH PRIVATE KEY-----";
static const char k_end[] = "-----END OPENSSH PRIVATE KEY-----";

struct sd_ssh_key {
  char type[48];
  uint8_t *pub; size_t pub_len;       /* SSH wire blob */
  sd_secbuf *priv;                    /* ed25519: seed(32) || pub(32) */
  char *comment;
};

typedef struct ossh_file {
  uint8_t *raw; size_t raw_len;       /* decoded body (heap) */
  sd_span cipher, kdf, kdfopts, pub, enc;
} ossh_file;

static const char *first_nonblank(const uint8_t *b, size_t n, size_t *off)
{
  size_t i = 0;
  while (i < n && (b[i] == ' ' || b[i] == '\t' || b[i] == '\r' || b[i] == '\n')) i++;
  *off = i;
  return (const char *)b + i;
}

static int starts_with(const char *p, size_t avail, const char *s)
{
  size_t n = strlen(s);
  return avail >= n && memcmp(p, s, n) == 0;
}

/* Identifies the format; for OpenSSH v1 decodes the body. */
static sd_err ossh_decode(const uint8_t *bytes, size_t len, ossh_file *f)
{
  size_t off, i, bstart, bend;
  const char *p;
  sd_rd r;
  sd_span magic;
  uint32_t nkeys;
  memset(f, 0, sizeof(*f));
  if (!bytes || len == 0 || len > KEY_MAX_FILE) return SD_E_KEY_FORMAT;
  p = first_nonblank(bytes, len, &off);
  if (!starts_with(p, len - off, k_begin)) {
    if (starts_with(p, len - off, "-----BEGIN ") || starts_with(p, len - off, "PuTTY-User-Key-File-") ||
        starts_with(p, len - off, "---- BEGIN SSH2"))
      return SD_E_KEY_UNSUPPORTED;   /* PEM, PKCS#8, PPK: M2 */
    return SD_E_KEY_FORMAT;
  }
  bstart = off + strlen(k_begin);
  bend = 0;
  for (i = bstart; i + strlen(k_end) <= len; i++) {
    if (bytes[i] == '-' && memcmp(bytes + i, k_end, strlen(k_end)) == 0) { bend = i; break; }
  }
  if (!bend) return SD_E_KEY_FORMAT;
  f->raw = (uint8_t *)sd_alloc(bend - bstart + 1);
  if (!f->raw) return SD_E_NO_MEMORY;
  if (ssh_b64_decode((const char *)bytes + bstart, bend - bstart, f->raw, bend - bstart + 1, &f->raw_len, 1) != SD_OK) {
    sd_free(f->raw);
    f->raw = NULL;
    return SD_E_KEY_FORMAT;
  }
  sd_rd_init(&r, f->raw, f->raw_len);
  magic = sd_rd_bytes(&r, sizeof(k_magic));
  if (!sd_rd_ok(&r) || memcmp(magic.p, k_magic, sizeof(k_magic)) != 0) goto bad;
  f->cipher = sd_rd_string(&r, 64);
  f->kdf = sd_rd_string(&r, 64);
  f->kdfopts = sd_rd_string(&r, 1024);
  nkeys = sd_rd_u32(&r);
  if (!sd_rd_ok(&r)) goto bad;
  if (nkeys != 1) { sd_free(f->raw); f->raw = NULL; return SD_E_KEY_UNSUPPORTED; }
  f->pub = sd_rd_string(&r, 16384);
  f->enc = sd_rd_string(&r, KEY_MAX_FILE);
  if (!sd_rd_ok(&r) || f->pub.n == 0) goto bad;
  return SD_OK;
bad:
  sd_free(f->raw);
  f->raw = NULL;
  return SD_E_KEY_FORMAT;
}

static void ossh_free(ossh_file *f)
{
  if (f->raw) sd_secure_free(f->raw, f->raw_len + 1);
  f->raw = NULL;
}

static uint32_t key_bits(sd_span type) { return ssh_span_eq(type, "ssh-ed25519") ? 256u : 0u; }

sd_err sd_ssh_key_probe(const uint8_t *bytes, size_t len, sd_ssh_key_probe_info *out)
{
  ossh_file f;
  sd_span type;
  sd_err e;
  if (!out) return SD_E_INVALID_PARAM;
  memset(out, 0, sizeof(*out));
  e = ossh_decode(bytes, len, &f);
  if (e != SD_OK) return e;
  type = ssh_blob_key_type(f.pub.p, f.pub.n);
  if (!type.n || !ssh_span_copy(type, out->type, sizeof(out->type)) || f.pub.n > sizeof(out->pub_blob)) {
    ossh_free(&f);
    return SD_E_KEY_FORMAT;
  }
  out->bits = key_bits(type);
  out->encrypted = !ssh_span_eq(f.cipher, "none");
  memcpy(out->pub_blob, f.pub.p, f.pub.n);
  out->pub_len = f.pub.n;
  if (sd_hostkey_fingerprint_sha256(f.pub.p, f.pub.n, out->fp_sha256) != SD_OK) out->fp_sha256[0] = '\0';
  out->format = SD_KEYFMT_OPENSSH;
  ossh_free(&f);
  return SD_OK;
}

static int cipher_params(sd_span c, const char **name, size_t *key_len)
{
  if (ssh_span_eq(c, "aes256-ctr")) { *name = "aes256-ctr"; *key_len = 32; return 1; }
  if (ssh_span_eq(c, "aes192-ctr")) { *name = "aes192-ctr"; *key_len = 24; return 1; }
  if (ssh_span_eq(c, "aes128-ctr")) { *name = "aes128-ctr"; *key_len = 16; return 1; }
  if (ssh_span_eq(c, "aes256-cbc")) { *name = "aes256-cbc"; *key_len = 32; return 1; }
  return 0;
}

void sd_ssh_key_free(sd_ssh_key *k)
{
  if (!k) return;
  sd_free(k->pub);
  sd_secbuf_free(k->priv);
  sd_free(k->comment);
  sd_free(k);
}

/* Parses the decrypted private section. */
static sd_err parse_private(const uint8_t *p, size_t n, int encrypted, sd_span pub_blob, sd_ssh_key **out)
{
  sd_rd r, pr;
  uint32_t c1, c2;
  sd_span type, pk, sk, comment, pub_type, pub_pk;
  size_t i, rem;
  sd_ssh_key *k;
  sd_err e;

  sd_rd_init(&r, p, n);
  c1 = sd_rd_u32(&r);
  c2 = sd_rd_u32(&r);
  if (!sd_rd_ok(&r)) return SD_E_KEY_FORMAT;
  if (c1 != c2) return encrypted ? SD_E_BAD_PASSPHRASE : SD_E_KEY_FORMAT;
  type = sd_rd_string(&r, 64);
  if (!sd_rd_ok(&r)) return SD_E_KEY_FORMAT;
  if (!ssh_span_eq(type, "ssh-ed25519")) return SD_E_KEY_UNSUPPORTED;
  pk = sd_rd_string(&r, 32);
  sk = sd_rd_string(&r, 64);
  comment = sd_rd_string(&r, 4096);
  if (!sd_rd_ok(&r) || pk.n != 32 || sk.n != 64) return SD_E_KEY_FORMAT;
  /* padding 1, 2, 3, ... */
  rem = sd_rd_remaining(&r);
  {
    sd_span pad = sd_rd_bytes(&r, rem);
    for (i = 0; i < rem; i++)
      if (pad.p[i] != (uint8_t)(i + 1)) return SD_E_KEY_FORMAT;
  }
  /* the embedded private key must match the public blob */
  sd_rd_init(&pr, pub_blob.p, pub_blob.n);
  pub_type = sd_rd_string(&pr, 64);
  pub_pk = sd_rd_string(&pr, 64);
  if (!sd_rd_done(&pr) || !ssh_span_eq(pub_type, "ssh-ed25519") || pub_pk.n != 32 ||
      memcmp(pub_pk.p, pk.p, 32) != 0 || memcmp(sk.p + 32, pk.p, 32) != 0)
    return SD_E_KEY_FORMAT;

  k = (sd_ssh_key *)sd_calloc(1, sizeof(*k));
  if (!k) return SD_E_NO_MEMORY;
  memcpy(k->type, "ssh-ed25519", 12);
  k->pub = (uint8_t *)sd_alloc(pub_blob.n);
  k->comment = (char *)sd_alloc(comment.n + 1);
  if (!k->pub || !k->comment) { sd_ssh_key_free(k); return SD_E_NO_MEMORY; }
  memcpy(k->pub, pub_blob.p, pub_blob.n);
  k->pub_len = pub_blob.n;
  if (comment.n) memcpy(k->comment, comment.p, comment.n);
  k->comment[comment.n] = '\0';
  e = sd_secbuf_from(sk.p, 64, &k->priv);
  if (e != SD_OK) { k->priv = NULL; sd_ssh_key_free(k); return e; }
  *out = k;
  return SD_OK;
}

sd_err sd_ssh_key_load(const uint8_t *bytes, size_t len, const char *pass, size_t pass_len, sd_ssh_key **out)
{
  ossh_file f;
  sd_err e;
  if (!out) return SD_E_INVALID_PARAM;
  *out = NULL;
  e = ossh_decode(bytes, len, &f);
  if (e != SD_OK) return e;
  if (ssh_span_eq(f.cipher, "none")) {
    if (!ssh_span_eq(f.kdf, "none")) { ossh_free(&f); return SD_E_KEY_FORMAT; }
    e = parse_private(f.enc.p, f.enc.n, 0, f.pub, out);
  } else {
    const char *cname;
    size_t klen;
    sd_rd r;
    sd_span salt;
    uint32_t rounds;
    uint8_t kiv[48];
    sd_secbuf *plain = NULL;
    if (!cipher_params(f.cipher, &cname, &klen) || !ssh_span_eq(f.kdf, "bcrypt")) {
      ossh_free(&f);
      return SD_E_KEY_UNSUPPORTED;
    }
    sd_rd_init(&r, f.kdfopts.p, f.kdfopts.n);
    salt = sd_rd_string(&r, 1024);
    rounds = sd_rd_u32(&r);
    if (!sd_rd_done(&r) || salt.n == 0 || rounds == 0 || (f.enc.n % 16) != 0 || f.enc.n == 0) {
      ossh_free(&f);
      return SD_E_KEY_FORMAT;
    }
    if (rounds > KEY_MAX_ROUNDS) { ossh_free(&f); return SD_E_KEY_UNSUPPORTED; }
    if (!pass) { ossh_free(&f); return SD_E_KEY_PASSPHRASE_REQUIRED; }
    if (!ssh_crypto_ready()) { ossh_free(&f); return SD_E_UNSUPPORTED; }
    e = sd_bcrypt_pbkdf(pass, pass_len, salt.p, salt.n, rounds, kiv, klen + 16);
    if (e == SD_OK) e = sd_secbuf_from(f.enc.p, f.enc.n, &plain);
    if (e == SD_OK) e = sd_cipher_oneshot(cname, 0, kiv, kiv + klen, plain->p, f.enc.n);
    sd_secure_zero(kiv, sizeof(kiv));
    if (e == SD_OK) e = parse_private(plain->p, f.enc.n, 1, f.pub, out);
    sd_secbuf_free(plain);
  }
  ossh_free(&f);
  return e;
}

const uint8_t *sd_ssh_key_public_blob(const sd_ssh_key *k, size_t *len)
{
  if (!k) { if (len) *len = 0; return NULL; }
  if (len) *len = k->pub_len;
  return k->pub;
}

const char *sd_ssh_key_type(const sd_ssh_key *k) { return k ? k->type : NULL; }

sd_err sd_ssh_key_sign(const sd_ssh_key *k, const uint8_t *data, size_t len, uint8_t *sig, size_t sig_cap,
                       size_t *sig_len)
{
  uint8_t raw[64];
  sd_wr w;
  sd_err e;
  if (!k || !sig || !sig_len || (!data && len)) return SD_E_INVALID_PARAM;
  if (!ssh_crypto_ready()) return SD_E_UNSUPPORTED;
  e = sd_ed25519_sign(raw, k->priv->p, k->priv->p + 32, data, len);
  if (e != SD_OK) return e;
  sd_wr_init_fixed(&w, sig, sig_cap);
  sd_wr_cstring(&w, "ssh-ed25519");
  sd_wr_string(&w, raw, 64);
  if (!sd_wr_ok(&w)) return SD_E_INVALID_PARAM;
  *sig_len = w.len;
  return SD_OK;
}

sd_err sd_ssh_key_serialize_openssh(const sd_ssh_key *k, sd_secbuf **out)
{
  sd_wr body, priv;
  uint8_t check[4];
  size_t i, b64len = 0, lines, total, o;
  char *b64 = NULL;
  sd_secbuf *sb;
  sd_err e;
  if (!k || !out) return SD_E_INVALID_PARAM;
  *out = NULL;
  e = ssh_random(check, 4);
  if (e != SD_OK) return e;
  sd_wr_init_secret(&priv, 64 * 1024);
  sd_wr_bytes(&priv, check, 4);
  sd_wr_bytes(&priv, check, 4);
  sd_wr_cstring(&priv, "ssh-ed25519");
  sd_wr_string(&priv, k->priv->p + 32, 32);
  sd_wr_string(&priv, k->priv->p, 64);
  sd_wr_cstring(&priv, k->comment ? k->comment : "");
  for (i = 1; priv.len % 8; i++) sd_wr_u8(&priv, (uint8_t)i);
  sd_wr_init_secret(&body, 128 * 1024);
  sd_wr_bytes(&body, k_magic, sizeof(k_magic));
  sd_wr_cstring(&body, "none");
  sd_wr_cstring(&body, "none");
  sd_wr_string(&body, "", 0);
  sd_wr_u32(&body, 1);
  sd_wr_string(&body, k->pub, k->pub_len);
  sd_wr_string(&body, priv.p, priv.len);
  e = (sd_wr_ok(&priv) && sd_wr_ok(&body)) ? SD_OK : SD_E_NO_MEMORY;
  sd_wr_free(&priv);
  if (e == SD_OK) {
    b64len = ssh_b64_encoded_len(body.len, 1);
    b64 = (char *)sd_alloc(b64len + 1);
    if (!b64) e = SD_E_NO_MEMORY;
    else ssh_b64_encode(body.p, body.len, b64, b64len + 1, 1);
  }
  sd_wr_free(&body);
  if (e != SD_OK) { sd_free(b64); return e; }
  lines = (b64len + 69) / 70;
  total = strlen(k_begin) + 1 + b64len + lines + strlen(k_end) + 1;
  e = sd_secbuf_new(total, &sb);
  if (e != SD_OK) { sd_secure_free(b64, b64len + 1); return e; }
  o = 0;
  memcpy(sb->p + o, k_begin, strlen(k_begin)); o += strlen(k_begin);
  sb->p[o++] = '\n';
  for (i = 0; i < b64len; i += 70) {
    size_t n = SD_MIN((size_t)70, b64len - i);
    memcpy(sb->p + o, b64 + i, n); o += n;
    sb->p[o++] = '\n';
  }
  memcpy(sb->p + o, k_end, strlen(k_end)); o += strlen(k_end);
  sb->p[o++] = '\n';
  sb->len = o;
  sd_secure_free(b64, b64len + 1);
  *out = sb;
  return SD_OK;
}
