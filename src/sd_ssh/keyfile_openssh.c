/* OpenSSH v1 private key files (01 §6.6; OpenSSH PROTOCOL.key): ssh-ed25519, ecdsa-sha2-nistp*,
 * ssh-rsa and their *-cert-v01@openssh.com forms; unencrypted, or bcrypt_pbkdf with
 * aes{128,192,256}-{ctr,cbc}, aes{128,256}-gcm@openssh.com or chacha20-poly1305@openssh.com.
 * No transport dependency: the CLI and UI link this unit. */
#include <string.h>

#include "sd_base/sd_buf.h"
#include "sd_base/sd_mem.h"
#include "sd_crypto/sd_ct.h"
#include "sd_platform/sd_secbuf.h"
#include "keyfile_internal.h"
#include "ssh_internal.h"

#define KEY_MAX_ROUNDS 1024u
static const char k_magic[] = "openssh-key-v1";   /* followed by a NUL on the wire (15 bytes) */
static const char k_begin[] = "-----BEGIN OPENSSH PRIVATE KEY-----";
static const char k_end[] = "-----END OPENSSH PRIVATE KEY-----";

typedef struct ossh_cipher {
  const char *name;
  size_t key_len, iv_len, block, tag_len;
  int kind;                             /* 0 ctr/cbc (oneshot), 1 gcm, 2 chacha20-poly1305 */
} ossh_cipher;

static const ossh_cipher k_ciphers[] = {
  { "aes128-ctr", 16, 16, 16, 0, 0 }, { "aes192-ctr", 24, 16, 16, 0, 0 }, { "aes256-ctr", 32, 16, 16, 0, 0 },
  { "aes128-cbc", 16, 16, 16, 0, 0 }, { "aes192-cbc", 24, 16, 16, 0, 0 }, { "aes256-cbc", 32, 16, 16, 0, 0 },
  { "aes128-gcm@openssh.com", 16, 12, 16, 16, 1 }, { "aes256-gcm@openssh.com", 32, 12, 16, 16, 1 },
  { "chacha20-poly1305@openssh.com", 64, 0, 8, 16, 2 },
};

static const ossh_cipher *find_cipher(sd_span name)
{
  size_t i;
  for (i = 0; i < SD_COUNTOF(k_ciphers); i++)
    if (ssh_span_eq(name, k_ciphers[i].name)) return &k_ciphers[i];
  return NULL;
}

typedef struct ossh_file {
  uint8_t *raw; size_t raw_len;       /* decoded body (heap) */
  sd_span cipher, kdf, kdfopts, pub, enc, tag;
} ossh_file;

static void ossh_free(ossh_file *f)
{
  if (f->raw) sd_secure_free(f->raw, f->raw_len + 1);
  f->raw = NULL;
}

/* Decodes the armored body and the outer structure. */
static sd_err ossh_decode(const uint8_t *bytes, size_t len, ossh_file *f)
{
  size_t off = 0, i, bstart, bend = 0;
  sd_rd r;
  sd_span magic;
  uint32_t nkeys;
  const ossh_cipher *c;
  memset(f, 0, sizeof(*f));
  if (!bytes || len == 0 || len > SSH_KEY_MAX_FILE) return SD_E_KEY_FORMAT;
  if (len >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF) off = 3;
  while (off < len && (bytes[off] == ' ' || bytes[off] == '\t' || bytes[off] == '\r' || bytes[off] == '\n')) off++;
  if (len - off < strlen(k_begin) || memcmp(bytes + off, k_begin, strlen(k_begin)) != 0) return SD_E_KEY_FORMAT;
  bstart = off + strlen(k_begin);
  for (i = bstart; i + strlen(k_end) <= len; i++) {
    if (bytes[i] == '-' && memcmp(bytes + i, k_end, strlen(k_end)) == 0) { bend = i; break; }
  }
  if (!bend) return SD_E_KEY_FORMAT;
  f->raw = (uint8_t *)sd_alloc(bend - bstart + 1);
  if (!f->raw) return SD_E_NO_MEMORY;
  if (ssh_b64_decode((const char *)bytes + bstart, bend - bstart, f->raw, bend - bstart + 1, &f->raw_len, 1) != SD_OK)
    goto bad;
  sd_rd_init(&r, f->raw, f->raw_len);
  magic = sd_rd_bytes(&r, sizeof(k_magic));
  if (!sd_rd_ok(&r) || memcmp(magic.p, k_magic, sizeof(k_magic)) != 0) goto bad;
  f->cipher = sd_rd_string(&r, 64);
  f->kdf = sd_rd_string(&r, 64);
  f->kdfopts = sd_rd_string(&r, 1024);
  nkeys = sd_rd_u32(&r);
  if (!sd_rd_ok(&r)) goto bad;
  if (nkeys != 1) { ossh_free(f); return SD_E_KEY_UNSUPPORTED; }
  f->pub = sd_rd_string(&r, 16384);
  f->enc = sd_rd_string(&r, SSH_KEY_MAX_FILE);
  if (!sd_rd_ok(&r) || f->pub.n == 0) goto bad;
  c = find_cipher(f->cipher);
  if (c && c->tag_len) f->tag = sd_rd_bytes(&r, c->tag_len);
  if (!sd_rd_done(&r)) goto bad;
  return SD_OK;
bad:
  ossh_free(f);
  return SD_E_KEY_FORMAT;
}

/* Plain public blob of the header (certificates carry their key inside). */
static sd_err header_plain_pub(sd_span pub, uint8_t *out, size_t cap, size_t *out_len, int *is_cert)
{
  char base[48];
  sd_span t = ssh_blob_key_type(pub.p, pub.n);
  *is_cert = ssh_cert_type_base(t, base, sizeof(base));
  if (*is_cert) return ssh_cert_plain_pub(pub.p, pub.n, out, cap, out_len);
  if (pub.n > cap) return SD_E_KEY_FORMAT;
  memcpy(out, pub.p, pub.n);
  *out_len = pub.n;
  return SD_OK;
}

sd_err ssh_ossh_probe(const uint8_t *bytes, size_t len, sd_ssh_key_probe_info *out)
{
  ossh_file f;
  uint8_t plain[1024];
  size_t pl = 0;
  int is_cert = 0;
  sd_span type;
  sd_err e;
  memset(out, 0, sizeof(*out));
  e = ossh_decode(bytes, len, &f);
  if (e != SD_OK) return e;
  e = header_plain_pub(f.pub, plain, sizeof(plain), &pl, &is_cert);
  type = ssh_blob_key_type(plain, pl);
  if (e != SD_OK || !type.n || !ssh_span_copy(type, out->type, sizeof(out->type))) {
    ossh_free(&f);
    return e != SD_OK ? e : SD_E_KEY_FORMAT;
  }
  ssh_probe_fill_from_pub(out, plain, pl);
  out->encrypted = !ssh_span_eq(f.cipher, "none");
  out->format = SD_KEYFMT_OPENSSH;
  ossh_free(&f);
  return SD_OK;
}

/* Parses the decrypted private section. */
static sd_err parse_private(const uint8_t *p, size_t n, int encrypted, sd_span hdr_pub, sd_ssh_key **out)
{
  sd_rd r;
  uint32_t c1, c2;
  sd_span type, comment, cert = { NULL, 0 };
  char base[48];
  uint8_t plain[1024];
  size_t i, rem, pl = 0;
  int is_cert = 0;
  sd_ssh_key *k = NULL;
  sd_err e;

  sd_rd_init(&r, p, n);
  c1 = sd_rd_u32(&r);
  c2 = sd_rd_u32(&r);
  if (!sd_rd_ok(&r)) return encrypted ? SD_E_BAD_PASSPHRASE : SD_E_KEY_FORMAT;
  if (c1 != c2) return encrypted ? SD_E_BAD_PASSPHRASE : SD_E_KEY_FORMAT;
  type = sd_rd_string(&r, 64);
  if (!sd_rd_ok(&r)) return SD_E_KEY_FORMAT;
  if (ssh_cert_type_base(type, base, sizeof(base))) {
    is_cert = 1;
    cert = sd_rd_string(&r, 16384);
    if (!sd_rd_ok(&r) || ssh_cert_plain_pub(cert.p, cert.n, plain, sizeof(plain), &pl) != SD_OK) return SD_E_KEY_FORMAT;
  } else {
    if (!ssh_span_copy(type, base, sizeof(base))) return SD_E_KEY_UNSUPPORTED;
  }

  if (strcmp(base, "ssh-ed25519") == 0) {
    sd_span pk, sk;
    pk = sd_rd_string(&r, 32);
    sk = sd_rd_string(&r, 64);
    comment = sd_rd_string(&r, 4096);
    if (!sd_rd_ok(&r) || pk.n != 32 || sk.n != 64 || memcmp(sk.p + 32, pk.p, 32) != 0) return SD_E_KEY_FORMAT;
    e = ssh_key_new_ed25519(sk.p, pk.p, comment, &k);
  } else if (strncmp(base, "ecdsa-sha2-", 11) == 0) {
    sd_span cn, q, d;
    sd_span suffix;
    uint32_t curve;
    suffix.p = (const uint8_t *)base + 11;
    suffix.n = strlen(base) - 11;
    curve = ssh_curve_from_name(suffix);
    if (!curve) return SD_E_KEY_UNSUPPORTED;
    if (is_cert) {
      sd_rd pr;
      sd_rd_init(&pr, plain, pl);
      (void)sd_rd_string(&pr, 64);
      cn = sd_rd_string(&pr, 64);
      q = sd_rd_string(&pr, 256);
      if (!sd_rd_done(&pr)) return SD_E_KEY_FORMAT;
    } else {
      cn = sd_rd_string(&r, 64);
      q = sd_rd_string(&r, 256);
    }
    d = sd_rd_mpint(&r, 67);
    comment = sd_rd_string(&r, 4096);
    if (!sd_rd_ok(&r) || ssh_curve_from_name(cn) != curve) return SD_E_KEY_FORMAT;
    e = ssh_key_new_ecdsa(curve, q, d, comment, &k);
  } else if (strcmp(base, "ssh-rsa") == 0) {
    sd_span rn, re, rd, iqmp, rp, rq;
    if (is_cert) {
      sd_rd pr;
      sd_rd_init(&pr, plain, pl);
      (void)sd_rd_string(&pr, 64);
      re = sd_rd_mpint(&pr, 64);
      rn = sd_rd_mpint(&pr, SSH_RSA_MAX_BYTES + 1);
      if (!sd_rd_done(&pr)) return SD_E_KEY_FORMAT;
    } else {
      rn = sd_rd_mpint(&r, SSH_RSA_MAX_BYTES + 1);
      re = sd_rd_mpint(&r, 64);
    }
    rd = sd_rd_mpint(&r, SSH_RSA_MAX_BYTES + 1);
    iqmp = sd_rd_mpint(&r, SSH_RSA_MAX_BYTES + 1);
    rp = sd_rd_mpint(&r, SSH_RSA_MAX_BYTES + 1);
    rq = sd_rd_mpint(&r, SSH_RSA_MAX_BYTES + 1);
    comment = sd_rd_string(&r, 4096);
    if (!sd_rd_ok(&r)) return SD_E_KEY_FORMAT;
    e = ssh_key_new_rsa(rn, re, rd, iqmp, rp, rq, comment, &k);
  } else {
    return SD_E_KEY_UNSUPPORTED;
  }
  if (e != SD_OK) return e;

  /* padding 1, 2, 3, ... */
  rem = sd_rd_remaining(&r);
  {
    sd_span pad = sd_rd_bytes(&r, rem);
    if (rem >= 255) { sd_ssh_key_free(k); return SD_E_KEY_FORMAT; }
    for (i = 0; i < rem; i++)
      if (pad.p[i] != (uint8_t)(i + 1)) { sd_ssh_key_free(k); return SD_E_KEY_FORMAT; }
  }
  /* the embedded private key must match the public blob of the header */
  {
    uint8_t hp[1024];
    size_t hl = 0;
    int hdr_cert = 0;
    if (header_plain_pub(hdr_pub, hp, sizeof(hp), &hl, &hdr_cert) != SD_OK || !ssh_key_pub_equal(k, hp, hl)) {
      sd_ssh_key_free(k);
      return SD_E_KEY_FORMAT;
    }
    if (hdr_cert && !is_cert) { cert = hdr_pub; is_cert = 1; }
  }
  if (is_cert) {
    e = sd_ssh_key_attach_cert(k, cert.p, cert.n);
    if (e != SD_OK) { sd_ssh_key_free(k); return e; }
  }
  *out = k;
  return SD_OK;
}

static sd_err ossh_decrypt(const ossh_cipher *c, const uint8_t *kiv, uint8_t *buf, size_t n, sd_span tag)
{
  if (c->kind == 0) return sd_cipher_oneshot(c->name, 0, kiv, kiv + c->key_len, buf, n);
  if (c->kind == 1) {
    if (tag.n != 16) return SD_E_KEY_FORMAT;
    return sd_aes_gcm_decrypt(kiv, c->key_len, kiv + c->key_len, NULL, 0, buf, n, tag.p, buf) == SD_OK
               ? SD_OK : SD_E_BAD_PASSPHRASE;
  }
  {
    /* chacha20-poly1305@openssh.com with sequence number 0 and no associated data: the Poly1305 key
       is the first ChaCha20 block of the main key (first 32 bytes), the payload uses counter 1. */
    static const uint8_t nonce[8] = { 0 };
    uint8_t zero[32], polykey[32], t[16];
    int ok;
    if (tag.n != 16) return SD_E_KEY_FORMAT;
    memset(zero, 0, sizeof(zero));
    sd_chacha20(kiv, nonce, 0, zero, 32, polykey);
    sd_poly1305(t, buf, n, polykey);
    ok = sd_ct_memeq(t, tag.p, 16);
    sd_secure_zero(polykey, sizeof(polykey));
    if (!ok) return SD_E_BAD_PASSPHRASE;
    sd_chacha20(kiv, nonce, 1, buf, n, buf);
    return SD_OK;
  }
}

sd_err ssh_ossh_load(const uint8_t *bytes, size_t len, const char *pass, size_t pass_len, sd_ssh_key **out)
{
  ossh_file f;
  sd_err e;
  *out = NULL;
  e = ossh_decode(bytes, len, &f);
  if (e != SD_OK) return e;
  if (ssh_span_eq(f.cipher, "none")) {
    if (!ssh_span_eq(f.kdf, "none") || f.kdfopts.n != 0) { ossh_free(&f); return SD_E_KEY_FORMAT; }
    if (f.enc.n % 8) { ossh_free(&f); return SD_E_KEY_FORMAT; }
    e = parse_private(f.enc.p, f.enc.n, 0, f.pub, out);
  } else {
    const ossh_cipher *c = find_cipher(f.cipher);
    sd_rd r;
    sd_span salt;
    uint32_t rounds;
    uint8_t kiv[80];
    sd_secbuf *plain = NULL;
    if (!c || !ssh_span_eq(f.kdf, "bcrypt")) { ossh_free(&f); return SD_E_KEY_UNSUPPORTED; }
    sd_rd_init(&r, f.kdfopts.p, f.kdfopts.n);
    salt = sd_rd_string(&r, 1024);
    rounds = sd_rd_u32(&r);
    if (!sd_rd_done(&r) || salt.n == 0 || rounds == 0 || (f.enc.n % c->block) != 0 || f.enc.n == 0) {
      ossh_free(&f);
      return SD_E_KEY_FORMAT;
    }
    if (rounds > KEY_MAX_ROUNDS) { ossh_free(&f); return SD_E_KEY_UNSUPPORTED; }
    if (!pass) { ossh_free(&f); return SD_E_KEY_PASSPHRASE_REQUIRED; }
    if (!ssh_crypto_ready()) { ossh_free(&f); return SD_E_UNSUPPORTED; }
    e = sd_bcrypt_pbkdf(pass, pass_len, salt.p, salt.n, rounds, kiv, c->key_len + c->iv_len);
    if (e == SD_OK) e = sd_secbuf_from(f.enc.p, f.enc.n, &plain);
    if (e == SD_OK) e = ossh_decrypt(c, kiv, plain->p, f.enc.n, f.tag);
    sd_secure_zero(kiv, sizeof(kiv));
    if (e == SD_OK) e = parse_private(plain->p, f.enc.n, 1, f.pub, out);
    sd_secbuf_free(plain);
  }
  ossh_free(&f);
  return e;
}

/* ---- serializer (unencrypted) ---- */

static void write_private_fields(sd_wr *w, const sd_ssh_key *k)
{
  switch (k->kt) {
  case SSH_KT_ED25519:
    sd_wr_string(w, k->priv->p + 32, 32);
    sd_wr_string(w, k->priv->p, 64);
    break;
  case SSH_KT_ECDSA: {
    sd_rd r;
    sd_span cn, q;
    sd_rd_init(&r, k->pub, k->pub_len);
    (void)sd_rd_string(&r, 64);
    cn = sd_rd_string(&r, 64);
    q = sd_rd_string(&r, 256);
    sd_wr_string(w, cn.p, cn.n);
    sd_wr_string(w, q.p, q.n);
    sd_wr_mpint(w, k->priv->p, k->priv->len);
    break;
  }
  case SSH_KT_RSA:
    sd_wr_bytes(w, k->priv->p, k->priv->len);   /* n, e, d, iqmp, p, q as stored */
    break;
  default:
    w->err = 1;
    break;
  }
}

sd_err ssh_ossh_serialize(const sd_ssh_key *k, sd_secbuf **out)
{
  sd_wr body, priv;
  uint8_t check[4];
  size_t i, b64len = 0, lines, total, o;
  char *b64 = NULL;
  sd_secbuf *sb;
  sd_err e;
  e = ssh_random(check, 4);
  if (e != SD_OK) return e;
  sd_wr_init_secret(&priv, 256 * 1024);
  sd_wr_bytes(&priv, check, 4);
  sd_wr_bytes(&priv, check, 4);
  sd_wr_cstring(&priv, k->type);
  write_private_fields(&priv, k);
  sd_wr_cstring(&priv, k->comment ? k->comment : "");
  for (i = 1; priv.len % 8; i++) sd_wr_u8(&priv, (uint8_t)i);
  sd_wr_init_secret(&body, 512 * 1024);
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
