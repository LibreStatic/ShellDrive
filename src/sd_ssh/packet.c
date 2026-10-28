/* Binary packet protocol (RFC 4253 §6, OpenSSH PROTOCOL.chacha20poly1305, RFC 5647 as profiled by
 * OpenSSH, EtM MACs). Encryption is done in place by sd_crypto packet-cipher objects; HMAC for the
 * non-AEAD ciphers is computed here with sd_hmac. */
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_crypto/sd_ct.h"
#include "ssh_internal.h"

void ssh_dir_init(ssh_dir *d)
{
  memset(d, 0, sizeof(*d));
  d->block = 8;
}

/* Wipes the cipher and MAC state; keeps seq and the compression state (re-keys keep both). */
static void dir_clear_cipher(ssh_dir *d)
{
  uint32_t seq = d->seq;
  ssh_comp comp = d->comp;
  if (d->pc) sd_pktcipher_free(d->pc);
  if (d->mac_on) sd_hmac_wipe(&d->hmac);
  sd_secure_zero(d, sizeof(*d));
  d->block = 8;
  d->seq = seq;
  d->comp = comp;
}

static void comp_free(ssh_comp *c)
{
  if (c->zdef) ssh_zdef_free(c->zdef);
  if (c->zinf) ssh_zinf_free(c->zinf);
  if (c->zout) {
    sd_secure_zero(c->zout, SSH_ZLIB_PACKET_MAX);
    sd_free(c->zout);
  }
  sd_wr_free(&c->zw);
  c->zdef = NULL;
  c->zinf = NULL;
  c->zout = NULL;
  c->on = 0;
  c->name[0] = 0;
  memset(&c->zw, 0, sizeof(c->zw));
}

void ssh_dir_clear(ssh_dir *d)
{
  comp_free(&d->comp);
  dir_clear_cipher(d);
}

#define ZLIB_OPENSSH "zlib@openssh.com"

void ssh_dir_set_comp_name(ssh_dir *d, const char *name)
{
  size_t n = strlen(name);
  if (n >= sizeof(d->comp.name)) n = sizeof(d->comp.name) - 1;
  if (strcmp(name, ZLIB_OPENSSH) != 0) {
    /* a re-key that drops compression: the stream ends here, on both sides */
    if (d->comp.on) comp_free(&d->comp);
    d->comp.name[0] = 0;
    return;
  }
  memcpy(d->comp.name, name, n);
  d->comp.name[n] = 0;
}

sd_err ssh_dir_comp_start(ssh_dir *d)
{
  if (strcmp(d->comp.name, ZLIB_OPENSSH) != 0 || d->comp.on) return SD_OK;
  if (d->comp.tx) {
    d->comp.zdef = ssh_zdef_new();
    if (!d->comp.zdef) return SD_E_NO_MEMORY;
    sd_wr_init(&d->comp.zw, SSH_MAX_PACKET_LEN);
  } else {
    d->comp.zinf = ssh_zinf_new();
    if (!d->comp.zinf) return SD_E_NO_MEMORY;
    d->comp.zout = (uint8_t *)sd_alloc(SSH_ZLIB_PACKET_MAX);
    if (!d->comp.zout) {
      comp_free(&d->comp);
      return SD_E_NO_MEMORY;
    }
  }
  d->comp.on = 1;
  return SD_OK;
}

static int mac_info(const char *mac, sd_hash_alg *alg, int *etm)
{
  if (strcmp(mac, "hmac-sha2-256") == 0) { *alg = SD_HASH_SHA256; *etm = 0; return 1; }
  if (strcmp(mac, "hmac-sha2-512") == 0) { *alg = SD_HASH_SHA512; *etm = 0; return 1; }
  if (strcmp(mac, "hmac-sha2-256-etm@openssh.com") == 0) { *alg = SD_HASH_SHA256; *etm = 1; return 1; }
  if (strcmp(mac, "hmac-sha2-512-etm@openssh.com") == 0) { *alg = SD_HASH_SHA512; *etm = 1; return 1; }
  if (strcmp(mac, "hmac-sha1") == 0) { *alg = SD_HASH_SHA1; *etm = 0; return 1; }
  if (strcmp(mac, "hmac-sha1-etm@openssh.com") == 0) { *alg = SD_HASH_SHA1; *etm = 1; return 1; }
  return 0;
}

sd_err ssh_alg_key_sizes(const char *cipher, const char *mac, size_t *key_len, size_t *iv_len,
                         size_t *mac_key_len)
{
  const sd_pktcipher_info *ci = sd_pktcipher_find(cipher);
  if (!ci) return SD_E_UNSUPPORTED;
  *key_len = ci->key_len;
  *iv_len = ci->iv_len;
  *mac_key_len = 0;
  if (!(ci->flags & SD_PC_AEAD)) {
    sd_hash_alg alg;
    int etm;
    if (!mac || !mac_info(mac, &alg, &etm)) return SD_E_UNSUPPORTED;
    *mac_key_len = sd_hash_len(alg);
  }
  return SD_OK;
}

sd_err ssh_dir_set_keys(ssh_dir *d, int encrypt, const char *cipher, const char *mac,
                        const uint8_t *key, const uint8_t *iv, const uint8_t *mac_key)
{
  const sd_pktcipher_info *ci = sd_pktcipher_find(cipher);
  sd_err e;
  dir_clear_cipher(d);
  d->comp.tx = encrypt ? 1 : 0;
  if (!ci) return SD_E_UNSUPPORTED;
  e = sd_pktcipher_new(ci, encrypt, key, iv, &d->pc);
  if (e != SD_OK) { d->pc = NULL; return e; }
  d->ci = ci;
  d->block = ci->block_len > 8 ? ci->block_len : 8;
  if (!(ci->flags & SD_PC_AEAD)) {
    if (!mac || !mac_info(mac, &d->mac_hash, &d->etm)) { dir_clear_cipher(d); return SD_E_UNSUPPORTED; }
    d->mac_len = sd_hash_len(d->mac_hash);
    sd_hmac_init(&d->hmac, d->mac_hash, mac_key, d->mac_len);
    d->mac_on = 1;
  }
  return SD_OK;
}

static int dir_aead(const ssh_dir *d) { return d->ci && (d->ci->flags & SD_PC_AEAD); }
static int cbc_mte(const ssh_dir *d) { return d->ci && (d->ci->flags & SD_PC_CBC) && !d->etm; }

static void compute_mac(ssh_dir *d, const uint8_t *p, size_t n, uint8_t *out)
{
  uint8_t seq[4];
  sd_store_be32(seq, d->seq);
  sd_hmac_reset(&d->hmac);
  sd_hmac_update(&d->hmac, seq, 4);
  sd_hmac_update(&d->hmac, p, n);
  sd_hmac_final(&d->hmac, out);
}

sd_err ssh_pkt_seal(ssh_dir *d, const uint8_t *payload, size_t n, sd_wr *out)
{
  int aead = dir_aead(d);
  int excl = aead || d->etm;                 /* length field excluded from block alignment */
  size_t block = d->block, base, pad, plen, extra, total, plain_n;
  uint8_t *pkt;
  sd_err e;

  if (n == 0 || n > SSH_MAX_PAYLOAD_OUT) return SD_E_INVALID_PARAM;
  plain_n = n;
  if (d->comp.on) {
    /* delayed zlib@openssh.com: the payload is compressed before padding and encryption */
    sd_wr_reset(&d->comp.zw);
    e = ssh_zdef_compress(d->comp.zdef, payload, n, &d->comp.zw);
    if (e != SD_OK) return e;
    if (!sd_wr_ok(&d->comp.zw) || d->comp.zw.len == 0 || d->comp.zw.len > SSH_MAX_PAYLOAD_OUT) return SD_E_INTERNAL;
    payload = d->comp.zw.p;
    n = d->comp.zw.len;
  }
  base = (excl ? 0 : 4) + 1 + n;
  pad = block - (base % block);
  if (pad < 4) pad += block;
  while (4 + 1 + n + pad < 16) pad += block;
  if (pad > 255) return SD_E_INTERNAL;
  plen = 1 + n + pad;
  extra = (aead && d->ci) ? d->ci->tag_len : (d->mac_on ? d->mac_len : 0);
  total = 4 + plen + extra;
  pkt = sd_wr_reserve(out, total);
  if (!pkt) return SD_E_NO_MEMORY;
  sd_store_be32(pkt, (uint32_t)plen);
  pkt[4] = (uint8_t)pad;
  memcpy(pkt + 5, payload, n);
  e = ssh_random(pkt + 5 + n, pad);
  if (e != SD_OK) { out->len -= total; return e; }

  if (aead) {
    e = sd_pktcipher_seal(d->pc, d->seq, pkt, 4 + plen, pkt + 4 + plen);
  } else if (d->ci && d->etm) {
    e = sd_pktcipher_crypt(d->pc, pkt + 4, plen);
    if (e == SD_OK) compute_mac(d, pkt, 4 + plen, pkt + 4 + plen);
  } else if (d->ci) {
    compute_mac(d, pkt, 4 + plen, pkt + 4 + plen);
    e = sd_pktcipher_crypt(d->pc, pkt, 4 + plen);
  }
  if (e != SD_OK) { sd_secure_zero(pkt, total); out->len -= total; return e; }
  d->seq++;
  d->packets++;
  d->bytes += plain_n;
  return SD_OK;
}

sd_err ssh_pkt_open(ssh_dir *d, uint8_t *buf, size_t avail, size_t *consumed, sd_span *payload)
{
  int aead = dir_aead(d);
  int excl = aead || d->etm;
  size_t extra, total, padlen;
  sd_err e;

  payload->p = NULL;
  payload->n = 0;
  *consumed = 0;

  /* CBC with a non-ETM MAC (01 §4.1, Albrecht et al.): after an invalid length or a MAC failure keep
     reading until SSH_MAX_PACKET_LEN bytes of this packet arrived, then fail, so the error's timing
     does not tell where the length check failed. The input stays buffered (the caller's buffer holds
     more than SSH_MAX_PACKET_LEN). */
  if (d->rx_discard) {
    if (avail < d->rx_discard) return SD_OK;
    d->rx_discard = 0;
    return SD_E_CRYPTO;
  }

  if (!d->rx_have_len) {
    uint32_t len;
    int ctr_plain = d->ci && !aead && !d->etm;   /* length is inside the first encrypted block */
    size_t need = ctr_plain ? d->block : 4;
    if (avail < need) return SD_OK;
    if (!d->ci || (aead && !(d->ci->flags & SD_PC_LEN_ENCRYPTED)) || d->etm) {
      len = sd_load_be32(buf);
    } else if (aead) {
      e = sd_pktcipher_peek_len(d->pc, d->seq, buf, &len);
      if (e != SD_OK) return SD_E_CRYPTO;
    } else {
      e = sd_pktcipher_crypt(d->pc, buf, d->block);
      if (e != SD_OK) return SD_E_CRYPTO;
      len = sd_load_be32(buf);
    }
    if (len < 5 || len > SSH_MAX_PACKET_LEN || (excl ? (len % d->block) != 0 : ((len + 4) % d->block) != 0)) {
      if (cbc_mte(d)) { d->rx_discard = SSH_MAX_PACKET_LEN; return avail < d->rx_discard ? SD_OK : SD_E_CRYPTO; }
      return SD_E_PROTOCOL;
    }
    d->rx_len = len;
    d->rx_have_len = 1;
  }

  extra = (aead && d->ci) ? d->ci->tag_len : (d->mac_on ? d->mac_len : 0);
  total = 4 + (size_t)d->rx_len + extra;
  if (avail < total) return SD_OK;

  if (aead) {
    e = sd_pktcipher_open(d->pc, d->seq, buf, 4 + (size_t)d->rx_len, buf + 4 + d->rx_len);
    if (e != SD_OK) return SD_E_CRYPTO;
  } else if (d->ci && d->etm) {
    uint8_t mac[SD_HASH_MAX_LEN];
    compute_mac(d, buf, 4 + (size_t)d->rx_len, mac);
    if (!sd_ct_memeq(mac, buf + 4 + d->rx_len, d->mac_len)) return SD_E_CRYPTO;
    e = sd_pktcipher_crypt(d->pc, buf + 4, d->rx_len);
    if (e != SD_OK) return SD_E_CRYPTO;
  } else if (d->ci) {
    uint8_t mac[SD_HASH_MAX_LEN];
    e = sd_pktcipher_crypt(d->pc, buf + d->block, 4 + (size_t)d->rx_len - d->block);
    if (e != SD_OK) return SD_E_CRYPTO;
    compute_mac(d, buf, 4 + (size_t)d->rx_len, mac);
    if (!sd_ct_memeq(mac, buf + 4 + d->rx_len, d->mac_len)) {
      if (cbc_mte(d) && total < SSH_MAX_PACKET_LEN) { d->rx_discard = SSH_MAX_PACKET_LEN; return avail < d->rx_discard ? SD_OK : SD_E_CRYPTO; }
      return SD_E_CRYPTO;
    }
  }

  padlen = buf[4];
  if (padlen < 4 || padlen + 2 > d->rx_len) return SD_E_PROTOCOL;
  payload->p = buf + 5;
  payload->n = d->rx_len - padlen - 1;
  if (d->comp.on) {
    /* authenticated packets only: the payload is inflated into the connection's buffer (valid until the next
       call); a corrupt stream or an oversized payload is a protocol error */
    size_t zn = 0;
    if (ssh_zinf_packet(d->comp.zinf, payload->p, payload->n, d->comp.zout, SSH_ZLIB_PACKET_MAX, &zn) != SD_OK ||
        zn == 0)
      return SD_E_PROTOCOL;
    payload->p = d->comp.zout;
    payload->n = zn;
  }
  *consumed = total;
  d->seq++;
  d->packets++;
  d->bytes += payload->n;
  d->rx_have_len = 0;
  return SD_OK;
}
