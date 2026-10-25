/* Algorithm lists, KEXINIT encoding/parsing, negotiation (01 §4.2, §4.3; TM-R01, TM-R04, D34) and
 * the identification-line scanner (01 §4.1). Pure code: no I/O, no crypto. */
#include <string.h>

#include "ssh_internal.h"

/* Static preference order of the algorithms M0 implements (01 §4.3). */
static const char *const k_kex[] = { "curve25519-sha256", "curve25519-sha256@libssh.org" };
static const char *const k_hostkey[] = { "ssh-ed25519" };
static const char *const k_hostkey_type[] = { "ssh-ed25519" };   /* key type per k_hostkey entry */
static const char *const k_cipher_sw[] = {
  "chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-gcm@openssh.com",
  "aes256-ctr", "aes192-ctr", "aes128-ctr"
};
static const char *const k_cipher_hw[] = {
  "aes256-gcm@openssh.com", "aes128-gcm@openssh.com", "chacha20-poly1305@openssh.com",
  "aes256-ctr", "aes192-ctr", "aes128-ctr"
};
static const char *const k_mac[] = {
  "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com", "hmac-sha2-256", "hmac-sha2-512"
};

#define SSH_CHACHA "chacha20-poly1305@openssh.com"
#define SSH_EXT_INFO_C "ext-info-c"
#define SSH_STRICT_C "kex-strict-c-v00@openssh.com"
#define SSH_STRICT_S "kex-strict-s-v00@openssh.com"

int ssh_csv_contains(const char *csv, const char *name)
{
  size_t n = strlen(name);
  const char *p = csv;
  while (p && *p) {
    const char *e = strchr(p, ',');
    size_t len = e ? (size_t)(e - p) : strlen(p);
    if (len == n && memcmp(p, name, n) == 0) return 1;
    p = e ? e + 1 : NULL;
  }
  return 0;
}

int ssh_cipher_is_aead(const char *name)
{
  return strcmp(name, SSH_CHACHA) == 0 || strcmp(name, "aes256-gcm@openssh.com") == 0 ||
         strcmp(name, "aes128-gcm@openssh.com") == 0;
}

static int cipher_is_gcm(const char *n) { return strstr(n, "-gcm@openssh.com") != NULL; }
static int cipher_is_ctr(const char *n) { size_t l = strlen(n); return l > 4 && strcmp(n + l - 4, "-ctr") == 0; }

static int default_cipher_available(const char *name) { return sd_pktcipher_find(name) != NULL; }

/* Appends name to a CSV buffer. */
static int csv_add(char *buf, size_t cap, const char *name)
{
  size_t l = strlen(buf), n = strlen(name);
  if (l + n + 2 > cap) return 0;
  if (l) buf[l++] = ',';
  memcpy(buf + l, name, n + 1);
  return 1;
}

static int disabled(const char *list, const char *name) { return list && ssh_csv_contains(list, name); }

static int stored_has(const sd_kh_types *t, const char *type)
{
  uint32_t i;
  for (i = 0; i < t->count && i < 8; i++)
    if (strcmp(t->type[i], type) == 0) return 1;
  return 0;
}

/* 1 if direction (our ciphers/macs vs the server's) has a pair Terrapin does not affect. */
static int has_unaffected_pair(const char *const *ciphers, size_t nc, const ssh_list_input *in,
                               int (*avail)(const char *), sd_span s_enc, sd_span s_mac)
{
  size_t i, j;
  for (i = 0; i < nc; i++) {
    const char *c = ciphers[i];
    if (disabled(in->disabled, c) || !avail(c) || !sd_namelist_contains(s_enc, c)) continue;
    if (cipher_is_gcm(c)) return 1;
    if (cipher_is_ctr(c)) {
      for (j = 0; j < SD_COUNTOF(k_mac); j++)
        if (!disabled(in->disabled, k_mac[j]) && sd_namelist_contains(s_mac, k_mac[j])) return 1;
    }
  }
  return 0;
}

static int chacha_shared(const ssh_list_input *in, int (*avail)(const char *), sd_span s_enc)
{
  return !disabled(in->disabled, SSH_CHACHA) && avail(SSH_CHACHA) && sd_namelist_contains(s_enc, SSH_CHACHA);
}

static sd_err build_cipher_list(const char *const *order, size_t n, const ssh_list_input *in,
                                int (*avail)(const char *), int drop_chacha, char *out, size_t cap)
{
  size_t i;
  out[0] = '\0';
  for (i = 0; i < n; i++) {
    if (disabled(in->disabled, order[i]) || !avail(order[i])) continue;
    if (drop_chacha && strcmp(order[i], SSH_CHACHA) == 0) continue;
    if (!csv_add(out, cap, order[i])) return SD_E_INTERNAL;
  }
  return out[0] ? SD_OK : SD_E_KEX_FAILED;
}

sd_err ssh_build_lists(const ssh_list_input *in, ssh_lists *out, ssh_list_result *res)
{
  int (*avail)(const char *) = in->cipher_available ? in->cipher_available : default_cipher_available;
  const char *const *corder = in->hw_aes ? k_cipher_hw : k_cipher_sw;
  int drop_c2s = 0, drop_s2c = 0;
  size_t i;
  sd_err e;

  memset(out, 0, sizeof(*out));
  memset(res, 0, sizeof(*res));

  /* kex */
  for (i = 0; i < SD_COUNTOF(k_kex); i++)
    if (!disabled(in->disabled, k_kex[i])) csv_add(out->kex, sizeof(out->kex), k_kex[i]);
  if (!out->kex[0]) return SD_E_KEX_FAILED;
  if (in->initial) {
    csv_add(out->kex, sizeof(out->kex), SSH_EXT_INFO_C);
    csv_add(out->kex, sizeof(out->kex), SSH_STRICT_C);
  }

  /* host key algorithms, restricted to stored key types (TM-R04) */
  {
    int restrict_types = in->stored && (in->stored->count > 0 || in->stored->has_ca);
    for (i = 0; i < SD_COUNTOF(k_hostkey); i++) {
      if (disabled(in->disabled, k_hostkey[i])) continue;
      if (restrict_types && !stored_has(in->stored, k_hostkey_type[i])) continue;
      csv_add(out->hostkey, sizeof(out->hostkey), k_hostkey[i]);
    }
    if (!out->hostkey[0]) return restrict_types ? SD_E_HOSTKEY_TYPE_UNAVAILABLE : SD_E_KEX_FAILED;
  }

  /* ciphers: Terrapin-aware construction after the server's KEXINIT (TM-R01, D34) */
  if (in->server) {
    res->strict = sd_namelist_contains(in->server->kex, SSH_STRICT_S);
    if (!res->strict) {
      int ok_c2s = has_unaffected_pair(corder, SD_COUNTOF(k_cipher_sw), in, avail,
                                       in->server->enc_c2s, in->server->mac_c2s);
      int ok_s2c = has_unaffected_pair(corder, SD_COUNTOF(k_cipher_sw), in, avail,
                                       in->server->enc_s2c, in->server->mac_s2c);
      drop_c2s = ok_c2s;
      drop_s2c = ok_s2c;
      if ((!ok_c2s && chacha_shared(in, avail, in->server->enc_c2s)) ||
          (!ok_s2c && chacha_shared(in, avail, in->server->enc_s2c))) {
        res->terrapin_exposed = 1;
        if (in->refuse_terrapin_exposed) return SD_E_KEX_FAILED;
      }
      res->chacha_removed = (drop_c2s && chacha_shared(in, avail, in->server->enc_c2s)) ||
                            (drop_s2c && chacha_shared(in, avail, in->server->enc_s2c));
    }
  } else {
    /* fallback lists: AES-GCM and AES-CTR above chacha20-poly1305 (01 §4.2) */
    static const char *const k_fallback[] = {
      "aes256-gcm@openssh.com", "aes128-gcm@openssh.com", "aes256-ctr", "aes192-ctr", "aes128-ctr",
      SSH_CHACHA
    };
    corder = k_fallback;
  }
  e = build_cipher_list(corder, SD_COUNTOF(k_cipher_sw), in, avail, drop_c2s, out->enc_c2s, sizeof(out->enc_c2s));
  if (e != SD_OK) return e;
  e = build_cipher_list(corder, SD_COUNTOF(k_cipher_sw), in, avail, drop_s2c, out->enc_s2c, sizeof(out->enc_s2c));
  if (e != SD_OK) return e;

  for (i = 0; i < SD_COUNTOF(k_mac); i++) {
    if (disabled(in->disabled, k_mac[i])) continue;
    csv_add(out->mac_c2s, sizeof(out->mac_c2s), k_mac[i]);
    csv_add(out->mac_s2c, sizeof(out->mac_s2c), k_mac[i]);
  }
  /* An empty MAC list is only acceptable if every cipher left is AEAD; negotiation checks it. */
  memcpy(out->comp, "none", 5);
  return SD_OK;
}

int ssh_pick(const char *client_csv, sd_span server_list, char *out, size_t cap)
{
  const char *p = client_csv;
  while (p && *p) {
    const char *e = strchr(p, ',');
    size_t len = e ? (size_t)(e - p) : strlen(p);
    char name[128];
    if (len < sizeof(name)) {
      memcpy(name, p, len);
      name[len] = '\0';
      if (strcmp(name, SSH_EXT_INFO_C) != 0 && strcmp(name, SSH_STRICT_C) != 0 &&
          sd_namelist_contains(server_list, name)) {
        if (len + 1 > cap) return 0;
        memcpy(out, name, len + 1);
        return 1;
      }
    }
    p = e ? e + 1 : NULL;
  }
  return 0;
}

sd_err ssh_negotiate(const ssh_lists *ours, const ssh_kexinit *s, ssh_algs *out, const char **category)
{
  memset(out, 0, sizeof(*out));
  *category = NULL;
  if (!ssh_pick(ours->kex, s->kex, out->kex, sizeof(out->kex))) { *category = "kex"; return SD_E_KEX_FAILED; }
  if (!ssh_pick(ours->hostkey, s->hostkey, out->hostkey, sizeof(out->hostkey))) {
    *category = "hostkey";
    return SD_E_KEX_FAILED;
  }
  if (!ssh_pick(ours->enc_c2s, s->enc_c2s, out->enc_c2s, sizeof(out->enc_c2s)) ||
      !ssh_pick(ours->enc_s2c, s->enc_s2c, out->enc_s2c, sizeof(out->enc_s2c))) {
    *category = "cipher";
    return SD_E_KEX_FAILED;
  }
  if (!ssh_cipher_is_aead(out->enc_c2s) && !ssh_pick(ours->mac_c2s, s->mac_c2s, out->mac_c2s, sizeof(out->mac_c2s))) {
    *category = "mac";
    return SD_E_KEX_FAILED;
  }
  if (!ssh_cipher_is_aead(out->enc_s2c) && !ssh_pick(ours->mac_s2c, s->mac_s2c, out->mac_s2c, sizeof(out->mac_s2c))) {
    *category = "mac";
    return SD_E_KEX_FAILED;
  }
  if (!ssh_pick(ours->comp, s->comp_c2s, out->comp_c2s, sizeof(out->comp_c2s)) ||
      !ssh_pick(ours->comp, s->comp_s2c, out->comp_s2c, sizeof(out->comp_s2c))) {
    *category = "compression";
    return SD_E_KEX_FAILED;
  }
  return SD_OK;
}

sd_err ssh_kexinit_parse(const uint8_t *payload, size_t n, ssh_kexinit *k)
{
  sd_rd r;
  sd_span c;
  memset(k, 0, sizeof(*k));
  sd_rd_init(&r, payload, n);
  if (sd_rd_u8(&r) != SSH_MSG_KEXINIT) return SD_E_PROTOCOL;
  c = sd_rd_bytes(&r, 16);
  if (sd_rd_ok(&r)) memcpy(k->cookie, c.p, 16);
  k->kex = sd_rd_name_list(&r, 8192);
  k->hostkey = sd_rd_name_list(&r, 8192);
  k->enc_c2s = sd_rd_name_list(&r, 8192);
  k->enc_s2c = sd_rd_name_list(&r, 8192);
  k->mac_c2s = sd_rd_name_list(&r, 8192);
  k->mac_s2c = sd_rd_name_list(&r, 8192);
  k->comp_c2s = sd_rd_name_list(&r, 8192);
  k->comp_s2c = sd_rd_name_list(&r, 8192);
  k->lang_c2s = sd_rd_name_list(&r, 8192);
  k->lang_s2c = sd_rd_name_list(&r, 8192);
  k->first_kex_follows = sd_rd_bool(&r);
  (void)sd_rd_u32(&r);   /* reserved */
  /* RFC 4253 allows no trailing data, but be lenient like OpenSSH: only require a complete parse. */
  return sd_rd_ok(&r) ? SD_OK : SD_E_PROTOCOL;
}

static void wr_csv(sd_wr *w, const char *csv) { sd_wr_string(w, csv, strlen(csv)); }

void ssh_kexinit_encode(sd_wr *w, const uint8_t cookie[16], const ssh_lists *l)
{
  sd_wr_u8(w, SSH_MSG_KEXINIT);
  sd_wr_bytes(w, cookie, 16);
  wr_csv(w, l->kex);
  wr_csv(w, l->hostkey);
  wr_csv(w, l->enc_c2s);
  wr_csv(w, l->enc_s2c);
  wr_csv(w, l->mac_c2s);
  wr_csv(w, l->mac_s2c);
  wr_csv(w, l->comp);
  wr_csv(w, l->comp);
  wr_csv(w, "");
  wr_csv(w, "");
  sd_wr_bool(w, 0);       /* first_kex_packet_follows: never (01 §4.2) */
  sd_wr_u32(w, 0);
}

#define SSH_MAX_PREBANNER_LINE 8192u

sd_err ssh_version_line(const uint8_t *buf, size_t n, size_t *line_len, int *is_ident, char *ident,
                        size_t ident_cap)
{
  size_t i, lim = SD_MIN(n, (size_t)SSH_MAX_PREBANNER_LINE);
  *line_len = 0;
  *is_ident = 0;
  for (i = 0; i < lim; i++) {
    if (buf[i] == '\n') {
      size_t end = i;
      int ssh = n >= 4 && memcmp(buf, "SSH-", 4) == 0;
      if (end > 0 && buf[end - 1] == '\r') end--;
      *line_len = i + 1;
      if (ssh) {
        if (i + 1 > 255) return SD_E_PROTOCOL;
        if (!(end >= 8 && memcmp(buf, "SSH-2.0-", 8) == 0) && !(end >= 9 && memcmp(buf, "SSH-1.99-", 9) == 0))
          return SD_E_PROTOCOL;
        if (end + 1 > ident_cap) return SD_E_PROTOCOL;
        memcpy(ident, buf, end);
        ident[end] = '\0';
        *is_ident = 1;
      }
      return SD_OK;
    }
  }
  if (n >= SSH_MAX_PREBANNER_LINE) return SD_E_PROTOCOL;
  if (n >= 4 && memcmp(buf, "SSH-", 4) == 0 && n > 255) return SD_E_PROTOCOL;
  return SD_OK;
}
