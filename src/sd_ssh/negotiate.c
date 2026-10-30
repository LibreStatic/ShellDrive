/* Algorithm lists, KEXINIT encoding/parsing, negotiation (01 §4.2, §4.3; TM-R01, TM-R04, D4, D33,
 * D34), legacy classification (01 §4.3 legacy_mask) and the identification-line scanner (01 §4.1).
 * Pure code: no I/O. Algorithm availability comes from callbacks (defaults: sd_crypto / sd_ssh). */
#include <string.h>

#include "ssh_internal.h"

/* ---- static preference order (01 §4.3): modern first, legacy last ---- */

typedef struct alg_entry { const char *name; int legacy; } alg_entry;

static const alg_entry k_kex[] = {
  { "mlkem768x25519-sha256", 0 },
  { "curve25519-sha256", 0 }, { "curve25519-sha256@libssh.org", 0 },
  { "ecdh-sha2-nistp256", 0 }, { "ecdh-sha2-nistp384", 0 }, { "ecdh-sha2-nistp521", 0 },
  { "diffie-hellman-group-exchange-sha256", 0 }, { "diffie-hellman-group16-sha512", 0 },
  { "diffie-hellman-group18-sha512", 0 }, { "diffie-hellman-group14-sha256", 0 },
  { "diffie-hellman-group14-sha1", 1 }, { "diffie-hellman-group-exchange-sha1", 1 },
  { "diffie-hellman-group1-sha1", 1 }
};

typedef struct hk_entry { const char *name; const char *key_type; int cert, legacy; } hk_entry;

static const hk_entry k_hostkey[] = {
  { "ssh-ed25519-cert-v01@openssh.com", "ssh-ed25519", 1, 0 },
  { "ecdsa-sha2-nistp256-cert-v01@openssh.com", "ecdsa-sha2-nistp256", 1, 0 },
  { "ecdsa-sha2-nistp384-cert-v01@openssh.com", "ecdsa-sha2-nistp384", 1, 0 },
  { "ecdsa-sha2-nistp521-cert-v01@openssh.com", "ecdsa-sha2-nistp521", 1, 0 },
  { "rsa-sha2-512-cert-v01@openssh.com", "ssh-rsa", 1, 0 },
  { "rsa-sha2-256-cert-v01@openssh.com", "ssh-rsa", 1, 0 },
  { "ssh-ed25519", "ssh-ed25519", 0, 0 },
  { "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp256", 0, 0 },
  { "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp384", 0, 0 },
  { "ecdsa-sha2-nistp521", "ecdsa-sha2-nistp521", 0, 0 },
  { "rsa-sha2-512", "ssh-rsa", 0, 0 },
  { "rsa-sha2-256", "ssh-rsa", 0, 0 },
  { "ssh-rsa-cert-v01@openssh.com", "ssh-rsa", 1, 1 },
  { "ssh-rsa", "ssh-rsa", 0, 1 }
};

#define N_CIPHERS 10
static const alg_entry k_cipher_sw[N_CIPHERS] = {
  { "chacha20-poly1305@openssh.com", 0 }, { "aes256-gcm@openssh.com", 0 }, { "aes128-gcm@openssh.com", 0 },
  { "aes256-ctr", 0 }, { "aes192-ctr", 0 }, { "aes128-ctr", 0 },
  { "aes256-cbc", 1 }, { "aes192-cbc", 1 }, { "aes128-cbc", 1 }, { "3des-cbc", 1 }
};
static const alg_entry k_cipher_hw[N_CIPHERS] = {
  { "aes256-gcm@openssh.com", 0 }, { "aes128-gcm@openssh.com", 0 }, { "chacha20-poly1305@openssh.com", 0 },
  { "aes256-ctr", 0 }, { "aes192-ctr", 0 }, { "aes128-ctr", 0 },
  { "aes256-cbc", 1 }, { "aes192-cbc", 1 }, { "aes128-cbc", 1 }, { "3des-cbc", 1 }
};
/* fallback lists (no server KEXINIT within 3 s, 01 §4.2): AES-GCM and AES-CTR above chacha20-poly1305 */
static const alg_entry k_cipher_fallback[N_CIPHERS] = {
  { "aes256-gcm@openssh.com", 0 }, { "aes128-gcm@openssh.com", 0 },
  { "aes256-ctr", 0 }, { "aes192-ctr", 0 }, { "aes128-ctr", 0 }, { "chacha20-poly1305@openssh.com", 0 },
  { "aes256-cbc", 1 }, { "aes192-cbc", 1 }, { "aes128-cbc", 1 }, { "3des-cbc", 1 }
};
static const alg_entry k_mac[] = {
  { "hmac-sha2-256-etm@openssh.com", 0 }, { "hmac-sha2-512-etm@openssh.com", 0 },
  { "hmac-sha2-256", 0 }, { "hmac-sha2-512", 0 },
  { "hmac-sha1-etm@openssh.com", 1 }, { "hmac-sha1", 1 }
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

static int ends_with(const char *s, const char *suffix)
{
  size_t l = strlen(s), m = strlen(suffix);
  return l >= m && strcmp(s + l - m, suffix) == 0;
}

static int cipher_is_gcm(const char *n) { return strstr(n, "-gcm@openssh.com") != NULL; }
static int cipher_is_ctr(const char *n) { return ends_with(n, "-ctr"); }
int ssh_cipher_is_cbc(const char *n) { return ends_with(n, "-cbc"); }
int ssh_mac_is_etm(const char *n) { return ends_with(n, "-etm@openssh.com"); }

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
  for (i = 0; i < t->count && i < SD_COUNTOF(t->type); i++)
    if (strcmp(t->type[i], type) == 0) return 1;
  return 0;
}

/* ---- legacy classification ---- */

int ssh_alg_is_legacy(const char *name)
{
  size_t i;
  for (i = 0; i < SD_COUNTOF(k_kex); i++) if (strcmp(k_kex[i].name, name) == 0) return k_kex[i].legacy;
  for (i = 0; i < SD_COUNTOF(k_hostkey); i++) if (strcmp(k_hostkey[i].name, name) == 0) return k_hostkey[i].legacy;
  for (i = 0; i < N_CIPHERS; i++) if (strcmp(k_cipher_sw[i].name, name) == 0) return k_cipher_sw[i].legacy;
  for (i = 0; i < SD_COUNTOF(k_mac); i++) if (strcmp(k_mac[i].name, name) == 0) return k_mac[i].legacy;
  return 0;
}

const char *ssh_hostkey_alg_key_type(const char *alg)
{
  size_t i;
  for (i = 0; i < SD_COUNTOF(k_hostkey); i++)
    if (strcmp(k_hostkey[i].name, alg) == 0) return k_hostkey[i].key_type;
  return NULL;
}

int ssh_hostkey_alg_is_cert(const char *alg)
{
  size_t i;
  for (i = 0; i < SD_COUNTOF(k_hostkey); i++)
    if (strcmp(k_hostkey[i].name, alg) == 0) return k_hostkey[i].cert;
  return 0;
}

sd_err ssh_hostkey_algs_for_type(const char *key_type, int allow_legacy, int (*avail)(const char *),
                                 char *out, size_t cap)
{
  size_t i;
  if (!cap) return SD_E_INVALID_PARAM;
  out[0] = '\0';
  for (i = 0; i < SD_COUNTOF(k_hostkey); i++) {
    const hk_entry *h = &k_hostkey[i];
    if (h->cert || (h->legacy && !allow_legacy) || strcmp(h->key_type, key_type) != 0) continue;
    if (avail && !avail(h->name)) continue;
    if (!csv_add(out, cap, h->name)) return SD_E_INTERNAL;
  }
  return out[0] ? SD_OK : SD_E_HOSTKEY_TYPE_UNAVAILABLE;
}

uint32_t ssh_legacy_mask_for(const ssh_algs *a, int strict)
{
  uint32_t m = 0;
  if (strcmp(a->kex, "diffie-hellman-group1-sha1") == 0) m |= SD_LEGACY_KEX_SHA1 | SD_LEGACY_DH_1024;
  if (strcmp(a->kex, "diffie-hellman-group14-sha1") == 0 || strcmp(a->kex, "diffie-hellman-group-exchange-sha1") == 0)
    m |= SD_LEGACY_KEX_SHA1;
  if (strcmp(a->hostkey, "ssh-rsa") == 0 || strcmp(a->hostkey, "ssh-rsa-cert-v01@openssh.com") == 0)
    m |= SD_LEGACY_HOSTKEY_SHA1;
  if (ssh_cipher_is_cbc(a->enc_c2s) || ssh_cipher_is_cbc(a->enc_s2c)) m |= SD_LEGACY_CIPHER_CBC;
  if (strcmp(a->enc_c2s, "3des-cbc") == 0 || strcmp(a->enc_s2c, "3des-cbc") == 0) m |= SD_LEGACY_CIPHER_3DES;
  if (strncmp(a->mac_c2s, "hmac-sha1", 9) == 0 || strncmp(a->mac_s2c, "hmac-sha1", 9) == 0) m |= SD_LEGACY_MAC_SHA1;
  if ((a->mac_c2s[0] && !ssh_mac_is_etm(a->mac_c2s)) || (a->mac_s2c[0] && !ssh_mac_is_etm(a->mac_s2c)))
    m |= SD_LEGACY_MAC_NON_ETM;
  if (!strict) {
    m |= SD_LEGACY_NO_STRICT_KEX;
    /* affected pairs (01 §4.3): chacha20-poly1305, or CBC with an -etm MAC */
    if (strcmp(a->enc_c2s, SSH_CHACHA) == 0 || strcmp(a->enc_s2c, SSH_CHACHA) == 0 ||
        (ssh_cipher_is_cbc(a->enc_c2s) && ssh_mac_is_etm(a->mac_c2s)) ||
        (ssh_cipher_is_cbc(a->enc_s2c) && ssh_mac_is_etm(a->mac_s2c)))
      m |= SD_LEGACY_TERRAPIN_EXPOSED;
  }
  return m;
}

void ssh_legacy_names(const ssh_algs *a, uint32_t mask, char *out, size_t cap)
{
  const char *cand[6];
  size_t i, j, n = 0;
  if (!cap) return;
  out[0] = '\0';
  cand[n++] = a->kex;
  cand[n++] = a->hostkey;
  cand[n++] = a->enc_c2s;
  cand[n++] = a->enc_s2c;
  cand[n++] = a->mac_c2s;
  cand[n++] = a->mac_s2c;
  for (i = 0; i < n; i++) {
    int dup = 0;
    if (!cand[i][0] || !ssh_alg_is_legacy(cand[i])) continue;
    for (j = 0; j < i; j++) if (strcmp(cand[i], cand[j]) == 0) dup = 1;
    if (!dup) csv_add(out, cap, cand[i]);
  }
  if (mask & SD_LEGACY_DH_SMALL) csv_add(out, cap, "dh_group_small");
  if (mask & SD_LEGACY_RSA_SHORT) csv_add(out, cap, "rsa_key_short");
  if (mask & SD_LEGACY_TERRAPIN_EXPOSED) csv_add(out, cap, "terrapin_exposed");
  else if (mask & SD_LEGACY_NO_STRICT_KEX) csv_add(out, cap, "no_strict_kex");
}

/* ---- list construction ---- */

typedef struct dir_choice {
  int drop_chacha;      /* rule 2: an unaffected pair exists */
  int drop_etm;         /* rule 2: the resulting cipher is CBC -> non-ETM MACs only */
  int exposed;          /* rule 3 */
  int chacha_removed;
} dir_choice;

static int usable(const ssh_list_input *in, const alg_entry *a, int (*avail)(const char *))
{
  if (a->legacy && !in->allow_legacy) return 0;
  if (disabled(in->disabled, a->name)) return 0;
  return avail ? avail(a->name) : 1;
}

/* Terrapin evaluation for one direction against the server's lists (01 §4.3 rules 2 and 3). */
static void choose_dir(const alg_entry *corder, const ssh_list_input *in, int (*avail)(const char *),
                       sd_span s_enc, sd_span s_mac, dir_choice *d)
{
  size_t i, j;
  int unaffected = 0, affected = 0;
  memset(d, 0, sizeof(*d));
  for (i = 0; i < N_CIPHERS; i++) {
    const char *c = corder[i].name;
    if (!usable(in, &corder[i], avail) || !sd_namelist_contains(s_enc, c)) continue;
    if (cipher_is_gcm(c)) { unaffected = 1; continue; }
    if (strcmp(c, SSH_CHACHA) == 0) { affected = 1; continue; }
    for (j = 0; j < SD_COUNTOF(k_mac); j++) {
      if (!usable(in, &k_mac[j], NULL) || !sd_namelist_contains(s_mac, k_mac[j].name)) continue;
      if (cipher_is_ctr(c)) unaffected = 1;            /* CTR + ETM: theoretical only (01 §4.3) */
      else if (ssh_mac_is_etm(k_mac[j].name)) affected = 1;
      else unaffected = 1;                            /* CBC + non-ETM MAC */
    }
  }
  if (unaffected) {
    d->drop_chacha = 1;
    /* the cipher negotiation will pick: first of our list (without chacha) the server has */
    for (i = 0; i < N_CIPHERS; i++) {
      const char *c = corder[i].name;
      if (!usable(in, &corder[i], avail) || strcmp(c, SSH_CHACHA) == 0 || !sd_namelist_contains(s_enc, c)) continue;
      d->drop_etm = ssh_cipher_is_cbc(c);
      break;
    }
    for (i = 0; i < N_CIPHERS; i++)
      if (strcmp(corder[i].name, SSH_CHACHA) == 0 && usable(in, &corder[i], avail) && sd_namelist_contains(s_enc, SSH_CHACHA))
        d->chacha_removed = 1;
  } else if (affected) {
    d->exposed = 1;
  }
}

static sd_err build_cipher_list(const alg_entry *order, const ssh_list_input *in, int (*avail)(const char *),
                                int drop_chacha, char *out, size_t cap)
{
  size_t i;
  out[0] = '\0';
  for (i = 0; i < N_CIPHERS; i++) {
    if (!usable(in, &order[i], avail)) continue;
    if (drop_chacha && strcmp(order[i].name, SSH_CHACHA) == 0) continue;
    if (!csv_add(out, cap, order[i].name)) return SD_E_INTERNAL;
  }
  return out[0] ? SD_OK : SD_E_KEX_FAILED;
}

static void build_mac_list(const ssh_list_input *in, int drop_etm, char *out, size_t cap)
{
  size_t i;
  out[0] = '\0';
  for (i = 0; i < SD_COUNTOF(k_mac); i++) {
    if (!usable(in, &k_mac[i], NULL)) continue;
    if (drop_etm && ssh_mac_is_etm(k_mac[i].name)) continue;
    csv_add(out, cap, k_mac[i].name);
  }
}

sd_err ssh_build_lists(const ssh_list_input *in, ssh_lists *out, ssh_list_result *res)
{
  int (*avail)(const char *) = in->cipher_available ? in->cipher_available : default_cipher_available;
  int (*kex_avail)(const char *) = in->kex_available ? in->kex_available : ssh_kex_supported;
  int (*hk_avail)(const char *) = in->hostkey_available ? in->hostkey_available : ssh_hostkey_alg_supported;
  const alg_entry *corder = in->hw_aes ? k_cipher_hw : k_cipher_sw;
  dir_choice dc2s, ds2c;
  size_t i;
  sd_err e;

  memset(out, 0, sizeof(*out));
  memset(res, 0, sizeof(*res));
  memset(&dc2s, 0, sizeof(dc2s));
  memset(&ds2c, 0, sizeof(ds2c));

  /* kex */
  for (i = 0; i < SD_COUNTOF(k_kex); i++)
    if (usable(in, &k_kex[i], kex_avail)) csv_add(out->kex, sizeof(out->kex), k_kex[i].name);
  if (!out->kex[0]) return SD_E_KEX_FAILED;
  if (in->initial) {
    csv_add(out->kex, sizeof(out->kex), SSH_EXT_INFO_C);
    csv_add(out->kex, sizeof(out->kex), SSH_STRICT_C);
  }

  /* host key algorithms, restricted to stored key types (TM-R04, 01 §4.3) */
  if (in->hostkey_only) {
    if (!csv_add(out->hostkey, sizeof(out->hostkey), in->hostkey_only)) return SD_E_INTERNAL;
  } else {
    int restrict_types = in->stored && (in->stored->count > 0 || in->stored->has_ca);
    int plain_stored = in->stored && in->stored->count > 0;
    for (i = 0; i < SD_COUNTOF(k_hostkey); i++) {
      const hk_entry *h = &k_hostkey[i];
      alg_entry a;
      a.name = h->name;
      a.legacy = h->legacy;
      if (!usable(in, &a, hk_avail)) continue;
      if (restrict_types) {
        if (h->cert) {
          if (!in->stored->has_ca) continue;
          if (plain_stored && !stored_has(in->stored, h->key_type)) continue;
        } else if (!stored_has(in->stored, h->key_type)) {
          continue;
        }
      }
      csv_add(out->hostkey, sizeof(out->hostkey), h->name);
    }
    if (!out->hostkey[0]) return restrict_types ? SD_E_HOSTKEY_TYPE_UNAVAILABLE : SD_E_KEX_FAILED;
  }

  /* ciphers and MACs: Terrapin-aware construction after the server's KEXINIT (TM-R01, D34) */
  if (in->server) {
    res->strict = sd_namelist_contains(in->server->kex, SSH_STRICT_S);
    if (!res->strict) {
      choose_dir(corder, in, avail, in->server->enc_c2s, in->server->mac_c2s, &dc2s);
      choose_dir(corder, in, avail, in->server->enc_s2c, in->server->mac_s2c, &ds2c);
      if (dc2s.exposed || ds2c.exposed) {
        res->terrapin_exposed = 1;
        if (in->refuse_terrapin_exposed) return SD_E_KEX_FAILED;
      }
      res->chacha_removed = dc2s.chacha_removed || ds2c.chacha_removed;
      res->etm_removed = dc2s.drop_etm || ds2c.drop_etm;
    }
  } else {
    corder = k_cipher_fallback;
  }
  e = build_cipher_list(corder, in, avail, dc2s.drop_chacha, out->enc_c2s, sizeof(out->enc_c2s));
  if (e != SD_OK) return e;
  e = build_cipher_list(corder, in, avail, ds2c.drop_chacha, out->enc_s2c, sizeof(out->enc_s2c));
  if (e != SD_OK) return e;
  build_mac_list(in, dc2s.drop_etm, out->mac_c2s, sizeof(out->mac_c2s));
  build_mac_list(in, ds2c.drop_etm, out->mac_s2c, sizeof(out->mac_s2c));
  /* An empty MAC list is only acceptable if every cipher left is AEAD; negotiation checks it. */
  if (in->compress) memcpy(out->comp, "zlib@openssh.com,none", 22);
  else memcpy(out->comp, "none", 5);
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
