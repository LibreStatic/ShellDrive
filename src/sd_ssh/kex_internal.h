/* sd_ssh private: key exchange methods (01 §4.2; RFC 4253 §8, RFC 4419, RFC 5656, RFC 8268,
 * RFC 8731, draft-ietf-sshm-mlkem-hybrid-kex). Shared by kex.c and the unit tests. */
#ifndef SD_SSH_KEX_INTERNAL_H
#define SD_SSH_KEX_INTERNAL_H

#include "sd/base.h"
#include "sd_base/sd_buf.h"
#include "sd_base/sd_err.h"
#include "sd_crypto/sd_crypto.h"

enum {
  SSH_MSG_KEXDH_INIT = 30, SSH_MSG_KEXDH_REPLY = 31,
  SSH_MSG_KEX_DH_GEX_GROUP = 31, SSH_MSG_KEX_DH_GEX_INIT = 32, SSH_MSG_KEX_DH_GEX_REPLY = 33,
  SSH_MSG_KEX_DH_GEX_REQUEST = 34
};

/* Group-exchange request (01 §4.2): min 2048, preferred 4096, max 8192. With legacy allowed a server
   answer of 1024..2047 bits is accepted and flagged SD_LEGACY_DH_SMALL; below 1024 always fails. */
#define SSH_GEX_MIN 2048u
#define SSH_GEX_N   4096u
#define SSH_GEX_MAX 8192u

typedef enum ssh_km_kind { SSH_KM_C25519, SSH_KM_ECDH, SSH_KM_DH, SSH_KM_GEX, SSH_KM_MLKEM } ssh_km_kind;

typedef struct ssh_kex_method {
  const char *name;
  ssh_km_kind kind;
  sd_hash_alg hash;
  int param;                  /* ECDH: sd_curve; DH: SD_DH_GROUP* */
} ssh_kex_method;

const ssh_kex_method *ssh_kex_method_find(const char *name);

/* Inputs of the exchange hash common to every method (RFC 4253 §8). */
typedef struct ssh_kex_hash_in {
  const char *v_c, *v_s;      /* identification strings without CR LF */
  const uint8_t *i_c; size_t i_c_len;
  const uint8_t *i_s; size_t i_s_len;
} ssh_kex_hash_in;

typedef struct ssh_kexm ssh_kexm;

/* Creates the method state and writes the first client message (INIT, or GEX REQUEST) into w. */
sd_err  ssh_kexm_start(const ssh_kex_method *m, int allow_legacy, ssh_kexm **out, sd_wr *w);
/* 1 while a GEX method waits for KEX_DH_GEX_GROUP. */
int     ssh_kexm_awaiting_group(const ssh_kexm *s);
/* GEX: validates the group (size policy, p odd, 1 < g < p-1), writes KEX_DH_GEX_INIT into w.
   *pbits receives bits(p). SD_E_KEX_FAILED on a rejected group. */
sd_err  ssh_kexm_gex_group(ssh_kexm *s, const uint8_t *msg, size_t n, sd_wr *w, uint32_t *pbits);
/* Message number of the server reply this method expects next. */
uint8_t ssh_kexm_reply_msg(const ssh_kexm *s);
/* Parses the server reply (message byte included), computes the shared secret and the exchange hash.
   ks / sig point into msg. k_enc receives K as encoded for hashing and key derivation (mpint, or
   string for mlkem768x25519-sha256); h receives sd_hash_len(m->hash) bytes. Ephemeral secrets are
   wiped. SD_E_PROTOCOL (malformed), SD_E_KEX_FAILED (invalid peer value). */
sd_err  ssh_kexm_finish(ssh_kexm *s, const uint8_t *msg, size_t n, const ssh_kex_hash_in *hin,
                        sd_span *ks, sd_span *sig, sd_wr *k_enc, uint8_t *h, size_t *hlen);
void    ssh_kexm_free(ssh_kexm *s);       /* NULL is a no-op; zeroizes */

/* RFC 4253 §7.2 key derivation with the KEX hash: out = HASH(K || H || x || session_id) extended
   by HASH(K || H || K1 || ...). need <= 64. */
void    ssh_kex_derive(sd_hash_alg hash, const uint8_t *k_enc, size_t k_len, const uint8_t *h, size_t hlen,
                       char x, const uint8_t *sid, size_t sid_len, uint8_t *out, size_t need);

#endif /* SD_SSH_KEX_INTERNAL_H */
