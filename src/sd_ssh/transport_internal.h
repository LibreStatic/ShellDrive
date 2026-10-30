/* sd_ssh private: transport state shared by kex.c and hostkey_update.c (UpdateHostKeys 01 §7.5,
 * sd_ssh_conn_fetch_hostkeys 01 §4.3/§9). I/O thread only. */
#ifndef SD_SSH_TRANSPORT_INTERNAL_H
#define SD_SSH_TRANSPORT_INTERNAL_H

#include "conn_internal.h"

#define SSH_HKU_MAX_KEYS 16u

typedef struct ssh_hku_key {
  uint8_t *blob; size_t len;
  char type[48];
  char fp[64];
} ssh_hku_key;

typedef enum ssh_hku_req { SSH_HKU_REQ_NONE, SSH_HKU_REQ_UPDATE, SSH_HKU_REQ_FETCH } ssh_hku_req;

struct ssh_hku {
  /* recorded at the initial KEX */
  char server_hk_algs[2048];      /* the server's host key algorithm list (first KEXINIT) */
  char legacy_names[512];         /* for SD_PROMPT_LEGACY_ACK */
  uint32_t gen;                   /* connect generation these values belong to */

  /* hostkeys-00@openssh.com announcement (at most one per connection) */
  int announced;
  ssh_hku_key ann[SSH_HKU_MAX_KEYS]; uint32_t nann;

  /* UpdateHostKeys processing */
  int update_started;
  sd_kh_store_kind target;
  ssh_hku_key rem[SSH_HKU_MAX_KEYS]; uint32_t nrem;      /* removal candidates */

  /* hostkeys-prove-00 request in flight (one at a time) */
  ssh_hku_req prove;
  uint32_t prove_ahead;           /* keepalive replies due before ours */
  uint32_t prove_idx[SSH_HKU_MAX_KEYS]; uint32_t nprove; /* indices into ann[] */

  /* sd_ssh_conn_fetch_hostkeys */
  int fetching;
  sd_ssh_hostkeys_cb fetch_done; void *fetch_ctx;
  char fetch_types[8][48]; uint32_t nfetch_types;      /* 0 = every announced key */
  uint32_t fetch_next_type;       /* next type to try with a restricted re-key */
  int fetch_rekey;                /* a restricted re-key is running */
  ssh_hku_key got[SSH_HKU_MAX_KEYS + 8]; uint32_t ngot;
};

typedef struct ssh_hku ssh_hku;

/* Returns c->hku, allocating it on first use (NULL only when out of memory). */
ssh_hku *ssh_hku_get(sd_ssh_conn *c);
/* kex.c -> hostkey_update.c: a fetch re-key produced host key ks (signature already verified). */
void ssh_hku_on_fetch_key(sd_ssh_conn *c, const uint8_t *ks, size_t n);
/* kex.c -> hostkey_update.c: a re-key finished (NEWKEYS both ways). */
void ssh_hku_on_rekey_done(sd_ssh_conn *c);
/* kex.c: starts a re-key that offers only host key algorithms hk_list (01 §4.3 "add a key"). */
sd_err ssh_kex_start_fetch_rekey(sd_ssh_conn *c, const char *hk_list);

#endif /* SD_SSH_TRANSPORT_INTERNAL_H */
