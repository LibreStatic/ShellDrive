/* mlkem768x25519-sha256 key agreement (draft-ietf-sshm-mlkem-hybrid-kex; 01 §4.2):
 *   Q_C = ek (1184) || X25519 public (32), Q_S = ct (1088) || X25519 public (32),
 *   K   = SHA-256(K_PQ || K_CL), with K_PQ the ML-KEM shared secret and K_CL the raw 32-byte X25519
 *         result (an all-zero K_CL is rejected, as for curve25519-sha256).
 * sd_ssh encodes K as an SSH string. Ephemeral keys come from sd_random(). */
#include <string.h>

#include "crypto_internal.h"
#include "sd_base/sd_mem.h"

static void combine(uint8_t k[32], const uint8_t pq[32], const uint8_t cl[32])
{
  sd_hash_ctx h;
  sd_hash_init(&h, SD_HASH_SHA256);
  sd_hash_update(&h, pq, 32);
  sd_hash_update(&h, cl, 32);
  sd_hash_final(&h, k);
}

void sd_mlkem768x25519_client_wipe(sd_mlkem768x25519_client *st)
{
  if (st)
    sd_secure_zero(st, sizeof(*st));
}

sd_err sd_mlkem768x25519_client_init(sd_mlkem768x25519_client *st, uint8_t q_c[1216])
{
  sd_err err;
  if (st == NULL || q_c == NULL)
    return SD_E_INVALID_PARAM;
  err = sd_mlkem768_keypair(q_c, st->mlkem_sk);
  if (err == SD_OK)
    err = sd_random(st->x25519_sk, 32) == SD_OK ? SD_OK : SD_E_CRYPTO;
  if (err == SD_OK)
    err = sd_x25519_base(q_c + SD_MLKEM768_PK_LEN, st->x25519_sk);
  if (err != SD_OK)
    sd_mlkem768x25519_client_wipe(st);
  return err;
}

sd_err sd_mlkem768x25519_client_finish(sd_mlkem768x25519_client *st, const uint8_t q_s[1120], uint8_t k[32])
{
  uint8_t pq[32], cl[32];
  sd_err err;
  if (st == NULL || q_s == NULL || k == NULL) {
    sd_mlkem768x25519_client_wipe(st);
    return SD_E_INVALID_PARAM;
  }
  err = sd_mlkem768_decaps(pq, q_s, st->mlkem_sk);
  if (err == SD_OK)
    err = sd_x25519(cl, st->x25519_sk, q_s + SD_MLKEM768_CT_LEN);
  if (err == SD_OK)
    combine(k, pq, cl);
  else
    memset(k, 0, 32);
  sd_secure_zero(pq, sizeof(pq));
  sd_secure_zero(cl, sizeof(cl));
  sd_mlkem768x25519_client_wipe(st);
  return err;
}

sd_err sd_mlkem768x25519_server(const uint8_t q_c[1216], uint8_t q_s[1120], uint8_t k[32])
{
  uint8_t pq[32], cl[32], eph[32];
  sd_err err;
  if (q_c == NULL || q_s == NULL || k == NULL)
    return SD_E_INVALID_PARAM;
  err = sd_mlkem768_encaps(q_s, pq, q_c);
  if (err == SD_OK)
    err = sd_random(eph, sizeof(eph)) == SD_OK ? SD_OK : SD_E_CRYPTO;
  if (err == SD_OK)
    err = sd_x25519_base(q_s + SD_MLKEM768_CT_LEN, eph);
  if (err == SD_OK)
    err = sd_x25519(cl, eph, q_c + SD_MLKEM768_PK_LEN);
  if (err == SD_OK)
    combine(k, pq, cl);
  else
    memset(k, 0, 32);
  sd_secure_zero(pq, sizeof(pq));
  sd_secure_zero(cl, sizeof(cl));
  sd_secure_zero(eph, sizeof(eph));
  return err;
}
