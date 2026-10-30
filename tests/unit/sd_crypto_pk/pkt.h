/* Shared helpers of the sd_crypto public-key tests. */
#ifndef SD_CRYPTO_PK_TESTS_H
#define SD_CRYPTO_PK_TESTS_H

#include <stdint.h>
#include <string.h>

#include "sd_crypto/sd_crypto.h"

/* "sha1" .. "sha512" -> algorithm; returns 0 for names sd_crypto lacks (sha224). */
static __inline int pkt_hash(const char *name, sd_hash_alg *out)
{
  if (strcmp(name, "sha1") == 0) { *out = SD_HASH_SHA1; return 1; }
  if (strcmp(name, "sha256") == 0) { *out = SD_HASH_SHA256; return 1; }
  if (strcmp(name, "sha384") == 0) { *out = SD_HASH_SHA384; return 1; }
  if (strcmp(name, "sha512") == 0) { *out = SD_HASH_SHA512; return 1; }
  return 0;
}

static __inline sd_curve pkt_curve(const char *name)
{
  if (strcmp(name, "256") == 0) return SD_CURVE_P256;
  if (strcmp(name, "384") == 0) return SD_CURVE_P384;
  return SD_CURVE_P521;
}

#endif
