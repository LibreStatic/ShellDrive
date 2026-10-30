/* Private interface of the constant-time 3DES core (des3.c), shared with pktcipher.c and the unit
 * tests (tests/unit/sd_crypto_pq). Not a public contract. */
#ifndef SD_DES3_INTERNAL_H
#define SD_DES3_INTERNAL_H

#include "sd/base.h"

/* Round keys of the three DES stages, 16 rounds each, as six selector masks per round (des3.c). */
typedef struct sd_des3_key { uint32_t ks[3][16][6]; } sd_des3_key;

void sd_des3_key_init(sd_des3_key *k, const uint8_t key[24]);
void sd_des3_key_wipe(sd_des3_key *k);
void sd_des3_block(const sd_des3_key *k, int encrypt, const uint8_t in[8], uint8_t out[8]);
/* CBC over whole 8-byte blocks; iv is the chaining value and is updated (in may equal out). */
void sd_des3_cbc(const sd_des3_key *k, int encrypt, uint8_t iv[8], const uint8_t *in, size_t len, uint8_t *out);
/* Single-DES S-box network output for one 6-bit input of box s (0..7), for the unit test. */
uint32_t sd_des_sbox_ct(unsigned box, unsigned v);

#endif /* SD_DES3_INTERNAL_H */
