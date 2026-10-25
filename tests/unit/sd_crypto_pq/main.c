#include "sd_test.h"

SD_TEST_DECL(sha3_fips202_cavp_short);
SD_TEST_DECL(shake_fips202_cavp);
SD_TEST_DECL(sha3_cavp_monte);
SD_TEST_DECL(sha3_hashlib_reference);
SD_TEST_DECL(sha3_incremental_matches_oneshot);
SD_TEST_DECL(mlkem768_acvp_keygen);
SD_TEST_DECL(mlkem768_acvp_encap_decap);
SD_TEST_DECL(wycheproof_mlkem768);
SD_TEST_DECL(mlkem768_roundtrip_and_implicit_rejection);
SD_TEST_DECL(mlkem768x25519_combiner);
SD_TEST_DECL(blake2b_rfc7693_and_kat);
SD_TEST_DECL(argon2_rfc9106);
SD_TEST_DECL(ppk_v3_key_derivation);
SD_TEST_DECL(aes_cbc_cavp);
SD_TEST_DECL(tdes_cavp);
SD_TEST_DECL(des_sbox_network);
SD_TEST_DECL(pktcipher_cbc_streams);
SD_TEST_DECL(cipher_oneshot_3des_names);
SD_TEST_DECL(cng_diff_aes_cbc_3des_cbc);
SD_TEST_DECL(cng_diff_mlkem768);
SD_TEST_DECL(bench_pq);

static const sd_test_case k_tests[] = {
  SD_TEST_ENTRY(sha3_fips202_cavp_short),
  SD_TEST_ENTRY(shake_fips202_cavp),
  SD_TEST_ENTRY(sha3_cavp_monte),
  SD_TEST_ENTRY(sha3_hashlib_reference),
  SD_TEST_ENTRY(sha3_incremental_matches_oneshot),
  SD_TEST_ENTRY(mlkem768_acvp_keygen),
  SD_TEST_ENTRY(mlkem768_acvp_encap_decap),
  SD_TEST_ENTRY(wycheproof_mlkem768),
  SD_TEST_ENTRY(mlkem768_roundtrip_and_implicit_rejection),
  SD_TEST_ENTRY(mlkem768x25519_combiner),
  SD_TEST_ENTRY(blake2b_rfc7693_and_kat),
  SD_TEST_ENTRY(argon2_rfc9106),
  SD_TEST_ENTRY(ppk_v3_key_derivation),
  SD_TEST_ENTRY(aes_cbc_cavp),
  SD_TEST_ENTRY(tdes_cavp),
  SD_TEST_ENTRY(des_sbox_network),
  SD_TEST_ENTRY(pktcipher_cbc_streams),
  SD_TEST_ENTRY(cipher_oneshot_3des_names),
  SD_TEST_ENTRY(cng_diff_aes_cbc_3des_cbc),
  SD_TEST_ENTRY(cng_diff_mlkem768),
  SD_TEST_ENTRY(bench_pq),
};

int main(int argc, char **argv)
{
  return sd_test_main(k_tests, SD_COUNTOF(k_tests), argc, argv);
}
