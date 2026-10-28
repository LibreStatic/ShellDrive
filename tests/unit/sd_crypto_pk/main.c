#include "sd_test.h"

SD_TEST_DECL(sha1_fips180);
SD_TEST_DECL(hmac_sha1_rfc2202);
SD_TEST_DECL(pbkdf2_sha1_rfc6070);
SD_TEST_DECL(wycheproof_hmac_sha1);
SD_TEST_DECL(bn_independent_reference);
SD_TEST_DECL(bn_api_edges);
SD_TEST_DECL(bn_montmul_matches_mul_mod);
SD_TEST_DECL(wycheproof_rsa_pkcs1_verify);
SD_TEST_DECL(wycheproof_rsa_pkcs1_sign);
SD_TEST_DECL(rsa_reference_keys);
SD_TEST_DECL(rsa_public_key_rules);
SD_TEST_DECL(dh_group_constants);
SD_TEST_DECL(dh_key_agreement);
SD_TEST_DECL(dh_new_rules);
SD_TEST_DECL(dh_gex_validation);
SD_TEST_DECL(ec_rfc5903_ecdh);
SD_TEST_DECL(ec_rfc6979_ecdsa);
SD_TEST_DECL(ec_independent_reference);
SD_TEST_DECL(wycheproof_ecdsa);
SD_TEST_DECL(wycheproof_ecdh);
SD_TEST_DECL(ec_sign_verify_and_rules);
SD_TEST_DECL(ec_field_reduction_differential);
SD_TEST_DECL(cng_diff_ecdsa);
SD_TEST_DECL(cng_diff_ecdh);
SD_TEST_DECL(cng_diff_rsa);
SD_TEST_DECL(cng_diff_dh);
SD_TEST_DECL(bench_pk_throughput);

static const sd_test_case k_tests[] = {
  SD_TEST_ENTRY(sha1_fips180),
  SD_TEST_ENTRY(hmac_sha1_rfc2202),
  SD_TEST_ENTRY(pbkdf2_sha1_rfc6070),
  SD_TEST_ENTRY(wycheproof_hmac_sha1),
  SD_TEST_ENTRY(bn_independent_reference),
  SD_TEST_ENTRY(bn_api_edges),
  SD_TEST_ENTRY(bn_montmul_matches_mul_mod),
  SD_TEST_ENTRY(wycheproof_rsa_pkcs1_verify),
  SD_TEST_ENTRY(wycheproof_rsa_pkcs1_sign),
  SD_TEST_ENTRY(rsa_reference_keys),
  SD_TEST_ENTRY(rsa_public_key_rules),
  SD_TEST_ENTRY(dh_group_constants),
  SD_TEST_ENTRY(dh_key_agreement),
  SD_TEST_ENTRY(dh_new_rules),
  SD_TEST_ENTRY(dh_gex_validation),
  SD_TEST_ENTRY(ec_rfc5903_ecdh),
  SD_TEST_ENTRY(ec_rfc6979_ecdsa),
  SD_TEST_ENTRY(ec_independent_reference),
  SD_TEST_ENTRY(wycheproof_ecdsa),
  SD_TEST_ENTRY(wycheproof_ecdh),
  SD_TEST_ENTRY(ec_sign_verify_and_rules),
  SD_TEST_ENTRY(ec_field_reduction_differential),
  SD_TEST_ENTRY(cng_diff_ecdsa),
  SD_TEST_ENTRY(cng_diff_ecdh),
  SD_TEST_ENTRY(cng_diff_rsa),
  SD_TEST_ENTRY(cng_diff_dh),
  SD_TEST_ENTRY(bench_pk_throughput),
};

int main(int argc, char **argv)
{
  return sd_test_main(k_tests, SD_COUNTOF(k_tests), argc, argv);
}
