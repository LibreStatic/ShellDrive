/* Test-only translation unit for the EC arithmetic hooks (sd_ec_test_mul/add/dbl). It includes ec_p.c
 * with SD_EC_TEST_HOOKS defined, so the hooks exist in sd-test-crypto_pk and nowhere in the product
 * library. The library object ec_p.obj is not pulled in: every symbol it defines is already provided
 * here, and the linker resolves nothing from it. */
#define SD_EC_TEST_HOOKS 1
#include "../../../src/sd_crypto/ec_p.c"
