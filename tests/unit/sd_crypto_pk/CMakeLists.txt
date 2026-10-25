# Unit tests for the public-key area of sd_crypto (SHA-1, sd_bn, RSA, DH, P-256/384/521). Owned by the
# sd_crypto pk agent. The executable is sd-test-crypto_pk.exe, registered with CTest as unit.crypto_pk.
# Vector data lives in tests/vectors (see tests/vectors/PROVENANCE.md) and is read at run time; the
# vector-file helpers are shared with tests/unit/sd_crypto (tutil.c, used unchanged).

sd_add_unit_test(crypto_pk
  SOURCES main.c test_sha1.c test_bn.c test_rsa.c test_dh.c test_ec.c test_cng_pk.c test_bench_pk.c pkt.h
          ../sd_crypto/tutil.c
  DEPS sd_crypto sd_platform sd_base)

target_include_directories(sd-test-crypto_pk PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../src/sd_crypto"
  "${CMAKE_CURRENT_SOURCE_DIR}/../sd_crypto")
target_compile_definitions(sd-test-crypto_pk PRIVATE
  SD_TEST_VECTORS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../../vectors")
