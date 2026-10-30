# Unit tests for the M2 symmetric/PQ additions of sd_crypto (area "pq"): SHA-3/SHAKE, ML-KEM-768 and
# mlkem768x25519-sha256, BLAKE2b, Argon2 / PPK v3, AES-CBC and 3DES-CBC. Executable
# sd-test-crypto_pq.exe, CTest unit.crypto_pq. Vectors in tests/vectors/pq (PROVENANCE.md there).
# The vector-file helpers are shared with tests/unit/sd_crypto (tutil.c).

sd_add_unit_test(crypto_pq
  SOURCES main.c ../sd_crypto/tutil.c test_sha3.c test_mlkem.c test_kdf.c test_cbc.c test_bench_pq.c
  DEPS sd_crypto sd_platform sd_base)

target_include_directories(sd-test-crypto_pq PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../sd_crypto"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../src/sd_crypto")
target_compile_definitions(sd-test-crypto_pq PRIVATE
  SD_TEST_VECTORS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../../vectors")
