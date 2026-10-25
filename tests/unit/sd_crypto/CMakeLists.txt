# Unit tests for sd_crypto. Owned by the sd_crypto agent.
# The executable is sd-test-crypto.exe, registered with CTest as unit.crypto. Vector data lives in
# tests/vectors (see tests/vectors/PROVENANCE.md) and is read at run time.

sd_add_unit_test(crypto
  SOURCES main.c tutil.c test_ct_bench.c test_curve.c test_hash.c test_sym.c test_cng.c
  DEPS sd_crypto sd_platform sd_base)

target_include_directories(sd-test-crypto PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../../../src/sd_crypto")
target_compile_definitions(sd-test-crypto PRIVATE
  SD_TEST_VECTORS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../../vectors")
