# Unit tests for the public-key area of sd_crypto (SHA-1, sd_bn, RSA, DH, P-256/384/521). Owned by the
# sd_crypto pk agent. The executable is sd-test-crypto_pk.exe, registered with CTest as unit.crypto_pk.0 .. .7
# (eight shards: the suite was the long pole of every ctest -j run).
# Vector data lives in tests/vectors (see tests/vectors/PROVENANCE.md) and is read at run time; the
# vector-file helpers are shared with tests/unit/sd_crypto (tutil.c, used unchanged).

sd_add_unit_test(crypto_pk SHARDS 8
  SOURCES main.c test_sha1.c test_bn.c test_rsa.c test_dh.c test_ec.c test_cng_pk.c test_bench_pk.c pkt.h
          ec_test_hooks.c ../sd_crypto/tutil.c
  DEPS sd_crypto sd_platform sd_base)

# Debug limbs on the 32-bit flavours run the suite in ~25-30 minutes by hand (bench_pk_throughput at
# ~3.5 ops/s), past the 300 s default: only the x86 ceiling is raised (Release finishes in ~83 s and
# x64 Debug in ~2 min; coverage is identical in every configuration). x64 gets 900 s: x64 Debug passed the
# 300 s default on a loaded machine (parallel builds).
foreach(_k RANGE 7)
  if(SD_X86)
    set_tests_properties(unit.crypto_pk.${_k} PROPERTIES TIMEOUT 3600)
  else()
    set_tests_properties(unit.crypto_pk.${_k} PROPERTIES TIMEOUT 900)
  endif()
endforeach()

target_include_directories(sd-test-crypto_pk PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../src/sd_crypto"
  "${CMAKE_CURRENT_SOURCE_DIR}/../sd_crypto")
target_compile_definitions(sd-test-crypto_pk PRIVATE
  SD_TEST_VECTORS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../../vectors")
