# sd-isacheck: x86 instruction-set audit and constant-time helper-call gate (04 §2.4, §3.2; 01 §2.7.5;
# TM-R02, TST-03). Build-time tool, never shipped. See sd-isacheck.c for the method.
#
# Wiring:
#   - every sd_add_app executable on x86-ia32 / x86-sse2: post-build ISA audit + CTest isacheck.<exe>
#     (cmake/SdModule.cmake, sd_add_isa_check);
#   - sd_crypto on both x86 flavours: the constant-time gate below, as a build step (target
#     sd_crypto_ctcheck, part of ALL) and as CTest isacheck.ct_sd_crypto;
#   - self-tests and negative fixtures below.

add_executable(sd-isacheck sd-isacheck.c x86_decode.c x86_decode.h)
target_link_libraries(sd-isacheck PRIVATE dbghelp)
set_target_properties(sd-isacheck PROPERTIES FOLDER "tools")

add_test(NAME isacheck.selftest COMMAND sd-isacheck --selftest)
set_tests_properties(isacheck.selftest PROPERTIES LABELS isacheck)

if(NOT SD_X86)
  return()
endif()

# Constant-time translation units of sd_crypto (01 §2.4 rule 3): field/scalar arithmetic, bitsliced AES,
# GHASH, ChaCha20-Poly1305, SHA-2/HMAC and the sd_ct_* helpers. Their objects must not reference any
# compiler runtime helper (_allmul, _aullshr, ...). Owned with the crypto agent: a new constant-time
# source is added here (the gate fails when a listed object disappears from the library).
set(SD_CT_SOURCES aes_ct ct curve25519 gcm chacha_poly hash)
list(APPEND SD_CT_SOURCES sha3 mlkem des3 blake2b argon2)   # M2 symmetric/PQ (sources_pq.cmake)
list(APPEND SD_CT_SOURCES bn rsa dh ec_p sha1)              # M2 public key (sources_pk.cmake; dh_gex is public-only)
set(_ct_args --ct-lib "$<TARGET_FILE:sd_crypto>" --config "$<CONFIG>")   # Release only, see sd-isacheck.c
foreach(_s IN LISTS SD_CT_SOURCES)
  list(APPEND _ct_args --ct-member "${_s}.obj")
endforeach()
set(_ct_stamp "${CMAKE_CURRENT_BINARY_DIR}/sd_crypto_ctcheck_$<CONFIG>.stamp")
add_custom_command(OUTPUT "${_ct_stamp}"
  COMMAND "$<TARGET_FILE:sd-isacheck>" ${_ct_args}
  COMMAND "${CMAKE_COMMAND}" -E touch "${_ct_stamp}"
  DEPENDS sd-isacheck sd_crypto "$<TARGET_FILE:sd_crypto>"
  COMMENT "Constant-time helper-call gate of sd_crypto (${SD_FLAVOUR})" VERBATIM)
add_custom_target(sd_crypto_ctcheck ALL DEPENDS "${_ct_stamp}")
set_target_properties(sd_crypto_ctcheck PROPERTIES FOLDER "checks")
add_test(NAME isacheck.ct_sd_crypto COMMAND sd-isacheck ${_ct_args})
set_tests_properties(isacheck.ct_sd_crypto PROPERTIES LABELS isacheck)

# Negative fixture for the ISA audit: one function compiled /arch:SSE2 with SSE2 intrinsics.
add_executable(isacheck-fixture-sse2 fixtures/sse2_fixture.c)
set_target_properties(isacheck-fixture-sse2 PROPERTIES FOLDER "tests" SD_X86_ARCH_OVERRIDE SSE2)
add_test(NAME isacheck.detects_sse2 COMMAND sd-isacheck --floor ia32 "$<TARGET_FILE:isacheck-fixture-sse2>")
set_tests_properties(isacheck.detects_sse2 PROPERTIES LABELS isacheck
  PASS_REGULAR_EXPRESSION "SSE2 instruction in isacheck_fixture_sse2_add")
# The same image passes on the sse2 floor (the fixture uses nothing newer).
add_test(NAME isacheck.sse2_floor_accepts_sse2
         COMMAND sd-isacheck --floor sse2 --allow "${CMAKE_CURRENT_SOURCE_DIR}/crt-allow.txt"
                 "$<TARGET_FILE:isacheck-fixture-sse2>")
set_tests_properties(isacheck.sse2_floor_accepts_sse2 PROPERTIES LABELS isacheck)

# Negative fixture for the constant-time gate: 64x64 multiply and a run-time 64-bit shift.
add_library(isacheck-fixture-ct STATIC fixtures/ct_fixture.c)
set_target_properties(isacheck-fixture-ct PROPERTIES FOLDER "tests")
add_test(NAME isacheck.detects_ct_helper_call
         COMMAND sd-isacheck --ct-lib "$<TARGET_FILE:isacheck-fixture-ct>" --ct-member ct_fixture.obj)
set_tests_properties(isacheck.detects_ct_helper_call PROPERTIES LABELS isacheck
  PASS_REGULAR_EXPRESSION "isacheck_fixture_mul64 references compiler runtime helper _allmul")

# Entry-thunk fixture (x86-sse2 thunk, built on both x86 flavours): with the non-shipping test hook the
# refusal path runs on any CPU; without it the program starts normally.
add_executable(cpucheck-fixture fixtures/cpucheck_fixture.c "${CMAKE_SOURCE_DIR}/src/sd_platform/entry/sd_cpucheck.c")
set_source_files_properties("${CMAKE_SOURCE_DIR}/src/sd_platform/entry/sd_cpucheck.c" DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
  PROPERTIES COMPILE_DEFINITIONS SD_CPUCHECK_TEST_HOOK=1)
set_target_properties(cpucheck-fixture PROPERTIES FOLDER "tests" SD_X86_ARCH_OVERRIDE IA32)
target_link_options(cpucheck-fixture PRIVATE /ENTRY:sd_cpucheck_entry "/SUBSYSTEM:CONSOLE,${SD_SUBSYSTEM_VERSION}")
add_test(NAME cpucheck.refuses_without_sse2
         COMMAND "${CMAKE_COMMAND}" "-DFIXTURE=$<TARGET_FILE:cpucheck-fixture>"
                 -P "${CMAKE_CURRENT_SOURCE_DIR}/expect_refusal.cmake")
set_tests_properties(cpucheck.refuses_without_sse2 PROPERTIES LABELS isacheck ENVIRONMENT "LANG=C")
add_test(NAME cpucheck.starts_with_sse2 COMMAND cpucheck-fixture)
set_tests_properties(cpucheck.starts_with_sse2 PROPERTIES LABELS isacheck
  PASS_REGULAR_EXPRESSION "cpucheck fixture ran")
add_test(NAME isacheck.entry_thunk_is_ia32
         COMMAND sd-isacheck --floor sse2 --allow "${CMAKE_CURRENT_SOURCE_DIR}/crt-allow.txt"
                 --entry sd_cpucheck_entry "$<TARGET_FILE:cpucheck-fixture>")
set_tests_properties(isacheck.entry_thunk_is_ia32 PROPERTIES LABELS isacheck)
