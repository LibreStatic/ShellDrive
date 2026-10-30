# sd-isacheck: x86 instruction-set audit and constant-time helper-call gate (04 §2.4, §3.2; 01 §2.7.5;
# TM-R02, TST-03). Build-time tool, never shipped. See sd-isacheck.c for the method.
#
# Wiring:
#   - every sd_add_app executable on x86-ia32 / x86-sse2: post-build ISA audit + CTest isacheck.<exe>
#     (cmake/SdModule.cmake, sd_add_isa_check);
#   - sd_crypto on the x86 flavours and the x64 flavours: the constant-time gate below, as a build step (target
#     sd_crypto_ctcheck, part of ALL) and as CTest isacheck.ct_sd_crypto (Release objects only);
#   - self-tests and negative fixtures below (x86 only, except the selftest).

add_executable(sd-isacheck sd-isacheck.c x86_decode.c x86_decode.h)
target_link_libraries(sd-isacheck PRIVATE dbghelp)
set_target_properties(sd-isacheck PROPERTIES FOLDER "tools")

add_test(NAME isacheck.selftest COMMAND sd-isacheck --selftest)
set_tests_properties(isacheck.selftest PROPERTIES LABELS isacheck)

# Constant-time translation units of sd_crypto (01 §2.4 rule 3): field/scalar arithmetic, bitsliced AES,
# GHASH, ChaCha20-Poly1305, SHA-2/HMAC and the sd_ct_* helpers. Their objects must not reference any
# compiler runtime helper (_allmul, _aullshr, ...). Owned with the crypto agent: a new constant-time
# source is added here (the gate fails when a listed object disappears from the library).
set(SD_CT_SOURCES aes_ct ct curve25519 gcm chacha_poly hash)
list(APPEND SD_CT_SOURCES sha3 mlkem des3 blake2b argon2)   # M2 symmetric/PQ (sources_pq.cmake)
list(APPEND SD_CT_SOURCES bn rsa dh ec_p sha1)              # M2 public key (sources_pk.cmake; dh_gex is public-only)
# M6 hardware fast paths (sources_hw.cmake): built on x86-sse2 and the x64 flavours, never on x86-ia32 or ARM.
set(SD_CT_HW_SOURCES aes_ni sha256_ni)
set(_ct_hw_built 0)
if(SD_X86)
  if(NOT SD_X86_IA32)
    list(APPEND SD_CT_SOURCES ${SD_CT_HW_SOURCES})
    set(_ct_hw_built 1)
  endif()
elseif(SD_ARM64 OR SD_ARM32)
  return()
else()
  # x64 flavours (x64-modern, x64-xp, x64-analysis): the same list as x86, judged in 64-bit mode by the AMD64
  # decoder (M6 round 12), with the hardware objects. Nothing is taken out of SD_CT_SOURCES on x64.
  list(APPEND SD_CT_SOURCES ${SD_CT_HW_SOURCES})
  set(_ct_hw_built 1)
endif()
set(_ct_args --ct-lib "$<TARGET_FILE:sd_crypto>" --config "$<CONFIG>"   # Release only, see sd-isacheck.c
                 --ct-allow "${CMAKE_CURRENT_SOURCE_DIR}/ct-branch-allow.txt")
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
# The gate must see the hardware functions by their constant-time names: the --list report prints every function
# the branch and divide rules judge. A rename back to a name without the convention fails these two tests. Only
# on the flavours that build the hardware objects (x86-sse2 and x64; not x86-ia32, not ARM).
if(_ct_hw_built)
  add_test(NAME isacheck.ct_scans_aes_ni CONFIGURATIONS Release COMMAND sd-isacheck ${_ct_args} --list)
  set_tests_properties(isacheck.ct_scans_aes_ni PROPERTIES LABELS isacheck
    PASS_REGULAR_EXPRESSION "scan aes_ni.obj: sd_aes_ni_encrypt_blocks_ct \\(")
  add_test(NAME isacheck.ct_scans_sha256_ni CONFIGURATIONS Release COMMAND sd-isacheck ${_ct_args} --list)
  set_tests_properties(isacheck.ct_scans_sha256_ni PROPERTIES LABELS isacheck
    PASS_REGULAR_EXPRESSION "scan sha256_ni.obj: sd_sha256_ni_blocks_ct \\(")
endif()
# Negative: a listed object that is not in the library fails the gate (the list cannot go stale unnoticed).
add_test(NAME isacheck.detects_missing_ct_member
         COMMAND sd-isacheck --ct-lib "$<TARGET_FILE:sd_crypto>" --ct-member sd_no_such_module.obj)
set_tests_properties(isacheck.detects_missing_ct_member PROPERTIES LABELS isacheck
  PASS_REGULAR_EXPRESSION "has no member sd_no_such_module.obj")

if(NOT SD_X86)
  return()
endif()
# Negative on the real object: without ct-branch-allow.txt the public-condition branch of sd_aes_sbox_ct is reported,
# so the allow-list entry is load-bearing and the branch rule does scan the constant-time objects of sd_crypto.
add_test(NAME isacheck.detects_ct_branch_without_allow_list CONFIGURATIONS Release
         COMMAND sd-isacheck --ct-lib "$<TARGET_FILE:sd_crypto>" --config Release --ct-member aes_ct.obj)
set_tests_properties(isacheck.detects_ct_branch_without_allow_list PROPERTIES LABELS isacheck
  PASS_REGULAR_EXPRESSION "aes_ct.obj\\): sd_aes_sbox_ct: forward conditional branch")

if(NOT SD_FUZZ)   # ISA and entry-thunk fixtures judge the x86-ia32 release code; ASan and libFuzzer code is not ISA-clean
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

endif()

# Negative fixture for the constant-time gate: 64x64 multiply and a run-time 64-bit shift.
add_library(isacheck-fixture-ct STATIC fixtures/ct_fixture.c)
set_target_properties(isacheck-fixture-ct PROPERTIES FOLDER "tests")
add_test(NAME isacheck.detects_ct_helper_call
         COMMAND sd-isacheck --ct-lib "$<TARGET_FILE:isacheck-fixture-ct>" --ct-member ct_fixture.obj)
set_tests_properties(isacheck.detects_ct_helper_call PROPERTIES LABELS isacheck
  PASS_REGULAR_EXPRESSION "isacheck_fixture_mul64 references compiler runtime helper _allmul")

# Branch and divide rules (01 2.4.1, 2.4.3) on constant-time-named functions: a forward branch on data, and a DIV.
add_test(NAME isacheck.detects_ct_forward_branch
         COMMAND sd-isacheck --ct-lib "$<TARGET_FILE:isacheck-fixture-ct>" --ct-member ct_fixture.obj)
set_tests_properties(isacheck.detects_ct_forward_branch PROPERTIES LABELS isacheck
  PASS_REGULAR_EXPRESSION "isacheck_fixture_ct_branch: forward conditional branch")
add_test(NAME isacheck.detects_ct_div
         COMMAND sd-isacheck --ct-lib "$<TARGET_FILE:isacheck-fixture-ct>" --ct-member ct_fixture.obj)
set_tests_properties(isacheck.detects_ct_div PROPERTIES LABELS isacheck
  PASS_REGULAR_EXPRESSION "isacheck_fixture_ct_div: DIV/IDIV")

if(NOT SD_FUZZ)
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
endif()
