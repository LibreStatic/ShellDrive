# sd-importcheck: PE import audit against the flavour's OS floor list (04 §2.4). Build-time tool.
# Applied to every shipping executable by sd_add_app (post-build step + CTest "importcheck.*").

add_executable(sd-importcheck sd-importcheck.c)
set_target_properties(sd-importcheck PROPERTIES FOLDER "tools")

# x86 flavours: an image linked /SAFESEH:NO must be rejected by --require-safeseh (04 §3.2).
if(SD_X86)
  add_executable(importcheck-fixture-nosafeseh "${CMAKE_SOURCE_DIR}/tests/importcheck/postxp_fixture.c")
  set_target_properties(importcheck-fixture-nosafeseh PROPERTIES FOLDER "tests" SD_SAFESEH_NO ON)
  add_test(NAME importcheck.detects_missing_safeseh
           COMMAND sd-importcheck --floor "${CMAKE_SOURCE_DIR}/tests/os-imports/xp-sp2-x64.txt" --require-safeseh
                   "$<TARGET_FILE:importcheck-fixture-nosafeseh>")
  set_tests_properties(importcheck.detects_missing_safeseh PROPERTIES LABELS importcheck
    PASS_REGULAR_EXPRESSION "missing /SAFESEH handler table")
endif()
