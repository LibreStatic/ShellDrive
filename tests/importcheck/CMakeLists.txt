# sd-importcheck self-tests: a fixture that statically imports GetTickCount64 (Vista+) must be
# rejected by the XP floor list, on every flavour.

add_executable(importcheck-fixture-postxp postxp_fixture.c)
set_target_properties(importcheck-fixture-postxp PROPERTIES FOLDER "tests")

add_test(NAME importcheck.detects_post_xp_import
         COMMAND sd-importcheck --floor "${CMAKE_SOURCE_DIR}/tests/os-imports/xp-sp2-x64.txt"
                 "$<TARGET_FILE:importcheck-fixture-postxp>")
set_tests_properties(importcheck.detects_post_xp_import PROPERTIES LABELS importcheck
  PASS_REGULAR_EXPRESSION "kernel32.dll!GetTickCount64 is not on the OS floor list")
