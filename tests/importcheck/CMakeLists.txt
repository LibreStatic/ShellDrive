# sd-importcheck self-tests: a fixture that statically imports GetTickCount64 (Vista+) must be
# rejected by the XP floor list, on every flavour.

add_executable(importcheck-fixture-postxp postxp_fixture.c)
set_target_properties(importcheck-fixture-postxp PROPERTIES FOLDER "tests")

add_test(NAME importcheck.detects_post_xp_import
         COMMAND sd-importcheck --floor "${CMAKE_SOURCE_DIR}/tests/os-imports/xp-sp2-x64.txt"
                 "$<TARGET_FILE:importcheck-fixture-postxp>")
set_tests_properties(importcheck.detects_post_xp_import PROPERTIES LABELS importcheck
  PASS_REGULAR_EXPRESSION "kernel32.dll!GetTickCount64 is not on the OS floor list")

# WinSock imports by ordinal (SDK 7.1A on x64-xp) are mapped to names and judged by the flavour's floor
# list by name.
add_executable(importcheck-fixture-winsock winsock_fixture.c)
target_link_libraries(importcheck-fixture-winsock PRIVATE ws2_32)
set_target_properties(importcheck-fixture-winsock PROPERTIES FOLDER "tests")

add_test(NAME importcheck.maps_winsock_ordinals
         COMMAND sd-importcheck --floor "${SD_OS_FLOOR_LIST}"
                 "$<TARGET_FILE:importcheck-fixture-winsock>")
set_tests_properties(importcheck.maps_winsock_ordinals PROPERTIES LABELS importcheck)

add_test(NAME importcheck.lists_winsock_names
         COMMAND sd-importcheck --list "$<TARGET_FILE:importcheck-fixture-winsock>")
set(_ws_list_re "ws2_32.dll!closesocket")
if(SD_XP)
  set(_ws_list_re "ws2_32.dll!closesocket \\(by ordinal #3\\)")
endif()
set_tests_properties(importcheck.lists_winsock_names PROPERTIES LABELS importcheck
  PASS_REGULAR_EXPRESSION "${_ws_list_re}" FAIL_REGULAR_EXPRESSION "ws2_32.dll!#")
