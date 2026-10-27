# sd-admxgen: Group Policy template generator (03 §3.5, 04 §8.6). Build-time tool, never shipped.
# Run by res/policy/CMakeLists.txt; sd-admxgen-test is the unit test (CTest unit.admxgen).

add_executable(sd-admxgen sd-admxgen.c)
set_target_properties(sd-admxgen PROPERTIES FOLDER "tools")

add_executable(sd-admxgen-test test_admxgen.c)
set_target_properties(sd-admxgen-test PROPERTIES FOLDER "tools")
target_compile_definitions(sd-admxgen-test PRIVATE
  "SD_ADMXGEN_TABLE=\"${CMAKE_SOURCE_DIR}/res/policy/policies.txt\""
  "SD_ADMXGEN_PO_DIR=\"${CMAKE_SOURCE_DIR}/l10n/policy\"")
add_test(NAME unit.admxgen COMMAND sd-admxgen-test)
set_tests_properties(unit.admxgen PROPERTIES LABELS unit TIMEOUT 120)
