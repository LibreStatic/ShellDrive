# Shell extension tests (apps/shelldrive-shellext, 03 §1.6, §8.2, §8.5).
#
# sd-test-shellext-dll is the same DLL source built with SD_SHELLEXT_TEST (test hooks: section name override,
# command line log instead of launching). It is not shipped. sd-test-shellext loads it from its own directory
# (bin\), so ctest runs unit.shellext with no arguments.

set(_shx_dir "${CMAKE_SOURCE_DIR}/apps/shelldrive-shellext")

sd_add_dll(sd-test-shellext-dll
  OUTPUT_NAME shelldrive-shellext-test
  DESCRIPTION "ShellDrive shell extension test build (SD_SHELLEXT_TEST)"
  DEF ${_shx_dir}/shelldrive-shellext.def
  SOURCES ${SD_SHELLEXT_SOURCES}
  DEPS sd_ipc sd_l10n sd_l10n_catalog_shell sd_platform sd_base advapi32 ole32 shell32 user32)
target_compile_definitions(sd-test-shellext-dll PRIVATE SD_SHELLEXT_TEST=1)
set_target_properties(sd-test-shellext-dll PROPERTIES FOLDER "tests")

sd_add_unit_test(shellext
  SOURCES test_shellext.c test_shellext_model.c ${_shx_dir}/shellext_snapshot.c ${_shx_dir}/shellext_model.c
  DEPS sd_ipc sd_config sd_platform sd_base advapi32 ole32 shell32 user32)
target_compile_definitions(sd-test-shellext PRIVATE SD_SHELLEXT_TEST=1)
target_include_directories(sd-test-shellext PRIVATE "${_shx_dir}")
add_dependencies(sd-test-shellext sd-test-shellext-dll)
