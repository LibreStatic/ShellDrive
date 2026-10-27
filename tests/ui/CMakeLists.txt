# UI tests (owned by the UI package): unit tests of the WM_COPYDATA codec and the verb grammar, the DPI
# helpers, and the smoke test of shelldrive-ui.exe (--test-window: the main window is created hidden, its
# class and controls are checked, and the process exits 0).

set(_ui_dir "${CMAKE_SOURCE_DIR}/apps/shelldrive-ui")

sd_add_unit_test(ui
  SOURCES main.c test_wire.c test_dpi.c ${SD_UI_PURE_SOURCES}
  DEPS sd_platform sd_base)
target_include_directories(sd-test-ui PRIVATE "${_ui_dir}")
add_dependencies(sd-test-ui shelldrive-ui)

add_test(NAME ui.smoke COMMAND $<TARGET_FILE:shelldrive-ui> --test-window)
set_tests_properties(ui.smoke PROPERTIES LABELS ui TIMEOUT 120)

# sd_add_dll fixture: exercises the DLL helper (version resource, import audit, ISA audit) on every flavour.
sd_add_dll(sd-test-ui-fixture
  OUTPUT_NAME sd-test-ui-fixture
  DESCRIPTION "ShellDrive UI test fixture (sd_add_dll)"
  SOURCES fixture_dll.c
  DEPS sd_headers)
set_target_properties(sd-test-ui-fixture PROPERTIES FOLDER "tests")
