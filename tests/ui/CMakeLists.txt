# UI tests (owned by the UI package): unit tests of the WM_COPYDATA codec and the verb grammar, the DPI
# helpers, the dialog templates, the prompt model (answers, server text sanitizing), the profile model, the M3
# models (Logs cursor and filters, host key rows and known_hosts enumeration, Settings and its save path). The
# smoke tests of shelldrive-ui.exe: --test-window (the main window is created hidden, its class and controls are
# checked, and the process exits 0), --test-prompts (every prompt dialog is created hidden and destroyed),
# --test-editor (the profile editor is created hidden and destroyed) and --test-windows (the host key manager,
# Logs, Settings and About windows are created hidden and destroyed). None of them starts an agent, reads the
# user's settings or known_hosts, or leaves a process behind.

set(_ui_dir "${CMAKE_SOURCE_DIR}/apps/shelldrive-ui")

sd_add_unit_test(ui
  SOURCES main.c test_wire.c test_dpi.c test_dlg.c test_prompt.c test_profile.c test_logs.c test_hostkeys.c
          test_settings.c test_notify.c test_dark.c test_wizard.c ${SD_UI_PURE_SOURCES}
  DEPS sd_config sd_crypto sd_ssh sd_platform sd_base)
target_include_directories(sd-test-ui PRIVATE "${_ui_dir}")
add_dependencies(sd-test-ui shelldrive-ui)

add_test(NAME ui.smoke COMMAND $<TARGET_FILE:shelldrive-ui> --test-window)
set_tests_properties(ui.smoke PROPERTIES LABELS ui TIMEOUT 120)

add_test(NAME ui.prompts COMMAND $<TARGET_FILE:shelldrive-ui> --test-prompts)
set_tests_properties(ui.prompts PROPERTIES LABELS ui TIMEOUT 120)

add_test(NAME ui.editor COMMAND $<TARGET_FILE:shelldrive-ui> --test-editor)
set_tests_properties(ui.editor PROPERTIES LABELS ui TIMEOUT 120)

add_test(NAME ui.windows COMMAND $<TARGET_FILE:shelldrive-ui> --test-windows)
set_tests_properties(ui.windows PROPERTIES LABELS ui TIMEOUT 120)

add_test(NAME ui.wizard COMMAND $<TARGET_FILE:shelldrive-ui> --test-wizard)
set_tests_properties(ui.wizard PROPERTIES LABELS ui TIMEOUT 120)

# sd_add_dll fixture: exercises the DLL helper (version resource, import audit, ISA audit) on every flavour.
sd_add_dll(sd-test-ui-fixture
  OUTPUT_NAME sd-test-ui-fixture
  DESCRIPTION "ShellDrive UI test fixture (sd_add_dll)"
  SOURCES fixture_dll.c
  DEPS sd_headers)
set_target_properties(sd-test-ui-fixture PROPERTIES FOLDER "tests")
