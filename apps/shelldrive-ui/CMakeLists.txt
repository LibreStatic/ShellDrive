# shelldrive-ui.exe: tray icon, main window (03 §1.4, §7) and prompt dialogs (03 §2.5). GUI subsystem,
# comctl32 v6 and DPI awareness come from sd_add_app WINDOWS (cmake/SdModule.cmake).
#
# ui_wire.c, ui_dpi.c, ui_dlg.c, ui_prompt_model.c, ui_sdmount.c and ui_profile_model.c are pure (no window, IPC or
# agent code): they are also compiled into the unit tests (tests/ui) through SD_UI_PURE_SOURCES. The profile editor
# (ui_editor.c) and the profile list (ui_profiles.c) link sd_config directly (03 §2.4 decision).

set(SD_UI_PURE_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/ui_wire.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ui_dpi.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ui_dlg.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ui_prompt_model.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ui_sdmount.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ui_profile_model.c)
set(SD_UI_PURE_SOURCES ${SD_UI_PURE_SOURCES} PARENT_SCOPE)

sd_add_app(shelldrive-ui
  OUTPUT_NAME shelldrive-ui
  DESCRIPTION "ShellDrive tray, main window, profile editor and prompts"
  WINDOWS
  SOURCES
    main.c
    ui_editor.c
    ui_icon.c
    ui_import.c
    ui_ipc.c
    ui_main.c
    ui_measure.c
    ui_model.c
    ui_profiles.c
    ui_prompt.c
    ui_tray.c
    ui_int.h
    ui_wire.h
    ui_dpi.h
    ui_dlg.h
    ui_measure.h
    ui_prompt_model.h
    ui_profile_model.h
    ui_sdmount.h
    ${SD_UI_PURE_SOURCES}
  DEPS sd_ipc sd_config sd_crypto sd_l10n sd_l10n_catalog_ui sd_platform sd_base comctl32 comdlg32 shell32)
