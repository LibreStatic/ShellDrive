# shelldrive-ui.exe: tray icon, main window (03 §1.4, §7) and prompt dialogs (03 §2.5). GUI subsystem,
# comctl32 v6 and DPI awareness come from sd_add_app WINDOWS (cmake/SdModule.cmake).
#
# ui_wire.c, ui_dpi.c, ui_dlg.c and ui_prompt_model.c are pure (no window, IPC or agent code): they are also
# compiled into the unit tests (tests/ui) through SD_UI_PURE_SOURCES.

set(SD_UI_PURE_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/ui_wire.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ui_dpi.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ui_dlg.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ui_prompt_model.c)
set(SD_UI_PURE_SOURCES ${SD_UI_PURE_SOURCES} PARENT_SCOPE)

sd_add_app(shelldrive-ui
  OUTPUT_NAME shelldrive-ui
  DESCRIPTION "ShellDrive tray, main window and prompts"
  WINDOWS
  SOURCES
    main.c
    ui_icon.c
    ui_ipc.c
    ui_main.c
    ui_model.c
    ui_prompt.c
    ui_tray.c
    ui_int.h
    ui_wire.h
    ui_dpi.h
    ui_dlg.h
    ui_prompt_model.h
    ${SD_UI_PURE_SOURCES}
  DEPS sd_ipc sd_l10n sd_l10n_catalog_ui sd_platform sd_base comctl32)
