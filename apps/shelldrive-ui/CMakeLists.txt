# shelldrive-ui.exe: tray icon, main window (03 §1.4, §7), prompt dialogs (03 §2.5), the profile editor, quick
# mount and import, and the M3 windows: host key manager, Logs viewer, Settings and About (03 §5, §10, §3.2;
# ui_win.h). GUI subsystem, comctl32 v6 and DPI awareness come from sd_add_app WINDOWS (cmake/SdModule.cmake).
#
# ui_wire.c, ui_dpi.c, ui_dlg.c, ui_prompt_model.c, ui_sdmount.c, ui_profile_model.c, ui_logs_model.c,
# ui_hostkeys_model.c, ui_settings_model.c, ui_hkissue_model.c and ui_mainview_model.c are pure (no window, IPC or agent code): they are also compiled into
# the unit tests (tests/ui) through SD_UI_PURE_SOURCES. The profile editor (ui_editor.c) and the profile list
# (ui_profiles.c) link sd_config directly (03 §2.4 decision).

set(SD_UI_PURE_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/ui_wire.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ui_dpi.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ui_dlg.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ui_prompt_model.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ui_sdmount.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ui_profile_model.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ui_logs_model.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ui_hostkeys_model.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ui_settings_model.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ui_update_model.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ui_notify_model.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ui_theme_model.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ui_wizard_model.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ui_admin_model.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ui_service_model.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ui_hkissue_model.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ui_events_model.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ui_mainview_model.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ui_notice_model.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ui_evhist_model.c
  ${CMAKE_CURRENT_SOURCE_DIR}/ui_taskdlg_model.c)
set(SD_UI_PURE_SOURCES ${SD_UI_PURE_SOURCES} PARENT_SCOPE)

# Icon resources (res/icons): the template gets the absolute icon directory (rc.exe does not search the
# source tree for relative paths).
set(SD_UI_ICON_DIR "${CMAKE_SOURCE_DIR}/res/icons")
configure_file("${CMAKE_SOURCE_DIR}/res/icons/shelldrive-ui.rc.in"
               "${CMAKE_CURRENT_BINARY_DIR}/shelldrive-ui-icons.rc" @ONLY)

set(_svc_host_dir "${CMAKE_SOURCE_DIR}/apps/shelldrive-host")

sd_add_app(shelldrive-ui
  OUTPUT_NAME shelldrive-ui
  DESCRIPTION "ShellDrive tray, main window, profile editor, prompts and the M3 windows"
  WINDOWS
  SOURCES
    main.c
    ui_about.c
    ui_editor.c
    ui_hostkeys.c
    ui_events.c
    ui_flyout.c
    ui_hkissue.c
    ui_icon.c
    ui_import.c
    ui_ipc.c
    ui_logs.c
    ui_main.c
    ui_measure.c
    ui_model.c
    ui_profiles.c
    ui_prompt.c
    ui_service.c
    ui_secdlg.c
    ui_settings.c
    ui_svc.c
    ui_update.c
    ui_tray.c
    ui_win.c
    ui_theme.c
    ui_wizard.c
    ui_flyout.h
    ui_int.h
    ui_res.h
    ui_theme.h
    ui_wizard.h
    ui_notify_model.h
    ui_theme_model.h
    ui_wizard_model.h
    ui_win.h
    ui_wire.h
    ui_dpi.h
    ui_dlg.h
    ui_measure.h
    ui_prompt_model.h
    ui_taskdlg_model.h
    ui_profile_model.h
    ui_sdmount.h
    ui_hostkeys_model.h
    ui_logs_model.h
    ui_settings_model.h
    ui_update.h
    ui_update_model.h
    ui_admin_model.h
    ui_service_model.h
    ui_hkissue_model.h
    ui_mainview_model.h
    ui_events_model.h
    ${CMAKE_CURRENT_BINARY_DIR}/shelldrive-ui-icons.rc
    # the Service page (03 §1.3): the SCM status and the data folder repair are the code of the CLI verbs
    # `service status` and `service repair-data` (shared with shelldrive.exe and the service host)
    ${_svc_host_dir}/svc_scm.c
    ${_svc_host_dir}/svc_scm.h
    ${_svc_host_dir}/svc_repair.c
    ${_svc_host_dir}/svc_repair.h
    ${_svc_host_dir}/svc_folder.c
    ${_svc_host_dir}/svc_folder.h
    ${SD_UI_PURE_SOURCES}
  DEPS sd_ipc sd_config sd_crypto sd_ssh sd_webdav sd_policy sd_l10n sd_l10n_catalog_ui sd_platform sd_base comctl32 comdlg32 shell32
       advapi32)
target_include_directories(shelldrive-ui PRIVATE "${_svc_host_dir}")
