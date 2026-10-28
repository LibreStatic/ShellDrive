# shelldrive-host.exe (agent + service, D3). Owned by the host agent. Console subsystem for M0
# (console prompts); the service mode does not need a console.
#
# tests/apps builds the same agent sources against the scripted fake backend (sd-test-host-fake.exe)
# without touching the shipping binary.

set(SD_HOST_AGENT_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/agent.c
  ${CMAKE_CURRENT_SOURCE_DIR}/log_ring.c
  ${CMAKE_CURRENT_SOURCE_DIR}/log_ring.h
  ${CMAKE_CURRENT_SOURCE_DIR}/state_producer.c
  ${CMAKE_CURRENT_SOURCE_DIR}/state_producer.h
  ${CMAKE_CURRENT_SOURCE_DIR}/explorer_data.c
  ${CMAKE_CURRENT_SOURCE_DIR}/explorer_data.h
  ${CMAKE_CURRENT_SOURCE_DIR}/config_watch.c
  ${CMAKE_CURRENT_SOURCE_DIR}/update_ipc.c
  ${CMAKE_CURRENT_SOURCE_DIR}/update_ipc.h
  ${CMAKE_CURRENT_SOURCE_DIR}/config_watch.h
  ${CMAKE_CURRENT_SOURCE_DIR}/host.h)

if(SD_HOST_REAL_BACKEND)
  set(_backend backend_real.c)
  set(_backend_lib sd_mount_real)
else()
  set(_backend backend_unavailable.c)
  set(_backend_lib "")
endif()

# Event Log message table (03 §10.3, English only): svc_events.mc is compiled by mc.exe, which ships with the Windows
# SDK next to the rc.exe of the active toolset. The generated header (message ids) is shared with the unit tests;
# the generated resource script is linked into shelldrive-host.exe, which is also the event message file.
set(_svc_mc_hints "$ENV{WindowsSdkVerBinPath}x64" "$ENV{WindowsSdkBinPath}")
if(CMAKE_RC_COMPILER)
  get_filename_component(_svc_tool_dir "${CMAKE_RC_COMPILER}" DIRECTORY)
  list(APPEND _svc_mc_hints "${_svc_tool_dir}")
endif()
set(_svc_pf86 "$ENV{SystemDrive}/Program Files (x86)")
list(APPEND _svc_mc_hints
  "${_svc_pf86}/Windows Kits/10/bin/${CMAKE_SYSTEM_VERSION}/x64"
  "${_svc_pf86}/Windows Kits/10/bin/${CMAKE_SYSTEM_VERSION}/x86"
  "${_svc_pf86}/Microsoft SDKs/Windows/v7.1A/Bin")
find_program(SD_MC_EXE NAMES mc mc.exe HINTS ${_svc_mc_hints})
if(NOT SD_MC_EXE)
  message(FATAL_ERROR "mc.exe was not found (Windows SDK): the Event Log message table of shelldrive-host cannot be built")
endif()
set(SD_SVC_EVENTS_DIR "${SD_GENERATED_DIR}/svc_events/$<CONFIG>")
add_custom_command(
  OUTPUT "${SD_SVC_EVENTS_DIR}/svc_events.h" "${SD_SVC_EVENTS_DIR}/svc_events.rc" "${SD_SVC_EVENTS_DIR}/MSG00409.bin"
  COMMAND "${CMAKE_COMMAND}" -E make_directory "${SD_SVC_EVENTS_DIR}"
  COMMAND "${SD_MC_EXE}" -h "${SD_SVC_EVENTS_DIR}" -r "${SD_SVC_EVENTS_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/svc_events.mc"
  DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/svc_events.mc"
  COMMENT "mc: Event Log message table of shelldrive-host"
  VERBATIM)
add_custom_target(sd_svc_events DEPENDS "${SD_SVC_EVENTS_DIR}/svc_events.h" "${SD_SVC_EVENTS_DIR}/svc_events.rc")
set_target_properties(sd_svc_events PROPERTIES FOLDER "apps")

sd_add_app(shelldrive-host
  OUTPUT_NAME shelldrive-host
  DESCRIPTION "ShellDrive agent and service host"
  SOURCES main.c ${SD_HOST_AGENT_SOURCES} ${_backend} ${CMAKE_CURRENT_SOURCE_DIR}/installer_hooks.c
          ${CMAKE_CURRENT_SOURCE_DIR}/service.c ${CMAKE_CURRENT_SOURCE_DIR}/service.h
          ${CMAKE_CURRENT_SOURCE_DIR}/svc_access.c ${CMAKE_CURRENT_SOURCE_DIR}/svc_access.h
          ${CMAKE_CURRENT_SOURCE_DIR}/svc_folder.c ${CMAKE_CURRENT_SOURCE_DIR}/svc_folder.h
          ${CMAKE_CURRENT_SOURCE_DIR}/svc_scm.c ${CMAKE_CURRENT_SOURCE_DIR}/svc_scm.h
          ${CMAKE_CURRENT_SOURCE_DIR}/svc_repair.c ${CMAKE_CURRENT_SOURCE_DIR}/svc_repair.h
          ${CMAKE_CURRENT_SOURCE_DIR}/svc_status.c ${CMAKE_CURRENT_SOURCE_DIR}/svc_status.h
          "${SD_SVC_EVENTS_DIR}/svc_events.rc"
  DEPS sd_mount ${_backend_lib} sd_ipc sd_state sd_secret sd_config sd_update sd_policy sd_platform sd_base
       sd_l10n sd_l10n_catalog_svc ole32 shell32 user32 advapi32)
target_include_directories(shelldrive-host PRIVATE "${SD_SVC_EVENTS_DIR}")
add_dependencies(shelldrive-host sd_svc_events)
