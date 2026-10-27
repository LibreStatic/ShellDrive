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

sd_add_app(shelldrive-host
  OUTPUT_NAME shelldrive-host
  DESCRIPTION "ShellDrive agent and service host"
  SOURCES main.c ${SD_HOST_AGENT_SOURCES} ${_backend}
  DEPS sd_mount ${_backend_lib} sd_ipc sd_state sd_secret sd_config sd_update sd_platform sd_base
       ole32 shell32 user32)
