# shelldrive-host.exe (agent + service, D3). Owned by the host agent. Console subsystem for M0
# (console prompts); the service mode does not need a console.

sd_add_app(shelldrive-host
  OUTPUT_NAME shelldrive-host
  DESCRIPTION "ShellDrive agent and service host"
  SOURCES main.c
  DEPS sd_platform sd_base)
