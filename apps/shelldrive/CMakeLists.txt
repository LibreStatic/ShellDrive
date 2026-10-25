# shelldrive.exe (CLI). Owned by the apps agent.

sd_add_app(shelldrive
  OUTPUT_NAME shelldrive
  DESCRIPTION "ShellDrive command-line interface"
  SOURCES main.c
  DEPS sd_platform sd_base sd_l10n_catalog_cli)
