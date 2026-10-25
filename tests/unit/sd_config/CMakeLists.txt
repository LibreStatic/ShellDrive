# Unit tests for sd_config (sd_ini grammar, profile model, profile files). sd-test-config.exe, unit.config.
sd_add_unit_test(config
  SOURCES main.c test_config.c
  DEPS sd_config sd_base sd_platform)
