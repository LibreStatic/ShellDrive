# Unit tests for sd_config (sd_ini grammar, profile model, profile files, M2 keys, chains, importers).
# sd-test-config.exe, unit.config. Importer fixtures: fixtures/ (a UTF-16LE regedit export and an
# ssh_config); the PuTTY registry test writes its own key under HKCU\Software\LibreStatic.
# test_config_menucache.c: menu.cache names, format, caps and the writer through the profile store (03 §8.2.2).
sd_add_unit_test(config
  SOURCES main.c test_config.c test_config_m2.c test_config_m3.c test_config_menucache.c test_config_m4.c test_config_templates.c
  DEPS sd_config sd_base sd_platform)
target_compile_definitions(sd-test-config PRIVATE SD_CONFIG_TEST_FIXTURES="${CMAKE_CURRENT_SOURCE_DIR}/fixtures")
