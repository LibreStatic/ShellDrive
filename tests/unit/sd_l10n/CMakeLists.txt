# Unit tests for the sd_l10n runtime. sd-test-l10n.exe, CTest unit.l10n.
sd_add_unit_test(l10n
  SOURCES main.c test_l10n.c
  DEPS sd_l10n sd_base sd_platform)
