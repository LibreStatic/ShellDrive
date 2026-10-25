# Unit tests for sd_secret (Credential Manager under a test-only target prefix, DPAPI files, key files).
sd_add_unit_test(secret
  SOURCES main.c test_secret.c
  DEPS sd_secret sd_config sd_base sd_platform)
