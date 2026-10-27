# Unit tests for the sd_policy reader. sd-test-policy.exe, CTest unit.policy.
sd_add_unit_test(policy
  SOURCES main.c test_policy.c
  DEPS sd_policy sd_base)
