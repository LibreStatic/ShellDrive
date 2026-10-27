# sd_state unit tests (03 §8.2.1). Executable sd-test-state.exe, CTest unit.state.
sd_add_unit_test(state
  SOURCES main.c test_state.c
  DEPS sd_state sd_ipc sd_base sd_platform advapi32)
