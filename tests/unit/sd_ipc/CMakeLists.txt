# Unit tests for sd_ipc and sd_json (the sd_json implementation, src/sd_base/json.c, is owned by
# the sd_ipc agent; its tests live here). Executable sd-test-ipc.exe, CTest unit.ipc.
sd_add_unit_test(ipc
  SOURCES main.c test_json.c test_ipc.c
  DEPS sd_ipc sd_base sd_platform advapi32)
