/* Entry-thunk fixture: linked with sd_cpucheck.c (SD_CPUCHECK_TEST_HOOK) and /ENTRY:sd_cpucheck_entry. */
#include <stdio.h>
#include <wchar.h>

int wmain(void)
{
  printf("cpucheck fixture ran\n");
  return 0;
}
