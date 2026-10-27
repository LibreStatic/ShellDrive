/* Mount backend of the test host (sd-test-host-fake.exe): the scripted fake of tests/unit/sd_mount.
 * SHELLDRIVE_TEST_WB_DIRTY=<bytes> reports that much write-behind data queued on every mount (cache.clear
 * refusal tests); the agent reads it when it asks for the backend, so the variable must be set before it starts. */
#include <windows.h>
#include <stdlib.h>

#include "host.h"
#include "fake_backend.h"

const sd_mount_backend *host_backend(void)
{
  wchar_t v[32];
  if (GetEnvironmentVariableW(L"SHELLDRIVE_TEST_WB_DIRTY", v, 32) > 0 && v[0] >= L'0' && v[0] <= L'9')
    fake_backend_set_wb_dirty((UINT64)wcstoull(v, NULL, 10));
  return fake_backend();
}
