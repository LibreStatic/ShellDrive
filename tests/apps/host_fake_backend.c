/* Mount backend of the test host (sd-test-host-fake.exe): the scripted fake of tests/unit/sd_mount. */
#include "host.h"
#include "fake_backend.h"

const sd_mount_backend *host_backend(void)
{
  return fake_backend();
}
