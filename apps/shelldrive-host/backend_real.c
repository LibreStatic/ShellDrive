/* Mount backend of the shipping host when the real SSH/SFTP/VFS/Dokany modules are built. */
#include "host.h"

const sd_mount_backend *host_backend(void)
{
  return sd_mount_backend_real();
}
