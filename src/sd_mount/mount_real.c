/* sd_mount_backend bound to the real modules (sd_ssh, sd_sftp, sd_vfs, sd_dokan, sd_webdav). Built as its own
 * library (sd_mount_real) so binaries and tests that use fakes never pull these symbols in. */
#include "sd_mount/sd_mount.h"

static const sd_mount_backend k_real = {
  "real",
  sd_ssh_global_init,
  sd_known_hosts_open,
  sd_known_hosts_close,
  sd_sftp_session_create,
  sd_sftp_session_start,
  sd_sftp_session_close,
  sd_sftp_session_destroy,
  sd_prompt_answer,
  sd_prompt_answer_hostkey,
  sd_prompt_cancel,
  sd_vfs_mount,
  sd_vfs_quiesce,
  sd_vfs_unmount,
  sd_dokan_probe,
  sd_dokan_mount_start,
  sd_dokan_mount_stop,
  sd_webdav_query_client,
  sd_webdav_ensure_client,
  sd_webdav_mount_start,
  sd_webdav_mount_stop,
  sd_webdav_cleanup_mappings,
  sd_vfs_cache_set_budget,
  sd_vfs_get_identity,
  sd_webdav_emergency_unmap,
};

const sd_mount_backend *sd_mount_backend_real(void)
{
  return &k_real;
}
