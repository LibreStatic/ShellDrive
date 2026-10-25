/* Mount backend used while the SSH/SFTP/VFS/Dokany modules are not built yet (M0 bring-up): every
 * mount fails cleanly with SD_E_UNSUPPORTED instead of the host failing to link. */
#include "host.h"

static sd_err u_err(void) { return SD_E_UNSUPPORTED; }
static sd_err u_kh_open(const sd_kh_store *s, uint32_t n, sd_known_hosts **out)
{
  SD_UNUSED(s); SD_UNUSED(n);
  *out = NULL;
  return SD_E_UNSUPPORTED;
}
static void u_kh_close(sd_known_hosts *kh) { SD_UNUSED(kh); }
static sd_err u_session_create(const sd_ssh_config *a, const sd_ssh_callbacks *b, const sd_sftp_options *c,
                               sd_sftp_event_cb d, void *e, sd_sftp_session **out)
{
  SD_UNUSED(a); SD_UNUSED(b); SD_UNUSED(c); SD_UNUSED(d); SD_UNUSED(e);
  *out = NULL;
  return SD_E_UNSUPPORTED;
}
static sd_err u_session(sd_sftp_session *s) { SD_UNUSED(s); return SD_E_UNSUPPORTED; }
static void u_session_destroy(sd_sftp_session *s) { SD_UNUSED(s); }
static sd_err u_answer(sd_prompt *p, uint32_t n, const char *const *r) { SD_UNUSED(p); SD_UNUSED(n); SD_UNUSED(r); return SD_E_UNSUPPORTED; }
static sd_err u_answer_hk(sd_prompt *p, sd_hostkey_decision d) { SD_UNUSED(p); SD_UNUSED(d); return SD_E_UNSUPPORTED; }
static sd_err u_cancel(sd_prompt *p) { SD_UNUSED(p); return SD_E_UNSUPPORTED; }
static sd_vfs_status u_vfs_mount(sd_sftp_session *s, const sd_vfs_options *o, sd_vfs_event_cb cb, void *ctx, sd_vfs **out)
{
  SD_UNUSED(s); SD_UNUSED(o); SD_UNUSED(cb); SD_UNUSED(ctx);
  *out = NULL;
  return SD_VFS_E_UNSUPPORTED;
}
static void u_vfs_quiesce(sd_vfs *v, DWORD b) { SD_UNUSED(v); SD_UNUSED(b); }
static void u_vfs_unmount(sd_vfs *v) { SD_UNUSED(v); }
static sd_dokan_avail u_probe(const sd_dokan_deny *d, sd_dokan_probe_info *i)
{
  SD_UNUSED(d);
  if (i) i->avail = SD_DOKAN_NOT_INSTALLED;
  return SD_DOKAN_NOT_INSTALLED;
}
static sd_err u_dokan_start(sd_vfs *v, const sd_dokan_mount_cfg *c, sd_dokan_unmounted_cb cb, void *ctx, sd_dokan_mount **out)
{
  SD_UNUSED(v); SD_UNUSED(c); SD_UNUSED(cb); SD_UNUSED(ctx);
  *out = NULL;
  return SD_E_UNSUPPORTED;
}
static sd_err u_dokan_stop(sd_dokan_mount *m) { SD_UNUSED(m); return SD_E_UNSUPPORTED; }

static const sd_mount_backend k_unavailable = {
  "unavailable", u_err, u_kh_open, u_kh_close, u_session_create, u_session, u_session, u_session_destroy,
  u_answer, u_answer_hk, u_cancel, u_vfs_mount, u_vfs_quiesce, u_vfs_unmount, u_probe, u_dokan_start,
  u_dokan_stop,
};

const sd_mount_backend *host_backend(void)
{
  return &k_unavailable;
}
