/* sd_mount_backend bound to the real modules (sd_ssh, sd_sftp, sd_vfs, sd_dokan, sd_webdav). Built as its own
 * library (sd_mount_real) so binaries and tests that use fakes never pull these symbols in. */
#include "sd_mount/sd_mount.h"
#include "sd_ssh/sd_keyfile.h"
#include <string.h>

/* M3 adapters: copy what the host needs into the sd_mount types (no pointer outlives the call). */
static void copy_str(char *dst, size_t cap, const char *src)
{
  size_t i = 0;
  if (cap == 0) return;
  if (src) for (; src[i] && i + 1 < cap; i++) dst[i] = src[i];
  dst[i] = 0;
}

static sd_err real_session_probe(sd_sftp_session *s, const char *remote, uint32_t timeout_ms, sd_mount_probe *out)
{
  sd_sftp_server_info info;
  char home[1024];
  sd_err e;
  e = sd_sftp_session_info(s, &info, home, sizeof(home));
  if (e != SD_OK)
    return e;
  if (info.ssh) {
    copy_str(out->kex, sizeof(out->kex), info.ssh->kex);
    copy_str(out->hostkey, sizeof(out->hostkey), info.ssh->hostkey);
    copy_str(out->cipher_c2s, sizeof(out->cipher_c2s), info.ssh->cipher_c2s);
    copy_str(out->cipher_s2c, sizeof(out->cipher_s2c), info.ssh->cipher_s2c);
    copy_str(out->mac_c2s, sizeof(out->mac_c2s), info.ssh->mac_c2s);
    copy_str(out->mac_s2c, sizeof(out->mac_s2c), info.ssh->mac_s2c);
    copy_str(out->hostkey_fp, sizeof(out->hostkey_fp), info.ssh->hostkey_fp_sha256);
    copy_str(out->server_version, sizeof(out->server_version), info.ssh->server_version);
  }
  return sd_sftp_realpath_sync(s, (remote && remote[0]) ? remote : ".", out->remote_real, sizeof(out->remote_real),
                               timeout_ms);
}

static void real_session_stats(const sd_sftp_session *s, sd_mount_stats *out)
{
  sd_sftp_stats st;
  memset(&st, 0, sizeof(st));
  if (sd_sftp_session_stats(s, &st) != SD_OK)
    return;
  out->srtt_ms = st.total.srtt_ms;
  out->rttvar_ms = st.total.rttvar_ms;
  out->rx_bps = st.total.rx_bps;
  out->tx_bps = st.total.tx_bps;
  out->rx_total = st.total.rx_total;
  out->tx_total = st.total.tx_total;
  out->inflight = st.total.inflight_reqs;
  out->queued = st.total.queued_reqs;
  out->channels = st.channels;
  out->generation = st.generation;
  out->reconnect_attempts = st.reconnect_attempts;
  out->members = st.conn_count > 4 ? 4 : st.conn_count;
  {
    uint32_t i;
    for (i = 0; i < out->members; i++) {
      out->member[i].ready = st.conn[i].ready;
      out->member[i].srtt_ms = st.conn[i].srtt_ms;
      out->member[i].inflight = st.conn[i].inflight_reqs;
      out->member[i].queued = st.conn[i].queued_reqs;
      out->member[i].rx_total = st.conn[i].rx_total;
      out->member[i].tx_total = st.conn[i].tx_total;
    }
  }
}

static void real_vfs_stats(sd_vfs *v, sd_mount_stats *out)
{
  sd_vfs_stats vs;
  memset(&vs, 0, sizeof(vs));
  sd_vfs_get_stats(v, &vs);
  out->cache_hits = vs.cache_hits;
  out->cache_misses = vs.cache_misses;
  out->bytes_rd = vs.bytes_rd;
  out->bytes_wr = vs.bytes_wr;
  out->write_failed = vs.write_failed;
  out->reconnects = vs.reconnects;
}

/* hostkey add (03 §6.1): not built. sd_ssh reports SSH_ST_CONNECTED only after user authentication, and the
   hostkey add command has no credentials yet (docs/dev/m5-notes.md, Part 6, open items). Until that exists the
   connect answers SD_E_UNSUPPORTED and nothing is read or stored. */
static sd_err real_hostkeys_fetch(const char *host, uint16_t port, const char *type, sd_mount_hk_fetch *out)
{
  SD_UNUSED(host); SD_UNUSED(port); SD_UNUSED(type);
  out->verified = 0;
  out->count = 0;
  return SD_E_UNSUPPORTED;
}

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
  sd_prompt_answer_ex,
  sd_prompt_answer_ack,
  sd_known_hosts_apply_hostkeys,
  sd_ssh_key_dpapi_unprotect,
  real_session_probe,
  real_session_stats,
  real_vfs_stats,
  sd_vfs_refresh,
  sd_vfs_cache_clear,
  sd_vfs_write_behind_bytes,
  sd_webdav_mount_port,
  real_hostkeys_fetch,
};

const sd_mount_backend *sd_mount_backend_real(void)
{
  return &k_real;
}
