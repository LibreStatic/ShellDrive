/* Scripted fake of sd_ssh/sd_sftp/sd_vfs/sd_dokan for sd_mount and host tests (no network).
 *
 * Behavior is chosen by the host name of the mount:
 *   "unreachable*"  -> SD_E_CONN_REFUSED
 *   "mismatch*"     -> host key mismatch event, then SD_E_HOSTKEY_MISMATCH
 *   anything else   -> TOFU prompt unless the host was trusted before (process-wide fake store),
 *                      then authentication: identity path containing "encrypted" asks a passphrase
 *                      ("pass"), another identity succeeds silently, no identity asks a password
 *                      ("secret", two rounds, then SD_E_AUTH_FAILED); "nodokany*" fails the
 *                      backend probe. WebDAV (M1): the fake WebClient starts MISSING after
 *                      fake_backend_reset(); fake_backend_set_webclient() changes it.
 * Each session runs on its own thread (the fake I/O thread) and delivers every callback there. */
#ifndef SD_FAKE_BACKEND_H
#define SD_FAKE_BACKEND_H

#include "sd_mount/sd_mount.h"

#define FAKE_PASSWORD   "secret"
#define FAKE_PASSPHRASE "pass"
#define FAKE_FP         "SHA256:K3l2sJ0pAqv0d8ZbFakeFakeFakeFakeFakeFake0Q"

const sd_mount_backend *fake_backend(void);
void fake_backend_reset(void);
int  fake_backend_is_trusted(const char *host);
int  fake_backend_letter_mounted(wchar_t letter);
uint32_t fake_backend_live_sessions(void);
/* last vfs options seen by vfs_mount (copied scalars) */
int  fake_backend_last_read_only(void);
const char *fake_backend_last_remote_root(void);
/* WebDAV fake: WebClient state and whether ensure_client may start a STOPPED one. */
void     fake_backend_set_webclient(sd_webdav_client_state st, int startable);
uint32_t fake_backend_webclient_starts(void);     /* ensure_client calls since reset (TM-R21 checks) */
uint32_t fake_backend_webdav_mounts(void);
uint32_t fake_backend_last_request_timeout(void);
/* M1: "flaky*" hosts stay READY until fake_backend_drop(): then DISCONNECTED, RECONNECT_WAIT(attempt 1),
   CONNECTING and READY of the next generation (or FAILED with fail = 1). */
void     fake_backend_drop(int fail);
uint32_t fake_backend_dokan_starts(void);
uint32_t fake_backend_vfs_mounts(void);
uint32_t fake_backend_budget_calls(void);
/* last session / vfs options seen */
int      fake_backend_last_reconnect_enabled(void);
uint32_t fake_backend_last_channels(void);
int      fake_backend_last_secret_cache(void);
uint32_t fake_backend_last_offline_wait(void);
uint32_t fake_backend_last_grace(void);
uint32_t fake_backend_last_disk_mb(void);
const wchar_t *fake_backend_last_disk_dir(void);
int      fake_backend_last_known_uid(uint32_t *uid);      /* 1 when known_identity was passed */
/* raises a vfs event on the last mounted vfs, from a foreign thread like the real vfs */
void     fake_backend_vfs_write_failed(const wchar_t *path, UINT64 bytes);
void     fake_backend_vfs_identity(uint32_t uid, uint32_t gid);

#endif /* SD_FAKE_BACKEND_H */
