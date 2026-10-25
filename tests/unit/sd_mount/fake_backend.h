/* Scripted fake of sd_ssh/sd_sftp/sd_vfs/sd_dokan for sd_mount and host tests (no network).
 *
 * Behavior is chosen by the host name of the mount:
 *   "unreachable*"  -> SD_E_CONN_REFUSED
 *   "mismatch*"     -> host key mismatch event, then SD_E_HOSTKEY_MISMATCH
 *   anything else   -> TOFU prompt unless the host was trusted before (process-wide fake store),
 *                      then authentication: identity path containing "encrypted" asks a passphrase
 *                      ("pass"), another identity succeeds silently, no identity asks a password
 *                      ("secret", two rounds, then SD_E_AUTH_FAILED); "nodokany*" fails the
 *                      backend probe.
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

#endif /* SD_FAKE_BACKEND_H */
