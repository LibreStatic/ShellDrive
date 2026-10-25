/* sd_dokan: Dokany 2.x backend over sd_vfs (02 §6). dokan2.dll is loaded dynamically from System32
 * (never the search path) and gated on DokanVersion() >= 210 && DokanDriverVersion() >= 210.
 * The Dokany ABI itself is private (src/sd_dokan/dokan_abi.h); this header exposes only what the
 * host (sd_mount) needs.
 *
 * Threading (02 §6.5, §6.6; review C33):
 * - sd_dokan_probe: any thread except Dokany callbacks.
 * - sd_dokan_mount_start / sd_dokan_mount_stop / sd_dokan_remove_stale_mounts: host control thread
 *   only. mount_stop calls DokanCloseHandle, which waits for in-flight callbacks.
 * - The unmounted callback runs on a Dokany thread: it must ONLY post to the control thread and
 *   return; calling mount_stop, sd_vfs_unmount or sd_sftp_session_destroy there deadlocks.
 * Ownership: a mount borrows the sd_vfs (which must outlive mount_stop); cfg strings and the volume
 * security descriptor are copied. */
#ifndef SD_DOKAN_H
#define SD_DOKAN_H

#include <windows.h>

#include "sd/base.h"
#include "sd_base/sd_err.h"
#include "sd_vfs/sd_vfs.h"

typedef enum sd_dokan_avail {
  SD_DOKAN_OK,
  SD_DOKAN_OS_UNSUPPORTED,
  SD_DOKAN_NOT_INSTALLED,    /* dokan2.dll absent or failed to load (load_error says why) */
  SD_DOKAN_TOO_OLD,          /* < 2.1.0 (incl. 2.0.x) */
  SD_DOKAN_DRIVER_MISSING,   /* DokanDriverVersion() == 0 */
  SD_DOKAN_WOW64,            /* our process architecture != OS architecture */
  SD_DOKAN_DENIED            /* version on the signed deny list (TM-R23) */
} sd_dokan_avail;

/* Deny list from the last verified update manifest (`dokany-deny`, 04 §9.2). Versions as 231 = 2.3.1. */
typedef struct sd_dokan_deny_range { uint32_t from, to; const char *reason; } sd_dokan_deny_range;
typedef struct sd_dokan_deny { const sd_dokan_deny_range *ranges; uint32_t count; } sd_dokan_deny;

typedef struct sd_dokan_probe_info {
  sd_dokan_avail avail;
  uint32_t lib_version, driver_version;   /* e.g. 231; 0 if unknown */
  DWORD load_error;                       /* GetLastError() of a failed load, else 0 */
  const char *deny_reason;                /* SD_DOKAN_DENIED: points into the deny list */
} sd_dokan_probe_info;

/* deny may be NULL. Loads (and keeps loaded) System32\dokan2.dll on success and calls DokanInit once.
   Never loads anything before Windows 7 SP1 (SD_DOKAN_OS_UNSUPPORTED, e.g. when run on XP). */
sd_dokan_avail sd_dokan_probe(const sd_dokan_deny *deny, sd_dokan_probe_info *info);
/* DokanShutdown at process exit (host control thread, after every mount_stop). */
void sd_dokan_shutdown(void);

typedef struct sd_dokan_mount_cfg {
  uint32_t struct_size;
  const wchar_t *mount_point;      /* L"Z:\\" or an empty NTFS folder */
  const wchar_t *unc_share;        /* <share> of \shelldrive\<share>; NULL = no network provider */
  BOOL network;                    /* DOKAN_OPTION_NETWORK (default when the provider is registered) */
  BOOL current_session;            /* per-user drive letter */
  BOOL global_mount;               /* service: MOUNT_MANAGER, no CURRENT_SESSION */
  BOOL read_only;
  BOOL case_sensitive;
  BOOL alt_stream_motw;            /* mark_of_the_web = internet: synthetic :Zone.Identifier only */
  uint32_t timeout_ms;             /* 0 = 30000 */
  const void *volume_sd; uint32_t volume_sd_len;   /* self-relative SD for global mounts (D35) */
} sd_dokan_mount_cfg;

typedef struct sd_dokan_mount sd_dokan_mount;
typedef void (*sd_dokan_unmounted_cb)(void *ctx, sd_dokan_mount *m);   /* Dokany thread: post only */

sd_err sd_dokan_mount_start(sd_vfs *vfs, const sd_dokan_mount_cfg *cfg, sd_dokan_unmounted_cb cb,
                            void *ctx, sd_dokan_mount **out);
sd_err sd_dokan_mount_stop(sd_dokan_mount *m);          /* DokanCloseHandle; frees m */

/* Removes stale ShellDrive mount points left by a crashed process (\shelldrive\ UNC prefix, 02 §6.6). */
sd_err sd_dokan_remove_stale_mounts(void);

/* sd_vfs_status -> NTSTATUS (02 §8 table). */
typedef LONG sd_ntstatus;
sd_ntstatus sd_vfs_to_ntstatus(sd_vfs_status s);

#endif /* SD_DOKAN_H */
