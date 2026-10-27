/* Explorer data written by the agent (03 §8.3, §8.7; M3): the per-user drive icon of each ShellDrive
 * drive and the Network location entries of the profiles that ask for one. Labels are not written here:
 * the WebDAV label is written by sd_webdav_map (_LabelFromReg), Dokany takes its volume label.
 *
 * Every function runs on the control thread WITHOUT the agent lock (the agent posts a work item with a
 * copy of the mount's data). Registry and file writes never happen under g.lock. */
#ifndef SD_HOST_EXPLORER_DATA_H
#define SD_HOST_EXPLORER_DATA_H

#include <windows.h>

/* One mount as Explorer needs it, copied out of the agent's record. */
typedef struct host_explorer_mount {
  wchar_t letter;              /* 'A'..'Z'; 0 = nothing to do */
  int present;                 /* the drive is mapped: mounted, offline or auth_required */
  int network_location;        /* the profile has mount.network_location = yes */
  char profile_id[33];         /* "" for ad hoc mounts (no Network location) */
  char profile_name[128];      /* UTF-8 display name */
} host_explorer_mount;

/* Reads the test hooks (SD_HOST_TEST_HOOKS builds only) and decides which parts are on. Shipping builds:
   icons and Network locations on (policy DisableNetworkLocations is read at start). Test builds: each part
   is on only when its test variable is set, so a test can never write the user's real keys or folders:
     SHELLDRIVE_TEST_EXPLORER_KEY  HKCU subkey used instead of Software\Classes\Applications\Explorer.exe\Drives
     SHELLDRIVE_TEST_NETHOOD       folder used instead of the NetHood folder */
void explorer_init(void);

/* Start: removes icons listed in state\explorer.ini (crash leftovers) and reconciles the Network location
   folders with the profiles (03 §8.7, lifecycle). Control thread, before the first mount. */
void explorer_reconcile_start(void);

/* A mount changed: sets or removes the icon of its letter (SHChangeNotify on the change), and points its
   Network location at the mount root (present) or at the placeholder folder (not present). */
void explorer_apply(const host_explorer_mount *m);

/* Shutdown, after every mount is gone: removes the icons this agent wrote (explorer.ini). */
void explorer_shutdown(void);

#endif /* SD_HOST_EXPLORER_DATA_H */
