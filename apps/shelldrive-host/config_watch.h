/* Watch of the user's configuration (03 §2.4 config.changed, M3): the profiles folder and settings.ini of the
 * user's config root, watched with ReadDirectoryChangesW on a thread of their own (XP-compatible, no
 * post-XP import). Changes are debounced (500 ms of quiet) and reported once per batch through the callback.
 * The watch never reloads anything: mounted profiles are not changed in flight; clients use config.reload. */
#ifndef SD_HOST_CONFIG_WATCH_H
#define SD_HOST_CONFIG_WATCH_H

#include <windows.h>
#include <stdint.h>

#include "sd_base/sd_err.h"

/* what: "settings" or "profiles". For profiles, paths lists the changed profile files that still exist (the
 * caller reads their ids); a removed file is not listed. Runs on the watch thread, once per debounced batch. */
typedef void (*config_watch_cb)(void *ctx, const char *what, const wchar_t *const *paths, uint32_t npaths);

/* Starts the watch thread. A missing config root is SD_E_NOT_FOUND (the agent then runs without the watch). */
sd_err config_watch_start(config_watch_cb cb, void *ctx);
/* Stops the thread and waits for it (up to 5 s). Safe when it was never started. */
void   config_watch_stop(void);

#endif /* SD_HOST_CONFIG_WATCH_H */
