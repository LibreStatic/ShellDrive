/* sd_mount: turns resolved mount parameters into a running mount (03 §1.11):
 *   sd_known_hosts (user store) -> sd_ssh_config -> sd_sftp_session -> sd_vfs -> sd_dokan.
 *
 * M0 scope: one hop, direct TCP, Dokany backend, drive letters only, no reconnect (the session's
 * reconnect policy is disabled), no pool, prompts relayed to the host (hostkey TOFU, password,
 * key passphrase, keyboard-interactive). A changed host key is never a prompt: sd_ssh fails the
 * connection and sd_mount reports SD_E_HOSTKEY_MISMATCH with the stored and offered fingerprints.
 *
 * The other modules are reached through sd_mount_backend, a table with exactly their public
 * signatures: sd_mount_backend_real() binds the real modules (mount_real.c, its own library
 * sd_mount_real), tests bind fakes. sd_mount itself only links headers of sd_ssh/sd_sftp/sd_vfs/
 * sd_dokan.
 *
 * Threading (review §4.1, 03 §1.11):
 * - sd_mount_create/start/stop/destroy run on the host control thread only.
 * - Every callback in sd_mount_callbacks except `post` runs on the control thread: sd_mount hops
 *   there from sd_ssh/sd_sftp I/O threads and Dokany threads through `post`.
 * - sd_mount_answer may be called from any thread (the IPC thread); the answer goes straight to
 *   sd_prompt_* (thread-safe in sd_ssh); secrets are wiped by the caller.
 * Ownership: params strings are deep-copied by sd_mount_create. Prompt structs passed to on_prompt
 * are valid during the callback only. */
#ifndef SD_MOUNT_H
#define SD_MOUNT_H

#include <windows.h>

#include "sd/base.h"
#include "sd_base/sd_err.h"
#include "sd_ssh/sd_ssh.h"
#include "sd_sftp/sd_sftp.h"
#include "sd_vfs/sd_vfs.h"
#include "sd_dokan/sd_dokan.h"

typedef struct sd_mount sd_mount;

typedef enum sd_mount_state {
  SD_MOUNT_CONNECTING, SD_MOUNT_AUTHENTICATING, SD_MOUNT_MOUNTED, SD_MOUNT_OFFLINE,
  SD_MOUNT_AUTH_REQUIRED, SD_MOUNT_FAILED, SD_MOUNT_UNMOUNTING, SD_MOUNT_UNMOUNTED
} sd_mount_state;
const char *sd_mount_state_name(sd_mount_state st);    /* IPC spelling: "connecting", ... */

typedef struct sd_mount_backend {
  const char *name;
  sd_err (*ssh_global_init)(void);
  sd_err (*kh_open)(const sd_kh_store *stores, uint32_t count, sd_known_hosts **out);
  void   (*kh_close)(sd_known_hosts *kh);
  sd_err (*session_create)(const sd_ssh_config *ssh, const sd_ssh_callbacks *ssh_cb, const sd_sftp_options *opt,
                           sd_sftp_event_cb ev, void *ev_ctx, sd_sftp_session **out);
  sd_err (*session_start)(sd_sftp_session *s);
  sd_err (*session_close)(sd_sftp_session *s);
  void   (*session_destroy)(sd_sftp_session *s);
  sd_err (*prompt_answer)(sd_prompt *p, uint32_t n, const char *const *utf8_responses);
  sd_err (*prompt_answer_hostkey)(sd_prompt *p, sd_hostkey_decision d);
  sd_err (*prompt_cancel)(sd_prompt *p);
  sd_vfs_status (*vfs_mount)(sd_sftp_session *s, const sd_vfs_options *o, sd_vfs_event_cb cb, void *cb_ctx,
                             sd_vfs **out);
  void   (*vfs_quiesce)(sd_vfs *v, DWORD budget_ms);
  void   (*vfs_unmount)(sd_vfs *v);
  sd_dokan_avail (*dokan_probe)(const sd_dokan_deny *deny, sd_dokan_probe_info *info);
  sd_err (*dokan_mount_start)(sd_vfs *vfs, const sd_dokan_mount_cfg *cfg, sd_dokan_unmounted_cb cb, void *ctx,
                              sd_dokan_mount **out);
  sd_err (*dokan_mount_stop)(sd_dokan_mount *m);
} sd_mount_backend;

/* Real modules (library sd_mount_real; link it only when sd_ssh/sd_sftp/sd_vfs/sd_dokan are built). */
const sd_mount_backend *sd_mount_backend_real(void);

typedef struct sd_mount_params {
  uint32_t struct_size;                 /* sizeof(sd_mount_params) */
  const wchar_t *host;                  /* as typed */
  uint16_t port;                        /* 0 = 22 */
  const char *user;                     /* UTF-8, required */
  const wchar_t *identity_path;         /* expanded key file path; NULL/"" = none */
  uint32_t auth_methods;                /* SD_AUTH_* (sd_ssh.h); 0 = publickey|kbdint|password */
  const char *remote_path;              /* UTF-8; NULL/"" = login directory */
  wchar_t letter;                       /* 'D'..'Z' */
  int read_only;
  int symlinks;                         /* sd_vfs_symlinks */
  int write_mode;                       /* sd_vfs_write_mode */
  const wchar_t *volume_label;          /* NULL = host */
  const wchar_t *known_hosts_path;      /* user store file; NULL = sd_known_hosts default */
} sd_mount_params;

typedef enum sd_mount_prompt_kind {
  SD_MP_HOSTKEY, SD_MP_PASSWORD, SD_MP_PASSPHRASE, SD_MP_KBDINT
} sd_mount_prompt_kind;
const char *sd_mount_prompt_kind_name(sd_mount_prompt_kind k);  /* "hostkey_unknown", "password", ... */

#define SD_MOUNT_PROMPT_MAX_ITEMS 8

typedef struct sd_mount_prompt {
  uint32_t id;                          /* unique per mount */
  sd_mount_prompt_kind kind;
  uint32_t hop_index;
  char host[256];                       /* sanitized by sd_ssh */
  uint16_t port;
  char user[128];
  /* SD_MP_HOSTKEY */
  char key_type[48];
  uint32_t key_bits;
  char fp_sha256[64];
  char lookup_name[300];
  /* SD_MP_PASSWORD / SD_MP_KBDINT / SD_MP_PASSPHRASE */
  uint32_t round;
  int hostkey_just_accepted;            /* TM-R05 */
  char key_path[520];                   /* passphrase: key file (UTF-8) */
  char key_fp[64];
  char name[256], instruction[1024];    /* kbd-int (server text, sanitized) */
  uint32_t item_count;
  struct { char text[512]; int echo; } items[SD_MOUNT_PROMPT_MAX_ITEMS];
} sd_mount_prompt;

/* Details kept for the error report of a failed mount. */
typedef struct sd_mount_failure {
  sd_err err;
  const char *code;                     /* IPC code when it differs from sd_err_name (e.g. "backend_unavailable") */
  char detail[256];                     /* English, for logs */
  /* SD_E_HOSTKEY_MISMATCH: stored vs offered key (from on_hostkey_event) */
  char stored_type[48], stored_fp[64], offered_type[48], offered_fp[64];
  wchar_t store_path[260];
  uint32_t store_line;
} sd_mount_failure;

typedef struct sd_mount_callbacks {
  void *ctx;
  /* Any thread: runs fn(arg) later on the control thread, in order. Must not fail; if it cannot
     queue, it must run nothing and sd_mount leaks the item rather than run on a foreign thread. */
  void (*post)(void *ctx, void (*fn)(void *), void *arg);
  void (*on_state)(void *ctx, sd_mount *m, sd_mount_state st, sd_err why);
  void (*on_prompt)(void *ctx, sd_mount *m, const sd_mount_prompt *p);
  void (*on_prompt_closed)(void *ctx, sd_mount *m, uint32_t prompt_id);
} sd_mount_callbacks;

sd_err sd_mount_create(const sd_mount_backend *be, const sd_mount_params *params, const sd_mount_callbacks *cb,
                       sd_mount **out);
sd_err sd_mount_start(sd_mount *m);
/* Starts the unmount (or cancels a connect); completion: on_state(UNMOUNTED) (or FAILED). */
sd_err sd_mount_stop(sd_mount *m);
/* Only after on_state reported UNMOUNTED or FAILED, or before sd_mount_start. */
void   sd_mount_destroy(sd_mount *m);

sd_mount_state sd_mount_get_state(const sd_mount *m);
wchar_t        sd_mount_letter(const sd_mount *m);
void           sd_mount_get_failure(const sd_mount *m, sd_mount_failure *out);
int            sd_mount_is_final(const sd_mount *m);    /* UNMOUNTED or FAILED and fully torn down */

typedef enum sd_mount_answer_kind {
  SD_MA_RESPONSES,                      /* password / passphrase / kbd-int responses */
  SD_MA_HOSTKEY_TRUST,                  /* accept and store */
  SD_MA_HOSTKEY_ONCE,                   /* accept for this connection */
  SD_MA_REJECT                          /* reject the key or cancel the prompt */
} sd_mount_answer_kind;
/* Any thread. SD_E_NOT_FOUND when the prompt was answered, withdrawn or never existed. */
sd_err sd_mount_answer(sd_mount *m, uint32_t prompt_id, sd_mount_answer_kind kind, uint32_t n,
                       const char *const *utf8_responses);
/* Cancels every open prompt (e.g. the requesting client went away). Any thread. */
uint32_t sd_mount_cancel_prompts(sd_mount *m);   /* returns how many were open */

#endif /* SD_MOUNT_H */
