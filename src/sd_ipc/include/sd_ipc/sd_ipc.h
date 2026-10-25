/* sd_ipc: named-pipe IPC between CLI/UI and the host (agent or service) (03 §2).
 *
 * Wire format: PIPE_TYPE_MESSAGE, one UTF-8 JSON object per message (sd_base/sd_json.h), first
 * message "hello" with proto negotiation (SD_IPC_PROTO / SD_IPC_MIN_PROTO). Error codes are the
 * sd_err_name() spellings (03 §2.3, review C25).
 *
 * Names (decisions.md D45):
 *   agent pipe      \\.\pipe\com.librestatic.shelldrive.agent.<UserSid>.<SessionId>
 *   service pipe    \\.\pipe\com.librestatic.shelldrive.service
 *   agent ready     Local\com.librestatic.shelldrive.agent.ready.<UserSid>
 *   agent shutdown  Global\com.librestatic.shelldrive.agent.shutdown.<UserSid>.<SessionId>
 *
 * Security (03 §2.2): the client verifies the server's owner SID (and PID/session on Vista+) before
 * sending anything; the server checks every client.
 *
 * Threading and ownership:
 * - Client: an sd_ipc_conn is used by one thread at a time (calls are synchronous with timeouts);
 *   sd_ipc_event_handle() lets a UI thread wait for events. Results and events returned as sd_json
 *   are owned by the caller and released with sd_json_free.
 * - Server: the handler runs on the server's pipe thread, one client message at a time; it must not
 *   block on SSH/VFS work (start it and reply later through events). sd_ipc_broadcast is
 *   thread-safe. */
#ifndef SD_IPC_H
#define SD_IPC_H

#include <windows.h>

#include "sd/base.h"
#include "sd_base/sd_err.h"
#include "sd_base/sd_json.h"

#define SD_IPC_PROTO        1
#define SD_IPC_MIN_PROTO    1
#define SD_IPC_MAX_MESSAGE  (1u << 20)

#define SD_IPC_PIPE_PREFIX       L"\\\\.\\pipe\\com.librestatic.shelldrive."
#define SD_IPC_SERVICE_PIPE      L"\\\\.\\pipe\\com.librestatic.shelldrive.service"
#define SD_IPC_AGENT_READY_FMT   L"Local\\com.librestatic.shelldrive.agent.ready.%ls"
#define SD_IPC_AGENT_STOP_FMT    L"Global\\com.librestatic.shelldrive.agent.shutdown.%ls.%lu"

typedef enum sd_ipc_endpoint { SD_IPC_AGENT, SD_IPC_SERVICE } sd_ipc_endpoint;

enum { SD_IPC_CAP_PROMPTS_CONSOLE = 1u << 0, SD_IPC_CAP_PROMPTS_UI = 1u << 1 };

typedef struct sd_ipc_conn   sd_ipc_conn;
typedef struct sd_ipc_server sd_ipc_server;
typedef struct sd_ipc_client sd_ipc_client;    /* server-side view of one connected client */

typedef struct sd_ipc_hello {
  const char *client_kind;                      /* "cli", "ui", "shellext" */
  const char *client_version;                   /* SD_VERSION_STRING */
  const char *lang;                             /* "en","es","fr","pt-BR","it","de" */
  uint32_t    caps;                             /* SD_IPC_CAP_* */
} sd_ipc_hello;

typedef struct sd_ipc_error {
  sd_err err;                                   /* SD_OK when no error */
  char   code[64];                              /* stable English identifier (sd_err_name spelling) */
  char   detail[256];                           /* English, for logs */
  int    exit_code;                             /* CLI exit code (03 §6.2) */
} sd_ipc_error;

/* Builds the agent pipe name for a user SID string and session id (or the service pipe). */
sd_err sd_ipc_pipe_name(sd_ipc_endpoint ep, const wchar_t *user_sid, DWORD session_id,
                        wchar_t *out, size_t cch);
/* Current process user SID string and session id (ConvertSidToStringSidW, ProcessIdToSessionId). */
sd_err sd_ipc_current_identity(wchar_t *sid_out, size_t sid_cch, DWORD *session_id);

/* ---- client ---- */

/* Connects, verifies the server owner SID, performs hello. start_if_missing: spawn the agent
   (unelevated if the caller is elevated, 03 §1.7.2). */
sd_err sd_ipc_connect(sd_ipc_endpoint ep, const sd_ipc_hello *hello, int start_if_missing,
                      DWORD timeout_ms, sd_ipc_conn **out);
sd_err sd_ipc_call(sd_ipc_conn *c, const char *method, const sd_json *params,
                   DWORD timeout_ms, sd_json **result, sd_ipc_error *err);
/* Same, with params given as an already-encoded JSON object (UTF-8). */
sd_err sd_ipc_call_raw(sd_ipc_conn *c, const char *method, const char *params_json, size_t len,
                       DWORD timeout_ms, sd_json **result, sd_ipc_error *err);
sd_err sd_ipc_next_event(sd_ipc_conn *c, DWORD timeout_ms, sd_json **event);   /* after "subscribe" */
HANDLE sd_ipc_event_handle(sd_ipc_conn *c);     /* signaled when an event is readable */
void   sd_ipc_close(sd_ipc_conn *c);

/* ---- server (host only) ---- */

/* Fills `result` (a JSON object writer positioned inside "result") or `err`. */
typedef sd_err (*sd_ipc_handler)(void *ctx, sd_ipc_client *client, const char *method,
                                 const sd_json *params, sd_json_writer *result, sd_ipc_error *err);
sd_err sd_ipc_server_start(sd_ipc_endpoint ep, sd_ipc_handler h, void *ctx, sd_ipc_server **out);
void   sd_ipc_server_stop(sd_ipc_server *s);    /* control thread; waits for the pipe thread */
int    sd_ipc_client_is_elevated(sd_ipc_client *client);   /* via impersonation; 0 on XP */
int    sd_ipc_client_is_admin(sd_ipc_client *client);      /* elevated + BUILTIN\Administrators */
DWORD  sd_ipc_client_pid(sd_ipc_client *client);
/* Sends an event to every client subscribed to `topic`; `event_json` is a complete JSON object. */
void   sd_ipc_broadcast(sd_ipc_server *s, const char *topic, const char *event_json, size_t len);

/* ==== additive API (M0 implementation, docs/dev/m0-notes.md) ====
 *
 * Protocol as implemented: the hello message is {"type":"hello","id":0,"proto":..,"min_proto":..,
 * "client":..,"client_version":..,"lang":..,"caps":["prompts.console",..]} and its reply a normal
 * response {"type":"res","id":0,"result":{"proto":1,"server_pid":N,"server_version":".."}}.
 * Events are complete messages {"type":"evt","event":"<name>","data":{...}} (sd_ipc_build_event).
 * The built-in methods "hello" and "subscribe" {topics:[..]} never reach the handler. The handler's
 * `result` writer already has the result object open: write members (sd_jw_key + value) only. */

typedef struct sd_ipc_server_cfg {
  uint32_t struct_size;                 /* sizeof(sd_ipc_server_cfg) */
  sd_ipc_handler handler;
  void *ctx;
  /* Called on the pipe thread after a client that completed hello disconnected. */
  void (*on_disconnect)(void *ctx, uint64_t client_id);
  uint32_t max_instances;               /* 0 = 32 (03 §2.2) */
  uint32_t max_message;                 /* 0 = SD_IPC_MAX_MESSAGE */
  uint32_t idle_timeout_ms;             /* non-subscribed clients; 0 = 10 min */
  uint32_t max_per_sid;                 /* 0 = unlimited (agent); service: 4 (TM-R25) */
  uint32_t max_requests_per_sec;        /* 0 = unlimited (agent); service non-admins: 10 */
} sd_ipc_server_cfg;

sd_err   sd_ipc_server_start_ex(sd_ipc_endpoint ep, const sd_ipc_server_cfg *cfg, sd_ipc_server **out);
/* Stable id of a connected client (never reused within a server's lifetime). */
uint64_t sd_ipc_client_id(sd_ipc_client *client);
uint32_t sd_ipc_client_caps(sd_ipc_client *client);          /* SD_IPC_CAP_* from hello */
const char *sd_ipc_client_lang(sd_ipc_client *client);       /* from hello; "en" if absent */
/* Thread-safe: queues a complete event message for one client. SD_E_NOT_FOUND once it is gone. */
sd_err   sd_ipc_send_to(sd_ipc_server *s, uint64_t client_id, const char *event_json, size_t len);
/* Number of clients that completed hello (thread-safe). */
uint32_t sd_ipc_server_client_count(sd_ipc_server *s);

/* Builds {"type":"evt","event":<event>,"data":<data_json>} into `out` (an initialized sd_wr). */
sd_err   sd_ipc_build_event(const char *event, const char *data_json, size_t data_len, sd_wr *out);

/* Error table (1.11, C25, 03 §6.2). Every sd_err maps to a CLI exit code (unit-tested for every
   value); IPC codes that have no sd_err (usage, profile_not_found, target_in_use, ...) map by name.
   Unknown codes map to 1. */
int      sd_ipc_exit_code_for_err(sd_err e);
int      sd_ipc_exit_code_for_code(const char *code);
/* Fills err: code = `code` if non-NULL else sd_err_name(e); exit_code from the table above. */
void     sd_ipc_error_set(sd_ipc_error *err, sd_err e, const char *code, const char *detail);

/* Named kernel objects of the agent (03 §1.2, §2.1; TM-R26). */
typedef enum sd_ipc_object {
  SD_IPC_OBJ_AGENT_MUTEX,     /* Local\com.librestatic.shelldrive.agent.<SID> */
  SD_IPC_OBJ_AGENT_READY,     /* Local\com.librestatic.shelldrive.agent.ready.<SID> (manual reset) */
  SD_IPC_OBJ_AGENT_STOP       /* Global\com.librestatic.shelldrive.agent.shutdown.<SID>.<session> */
} sd_ipc_object;
sd_err   sd_ipc_object_name(sd_ipc_object obj, wchar_t *out, size_t cch);
/* Creates the object with the owner/DACL of 03 §2.2 (stop event: §1.2 DACL). *existed is set when
   it already existed with our owner (second instance). A foreign owner is squatting: the handle is
   closed and SD_E_ACCESS_DENIED returned. */
sd_err   sd_ipc_object_create(sd_ipc_object obj, HANDLE *out, int *existed);
/* Opens an existing object with SYNCHRONIZE (events) after the same owner check. */
sd_err   sd_ipc_object_open(sd_ipc_object obj, HANDLE *out);

/* Agent auto-start: path of shelldrive-host.exe (default: next to the calling executable). The
   override is process-wide, set before the first sd_ipc_connect (tests and portable layouts). */
void     sd_ipc_set_agent_path(const wchar_t *path);

/* TEST HOOK: appends ".<suffix>" to every pipe and named-object name of this process so tests can
   run next to a real agent. NULL/empty clears it. Never used by shipping code paths. */
void     sd_ipc_set_instance_suffix(const wchar_t *suffix);
/* TEST HOOK: the owner SID string the client requires from the server (NULL = default rules). */
void     sd_ipc_test_set_expected_owner(const wchar_t *sid_string);
/* TEST HOOK: how often sd_ipc_connect retried because an instance broke before hello completed. */
uint32_t sd_ipc_test_connect_retries(void);

#endif /* SD_IPC_H */
