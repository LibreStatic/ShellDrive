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
 *   UI mutex        Local\com.librestatic.shelldrive.ui.<UserSid>        (M3)
 *   state section   Local\com.librestatic.shelldrive.state.<UserSid>     (M3, 256 KiB, 03 §8.2.1)
 *   Object scope (03 §2.1): per-session objects are Local\, machine objects Global\.
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
/* M3: sends an event to every client that completed hello, whatever its subscriptions (config.changed,
   agent.stopping). Thread-safe, queued like the others. */
sd_err sd_ipc_broadcast_all(sd_ipc_server *s, const char *event_json, size_t len);
/* Same, and reports how many recipients were queued: subscribed clients that completed hello, have
   every bit of `required_caps` and are not `exclude_client` (0 = none). `count` may be NULL. The
   count is taken when the event is queued; a recipient that disconnects before the pipe thread
   writes is counted but never receives it. */
sd_err sd_ipc_broadcast_count(sd_ipc_server *s, const char *topic, const char *event_json, size_t len,
                              uint32_t required_caps, uint64_t exclude_client, uint32_t *count);
/* Number of hello-completed clients subscribed to `topic` with `required_caps` (thread-safe). */
uint32_t sd_ipc_topic_subscribers(sd_ipc_server *s, const char *topic, uint32_t required_caps);
/* Topic names: 1..SD_IPC_TOPIC_MAX bytes of [a-z0-9._-]. Invalid names are never kept in a subscription. */
#define SD_IPC_TOPIC_MAX 23
int    sd_ipc_topic_valid(const char *topic);

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
  /* M3: called on the pipe thread once per topic a client newly subscribes to, after the subscribe
     request was accepted. It may call sd_ipc_send_to (events are queued, never written inline). */
  void (*on_subscribe)(void *ctx, sd_ipc_client *client, const char *topic);
  /* M3: feature names listed as "features" in the hello reply; NULL = none. Must outlive the server. */
  const char *const *features;
  /* M5 (service): called on the pipe thread for every valid topic of a subscribe request before anything is
     subscribed; 0 refuses the whole request with access_denied. NULL = every topic allowed. */
  int (*topic_allowed)(void *ctx, sd_ipc_client *client, const char *topic);
} sd_ipc_server_cfg;

/* TEST HOOK (M5): the service pipe is created with this owner SID string instead of SYSTEM (an unelevated test
   process cannot create a pipe owned by SYSTEM). NULL restores SYSTEM. Never used by shipping code. */
void     sd_ipc_test_set_service_owner(const wchar_t *sid_string);

sd_err   sd_ipc_server_start_ex(sd_ipc_endpoint ep, const sd_ipc_server_cfg *cfg, sd_ipc_server **out);
/* Stable id of a connected client (never reused within a server's lifetime). */
uint64_t sd_ipc_client_id(sd_ipc_client *client);
/* M5: 1 when the client's token has `sid` enabled (or it is the client's own user SID). Pipe thread, from a handler
   only (the client is impersonated). Fail closed: an error leaves *member = 0. */
sd_err   sd_ipc_client_member_of(sd_ipc_client *client, PSID sid, int *member);
uint32_t sd_ipc_client_caps(sd_ipc_client *client);          /* SD_IPC_CAP_* from hello */
const char *sd_ipc_client_lang(sd_ipc_client *client);       /* from hello; "en" if absent */
/* Thread-safe: queues a complete event message for one client. SD_E_NOT_FOUND once it is gone. */
sd_err   sd_ipc_send_to(sd_ipc_server *s, uint64_t client_id, const char *event_json, size_t len);
/* M3 deferred replies: a handler that cannot answer yet (profile.test) calls sd_ipc_defer(client, &id) inside
   the call and returns; the pipe thread sends no reply. Later, from any thread, sd_ipc_reply_deferred sends the
   reply once: result_json (an object of result_len bytes) on success, or the error of e/code/detail. sd_ipc_defer
   returns 0 when it is not called from a handler. */
int      sd_ipc_defer(sd_ipc_client *client, int64_t *req_id);
sd_err   sd_ipc_reply_deferred(sd_ipc_server *s, uint64_t client_id, int64_t req_id, sd_err e, const char *code,
                               const char *detail, const char *result_json, size_t result_len);
/* Number of clients that completed hello (thread-safe). */
uint32_t sd_ipc_server_client_count(sd_ipc_server *s);
/* "client" of the hello ("cli", "ui", "shellext"); "" before hello. */
const char *sd_ipc_client_kind(sd_ipc_client *client);

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
  SD_IPC_OBJ_AGENT_STOP,      /* Global\com.librestatic.shelldrive.agent.shutdown.<SID>.<session> */
  SD_IPC_OBJ_UI_MUTEX,        /* Local\com.librestatic.shelldrive.ui.<SID>: held by a running UI (M3) */
  SD_IPC_OBJ_STATE            /* Local\com.librestatic.shelldrive.state.<SID>: file mapping, see below (M3) */
} sd_ipc_object;
sd_err   sd_ipc_object_name(sd_ipc_object obj, wchar_t *out, size_t cch);
/* Creates the object with the owner/DACL of 03 §2.2 (stop event: §1.2 DACL). *existed is set when
   it already existed with our owner (second instance). A foreign owner is squatting: the handle is
   closed and SD_E_ACCESS_DENIED returned. SD_IPC_OBJ_STATE is not a kernel event or mutex: use
   sd_ipc_state_create (SD_E_INVALID_PARAM here). */
sd_err   sd_ipc_object_create(sd_ipc_object obj, HANDLE *out, int *existed);
/* Opens an existing object with SYNCHRONIZE (events) after the same owner check. */
sd_err   sd_ipc_object_open(sd_ipc_object obj, HANDLE *out);

/* State snapshot section (03 §1.6, §8.2; layout in docs/design/03-apps-platform.md §8.2): a fixed
   256 KiB page-file mapping, owned by the agent. The creator gets PAGE_READWRITE; sd_ipc_state_open
   opens it with FILE_MAP_READ | READ_CONTROL (the owner check needs READ_CONTROL; [verify] on XP,
   7 and 10/11, 03 §2.2). Both verify the owner (our user SID) and the label (medium or none) on the
   handle and fail closed: a squatted section is never returned. */
#define SD_IPC_STATE_BYTES 262144u
sd_err   sd_ipc_state_create(HANDLE *out, int *existed);
sd_err   sd_ipc_state_open(HANDLE *out);

/* Feature names of the hello reply, client side (the reply's "features" array). */
int      sd_ipc_conn_has_feature(const sd_ipc_conn *c, const char *name);

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
/* TEST HOOK: the owner and label decision of TM-R26 (ipc_owner_decision) without an object: owner_ok, want_label
   (Vista+ and the label asked), label_read, label_present and the label RID of the mandatory label. */
sd_err   sd_ipc_test_owner_decision(int owner_ok, int want_label, int label_read, int label_present, DWORD label_rid);

#endif /* SD_IPC_H */
