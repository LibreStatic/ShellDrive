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

#endif /* SD_IPC_H */
