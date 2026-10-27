/* M3 agent behaviour over the real IPC pipe, against the scripted fake backend (sd-test-host-fake.exe):
 * UI-only prompt delivery with one copy per recipient, prompt deadlines (injected through
 * SHELLDRIVE_TEST_PROMPT_MS), the queue (eviction with superseded, drain on subscribe with queued:true),
 * the initiator-disconnect rule (decision 5), and the read-only methods (status, selftest, log.tail,
 * config.reload, prompt.list, the warnings array of list, the features of hello).
 *
 * Every test runs its own agent: its own instance suffix, config root and environment (the agent reads
 * its test hooks from the environment it inherits). agent.shutdown ends it. Hosts used:
 *   new.test ... new7.test  unknown key (trust on first use), then a password prompt. */
#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "sd_test.h"
#include "sd_base/sd_json.h"
#include "sd_ipc/sd_ipc.h"
#include "sd_platform/sd_time.h"
#include "sd_state/sd_state.h"

#define M3_EVENTS 128

static wchar_t g_dir[MAX_PATH];
static unsigned g_tag;

typedef struct evlog {
  sd_json *ev[M3_EVENTS];
  int n;
} evlog;

static void wcat_u(wchar_t *dst, size_t cch, unsigned v)
{
  wchar_t tmp[16], o[16];
  size_t n = 0, i = 0;
  do { tmp[n++] = (wchar_t)(L'0' + v % 10); v /= 10; } while (v);
  while (n) o[i++] = tmp[--n];
  o[i] = 0;
  wcscat_s(dst, cch, o);
}

/* Fresh agent for this test: suffix and config root unique per process and test, test hooks set
   or cleared. */
static int setup_agent(const wchar_t *tag, const wchar_t *prompt_ms, const wchar_t *queue_max, const wchar_t *no_route)
{
  wchar_t suffix[96], root[MAX_PATH], exe[MAX_PATH], nethood[MAX_PATH + 16];
  DWORD n = GetModuleFileNameW(NULL, g_dir, MAX_PATH);
  size_t i, slash = 0;
  if (n == 0 || n >= MAX_PATH)
    return 0;
  for (i = 0; g_dir[i]; i++)
    if (g_dir[i] == L'\\') slash = i;
  g_dir[slash] = 0;
  g_tag++;
  wcscpy_s(suffix, SD_COUNTOF(suffix), L"m3");
  wcat_u(suffix, SD_COUNTOF(suffix), (unsigned)GetCurrentProcessId());
  wcscat_s(suffix, SD_COUNTOF(suffix), L"x");
  wcscat_s(suffix, SD_COUNTOF(suffix), tag);
  wcat_u(suffix, SD_COUNTOF(suffix), g_tag);
  if (GetTempPathW(MAX_PATH, root) == 0)
    return 0;
  wcscat_s(root, MAX_PATH, L"sd-m3-");
  wcat_u(root, MAX_PATH, (unsigned)GetCurrentProcessId());
  wcscat_s(root, MAX_PATH, L"-");
  wcscat_s(root, MAX_PATH, tag);
  wcat_u(root, MAX_PATH, g_tag);
  CreateDirectoryW(root, NULL);
  SetEnvironmentVariableW(L"SHELLDRIVE_TEST_INSTANCE", suffix);
  SetEnvironmentVariableW(L"SHELLDRIVE_TEST_CONFIG_DIR", root);
  SetEnvironmentVariableW(L"SHELLDRIVE_TEST_IDLE_MS", L"60000");
  SetEnvironmentVariableW(L"SHELLDRIVE_LANG", L"en");
  SetEnvironmentVariableW(L"SHELLDRIVE_TEST_PROMPT_MS", prompt_ms);
  SetEnvironmentVariableW(L"SHELLDRIVE_TEST_PROMPT_QUEUE_MAX", queue_max);
  SetEnvironmentVariableW(L"SHELLDRIVE_TEST_PROMPT_NO_ROUTE", no_route);
  SetEnvironmentVariableW(L"SHELLDRIVE_TEST_UI_LAUNCH", L"0");   /* never start the real prompt UI */
  /* M3 Explorer data: a test key and a test NetHood folder only (never the user's own) */
  SetEnvironmentVariableW(L"SHELLDRIVE_TEST_EXPLORER_KEY", L"Software\\LibreStatic\\ShellDriveTest\\m3icons");
  wcscpy_s(nethood, SD_COUNTOF(nethood), root);
  wcscat_s(nethood, SD_COUNTOF(nethood), L"\\nethood");
  CreateDirectoryW(nethood, NULL);
  SetEnvironmentVariableW(L"SHELLDRIVE_TEST_NETHOOD", nethood);
  sd_ipc_set_instance_suffix(suffix);
  wcscpy_s(exe, MAX_PATH, g_dir);
  wcscat_s(exe, MAX_PATH, L"\\sd-test-host-fake.exe");
  sd_ipc_set_agent_path(exe);
  return GetFileAttributesW(exe) != INVALID_FILE_ATTRIBUTES;
}

static sd_err connect_as(const char *kind, uint32_t caps, sd_ipc_conn **c)
{
  sd_ipc_hello h;
  memset(&h, 0, sizeof(h));
  h.client_kind = kind;
  h.lang = "en";
  h.caps = caps;
  return sd_ipc_connect(SD_IPC_AGENT, &h, 1, 15000, c);
}

static sd_err call(sd_ipc_conn *c, const char *method, const char *params, sd_json **res, sd_ipc_error *err)
{
  *res = NULL;
  return sd_ipc_call_raw(c, method, params, params ? strlen(params) : 0, 15000, res, err);
}

static void subscribe(sd_ipc_conn *c, const char *topics_json_items)
{
  sd_json *res = NULL;
  sd_ipc_error err;
  char buf[160];
  strcpy_s(buf, sizeof(buf), "{\"topics\":[");
  strcat_s(buf, sizeof(buf), topics_json_items);
  strcat_s(buf, sizeof(buf), "]}");
  (void)call(c, "subscribe", buf, &res, &err);     /* a failed subscribe shows up as missing events */
  sd_json_free(res);
}

static void shutdown_agent(sd_ipc_conn *c)
{
  sd_json *res = NULL;
  sd_ipc_error err;
  (void)call(c, "agent.shutdown", "{}", &res, &err);
  sd_json_free(res);
}

/* value of a bool or integer member, -1 when absent (the sd_json getters return a found flag) */
static int jbool3(const sd_json *o, const char *k, void *unused)
{
  int v = -1;
  SD_UNUSED(unused);
  if (!sd_json_get_bool(o, k, &v))
    return -1;
  return v;
}

static int64_t jint3(const sd_json *o, const char *k, void *unused)
{
  int64_t v = -1;
  SD_UNUSED(unused);
  if (!sd_json_get_int64(o, k, &v))
    return -1;
  return v;
}

static int ev_named(const sd_json *ev, const char *name)
{
  const char *e = sd_json_get_str(ev, "event");
  return e != NULL && strcmp(e, name) == 0;
}

static const sd_json *ev_data(const sd_json *ev)
{
  return sd_json_get(ev, "data");
}

static int ev_state_is(const sd_json *ev, const char *state)
{
  const char *s = sd_json_get_str(ev_data(ev), "state");
  return s != NULL && strcmp(s, state) == 0;
}

static int count_ev(const evlog *l, const char *name, const char *state)
{
  int i, n = 0;
  for (i = 0; i < l->n; i++)
    if (ev_named(l->ev[i], name) && (state == NULL || ev_state_is(l->ev[i], state)))
      n++;
  return n;
}

static const sd_json *nth_ev(const evlog *l, const char *name, const char *state, int k)
{
  int i;
  for (i = 0; i < l->n; i++)
    if (ev_named(l->ev[i], name) && (state == NULL || ev_state_is(l->ev[i], state)) && k-- == 0)
      return l->ev[i];
  return NULL;
}

/* Reads events into the log until `want` events named `name` (and `state`) are there, or total_ms passes. */
static int pump_until(sd_ipc_conn *c, evlog *l, const char *name, const char *state, int want, DWORD total_ms)
{
  uint64_t end = sd_tick_ms() + total_ms;
  while (count_ev(l, name, state) < want) {
    sd_json *ev = NULL;
    uint64_t now = sd_tick_ms();
    DWORD left = now >= end ? 0 : (DWORD)(end - now);
    if (left == 0 || sd_ipc_next_event(c, left, &ev) != SD_OK)
      return 0;
    if (l->n < M3_EVENTS) l->ev[l->n++] = ev;
    else sd_json_free(ev);
  }
  return 1;
}

/* Reads everything that arrives within idle_ms of the previous event. */
static void pump_idle(sd_ipc_conn *c, evlog *l, DWORD idle_ms)
{
  for (;;) {
    sd_json *ev = NULL;
    if (sd_ipc_next_event(c, idle_ms, &ev) != SD_OK)
      break;
    if (l->n < M3_EVENTS) l->ev[l->n++] = ev;
    else sd_json_free(ev);
  }
}

static void free_log(evlog *l)
{
  int i;
  for (i = 0; i < l->n; i++)
    sd_json_free(l->ev[i]);
  l->n = 0;
}

static void prompt_id_of(const evlog *l, const char *name, int k, char out[32])
{
  const sd_json *ev = nth_ev(l, name, NULL, k);
  const char *s = ev ? sd_json_get_str(ev_data(ev), "prompt_id") : NULL;
  out[0] = 0;
  if (s) strcpy_s(out, 32, s);
}

/* {"prompt_id":"<pid>",<rest>} */
static void answer_json(char *buf, size_t cap, const char *pid, const char *rest)
{
  strcpy_s(buf, cap, "{\"prompt_id\":\"");
  strcat_s(buf, cap, pid);
  strcat_s(buf, cap, "\",");
  strcat_s(buf, cap, rest);
  strcat_s(buf, cap, "}");
}

static int list_mounts(sd_ipc_conn *c)
{
  sd_json *res = NULL;
  sd_ipc_error err;
  int n = -1;
  if (call(c, "list", NULL, &res, &err) == SD_OK)
    n = (int)sd_json_count(sd_json_get(res, "mounts"));
  sd_json_free(res);
  return n;
}

/* Drive icon of a letter in the test key (SHELLDRIVE_TEST_EXPLORER_KEY): 1 while it exists. */
static int test_icon_exists(const wchar_t *letter)
{
  wchar_t sub[160];
  HKEY k;
  int found;
  _snwprintf_s(sub, SD_COUNTOF(sub), _TRUNCATE, L"Software\\LibreStatic\\ShellDriveTest\\m3icons\\%s\\DefaultIcon", letter);
  found = RegOpenKeyExW(HKEY_CURRENT_USER, sub, 0, KEY_QUERY_VALUE, &k) == ERROR_SUCCESS;
  if (found)
    RegCloseKey(k);
  return found;
}

static void test_icon_cleanup(void)
{
  RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\LibreStatic\\ShellDriveTest\\m3icons");
  RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\LibreStatic\\ShellDriveTest");
}

/* ---- tests ---- */

/* M3 (03 §8.2.1, §8.3): the state section exists from the start (empty), gets the mount while it is
   mounted (state, id, remote URL without credentials, the drive letter) and loses it after unmount; the
   drive icon follows the mount in the test key. */
SD_TEST(m3_snapshot_and_icon_follow_mount)
{
  sd_ipc_conn *c = NULL;
  sd_json *res = NULL;
  sd_ipc_error err;
  evlog l;
  char pid[32], buf[160];
  sd_state_snapshot *snap = NULL;
  wchar_t ls[2];
  uint64_t end;
  memset(&l, 0, sizeof(l));
  SD_REQUIRE(sd_state_snapshot_new(&snap) == SD_OK);
  test_icon_cleanup();
  SD_REQUIRE(setup_agent(L"snap", NULL, NULL, NULL));
  SD_REQUIRE(connect_as("ui", SD_IPC_CAP_PROMPTS_UI, &c) == SD_OK);
  subscribe(c, "\"prompt\",\"mount\"");
  SD_CHECK(sd_state_read_section(snap) == SD_OK && snap->count == 0);

  SD_REQUIRE(call(c, "mount", "{\"adhoc\":{\"host\":\"new.test\",\"user\":\"alice\"}}", &res, &err) == SD_OK);
  sd_json_free(res);
  res = NULL;
  SD_REQUIRE(pump_until(c, &l, "prompt.request", NULL, 1, 10000));
  prompt_id_of(&l, "prompt.request", 0, pid);
  answer_json(buf, sizeof(buf), pid, "\"action\":\"accept\"");
  SD_REQUIRE(call(c, "prompt.answer", buf, &res, &err) == SD_OK);
  sd_json_free(res);
  res = NULL;
  SD_REQUIRE(pump_until(c, &l, "prompt.request", NULL, 2, 10000));
  prompt_id_of(&l, "prompt.request", 1, pid);
  answer_json(buf, sizeof(buf), pid, "\"action\":\"answer\",\"responses\":[\"secret\"]");
  SD_REQUIRE(call(c, "prompt.answer", buf, &res, &err) == SD_OK);
  sd_json_free(res);
  res = NULL;
  SD_REQUIRE(pump_until(c, &l, "mount.state", "mounted", 1, 15000));

  SD_REQUIRE(sd_state_read_section(snap) == SD_OK);
  SD_REQUIRE(snap->count == 1);
  SD_CHECK(snap->entries[0].state == SD_STATE_S_MOUNTED);
  SD_CHECK(wcscmp(snap->entries[0].mount_id, L"m-1") == 0);
  SD_CHECK(wcscmp(snap->entries[0].remote_url, L"sftp://alice@new.test:22") == 0);
  SD_CHECK(snap->entries[0].letter >= L'A' && snap->entries[0].letter <= L'Z');
  ls[0] = (wchar_t)snap->entries[0].letter;
  ls[1] = 0;
  /* the icon is written by the work item the control thread runs after the event */
  end = sd_tick_ms() + 10000;
  while (!test_icon_exists(ls) && sd_tick_ms() < end)
    Sleep(100);
  SD_CHECK(test_icon_exists(ls));

  SD_REQUIRE(call(c, "unmount", "{\"mount_id\":\"m-1\"}", &res, &err) == SD_OK);
  sd_json_free(res);
  res = NULL;
  SD_REQUIRE(pump_until(c, &l, "mount.state", "unmounted", 1, 15000));
  /* the entry and the icon go once the control thread has run the posted work */
  end = sd_tick_ms() + 10000;
  while (sd_tick_ms() < end) {
    if (sd_state_read_section(snap) == SD_OK && snap->count == 0 && !test_icon_exists(ls))
      break;
    Sleep(100);
  }
  SD_CHECK(sd_state_read_section(snap) == SD_OK && snap->count == 0);
  SD_CHECK(!test_icon_exists(ls));
  free_log(&l);
  shutdown_agent(c);
  sd_ipc_close(c);
  sd_state_snapshot_free(snap);
  test_icon_cleanup();
}

/* M3 (03 §8.7): at agent start a profile with the default mount.network_location gets its NetHood folder
   (desktop.ini with the [ShellDrive] marker, target.lnk, placeholder file); a marked folder of a profile
   that no longer exists is removed; a folder without our marker is left alone. */
SD_TEST(m3_network_location_entries_at_start)
{
  static const char k_profile[] =
    "[profile]\r\nformat = 1\r\nid = 7f3c2a90d1e44b6c9a0e5b21c4d7f8aa\r\nname = Work Drive\r\n"
    "host = new.test\r\nuser = alice\r\n";
  wchar_t cfg[MAX_PATH], nh[MAX_PATH], dir[MAX_PATH], ini[MAX_PATH], path[MAX_PATH];
  sd_ipc_conn *c = NULL;
  HANDLE f;
  DWORD wrote = 0;
  wchar_t id[64];
  SD_REQUIRE(setup_agent(L"netloc", NULL, NULL, NULL));
  SD_REQUIRE(GetEnvironmentVariableW(L"SHELLDRIVE_TEST_CONFIG_DIR", cfg, MAX_PATH) > 0);
  SD_REQUIRE(GetEnvironmentVariableW(L"SHELLDRIVE_TEST_NETHOOD", nh, MAX_PATH) > 0);
  wcscat_s(cfg, MAX_PATH, L"\\profiles");
  CreateDirectoryW(cfg, NULL);
  _snwprintf_s(path, SD_COUNTOF(path), _TRUNCATE, L"%s\\7f3c2a90d1e44b6c9a0e5b21c4d7f8aa.ini", cfg);
  f = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  SD_REQUIRE(f != INVALID_HANDLE_VALUE);
  SD_REQUIRE(WriteFile(f, k_profile, (DWORD)strlen(k_profile), &wrote, NULL) && wrote == strlen(k_profile));
  CloseHandle(f);

  /* a stale entry of a profile that is gone, and a folder of someone else */
  _snwprintf_s(dir, SD_COUNTOF(dir), _TRUNCATE, L"%s\\Old Entry", nh);
  CreateDirectoryW(dir, NULL);
  _snwprintf_s(ini, SD_COUNTOF(ini), _TRUNCATE, L"%s\\desktop.ini", dir);
  WritePrivateProfileStringW(L"ShellDrive", L"profile", L"ffffffffffffffffffffffffffffffff", ini);
  _snwprintf_s(dir, SD_COUNTOF(dir), _TRUNCATE, L"%s\\Mine", nh);
  CreateDirectoryW(dir, NULL);

  /* the agent's start reconciles before it serves its first client */
  SD_REQUIRE(connect_as("ui", SD_IPC_CAP_PROMPTS_UI, &c) == SD_OK);
  _snwprintf_s(dir, SD_COUNTOF(dir), _TRUNCATE, L"%s\\Work Drive", nh);
  _snwprintf_s(ini, SD_COUNTOF(ini), _TRUNCATE, L"%s\\desktop.ini", dir);
  SD_CHECK(GetPrivateProfileStringW(L"ShellDrive", L"profile", L"", id, SD_COUNTOF(id), ini) > 0);
  SD_CHECK(wcscmp(id, L"7f3c2a90d1e44b6c9a0e5b21c4d7f8aa") == 0);
  _snwprintf_s(path, SD_COUNTOF(path), _TRUNCATE, L"%s\\target.lnk", dir);
  SD_CHECK(GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES);   /* [verify] the link target in a lab */
  SD_CHECK(GetFileAttributesW(dir) & FILE_ATTRIBUTE_READONLY);
  /* the placeholder the link points at while the drive is not mapped (8.7) */
  _snwprintf_s(path, SD_COUNTOF(path), _TRUNCATE,
               L"%s\\..\\places\\7f3c2a90d1e44b6c9a0e5b21c4d7f8aa\\Connect to Work Drive.sdmount", cfg);
  SD_CHECK(GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES);

  _snwprintf_s(path, SD_COUNTOF(path), _TRUNCATE, L"%s\\Old Entry", nh);
  SD_CHECK(GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES);
  _snwprintf_s(path, SD_COUNTOF(path), _TRUNCATE, L"%s\\Mine", nh);
  SD_CHECK(GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES);
  shutdown_agent(c);
  sd_ipc_close(c);
}

/* A UI that is the only client: the prompts reach it once each, answers route back, the mount
   completes, prompt.closed carries reason answered and answered_by ui. */
SD_TEST(m3_ui_only_prompts_and_answers)
{
  sd_ipc_conn *c = NULL;
  sd_json *res = NULL;
  sd_ipc_error err;
  evlog l;
  char pid[32], buf[160];
  memset(&l, 0, sizeof(l));
  SD_REQUIRE(setup_agent(L"ui", NULL, NULL, NULL));
  SD_REQUIRE(connect_as("ui", SD_IPC_CAP_PROMPTS_UI, &c) == SD_OK);
  subscribe(c, "\"prompt\",\"mount\"");
  SD_REQUIRE(call(c, "mount", "{\"adhoc\":{\"host\":\"new.test\",\"user\":\"alice\"}}", &res, &err) == SD_OK);
  SD_CHECK(sd_json_get_str(res, "mount_id") != NULL);
  sd_json_free(res);
  res = NULL;

  /* the host key first (trust on first use), then the password */
  SD_REQUIRE(pump_until(c, &l, "prompt.request", NULL, 1, 10000));
  prompt_id_of(&l, "prompt.request", 0, pid);
  SD_CHECK(strncmp(pid, "p-", 2) == 0);
  SD_CHECK(jbool3(ev_data(nth_ev(&l, "prompt.request", NULL, 0)), "queued", NULL) == 0);
  answer_json(buf, sizeof(buf), pid, "\"action\":\"accept\"");
  SD_REQUIRE(call(c, "prompt.answer", buf, &res, &err) == SD_OK);
  SD_CHECK(jbool3(res, "accepted", NULL) == 1);
  sd_json_free(res);
  res = NULL;

  SD_REQUIRE(pump_until(c, &l, "prompt.request", NULL, 2, 10000));
  prompt_id_of(&l, "prompt.request", 1, pid);
  SD_CHECK(strncmp(pid, "p-", 2) == 0);
  answer_json(buf, sizeof(buf), pid, "\"action\":\"answer\",\"responses\":[\"secret\"]");
  SD_REQUIRE(call(c, "prompt.answer", buf, &res, &err) == SD_OK);
  sd_json_free(res);
  res = NULL;

  SD_REQUIRE(pump_until(c, &l, "mount.state", "mounted", 1, 15000));
  SD_REQUIRE(pump_until(c, &l, "prompt.closed", NULL, 2, 5000));
  /* one copy of each request, both closed as answered by the UI */
  SD_CHECK(count_ev(&l, "prompt.request", NULL) == 2);
  SD_CHECK_STR(sd_json_get_str(ev_data(nth_ev(&l, "prompt.closed", NULL, 0)), "reason"), "answered");
  SD_CHECK_STR(sd_json_get_str(ev_data(nth_ev(&l, "prompt.closed", NULL, 1)), "answered_by"), "ui");
  free_log(&l);
  shutdown_agent(c);
  sd_ipc_close(c);
}

/* Deadline: nobody answers, so the agent rejects at the injected deadline (1.5 s) with timeout, and the
   mount fails with prompt_unavailable (exit 4). */
SD_TEST(m3_prompt_deadline_timeout)
{
  sd_ipc_conn *c = NULL;
  sd_json *res = NULL;
  sd_ipc_error err;
  evlog l;
  uint64_t t_mount;
  uint64_t elapsed;
  memset(&l, 0, sizeof(l));
  SD_REQUIRE(setup_agent(L"dead", L"1500", NULL, NULL));
  SD_REQUIRE(connect_as("ui", SD_IPC_CAP_PROMPTS_UI, &c) == SD_OK);
  subscribe(c, "\"prompt\",\"mount\"");
  t_mount = sd_tick_ms();
  SD_REQUIRE(call(c, "mount", "{\"adhoc\":{\"host\":\"new7.test\",\"user\":\"alice\"}}", &res, &err) == SD_OK);
  sd_json_free(res);
  res = NULL;
  SD_REQUIRE(pump_until(c, &l, "prompt.closed", NULL, 1, 12000));
  elapsed = sd_tick_ms() - t_mount;
  SD_CHECK(elapsed >= 1500);                   /* not before the deadline */
  SD_CHECK(elapsed < 6000);                    /* the sweep runs once a second */
  SD_CHECK_STR(sd_json_get_str(ev_data(nth_ev(&l, "prompt.closed", NULL, 0)), "reason"), "timeout");
  SD_CHECK(sd_json_get_str(ev_data(nth_ev(&l, "prompt.closed", NULL, 0)), "answered_by") == NULL);
  SD_REQUIRE(pump_until(c, &l, "mount.state", "failed", 1, 5000));
  SD_CHECK_STR(sd_json_get_str(sd_json_get(ev_data(nth_ev(&l, "mount.state", "failed", 0)), "error"), "code"),
               "prompt_unavailable");
  SD_CHECK_EQ_INT((int)jint3(sd_json_get(ev_data(nth_ev(&l, "mount.state", "failed", 0)), "error"), "exit_code", NULL), 4);
  free_log(&l);
  shutdown_agent(c);
  sd_ipc_close(c);
}

/* No routing at all (test hook: a locked session): the queue holds 3, the oldest is evicted with
   superseded, a UI that subscribes later gets the rest with queued:true, and rejects end the mounts. */
SD_TEST(m3_queue_evicts_and_drains_to_ui)
{
  sd_ipc_conn *c = NULL, *u = NULL;
  sd_json *res = NULL;
  sd_ipc_error err;
  evlog cl, ul;
  char pid[32], buf[160];
  int k;
  memset(&cl, 0, sizeof(cl));
  memset(&ul, 0, sizeof(ul));
  SD_REQUIRE(setup_agent(L"queue", NULL, L"3", L"1"));
  SD_REQUIRE(connect_as("cli", SD_IPC_CAP_PROMPTS_CONSOLE, &c) == SD_OK);
  for (k = 1; k <= 4; k++) {
    char params[96], n[2];
    strcpy_s(params, sizeof(params), "{\"adhoc\":{\"host\":\"q");
    n[0] = (char)('0' + k);
    n[1] = 0;
    strcat_s(params, sizeof(params), n);
    strcat_s(params, sizeof(params), ".test\",\"user\":\"alice\"}}");
    SD_REQUIRE(call(c, "mount", params, &res, &err) == SD_OK);
    sd_json_free(res);
    res = NULL;
  }
  /* the fourth raise evicts the oldest queued prompt */
  SD_REQUIRE(pump_until(c, &cl, "prompt.closed", NULL, 1, 10000));
  SD_CHECK_STR(sd_json_get_str(ev_data(nth_ev(&cl, "prompt.closed", NULL, 0)), "reason"), "superseded");
  SD_CHECK(count_ev(&cl, "prompt.request", NULL) == 0);       /* routing is off */
  SD_REQUIRE(call(c, "prompt.list", "{}", &res, &err) == SD_OK);
  SD_CHECK_EQ_U64(sd_json_count(sd_json_get(res, "prompts")), 3);
  {
    const sd_json *p0 = sd_json_at(sd_json_get(res, "prompts"), 0);
    SD_CHECK(jbool3(p0, "queued", NULL) == 1);
    SD_CHECK(jint3(p0, "deadline_ms", NULL) >= 0);
  }
  sd_json_free(res);
  res = NULL;
  {
    int waited = 0;
    while (list_mounts(c) != 3 && waited < 5000) {      /* the failed mount is torn down by the control thread */
      Sleep(200);
      waited += 200;
    }
  }
  SD_CHECK(list_mounts(c) == 3);

  /* a UI subscribes: the three queued prompts are drained, oldest first */
  SD_REQUIRE(connect_as("ui", SD_IPC_CAP_PROMPTS_UI, &u) == SD_OK);
  subscribe(u, "\"prompt\"");
  SD_REQUIRE(pump_until(u, &ul, "prompt.request", NULL, 3, 10000));
  SD_CHECK(count_ev(&ul, "prompt.request", NULL) == 3);
  {
    int i;
    for (i = 0; i < 3; i++)
      SD_CHECK(jbool3(ev_data(nth_ev(&ul, "prompt.request", NULL, i)), "queued", NULL) == 1);
  }
  /* reject each one: the mounts end */
  for (k = 0; k < 3; k++) {
    prompt_id_of(&ul, "prompt.request", k, pid);
    answer_json(buf, sizeof(buf), pid, "\"action\":\"reject\"");
    SD_REQUIRE(call(u, "prompt.answer", buf, &res, &err) == SD_OK);
    sd_json_free(res);
    res = NULL;
  }
  SD_REQUIRE(pump_until(u, &ul, "prompt.closed", NULL, 3, 10000));
  SD_CHECK_STR(sd_json_get_str(ev_data(nth_ev(&ul, "prompt.closed", NULL, 2)), "answered_by"), "ui");
  {
    int waited = 0;
    while (list_mounts(c) != 0 && waited < 10000) {
      Sleep(200);
      waited += 200;
    }
  }
  SD_CHECK(list_mounts(c) == 0);
  free_log(&cl);
  free_log(&ul);
  shutdown_agent(c);
  sd_ipc_close(u);
  sd_ipc_close(c);
}

/* decision 5: the initiator goes away while a UI is subscribed: its prompt keeps routing to the UI,
   which gets exactly one copy and decides; the initiator's copy went to the (gone) initiator only. */
SD_TEST(m3_initiator_gone_keeps_prompts_for_ui)
{
  sd_ipc_conn *c = NULL, *u = NULL;
  sd_json *res = NULL;
  sd_ipc_error err;
  evlog ul;
  char pid[32], buf[160];
  memset(&ul, 0, sizeof(ul));
  SD_REQUIRE(setup_agent(L"keep", NULL, NULL, NULL));
  SD_REQUIRE(connect_as("ui", SD_IPC_CAP_PROMPTS_UI, &u) == SD_OK);
  subscribe(u, "\"prompt\",\"mount\"");
  SD_REQUIRE(connect_as("cli", SD_IPC_CAP_PROMPTS_CONSOLE, &c) == SD_OK);
  SD_REQUIRE(call(c, "mount", "{\"adhoc\":{\"host\":\"new3.test\",\"user\":\"alice\"}}", &res, &err) == SD_OK);
  sd_json_free(res);
  res = NULL;
  SD_REQUIRE(pump_until(u, &ul, "prompt.request", NULL, 1, 10000));
  sd_ipc_close(c);
  c = NULL;
  Sleep(300);
  pump_idle(u, &ul, 300);
  SD_CHECK(count_ev(&ul, "prompt.request", NULL) == 1);
  prompt_id_of(&ul, "prompt.request", 0, pid);
  answer_json(buf, sizeof(buf), pid, "\"action\":\"reject\"");
  SD_REQUIRE(call(u, "prompt.answer", buf, &res, &err) == SD_OK);
  SD_CHECK(jbool3(res, "accepted", NULL) == 1);
  sd_json_free(res);
  res = NULL;
  SD_REQUIRE(pump_until(u, &ul, "mount.state", "failed", 1, 10000));
  SD_CHECK_STR(sd_json_get_str(ev_data(nth_ev(&ul, "prompt.closed", NULL, 0)), "answered_by"), "ui");
  free_log(&ul);
  shutdown_agent(u);
  sd_ipc_close(u);
}

/* decision 5, no prompt-capable client left: the initiator's disconnect cancels its mount. */
SD_TEST(m3_initiator_gone_without_ui_cancels)
{
  sd_ipc_conn *c = NULL, *x = NULL;
  sd_json *res = NULL;
  sd_ipc_error err;
  evlog l;
  memset(&l, 0, sizeof(l));
  SD_REQUIRE(setup_agent(L"cancel", NULL, NULL, NULL));
  SD_REQUIRE(connect_as("cli", SD_IPC_CAP_PROMPTS_CONSOLE, &c) == SD_OK);
  SD_REQUIRE(call(c, "mount", "{\"adhoc\":{\"host\":\"new4.test\",\"user\":\"alice\"}}", &res, &err) == SD_OK);
  sd_json_free(res);
  res = NULL;
  SD_REQUIRE(pump_until(c, &l, "prompt.request", NULL, 1, 10000));
  sd_ipc_close(c);
  c = NULL;
  SD_REQUIRE(connect_as("cli", 0, &x) == SD_OK);
  {
    int waited = 0;
    while (list_mounts(x) != 0 && waited < 10000) {
      Sleep(200);
      waited += 200;
    }
  }
  SD_CHECK(list_mounts(x) == 0);
  free_log(&l);
  shutdown_agent(x);
  sd_ipc_close(x);
}

/* The read-only methods and the reply shapes that changed in M3, plus the hello features. */
SD_TEST(m3_new_methods_and_list_warnings)
{
  sd_ipc_conn *c = NULL;
  sd_json *res = NULL;
  sd_ipc_error err;
  char cur[80];
  SD_REQUIRE(setup_agent(L"meth", NULL, NULL, NULL));
  SD_REQUIRE(connect_as("cli", 0, &c) == SD_OK);
  SD_CHECK(sd_ipc_conn_has_feature(c, "status"));
  SD_CHECK(sd_ipc_conn_has_feature(c, "log.tail"));
  SD_CHECK(sd_ipc_conn_has_feature(c, "selftest"));
  SD_CHECK(sd_ipc_conn_has_feature(c, "prompt.list"));
  SD_CHECK(!sd_ipc_conn_has_feature(c, "update.check"));    /* M4 */

  /* selftest: four checks, all passing in a test root */
  SD_REQUIRE(call(c, "selftest", "{}", &res, &err) == SD_OK);
  SD_CHECK(jbool3(res, "healthy", NULL) == 1);
  SD_CHECK_EQ_U64(sd_json_count(sd_json_get(res, "checks")), 4);
  sd_json_free(res);
  res = NULL;

  /* status: usage without a target, mount_not_found for an unknown one, stats unsupported */
  SD_CHECK(call(c, "status", "{}", &res, &err) != SD_OK);
  SD_CHECK_STR(err.code, "usage");
  SD_CHECK_EQ_INT(err.exit_code, 2);
  SD_CHECK(call(c, "status", "{\"mount_id\":\"m-99\"}", &res, &err) != SD_OK);
  SD_CHECK_STR(err.code, "mount_not_found");
  /* stats of a mount are checked in m3_refresh_cache_attach_and_status_stats; m-1 does not exist here */
  SD_CHECK(call(c, "status", "{\"mount_id\":\"m-1\",\"stats\":true}", &res, &err) != SD_OK);
  SD_CHECK_STR(err.code, "mount_not_found");

  /* config.reload: user scope reloads, machine scope belongs to the service */
  SD_REQUIRE(call(c, "config.reload", "{}", &res, &err) == SD_OK);
  SD_CHECK(jint3(sd_json_get(res, "profiles"), "loaded", NULL) == 0);
  SD_CHECK(sd_json_get_str(res, "settings") != NULL);
  sd_json_free(res);
  res = NULL;
  SD_CHECK(call(c, "config.reload", "{\"scope\":\"machine\"}", &res, &err) != SD_OK);
  SD_CHECK_STR(err.code, "unsupported");
  SD_CHECK(call(c, "config.reload", "{\"scope\":\"both\"}", &res, &err) != SD_OK);
  SD_CHECK_STR(err.code, "usage");

  /* log.tail: the start-up records, a cursor that resumes, a foreign cursor that resets */
  SD_REQUIRE(call(c, "log.tail", "{\"lines\":5}", &res, &err) == SD_OK);
  SD_CHECK(sd_json_count(sd_json_get(res, "records")) >= 1);
  SD_CHECK(sd_json_count(sd_json_get(res, "records")) <= 5);
  SD_CHECK(jbool3(res, "reset", NULL) == 0);
  {
    const char *cs = sd_json_get_str(res, "cursor");
    SD_REQUIRE(cs != NULL);
    strcpy_s(cur, sizeof(cur), cs);
  }
  sd_json_free(res);
  res = NULL;
  {
    char params[120];
    strcpy_s(params, sizeof(params), "{\"cursor\":\"");
    strcat_s(params, sizeof(params), cur);
    strcat_s(params, sizeof(params), "\"}");
    SD_REQUIRE(call(c, "log.tail", params, &res, &err) == SD_OK);
    SD_CHECK(jbool3(res, "reset", NULL) == 0);
    sd_json_free(res);
    res = NULL;
  }
  SD_REQUIRE(call(c, "log.tail", "{\"cursor\":\"0.0.1\"}", &res, &err) == SD_OK);
  SD_CHECK(jbool3(res, "reset", NULL) == 1);
  sd_json_free(res);
  res = NULL;
  SD_REQUIRE(call(c, "log.tail", "{\"component\":\"agent\",\"level\":\"info\",\"lines\":50}", &res, &err) == SD_OK);
  {
    size_t i, n = sd_json_count(sd_json_get(res, "records"));
    for (i = 0; i < n; i++) {
      SD_CHECK_STR(sd_json_get_str(sd_json_at(sd_json_get(res, "records"), i), "component"), "agent");
    }
  }
  sd_json_free(res);
  res = NULL;
  SD_CHECK(call(c, "log.tail", "{\"lines\":0}", &res, &err) != SD_OK);
  SD_CHECK_STR(err.code, "usage");
  SD_CHECK(call(c, "log.tail", "{\"level\":\"loud\"}", &res, &err) != SD_OK);
  SD_CHECK_STR(err.code, "usage");
  SD_CHECK(call(c, "log.tail", "{\"follow\":true}", &res, &err) != SD_OK);
  SD_CHECK_STR(err.code, "unsupported");

  /* list carries the warnings array (empty here); prompt.list is empty */
  SD_REQUIRE(call(c, "list", "{}", &res, &err) == SD_OK);
  SD_CHECK(sd_json_type_of(sd_json_get(res, "warnings")) == SD_JSON_ARRAY);
  sd_json_free(res);
  res = NULL;
  SD_REQUIRE(call(c, "prompt.list", "{}", &res, &err) == SD_OK);
  SD_CHECK_EQ_U64(sd_json_count(sd_json_get(res, "prompts")), 0);
  sd_json_free(res);
  res = NULL;

  /* methods that are not in this build keep the unknown-method answer */
  SD_CHECK(call(c, "refresh", "{}", &res, &err) != SD_OK);
  SD_CHECK_STR(err.code, "usage");
  shutdown_agent(c);
  sd_ipc_close(c);
}


/* ---- M3 methods of the agent (profile.test, refresh, cache.clear, mount.attach_info, status stats and
   proxy_legs, unmount force), the config watch and agent.stopping ---- */

/* profile.test blocks until the test ends, so each call runs on its own thread with its own connection; the
   prompts are answered from the UI connection on the main thread. */
typedef struct ptest_arg {
  sd_ipc_conn *c;
  const char *params;
  sd_json *res;
  sd_ipc_error err;
  sd_err rc;
} ptest_arg;

static DWORD WINAPI ptest_thread(void *p)
{
  ptest_arg *a = (ptest_arg *)p;
  a->res = NULL;
  memset(&a->err, 0, sizeof(a->err));
  a->rc = sd_ipc_call_raw(a->c, "profile.test", a->params, strlen(a->params), 30000, &a->res, &a->err);
  return 0;
}

/* Answers the TOFU prompt (accept) and the password prompt ("secret") of one connect, from conn u. `first` is
   the 1-based index of the TOFU prompt among the prompt.request events seen so far. */
#define M3_HREQ(x) do { if (!(x)) return 0; } while (0)

static int answer_tofu_and_password(sd_ipc_conn *u, evlog *ul, int first)
{
  sd_json *res = NULL;
  sd_ipc_error err;
  char pid[32], buf[160];
  M3_HREQ(pump_until(u, ul, "prompt.request", NULL, first, 10000));
  prompt_id_of(ul, "prompt.request", first - 1, pid);
  answer_json(buf, sizeof(buf), pid, "\"action\":\"accept\"");
  M3_HREQ(call(u, "prompt.answer", buf, &res, &err) == SD_OK);
  sd_json_free(res);
  res = NULL;
  M3_HREQ(pump_until(u, ul, "prompt.request", NULL, first + 1, 10000));
  prompt_id_of(ul, "prompt.request", first, pid);
  answer_json(buf, sizeof(buf), pid, "\"action\":\"answer\",\"responses\":[\"secret\"]");
  M3_HREQ(call(u, "prompt.answer", buf, &res, &err) == SD_OK);
  sd_json_free(res);
  return 1;
}

SD_TEST(m3_profile_test_results_and_errors)
{
  sd_ipc_conn *u = NULL, *c = NULL;
  sd_json *res = NULL;
  sd_ipc_error err;
  evlog ul;
  ptest_arg a, b;
  HANDLE th;
  memset(&ul, 0, sizeof(ul));
  SD_REQUIRE(setup_agent(L"ptest", NULL, NULL, NULL));
  SD_REQUIRE(connect_as("ui", SD_IPC_CAP_PROMPTS_UI, &u) == SD_OK);
  subscribe(u, "\"prompt\"");
  SD_REQUIRE(connect_as("cli", SD_IPC_CAP_PROMPTS_CONSOLE, &c) == SD_OK);

  /* usage and unknown profiles are answered at once */
  SD_CHECK(call(c, "profile.test", "{}", &res, &err) != SD_OK);
  SD_CHECK_STR(err.code, "usage");
  SD_CHECK(call(c, "profile.test", "{\"profile_id\":\"00000000000000000000000000000000\"}", &res, &err) != SD_OK);
  SD_CHECK_STR(err.code, "profile_not_found");
  SD_CHECK_EQ_INT(err.exit_code, 3);

  /* a host that answers: TOFU and the password through the broker, then the result of the test */
  memset(&a, 0, sizeof(a));
  a.c = c;
  a.params = "{\"adhoc\":{\"host\":\"probe1.test\",\"user\":\"alice\"}}";
  th = CreateThread(NULL, 0, ptest_thread, &a, 0, NULL);
  SD_REQUIRE(th != NULL);
  SD_REQUIRE(answer_tofu_and_password(u, &ul, 1));
  SD_REQUIRE(WaitForSingleObject(th, 20000) == WAIT_OBJECT_0);
  CloseHandle(th);
  SD_REQUIRE(a.rc == SD_OK && a.res != NULL);
  SD_CHECK_STR(sd_json_get_str(a.res, "host"), "probe1.test");
  SD_CHECK_STR(sd_json_get_str(a.res, "remote_path"), "/home/fake");
  SD_CHECK_STR(sd_json_get_str(a.res, "hostkey_fingerprint"), "SHA256:K3l2sJ0pAqv0d8ZbFakeFakeFakeFakeFakeFake0Q");
  SD_CHECK_STR(sd_json_get_str(sd_json_get(a.res, "algorithms"), "kex"), "curve25519-sha256");
  SD_CHECK_STR(sd_json_get_str(sd_json_get(a.res, "algorithms"), "hostkey"), "ssh-ed25519");
  SD_CHECK(jbool3(a.res, "legacy", NULL) == 0);
  sd_json_free(a.res);
  a.res = NULL;

  /* a failing realpath is a failed test with its code; a test is not a mount for `list` */
  memset(&b, 0, sizeof(b));
  b.c = c;
  b.params = "{\"adhoc\":{\"host\":\"probefail1.test\",\"user\":\"alice\"}}";
  th = CreateThread(NULL, 0, ptest_thread, &b, 0, NULL);
  SD_REQUIRE(th != NULL);
  SD_REQUIRE(answer_tofu_and_password(u, &ul, 3));
  SD_REQUIRE(WaitForSingleObject(th, 20000) == WAIT_OBJECT_0);
  CloseHandle(th);
  SD_CHECK(b.rc != SD_OK);
  SD_CHECK(b.res == NULL);
  SD_CHECK(b.err.code[0] != 0);
  SD_CHECK(list_mounts(c) == 0);
  free_log(&ul);
  shutdown_agent(c);
  sd_ipc_close(u);
  sd_ipc_close(c);
}

/* Waits for an event named `name` (and data.what == what when given) for at most ms. */
static int wait_event(sd_ipc_conn *c, const char *name, const char *what, DWORD ms, sd_json **out)
{
  uint64_t end = sd_tick_ms() + ms;
  *out = NULL;
  for (;;) {
    sd_json *ev = NULL;
    uint64_t now = sd_tick_ms();
    DWORD left = now >= end ? 0 : (DWORD)(end - now);
    const char *w;
    if (left == 0 || sd_ipc_next_event(c, left, &ev) != SD_OK)
      return 0;
    w = sd_json_get_str(ev_data(ev), "what");
    if (ev_named(ev, name) && (what == NULL || (w && strcmp(w, what) == 0))) {
      *out = ev;
      return 1;
    }
    sd_json_free(ev);
  }
}

static int write_text_file(const wchar_t *path, const char *text)
{
  DWORD got = 0;
  size_t n = strlen(text);
  HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  M3_HREQ(h != INVALID_HANDLE_VALUE);
  M3_HREQ(WriteFile(h, text, (DWORD)n, &got, NULL) && got == n);
  CloseHandle(h);
  return 1;
}

SD_TEST(m3_config_changed_and_agent_stopping)
{
  sd_ipc_conn *c = NULL;
  sd_json *ev = NULL, *res = NULL;
  sd_ipc_error err;
  wchar_t root[MAX_PATH], path[MAX_PATH];
  SD_REQUIRE(setup_agent(L"cfgw", NULL, NULL, NULL));
  SD_REQUIRE(GetEnvironmentVariableW(L"SHELLDRIVE_TEST_CONFIG_DIR", root, MAX_PATH) > 0);
  SD_REQUIRE(connect_as("cli", 0, &c) == SD_OK);
  Sleep(200);
  /* the profiles folder appears (the watch picks it up); a profile file change is reported within 2 s */
  wcscpy_s(path, MAX_PATH, root);
  wcscat_s(path, MAX_PATH, L"\\profiles");
  CreateDirectoryW(path, NULL);
  Sleep(300);
  wcscat_s(path, MAX_PATH, L"\\watch1.ini");
  SD_REQUIRE(write_text_file(path, "[profile]\nname=watch1\nhost=watch.test\n"));
  SD_CHECK(wait_event(c, "config.changed", "profiles", 2000, &ev));
  sd_json_free(ev);
  ev = NULL;
  /* settings.ini in the root: one event for "settings" */
  wcscpy_s(path, MAX_PATH, root);
  wcscat_s(path, MAX_PATH, L"\\settings.ini");
  SD_REQUIRE(write_text_file(path, "[log]\nlevel=info\n"));
  SD_CHECK(wait_event(c, "config.changed", "settings", 2000, &ev));
  sd_json_free(ev);
  ev = NULL;
  /* agent.shutdown: agent.stopping arrives with the reason */
  SD_REQUIRE(call(c, "agent.shutdown", "{}", &res, &err) == SD_OK);
  sd_json_free(res);
  SD_CHECK(wait_event(c, "agent.stopping", NULL, 3000, &ev));
  if (ev) {
    SD_CHECK_STR(sd_json_get_str(ev_data(ev), "reason"), "request");
    sd_json_free(ev);
  }
  sd_ipc_close(c);
}

/* A mount through the broker (TOFU and the password, answered from the same UI connection). */
static int mount_stat_host(sd_ipc_conn *c, evlog *l, const char *host)
{
  sd_json *res = NULL;
  sd_ipc_error err;
  char params[160];
  strcpy_s(params, sizeof(params), "{\"adhoc\":{\"host\":\"");
  strcat_s(params, sizeof(params), host);
  strcat_s(params, sizeof(params), "\",\"user\":\"alice\"}}");
  M3_HREQ(call(c, "mount", params, &res, &err) == SD_OK);
  sd_json_free(res);
  res = NULL;
  M3_HREQ(answer_tofu_and_password(c, l, 1));
  M3_HREQ(pump_until(c, l, "mount.state", "mounted", 1, 15000));
  return 1;
}

SD_TEST(m3_refresh_cache_attach_and_status_stats)
{
  sd_ipc_conn *c = NULL;
  sd_json *res = NULL;
  const sd_json *st = NULL;
  sd_ipc_error err;
  evlog l;
  memset(&l, 0, sizeof(l));
  SD_REQUIRE(setup_agent(L"rfsh", NULL, NULL, NULL));
  SD_REQUIRE(connect_as("ui", SD_IPC_CAP_PROMPTS_UI, &c) == SD_OK);
  subscribe(c, "\"prompt\",\"mount\"");
  SD_REQUIRE(mount_stat_host(c, &l, "stat2.test"));

  /* status: stats (session, pool, cache) and proxy_legs; without stats the stats object is absent */
  SD_REQUIRE(call(c, "status", "{\"mount_id\":\"m-1\",\"stats\":true}", &res, &err) == SD_OK);
  SD_CHECK_STR(sd_json_get_str(sd_json_get(res, "mount"), "state"), "mounted");
  st = sd_json_get(res, "stats");
  SD_REQUIRE(st != NULL);
  SD_CHECK(jbool3(sd_json_get(st, "session"), "present", NULL) == 1);
  SD_CHECK(jint3(sd_json_get(st, "session"), "srtt_ms", NULL) == 12);
  SD_CHECK(jint3(sd_json_get(st, "session"), "rx_bytes", NULL) == 4096);
  SD_CHECK_EQ_U64(sd_json_count(sd_json_get(sd_json_get(st, "pool"), "members")), 1);
  SD_CHECK(jbool3(sd_json_get(st, "cache"), "vfs", NULL) == 1);
  SD_CHECK(jint3(sd_json_get(st, "cache"), "hits", NULL) == 7);
  SD_CHECK_EQ_U64(sd_json_count(sd_json_get(res, "proxy_legs")), 0);
  sd_json_free(res);
  res = NULL;
  SD_REQUIRE(call(c, "status", "{\"mount_id\":\"m-1\"}", &res, &err) == SD_OK);
  SD_CHECK(sd_json_get(res, "stats") == NULL);
  SD_CHECK(sd_json_get(res, "proxy_legs") != NULL);
  sd_json_free(res);
  res = NULL;

  /* refresh: a path (or the whole mount), usage without a path, mount_not_found for an unknown mount */
  SD_REQUIRE(call(c, "refresh", "{\"mount_id\":\"m-1\",\"path\":\"/a/b\"}", &res, &err) == SD_OK);
  SD_CHECK(jbool3(res, "refreshed", NULL) == 1);
  sd_json_free(res);
  res = NULL;
  SD_CHECK(call(c, "refresh", "{\"mount_id\":\"m-1\",\"path\":\"\"}", &res, &err) == SD_OK);
  sd_json_free(res);
  res = NULL;
  SD_CHECK(call(c, "refresh", "{\"mount_id\":\"m-1\"}", &res, &err) != SD_OK);
  SD_CHECK_STR(err.code, "usage");
  SD_CHECK(call(c, "refresh", "{\"mount_id\":\"m-9\",\"path\":\"/\"}", &res, &err) != SD_OK);
  SD_CHECK_STR(err.code, "mount_not_found");

  /* cache.clear: one mount; usage without a selector; mount_not_found for an unknown profile */
  SD_REQUIRE(call(c, "cache.clear", "{\"mount_id\":\"m-1\"}", &res, &err) == SD_OK);
  SD_CHECK(jint3(res, "cleared", NULL) == 1);
  sd_json_free(res);
  res = NULL;
  SD_CHECK(call(c, "cache.clear", "{}", &res, &err) != SD_OK);
  SD_CHECK_STR(err.code, "usage");
  SD_CHECK(call(c, "cache.clear", "{\"profile_id\":\"zz\"}", &res, &err) != SD_OK);
  SD_CHECK_STR(err.code, "mount_not_found");

  /* mount.attach_info: the backend and the state; no WebDAV member for a Dokany mount */
  SD_REQUIRE(call(c, "mount.attach_info", "{\"mount_id\":\"m-1\"}", &res, &err) == SD_OK);
  SD_CHECK_STR(sd_json_get_str(res, "backend"), "dokany");
  SD_CHECK(jbool3(res, "mounted", NULL) == 1);
  SD_CHECK(sd_json_get(res, "webdav") == NULL);
  sd_json_free(res);
  res = NULL;
  SD_CHECK(call(c, "mount.attach_info", "{\"mount_id\":\"m-9\"}", &res, &err) != SD_OK);
  SD_CHECK_STR(err.code, "mount_not_found");

  /* unmount with force: the mount ends like any other unmount */
  SD_REQUIRE(call(c, "unmount", "{\"mount_id\":\"m-1\",\"force\":true}", &res, &err) == SD_OK);
  sd_json_free(res);
  res = NULL;
  SD_CHECK(pump_until(c, &l, "mount.state", "unmounted", 1, 10000));
  SD_CHECK(list_mounts(c) == 0);
  free_log(&l);
  shutdown_agent(c);
  sd_ipc_close(c);
}

SD_TEST(m3_cache_clear_refuses_queued_writes)
{
  sd_ipc_conn *c = NULL;
  sd_json *res = NULL;
  const sd_json *st = NULL;
  sd_ipc_error err;
  evlog l;
  memset(&l, 0, sizeof(l));
  /* the test host reports 4096 bytes of write-behind data queued (host_fake_backend.c) */
  SetEnvironmentVariableW(L"SHELLDRIVE_TEST_WB_DIRTY", L"4096");
  SD_REQUIRE(setup_agent(L"wbdirty", NULL, NULL, NULL));
  SD_REQUIRE(connect_as("ui", SD_IPC_CAP_PROMPTS_UI, &c) == SD_OK);
  subscribe(c, "\"prompt\",\"mount\"");
  SD_REQUIRE(mount_stat_host(c, &l, "stat3.test"));
  /* refused with busy (exit 8) while the data is queued; nothing is dropped */
  SD_CHECK(call(c, "cache.clear", "{\"mount_id\":\"m-1\"}", &res, &err) != SD_OK);
  SD_CHECK_STR(err.code, "write_behind_pending");
  SD_CHECK_EQ_INT(err.exit_code, 8);
  SD_CHECK(res == NULL);
  /* forced: the caches go, the queued bytes stay queued */
  SD_REQUIRE(call(c, "cache.clear", "{\"mount_id\":\"m-1\",\"force\":true}", &res, &err) == SD_OK);
  SD_CHECK(jint3(res, "cleared", NULL) == 1);
  sd_json_free(res);
  res = NULL;
  SD_REQUIRE(call(c, "status", "{\"mount_id\":\"m-1\",\"stats\":true}", &res, &err) == SD_OK);
  st = sd_json_get(res, "stats");
  SD_REQUIRE(st != NULL);
  SD_CHECK(jint3(sd_json_get(st, "cache"), "write_behind_bytes", NULL) == 4096);
  sd_json_free(res);
  res = NULL;
  SD_REQUIRE(call(c, "unmount", "{\"mount_id\":\"m-1\",\"force\":true}", &res, &err) == SD_OK);
  sd_json_free(res);
  res = NULL;
  SD_CHECK(pump_until(c, &l, "mount.state", "unmounted", 1, 10000));
  free_log(&l);
  shutdown_agent(c);
  sd_ipc_close(c);
  SetEnvironmentVariableW(L"SHELLDRIVE_TEST_WB_DIRTY", NULL);
}
