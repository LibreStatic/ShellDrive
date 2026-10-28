/* shelldrive diag bench <X:> [--scenario NAME] [--size MIB] [--write-mode through|behind] [--json]
 * (alias: shelldrive bench ...; 03 §6.1, 02 §11). A developer and support benchmark of a mounted drive
 * with plain Win32 file APIs: sequential writes (1 MiB and 64 KiB blocks), a sequential read, creation of
 * small files, and the latency of opening an existing file. The run creates one new folder on the drive
 * (CreateDirectory fails on an existing name, so no user file is replaced), writes only files inside it, and
 * removes them and the folder afterwards. A read-only drive is refused before anything is written.
 *
 * The agent does not report the mount's own write mode, so the report states the mode given with
 * --write-mode (default "through") and says that it is declared. The pool size comes from the agent's
 * list when an agent runs; it is null otherwise. Reads may be served from the memory cache, which the run
 * does not clear; the report says so. User-facing text comes from the cli catalog; JSON keys stay English. */
#include <windows.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "cli_int.h"
#include "sd_base/sd_json.h"
#include "sd_base/sd_mem.h"
#include "sd_ipc/sd_ipc.h"
#include "sd_l10n/sd_l10n.h"
#include "sd_l10n_cli_ids.h"

#define BENCH_MIB_DEFAULT   256u
#define BENCH_BLOCK_1M      (1024u * 1024u)
#define BENCH_BLOCK_64K     (64u * 1024u)
#define BENCH_SMALL_FILES   1000u
#define BENCH_SMALL_BYTES   4096u
#define BENCH_OPEN_SAMPLES  50u

#ifndef FILE_READ_ONLY_VOLUME
#define FILE_READ_ONLY_VOLUME 0x00080000
#endif

enum { BS_SEQ_W1M, BS_SEQ_W64K, BS_SEQ_R, BS_SMALL, BS_OPEN, BS_COUNT };
static const wchar_t *const k_scenario_name[BS_COUNT] = { L"seq-write", L"seq-write-64k", L"seq-read", L"small-files", L"open" };

typedef struct bench_seq { uint64_t bytes; uint32_t block; double seconds, mbps; } bench_seq;
typedef struct bench_open { double attr_med, attr_p95, read_med, read_p95; } bench_open;

typedef struct bench_ctx {
  wchar_t dir[MAX_PATH];         /* the temporary folder: <root>.shelldrive-bench-<pid>-<tick> */
  unsigned char *buf;            /* 1 MiB transfer buffer */
  uint64_t total;                /* bytes per sequential transfer */
  uint32_t size_mib;
  uint32_t small_made;           /* small files that exist (removed afterwards) */
  int seq_written;
  int ran[BS_COUNT];
  bench_seq seq[3];             /* BS_SEQ_W1M, BS_SEQ_W64K, BS_SEQ_R */
  double small_seconds;
  bench_open open;
} bench_ctx;

typedef struct mount_info {
  int found, read_only, pool;
  char backend[32];
} mount_info;

static double now_s(void)
{
  static LARGE_INTEGER freq;
  LARGE_INTEGER t;
  if (freq.QuadPart == 0)
    QueryPerformanceFrequency(&freq);
  QueryPerformanceCounter(&t);
  return (double)t.QuadPart / (double)freq.QuadPart;
}

static void join_path(wchar_t *out, size_t cch, const bench_ctx *c, const wchar_t *name)
{
  _snwprintf_s(out, cch, _TRUNCATE, L"%s\\%s", c->dir, name);
}

/* Creates `name` with CREATE_NEW (an existing file is never replaced) and writes `total` bytes in
   `block` pieces. With seconds != NULL the time from the first write to the close is measured, so the
   figure includes the flush of the cache on close. Returns 0 or the Win32 error. */
static DWORD write_file(const bench_ctx *c, const wchar_t *name, uint64_t total, uint32_t block, double *seconds)
{
  wchar_t path[MAX_PATH];
  HANDLE h;
  DWORD err = 0;
  double t0 = 0.0;
  uint64_t done = 0;
  join_path(path, MAX_PATH, c, name);
  h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE)
    return GetLastError();
  if (seconds)
    t0 = now_s();
  while (done < total) {
    DWORD n = 0;
    if (!WriteFile(h, c->buf, block, &n, NULL) || n != block) {
      err = GetLastError();
      if (err == 0) err = ERROR_WRITE_FAULT;
      break;
    }
    done += block;
  }
  if (!CloseHandle(h) && err == 0)
    err = GetLastError();
  if (seconds)
    *seconds = now_s() - t0;
  return err;
}

/* Reads `name` from the start to its end in `block` pieces; the byte count must equal `expect`. */
static DWORD read_file(const bench_ctx *c, const wchar_t *name, uint64_t expect, uint32_t block, bench_seq *out)
{
  wchar_t path[MAX_PATH];
  HANDLE h;
  DWORD err = 0;
  uint64_t total = 0;
  double t0;
  join_path(path, MAX_PATH, c, name);
  h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
  if (h == INVALID_HANDLE_VALUE)
    return GetLastError();
  t0 = now_s();
  for (;;) {
    DWORD n = 0;
    if (!ReadFile(h, c->buf, block, &n, NULL)) {
      err = GetLastError();
      break;
    }
    if (n == 0)
      break;
    total += n;
  }
  if (!CloseHandle(h) && err == 0)
    err = GetLastError();
  out->seconds = now_s() - t0;
  out->bytes = total;
  out->block = block;
  out->mbps = out->seconds > 0.0 ? ((double)total / 1048576.0) / out->seconds : 0.0;
  if (err == 0 && total != expect)
    err = ERROR_READ_FAULT;
  return err;
}

static DWORD scenario_seq_write(bench_ctx *c, uint32_t block, bench_seq *out, const wchar_t *name)
{
  DWORD err = write_file(c, name, c->total, block, &out->seconds);
  out->bytes = c->total;
  out->block = block;
  out->mbps = out->seconds > 0.0 ? ((double)c->total / 1048576.0) / out->seconds : 0.0;
  return err;
}

static DWORD scenario_small_files(bench_ctx *c)
{
  double t0 = now_s();
  DWORD err = 0;
  uint32_t i;
  for (i = 0; i < BENCH_SMALL_FILES; i++) {
    wchar_t name[32];
    _snwprintf_s(name, SD_COUNTOF(name), _TRUNCATE, L"s%04u.bin", (unsigned)i);
    err = write_file(c, name, BENCH_SMALL_BYTES, BENCH_SMALL_BYTES, NULL);
    if (err)
      break;
    c->small_made = i + 1;
  }
  c->small_seconds = now_s() - t0;
  return err;
}

static int cmp_double(const void *a, const void *b)
{
  double x = *(const double *)a, y = *(const double *)b;
  return (x > y) - (x < y);
}

static double median_of(double *v, uint32_t n)
{
  qsort(v, n, sizeof(double), cmp_double);
  return (n % 2) ? v[n / 2] : (v[n / 2 - 1] + v[n / 2]) / 2.0;
}

static double p95_of(const double *sorted, uint32_t n)
{
  uint32_t idx = (n * 95u + 99u) / 100u;   /* ceil(0.95 n), 1-based */
  return sorted[idx - 1];
}

/* Opens the existing 4 KiB file: attributes alone, then open + first 4 KiB read + close (milliseconds). */
static DWORD scenario_open(bench_ctx *c)
{
  double attr[BENCH_OPEN_SAMPLES], rd[BENCH_OPEN_SAMPLES];
  wchar_t path[MAX_PATH];
  uint32_t i;
  DWORD err = write_file(c, L"open.bin", BENCH_SMALL_BYTES, BENCH_SMALL_BYTES, NULL);
  if (err)
    return err;
  join_path(path, MAX_PATH, c, L"open.bin");
  for (i = 0; i < BENCH_OPEN_SAMPLES; i++) {
    WIN32_FILE_ATTRIBUTE_DATA d;
    HANDLE h;
    DWORD n = 0;
    double t0 = now_s();
    if (!GetFileAttributesExW(path, GetFileExInfoStandard, &d))
      return GetLastError();
    attr[i] = (now_s() - t0) * 1000.0;
    t0 = now_s();
    h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE)
      return GetLastError();
    if (!ReadFile(h, c->buf, BENCH_SMALL_BYTES, &n, NULL) || n != BENCH_SMALL_BYTES) {
      err = GetLastError();
      CloseHandle(h);
      return err ? err : ERROR_READ_FAULT;
    }
    CloseHandle(h);
    rd[i] = (now_s() - t0) * 1000.0;
  }
  c->open.attr_med = median_of(attr, BENCH_OPEN_SAMPLES);
  c->open.attr_p95 = p95_of(attr, BENCH_OPEN_SAMPLES);
  c->open.read_med = median_of(rd, BENCH_OPEN_SAMPLES);
  c->open.read_p95 = p95_of(rd, BENCH_OPEN_SAMPLES);
  return 0;
}

/* Deletes the files this run created, then the folder. Only names inside the run's own folder are
   touched. Returns 0 or the error of RemoveDirectory (the folder is then left behind). */
static DWORD remove_bench_dir(bench_ctx *c)
{
  static const wchar_t *const fixed[] = { L"seq-1m.bin", L"seq-64k.bin", L"open.bin" };
  wchar_t path[MAX_PATH];
  uint32_t i;
  size_t k;
  for (k = 0; k < SD_COUNTOF(fixed); k++) {
    join_path(path, MAX_PATH, c, fixed[k]);
    DeleteFileW(path);
  }
  for (i = 0; i < c->small_made; i++) {
    wchar_t name[32];
    _snwprintf_s(name, SD_COUNTOF(name), _TRUNCATE, L"s%04u.bin", (unsigned)i);
    join_path(path, MAX_PATH, c, name);
    DeleteFileW(path);
  }
  if (!RemoveDirectoryW(c->dir))
    return GetLastError();
  return 0;
}

/* The agent's view of the drive: whether a ShellDrive mount has the letter, its backend, read-only flag and
   pool size. No agent running (or no row for the letter): found stays 0 and the report shows nulls. */
static void mount_info_of(wchar_t letter, mount_info *mi)
{
  sd_ipc_hello hello;
  sd_ipc_conn *c = NULL;
  sd_json *list = NULL;
  sd_ipc_error err;
  const sd_json *arr;
  size_t i, n;
  memset(mi, 0, sizeof(*mi));
  if (sd_ipc_connect(SD_IPC_AGENT, quiet_hello(&hello), 0, 5000, &c) != SD_OK)
    return;
  if (sd_ipc_call_raw(c, "list", NULL, 0, CALL_TIMEOUT, &list, &err) == SD_OK) {
    arr = sd_json_get(list, "mounts");
    n = sd_json_count(arr);
    for (i = 0; i < n && !mi->found; i++) {
      const sd_json *m = sd_json_at(arr, i), *conn;
      wchar_t *wt = wide(sd_json_get_str(m, "target"));
      if (wt && wt[0] == letter && wt[1] == L':') {
        const char *be = sd_json_get_str(m, "backend");
        int64_t pool = 0;
        mi->found = 1;
        if (be) strncpy_s(mi->backend, sizeof(mi->backend), be, _TRUNCATE);
        sd_json_get_bool(m, "read_only", &mi->read_only);
        conn = sd_json_get(m, "connection");
        if (conn && sd_json_get_int64(conn, "pool", &pool))
          mi->pool = (int)pool;
      }
      sd_free(wt);
    }
  }
  sd_json_free(list);
  sd_ipc_close(c);
}

static void fmt_num(wchar_t *buf, size_t cch, double v, const wchar_t *fmt)
{
  _snwprintf_s(buf, cch, _TRUNCATE, fmt, v);
}

/* Human summary, one localized line per scenario that ran. */
static void print_text(const bench_ctx *c, const wchar_t *target, const mount_info *mi, const wchar_t *mode)
{
  wchar_t b[6][32];
  sd_arg args[6];
  int i;
  args[0].name = "target"; args[0].type = SD_ARG_STR; args[0].v.s = target;
  args[1].name = "size"; args[1].type = SD_ARG_INT; args[1].v.i = c->size_mib;
  say(SD_MSG_CLI_BENCH_HEADER, args, 2, 0);
  if (mi->found && mi->pool > 0) {
    sd_arg p;
    p.name = "count"; p.type = SD_ARG_INT; p.v.i = mi->pool;
    say(SD_MSG_CLI_BENCH_POOL, &p, 1, 0);
  }
  args[0].name = "mode"; args[0].type = SD_ARG_STR; args[0].v.s = mode;
  say(SD_MSG_CLI_BENCH_WRITE_MODE, args, 1, 0);
  for (i = 0; i < 3; i++) {
    const bench_seq *s = &c->seq[i];
    if (!c->ran[i] || s->bytes == 0) continue;
    fmt_num(b[0], SD_COUNTOF(b[0]), s->mbps, L"%.1f");
    fmt_num(b[1], SD_COUNTOF(b[1]), s->seconds, L"%.2f");
    args[0].name = "block"; args[0].type = SD_ARG_STR; args[0].v.s = s->block == BENCH_BLOCK_1M ? L"1 MiB" : L"64 KiB";
    args[1].name = "mbps"; args[1].type = SD_ARG_STR; args[1].v.s = b[0];
    args[2].name = "seconds"; args[2].type = SD_ARG_STR; args[2].v.s = b[1];
    say(i == 2 ? SD_MSG_CLI_BENCH_SEQ_READ : SD_MSG_CLI_BENCH_SEQ_WRITE, args, 3, 0);
  }
  if (c->ran[BS_SMALL]) {
    sd_arg sa[3];
    fmt_num(b[0], SD_COUNTOF(b[0]), c->small_seconds, L"%.2f");
    fmt_num(b[1], SD_COUNTOF(b[1]), c->small_seconds * 1000.0 / (c->small_made ? c->small_made : 1), L"%.2f");
    sa[0].name = "count"; sa[0].type = SD_ARG_INT; sa[0].v.i = c->small_made;
    sa[1].name = "seconds"; sa[1].type = SD_ARG_STR; sa[1].v.s = b[0];
    sa[2].name = "ms"; sa[2].type = SD_ARG_STR; sa[2].v.s = b[1];
    say(SD_MSG_CLI_BENCH_SMALL_FILES, sa, 3, 0);
  }
  if (c->ran[BS_OPEN]) {
    sd_arg oa[6];
    fmt_num(b[0], SD_COUNTOF(b[0]), c->open.attr_med, L"%.3f");
    fmt_num(b[1], SD_COUNTOF(b[1]), c->open.attr_p95, L"%.3f");
    fmt_num(b[2], SD_COUNTOF(b[2]), c->open.read_med, L"%.3f");
    fmt_num(b[3], SD_COUNTOF(b[3]), c->open.read_p95, L"%.3f");
    oa[0].name = "attr_median"; oa[0].type = SD_ARG_STR; oa[0].v.s = b[0];
    oa[1].name = "attr_p95"; oa[1].type = SD_ARG_STR; oa[1].v.s = b[1];
    oa[2].name = "read_median"; oa[2].type = SD_ARG_STR; oa[2].v.s = b[2];
    oa[3].name = "read_p95"; oa[3].type = SD_ARG_STR; oa[3].v.s = b[3];
    oa[4].name = "samples"; oa[4].type = SD_ARG_INT; oa[4].v.i = BENCH_OPEN_SAMPLES;
    say(SD_MSG_CLI_BENCH_OPEN, oa, 5, 0);
  }
  say(SD_MSG_CLI_BENCH_CACHE_NOTE, NULL, 0, 0);
}

static void json_num(sd_json_writer *jw, double v)
{
  char tmp[64];
  sprintf_s(tmp, sizeof(tmp), "%.3f", v);
  sd_jw_raw(jw, tmp, strlen(tmp));
}

static void print_json(const bench_ctx *c, const wchar_t *target, const mount_info *mi, const char *mode)
{
  sd_wr w;
  sd_json_writer jw;
  int i;
  char tt[4];
  tt[0] = (char)target[0]; tt[1] = ':'; tt[2] = 0;
  sd_wr_init(&w, 64 * 1024);
  sd_jw_init(&jw, &w);
  sd_jw_obj_begin(&jw);
  sd_jw_key(&jw, "ok"); sd_jw_bool(&jw, 1);
  sd_jw_key(&jw, "result"); sd_jw_obj_begin(&jw);
  sd_jw_key(&jw, "target"); sd_jw_cstr(&jw, tt);
  sd_jw_key(&jw, "size_mib"); sd_jw_int(&jw, c->size_mib);
  sd_jw_key(&jw, "write_mode"); sd_jw_cstr(&jw, mode);
  sd_jw_key(&jw, "write_mode_source"); sd_jw_cstr(&jw, "declared");
  sd_jw_key(&jw, "backend"); if (mi->found) sd_jw_cstr(&jw, mi->backend); else sd_jw_null(&jw);
  sd_jw_key(&jw, "pool"); if (mi->found) sd_jw_int(&jw, mi->pool); else sd_jw_null(&jw);
  sd_jw_key(&jw, "scenarios"); sd_jw_arr_begin(&jw);
  for (i = 0; i < 3; i++) {
    const bench_seq *s = &c->seq[i];
    if (!c->ran[i]) continue;
    sd_jw_obj_begin(&jw);
    sd_jw_key(&jw, "name"); sd_jw_cstr(&jw, i == 0 ? "seq-write" : i == 1 ? "seq-write-64k" : "seq-read");
    sd_jw_key(&jw, "block_bytes"); sd_jw_int(&jw, s->block);
    sd_jw_key(&jw, "bytes"); sd_jw_int(&jw, (int64_t)s->bytes);
    sd_jw_key(&jw, "seconds"); json_num(&jw, s->seconds);
    sd_jw_key(&jw, "mb_per_s"); json_num(&jw, s->mbps);
    sd_jw_obj_end(&jw);
  }
  if (c->ran[BS_SMALL]) {
    sd_jw_obj_begin(&jw);
    sd_jw_key(&jw, "name"); sd_jw_cstr(&jw, "small-files");
    sd_jw_key(&jw, "files"); sd_jw_int(&jw, c->small_made);
    sd_jw_key(&jw, "bytes_each"); sd_jw_int(&jw, BENCH_SMALL_BYTES);
    sd_jw_key(&jw, "seconds"); json_num(&jw, c->small_seconds);
    sd_jw_key(&jw, "ms_per_file"); json_num(&jw, c->small_seconds * 1000.0 / (c->small_made ? c->small_made : 1));
    sd_jw_obj_end(&jw);
  }
  if (c->ran[BS_OPEN]) {
    sd_jw_obj_begin(&jw);
    sd_jw_key(&jw, "name"); sd_jw_cstr(&jw, "open");
    sd_jw_key(&jw, "samples"); sd_jw_int(&jw, BENCH_OPEN_SAMPLES);
    sd_jw_key(&jw, "attr_median_ms"); json_num(&jw, c->open.attr_med);
    sd_jw_key(&jw, "attr_p95_ms"); json_num(&jw, c->open.attr_p95);
    sd_jw_key(&jw, "read_median_ms"); json_num(&jw, c->open.read_med);
    sd_jw_key(&jw, "read_p95_ms"); json_num(&jw, c->open.read_p95);
    sd_jw_obj_end(&jw);
  }
  sd_jw_arr_end(&jw);
  sd_jw_key(&jw, "cleaned"); sd_jw_bool(&jw, 1);
  sd_jw_obj_end(&jw);
  sd_jw_obj_end(&jw);
  if (sd_jw_finish(&jw) == SD_OK)
    cli_print_utf8_line((const char *)w.p, w.len);
  sd_wr_free(&w);
}

/* A failure of the run: localized text, or the JSON error object. The folder is removed before this. */
static int fail_run(const cli_args *a, DWORD err)
{
  wchar_t num[24];
  if (a->json) {
    char detail[64];
    sprintf_s(detail, sizeof(detail), "win32 error %lu", (unsigned long)err);
    json_err("io_error", detail, 1);
  } else {
    sd_arg arg;
    arg.name = "code"; arg.type = SD_ARG_STR; arg.v.s = decimal(num, SD_COUNTOF(num), (long long)err);
    say(SD_MSG_CLI_BENCH_FAILED, &arg, 1, 1);
  }
  return 1;
}

/* Drive letter of "X:" or "X:\" (any case), upper case; 0 when the text is not one. */
static wchar_t drive_letter_of(const wchar_t *s)
{
  if (s == NULL || !((s[0] >= L'A' && s[0] <= L'Z') || (s[0] >= L'a' && s[0] <= L'z')) || s[1] != L':')
    return 0;
  if (s[2] != 0 && s[2] != L'\\')
    return 0;
  return (s[0] >= L'a' && s[0] <= L'z') ? (wchar_t)(s[0] - L'a' + L'A') : s[0];
}

static int scenario_selected(const cli_args *a, int which)
{
  if (a->bench_scenario == NULL || wcscmp(a->bench_scenario, L"all") == 0)
    return 1;
  return wcscmp(a->bench_scenario, k_scenario_name[which]) == 0;
}

int cli_run_bench(const cli_args *a)
{
  bench_ctx c;
  mount_info mi;
  wchar_t letter, root[MAX_PATH], target[4];
  err_ctx ec;
  const wchar_t *mode_w = (a->bench_write_mode && wcscmp(a->bench_write_mode, L"behind") == 0) ? L"behind" : L"through";
  const char *mode = (a->bench_write_mode && wcscmp(a->bench_write_mode, L"behind") == 0) ? "behind" : "through";
  DWORD err = 0, rm_err = 0;
  int i, is_test_root = 0;
  wchar_t folder[MAX_PATH];
  memset(&c, 0, sizeof(c));
  memset(&ec, 0, sizeof(ec));
  ec.name = a->positional;
  letter = drive_letter_of(a->positional);
  if (letter == 0)
    return fail_run(a, ERROR_INVALID_PARAMETER);
  fill_target(ec.target, letter);
  fill_target(target, letter);
  c.size_mib = a->bench_size_mib ? (uint32_t)a->bench_size_mib : BENCH_MIB_DEFAULT;
  c.total = (uint64_t)c.size_mib * 1048576u;

  _snwprintf_s(root, SD_COUNTOF(root), _TRUNCATE, L"%c:\\", letter);
#ifdef SD_CLI_TEST_HOOKS
  {
    /* test builds: the run uses a folder of the test instead of the drive (no volume checks then) */
    wchar_t v[MAX_PATH];
    size_t n;
    if (GetEnvironmentVariableW(L"SHELLDRIVE_TEST_BENCH_ROOT", v, MAX_PATH) - 1u < MAX_PATH - 1u) {
      n = wcslen(v);
      if (n == 0 || v[n - 1] != L'\\') wcscat_s(v, MAX_PATH, L"\\");
      wcscpy_s(root, SD_COUNTOF(root), v);
      is_test_root = 1;
    }
  }
#endif
  if (!is_test_root) {
    DWORD flags = 0;
    if (!GetVolumeInformationW(root, NULL, 0, NULL, NULL, &flags, NULL, 0))
      return fail_code(a, "mount_not_found", "no volume", &ec);
    if (flags & FILE_READ_ONLY_VOLUME)
      return fail_code(a, "read_only_mount", "read-only volume", &ec);
  }
  mount_info_of(letter, &mi);
  if (mi.found && mi.read_only)
    return fail_code(a, "read_only_mount", "read-only mount", &ec);

  c.buf = (unsigned char *)sd_alloc(BENCH_BLOCK_1M);
  if (c.buf == NULL)
    return fail_run(a, ERROR_NOT_ENOUGH_MEMORY);
  for (i = 0; i < (int)BENCH_BLOCK_1M; i++)
    c.buf[i] = (unsigned char)(i * 31u + 1u);

  /* the run's own folder: a new name, so CreateDirectory cannot replace anything */
  _snwprintf_s(folder, SD_COUNTOF(folder), _TRUNCATE, L"%s.shelldrive-bench-%lu-%lu", root,
               (unsigned long)GetCurrentProcessId(), (unsigned long)GetTickCount());
  wcscpy_s(c.dir, SD_COUNTOF(c.dir), folder);
  if (!CreateDirectoryW(c.dir, NULL)) {
    err = GetLastError();
    sd_free(c.buf);
    return err == ERROR_WRITE_PROTECT ? fail_code(a, "read_only_mount", "read-only", &ec) : fail_run(a, err);
  }

  /* scenarios, in this order; a failure stops the run and the folder is removed */
  if (scenario_selected(a, BS_SEQ_W1M)) {
    c.ran[0] = 1;
    err = scenario_seq_write(&c, BENCH_BLOCK_1M, &c.seq[0], L"seq-1m.bin");
    c.seq_written = err == 0;
  }
  if (!err && scenario_selected(a, BS_SEQ_W64K)) {
    c.ran[1] = 1;
    err = scenario_seq_write(&c, BENCH_BLOCK_64K, &c.seq[1], L"seq-64k.bin");
  }
  if (!err && scenario_selected(a, BS_SEQ_R)) {
    c.ran[2] = 1;
    if (!c.seq_written) {
      /* read alone: the file is prepared first, untimed */
      err = write_file(&c, L"seq-1m.bin", c.total, BENCH_BLOCK_1M, NULL);
      c.seq_written = err == 0;
    }
    if (!err)
      err = read_file(&c, L"seq-1m.bin", c.total, BENCH_BLOCK_1M, &c.seq[2]);
  }
  if (!err && scenario_selected(a, BS_SMALL)) {
    c.ran[3] = 1;
    err = scenario_small_files(&c);
  }
  if (!err && scenario_selected(a, BS_OPEN)) {
    c.ran[4] = 1;
    err = scenario_open(&c);
  }

  rm_err = remove_bench_dir(&c);
  sd_free(c.buf);
  if (err)
    return fail_run(a, err);
  if (rm_err) {
    wchar_t num[24];
    if (a->json) {
      json_err("io_error", "the temporary folder could not be removed", 1);
    } else {
      sd_arg args[2];
      args[0].name = "path"; args[0].type = SD_ARG_STR; args[0].v.s = c.dir;
      args[1].name = "code"; args[1].type = SD_ARG_STR; args[1].v.s = decimal(num, SD_COUNTOF(num), (long long)rm_err);
      say(SD_MSG_CLI_BENCH_CLEANUP_FAILED, args, 2, 1);
    }
    return 1;
  }

  if (a->json) {
    print_json(&c, target, &mi, mode);
  } else if (!a->quiet) {
    print_text(&c, target, &mi, mode_w);
    say(SD_MSG_CLI_BENCH_CLEANED, NULL, 0, 0);
  }
  return 0;
}
