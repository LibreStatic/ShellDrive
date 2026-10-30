/* Test runner. Test binaries are never shipped, so stdio is allowed here. */
#include <windows.h>

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_test.h"

void sd_test_fail(sd_test_ctx *t, const char *file, int line, const char *fmt, ...)
{
  va_list ap;
  t->failures++;
  fprintf(stdout, "  %s(%d): ", file, line);
  va_start(ap, fmt);
  vfprintf(stdout, fmt, ap);
  va_end(ap);
  fputc('\n', stdout);
  fflush(stdout);
}

int sd_test_memcmp(const void *a, const void *b, size_t n)
{
  return memcmp(a, b, n);
}

int sd_test_strcmp(const char *a, const char *b)
{
  return strcmp(a, b);
}

static int hexval(char c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

size_t sd_test_unhex(const char *hex, uint8_t *out, size_t cap)
{
  size_t n = 0;
  while (hex[0] && hex[1]) {
    int hi = hexval(hex[0]), lo = hexval(hex[1]);
    if (hi < 0 || lo < 0 || n >= cap)
      return SIZE_MAX;
    out[n++] = (uint8_t)(hi * 16 + lo);
    hex += 2;
  }
  return hex[0] ? SIZE_MAX : n;
}

int sd_test_exe_dir_path(const char *rel, char *out, size_t cap)
{
  char exe[MAX_PATH];
  size_t n, rl = strlen(rel);
  DWORD m = GetModuleFileNameA(NULL, exe, (DWORD)sizeof(exe));
  if (m == 0 || m >= sizeof(exe))
    return 0;
  n = strlen(exe);
  while (n > 0 && exe[n - 1] != '\\' && exe[n - 1] != '/')
    n--;
  if (n == 0 || n + rl + 2 > cap)
    return 0;
  memcpy(out, exe, n);
  out[n] = '\\';
  memcpy(out + n + 1, rel, rl + 1);
  return 1;
}

/* Tests run on one thread, so plain accesses are enough. */
static LONG g_alloc_countdown = -1;

static int fail_hook(void *ctx, size_t n)
{
  SD_UNUSED(ctx);
  SD_UNUSED(n);
  if (g_alloc_countdown < 0)
    return 0;
  if (g_alloc_countdown == 0)
    return 1;
  g_alloc_countdown--;
  return 0;
}

void sd_test_alloc_fail_after(unsigned n)
{
  g_alloc_countdown = (LONG)n;
  sd_mem_set_fail_hook(fail_hook, NULL);
}

void sd_test_alloc_fail_off(void)
{
  sd_mem_set_fail_hook(NULL, NULL);
  g_alloc_countdown = -1;
}

static LONG WINAPI crash_filter(EXCEPTION_POINTERS *ep)
{
  fprintf(stdout, "FATAL: unhandled exception 0x%08lx\n", ep->ExceptionRecord->ExceptionCode);
  fflush(stdout);
  ExitProcess(3);
}

int sd_test_main(const sd_test_case *cases, size_t count, int argc, char **argv)
{
  const char *filter = NULL;
  size_t i, run = 0, failed = 0;
  unsigned shard = 0, shards = 1;   /* --shard K/N: only the cases whose index is K modulo N (parallel CTest entries) */
  int a;

  SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
  SetUnhandledExceptionFilter(crash_filter);

  for (a = 1; a < argc; a++) {
    if (strcmp(argv[a], "--list") == 0) {
      for (i = 0; i < count; i++)
        printf("%s\n", cases[i].name);
      return 0;
    }
    if (strcmp(argv[a], "--filter") == 0 && a + 1 < argc)
      filter = argv[++a];
    if (strcmp(argv[a], "--shard") == 0 && a + 1 < argc) {
      if (sscanf_s(argv[++a], "%u/%u", &shard, &shards) != 2 || shards == 0 || shard >= shards) {
        printf("bad --shard %s (want K/N with K < N)\n", argv[a]);
        return 2;
      }
    }
  }

  for (i = 0; i < count; i++) {
    sd_test_ctx t;
    if (filter && strstr(cases[i].name, filter) == NULL)
      continue;
    if (i % shards != shard)
      continue;
    t.name = cases[i].name;
    t.failures = 0;
    printf("[ RUN  ] %s\n", t.name);
    fflush(stdout);
    cases[i].fn(&t);
    sd_test_alloc_fail_off();
    run++;
    if (t.failures) {
      failed++;
      printf("[ FAIL ] %s (%d failed checks)\n", t.name, t.failures);
    } else {
      printf("[  OK  ] %s\n", t.name);
    }
  }
  printf("%u tests, %u failed\n", (unsigned)run, (unsigned)failed);
  if (run == 0) {
    printf("no tests selected\n");
    return 2;
  }
  return failed ? 1 : 0;
}
