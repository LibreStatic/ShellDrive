#include <windows.h>

#include <stdarg.h>
#include <string.h>

#include "sd_platform/sd_log.h"
#include "sd_platform/sd_platform.h"
#include "sd_platform/sd_secbuf.h"
#include "sd_platform/sd_thread.h"
#include "sd_platform/sd_time.h"
#include "sd_test.h"

SD_TEST(platform_os_version)
{
  const sd_os_version *v;
  SD_REQUIRE(sd_platform_init() == SD_OK);
  v = sd_os_version_get();
  SD_CHECK(v->major >= 5);
  SD_CHECK(sd_os_at_least(5, 1, 0));
  SD_CHECK(!sd_os_at_least(v->major + 1, 0, 0));
}

SD_TEST(platform_resolve)
{
  /* RtlGetVersion and RtlGenRandom exist on every supported OS; a missing name stays NULL. */
  SD_CHECK(sd_platform_resolve(SD_API_RtlGetVersion) != NULL);
  SD_CHECK(sd_platform_resolve(SD_API_RtlGenRandom) != NULL);
  SD_CHECK(sd_platform_resolve(SD_API_RtlGetVersion) == sd_platform_resolve(SD_API_RtlGetVersion));
  SD_CHECK(sd_platform_resolve((sd_api_id)SD_API_COUNT) == NULL);
  SD_CHECK(sd_platform_resolve_by_name(L"kernel32.dll", "NoSuchFunctionShellDrive") == NULL);
  SD_CHECK(sd_platform_load_system_dll(L"no-such-dll-shelldrive.dll") == NULL);
  if (sd_os_at_least(6, 0, 0)) {
    SD_CHECK(sd_platform_resolve(SD_API_GetTickCount64) != NULL);
    SD_CHECK(sd_platform_resolve(SD_API_BCryptGenRandom) != NULL);
  }
}

SD_TEST(platform_cpu_mask)
{
  uint32_t f = sd_cpu_features();
#if defined(_M_X64)
  SD_CHECK(f & SD_CPU_SSE2);                          /* architectural on x64 */
#elif defined(_M_IX86) && defined(SD_X86_ARCH_IA32)
  SD_CHECK_EQ_U64(f, 0);                              /* x86-ia32 detects nothing (01 §2.3) */
#endif
  sd_cpu_set_mask(0);
  SD_CHECK_EQ_U64(sd_cpu_features(), 0);
  sd_cpu_set_mask(0xFFFFFFFFu);
  SD_CHECK_EQ_U64(sd_cpu_features(), f);
}

SD_TEST(time_tick_monotonic)
{
  uint64_t a = sd_tick_ms(), b;
  Sleep(20);
  b = sd_tick_ms();
  SD_CHECK(b >= a + 10);
  SD_CHECK(sd_unix_time_now() > 1700000000);         /* after 2023 */
  SD_CHECK_EQ_INT(sd_filetime_to_unix(sd_unix_to_filetime(1234567890)), 1234567890);
  SD_CHECK_EQ_U64(sd_unix_to_filetime(0), 116444736000000000ULL);
  SD_CHECK_EQ_U64(sd_unix_to_filetime(-20000000000LL), 0);
}

static void once_fn(void *arg)
{
  InterlockedIncrement((volatile LONG *)arg);
}

static sd_once g_once = SD_ONCE_INIT;

static unsigned __stdcall thread_fn(void *arg)
{
  sd_once_run(&g_once, once_fn, arg);
  return 7;
}

SD_TEST(thread_once_and_join)
{
  volatile LONG count = 0;
  sd_thread t[4];
  uint32_t code = 0;
  int i;
  for (i = 0; i < 4; i++)
    SD_REQUIRE(sd_thread_create(&t[i], thread_fn, (void *)&count, 0, L"sd-test-once") == SD_OK);
  for (i = 0; i < 4; i++) {
    SD_CHECK(sd_thread_join(&t[i], 10000, &code) == SD_OK);
    SD_CHECK_EQ_U64(code, 7);
  }
  SD_CHECK_EQ_INT(count, 1);
}

SD_TEST(event_and_mutex)
{
  sd_event e;
  sd_mutex m;
  SD_REQUIRE(sd_event_init(&e, 0, 0) == SD_OK);
  SD_CHECK(sd_event_wait(&e, 0) == SD_E_TIMEOUT);
  sd_event_set(&e);
  SD_CHECK(sd_event_wait(&e, 0) == SD_OK);
  SD_CHECK(sd_event_wait(&e, 0) == SD_E_TIMEOUT);    /* auto-reset */
  sd_event_destroy(&e);
  sd_mutex_init(&m);
  sd_mutex_lock(&m);
  SD_CHECK(sd_mutex_trylock(&m));                     /* recursive */
  sd_mutex_unlock(&m);
  sd_mutex_unlock(&m);
  sd_mutex_destroy(&m);
}

static size_t fmt(char *buf, size_t cap, const char *f, ...)
{
  va_list ap;
  size_t n;
  va_start(ap, f);
  n = sd_log_format(buf, cap, f, ap);
  va_end(ap);
  return n;
}

SD_TEST(log_restricted_format)
{
  char buf[128];
  fmt(buf, sizeof(buf), "a=%d b=%u c=%x d=%lld e=%llu z=%zu %%", -5, 7u, 255u, -9000000000LL,
      18446744073709551615ULL, (size_t)42);
  SD_CHECK_STR(buf, "a=-5 b=7 c=ff d=-9000000000 e=18446744073709551615 z=42 %");
  fmt(buf, sizeof(buf), "s=%s w=%ls n=%s", "x\ny\xC3\xA9\xFF", L"wide", (const char *)NULL);
  SD_CHECK_STR(buf, "s=x\\x0ay\xC3\xA9\\xff w=wide n=(null)");
  fmt(buf, sizeof(buf), "bad=%q end", 1);
  SD_CHECK_STR(buf, "bad=%? end");
  SD_CHECK_EQ_U64(fmt(buf, 4, "abcdef"), 3);          /* truncated, NUL-terminated */
  SD_CHECK_STR(buf, "abc");
}

typedef struct sink_state { int calls; char last[256]; } sink_state;

static void test_sink(void *ctx, sd_log_level level, const char *line, size_t len)
{
  sink_state *s = (sink_state *)ctx;
  SD_UNUSED(level);
  s->calls++;
  if (len >= sizeof(s->last))
    len = sizeof(s->last) - 1;
  memcpy(s->last, line, len);
  s->last[len] = 0;
}

SD_TEST(log_sinks_and_levels)
{
  sink_state s;
  memset(&s, 0, sizeof(s));
  SD_REQUIRE(sd_log_add_sink(test_sink, &s) == SD_OK);
  sd_log_set_level(SD_LOG_INFO);
  sd_log(SD_LOG_DEBUG, "test", NULL, "hidden");
  SD_CHECK_EQ_INT(s.calls, 0);
  sd_log(SD_LOG_WARN, "ssh", "m-3", "kex done kex=%s", "curve25519-sha256");
  SD_CHECK_EQ_INT(s.calls, 1);
  SD_CHECK(strstr(s.last, " WARN  ssh  [m-3] kex done kex=curve25519-sha256") != NULL);
  SD_CHECK(s.last[4] == '-' && s.last[10] == 'T' && strchr(s.last, 'Z') != NULL);
  sd_log_remove_sink(test_sink, &s);
  sd_log(SD_LOG_ERROR, "test", NULL, "after removal");
  SD_CHECK_EQ_INT(s.calls, 1);
}

SD_TEST(log_file_sink)
{
  wchar_t dir[MAX_PATH], path[MAX_PATH];
  HANDLE h;
  char buf[512];
  DWORD got = 0;
  SD_REQUIRE(GetTempPathW(MAX_PATH, dir) > 0);
  SD_REQUIRE(GetTempFileNameW(dir, L"sdl", 0, path) != 0);
  SD_REQUIRE(sd_log_open_file(path) == SD_OK);
  sd_log(SD_LOG_INFO, "test", NULL, "file record %d", 1);
  sd_log_open_file(NULL);
  h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
  SD_REQUIRE(h != INVALID_HANDLE_VALUE);
  SD_CHECK(ReadFile(h, buf, sizeof(buf) - 1, &got, NULL));
  CloseHandle(h);
  buf[got] = 0;
  SD_CHECK(strstr(buf, "INFO  test file record 1\r\n") != NULL);
  DeleteFileW(path);
}

SD_TEST(secbuf_small_and_large)
{
  sd_secbuf *a = NULL, *b = NULL;
  SD_REQUIRE(sd_secbuf_from("secret", 6, &a) == SD_OK);
  SD_CHECK(a->len == 6 && memcmp(a->p, "secret", 6) == 0);
  SD_REQUIRE(sd_secbuf_new(65536, &b) == SD_OK);
  SD_CHECK(b->cap == 65536 && b->p[65535] == 0);
  b->p[0] = 1;
  sd_secbuf_free(a);
  sd_secbuf_free(b);
  sd_secbuf_free(NULL);
}

/* M4 (03 §10.1): the privacy filter of %Hs / %Us / %Rs. The sink keeps the last record. */
typedef struct priv_sink { int calls; char last[1024]; } priv_sink;

static void priv_sink_fn(void *ctx, sd_log_level level, const char *line, size_t len)
{
  priv_sink *s = (priv_sink *)ctx;
  SD_UNUSED(level);
  s->calls++;
  if (len >= sizeof(s->last))
    len = sizeof(s->last) - 1;
  memcpy(s->last, line, len);
  s->last[len] = 0;
}

/* A fixed fake MAC: the first three bytes give "3f9a1c" in strict mode. */
static void priv_hash(void *ctx, const char *utf8, size_t len, uint8_t out[32])
{
  size_t i;
  SD_UNUSED(ctx);
  SD_UNUSED(utf8);
  SD_UNUSED(len);
  for (i = 0; i < 32; i++)
    out[i] = 0xEE;
  out[0] = 0x3f;
  out[1] = 0x9a;
  out[2] = 0x1c;
}

/* sd_logv has no format annotation, so the restricted %Hs / %Us / %Rs specifiers do not trip the printf checks of /analyze. */
static void plog(sd_log_level level, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  sd_logv(level, "t", NULL, fmt, ap);
  va_end(ap);
}

SD_TEST(log_privacy_standard_and_strict)
{
  priv_sink s;
  memset(&s, 0, sizeof(s));
  SD_REQUIRE(sd_log_add_sink(priv_sink_fn, &s) == SD_OK);
  sd_log_set_level(SD_LOG_TRACE);

  sd_log_set_privacy(SD_LOG_PRIVACY_STANDARD, NULL, NULL);
  SD_CHECK(sd_log_get_privacy() == SD_LOG_PRIVACY_STANDARD);
  plog(SD_LOG_INFO, "host %Hs user %Us path %Rs", "example.org", "alice", "/srv/a.txt");
  SD_CHECK(strstr(s.last, "host example.org user alice path (hidden)") != NULL);
  plog(SD_LOG_ERROR, "failed %Rs", "/srv/a.txt");
  SD_CHECK(strstr(s.last, "failed /srv/a.txt") != NULL);            /* error records name the path */
  plog(SD_LOG_DEBUG, "debug %Rs", "/srv/b.txt");
  SD_CHECK(strstr(s.last, "debug /srv/b.txt") != NULL);

  sd_log_set_privacy(SD_LOG_PRIVACY_STRICT, priv_hash, NULL);
  plog(SD_LOG_ERROR, "host %Hs user %Us path %Rs", "example.org", "alice", "/srv/a.txt");
  SD_CHECK(strstr(s.last, "host h:3f9a1c user u:3f9a1c path p:3f9a1c") != NULL);   /* every level, errors too */
  SD_CHECK(strstr(s.last, "example.org") == NULL);
  SD_CHECK(strstr(s.last, "alice") == NULL);
  SD_CHECK(strstr(s.last, "/srv/") == NULL);

  /* strict without a key never prints the text */
  sd_log_set_privacy(SD_LOG_PRIVACY_STRICT, NULL, NULL);
  plog(SD_LOG_WARN, "host %Hs", "example.org");
  SD_CHECK(strstr(s.last, "host [redacted]") != NULL);

  sd_log_set_privacy(SD_LOG_PRIVACY_STANDARD, NULL, NULL);
  sd_log_set_level(SD_LOG_INFO);
  sd_log_remove_sink(priv_sink_fn, &s);
}

static const sd_test_case k_tests[] = {
  SD_TEST_ENTRY(platform_os_version),
  SD_TEST_ENTRY(platform_resolve),
  SD_TEST_ENTRY(platform_cpu_mask),
  SD_TEST_ENTRY(time_tick_monotonic),
  SD_TEST_ENTRY(thread_once_and_join),
  SD_TEST_ENTRY(event_and_mutex),
  SD_TEST_ENTRY(log_restricted_format),
  SD_TEST_ENTRY(log_sinks_and_levels),
  SD_TEST_ENTRY(log_file_sink),
  SD_TEST_ENTRY(log_privacy_standard_and_strict),
  SD_TEST_ENTRY(secbuf_small_and_large),
};

int main(int argc, char **argv)
{
  return sd_test_main(k_tests, SD_COUNTOF(k_tests), argc, argv);
}
