#include <windows.h>

#include <string.h>
#include <wchar.h>

#include "sd_base/sd_utf.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_thread.h"

#define SD_LOG_MAX_RECORD 4096
#define SD_LOG_MAX_ARG    512
#define SD_LOG_MAX_SINKS  4

typedef struct log_sink { sd_log_sink_fn fn; void *ctx; } log_sink;

static sd_once  g_once = SD_ONCE_INIT;
static sd_mutex g_lock;
static volatile LONG g_level = SD_LOG_INFO;
static HANDLE   g_file = INVALID_HANDLE_VALUE;
static wchar_t  g_path[MAX_PATH];
static uint64_t g_file_size;
static log_sink g_sinks[SD_LOG_MAX_SINKS];

static void log_init_once(void *arg)
{
  SD_UNUSED(arg);
  sd_mutex_init(&g_lock);
}

static void log_init(void)
{
  sd_once_run(&g_once, log_init_once, NULL);
}

void sd_log_set_level(sd_log_level max_level)
{
  InterlockedExchange(&g_level, (LONG)max_level);
}

sd_log_level sd_log_get_level(void)
{
  return (sd_log_level)g_level;
}

int sd_log_enabled(sd_log_level level)
{
  return (LONG)level <= g_level;
}

/* ---- restricted formatter ---- */

typedef struct out_buf { char *p; size_t cap, len; } out_buf;

static void ob_putc(out_buf *o, char c)
{
  if (o->len + 1 < o->cap)
    o->p[o->len++] = c;
}

static void ob_puts(out_buf *o, const char *s)
{
  while (*s)
    ob_putc(o, *s++);
}

static void ob_hexbyte(out_buf *o, unsigned b)
{
  static const char hex[] = "0123456789abcdef";
  ob_putc(o, '\\');
  ob_putc(o, 'x');
  ob_putc(o, hex[(b >> 4) & 15]);
  ob_putc(o, hex[b & 15]);
}

static void ob_uint(out_buf *o, uint64_t v, unsigned base, unsigned width)
{
  char tmp[24];
  unsigned n = 0;
  do {
    unsigned d = (unsigned)(v % base);
    tmp[n++] = (char)(d < 10 ? '0' + d : 'a' + d - 10);
    v /= base;
  } while (v && n < sizeof(tmp));
  while (width > n) {
    ob_putc(o, '0');
    width--;
  }
  while (n > 0) {
    n--;
    ob_putc(o, tmp[n]);
  }
}

static void ob_int(out_buf *o, int64_t v)
{
  if (v < 0) {
    ob_putc(o, '-');
    ob_uint(o, (uint64_t)0 - (uint64_t)v, 10, 0);
  } else {
    ob_uint(o, (uint64_t)v, 10, 0);
  }
}

/* UTF-8 string argument: valid sequences pass, control and invalid bytes are escaped. */
static void ob_str8(out_buf *o, const char *s)
{
  const uint8_t *u = (const uint8_t *)s;
  size_t i = 0, n, used = 0;
  if (s == NULL) {
    ob_puts(o, "(null)");
    return;
  }
  n = strlen(s);
  while (i < n) {
    uint8_t c = u[i];
    size_t k = 1;
    if (used >= SD_LOG_MAX_ARG) {
      ob_puts(o, "...");
      return;
    }
    if (c < 0x20 || c == 0x7F) {
      ob_hexbyte(o, c);
    } else if (c < 0x80) {
      ob_putc(o, (char)c);
    } else {
      k = c >= 0xF0 ? 4 : c >= 0xE0 ? 3 : c >= 0xC0 ? 2 : 1;
      if (k > n - i || !sd_utf8_valid(s + i, k)) {
        k = 1;
        ob_hexbyte(o, c);
      } else {
        size_t j;
        for (j = 0; j < k; j++)
          ob_putc(o, (char)u[i + j]);
      }
    }
    i += k;
    used += k;
  }
}

static void ob_str16(out_buf *o, const wchar_t *w)
{
  char tmp[SD_LOG_MAX_ARG * 3 + 1];
  size_t n, len;
  if (w == NULL) {
    ob_puts(o, "(null)");
    return;
  }
  n = wcslen(w);
  if (n > SD_LOG_MAX_ARG)
    n = SD_LOG_MAX_ARG;
  if (sd_utf16_to_utf8(w, n, tmp, sizeof(tmp) - 1, &len, SD_UTF_REPLACE) != SD_OK)
    len = 0;
  tmp[len] = 0;
  ob_str8(o, tmp);
}

size_t sd_log_format(char *buf, size_t cap, const char *fmt, va_list ap)
{
  out_buf o;
  o.p = buf;
  o.cap = cap;
  o.len = 0;
  if (cap == 0)
    return 0;
  while (*fmt) {
    char c = *fmt++;
    if (c != '%') {
      ob_putc(&o, c);
      continue;
    }
    c = *fmt++;
    switch (c) {
    case '%': ob_putc(&o, '%'); break;
    case 's': ob_str8(&o, va_arg(ap, const char *)); break;
    case 'c': {
      int ch = va_arg(ap, int);
      if (ch >= 0x20 && ch < 0x7F) ob_putc(&o, (char)ch); else ob_hexbyte(&o, (unsigned)ch & 0xFF);
      break;
    }
    case 'd': ob_int(&o, va_arg(ap, int)); break;
    case 'u': ob_uint(&o, va_arg(ap, unsigned), 10, 0); break;
    case 'x': ob_uint(&o, va_arg(ap, unsigned), 16, 0); break;
    case 'p': ob_puts(&o, "0x"); ob_uint(&o, (uint64_t)(uintptr_t)va_arg(ap, void *), 16, 0); break;
    case 'z':
      if (*fmt == 'u') { fmt++; ob_uint(&o, va_arg(ap, size_t), 10, 0); }
      else ob_puts(&o, "%?");
      break;
    case 'l':
      if (*fmt == 's') { fmt++; ob_str16(&o, va_arg(ap, const wchar_t *)); }
      else if (fmt[0] == 'l' && fmt[1] == 'd') { fmt += 2; ob_int(&o, va_arg(ap, long long)); }
      else if (fmt[0] == 'l' && fmt[1] == 'u') { fmt += 2; ob_uint(&o, va_arg(ap, unsigned long long), 10, 0); }
      else if (fmt[0] == 'l' && fmt[1] == 'x') { fmt += 2; ob_uint(&o, va_arg(ap, unsigned long long), 16, 0); }
      else ob_puts(&o, "%?");
      break;
    case 0:
      fmt--;                                    /* trailing '%' */
      ob_puts(&o, "%?");
      break;
    default:
      ob_puts(&o, "%?");
      break;
    }
  }
  o.p[o.len] = 0;
  return o.len;
}

/* ---- sinks ---- */

static void file_close_locked(void)
{
  if (g_file != INVALID_HANDLE_VALUE) {
    CloseHandle(g_file);
    g_file = INVALID_HANDLE_VALUE;
  }
}

static int file_open_locked(void)
{
  LARGE_INTEGER sz;
  g_file = CreateFileW(g_path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (g_file == INVALID_HANDLE_VALUE)
    return 0;
  g_file_size = GetFileSizeEx(g_file, &sz) ? (uint64_t)sz.QuadPart : 0;
  return 1;
}

static void file_rotate_locked(void)
{
  wchar_t from[MAX_PATH + 8], to[MAX_PATH + 8];
  int gen;
  file_close_locked();
  for (gen = SD_LOG_GENERATIONS; gen >= 1; gen--) {
    if (gen == 1)
      wcscpy_s(from, SD_COUNTOF(from), g_path);
    else
      swprintf_s(from, SD_COUNTOF(from), L"%ls.%d", g_path, gen - 1);
    swprintf_s(to, SD_COUNTOF(to), L"%ls.%d", g_path, gen);
    MoveFileExW(from, to, MOVEFILE_REPLACE_EXISTING);
  }
  file_open_locked();
}

sd_err sd_log_open_file(const wchar_t *path)
{
  sd_err e = SD_OK;
  log_init();
  sd_mutex_lock(&g_lock);
  file_close_locked();
  g_path[0] = 0;
  if (path) {
    if (wcscpy_s(g_path, SD_COUNTOF(g_path), path) != 0) {
      g_path[0] = 0;
      e = SD_E_NAME_TOO_LONG;
    } else if (!file_open_locked()) {
      g_path[0] = 0;
      e = SD_E_ACCESS_DENIED;
    }
  }
  sd_mutex_unlock(&g_lock);
  return e;
}

void sd_log_close(void)
{
  log_init();
  sd_mutex_lock(&g_lock);
  file_close_locked();
  g_path[0] = 0;
  memset(g_sinks, 0, sizeof(g_sinks));
  sd_mutex_unlock(&g_lock);
}

sd_err sd_log_add_sink(sd_log_sink_fn fn, void *ctx)
{
  sd_err e = SD_E_BUSY;
  int i;
  log_init();
  sd_mutex_lock(&g_lock);
  for (i = 0; i < SD_LOG_MAX_SINKS; i++) {
    if (g_sinks[i].fn == NULL) {
      g_sinks[i].fn = fn;
      g_sinks[i].ctx = ctx;
      e = SD_OK;
      break;
    }
  }
  sd_mutex_unlock(&g_lock);
  return e;
}

void sd_log_remove_sink(sd_log_sink_fn fn, void *ctx)
{
  int i;
  log_init();
  sd_mutex_lock(&g_lock);
  for (i = 0; i < SD_LOG_MAX_SINKS; i++) {
    if (g_sinks[i].fn == fn && g_sinks[i].ctx == ctx) {
      g_sinks[i].fn = NULL;
      g_sinks[i].ctx = NULL;
    }
  }
  sd_mutex_unlock(&g_lock);
}

static const char *const g_level_names[] = { "ERROR", "WARN ", "INFO ", "DEBUG", "TRACE" };

void sd_logv(sd_log_level level, const char *component, const char *mount_id,
             const char *fmt, va_list ap)
{
  char line[SD_LOG_MAX_RECORD + 2];
  out_buf o;
  SYSTEMTIME st;
  size_t comp_len;
  int i;

  if (!sd_log_enabled(level) || (unsigned)level > SD_LOG_TRACE)
    return;
  log_init();

  o.p = line;
  o.cap = SD_LOG_MAX_RECORD;
  o.len = 0;
  GetSystemTime(&st);
  ob_uint(&o, st.wYear, 10, 4);   ob_putc(&o, '-');
  ob_uint(&o, st.wMonth, 10, 2);  ob_putc(&o, '-');
  ob_uint(&o, st.wDay, 10, 2);    ob_putc(&o, 'T');
  ob_uint(&o, st.wHour, 10, 2);   ob_putc(&o, ':');
  ob_uint(&o, st.wMinute, 10, 2); ob_putc(&o, ':');
  ob_uint(&o, st.wSecond, 10, 2); ob_putc(&o, '.');
  ob_uint(&o, st.wMilliseconds, 10, 3); ob_puts(&o, "Z ");
  ob_uint(&o, GetCurrentProcessId(), 10, 0); ob_putc(&o, ' ');
  ob_uint(&o, GetCurrentThreadId(), 10, 0);  ob_putc(&o, ' ');
  ob_puts(&o, g_level_names[level]);         ob_putc(&o, ' ');
  ob_str8(&o, component ? component : "-");
  for (comp_len = component ? strlen(component) : 1; comp_len < 4; comp_len++)
    ob_putc(&o, ' ');
  ob_putc(&o, ' ');
  if (mount_id) {
    ob_putc(&o, '[');
    ob_str8(&o, mount_id);
    ob_puts(&o, "] ");
  }
  o.len += sd_log_format(o.p + o.len, o.cap - o.len, fmt, ap);

  sd_mutex_lock(&g_lock);
  for (i = 0; i < SD_LOG_MAX_SINKS; i++) {
    if (g_sinks[i].fn)
      g_sinks[i].fn(g_sinks[i].ctx, level, line, o.len);
  }
  line[o.len] = '\r';
  line[o.len + 1] = '\n';
  if (g_file != INVALID_HANDLE_VALUE) {
    DWORD written;
    if (g_file_size + o.len + 2 > SD_LOG_ROTATE_BYTES)
      file_rotate_locked();
    if (g_file != INVALID_HANDLE_VALUE && WriteFile(g_file, line, (DWORD)(o.len + 2), &written, NULL))
      g_file_size += written;
  }
  if (IsDebuggerPresent()) {
    wchar_t wline[SD_LOG_MAX_RECORD + 3];
    size_t wlen;
    if (sd_utf8_to_utf16(line, o.len + 2, wline, SD_LOG_MAX_RECORD + 2, &wlen, SD_UTF_REPLACE) == SD_OK) {
      wline[wlen] = 0;
      OutputDebugStringW(wline);
    }
  }
  sd_mutex_unlock(&g_lock);
}

void sd_log(sd_log_level level, const char *component, const char *mount_id,
            _Printf_format_string_ const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  sd_logv(level, component, mount_id, fmt, ap);
  va_end(ap);
}
