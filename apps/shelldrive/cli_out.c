/* Console I/O for shelldrive.exe (03 §6.4): WriteConsoleW on a console (no code page involved),
 * UTF-8 without BOM when redirected; never SetConsoleOutputCP. Prompts and progress go to stderr
 * (the console when stderr is one), so --json keeps stdout to exactly one JSON object. Secret input
 * uses ReadConsoleW with echo off; a console control handler restores the input mode on Ctrl+C. */
#include <windows.h>
#include <string.h>

#include "cli.h"
#include "sd_base/sd_mem.h"
#include "sd_base/sd_utf.h"

static int g_quiet;
static volatile LONG g_mode_saved;
static DWORD g_saved_mode;
static HANDLE g_saved_in;

static BOOL WINAPI ctrl_handler(DWORD type)
{
  SD_UNUSED(type);
  if (InterlockedCompareExchange(&g_mode_saved, 0, 1) == 1)
    SetConsoleMode(g_saved_in, g_saved_mode);
  return FALSE;   /* default handling (terminate) */
}

void cli_out_init(int json, int quiet)
{
  SD_UNUSED(json);
  g_quiet = quiet;
  SetConsoleCtrlHandler(ctrl_handler, TRUE);
}

static void write_handle(HANDLE h, const wchar_t *s, size_t n)
{
  DWORD mode, written;
  if (h == NULL || h == INVALID_HANDLE_VALUE || n == 0)
    return;
  if (GetConsoleMode(h, &mode)) {
    while (n) {
      DWORD chunk = (DWORD)SD_MIN(n, 8192);
      if (!WriteConsoleW(h, s, chunk, &written, NULL) || written == 0)
        return;
      s += written;
      n -= written;
    }
  } else {
    char *u = NULL;
    if (sd_wide_to_utf8_alloc(s, n, SD_UTF_REPLACE, &u) == SD_OK) {
      size_t len = strlen(u), off = 0;
      while (off < len) {
        if (!WriteFile(h, u + off, (DWORD)SD_MIN(len - off, 65536), &written, NULL) || written == 0)
          break;
        off += written;
      }
      sd_free(u);
    }
  }
}

void cli_print(const wchar_t *s)
{
  HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
  if (g_quiet)
    return;
  write_handle(h, s, wcslen(s));
  write_handle(h, L"\r\n", 2);
}

void cli_eprint_raw(const wchar_t *s)
{
  write_handle(GetStdHandle(STD_ERROR_HANDLE), s, wcslen(s));
}

void cli_eprint(const wchar_t *s)
{
  HANDLE h = GetStdHandle(STD_ERROR_HANDLE);
  write_handle(h, s, wcslen(s));
  write_handle(h, L"\r\n", 2);
}

void cli_print_utf8_line(const char *s, size_t n)
{
  HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
  DWORD mode, written;
  if (h == NULL || h == INVALID_HANDLE_VALUE)
    return;
  if (GetConsoleMode(h, &mode)) {
    wchar_t *w = NULL;
    if (sd_utf8_to_wide_alloc(s, n, SD_UTF_REPLACE, &w) == SD_OK) {
      write_handle(h, w, wcslen(w));
      sd_free(w);
    }
    write_handle(h, L"\r\n", 2);
  } else {
    /* JSON is always UTF-8 regardless of the output encoding (03 §6.3) */
    WriteFile(h, s, (DWORD)n, &written, NULL);
    WriteFile(h, "\r\n", 2, &written, NULL);
  }
}

int cli_stdin_is_console(void)
{
  DWORD mode;
  HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
  return h != NULL && h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mode);
}

static int read_console_line(char *out, size_t cap, int echo)
{
  HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
  wchar_t buf[1024];
  DWORD mode = 0, got = 0;
  size_t n, u8 = 0;
  int ok;
  if (!GetConsoleMode(in, &mode))
    return 0;
  if (!echo) {
    g_saved_in = in;
    g_saved_mode = mode;
    InterlockedExchange(&g_mode_saved, 1);
    SetConsoleMode(in, (mode | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT) & ~(DWORD)ENABLE_ECHO_INPUT);
  }
  ok = ReadConsoleW(in, buf, SD_COUNTOF(buf) - 1, &got, NULL) && got > 0;
  if (!echo) {
    if (InterlockedCompareExchange(&g_mode_saved, 0, 1) == 1)
      SetConsoleMode(in, mode);
    cli_eprint_raw(L"\r\n");
  }
  if (!ok) {
    SecureZeroMemory(buf, sizeof(buf));
    return 0;
  }
  n = got;
  while (n && (buf[n - 1] == L'\n' || buf[n - 1] == L'\r')) n--;
  ok = sd_utf16_to_utf8(buf, n, out, cap - 1, &u8, SD_UTF_REPLACE) == SD_OK;
  SecureZeroMemory(buf, sizeof(buf));
  if (!ok)
    return 0;
  out[u8] = 0;
  return 1;
}

static int read_stdin_line(char *out, size_t cap)
{
  HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
  size_t n = 0;
  if (in == NULL || in == INVALID_HANDLE_VALUE)
    return 0;
  /* byte-wise up to LF so later prompts read the following lines */
  for (;;) {
    char c;
    DWORD got = 0;
    if (!ReadFile(in, &c, 1, &got, NULL) || got == 0) {
      if (n == 0) return 0;
      break;
    }
    if (c == '\n')
      break;
    if (n + 1 < cap)
      out[n++] = c;
  }
  if (n && out[n - 1] == '\r') n--;
  out[n] = 0;
  if (n >= 3 && (uint8_t)out[0] == 0xEF && (uint8_t)out[1] == 0xBB && (uint8_t)out[2] == 0xBF)
    memmove(out, out + 3, n - 2);
  return sd_utf8_valid(out, strlen(out));
}

int cli_read_line(char *out, size_t cap, int echo, int from_stdin)
{
  if (cap == 0)
    return 0;
  out[0] = 0;
  if (!from_stdin && cli_stdin_is_console())
    return read_console_line(out, cap, echo);
  if (from_stdin)
    return read_stdin_line(out, cap);
  return 0;
}
