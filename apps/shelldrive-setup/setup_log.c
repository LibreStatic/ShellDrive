/* shelldrive-setup: the setup log (docs/design/04 §13). English lines, UTF-8, one file per run. The
   engine runs on one thread, so the log handle is process state. Failures to log never stop setup. */
#include "setup_int.h"

#include <string.h>

static HANDLE g_log = INVALID_HANDLE_VALUE;
static wchar_t g_log_path[MAX_PATH];

int sd_setup_log_open(const wchar_t *path)
{
  HANDLE h;

  if (g_log != INVALID_HANDLE_VALUE) {
    CloseHandle(g_log);
    g_log = INVALID_HANDLE_VALUE;
  }
  g_log_path[0] = L'\0';
  if (path == NULL || path[0] == L'\0')
    return 1;
  h = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE)
    return 1;
  SetFilePointer(h, 0, NULL, FILE_END);
  g_log = h;
  StringCchCopyW(g_log_path, MAX_PATH, path);
  return 0;
}

const wchar_t *sd_setup_log_path(void)
{
  return g_log_path;
}

/* One line: "YYYY-MM-DD HH:MM:SS <event> <text>\r\n", the text converted to UTF-8. */
void sd_setup_log(const char *event, const wchar_t *text)
{
  SYSTEMTIME st;
  char line[2048];
  char utf8[1536];
  char stamp[32];
  DWORD written = 0;

  if (g_log == INVALID_HANDLE_VALUE)
    return;
  GetLocalTime(&st);
  StringCchPrintfA(stamp, sizeof(stamp), "%04u-%02u-%02u %02u:%02u:%02u ",
                   (unsigned)st.wYear, (unsigned)st.wMonth, (unsigned)st.wDay,
                   (unsigned)st.wHour, (unsigned)st.wMinute, (unsigned)st.wSecond);
  if (WideCharToMultiByte(CP_UTF8, 0, text != NULL ? text : L"", -1, utf8, (int)sizeof(utf8), NULL, NULL) <= 0)
    utf8[0] = '\0';
  StringCchPrintfA(line, sizeof(line), "%s%s %s\r\n", stamp, event != NULL ? event : "event", utf8);
  WriteFile(g_log, line, (DWORD)strlen(line), &written, NULL);
}

void sd_setup_log_close(void)
{
  if (g_log != INVALID_HANDLE_VALUE)
    CloseHandle(g_log);
  g_log = INVALID_HANDLE_VALUE;
  g_log_path[0] = L'\0';
}
