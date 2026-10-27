/* shelldrive-ui: rows of the host key manager (03 §5.1, §5.6). See ui_hostkeys_model.h.
 *
 * Pure: no window or process calls. */
#include <windows.h>
#include <string.h>
#include <wchar.h>

#include "ui_hostkeys_model.h"

#define UI_HK_DEFAULT_PORT 22u

static void put_ascii(wchar_t *dst, size_t cap, const char *src)
{
  size_t i;
  if (cap == 0)
    return;
  for (i = 0; i + 1 < cap && src != NULL && src[i] != '\0'; i++)
    dst[i] = (src[i] >= 0x20 && src[i] < 0x7f) ? (wchar_t)(unsigned char)src[i] : L'?';
  dst[i] = L'\0';
}

static void put_wide(wchar_t *dst, size_t cap, const wchar_t *src)
{
  if (cap == 0)
    return;
  if (src == NULL)
    src = L"";
  wcsncpy_s(dst, cap, src, _TRUNCATE);
}

static int is_digit(char c)
{
  return c >= '0' && c <= '9';
}

/* "[host]:port" with a port 1..65535. */
static int parse_bracketed(const char *p, char *host, size_t host_cap, unsigned *port)
{
  const char *close = strchr(p, ']');
  size_t hl, i;
  unsigned long v = 0;
  if (p[0] != '[' || close == NULL)
    return 0;
  hl = (size_t)(close - (p + 1));
  if (hl == 0 || hl + 1 > host_cap || close[1] != ':' || !is_digit(close[2]))
    return 0;
  for (i = 2; close[i] != '\0'; i++) {
    if (!is_digit(close[i]) || v > 65535)
      return 0;
    v = v * 10u + (unsigned long)(close[i] - '0');
  }
  if (v == 0 || v > 65535)
    return 0;
  memcpy(host, p + 1, hl);
  host[hl] = '\0';
  *port = (unsigned)v;
  return 1;
}

sd_err ui_hk_row_init(ui_hk_row *row, ui_hk_store store, const char *pattern, int hashed, const char *type,
                      const char *fp, uint32_t line)
{
  size_t pl;
  if (row == NULL || pattern == NULL || type == NULL || fp == NULL)
    return SD_E_INVALID_PARAM;
  if (store != UI_HK_STORE_MACHINE && store != UI_HK_STORE_USER)
    return SD_E_INVALID_PARAM;
  pl = strlen(pattern);
  if (pl == 0 || pl >= UI_HK_HOST_MAX || strlen(type) >= UI_HK_TYPE_MAX || strlen(fp) >= UI_HK_FP_MAX)
    return SD_E_INVALID_PARAM;

  memset(row, 0, sizeof(*row));
  row->store = store;
  row->line = line;
  row->hashed = hashed ? 1 : 0;
  strcpy_s(row->type, sizeof(row->type), type);
  strcpy_s(row->fp, sizeof(row->fp), fp);
  strcpy_s(row->pattern, sizeof(row->pattern), pattern);
  row->port = UI_HK_DEFAULT_PORT;

  if (row->hashed || pattern[0] == '|') {
    row->hashed = 1;
    return SD_OK;
  }
  if (strchr(pattern, ',') != NULL || strchr(pattern, '*') != NULL || strchr(pattern, '?') != NULL ||
      strchr(pattern, '!') != NULL) {
    /* a list or a wildcard: shown as written, removed only through the file editor */
    strcpy_s(row->host, sizeof(row->host), pattern);
    return SD_OK;
  }
  if (pattern[0] == '[') {
    if (!parse_bracketed(pattern, row->host, sizeof(row->host), &row->port))
      return SD_OK;                       /* malformed: shown as written, not removable */
    strcpy_s(row->lookup, sizeof(row->lookup), pattern);
    row->removable = 1;
    return SD_OK;
  }
  strcpy_s(row->host, sizeof(row->host), pattern);
  strcpy_s(row->lookup, sizeof(row->lookup), pattern);
  row->removable = 1;
  return SD_OK;
}

void ui_hk_row_cells(const ui_hk_row *row, const wchar_t *hashed_text, const wchar_t *machine_text,
                     const wchar_t *user_text, wchar_t cells[UI_HK_CELLS][UI_HK_CELL_MAX])
{
  memset(cells, 0, sizeof(wchar_t) * UI_HK_CELLS * UI_HK_CELL_MAX);
  if (row->hashed) {
    put_wide(cells[0], UI_HK_CELL_MAX, hashed_text);
    cells[1][0] = L'\0';
  } else {
    put_ascii(cells[0], UI_HK_CELL_MAX, row->host);
    swprintf_s(cells[1], UI_HK_CELL_MAX, L"%u", row->port);
  }
  put_ascii(cells[2], UI_HK_CELL_MAX, row->type);
  put_ascii(cells[3], UI_HK_CELL_MAX, row->fp);
  put_wide(cells[4], UI_HK_CELL_MAX, row->store == UI_HK_STORE_MACHINE ? machine_text : user_text);
}

void ui_hk_announce_cells(const char *host, int action, const char *type, const char *fp,
                          const wchar_t *add_text, const wchar_t *remove_text,
                          wchar_t cells[4][UI_HK_CELL_MAX])
{
  memset(cells, 0, sizeof(wchar_t) * 4 * UI_HK_CELL_MAX);
  put_ascii(cells[0], UI_HK_CELL_MAX, host);
  put_wide(cells[1], UI_HK_CELL_MAX, action ? add_text : remove_text);
  put_ascii(cells[2], UI_HK_CELL_MAX, type);
  put_ascii(cells[3], UI_HK_CELL_MAX, fp);
}
