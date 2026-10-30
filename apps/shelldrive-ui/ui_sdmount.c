/* shelldrive-ui: the .sdmount grammar (03 §8.1). See ui_sdmount.h. Pure. */
#include <windows.h>
#include <string.h>

#include "ui_sdmount.h"

static int is_space(unsigned char c)
{
  return c == ' ' || c == '\t';
}

static int is_hex_lower(unsigned char c)
{
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

/* Checks that the bytes are well-formed UTF-8 (MB_ERR_INVALID_CHARS rejects overlong and surrogate forms). */
static int utf8_ok(const unsigned char *p, size_t n)
{
  if (n == 0)
    return 1;
  return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (LPCSTR)p, (int)n, NULL, 0) > 0;
}

sd_err ui_sdmount_parse(const unsigned char *data, size_t bytes, char id[33])
{
  size_t pos = 0, end;
  int have = 0;

  if (id == NULL)
    return SD_E_INVALID_PARAM;
  id[0] = 0;
  if (data == NULL || bytes == 0 || bytes > UI_SDMOUNT_MAX_BYTES)
    return SD_E_INVALID_PARAM;
  if (bytes >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF)
    pos = 3;
  if (!utf8_ok(data + pos, bytes - pos))
    return SD_E_INVALID_PARAM;

  while (pos < bytes) {
    size_t i, line_end, k, vend;
    /* one line: [pos, line_end), the terminator is LF or CRLF */
    for (line_end = pos; line_end < bytes && data[line_end] != '\n'; line_end++)
      ;
    end = line_end;
    if (end > pos && data[end - 1] == '\r')
      end--;
    for (i = pos; i < end; i++)
      if (data[i] == 0)
        return SD_E_INVALID_PARAM;
    i = pos;
    while (i < end && is_space(data[i]))
      i++;
    if (i < end && data[i] != '#' && data[i] != ';') {
      char key[8];
      size_t kn = 0;
      /* key: the letters of "profile", then spaces, "=", spaces, the value */
      while (i < end && kn < sizeof(key) - 1 && data[i] >= 'a' && data[i] <= 'z') {
        key[kn++] = (char)data[i++];
      }
      key[kn] = 0;
      while (i < end && is_space(data[i]))
        i++;
      if (strcmp(key, "profile") != 0 || i >= end || data[i] != '=')
        return SD_E_INVALID_PARAM;
      i++;
      while (i < end && is_space(data[i]))
        i++;
      /* the value is the text up to the last non-space character: exactly 32 lower case hex digits */
      vend = end;
      while (vend > i && is_space(data[vend - 1]))
        vend--;
      if (vend - i != 32)
        return SD_E_INVALID_PARAM;
      for (k = 0; k < 32; k++)
        if (!is_hex_lower(data[i + k]))
          return SD_E_INVALID_PARAM;
      if (have)
        return SD_E_INVALID_PARAM;
      have = 1;
      memcpy(id, data + i, 32);
      id[32] = 0;
    }
    pos = line_end < bytes ? line_end + 1 : bytes;
  }
  return have ? SD_OK : SD_E_INVALID_PARAM;
}
