/* Test-only helpers (stdio and malloc are allowed in test binaries). */
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tutil.h"

#ifndef SD_TEST_VECTORS_DIR
#error SD_TEST_VECTORS_DIR must be defined by the build
#endif

_Ret_notnull_ _Post_writable_byte_size_(n) void *tu_alloc(size_t n)
{
  void *p = calloc(1, n ? n : 1);
  if (p == NULL)
    abort();
  return p;
}

static int hv(char c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

size_t tu_hexbuf(const char *hex, uint8_t *out, size_t cap)
{
  size_t n = 0;
  if (hex[0] == '-' && hex[1] == 0)
    return 0;
  while (hex[0] && hex[1]) {
    int a = hv(hex[0]), b = hv(hex[1]);
    if (a < 0 || b < 0 || n >= cap)
      return SIZE_MAX;
    out[n++] = (uint8_t)(a * 16 + b);
    hex += 2;
  }
  return hex[0] ? SIZE_MAX : n;
}

size_t tu_hex(const char *hex, uint8_t **out)
{
  size_t cap = strlen(hex) / 2 + 1, n;
  *out = (uint8_t *)tu_alloc(cap);
  n = tu_hexbuf(hex, *out, cap);
  if (n == SIZE_MAX)
    abort();
  return n;
}

size_t tu_base64(const char *s, uint8_t *out, size_t cap)
{
  uint32_t acc = 0;
  int bits = 0;
  size_t n = 0;
  for (; *s; s++) {
    int v;
    char c = *s;
    if (c >= 'A' && c <= 'Z') v = c - 'A';
    else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
    else if (c >= '0' && c <= '9') v = c - '0' + 52;
    else if (c == '+') v = 62;
    else if (c == '/') v = 63;
    else if (c == '=') break;
    else if (c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
    else return SIZE_MAX;
    acc = (acc << 6) | (uint32_t)v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      if (n >= cap)
        return SIZE_MAX;
      out[n++] = (uint8_t)(acc >> bits);
    }
  }
  return n;
}

char *tu_read_vector_file(const char *rel, size_t *len)
{
  char path[MAX_PATH];
  FILE *f;
  char *buf;
  long sz;
  if (_snprintf_s(path, sizeof(path), _TRUNCATE, "%s/%s", SD_TEST_VECTORS_DIR, rel) < 0)
    return NULL;
  if (fopen_s(&f, path, "rb") != 0)
    return NULL;
  fseek(f, 0, SEEK_END);
  sz = ftell(f);
  fseek(f, 0, SEEK_SET);
  buf = (char *)malloc((size_t)sz + 1);
  if (buf == NULL || fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
    fclose(f);
    free(buf);
    return NULL;
  }
  fclose(f);
  buf[sz] = 0;
  if (len)
    *len = (size_t)sz;
  return buf;
}

int tu_lines_open(tu_lines *l, const char *rel)
{
  l->buf = tu_read_vector_file(rel, NULL);
  l->pos = l->buf;
  return l->buf ? 0 : -1;
}

int tu_lines_next(tu_lines *l, char **fields, int max)
{
  for (;;) {
    char *line = l->pos, *end;
    int n = 0;
    if (line == NULL || *line == 0)
      return 0;
    end = strchr(line, '\n');
    if (end) {
      *end = 0;
      l->pos = end + 1;
    } else {
      l->pos = line + strlen(line);
    }
    if (end && end > line && end[-1] == '\r')
      end[-1] = 0;
    if (line[0] == '#' || line[0] == 0)
      continue;
    while (*line && n < max) {
      fields[n++] = line;
      while (*line && *line != ' ')
        line++;
      if (*line)
        *line++ = 0;
    }
    return n;
  }
}

void tu_lines_close(tu_lines *l)
{
  free(l->buf);
  l->buf = l->pos = NULL;
}

uint32_t tu_rand_u32(uint64_t *s)
{
  uint64_t x = *s;
  x ^= x << 13;
  x ^= x >> 7;
  x ^= x << 17;
  *s = x;
  return (uint32_t)(x >> 16);
}

void tu_rand_fill(uint64_t *s, uint8_t *p, size_t n)
{
  size_t i;
  for (i = 0; i < n; i++)
    p[i] = (uint8_t)tu_rand_u32(s);
}

double tu_seconds(void)
{
  LARGE_INTEGER f, c;
  QueryPerformanceFrequency(&f);
  QueryPerformanceCounter(&c);
  return (double)c.QuadPart / (double)f.QuadPart;
}
