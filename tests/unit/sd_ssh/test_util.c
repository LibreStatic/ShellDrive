#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "sd_base/sd_mem.h"
#include "ssh_internal.h"
#include "test_util.h"

int tu_read_fixture(const char *name, uint8_t **buf, size_t *len)
{
  char path[MAX_PATH];
  FILE *f;
  long n;
  if (_snprintf_s(path, sizeof(path), _TRUNCATE, "%s/%s", SD_SSH_TEST_FIXTURES, name) < 0) return 0;
  if (fopen_s(&f, path, "rb") != 0 || !f) return 0;
  fseek(f, 0, SEEK_END);
  n = ftell(f);
  fseek(f, 0, SEEK_SET);
  *buf = (uint8_t *)sd_alloc((size_t)n + 1);
  if (!*buf) { fclose(f); return 0; }
  *len = fread(*buf, 1, (size_t)n, f);
  (*buf)[*len] = 0;
  fclose(f);
  return *len == (size_t)n;
}

int tu_crypto_or_skip(const char *test)
{
  if (ssh_crypto_ready()) return 1;
  printf("  [skip] %s: sd_crypto_init failed\n", test);
  return 0;
}

static uint32_t g_det = 0x12345678u;

sd_err tu_det_random(void *p, size_t n)
{
  uint8_t *b = (uint8_t *)p;
  size_t i;
  for (i = 0; i < n; i++) {
    g_det ^= g_det << 13; g_det ^= g_det >> 17; g_det ^= g_det << 5;
    b[i] = (uint8_t)g_det;
  }
  return SD_OK;
}

int tu_temp_path(const wchar_t *name, wchar_t *out, size_t cap)
{
  wchar_t tmp[MAX_PATH];
  DWORD n = GetTempPathW(MAX_PATH, tmp);
  if (n == 0 || n >= MAX_PATH) return 0;
  return _snwprintf_s(out, cap, _TRUNCATE, L"%ssd-test-ssh-%lu-%s", tmp, (unsigned long)GetCurrentProcessId(), name) > 0;
}
