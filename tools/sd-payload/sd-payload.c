/* sd-payload: attaches a setup payload to a copy of the setup stub (docs/design/04 §6.1).
 *
 *   sd-payload --base <stub.exe> --out <setup.exe> --flavour <x86-ia32|...> --cab <payload.cab>
 *
 * Writes the stub to <setup.exe> and adds two RT_RCDATA resources with UpdateResourceW:
 *   PAYLOAD_<FLAVOUR>  the CAB bytes (the flavour name in upper case, '-' replaced by '_');
 *   PAYLOAD_TABLE      one line "<flavour> <sha256 hex> <size>" (the stub verifies the hash before unpacking).
 * The PAYLOAD_SIG signature of the table (TM-R38) is not written yet: it waits for the release keyset
 * (04 §6.1, open item in docs/dev/m4-notes.md). Build-time tool, never shipped; the console and the
 * CRT are fine here, unlike in the stub. */
#define _CRT_SECURE_NO_WARNINGS 1
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void sd_setup_sha256(const void *data, size_t n, unsigned char out[32]);
int sd_setup_sha256_hex(const unsigned char sha[32], char out[65]);

static int fail(const char *what)
{
  fprintf(stderr, "sd-payload: %s\n", what);
  return 2;
}

static unsigned char *read_file(const char *path, size_t *size)
{
  FILE *f = fopen(path, "rb");
  unsigned char *buf;
  long n;

  if (f == NULL)
    return NULL;
  if (fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) < 0 || fseek(f, 0, SEEK_SET) != 0) {
    fclose(f);
    return NULL;
  }
  buf = (unsigned char *)malloc(n > 0 ? (size_t)n : 1);
  if (buf == NULL || fread(buf, 1, (size_t)n, f) != (size_t)n) {
    free(buf);
    fclose(f);
    return NULL;
  }
  fclose(f);
  *size = (size_t)n;
  return buf;
}

int main(int argc, char **argv)
{
  const char *base = NULL, *out = NULL, *flavour = NULL, *cab = NULL;
  wchar_t resname[64];
  wchar_t wflav[32];
  unsigned char *cab_bytes, *stub_bytes = NULL;
  size_t cab_size = 0, stub_size = 0;
  unsigned char sha[32];
  char hex[65];
  char table[256];
  HANDLE upd;
  size_t i;
  int n;
  int rc = 0;
  HANDLE f;
  DWORD written = 0;

  for (i = 1; i + 1 < (size_t)argc; i += 2) {
    if (strcmp(argv[i], "--base") == 0)
      base = argv[i + 1];
    else if (strcmp(argv[i], "--out") == 0)
      out = argv[i + 1];
    else if (strcmp(argv[i], "--flavour") == 0)
      flavour = argv[i + 1];
    else if (strcmp(argv[i], "--cab") == 0)
      cab = argv[i + 1];
    else
      return fail("unknown option");
  }
  if (base == NULL || out == NULL || flavour == NULL || cab == NULL)
    return fail("usage: sd-payload --base <stub> --out <exe> --flavour <name> --cab <cab>");
  if (strlen(flavour) >= sizeof(wflav) / sizeof(wflav[0]) - 1)
    return fail("flavour name too long");

  cab_bytes = read_file(cab, &cab_size);
  if (cab_bytes == NULL || cab_size == 0)
    return fail("cannot read the payload CAB");
  stub_bytes = read_file(base, &stub_size);
  if (stub_bytes == NULL || stub_size == 0)
    return fail("cannot read the stub");

  /* Copy the stub, then update its resources in the copy. */
  f = CreateFileA(out, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (f == INVALID_HANDLE_VALUE)
    return fail("cannot write the output");
  if (!WriteFile(f, stub_bytes, (DWORD)stub_size, &written, NULL) || written != stub_size) {
    CloseHandle(f);
    return fail("cannot copy the stub");
  }
  CloseHandle(f);

  sd_setup_sha256(cab_bytes, cab_size, sha);
  sd_setup_sha256_hex(sha, hex);
  n = _snprintf(table, sizeof(table), "%s %s %lu\r\n", flavour, hex, (unsigned long)cab_size);
  if (n <= 0 || n >= (int)sizeof(table))
    return fail("table overflow");

  for (i = 0; flavour[i] != '\0'; i++) {
    char c = flavour[i];
    if (c == '-')
      c = '_';
    else if (c >= 'a' && c <= 'z')
      c = (char)(c - 'a' + 'A');
    wflav[i] = (wchar_t)(unsigned char)c;
  }
  wflav[i] = L'\0';
  wcscpy(resname, L"PAYLOAD_");
  wcscat(resname, wflav);

  {
    wchar_t wout[MAX_PATH];
    int wl = MultiByteToWideChar(CP_ACP, 0, out, -1, wout, MAX_PATH);
    if (wl == 0)
      return fail("bad output path");
    upd = BeginUpdateResourceW(wout, FALSE);
  }
  if (upd == NULL)
    return fail("BeginUpdateResource failed");
  if (!UpdateResourceW(upd, RT_RCDATA, resname, 0, cab_bytes, (DWORD)cab_size) ||
      !UpdateResourceW(upd, RT_RCDATA, L"PAYLOAD_TABLE", 0, table, (DWORD)strlen(table))) {
    EndUpdateResourceW(upd, TRUE);
    return fail("UpdateResource failed");
  }
  if (!EndUpdateResourceW(upd, FALSE))
    rc = fail("EndUpdateResource failed");

  if (rc == 0)
    printf("sd-payload: %s (%lu bytes, sha256 %s)\n", out, (unsigned long)cab_size, hex);
  free(cab_bytes);
  free(stub_bytes);
  return rc;
}
