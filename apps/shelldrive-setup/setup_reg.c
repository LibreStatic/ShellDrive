/* shelldrive-setup: account registration (docs/design/04 §6.6, §6.7). The rows come from
   packaging/registration.txt through the generated table sd_setup_regtable (one source for the per-user
   setup and the MSI registry tables). Placeholders are expanded here: [INSTALLDIR], [VERSION], [FLAVOUR],
   [SIZEKB]. Removal deletes our values and only the keys this product owns and that end up empty. */
#include "setup_int.h"

#include <stdlib.h>
#include <string.h>

/* Expands the [PLACEHOLDER] tokens of a row into out. Unknown tokens stay as written. */
static int expand(const wchar_t *src, wchar_t *out, size_t cch, const sd_setup_regctx *c)
{
  size_t o = 0;
  const wchar_t *p = src;

  while (*p != L'\0') {
    const wchar_t *close;
    size_t tlen;
    const wchar_t *rep = NULL;
    wchar_t num[24];

    if (*p == L'[' && (close = wcschr(p, L']')) != NULL) {
      tlen = (size_t)(close - p) + 1;
      if (tlen == 12 && wcsncmp(p, L"[INSTALLDIR]", 12) == 0)
        rep = c->install_dir;
      else if (tlen == 9 && wcsncmp(p, L"[VERSION]", 9) == 0)
        rep = c->version;
      else if (tlen == 9 && wcsncmp(p, L"[FLAVOUR]", 9) == 0)
        rep = c->flavour;
      else if (tlen == 8 && wcsncmp(p, L"[SIZEKB]", 8) == 0) {
        unsigned long long kb = (c->install_bytes + 1023) / 1024;
        StringCchPrintfW(num, SD_SETUP_COUNTOF(num), L"%I64u", kb);
        rep = num;
      }
      if (rep != NULL) {
        size_t rl = wcslen(rep);
        if (o + rl >= cch)
          return 1;
        memcpy(out + o, rep, rl * sizeof(wchar_t));
        o += rl;
        p += tlen;
        continue;
      }
    }
    if (o + 1 >= cch)
      return 1;
    out[o++] = *p++;
  }
  out[o] = L'\0';
  return 0;
}

/* True when needle occurs in hay. Local: the CRT wcsstr is not on the IA32 ISA allowlist (04 §2.4). */
static int contains_text(const wchar_t *hay, const wchar_t *needle)
{
  size_t nl = wcslen(needle);
  for (; *hay != L'\0'; hay++) {
    if (wcsncmp(hay, needle, nl) == 0)
      return 1;
  }
  return 0;
}

static int row_is_product_key(const wchar_t *subkey)
{
  /* Keys we may delete when empty. Shared keys (Run, App Paths parent, Uninstall parent) are never
     deleted: only the entries that name ShellDrive or its executable. */
  return contains_text(subkey, L"ShellDrive") || contains_text(subkey, L"shelldrive-ui.exe");
}

int sd_setup_reg_apply(const sd_setup_regctx *c)
{
  size_t i;
  wchar_t data[MAX_PATH * 4];

  for (i = 0; i < sd_setup_regtable_count; i++) {
    const sd_setup_regrow *row = &sd_setup_regtable[i];
    HKEY hk = NULL;
    LONG rc;
    DWORD disp = 0;

    if (row->autostart && !c->autostart)
      continue;
    if (expand(row->data, data, SD_SETUP_COUNTOF(data), c) != 0)
      return SD_SETUP_EXIT_FATAL;

    rc = RegCreateKeyExW(c->root, row->subkey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hk,
                         &disp);
    if (rc != ERROR_SUCCESS) {
      sd_setup_log_error("reg.create", row->subkey, (DWORD)rc);
      return SD_SETUP_EXIT_FATAL;
    }
    if (row->is_dword) {
      DWORD v = (DWORD)_wtol(data);
      rc = RegSetValueExW(hk, row->name, 0, REG_DWORD, (const BYTE *)&v, sizeof(v));
    } else {
      rc = RegSetValueExW(hk, row->name, 0, REG_SZ, (const BYTE *)data,
                          (DWORD)((wcslen(data) + 1) * sizeof(wchar_t)));
    }
    RegCloseKey(hk);
    if (rc != ERROR_SUCCESS) {
      sd_setup_log_error("reg.set", row->subkey, (DWORD)rc);
      return SD_SETUP_EXIT_FATAL;
    }
  }
  return 0;
}

int sd_setup_reg_remove(const sd_setup_regctx *c)
{
  size_t i;

  for (i = 0; i < sd_setup_regtable_count; i++) {
    const sd_setup_regrow *row = &sd_setup_regtable[i];
    HKEY hk = NULL;

    /* An empty name is the key's default value, deleted the same way (so an emptied key can go). */
    if (RegOpenKeyExW(c->root, row->subkey, 0, KEY_SET_VALUE, &hk) == ERROR_SUCCESS) {
      RegDeleteValueW(hk, row->name != NULL ? row->name : L"");
      RegCloseKey(hk);
    }
  }

  /* Keys that belong to ShellDrive and are now empty. Walk the table backwards so that children go first. */
  for (i = sd_setup_regtable_count; i > 0; i--) {
    const sd_setup_regrow *row = &sd_setup_regtable[i - 1];
    HKEY hk = NULL;
    DWORD subkeys = 0, values = 0;

    if (!row_is_product_key(row->subkey))
      continue;
    if (RegOpenKeyExW(c->root, row->subkey, 0, KEY_READ, &hk) != ERROR_SUCCESS)
      continue;
    if (RegQueryInfoKeyW(hk, NULL, NULL, NULL, &subkeys, NULL, NULL, &values, NULL, NULL, NULL, NULL) ==
        ERROR_SUCCESS && subkeys == 0 && values == 0) {
      RegCloseKey(hk);
      hk = NULL;
      RegDeleteKeyW(c->root, row->subkey);
    }
    if (hk != NULL)
      RegCloseKey(hk);
  }
  return 0;
}
