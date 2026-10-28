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

/* Our two shell extension CLSIDs (packaging/registration.txt). Keys under them are ours, whatever their names. */
static const wchar_t k_clsid_context_menu[] = L"{C2A44993-862B-42AB-B40B-254EFB1F5C43}";
static const wchar_t k_clsid_this_pc[] = L"{5E1C7D02-3B8F-4A9E-9C61-7D24A0F3B5E8}";

/* True when the last component of subkey is ours: it names ShellDrive or the executable. */
static int leaf_is_ours(const wchar_t *subkey)
{
  const wchar_t *leaf = wcsrchr(subkey, L'\\');
  leaf = leaf != NULL ? leaf + 1 : subkey;
  return contains_text(leaf, L"ShellDrive") || contains_text(leaf, L"shelldrive-ui.exe");
}

/* Keys we may delete when empty. Only the rows of packaging/registration.txt are candidates, so no parent that no row
   names is ever deleted. Of those, only keys we own: the last component names ShellDrive or shelldrive-ui.exe, or the
   key sits under one of our CLSIDs (the CLSID key and its InprocServer32). Shared keys (Run, Approved, shellex,
   ContextMenuHandlers, the Windows This PC CLSID) never qualify. */
static int row_is_product_key(const wchar_t *subkey)
{
  return leaf_is_ours(subkey) || contains_text(subkey, k_clsid_context_menu) || contains_text(subkey, k_clsid_this_pc);
}

/* ------------------------------------------------------------------ machine (MSI) registry */

#ifndef KEY_WOW64_64KEY
#define KEY_WOW64_64KEY 0x0100
#endif
#ifndef KEY_WOW64_32KEY
#define KEY_WOW64_32KEY 0x0200
#endif

static const wchar_t k_arp_root[] = L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
static const wchar_t k_machine_state[] = L"Software\\LibreStatic\\ShellDrive";

/* Reads a REG_SZ value of an open key. 1 when it is not there or not a string. */
static int key_sz(HKEY hk, const wchar_t *name, wchar_t *out, DWORD cbytes)
{
  DWORD type = 0;
  DWORD size = cbytes;
  if (out == NULL || cbytes < sizeof(wchar_t))
    return 1;
  if (RegQueryValueExW(hk, name, NULL, &type, (BYTE *)out, &size) != ERROR_SUCCESS || type != REG_SZ)
    return 1;
  out[cbytes / sizeof(wchar_t) - 1] = L'\0';
  return 0;
}

/* 1 when name has the shape of a product code: braces, 36 characters, hyphens in the GUID places. */
static int product_name_ok(const wchar_t *name)
{
  size_t i;
  if (wcslen(name) != 38 || name[0] != L'{' || name[37] != L'}')
    return 0;
  for (i = 1; i < 37; i++) {
    int dash = (i == 9 || i == 14 || i == 19 || i == 24);
    wchar_t c = name[i];
    if (dash) {
      if (c != L'-')
        return 0;
    } else if (!((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') || (c >= L'A' && c <= L'F'))) {
      return 0;
    }
  }
  return 1;
}

/* 1 when the open Uninstall entry is the ShellDrive MSI product of LibreStatic (Windows Installer sets WindowsInstaller). */
static int entry_is_shelldrive_msi(HKEY hk)
{
  wchar_t text[128];
  DWORD type = 0;
  DWORD size = sizeof(DWORD);
  DWORD installer = 0;

  if (key_sz(hk, L"DisplayName", text, sizeof(text)) != 0 || _wcsicmp(text, L"ShellDrive") != 0)
    return 0;
  if (key_sz(hk, L"Publisher", text, sizeof(text)) != 0 || _wcsicmp(text, L"LibreStatic") != 0)
    return 0;
  if (RegQueryValueExW(hk, L"WindowsInstaller", NULL, &type, (BYTE *)&installer, &size) != ERROR_SUCCESS ||
      type != REG_DWORD || installer != 1)
    return 0;
  return 1;
}

int sd_setup_machine_product(wchar_t *code, size_t cch)
{
  static const REGSAM views[2] = { KEY_WOW64_64KEY, KEY_WOW64_32KEY };
  size_t v;

  if (code == NULL || cch < 39)
    return 0;
  for (v = 0; v < 2; v++) {
    HKEY root = NULL;
    DWORD index;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, k_arp_root, 0, KEY_READ | views[v], &root) != ERROR_SUCCESS)
      continue;
    for (index = 0;; index++) {
      wchar_t name[128];
      DWORD len = SD_SETUP_COUNTOF(name);
      HKEY entry = NULL;
      int found;

      if (RegEnumKeyExW(root, index, name, &len, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
        break;
      if (!product_name_ok(name) || RegOpenKeyExW(root, name, 0, KEY_READ, &entry) != ERROR_SUCCESS)
        continue;
      found = entry_is_shelldrive_msi(entry);
      RegCloseKey(entry);
      if (found) {
        StringCchCopyW(code, cch, name);
        RegCloseKey(root);
        return 1;
      }
    }
    RegCloseKey(root);
  }
  return 0;
}

int sd_setup_machine_install_dir(wchar_t *out, size_t cch)
{
  static const REGSAM views[2] = { KEY_WOW64_64KEY, KEY_WOW64_32KEY };
  size_t v;

  if (out == NULL || cch == 0)
    return 1;
  for (v = 0; v < 2; v++) {
    HKEY hk = NULL;
    wchar_t raw[MAX_PATH * 2];
    size_t n;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, k_machine_state, 0, KEY_READ | views[v], &hk) != ERROR_SUCCESS)
      continue;
    if (key_sz(hk, L"InstallDir", raw, sizeof(raw)) == 0) {
      RegCloseKey(hk);
      if (FAILED(StringCchCopyW(out, cch, raw)))
        return 1;
      n = wcslen(out);
      while (n > 0 && out[n - 1] == L'\\')
        out[--n] = L'\0';
      return n > 0 ? 0 : 1;
    }
    RegCloseKey(hk);
  }
  return 1;
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
