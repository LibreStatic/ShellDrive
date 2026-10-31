/* shelldrive-shellext.dll: COM server, class factories, the context menu handlers (03 §8.2).
 *
 * One object implements IShellExtInit and IContextMenu. Each interface is a subobject with its own vtable
 * (the usual C pattern), so QueryInterface returns different pointers for the two interfaces and both
 * recover the object with CONTAINING_RECORD. Two classes share the object:
 *
 *   SHX_CLSID_CONTEXT_MENU   Drive, Directory and * registrations. The selection is one path; the state section
 *                            says whether it is on a ShellDrive drive (8.2.1). Items:
 *       drive root           Open, Unmount, Reconnect, Copy remote path (by state and flags)
 *       inside a drive       Copy remote path
 *   SHX_CLSID_COMPUTER_MENU  This PC. Items: "Mount with ShellDrive" submenu (profiles from menu.cache, 8.2.2)
 *                            and "Open ShellDrive".
 *
 * Menu planning, remote path formatting and the menu.cache parser are pure functions in shellext_model.c.
 * InvokeCommand starts shelldrive-ui.exe --action <verb> <arg> and returns; it never waits. Copy remote path
 * puts the text on the clipboard in process (no UI process, no wait beyond a bounded clipboard retry). */
#define INITGUID
#include <windows.h>
#include <objidl.h>
#include <shlobj.h>
#include <shellapi.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "sd_base/sd_mem.h"
#include "sd_l10n/sd_l10n.h"
#include "sd_l10n_shell_ids.h"
#include "shellext_int.h"
#include "shellext_snapshot.h"

#ifndef GCS_UNICODE
#define GCS_UNICODE 0x00000004
#endif
#ifndef CMIC_MASK_UNICODE
#define CMIC_MASK_UNICODE 0x00004000
#endif

/* Profiles shown + "More connections" + "Open ShellDrive" (computer), or at most four drive items. */
#define SX_MAX_ACTIONS (SHX_SUBMENU_MAX + 2u)
#define SX_PATH_UNITS  (3u + SHX_REL_MAX + 1u)

typedef struct sx_action {
  shx_act act;
  wchar_t arg[SHX_ID_UNITS + 1];        /* profile id for SHX_ACT_MOUNT_PROFILE */
} sx_action;

typedef struct SxObject {
  IShellExtInit init;            /* first subobject: IShellExtInit (and IUnknown through it) */
  IContextMenu menu;             /* second subobject: IContextMenu */
  LONG refs;
  int computer;                  /* 1: the This PC class */
  wchar_t letter;                /* drive letter of the one selected path, 0 if none */
  int is_root;                   /* the selected path is the drive root */
  wchar_t rel[SHX_REL_MAX + 1];  /* the path below the drive root */
  wchar_t copy[SHX_COPY_MAX];    /* text for Copy remote path, built by QueryContextMenu */
  unsigned action_count;         /* command ids used by the last QueryContextMenu */
  sx_action actions[SX_MAX_ACTIONS];
} SxObject;

typedef struct SxFactory {
  IClassFactory iface;
  int computer;
} SxFactory;

HINSTANCE shx_module = NULL;

static volatile LONG g_objects = 0;   /* live objects (DllCanUnloadNow) */
static volatile LONG g_locks = 0;     /* LockServer count */
static volatile LONG g_l10n_state = 0;  /* 0 not started, 1 starting, 2 ready */

/* ---- localization (03 §9.3): initialized once per process, on first use ---- */

static void sx_l10n_ready(void)
{
  unsigned spins;
  if (InterlockedCompareExchange(&g_l10n_state, 1, 0) == 0) {
    /* Language resolution (03 §9.3): a shell extension has no command line, so SHELLDRIVE_LANG (a user
       variable, inherited by Explorer) ranks before the user UI language, as in the CLI and the tray app. */
    wchar_t lang[32];
    if (GetEnvironmentVariableW(L"SHELLDRIVE_LANG", lang, SD_COUNTOF(lang)) - 1u < SD_COUNTOF(lang) - 1u)
      sd_l10n_init(&sd_l10n_catalog_shell, lang);
    else
      sd_l10n_init(&sd_l10n_catalog_shell, NULL);
    InterlockedExchange(&g_l10n_state, 2);
    return;
  }
  /* Another thread is initializing: wait briefly (the work is a few registry reads). */
  for (spins = 0; InterlockedCompareExchange(&g_l10n_state, 2, 2) != 2 && spins < 1000; spins++)
    Sleep(1);
}

static const wchar_t *sx_menu_text(shx_act a)
{
  switch (a) {
  case SHX_ACT_UNMOUNT:   return sd_l10n_get(SD_MSG_SHELL_MENU_UNMOUNT);
  case SHX_ACT_RECONNECT: return sd_l10n_get(SD_MSG_SHELL_MENU_RECONNECT);
  case SHX_ACT_COPY_PATH: return sd_l10n_get(SD_MSG_SHELL_MENU_COPY_REMOTE_PATH);
  case SHX_ACT_SHOW:      return sd_l10n_get(SD_MSG_SHELL_MENU_OPEN_SHELLDRIVE);
  default:                return sd_l10n_get(SD_MSG_SHELL_MENU_OPEN);
  }
}

static const wchar_t *sx_help_text(shx_act a)
{
  switch (a) {
  case SHX_ACT_UNMOUNT:       return sd_l10n_get(SD_MSG_SHELL_HELP_UNMOUNT);
  case SHX_ACT_RECONNECT:     return sd_l10n_get(SD_MSG_SHELL_HELP_RECONNECT);
  case SHX_ACT_COPY_PATH:     return sd_l10n_get(SD_MSG_SHELL_HELP_COPY_REMOTE_PATH);
  case SHX_ACT_MOUNT_PROFILE: return sd_l10n_get(SD_MSG_SHELL_HELP_MOUNT_PROFILE);
  case SHX_ACT_SHOW:          return sd_l10n_get(SD_MSG_SHELL_HELP_OPEN_SHELLDRIVE);
  case SHX_ACT_NONE:          return sd_l10n_get(SD_MSG_SHELL_HELP_MOUNT_SUBMENU);
  default:                    return sd_l10n_get(SD_MSG_SHELL_HELP_OPEN);
  }
}

/* Machine-readable names: GCS_VERB and string verbs in InvokeCommand. Not shown to the user. Returns 0 when the
   action has none. */
static int sx_verb_name(const sx_action *a, wchar_t *out, size_t cch)
{
  const wchar_t *base;
  switch (a->act) {
  case SHX_ACT_UNMOUNT:       base = L"shelldrive.unmount"; break;
  case SHX_ACT_RECONNECT:     base = L"shelldrive.reconnect"; break;
  case SHX_ACT_COPY_PATH:     base = L"shelldrive.copyremotepath"; break;
  case SHX_ACT_SHOW:          base = L"shelldrive.show"; break;
  case SHX_ACT_OPEN:          base = L"shelldrive.open"; break;
  case SHX_ACT_MOUNT_PROFILE: base = L"shelldrive.mount."; break;
  default:                    return 0;
  }
  if (wcslen(base) + (a->act == SHX_ACT_MOUNT_PROFILE ? wcslen(a->arg) : 0) + 1 > cch)
    return 0;
  wcscpy_s(out, cch, base);
  if (a->act == SHX_ACT_MOUNT_PROFILE)
    wcscat_s(out, cch, a->arg);
  return 1;
}

/* ---- object lifetime and IUnknown ---- */

static HRESULT sx_qi(SxObject *o, REFIID riid, void **ppv)
{
  if (ppv == NULL)
    return E_POINTER;
  *ppv = NULL;
  if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IShellExtInit))
    *ppv = &o->init;
  else if (IsEqualIID(riid, &IID_IContextMenu))
    *ppv = &o->menu;
  else
    return E_NOINTERFACE;
  InterlockedIncrement(&o->refs);
  return S_OK;
}

static ULONG sx_release(SxObject *o)
{
  LONG r = InterlockedDecrement(&o->refs);
  if (r == 0) {
    sd_free(o);
    InterlockedDecrement(&g_objects);
  }
  return (ULONG)(r < 0 ? 0 : r);
}

/* ---- IShellExtInit ---- */

static HRESULT STDMETHODCALLTYPE init_QueryInterface(IShellExtInit *This, REFIID riid, void **ppv)
{
  return sx_qi(CONTAINING_RECORD(This, SxObject, init), riid, ppv);
}

static ULONG STDMETHODCALLTYPE init_AddRef(IShellExtInit *This)
{
  SxObject *o = CONTAINING_RECORD(This, SxObject, init);
  return (ULONG)InterlockedIncrement(&o->refs);
}

static ULONG STDMETHODCALLTYPE init_Release(IShellExtInit *This)
{
  return sx_release(CONTAINING_RECORD(This, SxObject, init));
}

static int sx_is_letter(wchar_t c)
{
  return (c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z');
}

/* Reads the selected path (CF_HDROP). Exactly one path counts, and only "X:\" or "X:\something": a UNC path or
   a second selected item gives no items. */
static HRESULT STDMETHODCALLTYPE init_Initialize(IShellExtInit *This, LPCITEMIDLIST pidlFolder,
                                                 IDataObject *pdtobj, HKEY hkeyProgID)
{
  SxObject *o = CONTAINING_RECORD(This, SxObject, init);
  FORMATETC fe;
  STGMEDIUM sm;
  HDROP drop;
  UINT count, len;
  wchar_t path[SX_PATH_UNITS + 1];
  HRESULT hr;

  (void)pidlFolder;
  (void)hkeyProgID;
  o->letter = 0;
  o->is_root = 0;
  o->rel[0] = 0;
  sx_l10n_ready();
  if (o->computer)
    return S_OK;                        /* the class says what is meant; the data object is not needed */
  if (pdtobj == NULL)
    return E_INVALIDARG;

  memset(&fe, 0, sizeof(fe));
  fe.cfFormat = CF_HDROP;
  fe.dwAspect = DVASPECT_CONTENT;
  fe.lindex = -1;
  fe.tymed = TYMED_HGLOBAL;
  memset(&sm, 0, sizeof(sm));
  hr = pdtobj->lpVtbl->GetData(pdtobj, &fe, &sm);
  if (FAILED(hr))
    return hr;
  if (sm.tymed != TYMED_HGLOBAL || sm.hGlobal == NULL) {
    ReleaseStgMedium(&sm);
    return E_INVALIDARG;
  }
  drop = (HDROP)sm.hGlobal;
  count = DragQueryFileW(drop, 0xFFFFFFFFu, NULL, 0);
  if (count == 1) {
    len = DragQueryFileW(drop, 0, NULL, 0);
    if (len >= 3 && len < SX_PATH_UNITS) {
      UINT got = DragQueryFileW(drop, 0, path, SX_PATH_UNITS);
      if (got == len && sx_is_letter(path[0]) && path[1] == L':' && path[2] == L'\\') {
        wchar_t letter = (wchar_t)((path[0] >= L'a' && path[0] <= L'z') ? path[0] - (L'a' - L'A') : path[0]);
        if (len == 3) {
          o->letter = letter;
          o->is_root = 1;
        } else if (path[3] != L'\\') {
          o->letter = letter;
          wcscpy_s(o->rel, SD_COUNTOF(o->rel), path + 3);
        }
      }
    }
  }
  ReleaseStgMedium(&sm);
  return S_OK;
}

/* ---- IContextMenu ---- */

static HRESULT STDMETHODCALLTYPE menu_QueryInterface(IContextMenu *This, REFIID riid, void **ppv)
{
  return sx_qi(CONTAINING_RECORD(This, SxObject, menu), riid, ppv);
}

static ULONG STDMETHODCALLTYPE menu_AddRef(IContextMenu *This)
{
  SxObject *o = CONTAINING_RECORD(This, SxObject, menu);
  return (ULONG)InterlockedIncrement(&o->refs);
}

static ULONG STDMETHODCALLTYPE menu_Release(IContextMenu *This)
{
  return sx_release(CONTAINING_RECORD(This, SxObject, menu));
}

static void sx_add_action(SxObject *o, shx_act a, const wchar_t *arg)
{
  if (o->action_count < SX_MAX_ACTIONS) {
    sx_action *s = &o->actions[o->action_count++];
    s->act = a;
    s->arg[0] = 0;
    if (arg != NULL)
      wcsncpy_s(s->arg, SD_COUNTOF(s->arg), arg, _TRUNCATE);
  }
}

/* Only the faults a mapped read can raise are caught (access violation, in-page error); anything else keeps
   searching for a handler, as usual. */
static int sx_fault_filter(unsigned long code)
{
  return (code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_IN_PAGE_ERROR) ? EXCEPTION_EXECUTE_HANDLER
                                                                              : EXCEPTION_CONTINUE_SEARCH;
}

/* Decides the items of a path from the snapshot. Runs under __try: a parser fault must not reach Explorer. */
static void sx_build_path_actions(SxObject *o, shx_entry *ents)
{
  size_t n, i;

  o->action_count = 0;
  o->copy[0] = 0;
  __try {
    n = shx_snapshot_read(ents, SHX_SNAP_MAX_ENTRIES);
    for (i = 0; i < n; i++) {
      const shx_entry *e = &ents[i];
      shx_act plan[4];
      size_t k, pn;
      int has_url;
      if ((wchar_t)e->letter != o->letter)
        continue;
      has_url = (e->flags & SHX_F_HAS_REMOTE_URL) != 0 && shx_remote_url_ok(e->remote_url) &&
                shx_remote_copy_text(e->remote_url, o->rel, o->copy, SD_COUNTOF(o->copy));
      pn = shx_plan_drive(e->flags, e->state, o->is_root, has_url, plan, SD_COUNTOF(plan));
      for (k = 0; k < pn; k++)
        sx_add_action(o, plan[k], NULL);
      break;                            /* one entry per drive letter */
    }
  } __except (sx_fault_filter(GetExceptionCode())) {
    o->action_count = 0;
    o->copy[0] = 0;
  }
}

/* Loads the profiles of menu.cache. Runs under __try like the snapshot read. */
static size_t sx_load_profiles(shx_profile *p, size_t max)
{
  size_t n = 0;
  __try {
    n = shx_menucache_load(p, max);
  } __except (sx_fault_filter(GetExceptionCode())) {
    n = 0;
  }
  return n;
}

static int sx_insert_string(HMENU hmenu, UINT pos, UINT id, const wchar_t *text, HMENU sub, int disabled)
{
  MENUITEMINFOW mii;
  memset(&mii, 0, sizeof(mii));
  mii.cbSize = sizeof(mii);
  mii.fMask = MIIM_STRING | MIIM_FTYPE | MIIM_STATE;
  mii.fType = MFT_STRING;
  mii.fState = disabled ? MFS_DISABLED : MFS_ENABLED;
  if (sub != NULL) {
    mii.fMask |= MIIM_SUBMENU;
    mii.hSubMenu = sub;
  } else {
    mii.fMask |= MIIM_ID;
    mii.wID = id;
  }
  mii.dwTypeData = (LPWSTR)text;
  mii.cch = (UINT)wcslen(text);
  return InsertMenuItemW(hmenu, pos, TRUE, &mii) ? 1 : 0;
}

/* Path classes: the items go straight into the menu, one command id each. */
static HRESULT sx_query_path(SxObject *o, HMENU hmenu, UINT indexMenu, UINT idCmdFirst, UINT idCmdLast)
{
  shx_entry *ents;
  unsigned k;
  UINT added = 0;

  if (o->letter == 0)
    return MAKE_HRESULT(SEVERITY_SUCCESS, 0, 0);
  ents = (shx_entry *)sd_alloc(sizeof(shx_entry) * SHX_SNAP_MAX_ENTRIES);
  if (ents == NULL)
    return MAKE_HRESULT(SEVERITY_SUCCESS, 0, 0);
  sx_build_path_actions(o, ents);
  sd_free(ents);

  for (k = 0; k < o->action_count; k++) {
    if (idCmdFirst + k > idCmdLast)
      break;
    if (!sx_insert_string(hmenu, indexMenu + added, idCmdFirst + k, sx_menu_text(o->actions[k].act), NULL, 0))
      break;
    added++;
  }
  o->action_count = added;
  return MAKE_HRESULT(SEVERITY_SUCCESS, 0, added);
}

/* This PC: the submenu with the profiles, then "Open ShellDrive". Command ids are the profile items, the
   optional "More connections..." item and "Open ShellDrive", in that order. */
static HRESULT sx_query_computer(SxObject *o, HMENU hmenu, UINT indexMenu, UINT idCmdFirst, UINT idCmdLast)
{
  shx_profile *profiles;
  size_t n, shown, i;
  HMENU sub;
  UINT room = idCmdLast >= idCmdFirst ? idCmdLast - idCmdFirst + 1 : 0;
  UINT pos = 0;

  if (room < 2)
    return MAKE_HRESULT(SEVERITY_SUCCESS, 0, 0);
  profiles = (shx_profile *)sd_alloc(sizeof(shx_profile) * SHX_CACHE_MAX_ENTRIES);
  if (profiles == NULL)
    return MAKE_HRESULT(SEVERITY_SUCCESS, 0, 0);
  n = sx_load_profiles(profiles, SHX_CACHE_MAX_ENTRIES);
  shown = n > SHX_SUBMENU_MAX ? SHX_SUBMENU_MAX : n;
  if (shown + 2 > room)
    shown = room - 2;

  o->action_count = 0;
  sub = CreatePopupMenu();
  if (sub == NULL) {
    sd_free(profiles);
    return MAKE_HRESULT(SEVERITY_SUCCESS, 0, 0);
  }
  if (n == 0) {
    sx_add_action(o, SHX_ACT_NONE, NULL);
    (void)sx_insert_string(sub, pos++, idCmdFirst, sd_l10n_get(SD_MSG_SHELL_MENU_NO_PROFILES), NULL, 1);
  }
  for (i = 0; i < shown; i++) {
    wchar_t label[2 * SHX_LABEL_MAX + 8];
    shx_menu_label(profiles[i].name, label, SD_COUNTOF(label));
    if (label[0] == 0)
      wcscpy_s(label, SD_COUNTOF(label), L"?");
    sx_add_action(o, SHX_ACT_MOUNT_PROFILE, profiles[i].id);
    (void)sx_insert_string(sub, pos++, idCmdFirst + (UINT)o->action_count - 1, label, NULL, 0);
  }
  if (n > shown) {
    sx_add_action(o, SHX_ACT_SHOW, NULL);
    (void)sx_insert_string(sub, pos++, idCmdFirst + (UINT)o->action_count - 1,
                           sd_l10n_get(SD_MSG_SHELL_MENU_MORE_PROFILES), NULL, 0);
  }
  sd_free(profiles);

  if (!sx_insert_string(hmenu, indexMenu, 0, sd_l10n_get(SD_MSG_SHELL_MENU_MOUNT_SUBMENU), sub, 0)) {
    DestroyMenu(sub);
    o->action_count = 0;
    return MAKE_HRESULT(SEVERITY_SUCCESS, 0, 0);
  }
  sx_add_action(o, SHX_ACT_SHOW, NULL);
  if (!sx_insert_string(hmenu, indexMenu + 1, idCmdFirst + (UINT)o->action_count - 1,
                        sd_l10n_get(SD_MSG_SHELL_MENU_OPEN_SHELLDRIVE), NULL, 0))
    o->action_count--;
  return MAKE_HRESULT(SEVERITY_SUCCESS, 0, o->action_count);
}

static HRESULT STDMETHODCALLTYPE menu_QueryContextMenu(IContextMenu *This, HMENU hmenu, UINT indexMenu,
                                                       UINT idCmdFirst, UINT idCmdLast, UINT uFlags)
{
  SxObject *o = CONTAINING_RECORD(This, SxObject, menu);

  o->action_count = 0;
  if ((uFlags & CMF_DEFAULTONLY) != 0 || hmenu == NULL)
    return MAKE_HRESULT(SEVERITY_SUCCESS, 0, 0);
  return o->computer ? sx_query_computer(o, hmenu, indexMenu, idCmdFirst, idCmdLast)
                     : sx_query_path(o, hmenu, indexMenu, idCmdFirst, idCmdLast);
}

/* Case-insensitive ASCII match of a string verb against the machine names of the current items. Returns the
   index of the item or -1. */
static int sx_find_verb(const SxObject *o, const char *s)
{
  unsigned k;
  for (k = 0; k < o->action_count; k++) {
    wchar_t name[80];
    size_t i;
    int same = 1;
    if (!sx_verb_name(&o->actions[k], name, SD_COUNTOF(name)))
      continue;
    for (i = 0; name[i] != 0; i++) {
      char c = s[i];
      if (c >= 'A' && c <= 'Z')
        c = (char)(c + ('a' - 'A'));
      if (c == 0 || (wchar_t)(unsigned char)c != name[i]) {
        same = 0;
        break;
      }
    }
    if (same && s[i] == 0)
      return (int)k;
  }
  return -1;
}

#ifdef SD_SHELLEXT_TEST
/* Test hook (test builds only): write the text to the file named by the environment variable instead of
   starting the UI or touching the clipboard. */
static int sx_test_write(const wchar_t *env_name, const wchar_t *text)
{
  wchar_t file[MAX_PATH];
  HANDLE h;
  DWORD written = 0, bytes;
  BOOL ok;
  if (GetEnvironmentVariableW(env_name, file, MAX_PATH) == 0)
    return 0;
  h = CreateFileW(file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE)
    return 0;
  bytes = (DWORD)(wcslen(text) * sizeof(wchar_t));
  ok = WriteFile(h, text, bytes, &written, NULL) && written == bytes;
  CloseHandle(h);
  return ok ? 1 : 0;
}
#endif

/* Starts shelldrive-ui.exe from this DLL's directory. Returns when the process is created. arg may be NULL. */
static int sx_launch(const wchar_t *verb, const wchar_t *arg)
{
  wchar_t dir[1024];
  wchar_t exe[1100];
  wchar_t cmd[1400];
  DWORD n;
  wchar_t *slash;
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;

  n = GetModuleFileNameW(shx_module, dir, SD_COUNTOF(dir));
  if (n == 0 || n >= SD_COUNTOF(dir))
    return 0;
  slash = wcsrchr(dir, L'\\');
  if (slash == NULL)
    return 0;
  slash[1] = 0;                         /* keep the trailing backslash */
  if (_snwprintf_s(exe, SD_COUNTOF(exe), _TRUNCATE, L"%s%s", dir, SHX_UI_EXE) < 0)
    return 0;
  exe[SD_COUNTOF(exe) - 1] = 0;
  if (arg != NULL) {
    if (_snwprintf_s(cmd, SD_COUNTOF(cmd), _TRUNCATE, L"\"%s\" --action %s %s", exe, verb, arg) < 0)
      return 0;
  } else {
    if (_snwprintf_s(cmd, SD_COUNTOF(cmd), _TRUNCATE, L"\"%s\" --action %s", exe, verb) < 0)
      return 0;
  }
  cmd[SD_COUNTOF(cmd) - 1] = 0;

#ifdef SD_SHELLEXT_TEST
  if (GetEnvironmentVariableW(L"SHELLDRIVE_TEST_SHELLEXT_CMDLINE_FILE", NULL, 0) != 0)
    return sx_test_write(L"SHELLDRIVE_TEST_SHELLEXT_CMDLINE_FILE", cmd);
#endif

  memset(&si, 0, sizeof(si));
  memset(&pi, 0, sizeof(pi));
  si.cb = sizeof(si);
  if (!CreateProcessW(exe, cmd, NULL, NULL, FALSE, 0, NULL, dir, &si, &pi))
    return 0;
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  return 1;
}

/* Puts text on the clipboard as CF_UNICODETEXT. The clipboard is retried for at most about 50 ms: Explorer's
   thread must not wait for another program. */
static int sx_copy_to_clipboard(HWND hwnd, const wchar_t *text)
{
  size_t bytes = (wcslen(text) + 1) * sizeof(wchar_t);
  HGLOBAL g;
  void *p;
  unsigned tries;
  int opened = 0;

#ifdef SD_SHELLEXT_TEST
  if (GetEnvironmentVariableW(L"SHELLDRIVE_TEST_SHELLEXT_CLIP_FILE", NULL, 0) != 0)
    return sx_test_write(L"SHELLDRIVE_TEST_SHELLEXT_CLIP_FILE", text);
#endif
  g = GlobalAlloc(GMEM_MOVEABLE, bytes);
  if (g == NULL)
    return 0;
  p = GlobalLock(g);
  if (p == NULL) {
    GlobalFree(g);
    return 0;
  }
  memcpy(p, text, bytes);
  GlobalUnlock(g);
  for (tries = 0; tries < 5; tries++) {
    if (OpenClipboard(hwnd)) {
      opened = 1;
      break;
    }
    Sleep(10);
  }
  if (!opened) {
    GlobalFree(g);
    return 0;
  }
  EmptyClipboard();
  if (SetClipboardData(CF_UNICODETEXT, g) == NULL) {
    CloseClipboard();
    GlobalFree(g);
    return 0;
  }
  CloseClipboard();                     /* the clipboard owns g now */
  return 1;
}

static int sx_run(SxObject *o, const sx_action *a, HWND hwnd)
{
  wchar_t drive[3];
  switch (a->act) {
  case SHX_ACT_COPY_PATH:
    return o->copy[0] != 0 && sx_copy_to_clipboard(hwnd, o->copy);
  case SHX_ACT_MOUNT_PROFILE:
    return sx_launch(L"mount", a->arg);
  case SHX_ACT_SHOW:
    return sx_launch(L"show", NULL);
  case SHX_ACT_OPEN:
  case SHX_ACT_UNMOUNT:
  case SHX_ACT_RECONNECT:
    if (o->letter == 0)
      return 0;
    drive[0] = o->letter;
    drive[1] = L':';
    drive[2] = 0;
    return sx_launch(a->act == SHX_ACT_UNMOUNT ? L"unmount" : a->act == SHX_ACT_RECONNECT ? L"reconnect" : L"open",
                     drive);
  default:
    return 0;
  }
}

static HRESULT STDMETHODCALLTYPE menu_InvokeCommand(IContextMenu *This, LPCMINVOKECOMMANDINFO pici)
{
  SxObject *o = CONTAINING_RECORD(This, SxObject, menu);
  unsigned idx;

  if (pici == NULL || pici->cbSize < sizeof(CMINVOKECOMMANDINFO))
    return E_INVALIDARG;
  if (((ULONG_PTR)pici->lpVerb >> 16) == 0) {
    /* MAKEINTRESOURCE: the offset of the item from idCmdFirst. */
    idx = (unsigned)((ULONG_PTR)pici->lpVerb & 0xFFFFu);
    if (idx >= o->action_count || idx >= SX_MAX_ACTIONS)
      return E_FAIL;
  } else {
    /* Verb string (ANSI): accepted only when it names one of our items. */
    int k;
    if ((pici->fMask & CMIC_MASK_UNICODE) != 0)
      return E_FAIL;
    k = sx_find_verb(o, pici->lpVerb);
    if (k < 0)
      return E_FAIL;
    idx = (unsigned)k;
  }
  return sx_run(o, &o->actions[idx], pici->hwnd) ? S_OK : E_FAIL;
}

static HRESULT STDMETHODCALLTYPE menu_GetCommandString(IContextMenu *This, UINT_PTR idCmd, UINT uType,
                                                       UINT *pwReserved, LPSTR pszName, UINT cchMax)
{
  SxObject *o = CONTAINING_RECORD(This, SxObject, menu);
  UINT type = uType & ~((UINT)GCS_UNICODE);
  int unicode = (uType & GCS_UNICODE) != 0;
  const wchar_t *text;
  wchar_t verb[80];

  (void)pwReserved;
  if (idCmd >= o->action_count || idCmd >= SX_MAX_ACTIONS)
    return E_INVALIDARG;
  if (type == GCS_VALIDATEA)
    return S_OK;
  if (pszName == NULL || cchMax == 0)
    return E_INVALIDARG;
  if (type == GCS_VERBA) {
    if (!sx_verb_name(&o->actions[idCmd], verb, SD_COUNTOF(verb)))
      return E_FAIL;
    text = verb;
  } else if (type == GCS_HELPTEXTA) {
    text = sx_help_text(o->actions[idCmd].act);
  } else {
    return E_NOTIMPL;
  }

  if (unicode) {
    size_t len = wcslen(text);
    wchar_t *dst = (wchar_t *)pszName;
    if (len >= cchMax) {
      len = cchMax - 1;
    }
    memcpy(dst, text, len * sizeof(wchar_t));
    dst[len] = 0;
    return S_OK;
  }
  if (WideCharToMultiByte(CP_ACP, 0, text, -1, pszName, (int)cchMax, NULL, NULL) == 0) {
    pszName[0] = 0;
    return E_FAIL;
  }
  return S_OK;
}

/* ---- vtables ---- */

static IShellExtInitVtbl g_init_vtbl = {
  init_QueryInterface,
  init_AddRef,
  init_Release,
  init_Initialize
};

static IContextMenuVtbl g_menu_vtbl = {
  menu_QueryInterface,
  menu_AddRef,
  menu_Release,
  menu_QueryContextMenu,
  menu_InvokeCommand,
  menu_GetCommandString
};

/* ---- class factories (static: no allocation, no reference count of its own) ---- */

static HRESULT sx_create(int computer, REFIID riid, void **ppv);

static HRESULT STDMETHODCALLTYPE fac_QueryInterface(IClassFactory *This, REFIID riid, void **ppv)
{
  if (ppv == NULL)
    return E_POINTER;
  *ppv = NULL;
  if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IClassFactory)) {
    *ppv = This;
    return S_OK;
  }
  return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE fac_AddRef(IClassFactory *This)
{
  (void)This;
  return 1;
}

static ULONG STDMETHODCALLTYPE fac_Release(IClassFactory *This)
{
  (void)This;
  return 1;
}

static HRESULT STDMETHODCALLTYPE fac_CreateInstance(IClassFactory *This, IUnknown *pUnkOuter, REFIID riid,
                                                    void **ppv)
{
  if (ppv == NULL)
    return E_POINTER;
  *ppv = NULL;
  if (pUnkOuter != NULL)
    return CLASS_E_NOAGGREGATION;
  return sx_create(CONTAINING_RECORD(This, SxFactory, iface)->computer, riid, ppv);
}


static HRESULT STDMETHODCALLTYPE fac_LockServer(IClassFactory *This, BOOL fLock)
{
  (void)This;
  if (fLock)
    InterlockedIncrement(&g_locks);
  else
    InterlockedDecrement(&g_locks);
  return S_OK;
}

static IClassFactoryVtbl g_factory_vtbl = {
  fac_QueryInterface,
  fac_AddRef,
  fac_Release,
  fac_CreateInstance,
  fac_LockServer
};

static SxFactory g_factory_path = { { &g_factory_vtbl }, 0 };
static SxFactory g_factory_computer = { { &g_factory_vtbl }, 1 };

/* Creates one object with its two vtables set, and returns the interface asked for (reference count 1). */
static HRESULT sx_create(int computer, REFIID riid, void **ppv)
{
  SxObject *o;
  HRESULT hr;
  o = (SxObject *)sd_calloc(1, sizeof(SxObject));
  if (o == NULL)
    return E_OUTOFMEMORY;
  o->init.lpVtbl = &g_init_vtbl;
  o->menu.lpVtbl = &g_menu_vtbl;
  o->computer = computer;
  InterlockedIncrement(&g_objects);
  hr = sx_qi(o, riid, ppv);
  if (FAILED(hr)) {
    sd_free(o);
    InterlockedDecrement(&g_objects);
  }
  return hr;
}

/* ---- exports (shelldrive-shellext.def) ---- */

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
  (void)reserved;
  if (reason == DLL_PROCESS_ATTACH) {
    shx_module = inst;
    DisableThreadLibraryCalls(inst);
  }
  return TRUE;
}

_Check_return_
STDAPI DllGetClassObject(_In_ REFCLSID rclsid, _In_ REFIID riid, _Outptr_ LPVOID *ppv)
{
  SxFactory *f;
  if (ppv == NULL)
    return E_POINTER;
  *ppv = NULL;
  if (IsEqualCLSID(rclsid, &SHX_CLSID_CONTEXT_MENU))
    f = &g_factory_path;
  else if (IsEqualCLSID(rclsid, &SHX_CLSID_COMPUTER_MENU))
    f = &g_factory_computer;
  else
    return CLASS_E_CLASSNOTAVAILABLE;
  return f->iface.lpVtbl->QueryInterface(&f->iface, riid, ppv);
}

__control_entrypoint(DllExport)
STDAPI DllCanUnloadNow(void)
{
  return (InterlockedCompareExchange(&g_objects, 0, 0) == 0 && InterlockedCompareExchange(&g_locks, 0, 0) == 0) ? S_OK : S_FALSE;
}

STDAPI DllRegisterServer(void)
{
  return shx_register_server();
}

STDAPI DllUnregisterServer(void)
{
  return shx_unregister_server();
}
