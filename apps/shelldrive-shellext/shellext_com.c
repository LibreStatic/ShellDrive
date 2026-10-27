/* shelldrive-shellext.dll: COM server, class factory, the context menu handler for drive roots (03 §8.2).
 *
 * One object implements IShellExtInit and IContextMenu. Each interface is a subobject with its own vtable
 * (the usual C pattern), so QueryInterface returns different pointers for the two interfaces and both
 * recover the object with CONTAINING_RECORD.
 *
 * Menu (drive roots of ShellDrive mounts only, from the state section, 8.2.1):
 *   Open       every entry of the drive
 *   Unmount    per-user entries that are not unmounting or unmounted
 *   Reconnect  per-user entries that are offline, need authentication or failed
 * InvokeCommand starts shelldrive-ui.exe --action <verb> <X:> and returns; it never waits. */
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

#define SX_MAX_ACTIONS 3u

typedef enum sx_verb {
  SX_VERB_OPEN = 0,
  SX_VERB_UNMOUNT,
  SX_VERB_RECONNECT
} sx_verb;

typedef struct SxObject {
  IShellExtInit init;            /* first subobject: IShellExtInit (and IUnknown through it) */
  IContextMenu menu;             /* second subobject: IContextMenu */
  LONG refs;
  wchar_t letter;                /* drive letter of the one selected drive root, 0 if none */
  unsigned action_count;         /* items added by the last QueryContextMenu */
  sx_verb actions[SX_MAX_ACTIONS];
} SxObject;

HINSTANCE shx_module = NULL;

static volatile LONG g_objects = 0;   /* live objects (DllCanUnloadNow) */
static volatile LONG g_locks = 0;     /* LockServer count */
static volatile LONG g_l10n_state = 0;  /* 0 not started, 1 starting, 2 ready */

/* ---- localization (03 §9.3): initialized once per process, on first use ---- */

static void sx_l10n_ready(void)
{
  unsigned spins;
  if (InterlockedCompareExchange(&g_l10n_state, 1, 0) == 0) {
    sd_l10n_init(&sd_l10n_catalog_shell, NULL);
    InterlockedExchange(&g_l10n_state, 2);
    return;
  }
  /* Another thread is initializing: wait briefly (the work is a few registry reads). */
  for (spins = 0; InterlockedCompareExchange(&g_l10n_state, 2, 2) != 2 && spins < 1000; spins++)
    Sleep(1);
}

static const wchar_t *sx_menu_text(sx_verb v)
{
  switch (v) {
  case SX_VERB_UNMOUNT:   return sd_l10n_get(SD_MSG_SHELL_MENU_UNMOUNT);
  case SX_VERB_RECONNECT: return sd_l10n_get(SD_MSG_SHELL_MENU_RECONNECT);
  default:                return sd_l10n_get(SD_MSG_SHELL_MENU_OPEN);
  }
}

static const wchar_t *sx_help_text(sx_verb v)
{
  switch (v) {
  case SX_VERB_UNMOUNT:   return sd_l10n_get(SD_MSG_SHELL_HELP_UNMOUNT);
  case SX_VERB_RECONNECT: return sd_l10n_get(SD_MSG_SHELL_HELP_RECONNECT);
  default:                return sd_l10n_get(SD_MSG_SHELL_HELP_OPEN);
  }
}

/* Machine-readable names: GCS_VERB and string verbs in InvokeCommand. Not shown to the user. */
static const wchar_t *sx_verb_name(sx_verb v)
{
  switch (v) {
  case SX_VERB_UNMOUNT:   return L"shelldrive.unmount";
  case SX_VERB_RECONNECT: return L"shelldrive.reconnect";
  default:                return L"shelldrive.open";
  }
}

/* The --action verb of shelldrive-ui.exe (03 §1.4). */
static const wchar_t *sx_ui_verb(sx_verb v)
{
  switch (v) {
  case SX_VERB_UNMOUNT:   return L"unmount";
  case SX_VERB_RECONNECT: return L"reconnect";
  default:                return L"open";
  }
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

/* Reads the selected paths (CF_HDROP). Only a single drive root ("X:\") is remembered. */
static HRESULT STDMETHODCALLTYPE init_Initialize(IShellExtInit *This, LPCITEMIDLIST pidlFolder,
                                                 IDataObject *pdtobj, HKEY hkeyProgID)
{
  SxObject *o = CONTAINING_RECORD(This, SxObject, init);
  FORMATETC fe;
  STGMEDIUM sm;
  HDROP drop;
  UINT count, i, roots = 0, others = 0;
  wchar_t path[MAX_PATH + 1];
  wchar_t letter = 0;
  HRESULT hr;

  (void)pidlFolder;
  (void)hkeyProgID;
  o->letter = 0;
  if (pdtobj == NULL)
    return E_INVALIDARG;
  sx_l10n_ready();

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
  for (i = 0; i < count; i++) {
    UINT len = DragQueryFileW(drop, i, path, MAX_PATH + 1);
    if (len == 3 && sx_is_letter(path[0]) && path[1] == L':' && path[2] == L'\\') {
      roots++;
      letter = (wchar_t)((path[0] >= L'a' && path[0] <= L'z') ? path[0] - (L'a' - L'A') : path[0]);
    } else {
      others++;
    }
  }
  if (roots == 1 && others == 0)
    o->letter = letter;
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

static void sx_add_action(SxObject *o, sx_verb v)
{
  if (o->action_count < SX_MAX_ACTIONS)
    o->actions[o->action_count++] = v;
}

/* Only the faults a mapped read can raise are caught (access violation, in-page error); anything else keeps
   searching for a handler, as usual. */
static int sx_fault_filter(unsigned long code)
{
  return (code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_IN_PAGE_ERROR) ? EXCEPTION_EXECUTE_HANDLER
                                                                              : EXCEPTION_CONTINUE_SEARCH;
}

/* Decides the items from the snapshot. Runs under __try: a parser fault must not reach Explorer. */
static void sx_build_actions(SxObject *o)
{
  shx_entry ents[SHX_SNAP_MAX_ENTRIES];
  size_t n, i;

  o->action_count = 0;
  __try {
    n = shx_snapshot_read(ents, SHX_SNAP_MAX_ENTRIES);
    for (i = 0; i < n; i++) {
      shx_entry *e = &ents[i];
      if ((wchar_t)e->letter != o->letter)
        continue;
      sx_add_action(o, SX_VERB_OPEN);
      if ((e->flags & SHX_F_GLOBAL) == 0) {
        if (e->state != SHX_STATE_UNMOUNTING && e->state != SHX_STATE_UNMOUNTED)
          sx_add_action(o, SX_VERB_UNMOUNT);
        if (e->state == SHX_STATE_OFFLINE || e->state == SHX_STATE_AUTH_REQUIRED || e->state == SHX_STATE_FAILED)
          sx_add_action(o, SX_VERB_RECONNECT);
      }
      break;                            /* one entry per drive letter */
    }
  } __except (sx_fault_filter(GetExceptionCode())) {
    o->action_count = 0;
  }
}

static HRESULT STDMETHODCALLTYPE menu_QueryContextMenu(IContextMenu *This, HMENU hmenu, UINT indexMenu,
                                                       UINT idCmdFirst, UINT idCmdLast, UINT uFlags)
{
  SxObject *o = CONTAINING_RECORD(This, SxObject, menu);
  unsigned k;
  UINT added = 0;

  o->action_count = 0;
  if ((uFlags & CMF_DEFAULTONLY) != 0 || hmenu == NULL || o->letter == 0)
    return MAKE_HRESULT(SEVERITY_SUCCESS, 0, 0);
  sx_build_actions(o);

  for (k = 0; k < o->action_count; k++) {
    MENUITEMINFOW mii;
    const wchar_t *text = sx_menu_text(o->actions[k]);
    if (idCmdFirst + k > idCmdLast)
      break;
    memset(&mii, 0, sizeof(mii));
    mii.cbSize = sizeof(mii);
    mii.fMask = MIIM_STRING | MIIM_ID | MIIM_FTYPE;
    mii.fType = MFT_STRING;
    mii.wID = idCmdFirst + k;
    mii.dwTypeData = (LPWSTR)text;
    mii.cch = (UINT)wcslen(text);
    if (!InsertMenuItemW(hmenu, indexMenu + added, TRUE, &mii))
      break;
    added++;
  }
  o->action_count = added;
  return MAKE_HRESULT(SEVERITY_SUCCESS, 0, added);
}

/* Case-insensitive ASCII match of a string verb against the machine names. */
static int sx_verb_from_string(const char *s, sx_verb *out)
{
  sx_verb v;
  for (v = SX_VERB_OPEN; v <= SX_VERB_RECONNECT; v++) {
    const wchar_t *name = sx_verb_name(v);
    const char *p = s;
    size_t i = 0;
    int same = 1;
    for (; name[i] != 0; i++) {
      char c = p[i];
      if (c >= 'A' && c <= 'Z')
        c = (char)(c + ('a' - 'A'));
      if (c == 0 || (wchar_t)(unsigned char)c != name[i]) {
        same = 0;
        break;
      }
    }
    if (same && p[i] == 0) {
      *out = v;
      return 1;
    }
  }
  return 0;
}

#ifdef SD_SHELLEXT_TEST
/* Test hook (test builds only): write the command line to this file instead of starting the UI. */
static int sx_test_write_cmdline(const wchar_t *cmd)
{
  wchar_t file[MAX_PATH];
  HANDLE h;
  DWORD written = 0, bytes;
  BOOL ok;
  if (GetEnvironmentVariableW(L"SHELLDRIVE_TEST_SHELLEXT_CMDLINE_FILE", file, MAX_PATH) == 0)
    return 0;
  h = CreateFileW(file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE)
    return 0;
  bytes = (DWORD)(wcslen(cmd) * sizeof(wchar_t));
  ok = WriteFile(h, cmd, bytes, &written, NULL) && written == bytes;
  CloseHandle(h);
  return ok ? 1 : 0;
}
#endif

/* Starts shelldrive-ui.exe from this DLL's directory. Returns when the process is created. */
static int sx_launch(sx_verb v, wchar_t letter)
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
  if (_snwprintf_s(cmd, SD_COUNTOF(cmd), _TRUNCATE, L"\"%s\" --action %s %c:", exe, sx_ui_verb(v), (int)letter) < 0)
    return 0;
  cmd[SD_COUNTOF(cmd) - 1] = 0;

#ifdef SD_SHELLEXT_TEST
  if (GetEnvironmentVariableW(L"SHELLDRIVE_TEST_SHELLEXT_CMDLINE_FILE", NULL, 0) != 0)
    return sx_test_write_cmdline(cmd);
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

static HRESULT STDMETHODCALLTYPE menu_InvokeCommand(IContextMenu *This, LPCMINVOKECOMMANDINFO pici)
{
  SxObject *o = CONTAINING_RECORD(This, SxObject, menu);
  unsigned idx;
  sx_verb v;

  if (pici == NULL || pici->cbSize < sizeof(CMINVOKECOMMANDINFO))
    return E_INVALIDARG;
  if (((ULONG_PTR)pici->lpVerb >> 16) == 0) {
    /* MAKEINTRESOURCE: the offset of the item from idCmdFirst. */
    idx = (unsigned)((ULONG_PTR)pici->lpVerb & 0xFFFFu);
    if (idx >= o->action_count || idx >= SX_MAX_ACTIONS)
      return E_FAIL;
    v = o->actions[idx];
  } else {
    /* Verb string (ANSI): accepted only when it names one of our items. */
    unsigned k;
    if ((pici->fMask & CMIC_MASK_UNICODE) != 0 || !sx_verb_from_string(pici->lpVerb, &v))
      return E_FAIL;
    for (k = 0; k < o->action_count && k < SX_MAX_ACTIONS && o->actions[k] != v; k++)
      ;
    if (k == o->action_count)
      return E_FAIL;
  }
  if (o->letter == 0)
    return E_FAIL;
  return sx_launch(v, o->letter) ? S_OK : E_FAIL;
}

static HRESULT STDMETHODCALLTYPE menu_GetCommandString(IContextMenu *This, UINT_PTR idCmd, UINT uType,
                                                       UINT *pwReserved, LPSTR pszName, UINT cchMax)
{
  SxObject *o = CONTAINING_RECORD(This, SxObject, menu);
  UINT type = uType & ~((UINT)GCS_UNICODE);
  int unicode = (uType & GCS_UNICODE) != 0;
  const wchar_t *text;

  (void)pwReserved;
  if (idCmd >= o->action_count || idCmd >= SX_MAX_ACTIONS)
    return E_INVALIDARG;
  if (type == GCS_VALIDATEA)
    return S_OK;
  if (pszName == NULL || cchMax == 0)
    return E_INVALIDARG;
  if (type == GCS_VERBA)
    text = sx_verb_name(o->actions[idCmd]);
  else if (type == GCS_HELPTEXTA)
    text = sx_help_text(o->actions[idCmd]);
  else
    return E_NOTIMPL;

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

/* ---- class factory (static: no allocation, no reference count of its own) ---- */

static HRESULT sx_create(REFIID riid, void **ppv);

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
  (void)This;
  if (ppv == NULL)
    return E_POINTER;
  *ppv = NULL;
  if (pUnkOuter != NULL)
    return CLASS_E_NOAGGREGATION;
  return sx_create(riid, ppv);
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

static IClassFactory g_factory = { &g_factory_vtbl };

/* Creates one object with its two vtables set, and returns the interface asked for (reference count 1). */
static HRESULT sx_create(REFIID riid, void **ppv)
{
  SxObject *o;
  HRESULT hr;
  o = (SxObject *)sd_calloc(1, sizeof(SxObject));
  if (o == NULL)
    return E_OUTOFMEMORY;
  o->init.lpVtbl = &g_init_vtbl;
  o->menu.lpVtbl = &g_menu_vtbl;
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
  if (ppv == NULL)
    return E_POINTER;
  *ppv = NULL;
  if (!IsEqualCLSID(rclsid, &SHX_CLSID_CONTEXT_MENU))
    return CLASS_E_CLASSNOTAVAILABLE;
  return g_factory.lpVtbl->QueryInterface(&g_factory, riid, ppv);
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
