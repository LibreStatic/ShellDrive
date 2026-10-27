/* shelldrive-shellext tests (03 §1.6, §8.2, §8.2.1, §8.5; TM-R26).
 *
 * Two layers:
 *   - the snapshot reader, called directly (shellext_snapshot.c is compiled into this executable with
 *     SD_SHELLEXT_TEST, so the section name comes from SHELLDRIVE_TEST_STATE_NAME);
 *   - the COM server, loaded from the test DLL next to this executable (shelldrive-shellext-test.dll):
 *     DllGetClassObject, IShellExtInit, IContextMenu on a real HMENU, GetCommandString, InvokeCommand (the
 *     command line goes to a file instead of launching), DllCanUnloadNow and registration under a redirected
 *     HKCU (RegOverridePredefKey). The real registry is only read to prove it is unchanged. */
#define INITGUID
#include <windows.h>
#include <objbase.h>
#include <sddl.h>
#include <shellapi.h>
#include <stdlib.h>
#include <stdio.h>
#include <objidl.h>
#include <shlobj.h>
#include <string.h>
#include <wchar.h>

#include "sd_test.h"
#include "shellext_int.h"
#include "shellext_snapshot.h"

#define T_SEC_BYTES   262144u
#define T_HDR         64u
#define T_ENTRY       1792u
#define T_TEST_STATE  L"SHELLDRIVE_TEST_STATE_NAME"
#define T_TEST_CMD    L"SHELLDRIVE_TEST_SHELLEXT_CMDLINE_FILE"

typedef HRESULT (STDAPICALLTYPE *t_pfn_get_class)(REFCLSID, REFIID, LPVOID *);
typedef HRESULT (STDAPICALLTYPE *t_pfn_can_unload)(void);
typedef HRESULT (STDAPICALLTYPE *t_pfn_register)(void);

static HMODULE t_dll;
static t_pfn_get_class t_get_class;
static t_pfn_can_unload t_can_unload;
static t_pfn_register t_register;
static t_pfn_register t_unregister;
static wchar_t t_dll_dir[MAX_PATH];         /* with trailing backslash */
static unsigned char t_buf[T_SEC_BYTES];    /* snapshot image being built */
static int t_name_seq;
static wchar_t t_name[260];                 /* current test section name */
static const GUID t_nil_guid = { 0, 0, 0, { 0, 0, 0, 0, 0, 0, 0, 0 } };
static HANDLE t_section;                    /* writable handle of the current test section */
static unsigned char *t_view;               /* writable view of the current test section */

/* ---- snapshot writer (the layout of 03 §8.2.1, written independently of the reader) ---- */

typedef struct t_ent {
  uint32_t flags;
  uint32_t state;
  uint32_t backend;
  wchar_t letter;
  const wchar_t *profile_id;
  const wchar_t *name;
} t_ent;

typedef struct t_hdr {
  uint32_t magic;
  uint32_t layout;
  uint32_t header_size;
  uint32_t entry_size;
  uint32_t entry_count;
  uint32_t total;
  uint32_t seq;
} t_hdr;

static void t_put16(unsigned char *p, uint32_t v)
{
  p[0] = (unsigned char)(v & 0xFF);
  p[1] = (unsigned char)((v >> 8) & 0xFF);
}

static void t_put32(unsigned char *p, uint32_t v)
{
  p[0] = (unsigned char)(v & 0xFF);
  p[1] = (unsigned char)((v >> 8) & 0xFF);
  p[2] = (unsigned char)((v >> 16) & 0xFF);
  p[3] = (unsigned char)((v >> 24) & 0xFF);
}

static void t_put_wstr(unsigned char *p, uint32_t units, const wchar_t *s)
{
  uint32_t i;
  for (i = 0; s != NULL && i < units && s[i] != 0; i++)
    t_put16(p + 2 * i, (uint32_t)s[i]);
}

static void t_default_hdr(t_hdr *h, uint32_t count)
{
  h->magic = SHX_SNAP_MAGIC;
  h->layout = 1;
  h->header_size = T_HDR;
  h->entry_size = T_ENTRY;
  h->entry_count = count;
  h->total = T_HDR + count * T_ENTRY;
  h->seq = 2;
}

/* Builds the image in t_buf: header, then the entries that fit the declared geometry. */
static void t_build(const t_hdr *h, const t_ent *ents, uint32_t n)
{
  uint32_t i;
  memset(t_buf, 0, sizeof(t_buf));
  t_put32(t_buf + 0, h->magic);
  t_put16(t_buf + 4, h->layout);
  t_put16(t_buf + 6, h->header_size);
  t_put32(t_buf + 8, h->total);
  t_put32(t_buf + 12, h->entry_size);
  t_put32(t_buf + 16, h->entry_count);
  t_put32(t_buf + 20, h->seq);
  t_put32(t_buf + 44, 128);
  for (i = 0; i < n; i++) {
    unsigned char *e = t_buf + h->header_size + i * h->entry_size;
    if (h->header_size + (i + 1) * h->entry_size > T_SEC_BYTES)
      break;
    t_put32(e + 0, ents[i].flags);
    t_put32(e + 4, ents[i].state);
    t_put32(e + 8, ents[i].backend);
    t_put32(e + 12, i + 1);
    t_put16(e + 16, (uint32_t)ents[i].letter);
    t_put_wstr(e + 24, 32, L"m-1");
    t_put_wstr(e + 88, 32, ents[i].profile_id);
    t_put_wstr(e + 152, 128, ents[i].name);
    t_put_wstr(e + 408, 260, L"X:");
    t_put_wstr(e + 928, 64, L"Label");
    t_put_wstr(e + 1056, 320, L"sftp://u@h:22/p");
  }
}

/* Copies t_buf into the test section with the seq word of the image as it is. */
static void t_publish(void)
{
  memcpy(t_view, t_buf, sizeof(t_buf));
}

/* ---- sections ---- */

static HANDLE t_create_section(const wchar_t *sacl_tail)
{
  HANDLE tok = NULL;
  DWORD len = 0;
  TOKEN_USER *tu = NULL;
  wchar_t *sid_text = NULL;
  wchar_t sddl[512];
  PSECURITY_DESCRIPTOR sd = NULL;
  SECURITY_ATTRIBUTES sa;
  HANDLE h = NULL;

  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok))
    return NULL;
  GetTokenInformation(tok, TokenUser, NULL, 0, &len);
  tu = (TOKEN_USER *)HeapAlloc(GetProcessHeap(), 0, len);
  if (tu != NULL && GetTokenInformation(tok, TokenUser, tu, len, &len) &&
      ConvertSidToStringSidW(tu->User.Sid, &sid_text)) {
    /* Owner and group are the current user; the DACL gives the user full access. */
    _snwprintf_s(sddl, 512, _TRUNCATE, L"O:%sG:%sD:(A;;GA;;;%s)%s", sid_text, sid_text, sid_text, sacl_tail);
    sddl[511] = 0;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sd, NULL)) {
      sa.nLength = sizeof(sa);
      sa.lpSecurityDescriptor = sd;
      sa.bInheritHandle = FALSE;
      h = CreateFileMappingW(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE, 0, T_SEC_BYTES, t_name);
      LocalFree(sd);
    }
    LocalFree(sid_text);
  }
  if (tu != NULL)
    HeapFree(GetProcessHeap(), 0, tu);
  CloseHandle(tok);
  return h;
}

/* Creates a fresh test section under a new name and points SHELLDRIVE_TEST_STATE_NAME at it. */
static int t_open_fresh(const wchar_t *sacl_tail)
{
  if (t_section != NULL) {
    if (t_view != NULL)
      UnmapViewOfFile(t_view);
    CloseHandle(t_section);
    t_section = NULL;
    t_view = NULL;
  }
  t_name_seq++;
  _snwprintf_s(t_name, 260, _TRUNCATE, L"Local\\com.librestatic.shelldrive.test.%lu.%d", (unsigned long)GetCurrentProcessId(),
             t_name_seq);
  t_name[259] = 0;
  SetEnvironmentVariableW(T_TEST_STATE, t_name);
  t_section = t_create_section(sacl_tail);
  if (t_section == NULL)
    return 0;
  t_view = (unsigned char *)MapViewOfFile(t_section, FILE_MAP_WRITE, 0, 0, T_SEC_BYTES);
  return t_view != NULL;
}

static void t_close_section(void)
{
  if (t_view != NULL)
    UnmapViewOfFile(t_view);
  if (t_section != NULL)
    CloseHandle(t_section);
  t_view = NULL;
  t_section = NULL;
  SetEnvironmentVariableW(T_TEST_STATE, NULL);
}

static size_t t_read_count(void)
{
  shx_entry out[SHX_SNAP_MAX_ENTRIES];
  return shx_snapshot_read(out, SHX_SNAP_MAX_ENTRIES);
}

/* ---- snapshot reader tests ---- */

SD_TEST(snapshot_valid_entries)
{
  t_ent e[4];
  t_hdr h;
  shx_entry out[8];
  size_t n;
  if (!t_open_fresh(L"")) { SD_CHECK(0); return; }
  memset(e, 0, sizeof(e));
  e[0].flags = SHX_F_IN_USE;  e[0].state = SHX_STATE_MOUNTED; e[0].backend = 1; e[0].letter = L'E';
  e[0].profile_id = L"0123456789abcdef0123456789abcdef";
  e[1].flags = SHX_F_IN_USE | SHX_F_GLOBAL; e[1].state = SHX_STATE_MOUNTED; e[1].backend = 2; e[1].letter = L'G';
  e[2].flags = SHX_F_IN_USE; e[2].state = SHX_STATE_UNMOUNTED; e[2].backend = 1; e[2].letter = L'H';
  e[3].flags = SHX_F_IN_USE; e[3].state = 99; e[3].backend = 7; e[3].letter = L'J';   /* read as 0 */
  t_default_hdr(&h, 4);
  t_build(&h, e, 4);
  t_publish();
  n = shx_snapshot_read(out, 8);
  SD_CHECK_EQ_INT(n, 4);
  if (n == 4) {
    SD_CHECK_EQ_INT(out[0].letter, L'E');
    SD_CHECK_EQ_INT(out[0].state, SHX_STATE_MOUNTED);
    SD_CHECK_EQ_INT(out[1].flags & SHX_F_GLOBAL, SHX_F_GLOBAL);
    SD_CHECK_EQ_INT(out[3].state, 0);
    SD_CHECK_EQ_INT(out[3].backend, 0);
  }
  /* Caller capacity is honored. */
  SD_CHECK_EQ_INT(shx_snapshot_read(out, 2), 2);
  t_close_section();
}

SD_TEST(snapshot_drops_bad_entries_only)
{
  t_ent e[7];
  t_hdr h;
  size_t n;
  if (!t_open_fresh(L"")) { SD_CHECK(0); return; }
  memset(e, 0, sizeof(e));
  e[0].flags = SHX_F_IN_USE; e[0].state = SHX_STATE_MOUNTED; e[0].letter = L'1';                 /* bad letter */
  e[1].flags = 0;            e[1].state = SHX_STATE_MOUNTED; e[1].letter = L'K';                 /* not in use */
  e[2].flags = SHX_F_IN_USE | 0x200u; e[2].letter = L'L';                                        /* unknown flag */
  e[3].flags = SHX_F_IN_USE; e[3].letter = L'M'; e[3].profile_id = L"not-hex";                  /* profile id */
  e[4].flags = SHX_F_IN_USE; e[4].letter = L'N'; e[4].name = L"bad\xD800" L"x";                  /* lone surrogate */
  e[5].flags = SHX_F_IN_USE; e[5].letter = L'P'; e[5].profile_id = L"0123456789ABCDEF0123456789abcdef"; /* ok */
  e[6].flags = SHX_F_IN_USE; e[6].letter = L'Q';                                                 /* ok */
  t_default_hdr(&h, 7);
  t_build(&h, e, 7);
  t_publish();
  n = t_read_count();
  SD_CHECK_EQ_INT(n, 2);            /* the two valid entries (P and Q) */
  t_close_section();
}

/* A header that does not fit the layout is "no data" (not "some entries"). */
SD_TEST(snapshot_bad_header_is_no_data)
{
  t_ent e[1];
  t_hdr h;
  int k;
  if (!t_open_fresh(L"")) { SD_CHECK(0); return; }
  memset(e, 0, sizeof(e));
  e[0].flags = SHX_F_IN_USE; e[0].letter = L'E';
  for (k = 0; k < 9; k++) {
    t_default_hdr(&h, 1);
    switch (k) {
    case 0: h.magic = 0x12345678u; break;                     /* magic */
    case 1: h.layout = 3; break;                              /* layout */
    case 2: h.header_size = 32; break;                        /* header below 64 */
    case 3: h.entry_size = 1790; break;                       /* entry below 1792 */
    case 4: h.entry_size = 1797; break;                       /* not a multiple of 8 */
    case 5: h.entry_count = 129; h.total = T_HDR + 129 * T_ENTRY; break; /* over 128 */
    case 6: h.total = T_HDR + T_ENTRY + 8; break;             /* total inconsistent */
    case 7: h.total = T_SEC_BYTES + 8; break;                 /* total over the section */
    default: h.header_size = T_HDR + T_ENTRY + 64; h.total = T_HDR + T_ENTRY; break; /* header past total */
    }
    t_build(&h, e, 1);
    t_publish();
    SD_CHECK_EQ_INT(t_read_count(), 0);
  }
  t_close_section();
}

/* A writer in progress (odd seq) on every try: three tries, then no data. */
SD_TEST(snapshot_odd_seq_is_no_data)
{
  t_ent e[1];
  t_hdr h;
  if (!t_open_fresh(L"")) { SD_CHECK(0); return; }
  memset(e, 0, sizeof(e));
  e[0].flags = SHX_F_IN_USE; e[0].letter = L'E';
  t_default_hdr(&h, 1);
  h.seq = 3;
  t_build(&h, e, 1);
  t_publish();
  SD_CHECK_EQ_INT(t_read_count(), 0);
  t_close_section();
}

SD_TEST(snapshot_missing_section_is_no_data)
{
  shx_entry out[4];
  /* A name nobody created. */
  SetEnvironmentVariableW(T_TEST_STATE, L"Local\\com.librestatic.shelldrive.test.absent");
  SD_CHECK_EQ_INT(shx_snapshot_read(out, 4), 0);
  SetEnvironmentVariableW(T_TEST_STATE, NULL);
}

/* A section with a low mandatory label is refused (TM-R26). Skipped when the test cannot create it. */
SD_TEST(snapshot_low_label_is_refused)
{
  t_ent e[1];
  t_hdr h;
  if (!t_open_fresh(L"S:(ML;;NW;;;LW)")) {
    /* Creation with a label needs the right to lower it; if the host refuses, the case is not testable here. */
    return;
  }
  memset(e, 0, sizeof(e));
  e[0].flags = SHX_F_IN_USE; e[0].letter = L'E';
  t_default_hdr(&h, 1);
  t_build(&h, e, 1);
  t_publish();
  SD_CHECK_EQ_INT(t_read_count(), 0);
  t_close_section();
}

/* Random corruption of a valid image: never a fault, never more entries than the capacity. */
SD_TEST(snapshot_random_corruption_is_bounded)
{
  t_ent e[3];
  t_hdr h;
  unsigned iter;
  unsigned long seed = 12345u;
  memset(e, 0, sizeof(e));
  e[0].flags = SHX_F_IN_USE; e[0].state = SHX_STATE_MOUNTED; e[0].letter = L'E';
  e[1].flags = SHX_F_IN_USE; e[1].state = SHX_STATE_FAILED; e[1].letter = L'F';
  e[2].flags = SHX_F_IN_USE | SHX_F_GLOBAL; e[2].letter = L'G';
  if (!t_open_fresh(L"")) { SD_CHECK(0); return; }
  for (iter = 0; iter < 400; iter++) {
    unsigned k, flips;
    t_default_hdr(&h, 3);
    t_build(&h, e, 3);
    flips = 1 + (iter % 12);
    for (k = 0; k < flips; k++) {
      unsigned pos, val;
      seed = seed * 1103515245u + 12345u;
      pos = (unsigned)((seed >> 8) % T_SEC_BYTES);
      seed = seed * 1103515245u + 12345u;
      val = (unsigned)((seed >> 8) & 0xFF);
      if (pos < sizeof(t_buf))
        t_buf[pos] = (unsigned char)val;
    }
    t_publish();
    {
      shx_entry out[SHX_SNAP_MAX_ENTRIES];
      size_t n = shx_snapshot_read(out, SHX_SNAP_MAX_ENTRIES);
      SD_CHECK(n <= SHX_SNAP_MAX_ENTRIES);
    }
  }
  t_close_section();
}

/* ---- COM helpers ---- */

typedef struct t_fdo {
  IDataObject iface;
  const wchar_t *paths[4];
  int n;
} t_fdo;

static HRESULT STDMETHODCALLTYPE fdo_QueryInterface(IDataObject *This, REFIID riid, void **ppv)
{
  (void)This; (void)riid;
  if (ppv) *ppv = NULL;
  return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE fdo_AddRef(IDataObject *This)
{
  (void)This;
  return 1;
}

static ULONG STDMETHODCALLTYPE fdo_Release(IDataObject *This)
{
  (void)This;
  return 1;
}

static HRESULT STDMETHODCALLTYPE fdo_GetData(IDataObject *This, FORMATETC *fe, STGMEDIUM *sm)
{
  t_fdo *d = (t_fdo *)This;
  SIZE_T bytes = sizeof(DROPFILES) + sizeof(wchar_t);
  int i;
  HGLOBAL g;
  unsigned char *p;
  DROPFILES *df;
  wchar_t *w;

  memset(sm, 0, sizeof(*sm));
  if (fe->cfFormat != CF_HDROP || (fe->tymed & TYMED_HGLOBAL) == 0)
    return DV_E_FORMATETC;
  for (i = 0; i < d->n; i++)
    bytes += (wcslen(d->paths[i]) + 1) * sizeof(wchar_t);
  g = GlobalAlloc(GMEM_MOVEABLE, bytes);
  if (g == NULL)
    return E_OUTOFMEMORY;
  p = (unsigned char *)GlobalLock(g);
  if (p == NULL) {
    GlobalFree(g);
    return E_OUTOFMEMORY;
  }
  df = (DROPFILES *)p;
  memset(df, 0, sizeof(*df));
  df->pFiles = sizeof(DROPFILES);
  df->fWide = TRUE;
  w = (wchar_t *)(p + sizeof(DROPFILES));
  for (i = 0; i < d->n; i++) {
    wcscpy_s(w, wcslen(d->paths[i]) + 1, d->paths[i]);
    w += wcslen(d->paths[i]) + 1;
  }
  *w = 0;
  GlobalUnlock(g);
  sm->tymed = TYMED_HGLOBAL;
  sm->hGlobal = g;
  sm->pUnkForRelease = NULL;
  return S_OK;
}

static HRESULT STDMETHODCALLTYPE fdo_GetDataHere(IDataObject *This, FORMATETC *fe, STGMEDIUM *sm)
{
  (void)This; (void)fe; (void)sm;
  return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE fdo_QueryGetData(IDataObject *This, FORMATETC *fe)
{
  (void)This; (void)fe;
  return S_OK;
}

static HRESULT STDMETHODCALLTYPE fdo_GetCanonicalFormatEtc(IDataObject *This, FORMATETC *a, FORMATETC *b)
{
  (void)This; (void)a; (void)b;
  return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE fdo_SetData(IDataObject *This, FORMATETC *a, STGMEDIUM *b, BOOL c)
{
  (void)This; (void)a; (void)b; (void)c;
  return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE fdo_EnumFormatEtc(IDataObject *This, DWORD dir, IEnumFORMATETC **e)
{
  (void)This; (void)dir;
  if (e) *e = NULL;
  return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE fdo_DAdvise(IDataObject *This, FORMATETC *a, DWORD b, IAdviseSink *c, DWORD *d)
{
  (void)This; (void)a; (void)b; (void)c; (void)d;
  return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE fdo_DUnadvise(IDataObject *This, DWORD a)
{
  (void)This; (void)a;
  return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE fdo_EnumDAdvise(IDataObject *This, IEnumSTATDATA **e)
{
  (void)This;
  if (e) *e = NULL;
  return E_NOTIMPL;
}

static IDataObjectVtbl t_fdo_vtbl = {
  fdo_QueryInterface,
  fdo_AddRef,
  fdo_Release,
  fdo_GetData,
  fdo_GetDataHere,
  fdo_QueryGetData,
  fdo_GetCanonicalFormatEtc,
  fdo_SetData,
  fdo_EnumFormatEtc,
  fdo_DAdvise,
  fdo_DUnadvise,
  fdo_EnumDAdvise
};

static void t_fdo_init(t_fdo *d, const wchar_t *p0, const wchar_t *p1)
{
  memset(d, 0, sizeof(*d));
  d->iface.lpVtbl = &t_fdo_vtbl;
  d->paths[0] = p0;
  d->paths[1] = p1;
  d->n = p1 ? 2 : 1;
}

/* Gets IShellExtInit from the DLL factory, initializes it with the data object and returns IContextMenu.
   The IShellExtInit reference is released here; the returned menu owns the object. */
static HRESULT t_make_menu(IDataObject *pdo, IContextMenu **menu)
{
  IClassFactory *fac = NULL;
  IShellExtInit *init = NULL;
  HRESULT hr;

  *menu = NULL;
  hr = t_get_class(&SHX_CLSID_CONTEXT_MENU, &IID_IClassFactory, (void **)&fac);
  if (FAILED(hr))
    return hr;
  hr = fac->lpVtbl->CreateInstance(fac, NULL, &IID_IShellExtInit, (void **)&init);
  fac->lpVtbl->Release(fac);
  if (FAILED(hr))
    return hr;
  hr = init->lpVtbl->Initialize(init, NULL, pdo, NULL);
  if (SUCCEEDED(hr))
    hr = init->lpVtbl->QueryInterface(init, &IID_IContextMenu, (void **)menu);
  init->lpVtbl->Release(init);
  return hr;
}

/* Writes one entry for drive `letter` with the given state and flags, and publishes it. */
static void t_one_drive(wchar_t letter, uint32_t flags, uint32_t state)
{
  t_ent e[1];
  t_hdr h;
  memset(e, 0, sizeof(e));
  e[0].flags = SHX_F_IN_USE | flags;
  e[0].state = state;
  e[0].backend = 1;
  e[0].letter = letter;
  e[0].profile_id = (flags & SHX_F_GLOBAL) ? NULL : L"0123456789abcdef0123456789abcdef";
  t_default_hdr(&h, 1);
  t_build(&h, e, 1);
  t_publish();
}

/* Query the menu for one path and return the count of items added, or -1 when the call failed. */
static int t_query(const wchar_t *path, HMENU *out_menu, UINT flags)
{
  t_fdo d;
  IContextMenu *menu = NULL;
  HRESULT hr, q;
  HMENU hm = CreatePopupMenu();
  int count;
  t_fdo_init(&d, path, NULL);
  hr = t_make_menu(&d.iface, &menu);
  if (FAILED(hr) || menu == NULL) {
    DestroyMenu(hm);
    return -1;
  }
  q = menu->lpVtbl->QueryContextMenu(menu, hm, 0, 100, 199, flags);
  count = (int)(SCODE_CODE(q));
  if (SUCCEEDED(q) && count != GetMenuItemCount(hm)) {
    /* The HRESULT carries the count; the menu must agree. */
    count = -1;
  }
  menu->lpVtbl->Release(menu);
  if (out_menu != NULL)
    *out_menu = hm;
  else
    DestroyMenu(hm);
  return SUCCEEDED(q) ? count : -1;
}

/* ---- COM tests ---- */

SD_TEST(exports_and_factory_arguments)
{
  IClassFactory *fac = NULL;
  SD_REQUIRE(t_get_class != NULL);
  SD_REQUIRE(t_can_unload != NULL);
  SD_REQUIRE(t_register != NULL);
  SD_REQUIRE(t_unregister != NULL);
  SD_CHECK(t_get_class(&SHX_CLSID_CONTEXT_MENU, &IID_IClassFactory, NULL) == E_POINTER);
  SD_CHECK(t_get_class(&t_nil_guid, &IID_IClassFactory, (void **)&fac) == CLASS_E_CLASSNOTAVAILABLE);
  SD_CHECK(fac == NULL);
  SD_CHECK(t_get_class(&SHX_CLSID_CONTEXT_MENU, &IID_IUnknown, (void **)&fac) == S_OK && fac != NULL);
  if (fac != NULL)
    fac->lpVtbl->Release(fac);
}

SD_TEST(menu_items_for_mounted_drive)
{
  HMENU hm = NULL;
  wchar_t text[128];
  int n;
  if (!t_open_fresh(L"")) { SD_CHECK(0); return; }
  t_one_drive(L'E', 0, SHX_STATE_MOUNTED);
  n = t_query(L"E:\\", &hm, 0);
  SD_CHECK_EQ_INT(n, 2);            /* Open, Unmount */
  if (hm != NULL) {
    SD_CHECK_EQ_INT(GetMenuItemID(hm, 0), 100);
    SD_CHECK_EQ_INT(GetMenuItemID(hm, 1), 101);
    SD_CHECK(GetMenuStringW(hm, 0, text, 128, MF_BYPOSITION) > 0);
    DestroyMenu(hm);
  }
  t_close_section();
}

SD_TEST(menu_failed_drive_offers_reconnect)
{
  HMENU hm = NULL;
  int n;
  IContextMenu *menu = NULL;
  t_fdo d;
  HRESULT hr;
  char verb[64];
  wchar_t wverb[64];
  if (!t_open_fresh(L"")) { SD_CHECK(0); return; }
  t_one_drive(L'F', 0, SHX_STATE_FAILED);
  n = t_query(L"F:\\", &hm, 0);
  SD_CHECK_EQ_INT(n, 3);            /* Open, Unmount, Reconnect */
  if (hm != NULL)
    DestroyMenu(hm);

  /* GetCommandString for the third item: machine verb in ANSI and Unicode, help text, validate. */
  t_fdo_init(&d, L"F:\\", NULL);
  hr = t_make_menu(&d.iface, &menu);
  SD_REQUIRE(SUCCEEDED(hr) && menu != NULL);
  {
    HMENU h2 = CreatePopupMenu();
    HRESULT qq = menu->lpVtbl->QueryContextMenu(menu, h2, 0, 100, 199, 0);
    SD_CHECK_EQ_INT(SCODE_CODE(qq), 3);
    DestroyMenu(h2);
  }
  SD_CHECK(menu->lpVtbl->GetCommandString(menu, 2, GCS_VERBA, NULL, verb, sizeof(verb)) == S_OK);
  SD_CHECK_STR(verb, "shelldrive.reconnect");
  SD_CHECK(menu->lpVtbl->GetCommandString(menu, 2, GCS_VERBW, NULL, (LPSTR)wverb, 64) == S_OK);
  SD_CHECK(wcscmp(wverb, L"shelldrive.reconnect") == 0);
  SD_CHECK(menu->lpVtbl->GetCommandString(menu, 2, GCS_HELPTEXTW, NULL, (LPSTR)wverb, 64) == S_OK);
  SD_CHECK(wverb[0] != 0);
  SD_CHECK(menu->lpVtbl->GetCommandString(menu, 2, GCS_HELPTEXTA, NULL, verb, sizeof(verb)) == S_OK);
  SD_CHECK(verb[0] != 0);
  SD_CHECK(menu->lpVtbl->GetCommandString(menu, 2, GCS_VALIDATEA, NULL, NULL, 0) == S_OK);
  SD_CHECK(menu->lpVtbl->GetCommandString(menu, 7, GCS_VERBA, NULL, verb, sizeof(verb)) == E_INVALIDARG);
  menu->lpVtbl->Release(menu);
  t_close_section();
}

SD_TEST(menu_global_drive_offers_open_only)
{
  int n;
  if (!t_open_fresh(L"")) { SD_CHECK(0); return; }
  t_one_drive(L'G', SHX_F_GLOBAL, SHX_STATE_MOUNTED);
  n = t_query(L"G:\\", NULL, 0);
  SD_CHECK_EQ_INT(n, 1);
  t_one_drive(L'G', SHX_F_GLOBAL, SHX_STATE_FAILED);
  n = t_query(L"G:\\", NULL, 0);
  SD_CHECK_EQ_INT(n, 1);
  t_close_section();
}

SD_TEST(menu_no_items_for_other_selections)
{
  if (!t_open_fresh(L"")) { SD_CHECK(0); return; }
  t_one_drive(L'E', 0, SHX_STATE_MOUNTED);
  SD_CHECK_EQ_INT(t_query(L"Z:\\", NULL, 0), 0);          /* not a ShellDrive drive */
  SD_CHECK_EQ_INT(t_query(L"C:\\Users", NULL, 0), 0);     /* a folder, not a drive root */
  SD_CHECK_EQ_INT(t_query(L"\\\\server\\share", NULL, 0), 0);
  SD_CHECK_EQ_INT(t_query(L"E:\\", NULL, CMF_DEFAULTONLY), 0);
  t_close_section();
}

SD_TEST(menu_corrupt_snapshot_has_no_items)
{
  t_hdr h;
  if (!t_open_fresh(L"")) { SD_CHECK(0); return; }
  t_one_drive(L'E', 0, SHX_STATE_MOUNTED);
  t_default_hdr(&h, 1);
  h.magic = 0;
  t_build(&h, NULL, 0);
  t_publish();
  SD_CHECK_EQ_INT(t_query(L"E:\\", NULL, 0), 0);
  t_close_section();
}

/* Writes the launch line to a file and checks it; launches nothing. */
static int t_read_cmdline(const wchar_t *file, wchar_t *out, size_t cch)
{
  HANDLE h = CreateFileW(file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  DWORD got = 0;
  BOOL ok;
  if (h == INVALID_HANDLE_VALUE)
    return 0;
  ok = ReadFile(h, out, (DWORD)((cch - 1) * sizeof(wchar_t)), &got, NULL);
  CloseHandle(h);
  if (!ok)
    return 0;
  out[got / sizeof(wchar_t)] = 0;
  return 1;
}

SD_TEST(invoke_builds_the_ui_command_line)
{
  t_fdo d;
  IContextMenu *menu = NULL;
  HRESULT hr;
  HMENU hm;
  CMINVOKECOMMANDINFO ci;
  wchar_t file[MAX_PATH], text[1024], expect[1200], tmpdir[MAX_PATH];

  if (!t_open_fresh(L"")) { SD_CHECK(0); return; }
  t_one_drive(L'E', 0, SHX_STATE_MOUNTED);
  GetTempPathW(MAX_PATH, tmpdir);
  _snwprintf_s(file, MAX_PATH, _TRUNCATE, L"%sshx-cmd-%lu.txt", tmpdir, (unsigned long)GetCurrentProcessId());
  file[MAX_PATH - 1] = 0;
  DeleteFileW(file);
  SetEnvironmentVariableW(T_TEST_CMD, file);

  t_fdo_init(&d, L"E:\\", NULL);
  hr = t_make_menu(&d.iface, &menu);
  SD_REQUIRE(SUCCEEDED(hr) && menu != NULL);
  hm = CreatePopupMenu();
  menu->lpVtbl->QueryContextMenu(menu, hm, 0, 100, 199, 0);
  DestroyMenu(hm);

  memset(&ci, 0, sizeof(ci));
  ci.cbSize = sizeof(ci);
  ci.nShow = SW_SHOWNORMAL;

  /* Offset 1 (Unmount on a mounted drive), by resource id. */
  ci.lpVerb = MAKEINTRESOURCEA(1);
  SD_CHECK(menu->lpVtbl->InvokeCommand(menu, &ci) == S_OK);
  SD_CHECK(t_read_cmdline(file, text, 1024) == 1);
  _snwprintf_s(expect, 1200, _TRUNCATE, L"\"%sshelldrive-ui.exe\" --action unmount E:", t_dll_dir);
  expect[1199] = 0;
  SD_CHECK(wcscmp(text, expect) == 0);
  DeleteFileW(file);

  /* Offset 0 (Open). */
  ci.lpVerb = MAKEINTRESOURCEA(0);
  SD_CHECK(menu->lpVtbl->InvokeCommand(menu, &ci) == S_OK);
  SD_CHECK(t_read_cmdline(file, text, 1024) == 1);
  _snwprintf_s(expect, 1200, _TRUNCATE, L"\"%sshelldrive-ui.exe\" --action open E:", t_dll_dir);
  expect[1199] = 0;
  SD_CHECK(wcscmp(text, expect) == 0);
  DeleteFileW(file);

  /* A string verb naming one of our items, case-insensitive. */
  ci.lpVerb = "ShellDrive.Unmount";
  SD_CHECK(menu->lpVtbl->InvokeCommand(menu, &ci) == S_OK);
  SD_CHECK(t_read_cmdline(file, text, 1024) == 1);
  _snwprintf_s(expect, 1200, _TRUNCATE, L"\"%sshelldrive-ui.exe\" --action unmount E:", t_dll_dir);
  expect[1199] = 0;
  SD_CHECK(wcscmp(text, expect) == 0);
  DeleteFileW(file);

  /* Out of range and unknown names launch nothing. */
  ci.lpVerb = MAKEINTRESOURCEA(2);                  /* no Reconnect on a mounted drive */
  SD_CHECK(menu->lpVtbl->InvokeCommand(menu, &ci) == E_FAIL);
  ci.lpVerb = "shelldrive.format";
  SD_CHECK(menu->lpVtbl->InvokeCommand(menu, &ci) == E_FAIL);
  SD_CHECK(GetFileAttributesW(file) == INVALID_FILE_ATTRIBUTES);

  SD_CHECK(menu->lpVtbl->Release(menu) == 0);
  SetEnvironmentVariableW(T_TEST_CMD, NULL);
  t_close_section();
}

/* Deletes a key tree under HKCU (the test's own temporary keys only). */
static void t_delete_tree(HKEY parent, const wchar_t *name)
{
  HKEY k = NULL;
  wchar_t sub[256];
  DWORD len;
  unsigned i;
  if (RegOpenKeyExW(parent, name, 0, KEY_READ | KEY_SET_VALUE, &k) != ERROR_SUCCESS)
    return;
  for (i = 0; i < 4096; i++) {
    len = 256;
    if (RegEnumKeyExW(k, 0, sub, &len, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
      break;
    t_delete_tree(k, sub);
  }
  RegCloseKey(k);
  RegDeleteKeyW(parent, name);
}

SD_TEST(register_redirected_hkcu_leaves_real_registry)
{
  HKEY tmp = NULL, probe = NULL;
  wchar_t tmp_name[200];
  wchar_t clsid_key[256];
  wchar_t inproc[300];
  wchar_t path[MAX_PATH];
  wchar_t data[MAX_PATH];
  DWORD type, cb;
  LONG rc;
  BOOL real_before, real_after;
  HRESULT hr_reg = E_FAIL, hr_unreg = E_FAIL;
  BOOL overridden = FALSE;

  _snwprintf_s(clsid_key, 256, _TRUNCATE, L"Software\\Classes\\CLSID\\%s", SHX_CLSID_TEXT);
  clsid_key[255] = 0;

  /* Real HKCU state before, for the class key and the Drive entry. */
  real_before = RegOpenKeyExW(HKEY_CURRENT_USER, clsid_key, 0, KEY_READ, &probe) == ERROR_SUCCESS;
  if (real_before)
    RegCloseKey(probe);
  probe = NULL;

  /* A temporary key under HKCU that becomes the HKCU root for this process, then is removed. */
  _snwprintf_s(tmp_name, 200, _TRUNCATE, L"Software\\LibreStatic-shellext-test-%lu", (unsigned long)GetCurrentProcessId());
  tmp_name[199] = 0;
  rc = RegCreateKeyExW(HKEY_CURRENT_USER, tmp_name, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &tmp,
                       NULL);
  SD_REQUIRE(rc == ERROR_SUCCESS && tmp != NULL);
  rc = RegOverridePredefKey(HKEY_CURRENT_USER, tmp);
  SD_REQUIRE(rc == ERROR_SUCCESS);
  overridden = TRUE;

  hr_reg = t_register();
  SD_CHECK(SUCCEEDED(hr_reg));

  /* Values written under the redirected HKCU. */
  GetModuleFileNameW(t_dll, path, MAX_PATH);
  cb = sizeof(data);
  rc = RegOpenKeyExW(HKEY_CURRENT_USER, clsid_key, 0, KEY_READ, &probe);
  SD_CHECK(rc == ERROR_SUCCESS);
  if (rc == ERROR_SUCCESS) {
    RegCloseKey(probe);
    probe = NULL;
  }
  _snwprintf_s(inproc, 300, _TRUNCATE, L"%s\\InprocServer32", clsid_key);
  rc = RegOpenKeyExW(HKEY_CURRENT_USER, inproc, 0, KEY_READ, &probe);
  SD_CHECK(rc == ERROR_SUCCESS);
  if (rc == ERROR_SUCCESS) {
    cb = sizeof(data);
    rc = RegQueryValueExW(probe, NULL, NULL, &type, (LPBYTE)data, &cb);
    SD_CHECK(rc == ERROR_SUCCESS && type == REG_SZ && wcscmp(data, path) == 0);
    cb = sizeof(data);
    rc = RegQueryValueExW(probe, L"ThreadingModel", NULL, &type, (LPBYTE)data, &cb);
    SD_CHECK(rc == ERROR_SUCCESS && wcscmp(data, L"Apartment") == 0);
    RegCloseKey(probe);
    probe = NULL;
  }
  rc = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Classes\\Drive\\shellex\\ContextMenuHandlers\\ShellDrive", 0,
                     KEY_READ, &probe);
  SD_CHECK(rc == ERROR_SUCCESS);
  if (rc == ERROR_SUCCESS) {
    cb = sizeof(data);
    rc = RegQueryValueExW(probe, NULL, NULL, &type, (LPBYTE)data, &cb);
    SD_CHECK(rc == ERROR_SUCCESS && wcscmp(data, SHX_CLSID_TEXT) == 0);
    RegCloseKey(probe);
    probe = NULL;
  }
  rc = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved",
                     0, KEY_READ, &probe);
  SD_CHECK(rc == ERROR_SUCCESS);
  if (rc == ERROR_SUCCESS) {
    cb = sizeof(data);
    rc = RegQueryValueExW(probe, SHX_CLSID_TEXT, NULL, &type, (LPBYTE)data, &cb);
    SD_CHECK(rc == ERROR_SUCCESS);
    RegCloseKey(probe);
    probe = NULL;
  }

  hr_unreg = t_unregister();
  SD_CHECK(SUCCEEDED(hr_unreg));
  rc = RegOpenKeyExW(HKEY_CURRENT_USER, clsid_key, 0, KEY_READ, &probe);
  SD_CHECK(rc == ERROR_FILE_NOT_FOUND);
  if (rc == ERROR_SUCCESS)
    RegCloseKey(probe);
  probe = NULL;
  rc = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Classes\\Drive\\shellex\\ContextMenuHandlers\\ShellDrive", 0,
                     KEY_READ, &probe);
  SD_CHECK(rc == ERROR_FILE_NOT_FOUND);
  if (rc == ERROR_SUCCESS)
    RegCloseKey(probe);
  probe = NULL;

  /* Restore HKCU, then check the real one was not touched. */
  RegOverridePredefKey(HKEY_CURRENT_USER, NULL);
  overridden = FALSE;
  real_after = RegOpenKeyExW(HKEY_CURRENT_USER, clsid_key, 0, KEY_READ, &probe) == ERROR_SUCCESS;
  if (real_after)
    RegCloseKey(probe);
  SD_CHECK(real_before == real_after);

  if (tmp != NULL) {
    RegCloseKey(tmp);
    tmp = NULL;
  }
  if (overridden)
    RegOverridePredefKey(HKEY_CURRENT_USER, NULL);
  /* The registrations were written under the temporary root; the whole tree goes. */
  t_delete_tree(HKEY_CURRENT_USER, tmp_name);
}

SD_TEST(unload_and_locks_follow_references)
{
  IClassFactory *fac = NULL;
  IShellExtInit *init = NULL;
  IContextMenu *menu = NULL;
  t_fdo d;
  HRESULT hr;

  SD_CHECK(t_can_unload() == S_OK);
  t_fdo_init(&d, L"E:\\", NULL);
  hr = t_get_class(&SHX_CLSID_CONTEXT_MENU, &IID_IClassFactory, (void **)&fac);
  SD_REQUIRE(SUCCEEDED(hr) && fac != NULL);
  SD_CHECK(fac->lpVtbl->LockServer(fac, TRUE) == S_OK);
  SD_CHECK(t_can_unload() == S_FALSE);
  SD_CHECK(fac->lpVtbl->LockServer(fac, FALSE) == S_OK);
  SD_CHECK(t_can_unload() == S_OK);

  hr = fac->lpVtbl->CreateInstance(fac, NULL, &IID_IShellExtInit, (void **)&init);
  SD_REQUIRE(SUCCEEDED(hr) && init != NULL);
  SD_CHECK(t_can_unload() == S_FALSE);
  SD_CHECK(init->lpVtbl->Initialize(init, NULL, &d.iface, NULL) == S_OK);
  SD_CHECK(init->lpVtbl->QueryInterface(init, &IID_IContextMenu, (void **)&menu) == S_OK);
  init->lpVtbl->Release(init);
  SD_CHECK(t_can_unload() == S_FALSE);
  SD_CHECK(menu->lpVtbl->Release(menu) == 0);
  SD_CHECK(t_can_unload() == S_OK);
  SD_CHECK(fac->lpVtbl->CreateInstance(fac, (IUnknown *)fac, &IID_IShellExtInit, (void **)&init) ==
           CLASS_E_NOAGGREGATION);
  fac->lpVtbl->Release(fac);
}

/* ---- entry point ---- */

static void t_setup_paths(void)
{
  wchar_t full[MAX_PATH];
  wchar_t *slash;
  wchar_t self[MAX_PATH];
  HMODULE self_mod;
  wchar_t dll[MAX_PATH];

  self_mod = GetModuleHandleW(NULL);
  GetModuleFileNameW(self_mod, self, MAX_PATH);
  wcscpy_s(full, MAX_PATH, self);
  slash = wcsrchr(full, L'\\');
  if (slash != NULL)
    slash[1] = 0;
  wcscpy_s(t_dll_dir, MAX_PATH, full);
  _snwprintf_s(dll, MAX_PATH, _TRUNCATE, L"%sshelldrive-shellext-test.dll", full);
  dll[MAX_PATH - 1] = 0;
  t_dll = LoadLibraryW(dll);
  if (t_dll == NULL)
    return;
  t_get_class = (t_pfn_get_class)GetProcAddress(t_dll, "DllGetClassObject");
  t_can_unload = (t_pfn_can_unload)GetProcAddress(t_dll, "DllCanUnloadNow");
  t_register = (t_pfn_register)GetProcAddress(t_dll, "DllRegisterServer");
  t_unregister = (t_pfn_register)GetProcAddress(t_dll, "DllUnregisterServer");
}

SD_TEST(dll_loads_with_the_four_exports)
{
  SD_CHECK(t_dll != NULL);
  SD_CHECK(t_get_class != NULL);
  SD_CHECK(t_can_unload != NULL);
  SD_CHECK(t_register != NULL);
  SD_CHECK(t_unregister != NULL);
}

static const sd_test_case k_tests[] = {
  SD_TEST_ENTRY(dll_loads_with_the_four_exports),
  SD_TEST_ENTRY(snapshot_valid_entries),
  SD_TEST_ENTRY(snapshot_drops_bad_entries_only),
  SD_TEST_ENTRY(snapshot_bad_header_is_no_data),
  SD_TEST_ENTRY(snapshot_odd_seq_is_no_data),
  SD_TEST_ENTRY(snapshot_missing_section_is_no_data),
  SD_TEST_ENTRY(snapshot_low_label_is_refused),
  SD_TEST_ENTRY(snapshot_random_corruption_is_bounded),
  SD_TEST_ENTRY(exports_and_factory_arguments),
  SD_TEST_ENTRY(menu_items_for_mounted_drive),
  SD_TEST_ENTRY(menu_failed_drive_offers_reconnect),
  SD_TEST_ENTRY(menu_global_drive_offers_open_only),
  SD_TEST_ENTRY(menu_no_items_for_other_selections),
  SD_TEST_ENTRY(menu_corrupt_snapshot_has_no_items),
  SD_TEST_ENTRY(invoke_builds_the_ui_command_line),
  SD_TEST_ENTRY(register_redirected_hkcu_leaves_real_registry),
  SD_TEST_ENTRY(unload_and_locks_follow_references),
};

int main(int argc, char **argv)
{
  int rc;
  (void)argc;
  (void)argv;
  t_setup_paths();
  rc = sd_test_main(k_tests, SD_COUNTOF(k_tests), argc, argv);
  if (t_dll != NULL)
    FreeLibrary(t_dll);
  return rc;
}
