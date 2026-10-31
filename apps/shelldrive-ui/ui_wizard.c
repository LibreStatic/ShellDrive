/* shelldrive-ui: the first-run wizard (03 §5.5, §7.5). See ui_wizard.h.
 *
 * The pages are DLGTEMPLATEEX blobs from ui_dlg (03 §7.1), like the profile editor. The flag [ui] first_run_done is
 * written with the public sd_ini API under sd_config_lock; sd_settings_save keeps unknown keys, so the flag survives
 * later saves of the Settings window. */
#include <windows.h>
#include <commctrl.h>
#include <string.h>
#include <wchar.h>

#include "sd_base/sd_buf.h"
#include "sd_base/sd_err.h"
#include "sd_base/sd_mem.h"
#include "sd_config/sd_config.h"
#include "sd_config/sd_ini.h"
#include "sd_l10n/sd_l10n.h"
#include "sd_l10n_ui_ids.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_platform.h"
#include "ui_dlg.h"
#include "ui_int.h"
#include "ui_measure.h"
#include "ui_theme.h"
#include "ui_win.h"
#include "ui_wizard.h"
#include "ui_wizard_model.h"

/* The Vista SDK constants the XP SDK 7.1A headers lack (06 §6.5). */
#ifndef PSH_AEROWIZARD
#define PSH_AEROWIZARD 0x00004000
#endif
#ifndef PSP_USEHEADERTITLE
#define PSP_USEHEADERTITLE 0x00002000
#endif

#define WIZ_WIDTH          280
#define WIZ_TEXT           0             /* static texts have no id */
#define WIZ_ID_IMPORT      5101
#define WIZ_ID_CREATE      5201
#define WIZ_ID_CREATE_NOTE 5202
#define WIZ_ID_MOUNT       5301
#define WIZ_LOCK_MS        5000

enum { PG_WELCOME = 0, PG_BACKEND, PG_IMPORT, PG_CREATE, PG_FINISH, WIZ_PAGES };

typedef struct wiz_ctx wiz_ctx;

typedef struct wiz_page {
  wiz_ctx *ctx;
  int index;
  HWND hwnd;
} wiz_page;

struct wiz_ctx {
  HWND sheet;                   /* the PropertySheet window (owner of the modal editor and import dialog) */
  wiz_page pages[WIZ_PAGES];
  int created;                  /* the create page saved a profile */
  char created_id[33];
  int mount_now;                /* the finish page's check box was on at Finish */
};

/* ---- the settings flag ---- */

static sd_err settings_path(wchar_t path[MAX_PATH])
{
  sd_err e = sd_config_root(path, MAX_PATH);
  if (e != SD_OK)
    return e;
  if (wcscat_s(path, MAX_PATH, L"\\settings.ini") != 0)
    return SD_E_NAME_TOO_LONG;
  return SD_OK;
}

/* Reads settings.ini under the user root. SD_E_NOT_FOUND when there is no file. The caller frees *ini with
   sd_ini_free. */
static sd_err read_settings_ini(sd_ini **ini)
{
  wchar_t path[MAX_PATH];
  HANDLE h;
  DWORD size, got = 0;
  char *data;
  uint32_t flags = 0;
  sd_err e;

  if ((e = settings_path(path)) != SD_OK)
    return e;
  if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES)
    return SD_E_NOT_FOUND;
  h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                  FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE)
    return SD_E_ACCESS_DENIED;
  size = GetFileSize(h, NULL);
  if (size == INVALID_FILE_SIZE || size > SD_INI_MAX_BYTES) {
    CloseHandle(h);
    return SD_E_INVALID_PARAM;
  }
  data = (char *)sd_alloc((size_t)size + 1u);
  if (data == NULL) {
    CloseHandle(h);
    return SD_E_NO_MEMORY;
  }
  if (!ReadFile(h, data, size, &got, NULL) || got != size) {
    CloseHandle(h);
    sd_free(data);
    return SD_E_FAILURE;
  }
  CloseHandle(h);
  e = sd_ini_parse(data, (size_t)size, ini, &flags);
  sd_free(data);
  return e;
}

int ui_wizard_first_run_done(void)
{
  sd_ini *ini = NULL;
  const char *v;
  int done = 0, b = 0;

  if (read_settings_ini(&ini) != SD_OK)
    return 0;
  v = sd_ini_get(ini, "ui", "first_run_done");
  if (v != NULL && sd_ini_parse_bool(v, &b))
    done = b ? 1 : 0;
  sd_ini_free(ini);
  return done;
}

/* Replaces settings.ini through a temporary file, as sd_config does for its own files. */
static sd_err write_settings_ini(const sd_ini *ini)
{
  wchar_t path[MAX_PATH], tmp[MAX_PATH];
  sd_wr w;
  HANDLE h;
  DWORD put = 0;
  BOOL ok;
  sd_err e;

  if ((e = settings_path(path)) != SD_OK)
    return e;
  if (wcscpy_s(tmp, SD_COUNTOF(tmp), path) != 0 || wcscat_s(tmp, SD_COUNTOF(tmp), L".tmp") != 0)
    return SD_E_NAME_TOO_LONG;

  sd_wr_init(&w, SD_INI_MAX_BYTES);
  e = sd_ini_serialize(ini, &w);
  if (e != SD_OK) {
    sd_wr_free(&w);
    return e;
  }
  h = CreateFileW(tmp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE) {
    sd_wr_free(&w);
    return SD_E_ACCESS_DENIED;
  }
  ok = WriteFile(h, w.p, (DWORD)w.len, &put, NULL) && put == (DWORD)w.len && FlushFileBuffers(h);
  CloseHandle(h);
  sd_wr_free(&w);
  if (!ok || !MoveFileExW(tmp, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
    DeleteFileW(tmp);
    return SD_E_FAILURE;
  }
  return SD_OK;
}

void ui_wizard_mark_done(void)
{
  sd_ini *ini = NULL;
  HANDLE lock = NULL;
  sd_err e;

  if (sd_config_ensure_dirs() != SD_OK)
    return;
  if (sd_config_lock(&lock, WIZ_LOCK_MS) != SD_OK)
    return;
  /* A file that exists but cannot be read is left alone: rewriting it would drop the user's other settings. */
  e = read_settings_ini(&ini);
  if (e == SD_E_NOT_FOUND)
    e = sd_ini_new(&ini);
  if (e == SD_OK && ini != NULL)
    e = sd_ini_set(ini, "ui", "first_run_done", "yes");
  if (e == SD_OK && ini != NULL)
    e = write_settings_ini(ini);
  if (e != SD_OK)
    SD_LOGW("ui", "the first-run wizard could not be marked as done (%s)", sd_err_name(e));
  sd_ini_free(ini);
  sd_config_unlock(lock);
}

/* ---- the backend page ---- */

/* Dokany is installed when its runtime is in System32 (sd_dokan loads the same file, 02 §6). The UI never links
   sd_dokan itself (03 §1.1): this only reports the file's presence, not whether the driver works. */
static int dokany_installed(void)
{
  wchar_t path[MAX_PATH];
  UINT n;
  if (!sd_os_at_least(6, 1, 7601))
    return 0;
  n = GetSystemDirectoryW(path, SD_COUNTOF(path));
  if (n == 0 || n > MAX_PATH - 16)
    return 0;
  if (wcscat_s(path, SD_COUNTOF(path), L"\\dokan2.dll") != 0)
    return 0;
  return GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES;
}

/* ---- page templates ---- */

static void add_text(ui_dlg *d, sd_msg_id msg)
{
  ui_dlg_text(d, WIZ_TEXT, sd_l10n_get(msg), 0);
  ui_dlg_space(d, 4);
}

static void add_page(ui_dlg *d, int pg)
{
  switch (pg) {
  case PG_WELCOME:
    add_text(d, SD_MSG_UI_WIZARD_WELCOME_TEXT);
    ui_dlg_text(d, WIZ_TEXT, sd_l10n_get(SD_MSG_UI_WIZARD_WELCOME_NEXT), 0);
    break;
  case PG_BACKEND:
    add_text(d, SD_MSG_UI_WIZARD_BACKEND_TEXT);
    ui_dlg_text(d, WIZ_TEXT, sd_l10n_get(dokany_installed() ? SD_MSG_UI_WIZARD_BACKEND_DOKANY_YES
                                                            : SD_MSG_UI_WIZARD_BACKEND_DOKANY_NO), 0);
    break;
  case PG_IMPORT: {
    static const WORD ids[1] = { WIZ_ID_IMPORT };
    const wchar_t *texts[1];
    add_text(d, SD_MSG_UI_WIZARD_IMPORT_TEXT);
    add_text(d, SD_MSG_UI_WIZARD_IMPORT_TRUST);
    texts[0] = sd_l10n_get(SD_MSG_UI_WIZARD_IMPORT_BUTTON);
    ui_dlg_buttons(d, ids, texts, 1, 0);
    break;
  }
  case PG_CREATE: {
    static const WORD ids[1] = { WIZ_ID_CREATE };
    const wchar_t *texts[1];
    add_text(d, SD_MSG_UI_WIZARD_CREATE_TEXT);
    texts[0] = sd_l10n_get(SD_MSG_UI_WIZARD_CREATE_BUTTON);
    ui_dlg_buttons(d, ids, texts, 1, 0);
    ui_dlg_text(d, WIZ_ID_CREATE_NOTE, L" ", 0);     /* one line of height; the saved name replaces it */
    break;
  }
  default:
    add_text(d, SD_MSG_UI_WIZARD_FINISH_TEXT);
    add_text(d, SD_MSG_UI_WIZARD_FDE_NOTE);
    ui_dlg_check(d, WIZ_ID_MOUNT, sd_l10n_get(SD_MSG_UI_WIZARD_MOUNT_NOW));
    break;
  }
}

static sd_msg_id page_title(int pg)
{
  switch (pg) {
  case PG_WELCOME: return SD_MSG_UI_WIZARD_WELCOME_TITLE;
  case PG_BACKEND: return SD_MSG_UI_WIZARD_BACKEND_TITLE;
  case PG_IMPORT:  return SD_MSG_UI_WIZARD_IMPORT_TITLE;
  case PG_CREATE:  return SD_MSG_UI_WIZARD_CREATE_TITLE;
  default:         return SD_MSG_UI_WIZARD_FINISH_TITLE;
  }
}

/* Builds the five page templates. All pages get the height of the tallest one, so the sheet has one size. */
static sd_err build_pages(unsigned char *blob[WIZ_PAGES], size_t len[WIZ_PAGES])
{
  wchar_t face[UI_DLG_FACE_MAX];
  WORD points = 8;
  int dpi = 96, tallest = 0, pg;
  ui_measure m;
  ui_dlg *d[WIZ_PAGES];
  sd_err e = SD_OK;

  memset(blob, 0, sizeof(unsigned char *) * WIZ_PAGES);
  memset(len, 0, sizeof(size_t) * WIZ_PAGES);
  for (pg = 0; pg < WIZ_PAGES; pg++)
    d[pg] = NULL;
  ui_message_font(face, &points, &dpi);
  ui_measure_init(&m, face, points, dpi);
  for (pg = 0; pg < WIZ_PAGES && e == SD_OK; pg++) {
    d[pg] = (ui_dlg *)sd_calloc(1, sizeof(ui_dlg));
    if (d[pg] == NULL) {
      e = SD_E_NO_MEMORY;
      break;
    }
    e = ui_dlg_init(d[pg], sd_l10n_get(page_title(pg)), WIZ_WIDTH, face, points, ui_measure_cb, &m);
    if (e != SD_OK)
      break;
    d[pg]->style = WS_CHILD | DS_CONTROL;
    add_page(d[pg], pg);
    if (d[pg]->cursor + d[pg]->margin > tallest)
      tallest = d[pg]->cursor + d[pg]->margin;
  }
  for (pg = 0; pg < WIZ_PAGES && e == SD_OK; pg++) {
    d[pg]->min_height = tallest;
    e = ui_dlg_build(d[pg], &blob[pg], &len[pg]);
  }
  for (pg = 0; pg < WIZ_PAGES; pg++)
    sd_free(d[pg]);
  ui_measure_free(&m);
  if (e != SD_OK) {
    for (pg = 0; pg < WIZ_PAGES; pg++) {
      sd_free(blob[pg]);
      blob[pg] = NULL;
    }
  }
  return e;
}

static void free_blobs(unsigned char *blob[WIZ_PAGES])
{
  int pg;
  for (pg = 0; pg < WIZ_PAGES; pg++) {
    sd_free(blob[pg]);
    blob[pg] = NULL;
  }
}

/* ---- the pages ---- */

static void set_buttons(HWND page, int pg)
{
  DWORD flags;
  switch (pg) {
  case PG_WELCOME: flags = PSWIZB_NEXT; break;
  case PG_FINISH:  flags = PSWIZB_BACK | PSWIZB_FINISH; break;
  default:         flags = PSWIZB_BACK | PSWIZB_NEXT; break;
  }
  PropSheet_SetWizButtons(GetParent(page), flags);
}

static void do_create(wiz_ctx *ctx, HWND page)
{
  sd_profile p;
  wchar_t name[160];
  wchar_t *text;

  sd_profile_defaults(&p);
  if (!ui_editor_run(ctx->sheet, UI_EDIT_NEW, &p))
    return;
  if (sd_profile_save(&p) != SD_OK) {
    ui_win_task(ctx->sheet, sd_l10n_get(SD_MSG_UI_ERROR_SAVE), NULL, NULL, MB_OK | MB_ICONERROR);
    return;
  }
  /* the agent reads the store again, as after any profile change (03 §2.4) */
  ui_profiles_load();
  ui_ipc_config_reload();
  ctx->created = 1;
  strcpy_s(ctx->created_id, sizeof(ctx->created_id), p.id);
  ui_text_utf8(p.name, name, SD_COUNTOF(name));
  text = ui_format1(SD_MSG_UI_WIZARD_CREATE_SAVED, "name", name);
  if (text != NULL) {
    SetDlgItemTextW(page, WIZ_ID_CREATE_NOTE, text);
    sd_free(text);
  }
  if (ctx->pages[PG_FINISH].hwnd != NULL)
    EnableWindow(GetDlgItem(ctx->pages[PG_FINISH].hwnd, WIZ_ID_MOUNT), TRUE);
}

static INT_PTR CALLBACK wiz_page_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
  switch (msg) {
  case WM_INITDIALOG: {
    const PROPSHEETPAGEW *psp = (const PROPSHEETPAGEW *)lp;
    wiz_page *pg = psp ? (wiz_page *)psp->lParam : NULL;
    if (pg == NULL)
      return FALSE;
    SetWindowLongPtrW(hwnd, DWLP_USER, (LONG_PTR)pg);
    pg->hwnd = hwnd;
    pg->ctx->sheet = GetParent(hwnd);
    if (pg->index == PG_FINISH)
      EnableWindow(GetDlgItem(hwnd, WIZ_ID_MOUNT), FALSE);   /* on once a profile exists */
    /* the page background, its controls and the dark palette (06 §3.6) */
    ui_theme_apply_dialog(hwnd);
    return TRUE;
  }
  case WM_NOTIFY: {
    const NMHDR *nm = (const NMHDR *)lp;
    wiz_page *pg = (wiz_page *)GetWindowLongPtrW(hwnd, DWLP_USER);
    if (pg == NULL)
      break;
    if (nm->code == PSN_SETACTIVE) {
      if (pg->index == PG_FINISH)
        EnableWindow(GetDlgItem(hwnd, WIZ_ID_MOUNT), pg->ctx->created ? TRUE : FALSE);
      set_buttons(hwnd, pg->index);
      SetWindowLongPtrW(hwnd, DWLP_MSGRESULT, 0);
      return TRUE;
    }
    if (nm->code == PSN_WIZFINISH && pg->index == PG_FINISH) {
      pg->ctx->mount_now = pg->ctx->created && IsDlgButtonChecked(hwnd, WIZ_ID_MOUNT) == BST_CHECKED;
      SetWindowLongPtrW(hwnd, DWLP_MSGRESULT, 0);
      return TRUE;
    }
    break;
  }
  case WM_COMMAND: {
    WORD id = LOWORD(wp), code = HIWORD(wp);
    wiz_page *pg = (wiz_page *)GetWindowLongPtrW(hwnd, DWLP_USER);
    if (pg == NULL || code != BN_CLICKED)
      break;
    if (id == WIZ_ID_IMPORT) {
      ui_import_run(pg->ctx->sheet);
      return TRUE;
    }
    if (id == WIZ_ID_CREATE) {
      do_create(pg->ctx, hwnd);
      return TRUE;
    }
    break;
  }
  default:
    break;
  }
  return FALSE;
}

/* ---- the sheet ---- */

void ui_wizard_run(HWND owner)
{
  wiz_ctx ctx;
  unsigned char *blob[WIZ_PAGES];
  size_t len[WIZ_PAGES];
  PROPSHEETPAGEW psp[WIZ_PAGES];
  PROPSHEETHEADERW hdr;
  int pg;
  /* Vista and later: the Aero wizard (06 §6.5); XP keeps Wizard97 */
  int aero = ui_theme_current() != NULL && ui_theme_current()->aero_wizard;

  memset(&ctx, 0, sizeof(ctx));
  for (pg = 0; pg < WIZ_PAGES; pg++) {
    ctx.pages[pg].ctx = &ctx;
    ctx.pages[pg].index = pg;
  }
  if (build_pages(blob, len) != SD_OK)
    return;
  for (pg = 0; pg < WIZ_PAGES; pg++) {
    memset(&psp[pg], 0, sizeof(psp[pg]));
    psp[pg].dwSize = sizeof(psp[pg]);
    psp[pg].dwFlags = PSP_DLGINDIRECT | PSP_USETITLE;
    psp[pg].hInstance = g_app.inst;
    psp[pg].pResource = (LPCDLGTEMPLATEW)blob[pg];
    psp[pg].pfnDlgProc = wiz_page_proc;
    psp[pg].pszTitle = sd_l10n_get(page_title(pg));
    if (aero) {
      /* the page title goes in the header of the Aero wizard */
      psp[pg].dwFlags |= PSP_USEHEADERTITLE;
      psp[pg].pszHeaderTitle = sd_l10n_get(page_title(pg));
    }
    psp[pg].lParam = (LPARAM)&ctx.pages[pg];
  }
  memset(&hdr, 0, sizeof(hdr));
  hdr.dwSize = sizeof(hdr);
  /* PSH_HEADER, PSH_WATERMARK and their bitmaps are Wizard97 only: never set with PSH_AEROWIZARD */
  hdr.dwFlags = (aero ? PSH_AEROWIZARD : PSH_WIZARD97) | PSH_PROPSHEETPAGE | PSH_NOAPPLYNOW | PSH_NOCONTEXTHELP | PSH_USECALLBACK;
  hdr.pfnCallback = ui_theme_sheet_callback;
  hdr.hwndParent = owner;
  hdr.hInstance = g_app.inst;
  hdr.pszCaption = sd_l10n_get(SD_MSG_UI_WIZARD_CAPTION);
  hdr.nPages = WIZ_PAGES;
  hdr.nStartPage = 0;
  hdr.ppsp = psp;
  PropertySheetW(&hdr);
  free_blobs(blob);

  /* Finish and Cancel both count: the wizard is not shown again (03 §7.5) */
  ui_wizard_mark_done();
  if (ctx.mount_now && ctx.created)
    ui_ipc_mount(ctx.created_id);
}

void ui_wizard_run_if_needed(HWND owner, int tray_mode, int prompt_host)
{
  int done = ui_wizard_first_run_done();
  if (!ui_wizard_should_show(ui_profiles_count(), done, tray_mode, prompt_host))
    return;
  ui_wizard_run(owner);
}

/* ---- smoke test (--test-wizard) ---- */

int ui_wizard_smoke_test(void)
{
  unsigned char *blob[WIZ_PAGES];
  size_t len[WIZ_PAGES];
  wiz_ctx ctx;
  HWND parent;
  int pg, ok = 1;

  memset(&ctx, 0, sizeof(ctx));
  parent = CreateWindowExW(0, L"STATIC", L"", WS_POPUP, 0, 0, 10, 10, NULL, NULL, g_app.inst, NULL);
  if (parent == NULL)
    return 0;
  for (pg = 0; pg < WIZ_PAGES; pg++) {
    ctx.pages[pg].ctx = &ctx;
    ctx.pages[pg].index = pg;
  }
  if (build_pages(blob, len) != SD_OK) {
    DestroyWindow(parent);
    return 0;
  }
  for (pg = 0; pg < WIZ_PAGES && ok; pg++) {
    PROPSHEETPAGEW psp;
    HWND page;
    memset(&psp, 0, sizeof(psp));
    psp.dwSize = sizeof(psp);
    psp.lParam = (LPARAM)&ctx.pages[pg];
    page = CreateDialogIndirectParamW(g_app.inst, (LPCDLGTEMPLATEW)blob[pg], parent, wiz_page_proc, (LPARAM)&psp);
    if (page == NULL || !IsWindow(page) || ctx.pages[pg].hwnd != page)
      ok = 0;
    if (page != NULL)
      DestroyWindow(page);
    ctx.pages[pg].hwnd = NULL;
  }
  free_blobs(blob);
  DestroyWindow(parent);
  return ok;
}
