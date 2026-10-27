/* shelldrive-ui: the profile editor, the ad-hoc mount dialog and the confirmation dialog (03 §7.1, §7.5).
 *
 * The editor is a property sheet (PropertySheetW, PSP_DLGINDIRECT pages, 03 §7.1) with five pages: General,
 * Authentication, Connection, Mount and Security. The pages are built in memory with ui_dlg (the generator the
 * prompt dialogs use), so every label is measured and nothing is clipped in German or French. Every page is
 * created up front (PSP_PREMATURE), so all of them can be read when the sheet is confirmed.
 *
 * Values travel as text through the pure model (ui_profile_model.h): ui_pform_get fills a control and
 * ui_pform_set reads it back into the working copy. The tables k_pages say which field lives in which control;
 * a control missing from a page (the name in ad-hoc mode) is skipped. Validation runs on every OK: the errors
 * of each page are shown on that page, and the first page with an error is brought to the front.
 *
 * Ad-hoc mount (UI_EDIT_ADHOC): the same pages without the name; the caller sends the connection to the agent
 * (ui_mount_params_json). A drop-down list grows while it is open (combo_drop): the template height of a combo
 * box is its closed height. */
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <prsht.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

#include "sd_base/sd_mem.h"
#include "sd_l10n/sd_l10n.h"
#include "sd_l10n_ui_ids.h"
#include "ui_dlg.h"
#include "ui_int.h"
#include "ui_measure.h"
#include "ui_profile_model.h"

#define ED_WIDTH      300                 /* dialog units; every page of the sheet has this width */
#define ED_PAGES      5
#define ED_ERR_LINES  3                   /* lines of the error box of a page */
#define ED_CTL(f)     (1000 + (int)(f))   /* control id of a field (edit, check box or combo box) */
#define ED_LBL(f)     (2000 + (int)(f))   /* static label of a field */
#define ED_ID_BROWSE  1500
#define ED_ID_ERR     1501
#define ED_ID_INTRO   1502
#define ED_ID_LEGACY  1503
#define ED_ERR_CHARS  1024                /* wide characters of the error text of one page */

enum { PG_GENERAL = 0, PG_AUTH, PG_CONN, PG_MOUNT, PG_SECURITY };

typedef enum ctl_kind { K_EDIT = 0, K_CHECK, K_ENUM, K_TARGET } ctl_kind;

/* A value list of a combo box: the stored values in display order, and the catalog label of each. */
typedef struct ed_enum {
  ui_pfield f;
  int n;
  const int *values;
  const sd_msg_id *labels;          /* NULL: the number itself is shown */
} ed_enum;

typedef struct ctl_desc {
  ui_pfield f;
  ctl_kind kind;
  const ed_enum *en;
} ctl_desc;

typedef struct ed_ctx ed_ctx;

typedef struct ed_page {
  ed_ctx *ed;
  int index;
  HWND hwnd;                        /* set by WM_INITDIALOG */
} ed_page;

struct ed_ctx {
  sd_profile work;                  /* the working copy; the caller's profile is replaced on OK */
  ui_edit_mode mode;
  ed_page pages[ED_PAGES];
  wchar_t drives[UI_DRIVE_CANDIDATES][3];
  size_t ndrives;
  wchar_t target_vals[UI_DRIVE_CANDIDATES + 2][8];   /* data of the target box: "auto", "X:" */
  const wchar_t *target_items[UI_DRIVE_CANDIDATES + 2];
  size_t ntarget;
  ui_pferr parse_errs[UI_PF_COUNT];  /* values that did not parse on the last read */
  size_t nparse;
};

/* ---- value lists (the stored values of each combo box, in display order) ---- */

static const int k_agent_v[] = { SD_PROFILE_AGENT_AUTO, SD_PROFILE_AGENT_PAGEANT, SD_PROFILE_AGENT_OPENSSH, SD_PROFILE_AGENT_NONE };
static const sd_msg_id k_agent_l[] = { SD_MSG_UI_AGENT_AUTO, SD_MSG_UI_AGENT_PAGEANT, SD_MSG_UI_AGENT_OPENSSH, SD_MSG_UI_AGENT_NONE };
static const ed_enum k_agent = { UI_PF_AGENT, 4, k_agent_v, k_agent_l };

static const int k_idonly_v[] = { SD_PROFILE_UNSET, 1, 0 };
static const sd_msg_id k_idonly_l[] = { SD_MSG_UI_IDONLY_UNSET, SD_MSG_UI_IDONLY_YES, SD_MSG_UI_IDONLY_NO };
static const ed_enum k_idonly = { UI_PF_IDENTITIES_ONLY, 3, k_idonly_v, k_idonly_l };

static const int k_proxy_v[] = { SD_PROFILE_PROXY_NONE, SD_PROFILE_PROXY_HTTP, SD_PROFILE_PROXY_SOCKS5, SD_PROFILE_PROXY_SYSTEM };
static const sd_msg_id k_proxy_l[] = { SD_MSG_UI_PROXY_NONE, SD_MSG_UI_PROXY_HTTP, SD_MSG_UI_PROXY_SOCKS5, SD_MSG_UI_PROXY_SYSTEM };
static const ed_enum k_proxy = { UI_PF_PROXY_KIND, 4, k_proxy_v, k_proxy_l };

static const int k_pauth_v[] = { SD_PROFILE_PROXY_AUTH_AUTO, SD_PROFILE_PROXY_AUTH_BASIC, SD_PROFILE_PROXY_AUTH_NEGOTIATE, SD_PROFILE_PROXY_AUTH_NONE };
static const sd_msg_id k_pauth_l[] = { SD_MSG_UI_PAUTH_AUTO, SD_MSG_UI_PAUTH_BASIC, SD_MSG_UI_PAUTH_NEGOTIATE, SD_MSG_UI_PAUTH_NONE };
static const ed_enum k_pauth = { UI_PF_PROXY_AUTH, 4, k_pauth_v, k_pauth_l };

static const int k_conn_v[] = { 1, 2, 3, 4 };
static const ed_enum k_conn = { UI_PF_CONNECTIONS, 4, k_conn_v, NULL };

static const int k_backend_v[] = { SD_PROFILE_BACKEND_AUTO, SD_PROFILE_BACKEND_DOKANY, SD_PROFILE_BACKEND_WEBDAV };
static const sd_msg_id k_backend_l[] = { SD_MSG_UI_BACKEND_AUTO, SD_MSG_UI_BACKEND_DOKANY, SD_MSG_UI_BACKEND_WEBDAV };
static const ed_enum k_backend = { UI_PF_BACKEND, 3, k_backend_v, k_backend_l };

static const int k_write_v[] = { SD_PROFILE_WRITE_THROUGH, SD_PROFILE_WRITE_BEHIND };
static const sd_msg_id k_write_l[] = { SD_MSG_UI_WRITE_THROUGH, SD_MSG_UI_WRITE_BEHIND };
static const ed_enum k_write = { UI_PF_WRITE_MODE, 2, k_write_v, k_write_l };

static const int k_symlinks_v[] = { SD_PROFILE_SYMLINKS_FOLLOW_INSIDE, SD_PROFILE_SYMLINKS_FOLLOW, SD_PROFILE_SYMLINKS_HIDE };
static const sd_msg_id k_symlinks_l[] = { SD_MSG_UI_SYMLINKS_INSIDE, SD_MSG_UI_SYMLINKS_FOLLOW, SD_MSG_UI_SYMLINKS_HIDE };
static const ed_enum k_symlinks = { UI_PF_SYMLINKS, 3, k_symlinks_v, k_symlinks_l };

static const int k_legacy_v[] = { SD_PROFILE_LEGACY_ALLOW, SD_PROFILE_LEGACY_WARN, SD_PROFILE_LEGACY_ASK, SD_PROFILE_LEGACY_REFUSE };
static const sd_msg_id k_legacy_l[] = { SD_MSG_UI_LEGACY_ALLOW, SD_MSG_UI_LEGACY_WARN, SD_MSG_UI_LEGACY_ASK, SD_MSG_UI_LEGACY_REFUSE };
static const ed_enum k_legacy = { UI_PF_LEGACY, 4, k_legacy_v, k_legacy_l };

static const int k_hku_v[] = { SD_PROFILE_HKU_ASK, SD_PROFILE_HKU_YES, SD_PROFILE_HKU_NO };
static const sd_msg_id k_hku_l[] = { SD_MSG_UI_HKU_ASK, SD_MSG_UI_HKU_SAVE, SD_MSG_UI_HKU_IGNORE };
static const ed_enum k_hku = { UI_PF_UPDATE_HOST_KEYS, 3, k_hku_v, k_hku_l };

/* ---- which control holds which field, per page ---- */

static const ctl_desc k_general[] = {
  { UI_PF_NAME, K_EDIT, NULL }, { UI_PF_HOST, K_EDIT, NULL }, { UI_PF_PORT, K_EDIT, NULL },
  { UI_PF_USER, K_EDIT, NULL }, { UI_PF_REMOTE_PATH, K_EDIT, NULL },
};
static const ctl_desc k_auth[] = {
  { UI_PF_METHOD_PUBLICKEY, K_CHECK, NULL }, { UI_PF_METHOD_KBDINT, K_CHECK, NULL },
  { UI_PF_METHOD_PASSWORD, K_CHECK, NULL }, { UI_PF_IDENTITY, K_EDIT, NULL },
  { UI_PF_CERTIFICATE, K_EDIT, NULL }, { UI_PF_AGENT, K_ENUM, &k_agent },
  { UI_PF_IDENTITIES_ONLY, K_ENUM, &k_idonly }, { UI_PF_SAVE_PASSWORD, K_CHECK, NULL },
  { UI_PF_CACHE_SECRETS, K_CHECK, NULL },
};
static const ctl_desc k_conn_page[] = {
  { UI_PF_JUMP, K_EDIT, NULL }, { UI_PF_PROXY_KIND, K_ENUM, &k_proxy }, { UI_PF_PROXY_HOST, K_EDIT, NULL },
  { UI_PF_PROXY_PORT, K_EDIT, NULL }, { UI_PF_PROXY_USER, K_EDIT, NULL }, { UI_PF_PROXY_AUTH, K_ENUM, &k_pauth },
  { UI_PF_CONNECTIONS, K_ENUM, &k_conn }, { UI_PF_KEEPALIVE, K_EDIT, NULL },
  { UI_PF_CONNECT_TIMEOUT, K_EDIT, NULL },
};
static const ctl_desc k_mount[] = {
  { UI_PF_TARGET, K_TARGET, NULL }, { UI_PF_BACKEND, K_ENUM, &k_backend }, { UI_PF_READ_ONLY, K_CHECK, NULL },
  { UI_PF_WRITE_MODE, K_ENUM, &k_write }, { UI_PF_SYMLINKS, K_ENUM, &k_symlinks }, { UI_PF_LABEL, K_EDIT, NULL },
  { UI_PF_OFFLINE_WAIT, K_EDIT, NULL }, { UI_PF_NETWORK_LOCATION, K_CHECK, NULL },
  { UI_PF_DISK_CACHE, K_EDIT, NULL },
};
static const ctl_desc k_security[] = {
  { UI_PF_LEGACY, K_ENUM, &k_legacy }, { UI_PF_HOST_KEY_ALIAS, K_EDIT, NULL },
  { UI_PF_UPDATE_HOST_KEYS, K_ENUM, &k_hku }, { UI_PF_REFUSE_TERRAPIN, K_CHECK, NULL },
};

static const struct { const ctl_desc *d; size_t n; } k_pages[ED_PAGES] = {
  { k_general, SD_COUNTOF(k_general) }, { k_auth, SD_COUNTOF(k_auth) }, { k_conn_page, SD_COUNTOF(k_conn_page) },
  { k_mount, SD_COUNTOF(k_mount) }, { k_security, SD_COUNTOF(k_security) },
};

/* The page that shows the error of a field; general errors and fields without a page go to General. */
static int page_of(int f)
{
  switch (f) {
  case UI_PF_METHOD_PUBLICKEY: case UI_PF_METHOD_KBDINT: case UI_PF_METHOD_PASSWORD: case UI_PF_IDENTITY:
  case UI_PF_CERTIFICATE: case UI_PF_AGENT: case UI_PF_IDENTITIES_ONLY: case UI_PF_SAVE_PASSWORD:
  case UI_PF_CACHE_SECRETS:
    return PG_AUTH;
  case UI_PF_JUMP: case UI_PF_PROXY_KIND: case UI_PF_PROXY_HOST: case UI_PF_PROXY_PORT: case UI_PF_PROXY_USER:
  case UI_PF_PROXY_AUTH: case UI_PF_CONNECTIONS: case UI_PF_KEEPALIVE: case UI_PF_CONNECT_TIMEOUT:
    return PG_CONN;
  case UI_PF_TARGET: case UI_PF_BACKEND: case UI_PF_READ_ONLY: case UI_PF_WRITE_MODE: case UI_PF_SYMLINKS:
  case UI_PF_LABEL: case UI_PF_OFFLINE_WAIT: case UI_PF_NETWORK_LOCATION: case UI_PF_DISK_CACHE:
    return PG_MOUNT;
  case UI_PF_LEGACY: case UI_PF_HOST_KEY_ALIAS: case UI_PF_UPDATE_HOST_KEYS: case UI_PF_REFUSE_TERRAPIN:
    return PG_SECURITY;
  default:
    return PG_GENERAL;
  }
}

/* ---- text conversion ---- */

static wchar_t *to_wide(const char *s)
{
  int n;
  wchar_t *w;
  if (s == NULL)
    s = "";
  n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
  if (n <= 0)
    return NULL;
  w = (wchar_t *)sd_alloc((size_t)n * sizeof(wchar_t));
  if (w != NULL && MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n) == 0) {
    sd_free(w);
    return NULL;
  }
  return w;
}

/* UTF-8 text of a control. SD_E_INVALID_PARAM when it does not fit in cap. */
static sd_err get_text(HWND ctl, char *out, size_t cap)
{
  int n = GetWindowTextLengthW(ctl);
  wchar_t *w;
  int k, u;
  if (n < 0)
    return SD_E_INVALID_PARAM;
  w = (wchar_t *)sd_alloc((size_t)n * sizeof(wchar_t) + sizeof(wchar_t));
  if (w == NULL)
    return SD_E_NO_MEMORY;
  k = GetWindowTextW(ctl, w, n + 1);
  if (k < 0)
    k = 0;
  w[k] = 0;
  u = WideCharToMultiByte(CP_UTF8, 0, w, -1, out, (int)cap, NULL, NULL);
  sd_free(w);
  return u > 0 ? SD_OK : SD_E_INVALID_PARAM;
}

static void set_text(HWND ctl, const char *utf8)
{
  wchar_t *w = to_wide(utf8);
  if (w != NULL) {
    SetWindowTextW(ctl, w);
    sd_free(w);
  }
}

/* ---- drop-down lists ---- */

/* The closed height of a combo box is kept in a window property. While the list is open the box is as tall as
   the list (up to 10 items), so the list is not clipped by its own box. */
static void combo_drop(HWND combo, int open)
{
  RECT rc;
  POINT pt;
  HWND parent = GetParent(combo);
  int closed = (int)(INT_PTR)GetPropW(combo, L"sd.closed");
  int items = (int)SendMessageW(combo, CB_GETCOUNT, 0, 0);
  int ih = (int)SendMessageW(combo, CB_GETITEMHEIGHT, 0, 0);
  int h = closed, k;
  if (closed <= 0 || parent == NULL || ih <= 0)
    return;
  if (open) {
    k = items < 1 ? 1 : (items > 10 ? 10 : items);
    h = closed + k * ih + 4;
  }
  GetWindowRect(combo, &rc);
  pt.x = rc.left;
  pt.y = rc.top;
  ScreenToClient(parent, &pt);
  SetWindowPos(combo, NULL, pt.x, pt.y, rc.right - rc.left, h, SWP_NOZORDER | SWP_NOACTIVATE);
}

static void remember_closed_height(HWND combo)
{
  RECT rc;
  if (GetWindowRect(combo, &rc))
    SetPropW(combo, L"sd.closed", (HANDLE)(INT_PTR)(rc.bottom - rc.top));
}

static void fill_enum(HWND combo, const ed_enum *en, long want)
{
  int i, sel = 0;
  SendMessageW(combo, CB_RESETCONTENT, 0, 0);
  for (i = 0; i < en->n; i++) {
    if (en->labels != NULL) {
      SendMessageW(combo, CB_ADDSTRING, 0, (LPARAM)sd_l10n_get(en->labels[i]));
    } else {
      wchar_t num[16];
      wsprintfW(num, L"%d", en->values[i]);
      SendMessageW(combo, CB_ADDSTRING, 0, (LPARAM)num);
    }
    if ((long)en->values[i] == want)
      sel = i;
  }
  SendMessageW(combo, CB_SETCURSEL, (WPARAM)sel, 0);
}

static int enum_value(HWND combo, const ed_enum *en, int *out)
{
  int sel = (int)SendMessageW(combo, CB_GETCURSEL, 0, 0);
  if (sel < 0 || sel >= en->n)
    return 0;
  *out = en->values[sel];
  return 1;
}

/* ---- target (drive letter) list: "auto", the free letters, and the current target when it is not free ---- */

static void fill_target(ed_ctx *ed, HWND combo)
{
  size_t i;
  char cur[16];
  int sel = 0;
  SendMessageW(combo, CB_RESETCONTENT, 0, 0);
  ed->ntarget = 0;
  wcscpy_s(ed->target_vals[0], SD_COUNTOF(ed->target_vals[0]), L"auto");
  ed->target_items[0] = ed->target_vals[0];
  ed->ntarget = 1;
  for (i = 0; i < ed->ndrives && ed->ntarget < SD_COUNTOF(ed->target_vals); i++) {
    wcscpy_s(ed->target_vals[ed->ntarget], SD_COUNTOF(ed->target_vals[0]), ed->drives[i]);
    ed->target_items[ed->ntarget] = ed->target_vals[ed->ntarget];
    ed->ntarget++;
  }
  if (ui_pform_get(&ed->work, UI_PF_TARGET, cur, sizeof(cur)) != SD_OK)
    strcpy_s(cur, sizeof(cur), "auto");
  if (strcmp(cur, "auto") != 0) {
    int found = 0;
    for (i = 1; i < ed->ntarget; i++) {
      char one[16];
      if (WideCharToMultiByte(CP_UTF8, 0, ed->target_items[i], -1, one, sizeof(one), NULL, NULL) > 0 &&
          strcmp(one, cur) == 0) {
        found = 1;
        break;
      }
    }
    if (!found && ed->ntarget < SD_COUNTOF(ed->target_vals)) {
      wchar_t *w = to_wide(cur);
      if (w != NULL) {
        wcsncpy_s(ed->target_vals[ed->ntarget], SD_COUNTOF(ed->target_vals[0]), w, _TRUNCATE);
        ed->target_items[ed->ntarget] = ed->target_vals[ed->ntarget];
        ed->ntarget++;
        sd_free(w);
      }
    }
  }
  for (i = 0; i < ed->ntarget; i++) {
    const wchar_t *label = i == 0 ? sd_l10n_get(SD_MSG_UI_TARGET_AUTO) : ed->target_items[i];
    int k = (int)SendMessageW(combo, CB_ADDSTRING, 0, (LPARAM)label);
    SendMessageW(combo, CB_SETITEMDATA, (WPARAM)k, (LPARAM)ed->target_items[i]);
    if (i > 0 && WideCharToMultiByte(CP_UTF8, 0, ed->target_items[i], -1, NULL, 0, NULL, NULL) > 0) {
      char one[16];
      if (WideCharToMultiByte(CP_UTF8, 0, ed->target_items[i], -1, one, sizeof(one), NULL, NULL) > 0 &&
          strcmp(one, cur) == 0)
        sel = k;
    }
  }
  SendMessageW(combo, CB_SETCURSEL, (WPARAM)sel, 0);
}

/* ---- reading and writing the pages ---- */

static void write_page(ed_ctx *ed, int pg, HWND page)
{
  size_t i;
  const ctl_desc *d = k_pages[pg].d;
  for (i = 0; i < k_pages[pg].n; i++) {
    HWND c = GetDlgItem(page, ED_CTL(d[i].f));
    char text[UI_PF_TEXT_MAX];
    if (c == NULL)
      continue;
    switch (d[i].kind) {
    case K_EDIT:
      if (ui_pform_get(&ed->work, d[i].f, text, sizeof(text)) == SD_OK)
        set_text(c, text);
      break;
    case K_CHECK:
      if (ui_pform_get(&ed->work, d[i].f, text, sizeof(text)) == SD_OK)
        SendMessageW(c, BM_SETCHECK, atoi(text) ? BST_CHECKED : BST_UNCHECKED, 0);
      break;
    case K_ENUM:
      if (ui_pform_get(&ed->work, d[i].f, text, sizeof(text)) == SD_OK)
        fill_enum(c, d[i].en, atol(text));
      remember_closed_height(c);
      break;
    case K_TARGET:
      fill_target(ed, c);
      remember_closed_height(c);
      break;
    }
  }
}

/* Reads the controls of one page into the working copy. A value that does not parse is recorded. */
static void read_page(ed_ctx *ed, int pg, HWND page)
{
  size_t i;
  const ctl_desc *d = k_pages[pg].d;
  if (page == NULL)
    return;
  for (i = 0; i < k_pages[pg].n; i++) {
    HWND c = GetDlgItem(page, ED_CTL(d[i].f));
    char text[UI_PF_TEXT_MAX];
    int value = 0;
    sd_err e = SD_OK;
    if (c == NULL)
      continue;
    switch (d[i].kind) {
    case K_EDIT:
      e = get_text(c, text, sizeof(text));
      if (e == SD_OK)
        e = ui_pform_set(&ed->work, d[i].f, text);
      break;
    case K_CHECK:
      sprintf_s(text, sizeof(text), "%d", SendMessageW(c, BM_GETCHECK, 0, 0) == BST_CHECKED ? 1 : 0);
      e = ui_pform_set(&ed->work, d[i].f, text);
      break;
    case K_ENUM:
      if (!enum_value(c, d[i].en, &value)) {
        e = SD_E_INVALID_PARAM;
      } else {
        sprintf_s(text, sizeof(text), "%d", value);
        e = ui_pform_set(&ed->work, d[i].f, text);
      }
      break;
    case K_TARGET: {
      int sel = (int)SendMessageW(c, CB_GETCURSEL, 0, 0);
      const wchar_t *v = sel >= 0 ? (const wchar_t *)SendMessageW(c, CB_GETITEMDATA, (WPARAM)sel, 0) : NULL;
      char narrow[16];
      if (v == NULL || WideCharToMultiByte(CP_UTF8, 0, v, -1, narrow, sizeof(narrow), NULL, NULL) == 0)
        e = SD_E_INVALID_PARAM;
      else
        e = ui_pform_set(&ed->work, d[i].f, narrow);
      break;
    }
    }
    if (e != SD_OK && ed->nparse < SD_COUNTOF(ed->parse_errs)) {
      ed->parse_errs[ed->nparse].field = (int)d[i].f;
      if (d[i].kind == K_EDIT && ui_pform_is_text(d[i].f))
        ed->parse_errs[ed->nparse].code = UI_PERR_OTHER;
      else if (d[i].f == UI_PF_PORT || d[i].f == UI_PF_PROXY_PORT)
        ed->parse_errs[ed->nparse].code = UI_PERR_PORT;
      else
        ed->parse_errs[ed->nparse].code = UI_PERR_NUMBER;
      ed->nparse++;
    }
  }
}

/* ---- validation messages ---- */

static sd_msg_id err_message(ui_perr code)
{
  switch (code) {
  case UI_PERR_NAME:        return SD_MSG_UI_ERROR_NAME;
  case UI_PERR_HOST:        return SD_MSG_UI_ERROR_HOST;
  case UI_PERR_PORT:        return SD_MSG_UI_ERROR_PORT;
  case UI_PERR_NUMBER:      return SD_MSG_UI_ERROR_NUMBER;
  case UI_PERR_CONNECTIONS: return SD_MSG_UI_ERROR_CONNECTIONS;
  case UI_PERR_METHODS:     return SD_MSG_UI_ERROR_METHODS;
  case UI_PERR_PROXY_HOST:  return SD_MSG_UI_ERROR_PROXY_HOST;
  case UI_PERR_PROXY_PORT:  return SD_MSG_UI_ERROR_PROXY_PORT;
  default:                  return SD_MSG_UI_ERROR_OTHER;
  }
}

/* Shows the error lines on every page: each page lists the errors of its own fields. */
static void show_errors(ed_ctx *ed, const ui_pferr *errs, size_t n)
{
  wchar_t *text[ED_PAGES];
  size_t used[ED_PAGES];
  size_t pg, i;
  for (pg = 0; pg < ED_PAGES; pg++) {
    text[pg] = (wchar_t *)sd_calloc(ED_ERR_CHARS, sizeof(wchar_t));
    used[pg] = 0;
  }
  for (i = 0; i < n; i++) {
    int pgi = page_of(errs[i].field);
    const wchar_t *msg = sd_l10n_get(err_message(errs[i].code));
    size_t add = wcslen(msg);
    if (text[pgi] == NULL || used[pgi] + add + 2 >= ED_ERR_CHARS)
      continue;
    if (used[pgi] > 0) {
      wcscat_s(text[pgi], ED_ERR_CHARS, L"\r\n");
      used[pgi] += 2;
    }
    wcscat_s(text[pgi], ED_ERR_CHARS, msg);
    used[pgi] += add;
  }
  for (pg = 0; pg < ED_PAGES; pg++) {
    HWND err = ed->pages[pg].hwnd ? GetDlgItem(ed->pages[pg].hwnd, ED_ID_ERR) : NULL;
    if (err != NULL)
      SetWindowTextW(err, text[pg] ? text[pg] : L"");
    sd_free(text[pg]);
  }
}

/* Reads every page, validates the whole profile and shows the errors. Returns the number of errors; the
   working copy holds what the controls say. */
static size_t apply_all(ed_ctx *ed, ui_pferr *errs, size_t cap)
{
  ui_pferr all[UI_PF_COUNT + 24];
  size_t pg, i, total = 0, n;
  ed->nparse = 0;
  for (pg = 0; pg < ED_PAGES; pg++)
    read_page(ed, (int)pg, ed->pages[pg].hwnd);
  if (ed->mode == UI_EDIT_ADHOC)
    strcpy_s(ed->work.name, sizeof(ed->work.name), ed->work.host);   /* the ad-hoc connection is named by its server */
  for (i = 0; i < ed->nparse && total < SD_COUNTOF(all); i++)
    all[total++] = ed->parse_errs[i];
  n = ui_pform_validate(&ed->work, all + total, SD_COUNTOF(all) - total);
  total += n;
  if (total > SD_COUNTOF(all))
    total = SD_COUNTOF(all);
  if (errs != NULL)
    for (i = 0; i < total && i < cap; i++)
      errs[i] = all[i];
  show_errors(ed, all, total);
  return total;
}

/* ---- the Browse button of the key file ---- */

static void browse_identity(ed_ctx *ed, HWND page)
{
  wchar_t path[MAX_PATH * 3];
  wchar_t filter[64];
  OPENFILENAMEW ofn;
  HWND edit = GetDlgItem(page, ED_CTL(UI_PF_IDENTITY));
  size_t n;
  (void)ed;
  if (edit == NULL)
    return;
  GetWindowTextW(edit, path, SD_COUNTOF(path));
  memset(filter, 0, sizeof(filter));
  wcscpy_s(filter, SD_COUNTOF(filter), sd_l10n_get(SD_MSG_UI_FILE_ANY));
  n = wcslen(filter);
  wcscpy_s(filter + n + 1, SD_COUNTOF(filter) - n - 1, L"*.*");
  memset(&ofn, 0, sizeof(ofn));
  ofn.lStructSize = sizeof(ofn);
  ofn.hwndOwner = page;
  ofn.lpstrFilter = filter;
  ofn.lpstrFile = path;
  ofn.nMaxFile = SD_COUNTOF(path);
  ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
  if (GetOpenFileNameW(&ofn))
    SetWindowTextW(edit, path);
}

/* ---- the page procedure ---- */

static INT_PTR CALLBACK page_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
  switch (msg) {
  case WM_INITDIALOG: {
    const PROPSHEETPAGEW *psp = (const PROPSHEETPAGEW *)lp;
    ed_page *pg = psp ? (ed_page *)psp->lParam : NULL;
    if (pg == NULL)
      return FALSE;
    SetWindowLongPtrW(hwnd, DWLP_USER, (LONG_PTR)pg);
    pg->hwnd = hwnd;
    write_page(pg->ed, pg->index, hwnd);
    return TRUE;
  }
  case WM_NOTIFY: {
    const NMHDR *nm = (const NMHDR *)lp;
    ed_page *pg = (ed_page *)GetWindowLongPtrW(hwnd, DWLP_USER);
    if (pg == NULL)
      break;
    if (nm->code == PSN_KILLACTIVE) {
      SetWindowLongPtrW(hwnd, DWLP_MSGRESULT, FALSE);
      return TRUE;
    }
    if (nm->code == PSN_APPLY) {
      /* every page reads its controls and validates the whole profile; this page refuses the OK when one of its
         own fields has an error, which also brings it to the front */
      ui_pferr errs[UI_PF_COUNT + 24];
      size_t i, total = apply_all(pg->ed, errs, SD_COUNTOF(errs));
      int mine = 0;
      for (i = 0; i < total && i < SD_COUNTOF(errs); i++)
        if (page_of(errs[i].field) == pg->index)
          mine = 1;
      SetWindowLongPtrW(hwnd, DWLP_MSGRESULT, mine ? PSNRET_INVALID : PSNRET_NOERROR);
      return TRUE;
    }
    break;
  }
  case WM_COMMAND: {
    WORD id = LOWORD(wp), code = HIWORD(wp);
    ed_page *pg = (ed_page *)GetWindowLongPtrW(hwnd, DWLP_USER);
    if (pg == NULL)
      break;
    if (id == ED_ID_BROWSE && code == BN_CLICKED) {
      browse_identity(pg->ed, hwnd);
      return TRUE;
    }
    if (code == CBN_DROPDOWN || code == CBN_CLOSEUP) {
      combo_drop((HWND)lp, code == CBN_DROPDOWN);
      return TRUE;
    }
    break;
  }
  default:
    break;
  }
  return FALSE;
}

/* ---- page templates ---- */

static void add_label(ui_dlg *d, ui_pfield f, sd_msg_id msg)
{
  ui_dlg_text(d, (WORD)ED_LBL(f), sd_l10n_get(msg), 0);
}

static void add_edit(ui_dlg *d, ui_pfield f, sd_msg_id msg, DWORD extra)
{
  add_label(d, f, msg);
  ui_dlg_edit(d, (WORD)ED_CTL(f), extra);
}

static void add_enum(ui_dlg *d, ui_pfield f, sd_msg_id msg)
{
  add_label(d, f, msg);
  ui_dlg_combo(d, (WORD)ED_CTL(f));
}

static void add_check(ui_dlg *d, ui_pfield f, sd_msg_id msg)
{
  ui_dlg_check(d, (WORD)ED_CTL(f), sd_l10n_get(msg));
}

static void add_errors(ui_dlg *d)
{
  ui_dlg_multiline(d, ED_ID_ERR, L"", ED_ERR_LINES);
}

static void add_page_general(ui_dlg *d, ed_ctx *ed)
{
  ui_dlg_text(d, ED_ID_INTRO, sd_l10n_get(SD_MSG_UI_GENERAL_INTRO), 0);
  if (ed->mode != UI_EDIT_ADHOC)
    add_edit(d, UI_PF_NAME, SD_MSG_UI_GENERAL_NAME, 0);
  add_edit(d, UI_PF_HOST, SD_MSG_UI_GENERAL_HOST, 0);
  add_edit(d, UI_PF_PORT, SD_MSG_UI_GENERAL_PORT, ES_NUMBER);
  add_edit(d, UI_PF_USER, SD_MSG_UI_GENERAL_USER, 0);
  add_edit(d, UI_PF_REMOTE_PATH, SD_MSG_UI_GENERAL_REMOTE_PATH, 0);
  add_errors(d);
}

static void add_page_auth(ui_dlg *d)
{
  static const WORD ids[] = { ED_ID_BROWSE };
  const wchar_t *texts[1];
  add_check(d, UI_PF_METHOD_PUBLICKEY, SD_MSG_UI_AUTH_METHOD_PUBLICKEY);
  add_check(d, UI_PF_METHOD_KBDINT, SD_MSG_UI_AUTH_METHOD_KBDINT);
  add_check(d, UI_PF_METHOD_PASSWORD, SD_MSG_UI_AUTH_METHOD_PASSWORD);
  add_edit(d, UI_PF_IDENTITY, SD_MSG_UI_AUTH_IDENTITY, 0);
  texts[0] = sd_l10n_get(SD_MSG_UI_AUTH_BROWSE);
  ui_dlg_buttons(d, ids, texts, 1, 0);
  add_edit(d, UI_PF_CERTIFICATE, SD_MSG_UI_AUTH_CERTIFICATE, 0);
  add_enum(d, UI_PF_AGENT, SD_MSG_UI_AUTH_AGENT);
  add_enum(d, UI_PF_IDENTITIES_ONLY, SD_MSG_UI_AUTH_IDENTITIES_ONLY);
  add_check(d, UI_PF_SAVE_PASSWORD, SD_MSG_UI_AUTH_SAVE_PASSWORD);
  add_check(d, UI_PF_CACHE_SECRETS, SD_MSG_UI_AUTH_CACHE_SECRETS);
  add_errors(d);
}

static void add_page_conn(ui_dlg *d)
{
  ui_dlg_text(d, ED_ID_INTRO, sd_l10n_get(SD_MSG_UI_CONN_INTRO), 0);
  add_edit(d, UI_PF_JUMP, SD_MSG_UI_CONN_JUMP, 0);
  add_enum(d, UI_PF_PROXY_KIND, SD_MSG_UI_CONN_PROXY_KIND);
  add_edit(d, UI_PF_PROXY_HOST, SD_MSG_UI_CONN_PROXY_HOST, 0);
  add_edit(d, UI_PF_PROXY_PORT, SD_MSG_UI_CONN_PROXY_PORT, ES_NUMBER);
  add_edit(d, UI_PF_PROXY_USER, SD_MSG_UI_CONN_PROXY_USER, 0);
  add_enum(d, UI_PF_PROXY_AUTH, SD_MSG_UI_CONN_PROXY_AUTH);
  add_enum(d, UI_PF_CONNECTIONS, SD_MSG_UI_CONN_CONNECTIONS);
  add_edit(d, UI_PF_KEEPALIVE, SD_MSG_UI_CONN_KEEPALIVE, ES_NUMBER);
  add_edit(d, UI_PF_CONNECT_TIMEOUT, SD_MSG_UI_CONN_CONNECT_TIMEOUT, ES_NUMBER);
  add_errors(d);
}

static void add_page_mount(ui_dlg *d)
{
  add_enum(d, UI_PF_TARGET, SD_MSG_UI_MOUNT_TARGET);
  add_enum(d, UI_PF_BACKEND, SD_MSG_UI_MOUNT_BACKEND);
  add_check(d, UI_PF_READ_ONLY, SD_MSG_UI_MOUNT_READ_ONLY);
  add_enum(d, UI_PF_WRITE_MODE, SD_MSG_UI_MOUNT_WRITE_MODE);
  add_enum(d, UI_PF_SYMLINKS, SD_MSG_UI_MOUNT_SYMLINKS);
  add_edit(d, UI_PF_LABEL, SD_MSG_UI_MOUNT_LABEL, 0);
  add_edit(d, UI_PF_OFFLINE_WAIT, SD_MSG_UI_MOUNT_OFFLINE_WAIT, ES_NUMBER);
  add_check(d, UI_PF_NETWORK_LOCATION, SD_MSG_UI_MOUNT_NETWORK_LOCATION);
  add_edit(d, UI_PF_DISK_CACHE, SD_MSG_UI_MOUNT_DISK_CACHE, ES_NUMBER);
  add_errors(d);
}

static void add_page_security(ui_dlg *d)
{
  ui_dlg_text(d, ED_ID_LEGACY, sd_l10n_get(SD_MSG_UI_SECURITY_LEGACY_TEXT), 0);
  add_enum(d, UI_PF_LEGACY, SD_MSG_UI_SECURITY_LEGACY);
  add_edit(d, UI_PF_HOST_KEY_ALIAS, SD_MSG_UI_SECURITY_HOST_KEY_ALIAS, 0);
  add_enum(d, UI_PF_UPDATE_HOST_KEYS, SD_MSG_UI_SECURITY_UPDATE_HOST_KEYS);
  add_check(d, UI_PF_REFUSE_TERRAPIN, SD_MSG_UI_SECURITY_REFUSE_TERRAPIN);
  add_errors(d);
}

/* Builds the five page templates. All pages get the height of the tallest one, so the sheet is one size. */
static sd_err build_pages(ed_ctx *ed, unsigned char *blob[ED_PAGES], size_t len[ED_PAGES])
{
  static const sd_msg_id titles[ED_PAGES] = { SD_MSG_UI_TAB_GENERAL, SD_MSG_UI_TAB_AUTH, SD_MSG_UI_TAB_CONN,
                                              SD_MSG_UI_TAB_MOUNT, SD_MSG_UI_TAB_SECURITY };
  wchar_t face[UI_DLG_FACE_MAX];
  WORD points = 8;
  int dpi = 96, tallest = 0, pg;
  ui_measure m;
  ui_dlg *d[ED_PAGES];
  sd_err e = SD_OK;

  memset(blob, 0, sizeof(unsigned char *) * ED_PAGES);
  memset(len, 0, sizeof(size_t) * ED_PAGES);
  for (pg = 0; pg < ED_PAGES; pg++)
    d[pg] = NULL;
  ui_message_font(face, &points, &dpi);
  ui_measure_init(&m, face, points, dpi);
  for (pg = 0; pg < ED_PAGES && e == SD_OK; pg++) {
    d[pg] = (ui_dlg *)sd_calloc(1, sizeof(ui_dlg));   /* about 40 KB: on the heap */
    if (d[pg] == NULL) {
      e = SD_E_NO_MEMORY;
      break;
    }
    e = ui_dlg_init(d[pg], sd_l10n_get(titles[pg]), ED_WIDTH, face, points, ui_measure_cb, &m);
    if (e != SD_OK)
      break;
    d[pg]->style = WS_CHILD | DS_CONTROL;
    switch (pg) {
    case PG_GENERAL:  add_page_general(d[pg], ed); break;
    case PG_AUTH:     add_page_auth(d[pg]); break;
    case PG_CONN:     add_page_conn(d[pg]); break;
    case PG_MOUNT:    add_page_mount(d[pg]); break;
    default:          add_page_security(d[pg]); break;
    }
    if (d[pg]->cursor + d[pg]->margin > tallest)
      tallest = d[pg]->cursor + d[pg]->margin;
  }
  for (pg = 0; pg < ED_PAGES && e == SD_OK; pg++) {
    d[pg]->min_height = tallest;
    e = ui_dlg_build(d[pg], &blob[pg], &len[pg]);
  }
  for (pg = 0; pg < ED_PAGES; pg++)
    sd_free(d[pg]);
  ui_measure_free(&m);
  if (e != SD_OK) {
    for (pg = 0; pg < ED_PAGES; pg++) {
      sd_free(blob[pg]);
      blob[pg] = NULL;
    }
  }
  return e;
}

/* ---- the sheet ---- */

static sd_err load_drives(ed_ctx *ed)
{
  DWORD mask = GetLogicalDrives();
  ed->ndrives = ui_drive_free_list((uint32_t)mask, ed->drives);
  return SD_OK;
}

static void free_blobs(unsigned char *blob[ED_PAGES])
{
  size_t pg;
  for (pg = 0; pg < ED_PAGES; pg++) {
    sd_free(blob[pg]);
    blob[pg] = NULL;
  }
}

static sd_err init_ctx(ed_ctx *ed, ui_edit_mode mode, const sd_profile *p)
{
  size_t pg;
  ed->mode = mode;
  ed->work = *p;
  for (pg = 0; pg < ED_PAGES; pg++) {
    ed->pages[pg].ed = ed;
    ed->pages[pg].index = (int)pg;
    ed->pages[pg].hwnd = NULL;
  }
  return load_drives(ed);
}

int ui_editor_run(HWND owner, ui_edit_mode mode, sd_profile *p)
{
  ed_ctx *ed;
  unsigned char *blob[ED_PAGES];
  size_t len[ED_PAGES], pg;
  PROPSHEETPAGEW psp[ED_PAGES];
  PROPSHEETHEADERW hdr;
  INT_PTR ret;
  sd_err e;

  if (p == NULL)
    return 0;
  ed = (ed_ctx *)sd_calloc(1, sizeof(ed_ctx));
  if (ed == NULL)
    return 0;
  e = init_ctx(ed, mode, p);
  if (e == SD_OK)
    e = build_pages(ed, blob, len);
  if (e != SD_OK) {
    sd_free(ed);
    return 0;
  }
  for (pg = 0; pg < ED_PAGES; pg++) {
    static const sd_msg_id titles[ED_PAGES] = { SD_MSG_UI_TAB_GENERAL, SD_MSG_UI_TAB_AUTH, SD_MSG_UI_TAB_CONN,
                                                SD_MSG_UI_TAB_MOUNT, SD_MSG_UI_TAB_SECURITY };
    memset(&psp[pg], 0, sizeof(psp[pg]));
    psp[pg].dwSize = sizeof(psp[pg]);
    psp[pg].dwFlags = PSP_DLGINDIRECT | PSP_USETITLE | PSP_PREMATURE;
    psp[pg].hInstance = g_app.inst;
    psp[pg].pResource = (LPCDLGTEMPLATEW)blob[pg];
    psp[pg].pfnDlgProc = page_proc;
    psp[pg].pszTitle = sd_l10n_get(titles[pg]);
    psp[pg].lParam = (LPARAM)&ed->pages[pg];
  }
  memset(&hdr, 0, sizeof(hdr));
  hdr.dwSize = sizeof(hdr);
  hdr.dwFlags = PSH_PROPSHEETPAGE | PSH_NOAPPLYNOW | PSH_NOCONTEXTHELP;
  hdr.hwndParent = owner;
  hdr.hInstance = g_app.inst;
  hdr.pszCaption = sd_l10n_get(mode == UI_EDIT_NEW ? SD_MSG_UI_EDITOR_CAPTION_NEW
                              : mode == UI_EDIT_EDIT ? SD_MSG_UI_EDITOR_CAPTION_EDIT
                                                     : SD_MSG_UI_EDITOR_CAPTION_ADHOC);
  hdr.nPages = ED_PAGES;
  hdr.ppsp = psp;
  ret = PropertySheetW(&hdr);
  free_blobs(blob);
  if (ret > 0) {
    /* OK was accepted: every page validated the working copy on its last apply */
    *p = ed->work;
    sd_free(ed);
    return 1;
  }
  sd_free(ed);
  return 0;
}

/* ---- confirmation dialog (Yes / No, no default button when default_yes is 0 and no_id is 0) ---- */

static INT_PTR CALLBACK confirm_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
  (void)lp;
  switch (msg) {
  case WM_INITDIALOG:
    return TRUE;
  case WM_COMMAND:
    if (LOWORD(wp) == IDOK || LOWORD(wp) == IDCANCEL) {
      EndDialog(hwnd, LOWORD(wp) == IDOK ? IDYES : IDNO);
      return TRUE;
    }
    break;
  default:
    break;
  }
  return FALSE;
}

int ui_confirm(HWND owner, sd_msg_id title_id, sd_msg_id text_id, const wchar_t *arg, sd_msg_id yes_id,
               sd_msg_id no_id, int default_yes)
{
  wchar_t face[UI_DLG_FACE_MAX];
  WORD points = 8;
  int dpi = 96;
  ui_measure m;
  ui_dlg *d;
  unsigned char *blob = NULL;
  size_t len = 0;
  wchar_t *text = NULL;
  sd_arg a[1];
  INT_PTR r = IDNO;
  sd_err e;
  static const WORD ids[2] = { IDOK, IDCANCEL };
  const wchar_t *texts[2];

  d = (ui_dlg *)sd_calloc(1, sizeof(ui_dlg));
  if (d == NULL)
    return 0;
  ui_message_font(face, &points, &dpi);
  ui_measure_init(&m, face, points, dpi);
  a[0].name = "name";
  a[0].type = SD_ARG_STR;
  a[0].v.s = arg ? arg : L"";
  text = (arg != NULL) ? sd_l10n_format_alloc(text_id, a, 1) : NULL;
  e = ui_dlg_init(d, sd_l10n_get(title_id), 260, face, points, ui_measure_cb, &m);
  if (e == SD_OK)
    e = ui_dlg_text(d, 0, text ? text : sd_l10n_get(text_id), 0);
  if (e == SD_OK) {
    texts[0] = sd_l10n_get(yes_id);
    texts[1] = sd_l10n_get(no_id);
    e = ui_dlg_space(d, 4);
    if (e == SD_OK)
      e = ui_dlg_buttons(d, ids, texts, 2, default_yes ? IDOK : IDCANCEL);
  }
  if (e == SD_OK)
    e = ui_dlg_build(d, &blob, &len);
  ui_measure_free(&m);
  sd_free(d);
  sd_free(text);
  if (e == SD_OK && blob != NULL) {
    /* DialogBoxIndirectParamW runs the modal loop; the answer comes back as IDYES or IDNO */
    r = DialogBoxIndirectParamW(g_app.inst, (LPCDLGTEMPLATEW)blob, owner, confirm_proc, 0);
  }
  sd_free(blob);
  return r == IDYES;
}

/* ---- smoke test (--test-editor) ---- */

int ui_editor_smoke_test(void)
{
  static const ui_edit_mode modes[] = { UI_EDIT_NEW, UI_EDIT_EDIT, UI_EDIT_ADHOC };
  HWND parent;
  size_t mi, pg;
  int ok = 1;

  parent = CreateWindowExW(0, L"STATIC", L"", WS_POPUP, 0, 0, 10, 10, NULL, NULL, g_app.inst, NULL);
  if (parent == NULL)
    return 0;
  for (mi = 0; mi < SD_COUNTOF(modes) && ok; mi++) {
    ed_ctx *ed = (ed_ctx *)sd_calloc(1, sizeof(ed_ctx));
    unsigned char *blob[ED_PAGES];
    size_t len[ED_PAGES];
    sd_profile p;
    if (ed == NULL) {
      ok = 0;
      break;
    }
    sd_profile_defaults(&p);
    if (init_ctx(ed, modes[mi], &p) != SD_OK || build_pages(ed, blob, len) != SD_OK) {
      sd_free(ed);
      ok = 0;
      break;
    }
    for (pg = 0; pg < ED_PAGES; pg++) {
      PROPSHEETPAGEW psp;
      HWND page;
      memset(&psp, 0, sizeof(psp));
      psp.dwSize = sizeof(psp);
      psp.lParam = (LPARAM)&ed->pages[pg];
      page = CreateDialogIndirectParamW(g_app.inst, (LPCDLGTEMPLATEW)blob[pg], parent, page_proc, (LPARAM)&psp);
      if (page == NULL || !IsWindow(page) || ed->pages[pg].hwnd != page)
        ok = 0;
      if (page != NULL)
        DestroyWindow(page);
    }
    free_blobs(blob);
    sd_free(ed);
  }
  DestroyWindow(parent);
  return ok;
}
