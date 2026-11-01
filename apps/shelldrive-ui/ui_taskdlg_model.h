/* shelldrive-ui: the mapping of MessageBox flags to a task dialog (06 §6.2). Pure: no window or process calls,
 * so the unit tests (tests/ui) build this file on its own through SD_UI_PURE_SOURCES. ui_win_task (ui_win.c)
 * uses it to call TaskDialogIndirect with the buttons, icon and default button a MessageBoxW call would have. */
#ifndef SD_UI_TASKDLG_MODEL_H
#define SD_UI_TASKDLG_MODEL_H

#include <windows.h>

/* TDCBF_* values of the common buttons (commctrl.h has them only from the Vista headers). */
#define UI_TASK_BTN_OK     0x0001u
#define UI_TASK_BTN_YES    0x0002u
#define UI_TASK_BTN_NO     0x0004u
#define UI_TASK_BTN_CANCEL 0x0008u
#define UI_TASK_BTN_RETRY  0x0010u

/* The main icon is MAKEINTRESOURCE(icon): TD_WARNING_ICON is -1, TD_ERROR_ICON -2, TD_INFORMATION_ICON -3. */
#define UI_TASK_ICON_NONE    0
#define UI_TASK_ICON_WARNING (-1)
#define UI_TASK_ICON_ERROR   (-2)
#define UI_TASK_ICON_INFO    (-3)

typedef struct ui_task_map {
  unsigned buttons;       /* UI_TASK_BTN_* mask */
  int icon;               /* UI_TASK_ICON_* */
  int default_id;         /* IDOK, IDYES, IDNO, IDCANCEL or IDRETRY: the button with the focus */
  int allow_cancel;       /* 1 when Escape / the close box can end the dialog (a Cancel button, or only OK) */
} ui_task_map;

/* Maps MB_* flags. Returns 1 on success; 0 for a button set a task dialog does not offer as common buttons
   (MB_ABORTRETRYIGNORE, MB_CANCELTRYCONTINUE, MB_HELP), where the caller uses MessageBoxW. The buttons appear
   in the order of MessageBox: OK / Cancel, Yes / No / Cancel, Retry / Cancel; MB_DEFBUTTONn picks the nth one
   (a number past the last falls back to the first). MB_ICONQUESTION has no task dialog icon (the Windows
   guidelines drop it), so it maps to none. */
int ui_task_map_flags(UINT mb_flags, ui_task_map *out);

/* The plain text of a message box when no task dialog is available: "main", then a blank line and "content",
   then a blank line and "details" for each one that is non-empty. Returns the length (without the NUL), or 0
   when the buffer is too small or main is empty. */
size_t ui_task_plain_text(const wchar_t *main_text, const wchar_t *content, const wchar_t *details,
                          wchar_t *out, size_t cap);

#endif /* SD_UI_TASKDLG_MODEL_H */
