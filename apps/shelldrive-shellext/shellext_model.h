/* Pure helpers of the shell extension (03 §8.2): menu planning, remote path formatting, the menu.cache parser and
 * menu label sanitizing. No Win32 calls, no allocation, no global state: every function is reentrant and is
 * unit-tested directly. Inputs that come from other processes (the state section, menu.cache) are untrusted. */
#ifndef SD_SHELLEXT_MODEL_H
#define SD_SHELLEXT_MODEL_H

#include <stddef.h>
#include <stdint.h>
#include <wchar.h>

#define SHX_URL_UNITS        320u     /* remote_url slot of the state section */
#define SHX_ID_UNITS         32u
#define SHX_NAME_UNITS       128u
#define SHX_REL_MAX          2047u    /* longest path below a drive root that Copy remote path handles */
#define SHX_COPY_MAX         4096u    /* longest text put on the clipboard (with the terminating NUL) */
#define SHX_CACHE_MAX_BYTES  65536u   /* menu.cache size cap (03 §8.2) */
#define SHX_CACHE_MAX_ENTRIES 256u
#define SHX_SUBMENU_MAX      32u      /* profiles listed in the This PC submenu; the rest sit behind "More" */
#define SHX_LABEL_MAX        48u      /* visible characters of a profile name in the menu */

/* What a menu item does. */
typedef enum shx_act {
  SHX_ACT_NONE = 0,       /* disabled placeholder, never invoked */
  SHX_ACT_OPEN,           /* --action open X: */
  SHX_ACT_UNMOUNT,        /* --action unmount X: */
  SHX_ACT_RECONNECT,      /* --action reconnect X: */
  SHX_ACT_COPY_PATH,      /* remote path to the clipboard (in process) */
  SHX_ACT_MOUNT_PROFILE,  /* --action mount <profile id> */
  SHX_ACT_SHOW            /* --action show */
} shx_act;

/* One profile of menu.cache. */
typedef struct shx_profile {
  wchar_t id[SHX_ID_UNITS + 1];       /* 32 lowercase hex digits */
  wchar_t name[SHX_NAME_UNITS + 1];   /* display name, valid UTF-16, no control characters */
} shx_profile;

/* Items for one selected path that is on a ShellDrive drive (03 §8.2): max items written, count returned.
   is_root: the selection is the drive root. flags and state are those of the state entry. has_url: the entry
   carries a usable remote URL. Drive roots: Open for every entry; Unmount and Reconnect for per-user entries
   by state; Copy remote path when has_url. Items inside the drive: Copy remote path only, when has_url. */
size_t shx_plan_drive(uint32_t flags, uint32_t state, int is_root, int has_url, shx_act *out, size_t max);

/* 1 when url is a usable remote URL: starts with "sftp://", fits the slot, and has no control, bidi or
   zero-width characters. Such a URL is copied as it is (the agent writes it ready for use, 03 §8.2.1). */
int shx_remote_url_ok(const wchar_t *url);

/* "sftp://user@host:port/base" + rel -> out. rel is the path below the drive root ("dir\file", no leading
   backslash; "" for the root itself): the backslashes become '/', each component is percent-encoded as UTF-8
   (RFC 3986 pchar characters stay), empty components are skipped, and "." and ".." refuse the whole call.
   The base is used verbatim without its trailing slashes. Returns 1 on success; on failure out[0] = 0. */
int shx_remote_copy_text(const wchar_t *url, const wchar_t *rel, wchar_t *out, size_t cch);

/* Parses menu.cache v1 (UTF-8, optional BOM): first line "SDMENU 1", then one profile per line,
   "<32 lowercase hex><TAB><name>". Blank lines and lines starting with '#' are skipped; a malformed line or a
   duplicate id is dropped on its own. A wrong first line, or len above SHX_CACHE_MAX_BYTES, means no data.
   At most max profiles (and SHX_CACHE_MAX_ENTRIES) are returned. */
size_t shx_menucache_parse(const unsigned char *buf, size_t len, shx_profile *out, size_t max);

/* Text for a menu item from a profile name: bidi and zero-width characters removed, control characters
   become spaces, '&' doubled (no accidental mnemonic), cut at SHX_LABEL_MAX characters with "...". */
void shx_menu_label(const wchar_t *name, wchar_t *out, size_t cch);

#endif /* SD_SHELLEXT_MODEL_H */
