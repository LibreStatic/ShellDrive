/* sd_l10n: runtime for the compiled message catalogs (03 §9.3-§9.5).
 *
 * Deviation from the 03 §9.5 sketch (docs/dev/m0-notes.md): sd_l10n_init takes the binary's
 * generated catalog explicitly, because each binary links its own merged set of domains.
 *
 * Threading: call sd_l10n_init once at startup, before other threads use the catalog (the language
 * is stored per process). After that every function is thread-safe. Strings returned by
 * sd_l10n_get are cached UTF-16 owned by sd_l10n and live until process exit.
 * sd_l10n_format_alloc results are released with sd_free. */
#ifndef SD_L10N_H
#define SD_L10N_H

#include <windows.h>

#include "sd/base.h"
#include "sd_base/sd_err.h"
#include "sd_l10n/sd_l10n_catalog.h"

/* Resolves the language (03 §9.3): override_code (--lang / SHELLDRIVE_LANG, "pt" = "pt-BR") ->
   policy UILanguage -> settings -> GetUserDefaultUILanguage() -> en. override_code may be NULL. */
sd_lang        sd_l10n_init(const sd_l10n_catalog *catalog, const wchar_t *override_code);
sd_lang        sd_l10n_lang(void);
const char    *sd_l10n_lang_code(sd_lang lang);          /* "en", "es", "fr", "pt-BR", "it", "de" */
int            sd_l10n_parse_lang(const wchar_t *code, sd_lang *out);   /* 1 if recognized */

/* CLDR cardinal category for an integer count in a language (03 §9.4). */
sd_plural_cat  sd_l10n_plural_category(sd_lang lang, long long n);

/* Cached UTF-16 of a non-plural message; never NULL (falls back to en, then to the key). */
const wchar_t *sd_l10n_get(sd_msg_id id);

typedef enum sd_arg_type { SD_ARG_STR, SD_ARG_INT, SD_ARG_SIZE, SD_ARG_DURATION_MS, SD_ARG_FILETIME } sd_arg_type;
typedef struct sd_arg {
  const char *name;
  sd_arg_type type;
  union { const wchar_t *s; long long i; FILETIME t; } v;
} sd_arg;
#define SD_S(n, val)  { (n), SD_ARG_STR, { .s = (val) } }
#define SD_I(n, val)  { (n), SD_ARG_INT, { .i = (val) } }

/* Named placeholders "{name}", "{{" / "}}" escapes; plural form chosen by the entry's plural_arg.
   Returns the number of wchar_t written (excluding NUL), or -1 if the buffer is too small (the
   output is then truncated and NUL-terminated). */
int      sd_l10n_format(wchar_t *buf, size_t cch, sd_msg_id id, const sd_arg *args, size_t nargs);
wchar_t *sd_l10n_format_alloc(sd_msg_id id, const sd_arg *args, size_t nargs);

#endif /* SD_L10N_H */
