/* sd_ini: the INI-like configuration format (03 §3.3).
 *
 * Grammar: `[section]`, `key = value`, comment lines starting with ';' or '#'. Keys and section
 * names are ASCII lowercase [a-z0-9_.] (sections also '-'). Values are trimmed; a value in double
 * quotes keeps whitespace and supports \" \\ \n. An unquoted value ends at an inline comment that
 * starts with whitespace followed by ';' or '#'. UTF-8 (a BOM is accepted on read, never written);
 * input that is not valid UTF-8 is decoded with the ANSI code page and reported through
 * SD_INI_F_ANSI_DECODED (the next write converts it).
 *
 * Round trip: every line is kept, including comments, blank lines, unknown sections and keys and
 * invalid lines; sd_ini_set rewrites only the line it changes (keeping its inline comment) or
 * appends to the end of the section. The first occurrence of a duplicated key wins.
 *
 * Ownership: strings returned by sd_ini_get live until the next modification or sd_ini_free.
 * Thread safety: none; one owner at a time. */
#ifndef SD_INI_H
#define SD_INI_H

#include "sd/base.h"
#include "sd_base/sd_err.h"
#include "sd_base/sd_buf.h"

typedef struct sd_ini sd_ini;

enum { SD_INI_F_ANSI_DECODED = 1u << 0, SD_INI_F_INVALID_LINES = 1u << 1, SD_INI_F_DUPLICATE_KEYS = 1u << 2 };

#define SD_INI_MAX_BYTES (1u << 20)      /* files above 1 MiB are refused */

sd_err sd_ini_new(sd_ini **out);
sd_err sd_ini_parse(const char *data, size_t len, sd_ini **out, uint32_t *flags);
void   sd_ini_free(sd_ini *ini);

const char *sd_ini_get(const sd_ini *ini, const char *section, const char *key);   /* NULL if absent */
sd_err sd_ini_set(sd_ini *ini, const char *section, const char *key, const char *value);
sd_err sd_ini_remove(sd_ini *ini, const char *section, const char *key);           /* SD_E_NOT_FOUND */
sd_err sd_ini_serialize(const sd_ini *ini, sd_wr *out);                             /* CRLF line ends */

/* Value helpers (03 §3.3). Return 1 on success. */
int sd_ini_parse_bool(const char *v, int *out);                 /* yes/no/true/false/1/0 */
int sd_ini_parse_u32(const char *v, uint32_t *out);
int sd_ini_parse_duration_ms(const char *v, uint32_t *out);    /* integer + ms|s|m|h (bare = seconds) */
int sd_ini_parse_size(const char *v, uint64_t *out);           /* integer + K|M|G (bare = bytes) */

int sd_ini_valid_key(const char *key);
int sd_ini_valid_section(const char *section);

#endif /* SD_INI_H */
