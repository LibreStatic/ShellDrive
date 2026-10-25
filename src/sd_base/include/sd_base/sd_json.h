/* Small JSON reader/writer for IPC, `--json` output and diagnostics (03 §2.3).
 *
 * DECLARATIONS ONLY in M0 foundation. The implementation (src/sd_base/json*.c) is owned by the
 * sd_ipc agent; it is the only file set that agent adds inside sd_base (picked up by the optional
 * glob in src/sd_base/CMakeLists.txt). Keep the API below; extend it additively.
 *
 * Ownership: sd_json_parse returns a root that owns every node (one arena per document); free it
 * with sd_json_free. Pointers returned by accessors live as long as the root.
 * A writer emits UTF-8 into an sd_wr; it validates nesting and escapes strings.
 * Thread safety: none internally; one document or writer per thread at a time. */
#ifndef SD_JSON_H
#define SD_JSON_H

#include "sd/base.h"
#include "sd_base/sd_err.h"
#include "sd_base/sd_buf.h"

typedef enum sd_json_type {
  SD_JSON_NULL, SD_JSON_BOOL, SD_JSON_NUMBER, SD_JSON_STRING, SD_JSON_ARRAY, SD_JSON_OBJECT
} sd_json_type;

typedef struct sd_json sd_json;

/* Strict RFC 8259 parser. Limits: max_depth (0 = 32); strings must be valid UTF-8; duplicate object
   keys are an error. */
sd_err        sd_json_parse(const char *utf8, size_t len, uint32_t max_depth, sd_json **out);
void          sd_json_free(sd_json *root);
sd_json_type  sd_json_type_of(const sd_json *v);
const sd_json *sd_json_get(const sd_json *obj, const char *key);     /* NULL if absent / not object */
size_t        sd_json_count(const sd_json *v);                        /* array or object members */
const sd_json *sd_json_at(const sd_json *v, size_t i);                /* array element / object value */
const char   *sd_json_key_at(const sd_json *obj, size_t i);
const char   *sd_json_str(const sd_json *v, size_t *len);             /* NULL if not a string */
int           sd_json_int64(const sd_json *v, int64_t *out);          /* 1 if an integral number */
int           sd_json_bool(const sd_json *v, int *out);               /* 1 if a boolean */

typedef struct sd_json_writer { sd_wr *out; uint32_t depth; uint32_t state[32]; int err; } sd_json_writer;
void sd_jw_init(sd_json_writer *jw, sd_wr *out);
void sd_jw_obj_begin(sd_json_writer *jw);
void sd_jw_obj_end(sd_json_writer *jw);
void sd_jw_arr_begin(sd_json_writer *jw);
void sd_jw_arr_end(sd_json_writer *jw);
void sd_jw_key(sd_json_writer *jw, const char *key);
void sd_jw_str(sd_json_writer *jw, const char *utf8, size_t len);
void sd_jw_int(sd_json_writer *jw, int64_t v);
void sd_jw_bool(sd_json_writer *jw, int v);
void sd_jw_null(sd_json_writer *jw);
sd_err sd_jw_finish(sd_json_writer *jw);                               /* SD_OK if complete and valid */

#endif /* SD_JSON_H */
