/* Anonymizer for "shelldrive diag --bundle" (03 §10.1 privacy, §10.5, TM-R31). A bundle hides host names,
 * user names and remote paths by default. Each value becomes a token: "h:" + six hex digits for a host,
 * "u:" for a user name and "p:" for a remote path. The token is HMAC-SHA-256 of the value under a random
 * key that is drawn for each bundle, so one value always gets the same token inside a bundle (a support
 * engineer can follow one host through the logs) and tokens cannot be compared across bundles.
 *
 * Secrets are never copied: a configuration line whose key names a password, passphrase, token, secret or
 * credential keeps its key and loses its value, whatever the anonymization setting is. */
#ifndef CLI_ANON_H
#define CLI_ANON_H

#include <windows.h>
#include <stddef.h>

#include "sd/base.h"
#include "sd_base/sd_buf.h"
#include "sd_base/sd_err.h"

typedef struct anon_ctx anon_ctx;

/* enabled = 0 keeps every value (--no-anonymize); secrets are still redacted. NULL when out of memory or
   when the random key cannot be drawn. */
anon_ctx *anon_new(int enabled);
void anon_free(anon_ctx *c);
int anon_enabled(const anon_ctx *c);

/* Registers a value to hide wherever it occurs in the text that follows (matched without regard to ASCII
   case). kind: 'h' host, 'u' user name, 'p' remote path. Values shorter than two bytes are ignored. */
void anon_add_value(anon_ctx *c, char kind, const char *utf8);

/* The token of a value: "h:xxxxxx", "u:xxxxxx" or "p:xxxxxx" into out (at least 16 bytes). The same value
   and kind give the same token within one context. */
void anon_token(anon_ctx *c, char kind, const char *utf8, char *out, size_t cap);

/* Processes one line of a log record (no line break). Fields host=, user=, rpath=, remote_path= and path=
   have their values replaced by a token, and every registered value is replaced wherever it appears. Other
   text is copied unchanged. */
sd_err anon_log_line(anon_ctx *c, const char *in, size_t n, sd_wr *out);

/* Processes one line of a configuration file: "key = value" pairs with a secret key lose their value (kept
   as "<redacted>"); host, user, remote_path and identity values are replaced when anonymization is on, and
   every registered value is replaced wherever it appears. Comments and other lines are copied unchanged
   (with the registered values replaced). */
sd_err anon_config_line(anon_ctx *c, const char *in, size_t n, sd_wr *out);

/* 1 when the key of a configuration or log field names a secret (password, passphrase, token, secret,
   credential, pin, private key). The comparison ignores ASCII case. */
int anon_is_secret_key(const char *key, size_t n);

#endif /* CLI_ANON_H */
