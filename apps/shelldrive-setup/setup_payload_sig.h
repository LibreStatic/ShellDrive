/* Payload table signature (docs/design/04 §6.1, §9.3; TM-R38, T-71).
 *
 * The setup stub refuses to unpack a payload unless its PAYLOAD_TABLE is signed (PAYLOAD_SIG) by a release key
 * that the keyring compiled into the stub authorizes for the build's channel, inside its validity dates and not
 * revoked. Verification is fail-closed: every error is a refusal.
 *
 * Signed bytes: SD_SETUP_PSIG_DOMAIN || <PAYLOAD_TABLE bytes exactly>. The table is LF-terminated printable ASCII:
 *
 *   shelldrive-payload-table 1
 *   product com.librestatic.shelldrive
 *   channel stable
 *   x86-ia32 <sha256 hex> <size>        (one line per flavour; the stub reads its own, see setup_args.c)
 *
 * PAYLOAD_SIG is one line: "sig ed25519 <key-id 16 lowercase hex> <signature base64 (88 chars)>" + LF.
 * Key ID = first 8 bytes of SHA-256(public key) (the same rule as sd_update).
 *
 * The functions here are pure (no clock, no resources) so tests run them with generated keys. The resource
 * wrapper sd_setup_payload_sig_check is the single call site in the stub (setup_main.c).
 *
 * Shared with tools/sd-release and tools/sd-payload through the sd_payload_sig library (no engine code). */
#ifndef SD_SETUP_PAYLOAD_SIG_H
#define SD_SETUP_PAYLOAD_SIG_H

#include <windows.h>
#include <stddef.h>
#include <stdint.h>

#define SD_SETUP_PSIG_DOMAIN       "com.librestatic.shelldrive payload table v1\n"
#define SD_SETUP_PSIG_PRODUCT      "com.librestatic.shelldrive"
#define SD_SETUP_PSIG_TABLE_MAX    4096u
#define SD_SETUP_PSIG_SIG_MAX      256u

typedef struct sd_setup_psig_key {
  uint8_t  pub[32];
  char     channel[8];          /* "stable" | "beta" */
  int64_t  valid_from;          /* unix seconds, inclusive */
  int64_t  valid_to;            /* unix seconds, inclusive */
  int      revoked;
} sd_setup_psig_key;

typedef enum sd_setup_psig_res {
  SD_SETUP_PSIG_OK = 0,
  SD_SETUP_PSIG_E_NO_KEYS,      /* empty keyring: nothing can verify */
  SD_SETUP_PSIG_E_TOO_LARGE,    /* table or signature line over its limit */
  SD_SETUP_PSIG_E_FORMAT,       /* table header or sig line is malformed */
  SD_SETUP_PSIG_E_PRODUCT,      /* product is not com.librestatic.shelldrive */
  SD_SETUP_PSIG_E_CHANNEL,      /* table channel differs from the build channel, or the key is for another channel */
  SD_SETUP_PSIG_E_UNKNOWN_KEY,  /* key id is not in the keyring */
  SD_SETUP_PSIG_E_KEY_INVALID,  /* revoked, or now outside the validity dates */
  SD_SETUP_PSIG_E_SIGNATURE,    /* the signature does not verify over domain || table */
  SD_SETUP_PSIG_E_RESOURCE      /* PAYLOAD_SIG or PAYLOAD_TABLE missing or unreadable (resource wrapper only) */
} sd_setup_psig_res;

/* Verifies the table against the signature line. channel_expected: the build's channel. now: unix seconds.
   Returns SD_SETUP_PSIG_OK only when every check passes. */
sd_setup_psig_res sd_setup_psig_verify(const uint8_t *table, size_t tlen, const uint8_t *sig, size_t slen,
                                       const sd_setup_psig_key *keys, size_t nkeys,
                                       const char *channel_expected, int64_t now);

/* Parses the "channel" header line of a table into out (NUL-terminated). 0 on success. */
int sd_setup_psig_table_channel(const uint8_t *table, size_t tlen, char *out, size_t cap);

/* Base64 (RFC 4648, padded, canonical) decode for the sig line. Returns the length or -1. */
int sd_setup_psig_b64_decode(const char *s, size_t len, uint8_t *out, size_t cap);

/* Current time as unix seconds (GetSystemTimeAsFileTime). */
int64_t sd_setup_psig_now(void);

/* Resource wrapper for the stub: loads PAYLOAD_SIG from inst, checks the PAYLOAD_TABLE bytes against the keyring
   compiled into the stub (setup_payload_sig.c, setup_keyring.inc) for SD_SETUP_BUILD_CHANNEL. 0 = verified. */
sd_setup_psig_res sd_setup_payload_sig_check(HINSTANCE inst, const uint8_t *table, size_t tlen);

#endif /* SD_SETUP_PAYLOAD_SIG_H */
