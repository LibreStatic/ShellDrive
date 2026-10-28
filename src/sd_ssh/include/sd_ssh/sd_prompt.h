/* UI-agnostic prompt model (01 §6.7, §7.1; TM-R03, TM-R05).
 *
 * sd_ssh raises prompts through sd_ssh_callbacks.on_prompt on the connection's I/O thread; the
 * callback must return quickly (it may only enqueue, review §4.1 rule 4). The prompt object is
 * owned by sd_ssh until it is answered or cancelled; answer it from ANY thread, exactly once.
 * If the connection dies first, answering returns SD_E_CANCELLED and on_prompt_withdrawn fires.
 * All strings in the info structs are UTF-8, sanitized (sd_text_sanitize_*), valid only until the
 * prompt is answered, cancelled or withdrawn. Responses are copied into secret buffers. */
#ifndef SD_PROMPT_H
#define SD_PROMPT_H

#include "sd/base.h"
#include "sd_base/sd_err.h"
#include "sd_ssh/sd_known_hosts.h"

typedef enum sd_prompt_kind {
  SD_PROMPT_HOSTKEY,          /* TOFU (SD_HK_NEW): sd_hostkey_prompt_info */
  SD_PROMPT_PASSWORD, SD_PROMPT_NEW_PASSWORD, SD_PROMPT_KBDINT, SD_PROMPT_KEY_PASSPHRASE,
  SD_PROMPT_LEGACY_ACK,       /* answered with sd_prompt_answer_ack() */
  SD_PROMPT_PROXY_PASSWORD
} sd_prompt_kind;

typedef struct sd_prompt sd_prompt;

typedef struct sd_prompt_item { const char *text; int echo; } sd_prompt_item;

typedef struct sd_auth_prompt_info {
  sd_prompt_kind kind;
  uint32_t hop_index; const char *host; const char *user;
  const char *name, *instruction;                               /* kbd-int; may be "" */
  const sd_prompt_item *items; uint32_t item_count;
  uint32_t round;            /* 0-based count of rounds of this kind */
  int may_autofill;          /* a stored secret is plausible; 0 if hostkey_just_accepted */
  int hostkey_just_accepted; /* TM-R05: stored secrets must not answer; SD_ANSWER_FROM_STORE is refused */
  int is_reconnect;          /* raised during an automatic reconnect (01 §8) */
  int is_pool_member;        /* answer from stored secrets or cancel, never show UI (01 §10.9) */
  const char *key_path; const char *key_fingerprint;            /* passphrase prompts */
  const char *proxy_host; uint16_t proxy_port;                  /* SD_PROMPT_PROXY_PASSWORD */
  uint32_t legacy_mask; const char *legacy_names;               /* SD_PROMPT_LEGACY_ACK */
  uint64_t deadline_tick_ms; /* best-effort server timeout, sd_tick_ms() scale; 0 = none */
} sd_auth_prompt_info;

typedef struct sd_hostkey_prompt_info {
  uint32_t hop_index;
  const char *host;          /* sanitized host as configured */
  uint16_t port;
  const char *via_host;      /* hop i >= 1: sanitized host of hop i-1 (TM-R03); NULL for hop 0 */
  const char *lookup_name;   /* the known_hosts name that will be stored */
  const char *key_type;      /* "ssh-ed25519", ... */
  uint32_t key_bits;
  const char *fp_sha256;     /* "SHA256:..." (primary) */
  const char *fp_md5;        /* "MD5:xx:..." (secondary; may be "" until MD5 exists, M2) */
  const uint8_t *blob; size_t blob_len;   /* the presented key (SSH wire format), owned by the prompt (M5 hostkey add) */
  sd_hk_status status;       /* always SD_HK_NEW for a prompt; other results fail without one */
  int is_reconnect;          /* M1: raised by an automatic reconnect (the key was removed from every
                                store meanwhile and differs from the key of the previous connect) */
} sd_hostkey_prompt_info;

typedef enum sd_hostkey_decision {
  SD_HK_REJECT, SD_HK_ACCEPT_ONCE, SD_HK_ACCEPT_AND_STORE
} sd_hostkey_decision;

enum { SD_ANSWER_FROM_STORE = 1u << 0 };   /* answer came from a store, not from the user */

sd_err sd_prompt_answer(sd_prompt *p, uint32_t n, const char *const *utf8_responses);
sd_err sd_prompt_answer_ex(sd_prompt *p, uint32_t n, const char *const *utf8_responses,
                           uint32_t answer_flags);
sd_err sd_prompt_answer_hostkey(sd_prompt *p, sd_hostkey_decision d);
sd_err sd_prompt_answer_ack(sd_prompt *p, int accept);
sd_err sd_prompt_cancel(sd_prompt *p);

#endif /* SD_PROMPT_H */
