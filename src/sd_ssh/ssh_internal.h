/* sd_ssh private declarations shared by the translation units of the module and its unit tests.
 * Not a public header: nothing outside src/sd_ssh and tests/unit/sd_ssh includes it.
 *
 * Layout (01 §1, §3-§7):
 *   base64.c          base64 encode/decode (known_hosts, key files, fingerprints)
 *   crypto_init.c     sd_crypto_init() once (ssh_crypto_ready()) and the random source
 *   negotiate.c       algorithm lists (D4, TM-R01, TM-R04), KEXINIT encode/parse, negotiation
 *   packet.c          binary packet protocol (RFC 4253 §6) with chacha20-poly1305, AES-GCM, CTR+HMAC
 *   known_hosts.c     known_hosts stores (no transport dependency)
 *   keyfile_openssh.c OpenSSH v1 key files (no transport dependency)
 *   prompt.c          sd_prompt objects
 *   conn.c, kex.c, auth.c, channel.c   connection, I/O thread and protocol state machine
 *
 * Threading: everything here is single-owner unless stated otherwise. */
#ifndef SD_SSH_INTERNAL_H
#define SD_SSH_INTERNAL_H

#include "sd/base.h"
#include "sd_base/sd_buf.h"
#include "sd_base/sd_err.h"
#include "sd_crypto/sd_crypto.h"
#include "sd_ssh/sd_known_hosts.h"
#include "sd_ssh/sd_ssh.h"
#include "ssh_zlib.h"

/* ---- message numbers (RFC 4250 §4.1, RFC 8308, OpenSSH PROTOCOL) ---- */
enum {
  SSH_MSG_DISCONNECT = 1, SSH_MSG_IGNORE = 2, SSH_MSG_UNIMPLEMENTED = 3, SSH_MSG_DEBUG = 4,
  SSH_MSG_SERVICE_REQUEST = 5, SSH_MSG_SERVICE_ACCEPT = 6, SSH_MSG_EXT_INFO = 7,
  SSH_MSG_KEXINIT = 20, SSH_MSG_NEWKEYS = 21,
  SSH_MSG_KEX_ECDH_INIT = 30, SSH_MSG_KEX_ECDH_REPLY = 31,
  SSH_MSG_USERAUTH_REQUEST = 50, SSH_MSG_USERAUTH_FAILURE = 51, SSH_MSG_USERAUTH_SUCCESS = 52,
  SSH_MSG_USERAUTH_BANNER = 53, SSH_MSG_USERAUTH_PK_OK = 60, SSH_MSG_USERAUTH_INFO_REQUEST = 60,
  SSH_MSG_USERAUTH_PASSWD_CHANGEREQ = 60, SSH_MSG_USERAUTH_INFO_RESPONSE = 61,
  SSH_MSG_GLOBAL_REQUEST = 80, SSH_MSG_REQUEST_SUCCESS = 81, SSH_MSG_REQUEST_FAILURE = 82,
  SSH_MSG_CHANNEL_OPEN = 90, SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91, SSH_MSG_CHANNEL_OPEN_FAILURE = 92,
  SSH_MSG_CHANNEL_WINDOW_ADJUST = 93, SSH_MSG_CHANNEL_DATA = 94, SSH_MSG_CHANNEL_EXTENDED_DATA = 95,
  SSH_MSG_CHANNEL_EOF = 96, SSH_MSG_CHANNEL_CLOSE = 97, SSH_MSG_CHANNEL_REQUEST = 98,
  SSH_MSG_CHANNEL_SUCCESS = 99, SSH_MSG_CHANNEL_FAILURE = 100
};

enum {
  SSH_DISCONNECT_PROTOCOL_ERROR = 2, SSH_DISCONNECT_KEY_EXCHANGE_FAILED = 3,
  SSH_DISCONNECT_MAC_ERROR = 5, SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE = 9,
  SSH_DISCONNECT_BY_APPLICATION = 11, SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 14
};

#define SSH_MAX_PACKET_LEN   (256u * 1024u)    /* inbound packet_length limit (01 §4.1) */
#define SSH_HOSTKEY_BUF      8192u             /* K_S / host certificate kept per connection */
#define SSH_MAX_PAYLOAD_OUT  (SSH_MAX_PACKET_LEN - 1024u)

/* ---- crypto availability (crypto_init.c) ---- */

/* 1 when sd_crypto_init() succeeded. Thread-safe; cached after the first call. */
int ssh_crypto_ready(void);

/* Random bytes for padding, cookies and ephemeral keys. Tests may install a deterministic source. */
sd_err ssh_random(void *p, size_t n);
typedef sd_err (*ssh_random_fn)(void *p, size_t n);
void ssh_set_random_for_tests(ssh_random_fn fn);

/* ---- base64 (base64.c) ---- */

size_t ssh_b64_encoded_len(size_t n, int pad);
/* Writes NUL-terminated output; returns length without NUL or 0 if cap is too small. */
size_t ssh_b64_encode(const uint8_t *in, size_t n, char *out, size_t cap, int pad);
/* Strict decoder: ignores nothing except (when skip_ws) CR/LF/space/tab; padding optional.
   Returns SD_OK and *out_len, or SD_E_INVALID_PARAM. */
sd_err ssh_b64_decode(const char *in, size_t n, uint8_t *out, size_t cap, size_t *out_len, int skip_ws);

/* ---- small helpers ---- */

int  ssh_span_eq(sd_span a, const char *s);
/* Copies a span into a NUL-terminated buffer; 0 if it does not fit. */
int  ssh_span_copy(sd_span a, char *out, size_t cap);
/* Key type string at the start of a public key blob ("ssh-ed25519"); empty span on error. */
sd_span ssh_blob_key_type(const uint8_t *blob, size_t len);

/* ---- algorithm negotiation (negotiate.c) ---- */

#define SSH_LIST_CAP 768

typedef struct ssh_kexinit {
  uint8_t cookie[16];
  sd_span kex, hostkey, enc_c2s, enc_s2c, mac_c2s, mac_s2c, comp_c2s, comp_s2c, lang_c2s, lang_s2c;
  int first_kex_follows;
} ssh_kexinit;

/* payload includes the message byte (SSH_MSG_KEXINIT). Spans point into payload. */
sd_err ssh_kexinit_parse(const uint8_t *payload, size_t n, ssh_kexinit *out);

typedef struct ssh_lists {
  char kex[SSH_LIST_CAP], hostkey[SSH_LIST_CAP];
  char enc_c2s[SSH_LIST_CAP], enc_s2c[SSH_LIST_CAP];
  char mac_c2s[SSH_LIST_CAP], mac_s2c[SSH_LIST_CAP];
  char comp[32];
} ssh_lists;

typedef struct ssh_list_input {
  const ssh_kexinit *server;     /* NULL: fallback lists (no server KEXINIT within 3 s) */
  const sd_kh_types *stored;     /* NULL or count 0 and !has_ca: nothing stored */
  int hw_aes;                    /* AES-NI + PCLMUL: GCM above chacha20-poly1305 */
  const char *disabled;          /* comma list or NULL */
  int refuse_terrapin_exposed;
  int initial;                   /* first KEX: add ext-info-c and kex-strict-c-v00@openssh.com */
  int compress;                  /* offer zlib@openssh.com first, then none (SD_SSH_CFG_COMPRESS) */
  int allow_legacy;              /* legacy_policy != REFUSE: legacy algorithms ranked last (D33) */
  const char *hostkey_only;      /* non-NULL: exact host-key list (fetch_hostkeys re-key, 01 §4.3) */
  /* availability; NULL = sd_pktcipher_find() / ssh_kex_supported() / ssh_hostkey_alg_supported().
     Used by tests. */
  int (*cipher_available)(const char *name);
  int (*kex_available)(const char *name);
  int (*hostkey_available)(const char *name);
} ssh_list_input;

typedef struct ssh_list_result {
  int strict;                    /* server KEXINIT has kex-strict-s-v00@openssh.com */
  int terrapin_exposed;          /* rule 3 of 01 §4.3: no unaffected pair, connecting anyway */
  int chacha_removed;            /* rule 2 applied in at least one direction */
  int etm_removed;               /* rule 2: CBC will be chosen, -etm MACs removed for that direction */
} ssh_list_result;

/* Builds the lists we send. Errors: SD_E_HOSTKEY_TYPE_UNAVAILABLE (stored types not supported),
   SD_E_KEX_FAILED (no algorithm left in a category, or refuse_terrapin_exposed). */
sd_err ssh_build_lists(const ssh_list_input *in, ssh_lists *out, ssh_list_result *res);

typedef struct ssh_algs {
  char kex[64], hostkey[64];
  char enc_c2s[64], enc_s2c[64], mac_c2s[64], mac_s2c[64];   /* mac "" for AEAD ciphers */
  char comp_c2s[32], comp_s2c[32];
} ssh_algs;

/* RFC 4253 §7.1: first entry of the client list that the server also lists. Returns 1 if found. */
int ssh_pick(const char *client_csv, sd_span server_list, char *out, size_t cap);
/* Negotiates every category. On failure *category names the one without overlap. */
sd_err ssh_negotiate(const ssh_lists *ours, const ssh_kexinit *server, ssh_algs *out, const char **category);
/* Encodes our KEXINIT payload (message byte included). */
void ssh_kexinit_encode(sd_wr *w, const uint8_t cookie[16], const ssh_lists *l);
int  ssh_cipher_is_aead(const char *name);
int  ssh_cipher_is_cbc(const char *name);
int  ssh_mac_is_etm(const char *name);
int  ssh_csv_contains(const char *csv, const char *name);
/* 1 for algorithms of the [legacy] tier of 01 §4.3. */
int  ssh_alg_is_legacy(const char *name);
/* Host key algorithm -> key blob type ("rsa-sha2-512" -> "ssh-rsa"; certs -> plain type); NULL if unknown. */
const char *ssh_hostkey_alg_key_type(const char *alg);
int  ssh_hostkey_alg_is_cert(const char *alg);
/* Plain (non-certificate) host key algorithms for a key type in static order, e.g. "ssh-rsa" ->
   "rsa-sha2-512,rsa-sha2-256[,ssh-rsa]". SD_E_HOSTKEY_TYPE_UNAVAILABLE when none is usable. */
sd_err ssh_hostkey_algs_for_type(const char *key_type, int allow_legacy, int (*avail)(const char *),
                                 char *out, size_t cap);
/* legacy_mask bits that follow from the negotiated names alone (01 §4.3); the KEX adds
   SD_LEGACY_DH_SMALL / SD_LEGACY_RSA_SHORT from the actual group and key. */
uint32_t ssh_legacy_mask_for(const ssh_algs *a, int strict);
/* Comma list of the negotiated legacy algorithm names (+ pseudo names for the other bits), for
   SD_PROMPT_LEGACY_ACK.legacy_names. */
void ssh_legacy_names(const ssh_algs *a, uint32_t mask, char *out, size_t cap);

/* ---- KEX methods and host keys (kex_methods.c, hostkey_verify.c) ---- */

/* 1 if the KEX method / host key algorithm is implemented with the crypto available now. */
int ssh_kex_supported(const char *name);
int ssh_hostkey_alg_supported(const char *name);

/* ---- binary packet protocol (packet.c) ---- */

/* Delayed compression of one direction (zlib@openssh.com, 01 section 4.7). The codec state survives re-keys;
   ssh_dir_clear frees it. */
typedef struct ssh_comp {
  int tx;                        /* 1: this is the sending direction */
  int on;                        /* compression active: after USERAUTH_SUCCESS, zlib@openssh.com negotiated */
  char name[24];                 /* negotiated algorithm for this direction at the last NEWKEYS */
  ssh_zdef *zdef;                /* tx codec */
  ssh_zinf *zinf;                /* rx codec */
  sd_wr zw;                      /* tx: compressed payload of the packet being sealed */
  uint8_t *zout;                 /* rx: decompressed payload, valid until the next ssh_pkt_open */
} ssh_comp;

typedef struct ssh_dir {
  const sd_pktcipher_info *ci;   /* NULL: no encryption (before the first NEWKEYS) */
  sd_pktcipher *pc;
  int mac_on, etm;
  sd_hash_alg mac_hash;
  size_t mac_len;
  sd_hmac_ctx hmac;
  uint32_t block;                /* alignment unit: max(8, cipher block) */
  uint32_t seq;
  uint64_t bytes;                /* payload bytes since the last NEWKEYS of this direction */
  uint32_t packets;              /* packets since the last NEWKEYS */
  /* receive-side partial state */
  int rx_have_len;
  uint32_t rx_len;
  size_t rx_discard;             /* CBC + non-ETM MAC failure: fail once this many bytes are buffered */
  ssh_comp comp;                 /* survives ssh_dir_set_keys (re-keys); freed by ssh_dir_clear */
} ssh_dir;

void   ssh_dir_init(ssh_dir *d);
void   ssh_dir_clear(ssh_dir *d);        /* frees the cipher and compression state, wipes keys; keeps seq */
/* Records the algorithm negotiated for this direction (NEWKEYS). Any other name than zlib@openssh.com
   ends compression in this direction. */
void   ssh_dir_set_comp_name(ssh_dir *d, const char *name);
/* Activates the recorded zlib@openssh.com for this direction (after USERAUTH_SUCCESS). No-op for none. */
sd_err ssh_dir_comp_start(ssh_dir *d);
/* Installs new keys. cipher/mac are negotiated names; mac ignored for AEAD. */
sd_err ssh_dir_set_keys(ssh_dir *d, int encrypt, const char *cipher, const char *mac,
                        const uint8_t *key, const uint8_t *iv, const uint8_t *mac_key);
/* Key/IV/MAC-key sizes needed for the pair (for key derivation). */
sd_err ssh_alg_key_sizes(const char *cipher, const char *mac, size_t *key_len, size_t *iv_len,
                         size_t *mac_key_len);

/* Appends one packet carrying payload to out. */
sd_err ssh_pkt_seal(ssh_dir *d, const uint8_t *payload, size_t n, sd_wr *out);
/* Tries to take one packet from buf (decrypting in place). SD_OK with payload->p == NULL means more
   input is needed (state is kept in d; do not move the unconsumed bytes relative to each other).
   SD_E_PROTOCOL: bad framing; SD_E_CRYPTO: MAC/tag failure. */
sd_err ssh_pkt_open(ssh_dir *d, uint8_t *buf, size_t avail, size_t *consumed, sd_span *payload);

/* ---- version exchange (negotiate.c) ---- */

/* Scans buffered input for the server identification line (01 §4.1). Returns SD_OK with *line_len
   (> 0, bytes including the line end consumed) when a line is complete; *is_ident set when it is the
   SSH-2.0/SSH-1.99 line, in which case ident receives it without CR/LF. *line_len == 0 means more
   input is needed. SD_E_PROTOCOL on an over-long line or other protocol versions. */
sd_err ssh_version_line(const uint8_t *buf, size_t n, size_t *line_len, int *is_ident, char *ident,
                        size_t ident_cap);

/* ---- known_hosts helpers exposed for unit tests (known_hosts.c) ---- */

/* OpenSSH-style host pattern list match: 1 = match, 0 = no match, -1 = negated match (veto). */
int ssh_kh_match_patterns(const char *patterns, size_t plen, const char *name);
/* 1 if every positive pattern consists only of '*', '?' and '.' (with or without [..]:port). */
int ssh_kh_wildcard_only(const char *patterns, size_t plen);
/* known_hosts lookup name: lowercase host, "[host]:port" when port != 22. */
sd_err ssh_kh_lookup_name(const char *host_utf8, uint16_t port, char *out, size_t cap);
/* In-memory variant of sd_known_hosts_check over one file's bytes (used by tests and the store). */
sd_err ssh_kh_check_buffer(const char *text, size_t len, const char *lookup_name, const uint8_t *blob,
                           size_t blob_len, sd_hk_result *res, int *found_other_types);
sd_err ssh_kh_types_buffer(const char *text, size_t len, const char *lookup_name, sd_kh_types *out);

#endif /* SD_SSH_INTERNAL_H */
