/* Private/public key file parsing (01 §6.6). M0: OpenSSH v1 "openssh-key-v1" Ed25519 keys,
 * unencrypted and bcrypt + aes256-ctr encrypted. Later: ECDSA/RSA, PEM/PKCS#8, PPK v2/v3.
 *
 * Parsers take bytes, never paths: the caller reads the file on a worker thread. KDFs can take long:
 * never call sd_ssh_key_load on an I/O thread. No transport dependency (the CLI/UI link this unit).
 *
 * Ownership: sd_ssh_key holds its private part in secret buffers; free with sd_ssh_key_free.
 * Thread safety: functions are reentrant; a key object may be shared read-only between threads. */
#ifndef SD_KEYFILE_H
#define SD_KEYFILE_H

#include "sd/base.h"
#include "sd_base/sd_err.h"
#include "sd_platform/sd_secbuf.h"

typedef struct sd_ssh_key sd_ssh_key;

enum { SD_KEYFMT_OPENSSH = 1, SD_KEYFMT_PEM = 2, SD_KEYFMT_PKCS8 = 3, SD_KEYFMT_PPK2 = 4, SD_KEYFMT_PPK3 = 5 };

typedef struct sd_ssh_key_probe_info {
  char type[48];                  /* "ssh-ed25519", ... */
  uint32_t bits;
  int encrypted;                  /* passphrase required */
  uint8_t pub_blob[1024]; size_t pub_len;
  char fp_sha256[64];             /* "SHA256:..." */
  int format;                     /* SD_KEYFMT_* */
} sd_ssh_key_probe_info;

/* No KDF runs; safe on any thread. */
sd_err sd_ssh_key_probe(const uint8_t *bytes, size_t len, sd_ssh_key_probe_info *out);

/* Errors: SD_E_KEY_FORMAT, SD_E_KEY_UNSUPPORTED, SD_E_KEY_PASSPHRASE_REQUIRED (pass == NULL on an
   encrypted key), SD_E_BAD_PASSPHRASE. */
sd_err sd_ssh_key_load(const uint8_t *bytes, size_t len, const char *pass, size_t pass_len,
                       sd_ssh_key **out);
void   sd_ssh_key_free(sd_ssh_key *k);

/* Public key blob (SSH wire format) and algorithm name; pointers live as long as the key. */
const uint8_t *sd_ssh_key_public_blob(const sd_ssh_key *k, size_t *len);
const char    *sd_ssh_key_type(const sd_ssh_key *k);

/* Signs data for publickey auth (e.g. "ssh-ed25519" signature blob, SSH wire format). */
sd_err sd_ssh_key_sign(const sd_ssh_key *k, const uint8_t *data, size_t len, uint8_t *sig,
                       size_t sig_cap, size_t *sig_len);

/* Serializes a decrypted key as an unencrypted OpenSSH v1 file into a secret buffer (DPAPI storage). */
sd_err sd_ssh_key_serialize_openssh(const sd_ssh_key *k, sd_secbuf **out);

#endif /* SD_KEYFILE_H */
