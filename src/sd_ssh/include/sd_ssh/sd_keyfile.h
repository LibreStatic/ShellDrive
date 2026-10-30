/* Private/public key file parsing (01 §6.3, §6.6). Private keys: OpenSSH v1 "openssh-key-v1"
 * (Ed25519, ECDSA P-256/384/521, RSA; unencrypted or bcrypt with any OpenSSH cipher), PEM PKCS#1
 * "RSA PRIVATE KEY" and SEC1 "EC PRIVATE KEY" (plain or legacy DEK-Info encrypted), PKCS#8
 * "PRIVATE KEY" and "ENCRYPTED PRIVATE KEY" (PBES2/PBKDF2), PuTTY PPK v2 and v3 (Argon2).
 * Public keys: OpenSSH one-line, RFC 4716 and "*-cert.pub" files; OpenSSH user certificates.
 * DPAPI-kept keys (03 §4.4, review C22): SDKEY1 files.
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

enum { SD_KEYFMT_OPENSSH = 1, SD_KEYFMT_PEM = 2, SD_KEYFMT_PKCS8 = 3, SD_KEYFMT_PPK2 = 4, SD_KEYFMT_PPK3 = 5,
       SD_KEYFMT_SDKEY = 6 };

typedef struct sd_ssh_key_probe_info {
  char type[48];                  /* "ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa", ... */
  uint32_t bits;
  int encrypted;                  /* passphrase required */
  uint8_t pub_blob[1024]; size_t pub_len;   /* 0 for encrypted PEM/PKCS#8 files without a public part */
  char fp_sha256[64];             /* "SHA256:..." ("" when pub_len is 0) */
  int format;                     /* SD_KEYFMT_* */
} sd_ssh_key_probe_info;

/* No KDF runs; safe on any thread. */
sd_err sd_ssh_key_probe(const uint8_t *bytes, size_t len, sd_ssh_key_probe_info *out);

/* Errors: SD_E_KEY_FORMAT, SD_E_KEY_UNSUPPORTED, SD_E_KEY_PASSPHRASE_REQUIRED (pass == NULL on an
   encrypted key), SD_E_BAD_PASSPHRASE, SD_E_NO_MEMORY (e.g. Argon2 memory on x86). */
sd_err sd_ssh_key_load(const uint8_t *bytes, size_t len, const char *pass, size_t pass_len,
                       sd_ssh_key **out);
void   sd_ssh_key_free(sd_ssh_key *k);

/* Public key blob (SSH wire format) and algorithm name; pointers live as long as the key. The blob
   and type are always those of the plain key, also when a certificate is attached. */
const uint8_t *sd_ssh_key_public_blob(const sd_ssh_key *k, size_t *len);
const char    *sd_ssh_key_type(const sd_ssh_key *k);
uint32_t       sd_ssh_key_bits(const sd_ssh_key *k);
const char    *sd_ssh_key_comment(const sd_ssh_key *k);   /* "" when none */

/* Signs data for publickey auth (SSH wire signature blob) with the key's default algorithm
   (ssh-ed25519, ecdsa-sha2-nistpNNN, rsa-sha2-512 for RSA). */
sd_err sd_ssh_key_sign(const sd_ssh_key *k, const uint8_t *data, size_t len, uint8_t *sig,
                       size_t sig_cap, size_t *sig_len);
/* Same with an explicit signature algorithm: for RSA "rsa-sha2-512", "rsa-sha2-256" or "ssh-rsa";
   other keys accept only their own type (or the matching *-cert-v01@openssh.com name).
   SD_E_KEY_UNSUPPORTED for an algorithm the key cannot produce. */
sd_err sd_ssh_key_sign_alg(const sd_ssh_key *k, const char *alg, const uint8_t *data, size_t len,
                           uint8_t *sig, size_t sig_cap, size_t *sig_len);

/* Serializes a decrypted key as an unencrypted OpenSSH v1 file into a secret buffer (DPAPI storage). */
sd_err sd_ssh_key_serialize_openssh(const sd_ssh_key *k, sd_secbuf **out);

/* ---- OpenSSH certificates (01 §6.3) ---- */

enum { SD_CERT_USER = 1, SD_CERT_HOST = 2 };
#define SD_CERT_FOREVER 0xFFFFFFFFFFFFFFFFull

typedef struct sd_ssh_cert_info {
  char type[64];                  /* "ssh-ed25519-cert-v01@openssh.com", ... */
  char key_type[48];              /* plain type of the certified key, "ssh-ed25519", ... */
  uint64_t serial;
  uint32_t cert_type;             /* SD_CERT_USER / SD_CERT_HOST */
  char key_id[256];               /* sanitized, truncated */
  char principals[512];           /* comma-separated, sanitized, truncated; "" = any */
  uint32_t principal_count;
  uint64_t valid_after, valid_before;   /* seconds since 1970; valid_before SD_CERT_FOREVER = forever */
  uint8_t key_blob[1024]; size_t key_len;   /* the plain public key it certifies */
  char ca_fp_sha256[64];          /* fingerprint of the signature (CA) key */
} sd_ssh_cert_info;

/* Parses a certificate blob (SSH wire format, as in a *-cert.pub file after base64). Structure
   only: the CA signature is not verified (the server enforces it). */
sd_err sd_ssh_cert_parse(const uint8_t *blob, size_t len, sd_ssh_cert_info *out);
/* 1 when now (seconds since 1970) lies in [valid_after, valid_before). */
int    sd_ssh_cert_valid_at(const sd_ssh_cert_info *ci, uint64_t now);

/* Public key files: OpenSSH one-line ("type base64 [comment]", also *-cert.pub) and RFC 4716
   ("---- BEGIN SSH2 PUBLIC KEY ----"). The first key of the file is returned. type receives the
   algorithm name of the blob. SD_E_KEY_FORMAT on malformed input. */
sd_err sd_ssh_pubkey_parse(const uint8_t *bytes, size_t len, uint8_t *blob, size_t blob_cap,
                           size_t *blob_len, char *type, size_t type_cap);

/* Attaches a user certificate to a key: the certificate's embedded public key must equal the key's
   (SD_E_KEY_FORMAT otherwise). Replaces an attached certificate. */
sd_err sd_ssh_key_attach_cert(sd_ssh_key *k, const uint8_t *cert, size_t cert_len);
/* Attached certificate blob, or NULL. */
const uint8_t *sd_ssh_key_cert_blob(const sd_ssh_key *k, size_t *len);

/* ---- DPAPI-kept keys (03 §4.4, review C22) ----
 * File layout (all integers big-endian, strings are uint32 length + bytes as on the SSH wire):
 *   "SDKEY1\0\0" | uint32 version = 1 | string key type | string public blob | string comment |
 *   string DPAPI blob
 * The DPAPI blob is CryptProtectData (user scope of the calling thread, CRYPTPROTECT_UI_FORBIDDEN,
 * entropy "com.librestatic.shelldrive/key/v1/" + id, description = descr) over the key as an
 * unencrypted OpenSSH v1 file. The service calls the same functions as LocalSystem (03 §4.5). */

typedef struct sd_ssh_dpapi_info {
  char type[48];
  uint8_t pub_blob[1024]; size_t pub_len;
  char fp_sha256[64];
  char comment[256];              /* sanitized, truncated */
} sd_ssh_dpapi_info;

/* Protects k into a new SDKEY1 file image (sd_alloc'ed; free with sd_free). id: the key id (UTF-8,
   non-empty); descr: shown by DPAPI tooling (may be NULL). */
sd_err sd_ssh_key_dpapi_protect(const sd_ssh_key *k, const char *id, const wchar_t *descr,
                                uint8_t **out, size_t *out_len);
/* Reads the clear metadata; no decryption. */
sd_err sd_ssh_key_dpapi_probe(const uint8_t *bytes, size_t len, sd_ssh_dpapi_info *out);
/* Decrypts an SDKEY1 image into the unencrypted OpenSSH v1 key file bytes, ready for SD_ID_BLOB or
   sd_ssh_key_load. SD_E_ACCESS_DENIED when DPAPI refuses (other user, wrong id, reset password);
   SD_E_KEY_FORMAT when the image is malformed or the decrypted key does not match the clear public
   blob. */
sd_err sd_ssh_key_dpapi_unprotect(const uint8_t *bytes, size_t len, const char *id, sd_secbuf **out);

#endif /* SD_KEYFILE_H */
