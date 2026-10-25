/* sd_ssh private: public host keys, signature verification and OpenSSH certificates
 * (RFC 4253 §6.6, RFC 5656, RFC 8332, RFC 8709, OpenSSH PROTOCOL.certkeys). Used by the KEX (server
 * signature over H), UpdateHostKeys proofs (01 §7.5) and known_hosts (@cert-authority, PuTTY
 * conversion, 01 §7.1-§7.3). No transport dependency: the CLI and UI link it with known_hosts.c.
 * Everything here handles public values only (variable time is fine). */
#ifndef SD_SSH_HOSTKEY_INTERNAL_H
#define SD_SSH_HOSTKEY_INTERNAL_H

#include "sd/base.h"
#include "sd_base/sd_buf.h"
#include "sd_base/sd_err.h"
#include "sd_crypto/sd_crypto.h"

#define SSH_HOSTKEY_MAX 16384u          /* longest host key / certificate blob we accept */

typedef enum ssh_pk_kind { SSH_PK_NONE, SSH_PK_ED25519, SSH_PK_ECDSA, SSH_PK_RSA } ssh_pk_kind;

/* A parsed plain public key. */
typedef struct ssh_pubkey {
  ssh_pk_kind kind;
  char type[24];                        /* "ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa" */
  uint8_t ed[32];                       /* SSH_PK_ED25519 */
  sd_curve curve;                       /* SSH_PK_ECDSA */
  sd_ec_key *ec;
  sd_rsa_key *rsa;                      /* SSH_PK_RSA */
  uint32_t bits;                        /* 256 for ed25519, curve bits, RSA modulus bits */
} ssh_pubkey;

/* Parses a plain public key blob (no certificates). SD_E_KEY_UNSUPPORTED for other key types,
   SD_E_KEY_FORMAT / SD_E_CRYPTO for malformed keys or invalid points. Free with ssh_pubkey_free. */
sd_err ssh_pubkey_parse(const uint8_t *blob, size_t len, ssh_pubkey *out);
void   ssh_pubkey_free(ssh_pubkey *k);

/* Verifies an SSH signature blob (string alg || string sig) over data with key k.
   sig_alg: the algorithm the signature must use (e.g. "rsa-sha2-512"); NULL accepts any algorithm
   valid for the key type (for RSA: rsa-sha2-512, rsa-sha2-256 and, if allow_sha1, ssh-rsa).
   SD_OK or SD_E_CRYPTO (also for a malformed blob or a disallowed algorithm). */
sd_err ssh_pubkey_verify(const ssh_pubkey *k, const char *sig_alg, int allow_sha1, const uint8_t *sig,
                         size_t sig_len, const uint8_t *data, size_t dlen);

/* OpenSSH certificate (PROTOCOL.certkeys). Spans point into the parsed blob. */
#define SSH_CERT_TYPE_USER 1u
#define SSH_CERT_TYPE_HOST 2u
typedef struct ssh_cert {
  char cert_type[48];                   /* "ssh-ed25519-cert-v01@openssh.com", ... */
  ssh_pubkey key;                       /* embedded key */
  uint8_t *plain; size_t plain_len;     /* the embedded key as a plain public key blob (allocated) */
  uint64_t serial;
  uint32_t type;
  sd_span key_id, principals, critical, extensions, sig_key, signature;
  uint64_t valid_after, valid_before;
  size_t signed_len;                    /* bytes of the blob covered by the CA signature */
} ssh_cert;

/* 1 if the blob's type is an OpenSSH certificate type we know. */
int    ssh_blob_is_cert(const uint8_t *blob, size_t len);
sd_err ssh_cert_parse(const uint8_t *blob, size_t len, ssh_cert *out);
void   ssh_cert_free(ssh_cert *c);
/* Host certificate checks of 01 §7.1 except the CA trust decision: type host, host (lookup name
   without "[...]:port") in a non-empty principal list, valid_after <= now < valid_before with 5
   minutes of skew, no critical options, CA key a plain key, CA signature valid (rsa-sha2-256/512,
   ECDSA, Ed25519; ssh-rsa is refused). SD_OK, or SD_E_HOSTKEY_REJECTED with *why set. */
sd_err ssh_cert_check_host(const ssh_cert *c, const uint8_t *blob, const char *host, uint64_t now_unix,
                           const char **why);

/* The plain key of a blob: a copy of the blob itself for plain keys, the embedded key for
   certificates. *out is allocated (sd_free). */
sd_err ssh_blob_plain_key(const uint8_t *blob, size_t len, uint8_t **out, size_t *out_len);

/* KEX host key signature (01 §4.2): ks is K_S, alg the negotiated host key algorithm, sig the
   signature blob over h. The key type inside ks must belong to alg; for certificate algorithms the
   embedded key is used (trust in the CA is known_hosts' decision). *bits receives the key size.
   SD_OK, SD_E_KEX_FAILED (type mismatch / unsupported) or SD_E_CRYPTO (bad signature). */
sd_err ssh_hostkey_verify_kex(const char *alg, const uint8_t *ks, size_t ks_len, const uint8_t *sig,
                              size_t sig_len, const uint8_t *h, size_t hlen, uint32_t *bits);

/* Key size in bits for display (prompt key_bits); 0 if the blob does not parse. */
uint32_t ssh_blob_key_bits(const uint8_t *blob, size_t len);

#endif /* SD_SSH_HOSTKEY_INTERNAL_H */
