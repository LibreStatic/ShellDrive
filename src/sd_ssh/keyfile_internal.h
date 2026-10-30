/* Private declarations shared by the key file units (keyfile*.c; 01 §6.3, §6.6). No transport
 * dependency: the CLI and UI link these units without conn.c.
 *
 *   keyfile.c          format detection, sd_ssh_key object, signing, OpenSSH serializer
 *   keyfile_openssh.c  OpenSSH v1 "openssh-key-v1" (all key types, every OpenSSH cipher)
 *   keyfile_der.c      strict minimal DER reader
 *   keyfile_pem.c      PEM: PKCS#1, SEC1, PKCS#8 (plain and PBES2), legacy DEK-Info encryption
 *   keyfile_ppk.c      PuTTY PPK v2 and v3 (Argon2)
 *   keyfile_cert.c     OpenSSH certificates and public key files
 *   keyfile_dpapi.c    DPAPI-kept keys (03 §4.4, review C22)
 *
 * Every parser takes bytes, never paths, and returns SD_E_KEY_FORMAT, SD_E_KEY_UNSUPPORTED,
 * SD_E_KEY_PASSPHRASE_REQUIRED or SD_E_BAD_PASSPHRASE on failure. */
#ifndef SD_SSH_KEYFILE_INTERNAL_H
#define SD_SSH_KEYFILE_INTERNAL_H

#include "sd/base.h"
#include "sd_base/sd_buf.h"
#include "sd_base/sd_err.h"
#include "sd_platform/sd_secbuf.h"
#include "sd_ssh/sd_keyfile.h"

#define SSH_KEY_MAX_FILE  (1024u * 1024u)
#define SSH_RSA_MIN_BITS  1024u
#define SSH_RSA_MAX_BITS  16384u
#define SSH_RSA_MAX_BYTES (SSH_RSA_MAX_BITS / 8u)

typedef enum ssh_kt { SSH_KT_NONE = 0, SSH_KT_ED25519, SSH_KT_ECDSA, SSH_KT_RSA } ssh_kt;

struct sd_ssh_key {
  ssh_kt kt;
  char type[48];                 /* plain algorithm: "ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa" */
  uint32_t bits;
  uint32_t curve;                /* ECDSA: 256, 384 or 521 */
  uint8_t *pub; size_t pub_len;  /* plain public key blob (SSH wire format) */
  /* private part:
     ed25519  seed(32) || pub(32)
     ecdsa    d as a fixed-length big-endian scalar (32, 48 or 66 bytes)
     rsa      SSH wire mpints n, e, d, iqmp, p, q (canonical magnitudes) */
  sd_secbuf *priv;
  char *comment;
  uint8_t *cert; size_t cert_len;   /* attached user certificate blob, or NULL */
  char cert_type[64];
  struct sd_rsa_key *rsa;           /* imported once at construction (sd_crypto_pk.h) */
  struct sd_ec_key *ec;
};

/* ---- curves ---- */

/* 256 / 384 / 521 for "nistp256" / "nistp384" / "nistp521"; 0 otherwise. */
uint32_t ssh_curve_from_name(sd_span name);
const char *ssh_curve_name(uint32_t curve);        /* "nistp256", ... */
size_t ssh_curve_bytes(uint32_t curve);            /* 32, 48, 66 */

/* ---- key construction (keyfile.c). Inputs are copied; the result is validated where the math is
   available (Ed25519 seed -> public key, ECDSA d*G == Q, RSA n == p*q). pub may be NULL: it is then
   derived (Ed25519, ECDSA). Comment may be NULL. ---- */

sd_err ssh_key_new_ed25519(const uint8_t seed[32], const uint8_t *pub32, sd_span comment, sd_ssh_key **out);
sd_err ssh_key_new_ecdsa(uint32_t curve, sd_span q, sd_span d, sd_span comment, sd_ssh_key **out);
/* iqmp may be empty (computed when possible). */
sd_err ssh_key_new_rsa(sd_span n, sd_span e, sd_span d, sd_span iqmp, sd_span p, sd_span q, sd_span comment,
                       sd_ssh_key **out);

/* Checks that a public blob is a well-formed plain public key and returns its kind (bits/curve
   optional). SD_E_KEY_UNSUPPORTED for unknown or too small/large types. */
sd_err ssh_pubblob_info(const uint8_t *blob, size_t len, ssh_kt *kt, uint32_t *bits, uint32_t *curve);
/* 1 when a public blob equals the key's public blob. */
int ssh_key_pub_equal(const sd_ssh_key *k, const uint8_t *blob, size_t len);

/* ---- format units ---- */

/* OpenSSH v1 (keyfile_openssh.c). `body` is the text after leading blanks. */
sd_err ssh_ossh_probe(const uint8_t *bytes, size_t len, sd_ssh_key_probe_info *out);
sd_err ssh_ossh_load(const uint8_t *bytes, size_t len, const char *pass, size_t pass_len, sd_ssh_key **out);
/* Serializer used by sd_ssh_key_serialize_openssh(). */
sd_err ssh_ossh_serialize(const sd_ssh_key *k, sd_secbuf **out);

/* PEM (keyfile_pem.c). */
sd_err ssh_pem_probe(const uint8_t *bytes, size_t len, sd_ssh_key_probe_info *out);
sd_err ssh_pem_load(const uint8_t *bytes, size_t len, const char *pass, size_t pass_len, sd_ssh_key **out);

/* PuTTY PPK (keyfile_ppk.c). */
sd_err ssh_ppk_probe(const uint8_t *bytes, size_t len, sd_ssh_key_probe_info *out);
sd_err ssh_ppk_load(const uint8_t *bytes, size_t len, const char *pass, size_t pass_len, sd_ssh_key **out);

/* Fills type/bits/fingerprint of a probe result from a public blob (pub_len 0 allowed). */
void ssh_probe_fill_from_pub(sd_ssh_key_probe_info *out, const uint8_t *blob, size_t len);

/* ---- DER (keyfile_der.c): strict, definite lengths only, max depth 8 ---- */

typedef struct ssh_der {
  const uint8_t *p; size_t n;    /* remaining input */
  int err;
  int depth;
} ssh_der;

enum {
  SSH_DER_INTEGER = 0x02, SSH_DER_BIT_STRING = 0x03, SSH_DER_OCTET_STRING = 0x04, SSH_DER_NULL = 0x05,
  SSH_DER_OID = 0x06, SSH_DER_SEQUENCE = 0x30, SSH_DER_CTX0 = 0xA0, SSH_DER_CTX1 = 0xA1
};

void    ssh_der_init(ssh_der *d, const uint8_t *p, size_t n);
/* Reads one TLV with the given tag; returns its contents. Errors are sticky. */
sd_span ssh_der_tlv(ssh_der *d, uint8_t tag);
/* Enters a constructed element (SEQUENCE or context tag): returns a reader over its contents. */
ssh_der ssh_der_enter(ssh_der *d, uint8_t tag);
/* INTEGER as an unsigned magnitude (leading zero removed); negative values are an error. */
sd_span ssh_der_uint(ssh_der *d);
/* Small non-negative INTEGER (<= 2^31-1). */
uint32_t ssh_der_small(ssh_der *d);
/* 1 when the next element has this tag (without consuming it). */
int     ssh_der_peek(const ssh_der *d, uint8_t tag);
int     ssh_der_ok(const ssh_der *d);
int     ssh_der_done(const ssh_der *d);     /* ok and nothing left */
/* Compares an OID's contents with a dotted string ("1.2.840.113549.1.1.1"). */
int     ssh_der_oid_is(sd_span oid, const char *dotted);

/* ---- certificates (keyfile_cert.c) ---- */

/* Extracts the plain public key blob embedded in a certificate into out (cap bytes). */
sd_err ssh_cert_plain_pub(const uint8_t *cert, size_t len, uint8_t *out, size_t cap, size_t *out_len);
/* 1 for "*-cert-v01@openssh.com" type names; the base (plain) algorithm goes to base. */
int ssh_cert_type_base(sd_span type, char *base, size_t cap);

#endif /* SD_SSH_KEYFILE_INTERNAL_H */
