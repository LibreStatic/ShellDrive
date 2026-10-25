/* DPAPI-kept private keys (03 §4.4, review C22): SDKEY1 images. Clear metadata (type, public blob,
 * comment) lets the UI list keys without decrypting; the private part is an unencrypted OpenSSH v1
 * key file protected with CryptProtectData in the calling thread's user scope (LocalSystem for the
 * service, 03 §4.5). No transport dependency. */
#include <windows.h>
#include <wincrypt.h>
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_base/sd_utf.h"
#include "sd_ssh/sd_known_hosts.h"
#include "keyfile_internal.h"
#include "ssh_internal.h"

#pragma comment(lib, "crypt32.lib")

static const uint8_t k_sdkey_magic[8] = { 'S', 'D', 'K', 'E', 'Y', '1', 0, 0 };
static const char k_entropy_prefix[] = "com.librestatic.shelldrive/key/v1/";
#define SDKEY_VERSION 1u
#define SDKEY_MAX_ID  256u

static sd_err make_entropy(const char *id, uint8_t *buf, size_t cap, DATA_BLOB *out)
{
  size_t pl = sizeof(k_entropy_prefix) - 1, il;
  if (!id || !id[0]) return SD_E_INVALID_PARAM;
  il = strlen(id);
  if (il > SDKEY_MAX_ID || pl + il > cap) return SD_E_INVALID_PARAM;
  memcpy(buf, k_entropy_prefix, pl);
  memcpy(buf + pl, id, il);
  out->pbData = buf;
  out->cbData = (DWORD)(pl + il);
  return SD_OK;
}

typedef struct sdkey_parts { sd_span type, pub, comment, blob; } sdkey_parts;

static sd_err sdkey_split(const uint8_t *bytes, size_t len, sdkey_parts *p)
{
  sd_rd r;
  sd_span magic;
  uint32_t ver;
  if (!bytes || len > SSH_KEY_MAX_FILE) return SD_E_KEY_FORMAT;
  sd_rd_init(&r, bytes, len);
  magic = sd_rd_bytes(&r, 8);
  ver = sd_rd_u32(&r);
  if (!sd_rd_ok(&r) || memcmp(magic.p, k_sdkey_magic, 8) != 0) return SD_E_KEY_FORMAT;
  if (ver != SDKEY_VERSION) return SD_E_KEY_UNSUPPORTED;
  p->type = sd_rd_string(&r, 64);
  p->pub = sd_rd_string(&r, 1024);
  p->comment = sd_rd_string(&r, 4096);
  p->blob = sd_rd_string(&r, SSH_KEY_MAX_FILE);
  if (!sd_rd_done(&r) || !p->type.n || !p->pub.n || !p->blob.n) return SD_E_KEY_FORMAT;
  {
    sd_span t = ssh_blob_key_type(p->pub.p, p->pub.n);
    if (t.n != p->type.n || memcmp(t.p, p->type.p, t.n) != 0) return SD_E_KEY_FORMAT;
  }
  return SD_OK;
}

sd_err sd_ssh_key_dpapi_protect(const sd_ssh_key *k, const char *id, const wchar_t *descr, uint8_t **out,
                                size_t *out_len)
{
  sd_secbuf *plain = NULL;
  uint8_t ent[sizeof(k_entropy_prefix) + SDKEY_MAX_ID];
  DATA_BLOB in, entropy, blob;
  sd_wr w;
  sd_err e;
  if (!k || !out || !out_len) return SD_E_INVALID_PARAM;
  *out = NULL;
  *out_len = 0;
  e = make_entropy(id, ent, sizeof(ent), &entropy);
  if (e != SD_OK) return e;
  e = sd_ssh_key_serialize_openssh(k, &plain);
  if (e != SD_OK) return e;
  in.pbData = plain->p;
  in.cbData = (DWORD)plain->len;
  memset(&blob, 0, sizeof(blob));
  if (!CryptProtectData(&in, descr ? descr : L"ShellDrive key", &entropy, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &blob)) {
    sd_secbuf_free(plain);
    return SD_E_ACCESS_DENIED;
  }
  sd_secbuf_free(plain);
  sd_wr_init(&w, SSH_KEY_MAX_FILE);
  sd_wr_bytes(&w, k_sdkey_magic, 8);
  sd_wr_u32(&w, SDKEY_VERSION);
  sd_wr_cstring(&w, k->type);
  sd_wr_string(&w, k->pub, k->pub_len);
  sd_wr_cstring(&w, k->comment ? k->comment : "");
  sd_wr_string(&w, blob.pbData, blob.cbData);
  LocalFree(blob.pbData);
  if (!sd_wr_ok(&w)) { sd_wr_free(&w); return SD_E_NO_MEMORY; }
  *out = w.p;            /* the writer's buffer comes from sd_alloc */
  *out_len = w.len;
  return SD_OK;
}

sd_err sd_ssh_key_dpapi_probe(const uint8_t *bytes, size_t len, sd_ssh_dpapi_info *out)
{
  sdkey_parts p;
  size_t ol = 0;
  sd_err e;
  if (!out) return SD_E_INVALID_PARAM;
  memset(out, 0, sizeof(*out));
  e = sdkey_split(bytes, len, &p);
  if (e != SD_OK) return e;
  if (!ssh_span_copy(p.type, out->type, sizeof(out->type)) || p.pub.n > sizeof(out->pub_blob)) return SD_E_KEY_FORMAT;
  memcpy(out->pub_blob, p.pub.p, p.pub.n);
  out->pub_len = p.pub.n;
  if (sd_hostkey_fingerprint_sha256(p.pub.p, p.pub.n, out->fp_sha256) != SD_OK) out->fp_sha256[0] = '\0';
  if (sd_text_sanitize_server((const char *)p.comment.p, SD_MIN(p.comment.n, (size_t)80), out->comment,
                              sizeof(out->comment) - 1, &ol) != SD_OK)
    ol = 0;
  out->comment[ol] = '\0';
  return SD_OK;
}

sd_err sd_ssh_key_dpapi_unprotect(const uint8_t *bytes, size_t len, const char *id, sd_secbuf **out)
{
  sdkey_parts p;
  uint8_t ent[sizeof(k_entropy_prefix) + SDKEY_MAX_ID];
  DATA_BLOB in, entropy, plain;
  sd_ssh_key *k = NULL;
  sd_secbuf *sb = NULL;
  sd_err e;
  if (!out) return SD_E_INVALID_PARAM;
  *out = NULL;
  e = sdkey_split(bytes, len, &p);
  if (e != SD_OK) return e;
  e = make_entropy(id, ent, sizeof(ent), &entropy);
  if (e != SD_OK) return e;
  in.pbData = (BYTE *)p.blob.p;
  in.cbData = (DWORD)p.blob.n;
  memset(&plain, 0, sizeof(plain));
  if (!CryptUnprotectData(&in, NULL, &entropy, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &plain)) return SD_E_ACCESS_DENIED;
  e = sd_secbuf_from(plain.pbData, plain.cbData, &sb);
  SecureZeroMemory(plain.pbData, plain.cbData);
  LocalFree(plain.pbData);
  if (e != SD_OK) return e;
  /* the protected key must be the one the clear metadata describes */
  e = ssh_ossh_load(sb->p, sb->len, NULL, 0, &k);
  if (e != SD_OK || !ssh_key_pub_equal(k, p.pub.p, p.pub.n)) {
    sd_ssh_key_free(k);
    sd_secbuf_free(sb);
    return e == SD_E_UNSUPPORTED ? e : SD_E_KEY_FORMAT;
  }
  sd_ssh_key_free(k);
  *out = sb;
  return SD_OK;
}
