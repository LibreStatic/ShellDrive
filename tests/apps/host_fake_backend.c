/* Mount backend of the test host (sd-test-host-fake.exe): the scripted fake of tests/unit/sd_mount.
 * SHELLDRIVE_TEST_WB_DIRTY=<bytes> reports that much write-behind data queued on every mount (cache.clear
 * refusal tests); the agent reads it when it asks for the backend, so the variable must be set before it starts.
 * SHELLDRIVE_TEST_WD_NOAUTH=1 makes WebClient startable and the WebDAV start fail without SSPI (TM-R19 tests).
 *
 * hostkey add (a hostkey mount on a fake connection) is scripted by the host name, so the smoke tests need no network:
 *   *.known.test      a stored key verifies the connection; the server has an ECDSA and an ssh-rsa key besides it
 *   *.changed.test    the stored key does not match (SD_E_HOSTKEY_MISMATCH)
 *   anything else     first contact: the server presents one ssh-ed25519 key (TOFU, 5.2) */
#include <windows.h>
#include <stdlib.h>
#include <string.h>

#include "host.h"
#include "sd_base/sd_mem.h"
#include "sd_config/sd_config.h"
#include "fake_backend.h"

static sd_mount_backend k_host;
static int k_host_ready;

static void put_u32(uint8_t *p, uint32_t v)
{
  p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

/* one ssh string (RFC 4251: uint32 length, bytes) at offset at; returns the offset after it */
static size_t put_str(uint8_t *p, size_t at, const void *s, size_t n)
{
  put_u32(p + at, (uint32_t)n);
  memcpy(p + at + 4, s, n);
  return at + 4 + n;
}

static int ends_with(const char *s, const char *suffix)
{
  size_t n = strlen(s), m = strlen(suffix);
  return n >= m && _stricmp(s + n - m, suffix) == 0;
}

/* appends one synthetic key (the bytes need not be a valid curve point: only the type and the blob are kept) */
static void add_key(sd_mount_hk_fetch *out, const char *type, const uint8_t *blob, size_t len)
{
  sd_mount_hostkey *k = &out->keys[out->count++];
  memset(k, 0, sizeof(*k));
  strcpy_s(k->type, sizeof(k->type), type);
  memcpy(k->blob, blob, len);
  k->len = len;
}


/* The fake keeps no known_hosts, so hostkey add would store nothing and the smoke tests could not read the keys
   back. The apply writes the real user store under the test configuration root (the CLI reads the same file). */
static sd_err hk_apply_user_store(sd_known_hosts *kh, sd_kh_store_kind target, const char *name, const sd_hk_key *add,
                                  uint32_t add_count, const sd_hk_key *remove, uint32_t remove_count)
{
  static wchar_t path[MAX_PATH];
  sd_kh_store st;
  sd_known_hosts *real = NULL;
  sd_err e;
  SD_UNUSED(kh);
  if (target != SD_KH_STORE_USER)
    return SD_E_ACCESS_DENIED;
  if (sd_config_root(path, SD_COUNTOF(path)) != SD_OK || wcslen(path) + 13 >= SD_COUNTOF(path))
    return SD_E_FAILURE;
  wcscat_s(path, SD_COUNTOF(path), L"\\known_hosts");
  memset(&st, 0, sizeof(st));
  st.kind = SD_KH_STORE_USER;
  st.path = path;
  st.writable = 1;
  e = sd_known_hosts_open(&st, 1, &real);
  if (e != SD_OK)
    return e;
  e = sd_known_hosts_apply_hostkeys(real, target, name, add, add_count, remove, remove_count);
  sd_known_hosts_close(real);
  return e;
}

/* hostkey add (M5): the fake sd_ssh connection of a hostkey mount. The mount's callbacks are driven as sd_ssh would:
   a first contact raises the TOFU prompt (answered ACCEPT_ONCE by the mount), the verified fetch then returns the
   scripted keys or fails with SD_E_HOSTKEY_REJECTED for a first contact, as sd_ssh does (01 §4.3). */
typedef struct hk_fake {
  char host[256];
  sd_ssh_callbacks cb;
  int first;                     /* first contact: no stored key */
  int changed;                   /* a stored key that does not match */
  uint8_t ed[4 + 11 + 4 + 32];   /* the presented ssh-ed25519 key blob */
  size_t ed_len;
  char ed_fp[64];
} hk_fake;

static char k_hk_prompt_marker;  /* the prompt object the fake raises (answered by hk_prompt_answer) */

static sd_err (*k_fake_prompt_answer_hostkey)(sd_prompt *p, sd_hostkey_decision d);

static sd_err hk_prompt_answer_hostkey(sd_prompt *p, sd_hostkey_decision d)
{
  if ((void *)p == (void *)&k_hk_prompt_marker)
    return SD_OK;
  return k_fake_prompt_answer_hostkey(p, d);
}

static sd_err hk_fake_create(const sd_ssh_config *cfg, const sd_ssh_callbacks *cb, sd_ssh_conn **out)
{
  hk_fake *c = (hk_fake *)sd_calloc(1, sizeof(*c));
  const sd_ssh_hop *last;
  if (c == NULL)
    return SD_E_NO_MEMORY;
  last = &cfg->hops[cfg->hop_count - 1];
  WideCharToMultiByte(CP_UTF8, 0, last->host, -1, c->host, sizeof(c->host), NULL, NULL);
  c->cb = *cb;
  c->changed = ends_with(c->host, ".changed.test");
  c->first = !c->changed && !ends_with(c->host, ".known.test");
  /* the presented key of a first contact: an ed25519 key with a 32-byte value */
  {
    uint8_t pk[32];
    memset(pk, 0x33, sizeof(pk));
    memset(c->ed, 0, sizeof(c->ed));
    c->ed_len = put_str(c->ed, 0, "ssh-ed25519", 11);
    c->ed_len = put_str(c->ed, c->ed_len, pk, sizeof(pk));
  }
  sd_hostkey_fingerprint_sha256(c->ed, c->ed_len, c->ed_fp);
  *out = (sd_ssh_conn *)c;
  return SD_OK;
}

static sd_err hk_fake_connect(sd_ssh_conn *cc, sd_ssh_done_cb done, void *ctx)
{
  hk_fake *c = (hk_fake *)cc;
  if (c->changed) {
    done(ctx, SD_E_HOSTKEY_MISMATCH, 0);
    return SD_OK;
  }
  if (c->first) {
    sd_hostkey_prompt_info hk;
    memset(&hk, 0, sizeof(hk));
    hk.host = c->host;
    hk.port = 22;
    hk.lookup_name = c->host;
    hk.key_type = "ssh-ed25519";
    hk.key_bits = 256;
    hk.fp_sha256 = c->ed_fp;
    hk.fp_md5 = "";
    hk.status = SD_HK_NEW;
    hk.blob = c->ed;
    hk.blob_len = c->ed_len;
    c->cb.on_prompt(c->cb.ctx, (sd_prompt *)&k_hk_prompt_marker, NULL, &hk);
  }
  done(ctx, SD_OK, 0);
  return SD_OK;
}

static sd_err hk_fake_fetch(sd_ssh_conn *cc, uint32_t hop, const char *const *types, uint32_t ntypes,
                            sd_ssh_hostkeys_cb done, void *ctx)
{
  static uint8_t blob_ec[600], blob_rsa[600];
  static sd_hk_key keys[2];
  static const char *const fp_ec = "SHA256:ecdsa-fake", *const fp_rsa = "SHA256:rsa-fake";
  uint8_t pt[65], mod[256];
  static const uint8_t e65537[3] = { 0x01, 0x00, 0x01 };
  hk_fake *c = (hk_fake *)cc;
  size_t n;
  uint32_t i, k = 0, want_ec = 1, want_rsa = 1;
  SD_UNUSED(hop);
  if (c->first) {
    done(ctx, SD_E_HOSTKEY_REJECTED, NULL, 0);
    return SD_OK;
  }
  if (ntypes) {
    want_ec = want_rsa = 0;
    for (i = 0; i < ntypes; i++) {
      if (strcmp(types[i], "ecdsa-sha2-nistp256") == 0) want_ec = 1;
      if (strcmp(types[i], "ssh-rsa") == 0) want_rsa = 1;
    }
  }
  /* ecdsa-sha2-nistp256: type, curve, the uncompressed point */
  memset(pt, 0x11, sizeof(pt));
  pt[0] = 0x04;
  n = put_str(blob_ec, 0, "ecdsa-sha2-nistp256", 19);
  n = put_str(blob_ec, n, "nistp256", 8);
  n = put_str(blob_ec, n, pt, sizeof(pt));
  if (want_ec) {
    keys[k].blob = blob_ec; keys[k].len = n; keys[k].type = "ecdsa-sha2-nistp256"; keys[k].fp_sha256 = fp_ec; k++;
  }
  /* ssh-rsa: type, exponent, modulus */
  memset(mod, 0x5a, sizeof(mod));
  n = put_str(blob_rsa, 0, "ssh-rsa", 7);
  n = put_str(blob_rsa, n, e65537, sizeof(e65537));
  n = put_str(blob_rsa, n, mod, sizeof(mod));
  if (want_rsa) {
    keys[k].blob = blob_rsa; keys[k].len = n; keys[k].type = "ssh-rsa"; keys[k].fp_sha256 = fp_rsa; k++;
  }
  done(ctx, SD_OK, keys, k);
  return SD_OK;
}

static void hk_fake_destroy(sd_ssh_conn *cc)
{
  sd_free(cc);
}

const sd_mount_backend *host_backend(void)
{
  wchar_t v[32];
  if (GetEnvironmentVariableW(L"SHELLDRIVE_TEST_WB_DIRTY", v, 32) > 0 && v[0] >= L'0' && v[0] <= L'9')
    fake_backend_set_wb_dirty((UINT64)wcstoull(v, NULL, 10));
  /* the no-SSPI WebDAV tests (SHELLDRIVE_TEST_WD_NOAUTH=1, read by the fake at start) need a startable WebClient */
  if (GetEnvironmentVariableW(L"SHELLDRIVE_TEST_WD_NOAUTH", v, 32) > 0 && v[0] == L'1')
    fake_backend_set_webclient(SD_WD_CLIENT_STOPPED, 1);
  if (!k_host_ready) {
    /* the fake table plus the hostkey connection and the real user store writer (see above) */
    k_host = *fake_backend();
    k_fake_prompt_answer_hostkey = k_host.prompt_answer_hostkey;
    k_host.prompt_answer_hostkey = hk_prompt_answer_hostkey;
    k_host.hk_conn_create = hk_fake_create;
    k_host.hk_conn_connect = hk_fake_connect;
    k_host.hk_conn_fetch = hk_fake_fetch;
    k_host.hk_conn_destroy = hk_fake_destroy;
    k_host.kh_apply_hostkeys = hk_apply_user_store;
    k_host_ready = 1;
  }
  return &k_host;
}
