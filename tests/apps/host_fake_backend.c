/* Mount backend of the test host (sd-test-host-fake.exe): the scripted fake of tests/unit/sd_mount.
 * SHELLDRIVE_TEST_WB_DIRTY=<bytes> reports that much write-behind data queued on every mount (cache.clear
 * refusal tests); the agent reads it when it asks for the backend, so the variable must be set before it starts.
 * SHELLDRIVE_TEST_WD_NOAUTH=1 makes WebClient startable and the WebDAV start fail without SSPI (TM-R19 tests).
 *
 * hostkey add (hostkeys_fetch) is scripted by the host name, so the smoke tests need no network:
 *   *.known.test      a stored key verifies the connection; the server has an ECDSA and an ssh-rsa key besides it
 *   *.changed.test    the stored key does not match (SD_E_HOSTKEY_MISMATCH)
 *   anything else     first contact: the server presents one ssh-ed25519 key (TOFU, 5.2) */
#include <windows.h>
#include <stdlib.h>
#include <string.h>

#include "host.h"
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

static sd_err fake_hostkeys_fetch(const char *host, uint16_t port, const char *type, sd_mount_hk_fetch *out)
{
  uint8_t blob[600];
  size_t n;
  uint8_t pt[65];
  uint8_t mod[256];
  static const uint8_t e65537[3] = { 0x01, 0x00, 0x01 };
  SD_UNUSED(port);
  if (ends_with(host, ".changed.test"))
    return SD_E_HOSTKEY_MISMATCH;
  if (ends_with(host, ".known.test")) {
    out->verified = 1;
    /* ecdsa-sha2-nistp256: type, curve, the uncompressed point */
    memset(pt, 0x11, sizeof(pt));
    pt[0] = 0x04;
    n = put_str(blob, 0, "ecdsa-sha2-nistp256", 19);
    n = put_str(blob, n, "nistp256", 8);
    n = put_str(blob, n, pt, sizeof(pt));
    if (type == NULL || strcmp(type, "ecdsa-sha2-nistp256") == 0)
      add_key(out, "ecdsa-sha2-nistp256", blob, n);
    /* ssh-rsa: type, exponent, modulus */
    memset(mod, 0x5a, sizeof(mod));
    n = put_str(blob, 0, "ssh-rsa", 7);
    n = put_str(blob, n, e65537, sizeof(e65537));
    n = put_str(blob, n, mod, sizeof(mod));
    if (type == NULL || strcmp(type, "ssh-rsa") == 0)
      add_key(out, "ssh-rsa", blob, n);
    return SD_OK;
  }
  /* first contact: one ed25519 key */
  memset(mod, 0x33, 32);
  n = put_str(blob, 0, "ssh-ed25519", 11);
  n = put_str(blob, n, mod, 32);
  out->verified = 0;
  if (type == NULL || strcmp(type, "ssh-ed25519") == 0)
    add_key(out, "ssh-ed25519", blob, n);
  return SD_OK;
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
    /* the fake table plus hostkeys_fetch and the real user store writer (see above) */
    k_host = *fake_backend();
    k_host.hostkeys_fetch = fake_hostkeys_fetch;
    k_host.kh_apply_hostkeys = hk_apply_user_store;
    k_host_ready = 1;
  }
  return &k_host;
}
