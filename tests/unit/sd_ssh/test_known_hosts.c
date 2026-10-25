/* known_hosts parsing, matching and the user file store (01 §7.1, §7.2; TM-R04, TM-R07). */
#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_test.h"
#include "ssh_internal.h"
#include "test_util.h"

/* ed25519 public keys from fixtures/ed25519_plain.pub and fixtures/other_host.pub */
#define KEY_A_B64 "AAAAC3NzaC1lZDI1NTE5AAAAIDdtlhWJx8c2XC36nz8A2l1/6MUfcs+UVR5s7rw65xze"
#define KEY_B_FILE "other_host.pub"

static size_t blob_of(const char *b64, uint8_t *out, size_t cap)
{
  size_t n = 0;
  if (ssh_b64_decode(b64, strlen(b64), out, cap, &n, 0) != SD_OK) return 0;
  return n;
}

static size_t key_b(uint8_t *out, size_t cap, char *b64out, size_t b64cap)
{
  uint8_t *f;
  size_t n, i, s, e;
  if (!tu_read_fixture(KEY_B_FILE, &f, &n)) return 0;
  for (i = 0; i < n && f[i] != ' '; i++) {}
  s = i + 1;
  for (e = s; e < n && f[e] != ' '; e++) {}
  if (e - s + 1 > b64cap) { sd_free(f); return 0; }
  memcpy(b64out, f + s, e - s);
  b64out[e - s] = 0;
  sd_free(f);
  return blob_of(b64out, out, cap);
}

SD_TEST(ssh_kh_patterns)
{
  static const char p1[] = "example.com,*.example.org,!bad.example.org";
  SD_CHECK_EQ_INT(ssh_kh_match_patterns(p1, strlen(p1), "example.com"), 1);
  SD_CHECK_EQ_INT(ssh_kh_match_patterns(p1, strlen(p1), "EXAMPLE.com"), 1);
  SD_CHECK_EQ_INT(ssh_kh_match_patterns(p1, strlen(p1), "a.example.org"), 1);
  SD_CHECK_EQ_INT(ssh_kh_match_patterns(p1, strlen(p1), "bad.example.org"), -1);
  SD_CHECK_EQ_INT(ssh_kh_match_patterns(p1, strlen(p1), "example.org"), 0);
  SD_CHECK_EQ_INT(ssh_kh_match_patterns("[host]:2222", 11, "[host]:2222"), 1);
  SD_CHECK_EQ_INT(ssh_kh_match_patterns("[host]:2222", 11, "host"), 0);
  SD_CHECK_EQ_INT(ssh_kh_match_patterns("host", 4, "[host]:2222"), 0);
  SD_CHECK_EQ_INT(ssh_kh_match_patterns("[h?st]:22*", 10, "[host]:2222"), 1);
  SD_CHECK_EQ_INT(ssh_kh_match_patterns("|1|abc=|def=", 12, "host"), 0);   /* hashed: M2 */
  SD_CHECK(ssh_kh_wildcard_only("*", 1));
  SD_CHECK(ssh_kh_wildcard_only("*.*,!x", 6));
  SD_CHECK(ssh_kh_wildcard_only("[*]:2222", 8));
  SD_CHECK(!ssh_kh_wildcard_only("*.example.com", 13));
}

SD_TEST(ssh_kh_lookup_names)
{
  char out[64];
  SD_CHECK_EQ_INT(ssh_kh_lookup_name("Example.COM", 22, out, sizeof(out)), SD_OK);
  SD_CHECK_STR(out, "example.com");
  SD_CHECK_EQ_INT(ssh_kh_lookup_name("Example.COM", 0, out, sizeof(out)), SD_OK);
  SD_CHECK_STR(out, "example.com");
  SD_CHECK_EQ_INT(ssh_kh_lookup_name("127.0.0.1", 2222, out, sizeof(out)), SD_OK);
  SD_CHECK_STR(out, "[127.0.0.1]:2222");
  SD_CHECK_EQ_INT(ssh_kh_lookup_name("[::1]", 2222, out, sizeof(out)), SD_OK);
  SD_CHECK_STR(out, "[::1]:2222");
  SD_CHECK_EQ_INT(ssh_kh_lookup_name("bad host", 22, out, sizeof(out)), SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(ssh_kh_lookup_name("a,b", 22, out, sizeof(out)), SD_E_INVALID_PARAM);
}

SD_TEST(ssh_kh_check_statuses)
{
  uint8_t a[128], b[128];
  char bb64[128], text[2048];
  size_t al = blob_of(KEY_A_B64, a, sizeof(a)), bl = key_b(b, sizeof(b), bb64, sizeof(bb64));
  sd_hk_result r;
  int other;
  SD_REQUIRE(al && bl);

  /* MATCH, including through [host]:port and a pattern list; comments and garbage skipped */
  _snprintf_s(text, sizeof(text), _TRUNCATE,
              "# comment\n\ngarbage\n[127.0.0.1]:2222,other ssh-ed25519 %s c1\r\nhost2 ssh-rsa AAAA\n", KEY_A_B64);
  SD_CHECK_EQ_INT(ssh_kh_check_buffer(text, strlen(text), "[127.0.0.1]:2222", a, al, &r, &other), SD_OK);
  SD_CHECK_EQ_INT(r.status, SD_HK_MATCH);
  SD_CHECK_EQ_INT(r.line, 4);
  SD_CHECK(r.trusted_before);
  /* NEW for another name */
  SD_CHECK_EQ_INT(ssh_kh_check_buffer(text, strlen(text), "127.0.0.1", a, al, &r, &other), SD_OK);
  SD_CHECK_EQ_INT(r.status, SD_HK_NEW);
  /* MISMATCH: same type, other key; reported line and stored type */
  SD_CHECK_EQ_INT(ssh_kh_check_buffer(text, strlen(text), "[127.0.0.1]:2222", b, bl, &r, &other), SD_OK);
  SD_CHECK_EQ_INT(r.status, SD_HK_MISMATCH);
  SD_CHECK_EQ_INT(r.line, 4);
  SD_CHECK_STR(r.stored_type, "ssh-ed25519");
  /* M2: one store may hold several keys of a type (UpdateHostKeys rotation): a matching line wins
     within the store; a mismatch in ANOTHER store still blocks (D7, test_known_hosts_m2.c) */
  _snprintf_s(text, sizeof(text), _TRUNCATE, "h ssh-ed25519 %s\nh ssh-ed25519 %s\n", bb64, KEY_A_B64);
  SD_CHECK_EQ_INT(ssh_kh_check_buffer(text, strlen(text), "h", a, al, &r, &other), SD_OK);
  SD_CHECK_EQ_INT(r.status, SD_HK_MATCH);
  SD_CHECK_EQ_INT(r.line, 2);
  /* NEW_TYPE: only an RSA key is stored for the name (TM-R04: fail, never a prompt) */
  _snprintf_s(text, sizeof(text), _TRUNCATE,
              "h ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC7\n");
  SD_CHECK_EQ_INT(ssh_kh_check_buffer(text, strlen(text), "h", a, al, &r, &other), SD_OK);
  SD_CHECK_EQ_INT(r.status, SD_HK_NEW_TYPE);
  /* REVOKED wins */
  _snprintf_s(text, sizeof(text), _TRUNCATE, "h ssh-ed25519 %s\n@revoked * ssh-ed25519 %s\n", KEY_A_B64, KEY_A_B64);
  SD_CHECK_EQ_INT(ssh_kh_check_buffer(text, strlen(text), "h", a, al, &r, &other), SD_OK);
  SD_CHECK_EQ_INT(r.status, SD_HK_REVOKED);
  /* negation vetoes the line */
  _snprintf_s(text, sizeof(text), _TRUNCATE, "*,!h ssh-ed25519 %s\n", bb64);
  SD_CHECK_EQ_INT(ssh_kh_check_buffer(text, strlen(text), "h", a, al, &r, &other), SD_OK);
  SD_CHECK_EQ_INT(r.status, SD_HK_NEW);
  /* the type inside the blob must equal the line's type */
  _snprintf_s(text, sizeof(text), _TRUNCATE, "h ssh-rsa %s\n", KEY_A_B64);
  SD_CHECK_EQ_INT(ssh_kh_check_buffer(text, strlen(text), "h", a, al, &r, &other), SD_OK);
  SD_CHECK_EQ_INT(r.status, SD_HK_NEW);
}

SD_TEST(ssh_kh_stored_types_for_tmr04)
{
  char text[1024];
  sd_kh_types t;
  _snprintf_s(text, sizeof(text), _TRUNCATE,
              "h ssh-ed25519 %s\nh,x ssh-ed25519 %s\n@revoked h ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC7\n"
              "@cert-authority *.d ssh-ed25519 %s\nother ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC7\n",
              KEY_A_B64, KEY_A_B64, KEY_A_B64);
  memset(&t, 0, sizeof(t));
  SD_CHECK_EQ_INT(ssh_kh_types_buffer(text, strlen(text), "h", &t), SD_OK);
  SD_CHECK_EQ_INT(t.count, 1);
  SD_CHECK_STR(t.type[0], "ssh-ed25519");
  SD_CHECK(!t.has_ca);
  memset(&t, 0, sizeof(t));
  SD_CHECK_EQ_INT(ssh_kh_types_buffer(text, strlen(text), "a.d", &t), SD_OK);
  SD_CHECK_EQ_INT(t.count, 0);
  SD_CHECK(t.has_ca);
}

SD_TEST(ssh_kh_user_store_add_check_remove)
{
  wchar_t path[MAX_PATH];
  sd_kh_store st;
  sd_known_hosts *kh = NULL;
  uint8_t a[128], b[128];
  char bb64[128];
  size_t al = blob_of(KEY_A_B64, a, sizeof(a)), bl = key_b(b, sizeof(b), bb64, sizeof(bb64));
  sd_hk_result r;
  sd_kh_types t;
  sd_kh_src_state ss;
  SD_REQUIRE(al && bl);
  SD_REQUIRE(tu_temp_path(L"kh\\sub\\known_hosts", path, SD_COUNTOF(path)));
  DeleteFileW(path);
  st.kind = SD_KH_STORE_USER;
  st.path = path;
  st.writable = 1;
  SD_REQUIRE(sd_known_hosts_open(&st, 1, &kh) == SD_OK);
  SD_CHECK_EQ_INT(sd_known_hosts_source_state(kh, SD_KH_STORE_USER, &ss, NULL, 0), SD_OK);
  SD_CHECK_EQ_INT(ss, SD_KH_SRC_ABSENT);
  SD_CHECK_EQ_INT(sd_known_hosts_check(kh, "[127.0.0.1]:2222", a, al, 0, &r), SD_OK);
  SD_CHECK_EQ_INT(r.status, SD_HK_NEW);
  SD_CHECK_EQ_INT(sd_known_hosts_add(kh, SD_KH_STORE_USER, "[127.0.0.1]:2222", a, al, "# added=test"), SD_OK);
  SD_CHECK_EQ_INT(sd_known_hosts_add(kh, SD_KH_STORE_USER, "bad name", a, al, NULL), SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(sd_known_hosts_add(kh, SD_KH_STORE_MACHINE, "x", a, al, NULL), SD_E_NOT_FOUND);
  SD_CHECK_EQ_INT(sd_known_hosts_check(kh, "[127.0.0.1]:2222", a, al, 0, &r), SD_OK);
  SD_CHECK_EQ_INT(r.status, SD_HK_MATCH);
  SD_CHECK_EQ_INT(r.store, SD_KH_STORE_USER);
  SD_CHECK_EQ_INT(r.line, 1);
  SD_CHECK(wcscmp(r.path, path) == 0);
  SD_CHECK_EQ_INT(sd_known_hosts_check(kh, "[127.0.0.1]:2222", b, bl, 0, &r), SD_OK);
  SD_CHECK_EQ_INT(r.status, SD_HK_MISMATCH);
  SD_CHECK_EQ_INT(sd_known_hosts_stored_types(kh, "[127.0.0.1]:2222", &t), SD_OK);
  SD_CHECK_EQ_INT(t.count, 1);
  SD_CHECK_EQ_INT(sd_known_hosts_add(kh, SD_KH_STORE_USER, "other", b, bl, NULL), SD_OK);
  SD_CHECK_EQ_INT(sd_known_hosts_check(kh, "other", b, bl, 0, &r), SD_OK);
  SD_CHECK_EQ_INT(r.status, SD_HK_MATCH);
  SD_CHECK_EQ_INT(r.line, 2);
  SD_CHECK_EQ_INT(sd_known_hosts_remove(kh, SD_KH_STORE_USER, "[127.0.0.1]:2222", NULL), SD_OK);
  SD_CHECK_EQ_INT(sd_known_hosts_remove(kh, SD_KH_STORE_USER, "[127.0.0.1]:2222", NULL), SD_E_NOT_FOUND);
  SD_CHECK_EQ_INT(sd_known_hosts_check(kh, "[127.0.0.1]:2222", a, al, 0, &r), SD_OK);
  SD_CHECK_EQ_INT(r.status, SD_HK_NEW);
  SD_CHECK_EQ_INT(sd_known_hosts_check(kh, "other", b, bl, 0, &r), SD_OK);
  SD_CHECK_EQ_INT(r.status, SD_HK_MATCH);
  SD_CHECK_EQ_INT(sd_known_hosts_source_state(kh, SD_KH_STORE_USER, &ss, NULL, 0), SD_OK);
  SD_CHECK_EQ_INT(ss, SD_KH_SRC_OK);
  SD_CHECK_EQ_INT(sd_known_hosts_source_state(kh, SD_KH_SRC_OPENSSH, &ss, NULL, 0), SD_OK);
  SD_CHECK_EQ_INT(ss, SD_KH_SRC_DISABLED);
  sd_known_hosts_close(kh);
  /* a read-only store refuses writes */
  st.writable = 0;
  SD_REQUIRE(sd_known_hosts_open(&st, 1, &kh) == SD_OK);
  SD_CHECK_EQ_INT(sd_known_hosts_add(kh, SD_KH_STORE_USER, "x", a, al, NULL), SD_E_READ_ONLY);
  sd_known_hosts_close(kh);
  DeleteFileW(path);
}

SD_TEST(ssh_kh_fingerprint)
{
  uint8_t a[128];
  char fp[64];
  size_t al = blob_of(KEY_A_B64, a, sizeof(a));
  if (!tu_crypto_or_skip("ssh_kh_fingerprint")) return;
  SD_CHECK_EQ_INT(sd_hostkey_fingerprint_sha256(a, al, fp), SD_OK);
  SD_CHECK_STR(fp, "SHA256:bKExo77Fub+16j6ZHadz2gGgn+jcY0wAbkoJZR8ZSW0");   /* ssh-keygen -lf */
}
