/* known_hosts M2 (01 §7.1-§7.3, §7.5; D7, D8; TM-R04, TM-R06): hashed entries, @cert-authority,
 * live OpenSSH and PuTTY sources with their ACL checks, imports and the UpdateHostKeys review helpers. */
#include <windows.h>
#include <sddl.h>
#include <stdio.h>
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_test.h"
#include "hostkey_internal.h"
#include "known_hosts_internal.h"
#include "ssh_internal.h"
#include "test_util.h"

static size_t pub_blob(const char *name, uint8_t *out, size_t cap, char *b64, size_t b64cap)
{
  uint8_t *f;
  size_t n, i, s, e, bl = 0;
  if (!tu_read_fixture(name, &f, &n)) return 0;
  for (i = 0; i < n && f[i] != ' '; i++) {}
  s = i + 1;
  for (e = s; e < n && f[e] != ' ' && f[e] != '\n' && f[e] != '\r'; e++) {}
  if (b64) {
    if (e - s + 1 > b64cap) { sd_free(f); return 0; }
    memcpy(b64, f + s, e - s);
    b64[e - s] = '\0';
  }
  if (ssh_b64_decode((const char *)f + s, e - s, out, cap, &bl, 0) != SD_OK) bl = 0;
  sd_free(f);
  return bl;
}

static int write_text(const wchar_t *path, const char *text)
{
  HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  DWORD w = 0;
  int ok;
  if (h == INVALID_HANDLE_VALUE) return 0;
  ok = WriteFile(h, text, (DWORD)strlen(text), &w, NULL) && w == strlen(text);
  CloseHandle(h);
  return ok;
}

static char *read_text(const wchar_t *path)
{
  HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
  DWORD sz, got = 0;
  char *b;
  if (h == INVALID_HANDLE_VALUE) return NULL;
  sz = GetFileSize(h, NULL);
  b = (char *)sd_calloc(1, (size_t)sz + 1);
  if (b && !ReadFile(h, b, sz, &got, NULL)) { sd_free(b); b = NULL; }
  CloseHandle(h);
  return b;
}

SD_TEST(tr_kh_hashed_entries)
{
  uint8_t key[128], *f;
  size_t kl, fl;
  sd_hk_result r;
  wchar_t path[MAX_PATH];
  sd_kh_store st;
  sd_known_hosts *kh = NULL;
  char *txt;
  if (!tu_crypto_or_skip("tr_kh_hashed_entries")) return;
  kl = pub_blob("hk_host.pub", key, sizeof(key), NULL, 0);
  SD_REQUIRE(kl && tu_read_fixture("hk_hashed_known_hosts", &f, &fl));   /* written by ssh-keygen -H */
  SD_CHECK_EQ_INT(ssh_kh_check_buffer((const char *)f, fl, "host.example", key, kl, &r, NULL), SD_OK);
  SD_CHECK_EQ_INT(r.status, SD_HK_MATCH);
  SD_CHECK_EQ_INT(r.line, 1);
  SD_CHECK_EQ_INT(ssh_kh_check_buffer((const char *)f, fl, "[host.example]:2222", key, kl, &r, NULL), SD_OK);
  SD_CHECK_EQ_INT(r.status, SD_HK_MATCH);
  SD_CHECK_EQ_INT(r.line, 2);
  SD_CHECK_EQ_INT(ssh_kh_check_buffer((const char *)f, fl, "host.example.org", key, kl, &r, NULL), SD_OK);
  SD_CHECK_EQ_INT(r.status, SD_HK_NEW);
  sd_free(f);
  /* optional hashed write */
  SD_REQUIRE(tu_temp_path(L"kh-hashed\\known_hosts", path, SD_COUNTOF(path)));
  DeleteFileW(path);
  st.kind = SD_KH_STORE_USER; st.path = path; st.writable = 1;
  SD_REQUIRE(sd_known_hosts_open(&st, 1, &kh) == SD_OK);
  SD_CHECK_EQ_INT(sd_known_hosts_add_ex(kh, SD_KH_STORE_USER, "[10.0.0.1]:2200", key, kl, NULL, SD_KH_ADD_HASHED), SD_OK);
  txt = read_text(path);
  SD_CHECK(txt && strncmp(txt, "|1|", 3) == 0 && !strstr(txt, "10.0.0.1"));
  sd_free(txt);
  SD_CHECK_EQ_INT(sd_known_hosts_check(kh, "[10.0.0.1]:2200", key, kl, 0, &r), SD_OK);
  SD_CHECK_EQ_INT(r.status, SD_HK_MATCH);
  SD_CHECK_EQ_INT(sd_known_hosts_remove_key(kh, SD_KH_STORE_USER, "[10.0.0.1]:2200", key, kl), SD_OK);
  SD_CHECK_EQ_INT(sd_known_hosts_check(kh, "[10.0.0.1]:2200", key, kl, 0, &r), SD_OK);
  SD_CHECK_EQ_INT(r.status, SD_HK_NEW);
  sd_known_hosts_close(kh);
  DeleteFileW(path);
}

SD_TEST(tr_kh_cert_authority)
{
  uint8_t cert[2048], exp[2048], ca2c[2048], plain[128];
  char ca[128], ca2[128], hostb64[128], text[2048];
  size_t cl, el, c2l, pl;
  sd_hk_result r;
  sd_kh_types t;
  uint8_t tmp[128];
  if (!tu_crypto_or_skip("tr_kh_cert_authority")) return;
  cl = pub_blob("hk_host-cert.pub", cert, sizeof(cert), NULL, 0);
  el = pub_blob("hk_host_expired-cert.pub", exp, sizeof(exp), NULL, 0);
  c2l = pub_blob("hk_host_ca2-cert.pub", ca2c, sizeof(ca2c), NULL, 0);
  pl = pub_blob("hk_host.pub", plain, sizeof(plain), hostb64, sizeof(hostb64));
  SD_REQUIRE(cl && el && c2l && pl);
  SD_REQUIRE(pub_blob("hk_ca.pub", tmp, sizeof(tmp), ca, sizeof(ca)) && pub_blob("hk_ca2.pub", tmp, sizeof(tmp), ca2, sizeof(ca2)));
  _snprintf_s(text, sizeof(text), _TRUNCATE, "@cert-authority *.example,127.0.0.1 ssh-ed25519 %s\n", ca);
  SD_CHECK_EQ_INT(ssh_kh_check_buffer(text, strlen(text), "host.example", cert, cl, &r, NULL), SD_OK);
  SD_CHECK_EQ_INT(r.status, SD_HK_MATCH_CA);
  SD_CHECK_EQ_INT(r.line, 1);
  /* the CA line must apply to the name */
  SD_CHECK_EQ_INT(ssh_kh_check_buffer(text, strlen(text), "host.other", cert, cl, &r, NULL), SD_OK);
  SD_CHECK_EQ_INT(r.status, SD_HK_NEW);
  /* signed by another CA, or expired: a trusted CA applies, no TOFU path */
  SD_CHECK_EQ_INT(ssh_kh_check_buffer(text, strlen(text), "host.example", ca2c, c2l, &r, NULL), SD_OK);
  SD_CHECK_EQ_INT(r.status, SD_HK_MISMATCH);
  SD_CHECK_EQ_INT(ssh_kh_check_buffer(text, strlen(text), "host.example", exp, el, &r, NULL), SD_OK);
  SD_CHECK_EQ_INT(r.status, SD_HK_MISMATCH);
  /* ... unless the plain key is known (OpenSSH behaviour) */
  _snprintf_s(text, sizeof(text), _TRUNCATE, "@cert-authority *.example ssh-ed25519 %s\nhost.example ssh-ed25519 %s\n",
              ca, hostb64);
  SD_CHECK_EQ_INT(ssh_kh_check_buffer(text, strlen(text), "host.example", exp, el, &r, NULL), SD_OK);
  SD_CHECK_EQ_INT(r.status, SD_HK_MATCH);
  SD_CHECK_EQ_INT(r.line, 2);
  /* @revoked CA or key wins */
  _snprintf_s(text, sizeof(text), _TRUNCATE, "@cert-authority *.example ssh-ed25519 %s\n@revoked * ssh-ed25519 %s\n", ca, ca);
  SD_CHECK_EQ_INT(ssh_kh_check_buffer(text, strlen(text), "host.example", cert, cl, &r, NULL), SD_OK);
  SD_CHECK_EQ_INT(r.status, SD_HK_REVOKED);
  _snprintf_s(text, sizeof(text), _TRUNCATE, "@cert-authority *.example ssh-ed25519 %s\n@revoked * ssh-ed25519 %s\n", ca,
              hostb64);
  SD_CHECK_EQ_INT(ssh_kh_check_buffer(text, strlen(text), "host.example", cert, cl, &r, NULL), SD_OK);
  SD_CHECK_EQ_INT(r.status, SD_HK_REVOKED);
  /* types: only the CA */
  _snprintf_s(text, sizeof(text), _TRUNCATE, "@cert-authority *.example ssh-ed25519 %s\n@cert-authority x ssh-ed25519 %s\n",
              ca, ca2);
  memset(&t, 0, sizeof(t));
  SD_CHECK_EQ_INT(ssh_kh_types_buffer(text, strlen(text), "host.example", &t), SD_OK);
  SD_CHECK(t.has_ca && t.count == 0);
  /* a certificate accepted on first contact is stored as its plain key */
  {
    wchar_t path[MAX_PATH];
    sd_kh_store st;
    sd_known_hosts *kh = NULL;
    char *txt;
    SD_REQUIRE(tu_temp_path(L"kh-cert\\known_hosts", path, SD_COUNTOF(path)));
    DeleteFileW(path);
    st.kind = SD_KH_STORE_USER; st.path = path; st.writable = 1;
    SD_REQUIRE(sd_known_hosts_open(&st, 1, &kh) == SD_OK);
    SD_CHECK_EQ_INT(sd_known_hosts_add(kh, SD_KH_STORE_USER, "host.example", cert, cl, NULL), SD_OK);
    txt = read_text(path);
    SD_CHECK(txt && strstr(txt, hostb64) && strstr(txt, "host.example ssh-ed25519 "));
    sd_free(txt);
    SD_CHECK_EQ_INT(sd_known_hosts_check(kh, "host.example", cert, cl, 0, &r), SD_OK);
    SD_CHECK_EQ_INT(r.status, SD_HK_MATCH);
    sd_known_hosts_close(kh);
    DeleteFileW(path);
  }
}

#define KEY_A "ed25519_plain.pub"
#define KEY_B "other_host.pub"

/* The live file must pass the TM-R06 check on its own DACL. A file created in %TEMP% inherits the
   temp directory's ACEs, which on some machines include other principals, so the test gives the
   live file a user-only DACL (owner, SYSTEM, Administrators) before the source is read. */
static int secure_test_path(const wchar_t *path)
{
  PSECURITY_DESCRIPTOR sd = NULL;
  int ok = 0;
  if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)",
                                                           SDDL_REVISION_1, &sd, NULL)) {
    ok = SetFileSecurityW(path, DACL_SECURITY_INFORMATION, sd) != 0;
    LocalFree(sd);
  }
  return ok;
}

/* Live OpenSSH file next to our user store; returns 0 if the file cannot be written or secured. */
static int live_setup(sd_test_ctx *sd_t_, const wchar_t *tag, wchar_t *user, wchar_t *live, sd_known_hosts **kh,
                      const char *text)
{
  sd_kh_store st[2];
  wchar_t dir[MAX_PATH];
  wchar_t sub[64];
  _snwprintf_s(sub, SD_COUNTOF(sub), _TRUNCATE, L"%s-ssh\\", tag);
  SD_CHECK(tu_temp_path(sub, dir, SD_COUNTOF(dir)));
  CreateDirectoryW(dir, NULL);
  if (!secure_test_path(dir)) return 0;
  _snwprintf_s(live, MAX_PATH, _TRUNCATE, L"%sknown_hosts", dir);
  _snwprintf_s(sub, SD_COUNTOF(sub), _TRUNCATE, L"%s-user\\known_hosts", tag);
  SD_CHECK(tu_temp_path(sub, user, MAX_PATH));
  DeleteFileW(user);
  if (!write_text(live, text) || !secure_test_path(live)) return 0;
  st[0].kind = SD_KH_STORE_USER; st[0].path = user; st[0].writable = 1;
  st[1].kind = SD_KH_SRC_OPENSSH; st[1].path = live; st[1].writable = 0;
  return sd_known_hosts_open(st, 2, kh) == SD_OK;
}

SD_TEST(tr_kh_live_openssh_source)
{
  uint8_t a[128], b[128];
  char ab64[128], bb64[128], text[1024], *txt;
  size_t al, bl;
  wchar_t user[MAX_PATH], live[MAX_PATH], sid[128];
  sd_known_hosts *kh = NULL;
  sd_hk_result r;
  sd_kh_src_state ss;
  sd_kh_types t;
  if (!tu_crypto_or_skip("tr_kh_live_openssh_source")) return;
  al = pub_blob(KEY_A, a, sizeof(a), ab64, sizeof(ab64));
  bl = pub_blob(KEY_B, b, sizeof(b), bb64, sizeof(bb64));
  SD_REQUIRE(al && bl);
  _snprintf_s(text, sizeof(text), _TRUNCATE, "h1 ssh-ed25519 %s\n* ssh-ed25519 %s\n", ab64, bb64);
  SD_REQUIRE(live_setup(sd_t_, L"live", user, live, &kh, text));
  SD_CHECK_EQ_INT(sd_known_hosts_source_state(kh, SD_KH_SRC_OPENSSH, &ss, sid, SD_COUNTOF(sid)), SD_OK);
  SD_CHECK_EQ_INT(ss, SD_KH_SRC_OK);
  if (ss != SD_KH_SRC_OK) { sd_known_hosts_close(kh); return; }
  /* MATCH from the live source, copied into the user store with its origin (D7) */
  SD_CHECK_EQ_INT(sd_known_hosts_check(kh, "h1", a, al, 0, &r), SD_OK);
  SD_CHECK_EQ_INT(r.status, SD_HK_MATCH);
  SD_CHECK_EQ_INT(r.store, SD_KH_SRC_OPENSSH);
  txt = read_text(user);
  SD_CHECK(txt && strstr(txt, "h1 ssh-ed25519 ") && strstr(txt, "# imported-from=openssh added="));
  sd_free(txt);
  SD_CHECK_EQ_INT(sd_known_hosts_check(kh, "h1", a, al, 0, &r), SD_OK);
  SD_CHECK_EQ_INT(r.store, SD_KH_STORE_USER);
  /* TM-R06: '*' in a live source never matches ... */
  SD_CHECK_EQ_INT(sd_known_hosts_check(kh, "h2", b, bl, 0, &r), SD_OK);
  SD_CHECK_EQ_INT(r.status, SD_HK_NEW);
  memset(&t, 0, sizeof(t));
  SD_CHECK_EQ_INT(sd_known_hosts_stored_types(kh, "h2", &t), SD_OK);
  SD_CHECK_EQ_INT(t.count, 0);
  /* ... but still blocks a different key of the same type */
  SD_CHECK_EQ_INT(sd_known_hosts_check(kh, "h2", a, al, 0, &r), SD_OK);
  SD_CHECK_EQ_INT(r.status, SD_HK_MISMATCH);
  SD_CHECK_EQ_INT(r.store, SD_KH_SRC_OPENSSH);
  /* any mismatch blocks, even when our own store matches (D7) */
  SD_CHECK_EQ_INT(sd_known_hosts_add(kh, SD_KH_STORE_USER, "h3", b, bl, NULL), SD_OK);
  _snprintf_s(text, sizeof(text), _TRUNCATE, "h3 ssh-ed25519 %s\n", ab64);
  SD_REQUIRE(write_text(live, text));
  SD_CHECK_EQ_INT(sd_known_hosts_check(kh, "h3", b, bl, 0, &r), SD_OK);
  SD_CHECK_EQ_INT(r.status, SD_HK_MISMATCH);
  /* the live source is read-only */
  SD_CHECK_EQ_INT(sd_known_hosts_add(kh, SD_KH_SRC_OPENSSH, "x", a, al, NULL), SD_E_READ_ONLY);
  sd_known_hosts_close(kh);
  DeleteFileW(user);
  DeleteFileW(live);
}

SD_TEST(tr_kh_live_source_insecure_is_skipped)
{
  uint8_t a[128];
  char ab64[128], text[512];
  size_t al;
  wchar_t user[MAX_PATH], live[MAX_PATH], sid[128];
  sd_known_hosts *kh = NULL;
  sd_hk_result r;
  sd_kh_src_state ss;
  PSECURITY_DESCRIPTOR sd = NULL;
  if (!tu_crypto_or_skip("tr_kh_live_source_insecure_is_skipped")) return;
  al = pub_blob(KEY_A, a, sizeof(a), ab64, sizeof(ab64));
  SD_REQUIRE(al);
  _snprintf_s(text, sizeof(text), _TRUNCATE, "h1 ssh-ed25519 %s\n", ab64);
  SD_REQUIRE(live_setup(sd_t_, L"insecure", user, live, &kh, text));
  /* Everyone may write the file */
  SD_REQUIRE(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)(A;;FW;;;WD)",
                                                                  SDDL_REVISION_1, &sd, NULL));
  SD_REQUIRE(SetFileSecurityW(live, DACL_SECURITY_INFORMATION, sd));
  LocalFree(sd);
  SD_CHECK_EQ_INT(sd_known_hosts_source_state(kh, SD_KH_SRC_OPENSSH, &ss, sid, SD_COUNTOF(sid)), SD_OK);
  SD_CHECK_EQ_INT(ss, SD_KH_SRC_INSECURE);
  SD_CHECK(wcscmp(sid, L"S-1-1-0") == 0);
  SD_CHECK_EQ_INT(sd_known_hosts_check(kh, "h1", a, al, 0, &r), SD_OK);
  SD_CHECK_EQ_INT(r.status, SD_HK_NEW);                 /* skipped entirely */
  sd_known_hosts_close(kh);
  DeleteFileW(user);
  /* restore a deletable DACL */
  if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;FA;;;OW)(A;;FA;;;SY)", SDDL_REVISION_1, &sd, NULL)) {
    SetFileSecurityW(live, DACL_SECURITY_INFORMATION, sd);
    LocalFree(sd);
  }
  DeleteFileW(live);
}

/* Ed25519 base point B and the P-256 generator G as PuTTY stores them. */
#define ED_X "0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a"
#define ED_Y "0x6666666666666666666666666666666666666666666666666666666666666658"
#define P256_X "0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
#define P256_Y "0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
#define RSA_N "0xd22337205d201c5fe7308f4f5422eefb72b99fab57b408a73a2563df55a6b8368335cf46a6c76177d8da0ac754d8ec3393384be253bd0a97d50f5d5d64db0b07857fbe9a9294791a87c381dff63bff88251cbdcf36c7082396b91e31f89fe4c0811c510c72f5781924dfeced0aab0e8a2353039a04defe906946dfe81a2e2a05eb1137cd7b8aebb1acdf69d78048b2ab2591ae21bae21b76227694977293a92502ad01f8bd13d3d532a6a9974c6e3b11a3e285fbd47cd299613979d90c05fb473f2e76f2d658938648d85bf947fe56deefb5902d06fe3bcc50457b7f004d8a50e03e21e90a72e2268ceee865055a4ee810e610fd33dafd85da84ade8882d522f"

static int line_of(const wchar_t *name, const wchar_t *data, char *out, size_t cap, sd_err *err)
{
  sd_wr w;
  sd_wr_init(&w, 1u << 16);
  *err = ssh_putty_value_to_line(name, data, &w);
  if (*err == SD_OK && w.len < cap) { memcpy(out, w.p, w.len); out[w.len] = '\0'; }
  else out[0] = '\0';
  sd_wr_free(&w);
  return *err == SD_OK;
}

SD_TEST(tr_kh_putty_values)
{
  char line[2048], want[512], b64[256];
  uint8_t blob[128];
  sd_wr w;
  sd_err e;
  if (!tu_crypto_or_skip("tr_kh_putty_values")) return;
  /* ed25519: y little-endian with bit 255 = x & 1 */
  sd_wr_init_fixed(&w, blob, sizeof(blob));
  sd_wr_cstring(&w, "ssh-ed25519");
  {
    uint8_t pk[32];
    memset(pk, 0x66, 32);
    pk[0] = 0x58;
    sd_wr_string(&w, pk, 32);
  }
  ssh_b64_encode(w.p, w.len, b64, sizeof(b64), 1);
  _snprintf_s(want, sizeof(want), _TRUNCATE, "host.example ssh-ed25519 %s\n", b64);
  SD_CHECK(line_of(L"ssh-ed25519@22:host.example", L"" ED_X L"," ED_Y, line, sizeof(line), &e));
  SD_CHECK_STR(line, want);
  /* off the curve */
  SD_CHECK(!line_of(L"ssh-ed25519@22:host.example", L"" ED_X L",0x6666666666666666666666666666666666666666666666666666666666666659",
                    line, sizeof(line), &e));
  SD_CHECK_EQ_INT(e, SD_E_KEY_FORMAT);
  /* ECDSA P-256, port != 22, escaped name, upper case host */
  SD_CHECK(line_of(L"ecdsa-sha2-nistp256@2222:%2EHost.Example", L"nistp256," P256_X L"," P256_Y, line, sizeof(line), &e));
  /* the comparison length is the literal's own length: the old fixed 96 read past its NUL terminator */
  SD_CHECK(strncmp(line, "[.host.example]:2222 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGsX",
                   sizeof("[.host.example]:2222 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGsX") - 1) == 0);
  SD_CHECK(!line_of(L"ecdsa-sha2-nistp256@22:h", L"nistp256," P256_X L",0x01", line, sizeof(line), &e));
  SD_CHECK(!line_of(L"ecdsa-sha2-nistp384@22:h", L"nistp256," P256_X L"," P256_Y, line, sizeof(line), &e));
  /* RSA */
  SD_CHECK(line_of(L"rsa2@22:rsahost", L"0x10001," RSA_N, line, sizeof(line), &e));
  SD_CHECK(strncmp(line, "rsahost ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDS", 47) == 0);
  SD_CHECK(!line_of(L"rsa2@22:rsahost", L"0x10001,0xd2233720", line, sizeof(line), &e));   /* < 1024 bits */
  /* unsupported and malformed */
  SD_CHECK(!line_of(L"dss@22:h", L"0x1,0x2,0x3,0x4", line, sizeof(line), &e));
  SD_CHECK_EQ_INT(e, SD_E_KEY_UNSUPPORTED);
  SD_CHECK(!line_of(L"ssh-ed448@22:h", L"0x1,0x2", line, sizeof(line), &e));
  SD_CHECK_EQ_INT(e, SD_E_KEY_UNSUPPORTED);
  SD_CHECK(!line_of(L"ssh-ed25519:host", L"" ED_X L"," ED_Y, line, sizeof(line), &e));
  SD_CHECK(!line_of(L"ssh-ed25519@0:host", L"" ED_X L"," ED_Y, line, sizeof(line), &e));
  SD_CHECK(!line_of(L"ssh-ed25519@22:bad%20host", L"" ED_X L"," ED_Y, line, sizeof(line), &e));
}

SD_TEST(tr_kh_putty_registry_source)
{
  wchar_t sub[160], user[MAX_PATH], user2[MAX_PATH];
  HKEY hk;
  sd_kh_store st[2];
  sd_known_hosts *kh = NULL;
  sd_hk_result r;
  sd_kh_src_state ss;
  sd_kh_import_report rep;
  uint8_t blob[128];
  sd_wr w;
  char *txt;
  static const wchar_t k_ed[] = L"" ED_X L"," ED_Y;
  static const wchar_t k_rsa[] = L"0x10001," RSA_N;
  static const wchar_t k_bad[] = L"0x1,0x2";
  if (!tu_crypto_or_skip("tr_kh_putty_registry_source")) return;
  _snwprintf_s(sub, SD_COUNTOF(sub), _TRUNCATE, L"Software\\LibreStatic\\ShellDriveTest\\SshHostKeys-%lu",
               (unsigned long)GetCurrentProcessId());
  SD_REQUIRE(RegCreateKeyExW(HKEY_CURRENT_USER, sub, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hk, NULL) == ERROR_SUCCESS);
  RegSetValueExW(hk, L"ssh-ed25519@22:host.example", 0, REG_SZ, (const BYTE *)k_ed, sizeof(k_ed));
  RegSetValueExW(hk, L"rsa2@2200:rsahost", 0, REG_SZ, (const BYTE *)k_rsa, sizeof(k_rsa));
  RegSetValueExW(hk, L"ssh-ed25519@22:broken", 0, REG_SZ, (const BYTE *)k_bad, sizeof(k_bad));
  RegCloseKey(hk);
  SD_REQUIRE(tu_temp_path(L"kh-putty\\known_hosts", user, SD_COUNTOF(user)));
  SD_REQUIRE(tu_temp_path(L"kh-putty2\\known_hosts", user2, SD_COUNTOF(user2)));
  DeleteFileW(user);
  DeleteFileW(user2);
  st[0].kind = SD_KH_STORE_USER; st[0].path = user; st[0].writable = 1;
  st[1].kind = SD_KH_SRC_PUTTY; st[1].path = sub; st[1].writable = 0;
  SD_REQUIRE(sd_known_hosts_open(st, 2, &kh) == SD_OK);
  SD_CHECK_EQ_INT(sd_known_hosts_source_state(kh, SD_KH_SRC_PUTTY, &ss, NULL, 0), SD_OK);
  SD_CHECK_EQ_INT(ss, SD_KH_SRC_OK);
  if (ss == SD_KH_SRC_OK) {
    uint8_t pk[32];
    sd_wr_init_fixed(&w, blob, sizeof(blob));
    sd_wr_cstring(&w, "ssh-ed25519");
    memset(pk, 0x66, 32);
    pk[0] = 0x58;
    sd_wr_string(&w, pk, 32);
    SD_CHECK_EQ_INT(sd_known_hosts_check(kh, "host.example", w.p, w.len, 0, &r), SD_OK);
    SD_CHECK_EQ_INT(r.status, SD_HK_MATCH);
    SD_CHECK_EQ_INT(r.store, SD_KH_SRC_PUTTY);
    txt = read_text(user);
    SD_CHECK(txt && strstr(txt, "# imported-from=putty added="));
    sd_free(txt);
    sd_known_hosts_close(kh);
    /* one-shot import into another store */
    st[0].path = user2;
    SD_REQUIRE(sd_known_hosts_open(st, 2, &kh) == SD_OK);
    SD_CHECK_EQ_INT(sd_known_hosts_import(kh, SD_KH_SRC_PUTTY, SD_KH_STORE_USER, &rep), SD_OK);
    SD_CHECK_EQ_INT(rep.imported, 2);
    SD_CHECK_EQ_INT(rep.invalid_lines, 1);
    SD_CHECK_EQ_INT(sd_known_hosts_import(kh, SD_KH_SRC_PUTTY, SD_KH_STORE_USER, &rep), SD_OK);
    SD_CHECK_EQ_INT(rep.already_present, 2);
    SD_CHECK_EQ_INT(rep.imported, 0);
    txt = read_text(user2);
    SD_CHECK(txt && strstr(txt, "[rsahost]:2200 ssh-rsa "));
    sd_free(txt);
  }
  sd_known_hosts_close(kh);
  RegDeleteKeyW(HKEY_CURRENT_USER, sub);
  DeleteFileW(user);
  DeleteFileW(user2);
}

typedef struct list_ctx { uint32_t n, explicit_n; } list_ctx;

static int count_cb(void *ctx, const sd_kh_entry *e)
{
  list_ctx *l = (list_ctx *)ctx;
  l->n++;
  if (e->explicit_name) l->explicit_n++;
  return 0;
}

SD_TEST(tr_kh_apply_hostkeys_and_remove_key)
{
  uint8_t a[128], b[128], c[128];
  size_t al, bl, cl;
  wchar_t path[MAX_PATH];
  sd_kh_store st;
  sd_known_hosts *kh = NULL;
  sd_hk_key add[2], rem[1];
  list_ctx lc;
  sd_hk_result r;
  char *txt;
  if (!tu_crypto_or_skip("tr_kh_apply_hostkeys_and_remove_key")) return;
  al = pub_blob(KEY_A, a, sizeof(a), NULL, 0);
  bl = pub_blob(KEY_B, b, sizeof(b), NULL, 0);
  cl = pub_blob("hk_host.pub", c, sizeof(c), NULL, 0);
  SD_REQUIRE(al && bl && cl);
  SD_REQUIRE(tu_temp_path(L"kh-apply\\known_hosts", path, SD_COUNTOF(path)));
  DeleteFileW(path);
  st.kind = SD_KH_STORE_USER; st.path = path; st.writable = 1;
  SD_REQUIRE(sd_known_hosts_open(&st, 1, &kh) == SD_OK);
  SD_CHECK_EQ_INT(sd_known_hosts_add(kh, SD_KH_STORE_USER, "[rot]:2236", a, al, NULL), SD_OK);
  SD_CHECK_EQ_INT(sd_known_hosts_add(kh, SD_KH_STORE_USER, "[rot]:2236,alias", c, cl, NULL), SD_E_INVALID_PARAM);
  memset(add, 0, sizeof(add));
  add[0].blob = b; add[0].len = bl;
  add[1].blob = a; add[1].len = al;        /* already present: skipped */
  SD_CHECK_EQ_INT(sd_known_hosts_apply_hostkeys(kh, SD_KH_STORE_USER, "[rot]:2236", add, 2, NULL, 0), SD_OK);
  memset(&lc, 0, sizeof(lc));
  SD_CHECK_EQ_INT(sd_known_hosts_list(kh, SD_KH_STORE_USER, "[rot]:2236", count_cb, &lc), SD_OK);
  SD_CHECK_EQ_INT(lc.n, 2);
  SD_CHECK_EQ_INT(lc.explicit_n, 2);
  txt = read_text(path);
  SD_CHECK(txt && strstr(txt, "# updated-by=hostkeys-00 added="));
  sd_free(txt);
  /* both keys of the same type MATCH (one store may hold several); the review then removes the old one */
  SD_CHECK_EQ_INT(sd_known_hosts_check(kh, "[rot]:2236", b, bl, 0, &r), SD_OK);
  SD_CHECK_EQ_INT(r.status, SD_HK_MATCH);
  SD_CHECK_EQ_INT(sd_known_hosts_check(kh, "[rot]:2236", a, al, 0, &r), SD_OK);
  SD_CHECK_EQ_INT(r.status, SD_HK_MATCH);
  memset(rem, 0, sizeof(rem));
  rem[0].blob = a; rem[0].len = al;
  SD_CHECK_EQ_INT(sd_known_hosts_apply_hostkeys(kh, SD_KH_STORE_USER, "[rot]:2236", NULL, 0, rem, 1), SD_OK);
  SD_CHECK_EQ_INT(sd_known_hosts_check(kh, "[rot]:2236", b, bl, 0, &r), SD_OK);
  SD_CHECK_EQ_INT(r.status, SD_HK_MATCH);
  /* a line naming several hosts is never removed by remove_key */
  {
    char text[512], cb64[128];
    sd_known_hosts_close(kh);
    SD_REQUIRE(pub_blob("hk_host.pub", c, sizeof(c), cb64, sizeof(cb64)));
    _snprintf_s(text, sizeof(text), _TRUNCATE, "multi,other ssh-ed25519 %s\n", cb64);
    SD_REQUIRE(write_text(path, text));
    SD_REQUIRE(sd_known_hosts_open(&st, 1, &kh) == SD_OK);
    SD_CHECK_EQ_INT(sd_known_hosts_remove_key(kh, SD_KH_STORE_USER, "multi", c, cl), SD_E_NOT_FOUND);
    memset(&lc, 0, sizeof(lc));
    SD_CHECK_EQ_INT(sd_known_hosts_list(kh, SD_KH_STORE_USER, "multi", count_cb, &lc), SD_OK);
    SD_CHECK(lc.n == 1 && lc.explicit_n == 0);
  }
  sd_known_hosts_close(kh);
  DeleteFileW(path);
}
