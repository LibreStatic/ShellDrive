/* Unit tests of the diag pieces that have no system dependency: the stored ZIP writer (cli_zip.c) and the
 * anonymizer (cli_anon.c). Both are pure; the sinks here keep the bytes in memory. */
#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "sd_test.h"
#include "cli_zip.h"
#include "cli_anon.h"
#include "cli_diag_rules.h"
#include "sd_base/sd_buf.h"
#include "sd_base/sd_mem.h"

/* ---- memory sink ---- */

typedef struct mem_sink {
  unsigned char buf[8192];
  size_t n;
  int fail_after;          /* < 0: never fail; else fail the write that would pass this many bytes */
} mem_sink;

static int mem_write(void *ctx, const void *p, size_t n)
{
  mem_sink *m = (mem_sink *)ctx;
  if (m->fail_after >= 0 && m->n + n > (size_t)m->fail_after)
    return 1;
  if (m->n + n > sizeof(m->buf))
    return 1;
  memcpy(m->buf + m->n, p, n);
  m->n += n;
  return 0;
}

static uint32_t rd32(const unsigned char *p)
{
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint16_t rd16(const unsigned char *p)
{
  return (uint16_t)(p[0] | (p[1] << 8));
}

static size_t find_bytes(const unsigned char *hay, size_t hn, const void *needle, size_t nn)
{
  size_t i;
  if (nn == 0 || hn < nn)
    return (size_t)-1;
  for (i = 0; i + nn <= hn; i++)
    if (memcmp(hay + i, needle, nn) == 0)
      return i;
  return (size_t)-1;
}

/* ---- ZIP ---- */

SD_TEST(zip_crc32_matches_the_check_value)
{
  /* the standard check value of CRC-32 (IEEE): "123456789" -> 0xCBF43926 */
  SD_CHECK(zip_crc32(0, "123456789", 9) == 0xCBF43926u);
  /* streaming gives the same value */
  {
    uint32_t c = zip_crc32(0, "1234", 4);
    c = zip_crc32(c, "56789", 5);
    SD_CHECK(c == 0xCBF43926u);
  }
  SD_CHECK(zip_crc32(0, "", 0) == 0);
}

SD_TEST(zip_writes_stored_entries_with_descriptors)
{
  static mem_sink m;
  zip_writer *z;
  SYSTEMTIME st;
  const unsigned char *b;
  size_t pos, eocd;
  uint32_t cd_off, cd_size;
  memset(&st, 0, sizeof(st));
  st.wYear = 2026; st.wMonth = 10; st.wDay = 28; st.wHour = 9; st.wMinute = 14; st.wSecond = 3;
  m.n = 0;
  m.fail_after = -1;
  z = zip_open(mem_write, &m);
  SD_REQUIRE(z != NULL);
  SD_CHECK(zip_add_begin(z, "logs/ui.log", &st) == SD_OK);
  SD_CHECK(zip_add_data(z, "hello ", 6) == SD_OK);
  SD_CHECK(zip_add_data(z, "world", 5) == SD_OK);
  SD_CHECK(zip_add_end(z) == SD_OK);
  SD_CHECK(zip_add_begin(z, "README.txt", NULL) == SD_OK);
  SD_CHECK(zip_add_end(z) == SD_OK);            /* an empty entry is valid */
  SD_CHECK(zip_entry_count(z) == 2);
  SD_CHECK(zip_finish(z) == SD_OK);
  SD_CHECK(zip_add_begin(z, "late.txt", NULL) != SD_OK);   /* no entry after the end record */
  SD_CHECK(zip_finish(z) != SD_OK);
  SD_CHECK(zip_bytes(z) == m.n);
  zip_free(z);

  b = m.buf;
  /* first local header: signature, flags 0x0808 (data descriptor, UTF-8), method 0, the name and the data */
  SD_CHECK(rd32(b) == 0x04034b50u);
  SD_CHECK(rd16(b + 6) == 0x0808u);
  SD_CHECK(rd16(b + 8) == 0);
  SD_CHECK(rd16(b + 26) == 11);                 /* "logs/ui.log" */
  SD_CHECK(memcmp(b + 30, "logs/ui.log", 11) == 0);
  SD_CHECK(memcmp(b + 41, "hello world", 11) == 0);
  /* the data descriptor after the data carries the CRC and both sizes */
  pos = 41 + 11;
  SD_CHECK(rd32(b + pos) == 0x08074b50u);
  SD_CHECK(rd32(b + pos + 4) == zip_crc32(0, "hello world", 11));
  SD_CHECK(rd32(b + pos + 8) == 11 && rd32(b + pos + 12) == 11);
  pos += 16;
  /* the empty entry follows with size 0 and crc 0 */
  SD_CHECK(rd32(b + pos) == 0x04034b50u);
  SD_CHECK(rd16(b + pos + 26) == 10);          /* "README.txt" */
  pos += 30 + 10 + 16;
  /* the central directory of two entries, then the end record */
  eocd = m.n - 22;
  SD_CHECK(rd32(b + eocd) == 0x06054b50u);
  SD_CHECK(rd16(b + eocd + 8) == 2 && rd16(b + eocd + 10) == 2);
  cd_size = rd32(b + eocd + 12);
  cd_off = rd32(b + eocd + 16);
  SD_CHECK(cd_off == pos);
  SD_CHECK(cd_off + cd_size == eocd);
  SD_CHECK(rd32(b + cd_off) == 0x02014b50u);
  SD_CHECK(rd32(b + cd_off + 42) == 0);        /* the first local header is at offset 0 */
  SD_CHECK(rd16(b + cd_off + 28) == 11);       /* name length of the first entry */
  SD_CHECK(find_bytes(b + cd_off, cd_size, "README.txt", 10) != (size_t)-1);
  /* the DOS date of 2026-10-28 is ((2026-1980) << 9) | (10 << 5) | 28 */
  SD_CHECK(rd16(b + 12) == (uint16_t)(((2026 - 1980) << 9) | (10 << 5) | 28));
}

SD_TEST(zip_refuses_bad_names_and_sink_failures)
{
  static mem_sink m;
  zip_writer *z;
  m.n = 0;
  m.fail_after = -1;
  z = zip_open(mem_write, &m);
  SD_REQUIRE(z != NULL);
  SD_CHECK(zip_add_begin(z, "../escape.txt", NULL) == SD_E_INVALID_PARAM);
  SD_CHECK(zip_add_begin(z, "/absolute.txt", NULL) == SD_E_INVALID_PARAM);
  SD_CHECK(zip_add_begin(z, "back\\slash.txt", NULL) == SD_E_INVALID_PARAM);
  SD_CHECK(zip_add_begin(z, "", NULL) == SD_E_INVALID_PARAM);
  SD_CHECK(zip_add_data(z, "x", 1) == SD_E_INVALID_PARAM);       /* no entry open */
  zip_free(z);

  /* a sink that fails: the error is sticky and the writer refuses to go on */
  memset(&m, 0, sizeof(m));
  m.fail_after = 20;
  z = zip_open(mem_write, &m);
  SD_REQUIRE(z != NULL);
  SD_CHECK(zip_add_begin(z, "a-long-name-for-the-entry.txt", NULL) != SD_OK);
  SD_CHECK(zip_finish(z) != SD_OK);
  zip_free(z);
  SD_CHECK(zip_open(NULL, NULL) == NULL);
}

/* ---- anonymizer ---- */

static int is_token(const char *s, char kind)
{
  size_t i;
  if (strlen(s) != 8 || s[0] != kind || s[1] != ':')
    return 0;
  for (i = 2; i < 8; i++)
    if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
      return 0;
  return 1;
}

static int out_has(const sd_wr *w, const char *s)
{
  return find_bytes((const unsigned char *)w->p, w->len, s, strlen(s)) != (size_t)-1;
}

SD_TEST(anon_tokens_are_stable_per_context)
{
  anon_ctx *c = anon_new(1), *d = anon_new(1);
  char t1[16], t2[16], t3[16], t4[16];
  SD_REQUIRE(c != NULL && d != NULL);
  anon_token(c, 'h', "example.org", t1, sizeof(t1));
  anon_token(c, 'h', "example.org", t2, sizeof(t2));
  anon_token(c, 'u', "example.org", t3, sizeof(t3));
  anon_token(d, 'h', "example.org", t4, sizeof(t4));
  SD_CHECK(is_token(t1, 'h'));
  SD_CHECK(strcmp(t1, t2) == 0);           /* same value, same context: same token */
  SD_CHECK(is_token(t3, 'u'));
  SD_CHECK(strcmp(t1, t3) != 0);           /* the kind is part of the token */
  SD_CHECK(strcmp(t1, t4) != 0);           /* another context (another random key): another token */
  anon_free(c);
  anon_free(d);
}

SD_TEST(anon_log_lines_hide_fields_and_registered_values)
{
  anon_ctx *c = anon_new(1);
  sd_wr w;
  /* a field value runs to the next "key=" or to the end of the line, so the free text comes first */
  const char *line = "2026-10-28T09:14:03.000Z 4412 7720 INFO  ssh  kex done "
                     "host=example.org user=alice rpath=/home/alice/secret.txt";
  SD_REQUIRE(c != NULL);
  sd_wr_init(&w, 256);
  SD_CHECK(anon_log_line(c, line, strlen(line), &w) == SD_OK);
  SD_CHECK(!out_has(&w, "example.org"));
  SD_CHECK(!out_has(&w, "alice"));
  SD_CHECK(!out_has(&w, "secret.txt"));
  SD_CHECK(out_has(&w, "host=h:") && out_has(&w, "user=u:") && out_has(&w, "rpath=p:"));
  SD_CHECK(out_has(&w, "kex done"));
  sd_wr_free(&w);

  /* a value registered earlier is hidden in free text too, ASCII case ignored */
  anon_add_value(c, 'h', "Example.ORG");
  sd_wr_init(&w, 256);
  SD_CHECK(anon_log_line(c, "connect to EXAMPLE.org failed", 30, &w) == SD_OK);
  SD_CHECK(!out_has(&w, "EXAMPLE.org") && !out_has(&w, "example"));
  sd_wr_free(&w);
  anon_free(c);
}

SD_TEST(anon_log_lines_redact_secrets_always)
{
  anon_ctx *off = anon_new(0), *on = anon_new(1);
  sd_wr w;
  const char *line = "auth password=hunter2 passphrase=pw-12 user=bob";
  SD_REQUIRE(off != NULL && on != NULL);
  sd_wr_init(&w, 256);
  SD_CHECK(anon_log_line(on, line, strlen(line), &w) == SD_OK);
  SD_CHECK(out_has(&w, "password=<redacted>") && out_has(&w, "passphrase=<redacted>"));
  SD_CHECK(!out_has(&w, "hunter2") && !out_has(&w, "pw-12") && !out_has(&w, "bob"));
  sd_wr_free(&w);

  /* --no-anonymize keeps host and user names, but secrets are still redacted */
  sd_wr_init(&w, 256);
  SD_CHECK(anon_log_line(off, line, strlen(line), &w) == SD_OK);
  SD_CHECK(out_has(&w, "user=bob") && out_has(&w, "password=<redacted>"));
  SD_CHECK(!out_has(&w, "hunter2"));
  sd_wr_free(&w);
  anon_free(on);
  anon_free(off);
}

SD_TEST(anon_config_lines_keep_structure)
{
  anon_ctx *c = anon_new(1);
  sd_wr w;
  const char *l1 = "host = example.org";
  const char *l2 = "password = s3cret";
  const char *l3 = "identity = C:\\Users\\alice\\id_ed25519";
  const char *l4 = "[log]";
  const char *l5 = "privacy = strict";
  const char *l6 = "; a comment";
  SD_REQUIRE(c != NULL);
  sd_wr_init(&w, 256);
  SD_CHECK(anon_config_line(c, l1, strlen(l1), &w) == SD_OK);
  SD_CHECK(out_has(&w, "host = h:") && !out_has(&w, "example.org"));
  sd_wr_reset(&w);
  SD_CHECK(anon_config_line(c, l2, strlen(l2), &w) == SD_OK);
  SD_CHECK(out_has(&w, "password = <redacted>") && !out_has(&w, "s3cret"));
  sd_wr_reset(&w);
  SD_CHECK(anon_config_line(c, l3, strlen(l3), &w) == SD_OK);
  SD_CHECK(out_has(&w, "identity = p:") && !out_has(&w, "alice"));
  sd_wr_reset(&w);
  SD_CHECK(anon_config_line(c, l4, strlen(l4), &w) == SD_OK && out_has(&w, "[log]") && w.len == strlen(l4));
  sd_wr_reset(&w);
  SD_CHECK(anon_config_line(c, l5, strlen(l5), &w) == SD_OK && out_has(&w, "privacy = strict"));
  sd_wr_reset(&w);
  SD_CHECK(anon_config_line(c, l6, strlen(l6), &w) == SD_OK && w.len == strlen(l6));
  sd_wr_free(&w);
  anon_free(c);
}

SD_TEST(anon_secret_key_names)
{
  SD_CHECK(anon_is_secret_key("password", 8));
  SD_CHECK(anon_is_secret_key("Passphrase", 10));
  SD_CHECK(anon_is_secret_key("proxy_password", 14));
  SD_CHECK(anon_is_secret_key("api_token", 9));
  SD_CHECK(anon_is_secret_key("client_secret", 13));
  SD_CHECK(anon_is_secret_key("credential", 10));
  SD_CHECK(!anon_is_secret_key("host", 4));
  SD_CHECK(!anon_is_secret_key("remote_path", 11));
  SD_CHECK(!anon_is_secret_key("identity", 8));
}

/* ---- diag rules (cli_diag_rules.c): versions, the dokany-deny list, Network location sync ---- */

SD_TEST(diag_version_parse_and_text)
{
  char t[16];
  SD_CHECK(diag_version_parse("2.3.1", 5) == 2003001u);
  SD_CHECK(diag_version_parse("2.3.1.1000", 10) == 2003001u);
  SD_CHECK(diag_version_parse("2.3", 3) == 2003000u);
  SD_CHECK(diag_version_parse("2", 1) == 0);
  SD_CHECK(diag_version_parse("2.x.1", 5) == 0);
  SD_CHECK(diag_version_parse("2..1", 4) == 0);
  SD_CHECK(diag_version_parse("1.2.3.4.5", 9) == 0);
  SD_CHECK(diag_version_parse("", 0) == 0);
  diag_version_text(2003001u, t, sizeof(t));
  SD_CHECK(strcmp(t, "2.3.1") == 0);
  diag_version_text(0, t, sizeof(t));
  SD_CHECK(t[0] == 0);
}

SD_TEST(diag_deny_parse_and_match)
{
  static const char text[] =
      "shelldrive-manifest 1\n"
      "dokany-deny 2.0.0-2.2.9 dokany-cve-2018\n"
      "dokany-deny 2.3.0-2.3.0 reason-b\r\n"
      "dokany-deny 3.0.0-2.0.0 backwards\n"
      "dokany-deny 2.1.0 nodash\n"
      "xdokany-deny 9.0.0-9.9.9 other\n"
      "dokany-deny 2.3.1-2.3.1\n";
  diag_deny_list d;
  const char *m;
  memset(&d, 0, sizeof(d));
  diag_deny_parse(&d, text, strlen(text));
  SD_CHECK(d.count == 3);
  m = diag_deny_match(&d, diag_version_pack(2, 2, 9));
  SD_CHECK(m != NULL && strcmp(m, "dokany-cve-2018") == 0);
  m = diag_deny_match(&d, diag_version_pack(2, 3, 0));
  SD_CHECK(m != NULL && strcmp(m, "reason-b") == 0);
  m = diag_deny_match(&d, diag_version_pack(2, 3, 1));
  SD_CHECK(m != NULL && strcmp(m, "unspecified") == 0);
  SD_CHECK(diag_deny_match(&d, diag_version_pack(2, 2, 10)) == NULL);
  SD_CHECK(diag_deny_match(&d, diag_version_pack(2, 0, 0)) != NULL);
  SD_CHECK(diag_deny_match(&d, 0) == NULL);
  SD_CHECK(diag_deny_match(&d, diag_version_pack(9, 9, 9)) == NULL);
}

SD_TEST(diag_deny_parse_truncates_at_the_capacity)
{
  diag_deny_list d;
  char text[4096];
  size_t n = 0, i;
  memset(&d, 0, sizeof(d));
  for (i = 0; i < 40; i++)
    n += (size_t)sprintf_s(text + n, sizeof(text) - n, "dokany-deny 2.0.%u-2.0.%u r%u\n", (unsigned)i, (unsigned)i,
                           (unsigned)i);
  diag_deny_parse(&d, text, n);
  SD_CHECK(d.count == DIAG_DENY_MAX);
  SD_CHECK(diag_deny_match(&d, diag_version_pack(2, 0, 0)) != NULL);
}

SD_TEST(diag_netloc_compare_token_lists)
{
  int missing = -1, stale = -1, wanted = -1;
  diag_netloc_compare("aa\nbb\n", "aa,cc\n", &missing, &stale, &wanted);
  SD_CHECK(wanted == 2 && missing == 1 && stale == 1);
  diag_netloc_compare("", "", &missing, &stale, &wanted);
  SD_CHECK(wanted == 0 && missing == 0 && stale == 0);
  diag_netloc_compare("  aa  bb", "bb aa", &missing, &stale, &wanted);
  SD_CHECK(wanted == 2 && missing == 0 && stale == 0);
  diag_netloc_compare("aa", "aab", &missing, &stale, &wanted);
  SD_CHECK(wanted == 1 && missing == 1 && stale == 1);
}
