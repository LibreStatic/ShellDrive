#include <string.h>

#include "sd_base/sd_buf.h"
#include "sd_test.h"

SD_TEST(buf_reads_integers)
{
  static const uint8_t in[] = { 0x01, 0x00, 0x00, 0x01, 0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00 };
  sd_rd r;
  sd_rd_init(&r, in, sizeof(in));
  SD_CHECK_EQ_U64(sd_rd_u8(&r), 1);
  SD_CHECK_EQ_U64(sd_rd_u32(&r), 0x00000102u);
  SD_CHECK_EQ_U64(sd_rd_u64(&r), 0x0102030405060708ull);
  SD_CHECK_EQ_INT(sd_rd_bool(&r), 0);
  SD_CHECK(sd_rd_done(&r));
}

SD_TEST(buf_short_input_is_sticky)
{
  static const uint8_t in[] = { 0x00, 0x00, 0x01 };
  sd_rd r;
  sd_rd_init(&r, in, sizeof(in));
  SD_CHECK_EQ_U64(sd_rd_u32(&r), 0);
  SD_CHECK(!sd_rd_ok(&r));
  SD_CHECK_EQ_U64(sd_rd_u8(&r), 0);                  /* still failing */
  SD_CHECK(!sd_rd_done(&r));
}

SD_TEST(buf_string_respects_max)
{
  static const uint8_t in[] = { 0, 0, 0, 5, 'h', 'e', 'l', 'l', 'o' };
  sd_rd r;
  sd_span s;
  sd_rd_init(&r, in, sizeof(in));
  s = sd_rd_string(&r, 16);
  SD_REQUIRE(sd_rd_done(&r));
  SD_CHECK_EQ_U64(s.n, 5);
  SD_CHECK_MEM(s.p, "hello", 5);

  sd_rd_init(&r, in, sizeof(in));
  s = sd_rd_string(&r, 4);
  SD_CHECK(!sd_rd_ok(&r));
  SD_CHECK_EQ_U64(s.n, 0);

  /* length larger than the remaining input */
  sd_rd_init(&r, in, sizeof(in) - 1);
  sd_rd_string(&r, 16);
  SD_CHECK(!sd_rd_ok(&r));
}

SD_TEST(buf_trailing_data_fails_done)
{
  static const uint8_t in[] = { 0, 0, 0, 0, 0xFF };
  sd_rd r;
  sd_rd_init(&r, in, sizeof(in));
  sd_rd_string(&r, 16);
  SD_CHECK(sd_rd_ok(&r));
  SD_CHECK(!sd_rd_done(&r));
}

SD_TEST(buf_mpint_rfc4251_examples)
{
  /* RFC 4251 §5: 0, 0x9a378f9b2e332a7, 0x80, -0x1234 (rejected), -0xdeadbeef (rejected). */
  static const uint8_t zero[] = { 0, 0, 0, 0 };
  static const uint8_t v1[] = { 0, 0, 0, 8, 0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7 };
  static const uint8_t v80[] = { 0, 0, 0, 2, 0x00, 0x80 };
  static const uint8_t neg[] = { 0, 0, 0, 2, 0xed, 0xcc };
  static const uint8_t pad[] = { 0, 0, 0, 2, 0x00, 0x7f };     /* unneeded 00 */
  static const uint8_t zero_nc[] = { 0, 0, 0, 1, 0x00 };       /* zero must be empty */
  sd_rd r;
  sd_span s;

  sd_rd_init(&r, zero, sizeof(zero));
  s = sd_rd_mpint(&r, 64);
  SD_CHECK(sd_rd_done(&r) && s.n == 0);

  sd_rd_init(&r, v1, sizeof(v1));
  s = sd_rd_mpint(&r, 64);
  SD_CHECK(sd_rd_done(&r) && s.n == 8 && s.p[0] == 0x09);

  sd_rd_init(&r, v80, sizeof(v80));
  s = sd_rd_mpint(&r, 64);
  SD_CHECK(sd_rd_done(&r) && s.n == 1 && s.p[0] == 0x80);

  sd_rd_init(&r, neg, sizeof(neg));
  sd_rd_mpint(&r, 64);
  SD_CHECK(!sd_rd_ok(&r));

  sd_rd_init(&r, pad, sizeof(pad));
  sd_rd_mpint(&r, 64);
  SD_CHECK(!sd_rd_ok(&r));

  sd_rd_init(&r, zero_nc, sizeof(zero_nc));
  sd_rd_mpint(&r, 64);
  SD_CHECK(!sd_rd_ok(&r));
}

SD_TEST(buf_name_list)
{
  static const uint8_t good[] = { 0, 0, 0, 9, 'z', 'l', 'i', 'b', ',', 'n', 'o', 'n', 'e' };
  static const uint8_t empty_name[] = { 0, 0, 0, 5, 'a', ',', ',', 'b', 'c' };
  static const uint8_t trailing[] = { 0, 0, 0, 2, 'a', ',' };
  static const uint8_t nul[] = { 0, 0, 0, 3, 'a', 0, 'b' };
  static const uint8_t empty_list[] = { 0, 0, 0, 0 };
  sd_rd r;
  sd_span s, it;
  int n = 0;

  sd_rd_init(&r, good, sizeof(good));
  s = sd_rd_name_list(&r, 64);
  SD_REQUIRE(sd_rd_done(&r));
  SD_CHECK(sd_namelist_contains(s, "none"));
  SD_CHECK(sd_namelist_contains(s, "zlib"));
  SD_CHECK(!sd_namelist_contains(s, "zli"));
  while (sd_namelist_next(&s, &it))
    n++;
  SD_CHECK_EQ_INT(n, 2);

  sd_rd_init(&r, empty_name, sizeof(empty_name));
  sd_rd_name_list(&r, 64);
  SD_CHECK(!sd_rd_ok(&r));
  sd_rd_init(&r, trailing, sizeof(trailing));
  sd_rd_name_list(&r, 64);
  SD_CHECK(!sd_rd_ok(&r));
  sd_rd_init(&r, nul, sizeof(nul));
  sd_rd_name_list(&r, 64);
  SD_CHECK(!sd_rd_ok(&r));
  sd_rd_init(&r, empty_list, sizeof(empty_list));
  s = sd_rd_name_list(&r, 64);
  SD_CHECK(sd_rd_done(&r) && s.n == 0);
}

SD_TEST(buf_sub_reader)
{
  static const uint8_t in[] = { 0, 0, 0, 5, 0, 0, 0, 1, 'x', 0x2A };
  sd_rd r, sub;
  sd_span s;
  sd_rd_init(&r, in, sizeof(in));
  sub = sd_rd_sub(&r, 16);
  s = sd_rd_string(&sub, 8);
  SD_CHECK(sd_rd_done(&sub) && s.n == 1 && s.p[0] == 'x');
  SD_CHECK_EQ_U64(sd_rd_u8(&r), 0x2A);
  SD_CHECK(sd_rd_done(&r));
}

SD_TEST(buf_writer_roundtrip)
{
  static const char *const names[] = { "curve25519-sha256", "ext-info-c" };
  static const uint8_t mag[] = { 0x00, 0x00, 0x80, 0x01 };
  sd_wr w;
  sd_rd r;
  sd_span s;
  sd_wr_init(&w, 1024);
  sd_wr_u8(&w, 20);
  sd_wr_u32(&w, 0xDEADBEEFu);
  sd_wr_u64(&w, 0x1122334455667788ull);
  sd_wr_bool(&w, 7);
  sd_wr_cstring(&w, "ssh-userauth");
  sd_wr_mpint(&w, mag, sizeof(mag));
  sd_wr_name_list(&w, names, 2);
  SD_REQUIRE(sd_wr_ok(&w));

  sd_rd_init(&r, w.p, w.len);
  SD_CHECK_EQ_U64(sd_rd_u8(&r), 20);
  SD_CHECK_EQ_U64(sd_rd_u32(&r), 0xDEADBEEFu);
  SD_CHECK_EQ_U64(sd_rd_u64(&r), 0x1122334455667788ull);
  SD_CHECK_EQ_INT(sd_rd_bool(&r), 1);
  s = sd_rd_string(&r, 64);
  SD_CHECK(s.n == 12 && memcmp(s.p, "ssh-userauth", 12) == 0);
  s = sd_rd_mpint(&r, 64);
  SD_CHECK(s.n == 2 && s.p[0] == 0x80 && s.p[1] == 0x01);    /* leading zeros stripped, sign byte added */
  s = sd_rd_name_list(&r, 64);
  SD_CHECK(sd_namelist_contains(s, "ext-info-c"));
  SD_CHECK(sd_rd_done(&r));
  sd_wr_free(&w);
}

SD_TEST(buf_writer_limits)
{
  uint8_t fixed[6];
  sd_wr w;
  sd_wr_init_fixed(&w, fixed, sizeof(fixed));
  sd_wr_u32(&w, 1);
  SD_CHECK(sd_wr_ok(&w));
  sd_wr_u32(&w, 2);                                  /* would exceed 6 bytes */
  SD_CHECK(!sd_wr_ok(&w));
  SD_CHECK_EQ_U64(w.len, 4);

  sd_wr_init(&w, 8);
  sd_wr_u64(&w, 1);
  SD_CHECK(sd_wr_ok(&w));
  sd_wr_u8(&w, 1);                                   /* max reached */
  SD_CHECK(!sd_wr_ok(&w));
  sd_wr_free(&w);
}

SD_TEST(buf_writer_patch_and_secret)
{
  sd_wr w;
  sd_rd r;
  int i;
  sd_wr_init_secret(&w, 1u << 20);
  sd_wr_u32(&w, 0);
  for (i = 0; i < 1000; i++)                         /* forces several growth steps */
    sd_wr_u8(&w, (uint8_t)i);
  sd_wr_patch_u32(&w, 0, (uint32_t)(w.len - 4));
  SD_REQUIRE(sd_wr_ok(&w));
  sd_rd_init(&r, w.p, w.len);
  SD_CHECK_EQ_U64(sd_rd_u32(&r), 1000);
  sd_wr_patch_u32(&w, w.len - 2, 1);                 /* out of range */
  SD_CHECK(!sd_wr_ok(&w));
  sd_wr_free(&w);
  SD_CHECK(w.p == NULL);
}

SD_TEST(buf_writer_alloc_failure)
{
  sd_wr w;
  sd_wr_init(&w, 1024);
  sd_test_alloc_fail_after(0);
  sd_wr_u32(&w, 1);
  sd_test_alloc_fail_off();
  SD_CHECK(!sd_wr_ok(&w));
  sd_wr_u32(&w, 2);                                  /* sticky */
  SD_CHECK(!sd_wr_ok(&w));
  sd_wr_free(&w);
}
