/* Canned-byte tests of the SFTP v3 codec (sftp_proto.c). */
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_test.h"
#include "sftp_proto.h"

SD_TEST(proto_status_mapping)
{
  static const struct { uint32_t st; sd_err e; } k[] = {
    { 0, SD_OK }, { 1, SD_E_EOF }, { 2, SD_E_NOT_FOUND }, { 3, SD_E_ACCESS_DENIED }, { 4, SD_E_FAILURE },
    { 5, SD_E_PROTOCOL }, { 6, SD_E_DISCONNECTED }, { 7, SD_E_DISCONNECTED }, { 8, SD_E_UNSUPPORTED },
    { 9, SD_E_STALE_HANDLE }, { 10, SD_E_NOT_FOUND }, { 11, SD_E_EXISTS }, { 12, SD_E_READ_ONLY },
    { 13, SD_E_FAILURE }, { 14, SD_E_NO_SPACE }, { 15, SD_E_QUOTA }, { 16, SD_E_INVALID_PARAM },
    { 17, SD_E_LOCK_CONFLICT }, { 18, SD_E_NOT_EMPTY }, { 19, SD_E_NOT_A_DIRECTORY },
    { 20, SD_E_INVALID_NAME }, { 21, SD_E_LINK_LOOP }, { 22, SD_E_ACCESS_DENIED },
    { 23, SD_E_INVALID_PARAM }, { 24, SD_E_IS_A_DIRECTORY }, { 25, SD_E_LOCK_CONFLICT },
    { 31, SD_E_INVALID_PARAM }, { 32, SD_E_INVALID_PARAM }, { 99, SD_E_FAILURE }, { 0xFFFFFFFFu, SD_E_FAILURE },
  };
  size_t i;
  for (i = 0; i < SD_COUNTOF(k); i++)
    SD_CHECK_EQ_INT(sd_sftp_status_to_err(k[i].st), k[i].e);
}

/* ATTRS with every v3 field and two extended pairs, as an OpenSSH-like server would send. */
static const uint8_t k_attrs_full[] = {
  0x80, 0x00, 0x00, 0x0F,                          /* flags: SIZE|UIDGID|PERM|ACMODTIME|EXTENDED */
  0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02,  /* size 0x100000002 */
  0x00, 0x00, 0x03, 0xE8, 0x00, 0x00, 0x00, 0x64,  /* uid 1000, gid 100 */
  0x00, 0x00, 0x81, 0xA4,                          /* perm 0100644 */
  0x65, 0x53, 0xF1, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,  /* atime, mtime 0xFFFFFFFF (2106) */
  0x00, 0x00, 0x00, 0x02,                          /* 2 pairs */
  0x00, 0x00, 0x00, 0x03, 'a', '@', 'b', 0x00, 0x00, 0x00, 0x01, 'X',
  0x00, 0x00, 0x00, 0x01, 'c', 0x00, 0x00, 0x00, 0x00,
};

SD_TEST(proto_attrs_decode_canned)
{
  sd_rd r;
  sd_sftp_attrs a;
  sd_sftp_extattr ext[4];
  uint32_t pairs = 0;
  sd_rd_init(&r, k_attrs_full, sizeof(k_attrs_full));
  SD_CHECK(sftp_count_attr_ext(&r, &pairs) == 0);
  SD_CHECK_EQ_U64(pairs, 2);
  SD_REQUIRE(sftp_dec_attrs(&r, &a, ext, 4) == 0);
  SD_CHECK(sd_rd_done(&r));
  SD_CHECK_EQ_U64(a.valid, 0xF);
  SD_CHECK_EQ_U64(a.size, 0x100000002ull);
  SD_CHECK_EQ_U64(a.uid, 1000);
  SD_CHECK_EQ_U64(a.gid, 100);
  SD_CHECK(SD_SFTP_IS_REG(&a));
  SD_CHECK_EQ_U64(a.mtime, 0xFFFFFFFFull);         /* unsigned: no sign extension */
  SD_CHECK_EQ_U64(a.atime, 0x6553F100ull);
  SD_REQUIRE(a.ext_count == 2 && a.ext == ext);
  SD_CHECK(ext[0].type_len == 3 && memcmp(ext[0].type, "a@b", 3) == 0);
  SD_CHECK(ext[0].data_len == 1 && ext[0].data[0] == 'X');
  SD_CHECK(ext[1].type_len == 1 && ext[1].data_len == 0);

  /* without ext storage: validated and skipped */
  sd_rd_init(&r, k_attrs_full, sizeof(k_attrs_full));
  SD_CHECK(sftp_dec_attrs(&r, &a, NULL, 0) == 0 && sd_rd_done(&r) && a.ext == NULL && a.ext_count == 0);
}

SD_TEST(proto_attrs_reject_malformed)
{
  static const uint8_t unknown_flag[] = { 0x00, 0x00, 0x00, 0x10 };
  static const uint8_t short_size[] = { 0x00, 0x00, 0x00, 0x01, 0x00, 0x00 };
  uint8_t many[4 + 4 + 65 * 8];
  sd_rd r;
  sd_sftp_attrs a;
  sd_rd_init(&r, unknown_flag, sizeof(unknown_flag));
  SD_CHECK(sftp_dec_attrs(&r, &a, NULL, 0) != 0);
  sd_rd_init(&r, short_size, sizeof(short_size));
  SD_CHECK(sftp_dec_attrs(&r, &a, NULL, 0) != 0);
  /* 65 extended pairs: over the cap of 64 */
  memset(many, 0, sizeof(many));
  many[0] = 0x80; many[7] = 65;
  sd_rd_init(&r, many, sizeof(many));
  SD_CHECK(sftp_dec_attrs(&r, &a, NULL, 0) != 0);
  many[7] = 64;
  sd_rd_init(&r, many, sizeof(many) - 8);
  SD_CHECK(sftp_dec_attrs(&r, &a, NULL, 0) == 0);
}

SD_TEST(proto_attrs_encode)
{
  sd_wr w;
  sd_sftp_attrs a;
  static const uint8_t expect[] = {
    0x00, 0x00, 0x00, 0x0D,                                  /* SIZE|PERM|TIMES */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
    0x00, 0x00, 0x01, 0xED,                                  /* 0755 */
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,          /* atime < 0 -> 0, mtime > 2^32 -> max */
  };
  memset(&a, 0, sizeof(a));
  a.valid = SD_SFTP_ATTR_SIZE | SD_SFTP_ATTR_PERM | SD_SFTP_ATTR_TIMES | SD_SFTP_ATTR_EXTENDED;
  a.size = 4096; a.perm = 0755; a.atime = -5; a.mtime = 0x1FFFFFFFFll;
  sd_wr_init(&w, 1024);
  sftp_enc_attrs(&w, &a);
  SD_REQUIRE(sd_wr_ok(&w));
  SD_CHECK_EQ_U64(w.len, sizeof(expect));
  SD_CHECK_MEM(w.p, expect, sizeof(expect));
  sd_wr_reset(&w);
  sftp_enc_attrs(&w, NULL);
  SD_CHECK(w.len == 4 && w.p[3] == 0);
  sd_wr_free(&w);
}

/* VERSION body (after the type byte) from OpenSSH 9.6 plus one unknown extension. */
static const char *const k_ver_exts[][2] = {
  { "posix-rename@openssh.com", "1" }, { "statvfs@openssh.com", "2" }, { "fstatvfs@openssh.com", "2" },
  { "hardlink@openssh.com", "1" }, { "fsync@openssh.com", "1" }, { "lsetstat@openssh.com", "1" },
  { "limits@openssh.com", "1" }, { "expand-path@openssh.com", "1" }, { "copy-data", "1" },
  { "home-directory", "1" }, { "users-groups-by-id@openssh.com", "1" }, { "x-future@example.org", "9" },
};

SD_TEST(proto_version_parse)
{
  sd_wr w;
  sftp_version_info *vi = (sftp_version_info *)sd_calloc(1, sizeof(*vi));
  size_t i;
  SD_REQUIRE(vi != NULL);
  sd_wr_init(&w, 4096);
  sd_wr_u32(&w, 3);
  for (i = 0; i < SD_COUNTOF(k_ver_exts); i++) { sd_wr_cstring(&w, k_ver_exts[i][0]); sd_wr_cstring(&w, k_ver_exts[i][1]); }
  SD_REQUIRE(sftp_parse_version(w.p, w.len, vi) == 0);
  SD_CHECK_EQ_U64(vi->version, 3);
  SD_CHECK_EQ_U64(vi->ext_count, SD_COUNTOF(k_ver_exts));
  SD_CHECK_EQ_U64(vi->ext, 0x7FF);                     /* all eleven known bits */
  SD_CHECK(vi->any_openssh);
  SD_CHECK(vi->names[11].n == 20 && memcmp(vi->names[11].p, "x-future@example.org", 20) == 0);
  /* a known name with another version does not set the bit */
  SD_CHECK_EQ_U64(sftp_ext_bit((const uint8_t *)"statvfs@openssh.com", 19, (const uint8_t *)"1", 1), 0);
  SD_CHECK_EQ_U64(sftp_ext_bit((const uint8_t *)"fsync@openssh.com", 17, (const uint8_t *)"1", 1), SD_SFTP_EXT_FSYNC);
  /* truncated extension pair */
  SD_CHECK(sftp_parse_version(w.p, w.len - 1, vi) != 0);
  /* bare version 3, no extensions */
  SD_CHECK(sftp_parse_version(w.p, 4, vi) == 0 && vi->ext_count == 0 && vi->ext == 0 && !vi->any_openssh);
  sd_wr_free(&w);
  sd_free(vi);
}

SD_TEST(proto_limits_effective)
{
  uint64_t none[4] = { 0, 0, 0, 0 };
  uint64_t openssh[4] = { 262144, 261120, 261120, 1024 };
  uint64_t huge[4] = { 1ull << 40, 1ull << 30, 1ull << 30, 0 };
  sd_sftp_limits l;
  sftp_effective_limits(none, &l);
  SD_CHECK(l.max_packet == 34000 && l.max_read == 32768 && l.max_write == 32768 && l.max_open_handles != 0);
  sftp_effective_limits(openssh, &l);
  SD_CHECK(l.max_packet == 262144 && l.max_read == 261120 && l.max_write == 261120 && l.max_open_handles == 1024);
  sftp_effective_limits(huge, &l);
  SD_CHECK(l.max_read == 255 * 1024 && l.max_write == 255 * 1024);
}

SD_TEST(proto_limits_and_statvfs_parse)
{
  uint8_t buf[11 * 8];
  uint64_t v[4];
  sd_sftp_statvfs sv;
  sd_rd r;
  size_t i;
  for (i = 0; i < 11; i++) sd_store_be64(buf + i * 8, 0x0102030405060700ull + i);
  sd_rd_init(&r, buf, 32);
  SD_CHECK(sftp_parse_limits(&r, v) == 0 && v[3] == 0x0102030405060703ull);
  sd_rd_init(&r, buf, sizeof(buf));
  SD_CHECK(sftp_parse_statvfs(&r, &sv) == 0 && sv.bsize == 0x0102030405060700ull && sv.namemax == 0x010203040506070Aull);
  sd_rd_init(&r, buf, sizeof(buf) - 1);
  SD_CHECK(sftp_parse_statvfs(&r, &sv) != 0);
}

SD_TEST(proto_dirent_filter)
{
  SD_CHECK(sftp_dirent_name_ok((const uint8_t *)"a", 1));
  SD_CHECK(sftp_dirent_name_ok((const uint8_t *)"...", 3));
  SD_CHECK(sftp_dirent_name_ok((const uint8_t *)"\xff\xfe", 2));      /* raw bytes pass */
  SD_CHECK(!sftp_dirent_name_ok((const uint8_t *)"", 0));
  SD_CHECK(!sftp_dirent_name_ok((const uint8_t *)".", 1));
  SD_CHECK(!sftp_dirent_name_ok((const uint8_t *)"..", 2));
  SD_CHECK(!sftp_dirent_name_ok((const uint8_t *)"a/b", 3));
  SD_CHECK(!sftp_dirent_name_ok((const uint8_t *)"a\0b", 3));
}

SD_TEST(proto_packet_framing)
{
  sd_wr w;
  size_t st;
  static const uint8_t init3[] = { 0, 0, 0, 5, 1, 0, 0, 0, 3 };
  static const uint8_t stat_pkt[] = { 0, 0, 0, 14, 17, 0, 0, 0, 7, 0, 0, 0, 5, '/', 't', 'm', 'p', '/' };
  sd_wr_init(&w, 1024);
  st = sftp_pkt_begin(&w, 1, 0, 0);
  sd_wr_u32(&w, 3);
  sftp_pkt_end(&w, st);
  SD_CHECK(w.len == sizeof(init3));
  SD_CHECK_MEM(w.p, init3, sizeof(init3));
  sd_wr_reset(&w);
  st = sftp_pkt_begin(&w, 17, 1, 7);
  sd_wr_cstring(&w, "/tmp/");
  sftp_pkt_end(&w, st);
  SD_CHECK(w.len == sizeof(stat_pkt));
  SD_CHECK_MEM(w.p, stat_pkt, sizeof(stat_pkt));
  sd_wr_free(&w);
}

SD_TEST(proto_win_drive_path)
{
  SD_CHECK(sftp_is_win_drive_path("/C:/Users/x", 11));
  SD_CHECK(sftp_is_win_drive_path("/d:", 3));
  SD_CHECK(!sftp_is_win_drive_path("/home/x", 7));
  SD_CHECK(!sftp_is_win_drive_path("/1:/x", 5));
  SD_CHECK(!sftp_is_win_drive_path("/C:x", 4));
}
