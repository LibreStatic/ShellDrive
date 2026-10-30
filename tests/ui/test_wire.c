/* WM_COPYDATA codec and verb grammar (apps/shelldrive-ui/ui_wire.c). */
#include <windows.h>
#include <string.h>

#include "sd_test.h"
#include "sd_base/sd_err.h"
#include "sd_base/sd_mem.h"
#include "ui_wire.h"

static size_t raw_u32(unsigned char *p, size_t pos, uint32_t v)
{
  p[pos] = (unsigned char)(v & 0xFFu);
  p[pos + 1] = (unsigned char)((v >> 8) & 0xFFu);
  p[pos + 2] = (unsigned char)((v >> 16) & 0xFFu);
  p[pos + 3] = (unsigned char)((v >> 24) & 0xFFu);
  return pos + 4;
}

static size_t raw_header(unsigned char *p, uint32_t magic, uint32_t version, uint32_t argc)
{
  size_t pos = raw_u32(p, 0, magic);
  pos = raw_u32(p, pos, version);
  pos = raw_u32(p, pos, argc);
  return raw_u32(p, pos, 0);
}

/* One argument with an explicit unit count, whatever its content. */
static size_t raw_arg(unsigned char *p, size_t pos, const wchar_t *units, uint32_t n)
{
  uint32_t k;
  pos = raw_u32(p, pos, n);
  for (k = 0; k < n; k++) {
    unsigned c = (unsigned)(unsigned short)units[k];
    p[pos + 2 * k] = (unsigned char)(c & 0xFFu);
    p[pos + 2 * k + 1] = (unsigned char)(c >> 8);
  }
  return pos + 2 * (size_t)n;
}

static size_t encode_args(unsigned char *buf, size_t cap, const wchar_t *const *argv, int argc)
{
  unsigned char *out = NULL;
  size_t n = 0;
  if (ui_wire_encode(argc, argv, &out, &n) != SD_OK)
    return 0;
  if (n <= cap)
    memcpy(buf, out, n);
  else
    n = 0;
  sd_free(out);
  return n;
}

SD_TEST(wire_roundtrip_and_empty)
{
  static const wchar_t *const av[] = { L"--action", L"mount", L"0123456789abcdef0123456789abcdef" };
  unsigned char buf[UI_WIRE_MAX_BYTES];
  ui_request req;
  size_t n;

  n = encode_args(buf, sizeof(buf), av, 3);
  SD_REQUIRE(n > 0);
  SD_CHECK_EQ_INT(ui_request_from_payload(buf, n, &req), SD_OK);
  SD_CHECK_EQ_INT(req.verb, UI_VERB_MOUNT);
  SD_CHECK_EQ_INT(req.kind, UI_TARGET_PROFILE);
  SD_CHECK(wcscmp(req.target, av[2]) == 0);

  n = encode_args(buf, sizeof(buf), NULL, 0);
  SD_REQUIRE(n == UI_WIRE_HEADER);
  SD_CHECK_EQ_INT(ui_request_from_payload(buf, n, &req), SD_OK);
  SD_CHECK_EQ_INT(req.verb, UI_VERB_NONE);
}

SD_TEST(wire_rejects_bad_header)
{
  unsigned char buf[64];
  ui_request req;
  size_t n;

  n = raw_header(buf, 0x12345678u, UI_WIRE_VERSION, 0);
  SD_CHECK_EQ_INT(ui_request_from_payload(buf, n, &req), SD_E_INVALID_PARAM);
  n = raw_header(buf, UI_WIRE_MAGIC, UI_WIRE_VERSION + 1, 0);
  SD_CHECK_EQ_INT(ui_request_from_payload(buf, n, &req), SD_E_INVALID_PARAM);
  n = raw_header(buf, UI_WIRE_MAGIC, UI_WIRE_VERSION, 0);
  buf[12] = 1;                                  /* reserved word must be 0 */
  SD_CHECK_EQ_INT(ui_request_from_payload(buf, n, &req), SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(ui_request_from_payload(buf, 8, &req), SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(ui_request_from_payload(NULL, 16, &req), SD_E_INVALID_PARAM);
}

SD_TEST(wire_rejects_truncated_and_trailing)
{
  static const wchar_t arg[] = L"--tray";
  unsigned char buf[64];
  size_t n, pos;
  ui_request req;

  pos = raw_header(buf, UI_WIRE_MAGIC, UI_WIRE_VERSION, 1);
  pos = raw_arg(buf, pos, arg, 6);
  SD_CHECK_EQ_INT(ui_request_from_payload(buf, pos, &req), SD_OK);
  SD_CHECK_EQ_INT(req.verb, UI_VERB_TRAY);
  SD_CHECK_EQ_INT(ui_request_from_payload(buf, pos - 1, &req), SD_E_INVALID_PARAM);   /* truncated */
  buf[pos] = 0;
  SD_CHECK_EQ_INT(ui_request_from_payload(buf, pos + 1, &req), SD_E_INVALID_PARAM);   /* trailing byte */
  n = pos;
  SD_CHECK_EQ_INT(ui_request_from_payload(buf, n, &req), SD_OK);
}

SD_TEST(wire_rejects_bad_units)
{
  static const wchar_t surrogate[] = { 0xD800, L'a' };
  static const wchar_t lone_low[] = { 0xDC00 };
  static const wchar_t with_nul[] = { L'-', 0, L'-' };
  unsigned char buf[64];
  size_t pos;
  ui_request req;

  pos = raw_header(buf, UI_WIRE_MAGIC, UI_WIRE_VERSION, 2);
  pos = raw_arg(buf, pos, L"--action", 8);
  pos = raw_arg(buf, pos, surrogate, 2);
  SD_CHECK_EQ_INT(ui_request_from_payload(buf, pos, &req), SD_E_INVALID_PARAM);

  pos = raw_header(buf, UI_WIRE_MAGIC, UI_WIRE_VERSION, 1);
  pos = raw_arg(buf, pos, lone_low, 1);
  SD_CHECK_EQ_INT(ui_request_from_payload(buf, pos, &req), SD_E_INVALID_PARAM);

  pos = raw_header(buf, UI_WIRE_MAGIC, UI_WIRE_VERSION, 1);
  pos = raw_arg(buf, pos, with_nul, 3);
  SD_CHECK_EQ_INT(ui_request_from_payload(buf, pos, &req), SD_E_INVALID_PARAM);
}

SD_TEST(wire_rejects_too_many_or_too_long)
{
  static const wchar_t one[] = L"x";
  unsigned char buf[UI_WIRE_MAX_BYTES + 16];
  size_t pos, i;
  ui_request req;
  wchar_t *long_arg;
  const wchar_t *argv[UI_WIRE_MAX_ARGS + 1];

  /* argc above the limit */
  pos = raw_header(buf, UI_WIRE_MAGIC, UI_WIRE_VERSION, UI_WIRE_MAX_ARGS + 1);
  SD_CHECK_EQ_INT(ui_request_from_payload(buf, pos, &req), SD_E_INVALID_PARAM);

  /* an argument of MAX_UNITS units (no terminator room) */
  long_arg = sd_alloc(sizeof(wchar_t) * (UI_WIRE_MAX_UNITS + 1));
  SD_REQUIRE(long_arg != NULL);
  for (i = 0; i < UI_WIRE_MAX_UNITS; i++)
    long_arg[i] = L'a';
  long_arg[UI_WIRE_MAX_UNITS] = 0;
  argv[0] = long_arg;
  {
    unsigned char *none = NULL;
    size_t none_n = 0;
    SD_CHECK_EQ_INT(ui_wire_encode(1, argv, &none, &none_n), SD_E_INVALID_PARAM);
  }
  pos = raw_header(buf, UI_WIRE_MAGIC, UI_WIRE_VERSION, 1);
  pos = raw_arg(buf, pos, long_arg, UI_WIRE_MAX_UNITS);
  SD_CHECK_EQ_INT(ui_request_from_payload(buf, pos, &req), SD_E_INVALID_PARAM);
  sd_free(long_arg);

  /* eight arguments are accepted by the codec; the grammar then rejects them (not a verb) */
  for (i = 0; i < UI_WIRE_MAX_ARGS; i++)
    argv[i] = one;
  {
    unsigned char *out = NULL;
    size_t n = 0;
    SD_CHECK_EQ_INT(ui_wire_encode((int)UI_WIRE_MAX_ARGS, argv, &out, &n), SD_OK);
    if (out != NULL) {
      SD_CHECK_EQ_INT(ui_request_from_payload(out, n, &req), SD_E_INVALID_PARAM);
      sd_free(out);
    }
  }
}

SD_TEST(verbs_show_tray_prompt)
{
  static const wchar_t *const show[] = { L"--action", L"show" };
  static const wchar_t *const show_extra[] = { L"--action", L"show", L"x" };
  static const wchar_t *const tray[] = { L"--tray" };
  static const wchar_t *const host[] = { L"--prompt-host" };
  static const wchar_t *const tray_extra[] = { L"--tray", L"--tray" };
  ui_request req;

  SD_CHECK_EQ_INT(ui_request_from_args(0, NULL, &req), SD_OK);
  SD_CHECK_EQ_INT(req.verb, UI_VERB_NONE);
  SD_CHECK_EQ_INT(ui_request_from_args(2, show, &req), SD_OK);
  SD_CHECK_EQ_INT(req.verb, UI_VERB_SHOW);
  SD_CHECK_EQ_INT(ui_request_from_args(3, show_extra, &req), SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(ui_request_from_args(1, tray, &req), SD_OK);
  SD_CHECK_EQ_INT(req.verb, UI_VERB_TRAY);
  SD_CHECK_EQ_INT(ui_request_from_args(1, host, &req), SD_OK);
  SD_CHECK_EQ_INT(req.verb, UI_VERB_PROMPT_HOST);
  SD_CHECK_EQ_INT(ui_request_from_args(2, tray_extra, &req), SD_E_INVALID_PARAM);
}

SD_TEST(verbs_unmount_drive)
{
  static const wchar_t *const lower[] = { L"--action", L"unmount", L"e:" };
  static const wchar_t *const upper[] = { L"--action", L"unmount", L"Z:" };
  static const wchar_t *const bare[] = { L"--action", L"unmount", L"E" };
  static const wchar_t *const digit[] = { L"--action", L"unmount", L"1:" };
  static const wchar_t *const longer[] = { L"--action", L"unmount", L"EE:" };
  static const wchar_t *const slash[] = { L"--action", L"unmount", L"E:\\" };
  ui_request req;

  SD_CHECK_EQ_INT(ui_request_from_args(3, lower, &req), SD_OK);
  SD_CHECK_EQ_INT(req.verb, UI_VERB_UNMOUNT);
  SD_CHECK_EQ_INT(req.kind, UI_TARGET_DRIVE);
  SD_CHECK(wcscmp(req.target, L"E:") == 0);
  SD_CHECK_EQ_INT(ui_request_from_args(3, upper, &req), SD_OK);
  SD_CHECK(wcscmp(req.target, L"Z:") == 0);
  SD_CHECK_EQ_INT(ui_request_from_args(3, bare, &req), SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(ui_request_from_args(3, digit, &req), SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(ui_request_from_args(3, longer, &req), SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(ui_request_from_args(3, slash, &req), SD_E_INVALID_PARAM);
}

SD_TEST(verbs_mount_profile_id)
{
  static const wchar_t *const good[] = { L"--action", L"mount", L"0123456789abcdef0123456789abcdef" };
  static const wchar_t *const upper[] = { L"--action", L"mount", L"0123456789ABCDEF0123456789ABCDEF" };
  static const wchar_t *const short_id[] = { L"--action", L"mount", L"0123456789abcdef0123456789abcde" };
  static const wchar_t *const not_hex[] = { L"--action", L"mount", L"0123456789abcdef0123456789abcdeg" };
  static const wchar_t *const drive[] = { L"--action", L"mount", L"E:" };
  ui_request req;

  SD_CHECK_EQ_INT(ui_request_from_args(3, good, &req), SD_OK);
  SD_CHECK_EQ_INT(req.kind, UI_TARGET_PROFILE);
  SD_CHECK_EQ_INT(ui_request_from_args(3, upper, &req), SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(ui_request_from_args(3, short_id, &req), SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(ui_request_from_args(3, not_hex, &req), SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(ui_request_from_args(3, drive, &req), SD_E_INVALID_PARAM);
  SD_CHECK(ui_profile_id_valid(L"0123456789abcdef0123456789abcdef"));
  SD_CHECK(!ui_profile_id_valid(NULL));
}

SD_TEST(verbs_reconnect_and_mount_file)
{
  static const wchar_t *const reconnect_drive[] = { L"--action", L"reconnect", L"W:" };
  static const wchar_t *const reconnect_id[] = { L"--action", L"reconnect", L"0123456789abcdef0123456789abcdef" };
  static const wchar_t *const file_ok[] = { L"--action", L"mount-file", L"C:\\Users\\me\\share.sdmount" };
  static const wchar_t *const file_rel[] = { L"--action", L"mount-file", L"share\\x.sdmount" };
  static const wchar_t *const file_nocolon[] = { L"--action", L"mount-file", L"C\\x" };
  static const wchar_t *const file_dots[] = { L"--action", L"mount-file", L"C:\\a\\..\\b" };
  static const wchar_t *const file_bad[] = { L"--action", L"mount-file", L"C:\\a<b" };
  static const wchar_t *const file_ctl[] = { L"--action", L"mount-file", L"C:\\a\tb" };
  ui_request req;

  SD_CHECK_EQ_INT(ui_request_from_args(3, reconnect_drive, &req), SD_OK);
  SD_CHECK_EQ_INT(req.verb, UI_VERB_RECONNECT);
  SD_CHECK_EQ_INT(req.kind, UI_TARGET_DRIVE);
  SD_CHECK_EQ_INT(ui_request_from_args(3, reconnect_id, &req), SD_OK);
  SD_CHECK_EQ_INT(req.kind, UI_TARGET_PROFILE);

  SD_CHECK_EQ_INT(ui_request_from_args(3, file_ok, &req), SD_OK);
  SD_CHECK_EQ_INT(req.verb, UI_VERB_MOUNT_FILE);
  SD_CHECK_EQ_INT(req.kind, UI_TARGET_PATH);
  SD_CHECK(wcscmp(req.target, file_ok[2]) == 0);
  SD_CHECK_EQ_INT(ui_request_from_args(3, file_rel, &req), SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(ui_request_from_args(3, file_nocolon, &req), SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(ui_request_from_args(3, file_dots, &req), SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(ui_request_from_args(3, file_bad, &req), SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(ui_request_from_args(3, file_ctl, &req), SD_E_INVALID_PARAM);
}

SD_TEST(verbs_open_drive)
{
  static const wchar_t *const open_e[] = { L"--action", L"open", L"e:" };
  static const wchar_t *const open_bad[] = { L"--action", L"open", L"E:\\x" };
  static const wchar_t *const open_path[] = { L"--action", L"open", L"C:\\Users" };
  static const wchar_t *const open_id[] = { L"--action", L"open", L"0123456789abcdef0123456789abcdef" };
  ui_request req;

  SD_CHECK_EQ_INT(ui_request_from_args(3, open_e, &req), SD_OK);
  SD_CHECK_EQ_INT(req.verb, UI_VERB_OPEN);
  SD_CHECK_EQ_INT(req.kind, UI_TARGET_DRIVE);
  SD_CHECK(wcscmp(req.target, L"E:") == 0);
  SD_CHECK_EQ_INT(ui_request_from_args(3, open_bad, &req), SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(ui_request_from_args(3, open_path, &req), SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(ui_request_from_args(3, open_id, &req), SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(ui_request_from_args(2, open_e, &req), SD_E_INVALID_PARAM);
}

SD_TEST(verbs_unknown_are_rejected)
{
  static const wchar_t *const format[] = { L"--action", L"format", L"E:" };
  static const wchar_t *const upper_flag[] = { L"--Tray" };
  static const wchar_t *const bare_action[] = { L"--action" };
  static const wchar_t *const mount_only[] = { L"--action", L"mount" };
  static const wchar_t *const positional[] = { L"E:" };
  static const wchar_t *const tray_with_arg[] = { L"--tray", L"E:" };
  ui_request req;

  SD_CHECK_EQ_INT(ui_request_from_args(3, format, &req), SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(ui_request_from_args(1, upper_flag, &req), SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(ui_request_from_args(1, bare_action, &req), SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(ui_request_from_args(2, mount_only, &req), SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(ui_request_from_args(1, positional, &req), SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(ui_request_from_args(2, tray_with_arg, &req), SD_E_INVALID_PARAM);
  SD_CHECK(ui_drive_normalize(L"e:", req.target));
  SD_CHECK(!ui_path_valid(L"C:"));
}
