/* fuzz_sftp_reply: SFTP payload decoders (draft-ietf-secsh-filexfer): ATTRS with extended pairs, VERSION with
   extensions, limits and statvfs extension replies, and the directory-entry name check. Each decoder must stop at
   the buffer end (sticky reader errors) and never report success with unread or out-of-range values. */
#include "sd_fuzz.h"
#include "sd_base/sd_buf.h"
#include "sd_base/sd_err.h"
#include "sftp_proto.h"

int sd_fuzz_one(const uint8_t *data, size_t size)
{
  sd_rd r;
  sd_sftp_attrs a;
  sd_sftp_extattr ext[16];
  uint32_t pairs = 0;
  sftp_version_info vi;
  uint64_t lim[4];
  sd_sftp_statvfs sv;
  sd_sftp_limits eff;
  uint32_t bit;

  if (size > 64u * 1024u) return 0;

  sd_rd_init(&r, data, size);
  memset(&a, 0, sizeof(a));
  if (sftp_dec_attrs(&r, &a, ext, 16) && sd_rd_ok(&r)) (void)sftp_count_attr_ext(&r, &pairs);

  (void)sftp_parse_version(data, size, &vi);

  sd_rd_init(&r, data, size);
  memset(lim, 0, sizeof(lim));
  if (sftp_parse_limits(&r, lim) && sd_rd_ok(&r)) {
    sftp_effective_limits(lim, &eff);
  }

  sd_rd_init(&r, data, size);
  memset(&sv, 0, sizeof(sv));
  (void)sftp_parse_statvfs(&r, &sv);

  (void)sftp_dirent_name_ok(data, size);
  bit = sftp_ext_bit(data, size / 2, data + size / 2, size - size / 2);
  (void)bit;
  (void)sftp_is_win_drive_path((const char *)data, size);
  return 0;
}
