/* SFTP v3 wire codec (draft-ietf-secsh-filexfer-02 + OpenSSH extensions, 01 §10.1). Pure functions,
 * no I/O, no windows.h: exercised directly by the canned-fixture unit tests.
 * Thread safety: pure functions; callers own every buffer. */
#ifndef SD_SFTP_PROTO_H
#define SD_SFTP_PROTO_H

#include "sd/base.h"
#include "sd_base/sd_buf.h"
#include "sd_base/sd_err.h"
#include "sd_sftp/sd_sftp.h"

enum {
  SFTP_INIT = 1, SFTP_VERSION = 2, SFTP_OPEN = 3, SFTP_CLOSE = 4, SFTP_READ = 5, SFTP_WRITE = 6,
  SFTP_LSTAT = 7, SFTP_FSTAT = 8, SFTP_SETSTAT = 9, SFTP_FSETSTAT = 10, SFTP_OPENDIR = 11,
  SFTP_READDIR = 12, SFTP_REMOVE = 13, SFTP_MKDIR = 14, SFTP_RMDIR = 15, SFTP_REALPATH = 16,
  SFTP_STAT = 17, SFTP_RENAME = 18, SFTP_READLINK = 19, SFTP_SYMLINK = 20,
  SFTP_STATUS = 101, SFTP_HANDLE = 102, SFTP_DATA = 103, SFTP_NAME = 104, SFTP_ATTRS = 105,
  SFTP_EXTENDED = 200, SFTP_EXTENDED_REPLY = 201
};

enum { SFTP_FX_OK = 0, SFTP_FX_EOF = 1, SFTP_FX_NO_SUCH_FILE = 2, SFTP_FX_PERMISSION_DENIED = 3,
       SFTP_FX_FAILURE = 4, SFTP_FX_BAD_MESSAGE = 5, SFTP_FX_OP_UNSUPPORTED = 8 };

#define SFTP_MAX_HANDLE      256u
#define SFTP_MAX_IN_PACKET   (256u * 1024u + 13u)   /* inbound cap, header excluded (01 §10.1) */
#define SFTP_DEFAULT_PACKET  34000u
#define SFTP_DEFAULT_CHUNK   32768u
#define SFTP_MAX_CHUNK       (255u * 1024u)
#define SFTP_MAX_PATH        (64u * 1024u)
#define SFTP_MAX_EXT_PAIRS   64u
#define SFTP_MAX_EXT_BYTES   (64u * 1024u)
#define SFTP_MAX_EXTENSIONS  256u

/* Attributes. Encoding writes SIZE/UIDGID/PERM/TIMES (never extended pairs). Times are clamped to
   the uint32 wire range. */
void sftp_enc_attrs(sd_wr *w, const sd_sftp_attrs *a);
/* Decodes one ATTRS. ext may be NULL (pairs are validated and skipped, ext_count = 0). Returns 0 on
   success, -1 on malformed input (unknown flag bits, too many/too large pairs). */
int  sftp_dec_attrs(sd_rd *r, sd_sftp_attrs *a, sd_sftp_extattr *ext, uint32_t ext_cap);
/* Counts the extended pairs of the ATTRS at r without consuming it; -1 if malformed. */
int  sftp_count_attr_ext(const sd_rd *r, uint32_t *pairs);

/* TM-R12 rule for directory entries from the server: 1 if the name may be delivered. */
int  sftp_dirent_name_ok(const uint8_t *name, size_t len);

/* VERSION payload (after the type byte). */
typedef struct sftp_version_info {
  uint32_t version;
  uint32_t ext;                           /* SD_SFTP_EXT_* */
  uint32_t ext_count;
  sd_span  names[SFTP_MAX_EXTENSIONS];    /* point into the input */
  sd_span  versions[SFTP_MAX_EXTENSIONS];
  int      any_openssh;                   /* some name ends in "@openssh.com" */
} sftp_version_info;
int sftp_parse_version(const uint8_t *p, size_t n, sftp_version_info *out);   /* 0 / -1 */

/* Extension bit for an announced (name, version) pair; 0 when unknown or the version differs. */
uint32_t sftp_ext_bit(const uint8_t *name, size_t nlen, const uint8_t *ver, size_t vlen);

/* limits@openssh.com reply payload (after id): four uint64. */
int sftp_parse_limits(sd_rd *r, uint64_t v[4]);
/* statvfs@openssh.com reply payload (after id): eleven uint64. */
int sftp_parse_statvfs(sd_rd *r, sd_sftp_statvfs *v);

/* Effective limits per 01 §10.1 from the raw limits values (all 0 when the extension is missing). */
void sftp_effective_limits(const uint64_t raw[4], sd_sftp_limits *out);

/* Packet framing helpers: sftp_pkt_begin writes the length placeholder, type and (when id_present)
   the id; sftp_pkt_end patches the length. */
size_t sftp_pkt_begin(sd_wr *w, uint8_t type, int id_present, uint32_t id);
void   sftp_pkt_end(sd_wr *w, size_t start);

/* 1 if path looks like a Windows drive path ("/C:/..." or "/C:"), the 01 §4.9 quirk. */
int sftp_is_win_drive_path(const char *p, size_t n);

#endif /* SD_SFTP_PROTO_H */
