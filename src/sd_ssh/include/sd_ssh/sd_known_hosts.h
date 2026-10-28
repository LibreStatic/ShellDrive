/* known_hosts stores and host-key verification results (01 §7.1, §7.2; D7, D8; TM-R04, R06, R07).
 *
 * sd_known_hosts is the ONLY component that reads, writes and locks known_hosts files. It has no
 * transport dependency: the CLI and UI link it (and the key-file parsers) without the SSH stack.
 * M2 scope: machine and user stores (plain entries written, hashed |1| entries read and optionally
 * written), @revoked, @cert-authority (host certificates, SD_HK_MATCH_CA), and the live read-only
 * sources of D7:
 * - SD_KH_SRC_OPENSSH: path NULL = %USERPROFILE%\.ssh\known_hosts plus known_hosts2 if present;
 *   a path names one file instead.
 * - SD_KH_SRC_PUTTY: path NULL = HKCU\Software\SimonTatham\PuTTY\SshHostKeys; a path names another
 *   key under HKCU (tests). rsa2, ssh-ed25519 and ecdsa-sha2-nistp256/384/521 values are converted
 *   (01 §7.3); other types are counted as invalid by sd_known_hosts_import.
 * A live source is used only when nobody but the user, SYSTEM and Administrators can change it
 * (TM-R06: owner and DACL of the file and its directory, or of the registry key; reparse points and
 * volumes without persistent ACLs are refused); otherwise it is skipped entirely and reported
 * SD_KH_SRC_INSECURE. In live sources, wildcard-only lines (only '*', '?', '.') are ignored for MATCH
 * and the stored-type list but still count for MISMATCH and @revoked. A MATCH found only in a live
 * source is copied into the writable user store with "# imported-from=openssh|putty added=<date>".
 * Every store and source is consulted: @revoked wins, then a valid host certificate (MATCH_CA), then
 * any MISMATCH (D7), then MATCH. A certificate whose CA line applies to the name but that fails
 * validation (01 §7.1) is a MISMATCH unless its plain key is known (then MATCH, as in OpenSSH).
 *
 * Threading: an sd_known_hosts object is thread-safe and shared by all connections of a process.
 * Every call does file I/O: run it on worker items, never on an SSH I/O thread or a Dokany thread.
 * Cross-process writes are serialized with Local\com.librestatic.shelldrive.known_hosts.<hash>
 * (Global\ for the machine store). Result structs are plain data owned by the caller. */
#ifndef SD_KNOWN_HOSTS_H
#define SD_KNOWN_HOSTS_H

#include "sd/base.h"
#include "sd_base/sd_err.h"

typedef enum sd_kh_store_kind {
  SD_KH_STORE_MACHINE,     /* %ProgramData%\LibreStatic\ShellDrive\known_hosts */
  SD_KH_STORE_USER,        /* %APPDATA%\LibreStatic\ShellDrive\known_hosts */
  SD_KH_SRC_OPENSSH,       /* live read-only source: %USERPROFILE%\.ssh\known_hosts (+ known_hosts2) */
  SD_KH_SRC_PUTTY          /* live read-only source: HKCU\...\PuTTY\SshHostKeys */
} sd_kh_store_kind;

typedef struct sd_kh_store {
  sd_kh_store_kind kind;
  const wchar_t *path;     /* files; NULL = default path for the kind */
  int writable;            /* 0 for live sources always; machine store writable only in the service/admin */
} sd_kh_store;

typedef enum sd_hk_status {
  SD_HK_MATCH,             /* exact key in a store or live source */
  SD_HK_MATCH_CA,          /* valid host certificate from a matching @cert-authority */
  SD_HK_NEW,               /* no key of any type for this name: TOFU prompt */
  SD_HK_NEW_TYPE,          /* name known only with other key types: fail, never a prompt (TM-R04) */
  SD_HK_MISMATCH,          /* same type, different key: fail, no accept path */
  SD_HK_REVOKED            /* key or CA under @revoked: fail */
} sd_hk_status;

/* A host key as reported in events and fetch results. Pointers valid during the callback only. */
typedef struct sd_hk_key { const uint8_t *blob; size_t len; const char *type, *fp_sha256; } sd_hk_key;

typedef struct sd_hk_result {
  sd_hk_status status;
  sd_kh_store_kind store;  /* store that decided (MATCH: first match; MISMATCH/REVOKED: offending entry) */
  wchar_t  path[260];      /* file of the deciding entry ("" for the PuTTY registry) */
  uint32_t line;           /* 1-based line of the deciding entry; 0 if not applicable */
  char     stored_type[48];      /* MISMATCH: type of the stored key */
  char     stored_fp_sha256[64]; /* MISMATCH: "SHA256:..." of the stored key */
  int      trusted_before;       /* MATCH from a store entry that existed before this call (7.5) */
  int      wildcard_only;        /* matched only through a wildcard-only pattern line (7.2, 7.5) */
} sd_hk_result;

typedef struct sd_kh_import_report {
  uint32_t imported, already_present, conflicts, invalid_lines;
} sd_kh_import_report;

typedef struct sd_known_hosts sd_known_hosts;

/* stores[] order: machine -> user -> live sources. @revoked in any store wins; otherwise any
   MISMATCH wins over MATCH (D7); MATCH records the first store that matched. Deep-copies stores. */
sd_err sd_known_hosts_open(const sd_kh_store *stores, uint32_t count, sd_known_hosts **out);
void   sd_known_hosts_close(sd_known_hosts *kh);

/* lookup_name: lowercase host, "[host]:port" when port != 22, or the host_key_alias (01 §7.1). */
sd_err sd_known_hosts_check(sd_known_hosts *kh, const char *lookup_name, const uint8_t *blob, size_t len,
                            uint64_t now_unix, sd_hk_result *res);
/* Appends a plain entry (D8) to a writable store, creating the file with the TM-R07 DACL.
   A host certificate blob is stored as its plain key. */
sd_err sd_known_hosts_add(sd_known_hosts *kh, sd_kh_store_kind target, const char *lookup_name,
                          const uint8_t *blob, size_t len, const char *comment);
/* As sd_known_hosts_add; SD_KH_ADD_HASHED writes the name as |1|salt|HMAC-SHA1 (OpenSSH
   HashKnownHosts). Our own stores are written plain by default (D8). */
enum { SD_KH_ADD_HASHED = 1u << 0 };
sd_err sd_known_hosts_add_ex(sd_known_hosts *kh, sd_kh_store_kind target, const char *lookup_name,
                             const uint8_t *blob, size_t len, const char *comment, uint32_t flags);
sd_err sd_known_hosts_remove(sd_known_hosts *kh, sd_kh_store_kind target, const char *lookup_name,
                             const char *key_type /* NULL = all */);
/* Removes the entries of exactly this key for lookup_name (lines naming only that host, plain or
   hashed). SD_E_NOT_FOUND if there is none. Used to apply UpdateHostKeys removals after review. */
sd_err sd_known_hosts_remove_key(sd_known_hosts *kh, sd_kh_store_kind target, const char *lookup_name,
                                 const uint8_t *blob, size_t len);

/* Plain keys stored for lookup_name in one store or source (no @revoked / @cert-authority lines).
   explicit_name: the line names only this host (one pattern, plain or hashed), so it can be removed
   without touching other hosts. Return nonzero from the callback to stop. Pointers are valid during
   the callback only. */
typedef struct sd_kh_entry {
  const uint8_t *blob; size_t len;
  const char *type;
  uint32_t line;
  int explicit_name;
  int wildcard_only;
} sd_kh_entry;
typedef int (*sd_kh_entry_cb)(void *ctx, const sd_kh_entry *e);
sd_err sd_known_hosts_list(sd_known_hosts *kh, sd_kh_store_kind store, const char *lookup_name,
                           sd_kh_entry_cb cb, void *ctx);

/* Every plain key of one file store (SD_KH_STORE_MACHINE or SD_KH_STORE_USER), for the host key manager
   (03 §5.1): pattern is the host field as written ("host", "[host]:port", a comma list, or a hashed
   "|1|salt|hash" when hashed is set). No name filter; @revoked and @cert-authority lines are not listed.
   Live sources are not enumerated (SD_E_INVALID_PARAM). Return nonzero from the callback to stop. Pointers
   are valid during the callback only. SD_E_NOT_FOUND when the store has no file. */
typedef enum sd_kh_origin {
  SD_KH_ORIGIN_OTHER = 0,      /* no source comment we know (another tool, or a hand-written line) */
  SD_KH_ORIGIN_SHELLDRIVE,     /* "by=shelldrive" or a bare "added=" (our own writers, 5.1) */
  SD_KH_ORIGIN_PUTTY,          /* "imported-from=putty" (D7 copy, "Copied from PuTTY") */
  SD_KH_ORIGIN_OPENSSH,        /* "imported-from=openssh" ("Copied from OpenSSH") */
  SD_KH_ORIGIN_SERVER          /* "updated-by=hostkeys-00" (UpdateHostKeys, 5.6, "Updated by server") */
} sd_kh_origin;
typedef struct sd_kh_all_entry {
  const char *pattern;     /* NUL-terminated copy, at most 255 bytes */
  const uint8_t *blob;
  size_t len;
  const char *type;
  uint32_t line;
  int hashed;
  const char *comment;     /* the trailing text of the line after the key, trimmed, at most 255 bytes ("" if none) */
  const char *added;       /* "YYYY-MM-DD" from the added= member of the comment, or "" */
  sd_kh_origin origin;     /* see sd_kh_origin */
} sd_kh_all_entry;
typedef int (*sd_kh_all_cb)(void *ctx, const sd_kh_all_entry *e);
sd_err sd_known_hosts_list_all(sd_known_hosts *kh, sd_kh_store_kind store, sd_kh_all_cb cb, void *ctx);

/* Applies a reviewed UpdateHostKeys announcement (01 §7.5, SD_HKEV_ANNOUNCED): adds the proven keys
   with "# updated-by=hostkeys-00 added=<date>" (keys already present are skipped) and removes the
   listed keys (sd_known_hosts_remove_key). sd_ssh never calls this itself; the host does, at once for
   update_host_keys = yes or after the review dialog for ask. Stops at the first error. */
sd_err sd_known_hosts_apply_hostkeys(sd_known_hosts *kh, sd_kh_store_kind target, const char *lookup_name,
                                     const sd_hk_key *add, uint32_t add_count,
                                     const sd_hk_key *remove, uint32_t remove_count);
sd_err sd_known_hosts_import(sd_known_hosts *kh, sd_kh_store_kind source, sd_kh_store_kind target,
                             sd_kh_import_report *rep);

/* TM-R04: key types that could MATCH for lookup_name, used to restrict the host-key algorithm list
   before KEXINIT (01 §4.3). */
typedef struct sd_kh_types { uint32_t count; char type[8][48]; int has_ca; } sd_kh_types;
sd_err sd_known_hosts_stored_types(sd_known_hosts *kh, const char *lookup_name, sd_kh_types *out);

/* TM-R06: state of a live source. INSECURE: detail_sid receives a SID that may write it. */
typedef enum sd_kh_src_state { SD_KH_SRC_OK, SD_KH_SRC_ABSENT, SD_KH_SRC_DISABLED, SD_KH_SRC_INSECURE } sd_kh_src_state;
sd_err sd_known_hosts_source_state(sd_known_hosts *kh, sd_kh_store_kind source, sd_kh_src_state *state,
                                   wchar_t *detail_sid, size_t detail_cap);

/* "SHA256:<base64 without padding>" of a public key blob; out must hold 64 bytes. */
sd_err sd_hostkey_fingerprint_sha256(const uint8_t *blob, size_t len, char out[64]);
/* "MD5:xx:xx:..." (16 bytes, lowercase hex, colon separated; the legacy form PuTTY shows, 5.2). Secondary display
   only. out must hold 64 bytes. */
sd_err sd_hostkey_fingerprint_md5(const uint8_t *blob, size_t len, char out[64]);

#endif /* SD_KNOWN_HOSTS_H */
