/* Profile importers (03 §3.7): PuTTY sessions and the OpenSSH ssh_config subset.
 *
 * Both produce candidate profiles for a preview (CLI table / UI wizard page) before anything is
 * written. Candidates that duplicate an existing profile (same host, port and user, compared
 * case-insensitively for the host) are flagged and unselected by default (sd_import_mark_duplicates).
 *
 * PuTTY: sessions under HKCU\Software\SimonTatham\PuTTY\Sessions\<URL-escaped name> (or any other
 * key: tests pass their own), or a regedit export (.reg, "Windows Registry Editor Version 5.00" in
 * UTF-16LE or UTF-8, or REGEDIT4). Values read: HostName ("user@host" is split), PortNumber, UserName,
 * Protocol (only "ssh"), PublicKeyFile -> auth.identity, DetachedCertificate -> auth.certificate,
 * ProxyMethod / ProxyHost / ProxyPort / ProxyUsername: 2 (SOCKS 5) -> proxy = socks5://, 3 (HTTP) ->
 * proxy = http://, 6..8 (SSH, PuTTY 0.77+) -> one jump hop; 1 (SOCKS 4), 4 (Telnet), 5 (local command)
 * are skipped with a note (no ProxyCommand, D20). The proxy password is never imported. "Default
 * Settings" provides defaults for missing values. [verify the ProxyMethod numbering against PuTTY
 * settings.c]
 *
 * ssh_config: Host, HostName, User, Port, IdentityFile, IdentitiesOnly, ProxyJump, CertificateFile.
 * First obtained value wins; Host sections apply in file order; wildcard patterns (* ?) contribute
 * defaults to the literal aliases they match, negated patterns (!p) are honored; each literal alias
 * of a Host line becomes one profile. IdentityFile tokens %d %u %h %r %% and a leading ~ are
 * expanded; several IdentityFile lines become identity, identity.2, ...; IdentitiesOnly yes|no is
 * kept, its absence leaves the key unset (D37: an imported IdentityFile is then the only key
 * offered; the preview says so, SD_IMPORT_F_ONLY_THIS_KEY). ProxyJump aliases that are other
 * imported Hosts become references to those profiles; "ProxyJump none" clears. Match, Include,
 * ProxyCommand and every other keyword are listed as not imported (no silent loss).
 *
 * Ownership: sd_import_result owns its arrays; free with sd_import_result_free. Not thread-safe. */
#ifndef SD_IMPORT_H
#define SD_IMPORT_H

#include <windows.h>

#include "sd_config/sd_config.h"

enum {
  SD_IMPORT_F_DUPLICATE     = 1u << 0,   /* same host/port/user as an existing profile */
  SD_IMPORT_F_ONLY_THIS_KEY = 1u << 1,   /* identity set, identities_only unset (D37 note) */
  SD_IMPORT_F_PROXY_SKIPPED = 1u << 2,   /* PuTTY SOCKS 4 / Telnet / local command proxy */
  SD_IMPORT_F_NAME_CHANGED  = 1u << 3    /* the name clashed with an existing profile: " (2)" added */
};

typedef struct sd_import_candidate {
  sd_profile p;                  /* ready to save (no id yet) */
  char source[256];              /* PuTTY session name (decoded) or ssh_config alias */
  uint32_t flags;                /* SD_IMPORT_F_* */
  int selected;                  /* written by sd_import_write */
} sd_import_candidate;

typedef enum sd_import_skip_kind {
  SD_IMPORT_SKIP_KEYWORD,        /* ssh_config keyword not imported (item = keyword) */
  SD_IMPORT_SKIP_NOT_SSH,        /* PuTTY session with another protocol (item = protocol) */
  SD_IMPORT_SKIP_PROXY,          /* PuTTY proxy type that is not supported (item = method number) */
  SD_IMPORT_SKIP_INVALID         /* unusable entry, e.g. no host name (item = what is wrong) */
} sd_import_skip_kind;

typedef struct sd_import_skip {
  sd_import_skip_kind kind;
  char source[256];              /* session / Host alias, "" for global ssh_config lines */
  char item[64];
  uint32_t line;                 /* ssh_config line (1-based); 0 for PuTTY */
} sd_import_skip;

typedef struct sd_import_result {
  sd_import_candidate *items; uint32_t count, cap;
  sd_import_skip *skipped; uint32_t nskipped, skip_cap;
} sd_import_result;

void sd_import_result_init(sd_import_result *r);
void sd_import_result_free(sd_import_result *r);

/* root = HKEY_CURRENT_USER and key = NULL read the real PuTTY sessions; tests pass their own key. */
sd_err sd_import_putty_registry(HKEY root, const wchar_t *key, sd_import_result *out);
/* A regedit export of the Sessions key (or of single sessions). */
sd_err sd_import_putty_reg_text(const uint8_t *data, size_t len, sd_import_result *out);

typedef struct sd_import_env {
  const char *home;              /* UTF-8 for %d and ~ (NULL = %USERPROFILE%) */
  const char *local_user;        /* UTF-8 for %u (NULL = the Windows user name) */
} sd_import_env;
sd_err sd_import_ssh_config_text(const char *data, size_t len, const sd_import_env *env, sd_import_result *out);
/* path NULL = %USERPROFILE%\.ssh\config. */
sd_err sd_import_ssh_config_file(const wchar_t *path, const sd_import_env *env, sd_import_result *out);

/* Flags duplicates of existing profiles (lookup through sd_profile_enum unless enum_fn is given) and
   unselects them; renames candidates whose name is taken (SD_IMPORT_F_NAME_CHANGED). */
typedef sd_err (*sd_import_enum_fn)(sd_profile_enum_cb cb, void *ctx);
void sd_import_mark_duplicates(sd_import_result *r, sd_import_enum_fn enum_fn);

/* Saves every selected candidate (sd_profile_save). written counts the saved ones; the first error
   is returned but the others are still attempted. */
sd_err sd_import_write(sd_import_result *r, uint32_t *written);

#endif /* SD_IMPORT_H */
