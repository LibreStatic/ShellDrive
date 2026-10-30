/* sd_config M3 profile keys (03 §3.4.1): profile.scope and the service keys (parsed only, M5), security.trust,
   the mount.* and cache.* keys of the vfs, the autostart keys, and the keys without a consumer yet (parsed only,
   listed in docs/dev/m3-notes.md). Unset keys keep the 3.4.1 default; a key is written back only when it differs
   from its default or is already present (the M0/M1/M2 rule). The legacy cache keys of 3.4.1 are read once and
   removed on the next write. */
#include <windows.h>
#include <string.h>
#include <stdio.h>

#include "config_internal.h"
#include "sd_platform/sd_log.h"

#define TTL_MAX_MS     3600000u
#define READAHEAD_MIN  65536u
#define OFFLINE_MAX_MB 1048576u

static int ieq(const char *a, const char *b)
{
  for (; *a && *b; a++, b++) {
    char x = *a, y = *b;
    if (x >= 'A' && x <= 'Z') x = (char)(x - 'A' + 'a');
    if (y >= 'A' && y <= 'Z') y = (char)(y - 'A' + 'a');
    if (x != y) return 0;
  }
  return *a == *b;
}

void sd_profile_m3_defaults(sd_profile *p)
{
  p->scope = SD_PROFILE_SCOPE_USER;
  p->trust = SD_PROFILE_TRUST_UNTRUSTED;
  p->shell_active_files = SD_PROFILE_UNSET;
  p->hide_dotfiles = 1;
  p->exec_hint = 1;
  p->autostart = SD_PROFILE_AUTOSTART_NO;
  p->autostart_sessions = SD_PROFILE_SESSIONS_ANY;
  p->fsync_on_flush = 1;
  p->umask = SD_PROFILE_UMASK_DEFAULT;
  p->map_readonly = 1;
  p->allow_system = 1;
  sd_cfg_scpy(p->fs_name, sizeof(p->fs_name), "NTFS");
  p->attr_ttl_ms = 30000;
  p->dir_ttl_ms = 30000;
  p->neg_ttl_ms = 10000;
  p->open_revalidate_ms = 1000;
  p->max_readahead = 8u * 1024u * 1024u;
}

int sd_profile_block_shell_active(const sd_profile *p)
{
  if (p->shell_active_files != SD_PROFILE_UNSET)
    return p->shell_active_files ? 1 : 0;
  return p->trust == SD_PROFILE_TRUST_UNTRUSTED;   /* D41: untrusted blocks, trusted shows */
}

int sd_profile_parse_umask(const char *v, uint32_t *out)
{
  uint32_t u = 0;
  size_t i, n = strlen(v);
  if (n == 0 || n > 4)
    return 0;
  for (i = 0; i < n; i++) {
    if (v[i] < '0' || v[i] > '7')
      return 0;
    u = u * 8u + (uint32_t)(v[i] - '0');
  }
  if (u == 0 || u > 0777u)
    return 0;
  *out = u;
  return 1;
}

/* A duration for a TTL or a revalidation interval: 1 ms to one hour. */
static int parse_ttl(const char *v, uint32_t *out)
{
  uint32_t ms = 0;
  if (!sd_ini_parse_duration_ms(v, &ms) || ms == 0 || ms > TTL_MAX_MS)
    return 0;
  *out = ms;
  return 1;
}

/* Letters, digits, '.', '_' and '-', 1 to 31 characters (mount.fs_name, mount.remote_charset). */
static int name_chars_ok(const char *s, size_t max)
{
  size_t n = strlen(s), i;
  if (n == 0 || n > max)
    return 0;
  for (i = 0; i < n; i++) {
    char c = s[i];
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' ||
          c == '-'))
      return 0;
  }
  return 1;
}

/* A comma list: entries trimmed, none empty, no control characters. Empty input is an empty list. */
static int list_ok(const char *s)
{
  const char *p = s;
  if (sd_cfg_has_ctl(s))
    return 0;
  if (*s == 0)
    return 1;
  for (;;) {
    const char *b, *e;
    while (*p == ' ' || *p == '\t') p++;
    b = p;
    while (*p && *p != ',') p++;
    e = p;
    while (e > b && (e[-1] == ' ' || e[-1] == '\t')) e--;
    if (e == b)
      return 0;
    if (*p == 0)
      return 1;
    p++;
  }
}

/* Whether every entry of list a (trimmed, ASCII case-insensitive) is in list b. */
static int list_subset(const char *a, const char *b)
{
  const char *p = a;
  while (*p) {
    const char *eb, *ea;
    size_t na;
    int found = 0;
    const char *q;
    while (*p == ' ' || *p == '\t' || *p == ',') p++;
    if (*p == 0)
      break;
    ea = p;
    while (*ea && *ea != ',') ea++;
    eb = ea;
    while (eb > p && (eb[-1] == ' ' || eb[-1] == '\t')) eb--;
    na = (size_t)(eb - p);
    for (q = b; *q && !found;) {
      const char *fe, *fb;
      while (*q == ' ' || *q == '\t' || *q == ',') q++;
      if (*q == 0)
        break;
      fb = q;
      while (*q && *q != ',') q++;
      fe = q;
      while (fe > fb && (fe[-1] == ' ' || fe[-1] == '\t')) fe--;
      if ((size_t)(fe - fb) == na && _strnicmp(fb, p, na) == 0)
        found = 1;
    }
    if (!found)
      return 0;
    p = ea;
  }
  return 1;
}

const char *sd_profile_m3_from_ini(const sd_ini *ini, sd_profile *p)
{
  const char *v;
  uint32_t u;
  int b;
  if ((v = sd_ini_get(ini, "profile", "scope")) != NULL) {
    if (strcmp(v, "user") == 0) p->scope = SD_PROFILE_SCOPE_USER;
    else if (strcmp(v, "users") == 0) p->scope = SD_PROFILE_SCOPE_USERS;
    else if (strcmp(v, "service") == 0) p->scope = SD_PROFILE_SCOPE_SERVICE;
    else return "profile.scope";
  }
  if ((v = sd_ini_get(ini, "profile", "service_access")) != NULL && !sd_cfg_scpy(p->service_access, sizeof(p->service_access), v))
    return "profile.service_access";
  if ((v = sd_ini_get(ini, "profile", "service_access_write")) != NULL &&
      !sd_cfg_scpy(p->service_access_write, sizeof(p->service_access_write), v))
    return "profile.service_access_write";
  if ((v = sd_ini_get(ini, "security", "trust")) != NULL) {
    if (strcmp(v, "untrusted") == 0) p->trust = SD_PROFILE_TRUST_UNTRUSTED;
    else if (strcmp(v, "trusted") == 0) p->trust = SD_PROFILE_TRUST_TRUSTED;
    else return "security.trust";
  }
  if ((v = sd_ini_get(ini, "mount", "shell_active_files")) != NULL) {
    if (strcmp(v, "show") == 0) p->shell_active_files = 0;
    else if (strcmp(v, "block") == 0) p->shell_active_files = 1;
    else return "mount.shell_active_files";
  }
  if ((v = sd_ini_get(ini, "mount", "hide_dotfiles")) != NULL) {
    if (!sd_ini_parse_bool(v, &b)) return "mount.hide_dotfiles";
    p->hide_dotfiles = b;
  }
  if ((v = sd_ini_get(ini, "mount", "exec_hint")) != NULL) {
    if (!sd_ini_parse_bool(v, &b)) return "mount.exec_hint";
    p->exec_hint = b;
  }
  if ((v = sd_ini_get(ini, "mount", "autostart")) != NULL) {
    if (strcmp(v, "no") == 0) p->autostart = SD_PROFILE_AUTOSTART_NO;
    else if (strcmp(v, "logon") == 0) p->autostart = SD_PROFILE_AUTOSTART_LOGON;
    else if (strcmp(v, "boot") == 0) p->autostart = SD_PROFILE_AUTOSTART_BOOT;
    else return "mount.autostart";
  }
  if ((v = sd_ini_get(ini, "mount", "autostart_sessions")) != NULL) {
    if (strcmp(v, "any") == 0) p->autostart_sessions = SD_PROFILE_SESSIONS_ANY;
    else if (strcmp(v, "console") == 0) p->autostart_sessions = SD_PROFILE_SESSIONS_CONSOLE;
    else if (strcmp(v, "remote") == 0) p->autostart_sessions = SD_PROFILE_SESSIONS_REMOTE;
    else return "mount.autostart_sessions";
  }
  if ((v = sd_ini_get(ini, "mount", "open_after_mount")) != NULL) {
    if (!sd_ini_parse_bool(v, &b)) return "mount.open_after_mount";
    p->open_after_mount = b;
  }
  if ((v = sd_ini_get(ini, "mount", "fsync_on_flush")) != NULL) {
    if (!sd_ini_parse_bool(v, &b)) return "mount.fsync_on_flush";
    p->fsync_on_flush = b;
  }
  if ((v = sd_ini_get(ini, "mount", "atomic_put")) != NULL) {
    if (!sd_ini_parse_bool(v, &b)) return "mount.atomic_put";
    p->atomic_put = b;
  }
  if ((v = sd_ini_get(ini, "mount", "case")) != NULL) {
    if (strcmp(v, "insensitive") == 0) p->case_sensitive = 0;
    else if (strcmp(v, "sensitive") == 0) p->case_sensitive = 1;
    else return "mount.case";
  }
  if ((v = sd_ini_get(ini, "mount", "remote_case")) != NULL) {
    if (strcmp(v, "auto") == 0) p->remote_case = 0;
    else if (strcmp(v, "sensitive") == 0) p->remote_case = 1;
    else if (strcmp(v, "insensitive") == 0) p->remote_case = 2;
    else return "mount.remote_case";
  }
  if ((v = sd_ini_get(ini, "mount", "remote_charset")) != NULL) {
    if (ieq(v, "utf-8") || ieq(v, "utf8") || v[0] == 0)
      p->remote_charset[0] = 0;
    else if (name_chars_ok(v, sizeof(p->remote_charset) - 1))
      sd_cfg_scpy(p->remote_charset, sizeof(p->remote_charset), v);
    else
      return "mount.remote_charset";
  }
  if ((v = sd_ini_get(ini, "mount", "umask")) != NULL) {
    if (!sd_profile_parse_umask(v, &p->umask)) return "mount.umask";
  }
  if ((v = sd_ini_get(ini, "mount", "map_readonly")) != NULL) {
    if (!sd_ini_parse_bool(v, &b)) return "mount.map_readonly";
    p->map_readonly = b;
  }
  if ((v = sd_ini_get(ini, "mount", "show_special")) != NULL) {
    if (!sd_ini_parse_bool(v, &b)) return "mount.show_special";
    p->show_special = b;
  }
  if ((v = sd_ini_get(ini, "mount", "allow_system")) != NULL) {
    if (!sd_ini_parse_bool(v, &b)) return "mount.allow_system";
    p->allow_system = b;
  }
  if ((v = sd_ini_get(ini, "mount", "strict_acl")) != NULL) {
    if (!sd_ini_parse_bool(v, &b)) return "mount.strict_acl";
    p->strict_acl = b;
  }
  if ((v = sd_ini_get(ini, "mount", "identity_probe")) != NULL) {
    if (strcmp(v, "owner") == 0) p->identity_probe_exec = 0;
    else if (strcmp(v, "exec") == 0) p->identity_probe_exec = 1;
    else return "mount.identity_probe";
  }
  if ((v = sd_ini_get(ini, "mount", "fs_name")) != NULL) {
    if (!name_chars_ok(v, sizeof(p->fs_name) - 1) || !sd_cfg_scpy(p->fs_name, sizeof(p->fs_name), v))
      return "mount.fs_name";
  }
  if ((v = sd_ini_get(ini, "mount", "offline_hint_over_mb")) != NULL) {
    if (!sd_ini_parse_u32(v, &u) || u > OFFLINE_MAX_MB) return "mount.offline_hint_over_mb";
    p->offline_hint_over_mb = u;
  }
  if ((v = sd_ini_get(ini, "mount", "mark_of_the_web")) != NULL) {
    if (strcmp(v, "off") == 0) p->mark_of_the_web = 0;
    else if (strcmp(v, "internet") == 0) p->mark_of_the_web = 1;
    else return "mount.mark_of_the_web";
  }
  /* 3.4.1 renames: metadata_ttl -> attr_ttl and directory_ttl -> dir_ttl, read once when the new name is absent */
  if ((v = sd_ini_get(ini, "cache", "attr_ttl")) == NULL)
    v = sd_ini_get(ini, "cache", "metadata_ttl");
  if (v != NULL && !parse_ttl(v, &p->attr_ttl_ms)) return "cache.attr_ttl";
  if ((v = sd_ini_get(ini, "cache", "dir_ttl")) == NULL)
    v = sd_ini_get(ini, "cache", "directory_ttl");
  if (v != NULL && !parse_ttl(v, &p->dir_ttl_ms)) return "cache.dir_ttl";
  if ((v = sd_ini_get(ini, "cache", "neg_ttl")) != NULL && !parse_ttl(v, &p->neg_ttl_ms)) return "cache.neg_ttl";
  if ((v = sd_ini_get(ini, "cache", "open_revalidate")) != NULL) {
    if (ieq(v, "never")) p->open_revalidate_ms = -1;
    else {
      uint32_t ms;
      if (!parse_ttl(v, &ms)) return "cache.open_revalidate";
      p->open_revalidate_ms = (int)ms;
    }
  }
  if ((v = sd_ini_get(ini, "cache", "max_readahead")) != NULL) {
    uint64_t sz;
    if (!sd_ini_parse_size(v, &sz) || sz < READAHEAD_MIN || sz > SD_PROFILE_MAX_READAHEAD)
      return "cache.max_readahead";
    p->max_readahead = (uint32_t)sz;
  }
  if ((v = sd_ini_get(ini, "security", "crypto_backend")) != NULL) {
    if (strcmp(v, "auto") == 0) p->crypto_backend = SD_PROFILE_CRYPTO_AUTO;
    else if (strcmp(v, "own") == 0) p->crypto_backend = SD_PROFILE_CRYPTO_OWN;
    else return "security.crypto_backend";
  }
  if (sd_ini_get(ini, "cache", "read_cache_memory") != NULL)
    SD_LOGW("config", "profile key cache.read_cache_memory is ignored (the memory budget is global, 3.4.1)");
  return NULL;
}

const char *sd_profile_m3_validate(const sd_profile *p)
{
  if (p->scope < SD_PROFILE_SCOPE_USER || p->scope > SD_PROFILE_SCOPE_SERVICE) return "profile.scope";
  if (!list_ok(p->service_access)) return "profile.service_access";
  if (!list_ok(p->service_access_write)) return "profile.service_access_write";
  if (p->scope == SD_PROFILE_SCOPE_SERVICE && p->service_access[0] == 0) return "profile.service_access";
  if (p->service_access_write[0] && !list_subset(p->service_access_write, p->service_access))
    return "profile.service_access_write";
  if (p->trust < SD_PROFILE_TRUST_UNTRUSTED || p->trust > SD_PROFILE_TRUST_TRUSTED) return "security.trust";
  if (p->shell_active_files < SD_PROFILE_UNSET || p->shell_active_files > 1) return "mount.shell_active_files";
  if (p->autostart < SD_PROFILE_AUTOSTART_NO || p->autostart > SD_PROFILE_AUTOSTART_BOOT) return "mount.autostart";
  if (p->autostart == SD_PROFILE_AUTOSTART_BOOT && p->scope != SD_PROFILE_SCOPE_SERVICE) return "mount.autostart";
  if (p->autostart_sessions < SD_PROFILE_SESSIONS_ANY || p->autostart_sessions > SD_PROFILE_SESSIONS_REMOTE)
    return "mount.autostart_sessions";
  if (p->case_sensitive < 0 || p->case_sensitive > 1) return "mount.case";
  if (p->remote_case < 0 || p->remote_case > 2) return "mount.remote_case";
  if (p->remote_charset[0] && !name_chars_ok(p->remote_charset, sizeof(p->remote_charset) - 1))
    return "mount.remote_charset";
  if (p->umask == 0 || p->umask > 0777u) return "mount.umask";
  if (p->identity_probe_exec < 0 || p->identity_probe_exec > 1) return "mount.identity_probe";
  if (!name_chars_ok(p->fs_name, sizeof(p->fs_name) - 1)) return "mount.fs_name";
  if (p->offline_hint_over_mb > OFFLINE_MAX_MB) return "mount.offline_hint_over_mb";
  if (p->mark_of_the_web < 0 || p->mark_of_the_web > 1) return "mount.mark_of_the_web";
  if (p->attr_ttl_ms == 0 || p->attr_ttl_ms > TTL_MAX_MS) return "cache.attr_ttl";
  if (p->dir_ttl_ms == 0 || p->dir_ttl_ms > TTL_MAX_MS) return "cache.dir_ttl";
  if (p->neg_ttl_ms == 0 || p->neg_ttl_ms > TTL_MAX_MS) return "cache.neg_ttl";
  if (p->open_revalidate_ms != -1 && (p->open_revalidate_ms < 1 || (uint32_t)p->open_revalidate_ms > TTL_MAX_MS))
    return "cache.open_revalidate";
  if (p->max_readahead < READAHEAD_MIN || p->max_readahead > SD_PROFILE_MAX_READAHEAD) return "cache.max_readahead";
  if (p->crypto_backend < SD_PROFILE_CRYPTO_AUTO || p->crypto_backend > SD_PROFILE_CRYPTO_OWN) return "security.crypto_backend";
  return NULL;
}

/* Milliseconds as the shortest exact unit: 30s, 5m, 1h, 1500ms. */
static void fmt_ms(char out[24], uint32_t ms)
{
  if (ms && ms % 3600000u == 0) sprintf_s(out, 24, "%uh", (unsigned)(ms / 3600000u));
  else if (ms && ms % 60000u == 0) sprintf_s(out, 24, "%um", (unsigned)(ms / 60000u));
  else if (ms && ms % 1000u == 0) sprintf_s(out, 24, "%us", (unsigned)(ms / 1000u));
  else sprintf_s(out, 24, "%ums", (unsigned)ms);
}

static void fmt_size(char out[24], uint32_t v)
{
  if (v && v % (1024u * 1024u * 1024u) == 0) sprintf_s(out, 24, "%uG", (unsigned)(v / (1024u * 1024u * 1024u)));
  else if (v && v % (1024u * 1024u) == 0) sprintf_s(out, 24, "%uM", (unsigned)(v / (1024u * 1024u)));
  else if (v && v % 1024u == 0) sprintf_s(out, 24, "%uK", (unsigned)(v / 1024u));
  else sprintf_s(out, 24, "%u", (unsigned)v);
}

sd_err sd_profile_m3_to_ini(const sd_profile *p, sd_ini *d)
{
  char num[24];
  sd_err e;
#define SET(s, k, v) do { if ((e = sd_ini_set(d, (s), (k), (v))) != SD_OK) return e; } while (0)
#define HAS(s, k) (sd_ini_get(d, (s), (k)) != NULL)
#define YN(b) ((b) ? "yes" : "no")
  if (p->scope != SD_PROFILE_SCOPE_USER || HAS("profile", "scope"))
    SET("profile", "scope", p->scope == SD_PROFILE_SCOPE_SERVICE ? "service" : p->scope == SD_PROFILE_SCOPE_USERS
                            ? "users" : "user");
  if (p->service_access[0] || HAS("profile", "service_access")) SET("profile", "service_access", p->service_access);
  if (p->service_access_write[0] || HAS("profile", "service_access_write"))
    SET("profile", "service_access_write", p->service_access_write);
  if (p->trust != SD_PROFILE_TRUST_UNTRUSTED || HAS("security", "trust"))
    SET("security", "trust", p->trust == SD_PROFILE_TRUST_TRUSTED ? "trusted" : "untrusted");
  if (p->shell_active_files != SD_PROFILE_UNSET)
    SET("mount", "shell_active_files", p->shell_active_files ? "block" : "show");
  else if (HAS("mount", "shell_active_files"))
    (void)sd_ini_remove(d, "mount", "shell_active_files");       /* back to the D41 rule */
  if (!p->hide_dotfiles || HAS("mount", "hide_dotfiles")) SET("mount", "hide_dotfiles", YN(p->hide_dotfiles));
  if (!p->exec_hint || HAS("mount", "exec_hint")) SET("mount", "exec_hint", YN(p->exec_hint));
  if (p->autostart != SD_PROFILE_AUTOSTART_NO || HAS("mount", "autostart"))
    SET("mount", "autostart", p->autostart == SD_PROFILE_AUTOSTART_BOOT ? "boot"
                              : p->autostart == SD_PROFILE_AUTOSTART_LOGON ? "logon" : "no");
  if (p->autostart_sessions != SD_PROFILE_SESSIONS_ANY || HAS("mount", "autostart_sessions"))
    SET("mount", "autostart_sessions", p->autostart_sessions == SD_PROFILE_SESSIONS_CONSOLE ? "console"
                                       : p->autostart_sessions == SD_PROFILE_SESSIONS_REMOTE ? "remote" : "any");
  if (p->open_after_mount || HAS("mount", "open_after_mount")) SET("mount", "open_after_mount", YN(p->open_after_mount));
  if (!p->fsync_on_flush || HAS("mount", "fsync_on_flush")) SET("mount", "fsync_on_flush", YN(p->fsync_on_flush));
  if (p->atomic_put || HAS("mount", "atomic_put")) SET("mount", "atomic_put", YN(p->atomic_put));
  if (p->case_sensitive || HAS("mount", "case")) SET("mount", "case", p->case_sensitive ? "sensitive" : "insensitive");
  if (p->remote_case || HAS("mount", "remote_case"))
    SET("mount", "remote_case", p->remote_case == 1 ? "sensitive" : p->remote_case == 2 ? "insensitive" : "auto");
  if (p->remote_charset[0]) SET("mount", "remote_charset", p->remote_charset);
  else if (HAS("mount", "remote_charset")) (void)sd_ini_remove(d, "mount", "remote_charset");
  if (p->umask != SD_PROFILE_UMASK_DEFAULT || HAS("mount", "umask")) {
    sprintf_s(num, sizeof(num), "%03o", (unsigned)p->umask);
    SET("mount", "umask", num);
  }
  if (!p->map_readonly || HAS("mount", "map_readonly")) SET("mount", "map_readonly", YN(p->map_readonly));
  if (p->show_special || HAS("mount", "show_special")) SET("mount", "show_special", YN(p->show_special));
  if (!p->allow_system || HAS("mount", "allow_system")) SET("mount", "allow_system", YN(p->allow_system));
  if (p->strict_acl || HAS("mount", "strict_acl")) SET("mount", "strict_acl", YN(p->strict_acl));
  if (p->identity_probe_exec || HAS("mount", "identity_probe"))
    SET("mount", "identity_probe", p->identity_probe_exec ? "exec" : "owner");
  if (strcmp(p->fs_name, "NTFS") != 0 || HAS("mount", "fs_name")) SET("mount", "fs_name", p->fs_name);
  if (p->offline_hint_over_mb || HAS("mount", "offline_hint_over_mb")) {
    sprintf_s(num, sizeof(num), "%u", (unsigned)p->offline_hint_over_mb);
    SET("mount", "offline_hint_over_mb", num);
  }
  if (p->mark_of_the_web || HAS("mount", "mark_of_the_web"))
    SET("mount", "mark_of_the_web", p->mark_of_the_web ? "internet" : "off");
  if (p->attr_ttl_ms != 30000u || HAS("cache", "attr_ttl")) {
    fmt_ms(num, p->attr_ttl_ms);
    SET("cache", "attr_ttl", num);
  }
  if (p->dir_ttl_ms != 30000u || HAS("cache", "dir_ttl")) {
    fmt_ms(num, p->dir_ttl_ms);
    SET("cache", "dir_ttl", num);
  }
  if (p->neg_ttl_ms != 10000u || HAS("cache", "neg_ttl")) {
    fmt_ms(num, p->neg_ttl_ms);
    SET("cache", "neg_ttl", num);
  }
  if (p->open_revalidate_ms != 1000 || HAS("cache", "open_revalidate")) {
    if (p->open_revalidate_ms == -1) SET("cache", "open_revalidate", "never");
    else {
      fmt_ms(num, (uint32_t)p->open_revalidate_ms);
      SET("cache", "open_revalidate", num);
    }
  }
  if (p->max_readahead != 8u * 1024u * 1024u || HAS("cache", "max_readahead")) {
    fmt_size(num, p->max_readahead);
    SET("cache", "max_readahead", num);
  }
  if (p->crypto_backend != SD_PROFILE_CRYPTO_AUTO || HAS("security", "crypto_backend"))
    SET("security", "crypto_backend", p->crypto_backend == SD_PROFILE_CRYPTO_OWN ? "own" : "auto");
  /* 3.4.1 legacy names: rewritten under the new names (the values were read into the struct above) */
  (void)sd_ini_remove(d, "cache", "metadata_ttl");
  (void)sd_ini_remove(d, "cache", "directory_ttl");
  (void)sd_ini_remove(d, "cache", "read_cache_memory");
#undef SET
#undef HAS
#undef YN
  return SD_OK;
}
