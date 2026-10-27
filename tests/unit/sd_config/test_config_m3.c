/* sd_config M3 profile keys (03 §3.4.1): defaults, parsing and bounds of every M3 key, the legacy cache names,
 * the round trip (a key is written only when it differs from its default or is already present) and the
 * derived shell-active default (D41). */
#include <windows.h>
#include <string.h>

#include "sd_test.h"
#include "sd_config/sd_config.h"
#include "sd_base/sd_mem.h"

static sd_ini *parse_text(const char *text)
{
  sd_ini *ini = NULL;
  uint32_t flags = 0;
  if (sd_ini_parse(text, strlen(text), &ini, &flags) != SD_OK)
    return NULL;
  return ini;
}

SD_TEST(profile_m3_defaults)
{
  sd_profile p;
  sd_profile_defaults(&p);
  SD_CHECK_EQ_INT(p.scope, SD_PROFILE_SCOPE_USER);
  SD_CHECK_EQ_INT(p.trust, SD_PROFILE_TRUST_UNTRUSTED);
  SD_CHECK_EQ_INT(p.shell_active_files, SD_PROFILE_UNSET);
  SD_CHECK_EQ_INT(sd_profile_block_shell_active(&p), 1);          /* D41: untrusted blocks */
  SD_CHECK_EQ_INT(p.hide_dotfiles, 1);
  SD_CHECK_EQ_INT(p.exec_hint, 1);
  SD_CHECK_EQ_INT(p.autostart, SD_PROFILE_AUTOSTART_NO);
  SD_CHECK_EQ_INT(p.autostart_sessions, SD_PROFILE_SESSIONS_ANY);
  SD_CHECK_EQ_INT(p.open_after_mount, 0);
  SD_CHECK_EQ_INT(p.fsync_on_flush, 1);
  SD_CHECK_EQ_INT(p.atomic_put, 0);
  SD_CHECK_EQ_INT(p.case_sensitive, 0);
  SD_CHECK_EQ_INT(p.remote_case, 0);
  SD_CHECK_STR(p.remote_charset, "");
  SD_CHECK_EQ_INT(p.umask, 18);                                    /* 022 */
  SD_CHECK_EQ_INT(p.map_readonly, 1);
  SD_CHECK_EQ_INT(p.show_special, 0);
  SD_CHECK_EQ_INT(p.allow_system, 1);
  SD_CHECK_EQ_INT(p.strict_acl, 0);
  SD_CHECK_EQ_INT(p.identity_probe_exec, 0);
  SD_CHECK_STR(p.fs_name, "NTFS");
  SD_CHECK_EQ_INT(p.offline_hint_over_mb, 0);
  SD_CHECK_EQ_INT(p.mark_of_the_web, 0);
  SD_CHECK_EQ_INT(p.attr_ttl_ms, 30000);
  SD_CHECK_EQ_INT(p.dir_ttl_ms, 30000);
  SD_CHECK_EQ_INT(p.neg_ttl_ms, 10000);
  SD_CHECK_EQ_INT(p.open_revalidate_ms, 1000);
  SD_CHECK_EQ_INT(p.max_readahead, 8u * 1024u * 1024u);
  SD_CHECK_EQ_INT(p.crypto_backend, SD_PROFILE_CRYPTO_AUTO);
  SD_CHECK_STR(p.service_access, "");
  SD_CHECK_STR(p.service_access_write, "");
}

SD_TEST(profile_m3_umask_octal)
{
  uint32_t u = 0;
  SD_CHECK(sd_profile_parse_umask("022", &u) && u == 18);
  SD_CHECK(sd_profile_parse_umask("0777", &u) && u == 511);
  SD_CHECK(sd_profile_parse_umask("2", &u) && u == 2);
  SD_CHECK(!sd_profile_parse_umask("0", &u));                      /* 0 is not a mask the vfs can take */
  SD_CHECK(!sd_profile_parse_umask("778", &u));                    /* 8 is not octal */
  SD_CHECK(!sd_profile_parse_umask("01000", &u));                  /* more than four digits */
  SD_CHECK(!sd_profile_parse_umask("", &u));
}

/* Each case parses a whole profile and names the bad key, or NULL when the profile is valid. */
SD_TEST(profile_m3_key_values_and_bounds)
{
  static const struct { const char *text; const char *bad; } cases[] = {
    { "[profile]\nhost = h\nscope = service\n", "profile.service_access" },
    { "[profile]\nhost = h\nscope = service\nservice_access = S-1-5-32-544\n", NULL },
    { "[profile]\nhost = h\nscope = machine\n", "profile.scope" },
    { "[profile]\nhost = h\nservice_access = S-1-1-0, \n", "profile.service_access" },
    { "[profile]\nhost = h\nscope = service\nservice_access = alice,bob\nservice_access_write = carol\n",
      "profile.service_access_write" },
    { "[profile]\nhost = h\nscope = service\nservice_access = alice,BOB\nservice_access_write = bob\n", NULL },
    { "[mount]\nautostart = boot\n", "mount.autostart" },
    { "[mount]\nautostart = logon\nautostart_sessions = remote\n", NULL },
    { "[mount]\nautostart_sessions = both\n", "mount.autostart_sessions" },
    { "[mount]\nautostart = yes\n", "mount.autostart" },
    { "[mount]\nhide_dotfiles = perhaps\n", "mount.hide_dotfiles" },
    { "[mount]\nexec_hint = no\nopen_after_mount = yes\nfsync_on_flush = no\natomic_put = yes\n"
      "map_readonly = no\nshow_special = yes\nallow_system = no\nstrict_acl = yes\n", NULL },
    { "[mount]\ncase = Sensitive\n", "mount.case" },
    { "[mount]\ncase = sensitive\n", NULL },
    { "[mount]\nremote_case = both\n", "mount.remote_case" },
    { "[mount]\nremote_case = insensitive\n", NULL },
    { "[mount]\nremote_charset = UTF-8\n", NULL },
    { "[mount]\nremote_charset = cp1252\n", NULL },
    { "[mount]\nremote_charset = bad/name\n", "mount.remote_charset" },
    { "[mount]\numask = 022\n", NULL },
    { "[mount]\numask = 0\n", "mount.umask" },
    { "[mount]\numask = 778\n", "mount.umask" },
    { "[mount]\numask = 0777\n", NULL },
    { "[mount]\nidentity_probe = exec\n", NULL },
    { "[mount]\nidentity_probe = magic\n", "mount.identity_probe" },
    { "[mount]\nfs_name = exFAT\n", NULL },
    { "[mount]\nfs_name = bad name\n", "mount.fs_name" },
    { "[mount]\noffline_hint_over_mb = 1048577\n", "mount.offline_hint_over_mb" },
    { "[mount]\noffline_hint_over_mb = 512\n", NULL },
    { "[mount]\nmark_of_the_web = internet\n", NULL },
    { "[mount]\nmark_of_the_web = on\n", "mount.mark_of_the_web" },
    { "[cache]\nattr_ttl = 0s\n", "cache.attr_ttl" },
    { "[cache]\nattr_ttl = 2h\n", "cache.attr_ttl" },
    { "[cache]\nattr_ttl = 1h\n", NULL },
    { "[cache]\nattr_ttl = 45\n", NULL },
    { "[cache]\nneg_ttl = 1500ms\n", NULL },
    { "[cache]\nopen_revalidate = never\n", NULL },
    { "[cache]\nopen_revalidate = 0s\n", "cache.open_revalidate" },
    { "[cache]\nopen_revalidate = 500ms\n", NULL },
    { "[cache]\nmax_readahead = 16K\n", "cache.max_readahead" },
    { "[cache]\nmax_readahead = 64K\n", NULL },
    { "[cache]\nmax_readahead = 2G\n", "cache.max_readahead" },
    { "[cache]\nmax_readahead = 0\n", "cache.max_readahead" },
    { "[security]\ncrypto_backend = own\n", NULL },
    { "[security]\ncrypto_backend = openssl\n", "security.crypto_backend" },
    { "[security]\ntrust = trusted\n", NULL },
    { "[security]\ntrust = maybe\n", "security.trust" },
    { "[mount]\nshell_active_files = show\n", NULL },
    { "[mount]\nshell_active_files = maybe\n", "mount.shell_active_files" },
  };
  size_t i;
  for (i = 0; i < SD_COUNTOF(cases); i++) {
    sd_ini *ini;
    sd_profile *p = (sd_profile *)sd_alloc(sizeof(*p));
    const char *bad = NULL;
    sd_err e;
    SD_REQUIRE(p != NULL);
    if (strncmp(cases[i].text, "[profile]", 9) == 0) {
      ini = parse_text(cases[i].text);
    } else {
      char text[512];
      strcpy_s(text, sizeof(text), "[profile]\nhost = h\n");
      strcat_s(text, sizeof(text), cases[i].text);
      ini = parse_text(text);
    }
    SD_REQUIRE(ini != NULL);
    e = sd_profile_from_ini(ini, p, &bad);
    if (cases[i].bad == NULL) {
      if (e != SD_OK)
        sd_test_fail(sd_t_, __FILE__, __LINE__, "case %u: expected OK, got %s", (unsigned)i, bad ? bad : "?");
    } else if (e != SD_E_INVALID_PARAM || bad == NULL || strcmp(bad, cases[i].bad) != 0) {
      sd_test_fail(sd_t_, __FILE__, __LINE__, "case %u: expected %s, got %s", (unsigned)i, cases[i].bad,
                   bad ? bad : "(ok)");
    }
    sd_ini_free(ini);
    sd_free(p);
  }
}

SD_TEST(profile_m3_values_and_derived_shell_active)
{
  sd_ini *ini = parse_text("[profile]\nhost = h\n[security]\ntrust = trusted\n[mount]\nfs_name = exFAT\n"
                           "umask = 077\nremote_case = sensitive\ncase = sensitive\nidentity_probe = exec\n"
                           "[cache]\nattr_ttl = 90s\nopen_revalidate = never\nmax_readahead = 4M\n");
  sd_profile p;
  const char *bad = NULL;
  SD_REQUIRE(ini != NULL);
  SD_REQUIRE(sd_profile_from_ini(ini, &p, &bad) == SD_OK);
  /* trusted and no shell_active_files key: the D41 default shows the shell-active files */
  SD_CHECK_EQ_INT(p.shell_active_files, SD_PROFILE_UNSET);
  SD_CHECK_EQ_INT(sd_profile_block_shell_active(&p), 0);
  SD_CHECK_STR(p.fs_name, "exFAT");
  SD_CHECK_EQ_INT(p.umask, 63);                                    /* 077 */
  SD_CHECK_EQ_INT(p.remote_case, 1);
  SD_CHECK_EQ_INT(p.case_sensitive, 1);
  SD_CHECK_EQ_INT(p.identity_probe_exec, 1);
  SD_CHECK_EQ_INT(p.attr_ttl_ms, 90000);
  SD_CHECK_EQ_INT(p.open_revalidate_ms, -1);
  SD_CHECK_EQ_INT(p.max_readahead, 4u * 1024u * 1024u);
  sd_ini_free(ini);

  /* an explicit value wins over the trust default, in both directions */
  ini = parse_text("[profile]\nhost = h\n[security]\ntrust = trusted\n[mount]\nshell_active_files = block\n");
  SD_REQUIRE(ini != NULL);
  SD_REQUIRE(sd_profile_from_ini(ini, &p, &bad) == SD_OK);
  SD_CHECK_EQ_INT(sd_profile_block_shell_active(&p), 1);
  sd_ini_free(ini);
  ini = parse_text("[profile]\nhost = h\n[mount]\nshell_active_files = show\n");
  SD_REQUIRE(ini != NULL);
  SD_REQUIRE(sd_profile_from_ini(ini, &p, &bad) == SD_OK);
  SD_CHECK_EQ_INT(sd_profile_block_shell_active(&p), 0);
  sd_ini_free(ini);
}

/* 3.4.1 renames: the old names are read once and removed on the next write; the new name wins when both exist. */
SD_TEST(profile_m3_legacy_cache_names)
{
  sd_ini *ini = parse_text("[profile]\nhost = h\n[cache]\nmetadata_ttl = 60s\ndirectory_ttl = 2m\n"
                           "read_cache_disk = 100M\nread_cache_memory = 1G\n");
  sd_profile p;
  const char *bad = NULL;
  SD_REQUIRE(ini != NULL);
  SD_REQUIRE(sd_profile_from_ini(ini, &p, &bad) == SD_OK);
  SD_CHECK_EQ_INT(p.attr_ttl_ms, 60000);
  SD_CHECK_EQ_INT(p.dir_ttl_ms, 120000);
  SD_CHECK_EQ_INT(p.disk_cache_mb, 100);
  SD_REQUIRE(sd_profile_to_ini(&p, &ini) == SD_OK);
  SD_CHECK(sd_ini_get(ini, "cache", "metadata_ttl") == NULL);
  SD_CHECK(sd_ini_get(ini, "cache", "directory_ttl") == NULL);
  SD_CHECK(sd_ini_get(ini, "cache", "read_cache_disk") == NULL);
  SD_CHECK(sd_ini_get(ini, "cache", "read_cache_memory") == NULL);
  SD_CHECK_STR(sd_ini_get(ini, "cache", "attr_ttl"), "1m");
  SD_CHECK_STR(sd_ini_get(ini, "cache", "dir_ttl"), "2m");
  SD_CHECK_STR(sd_ini_get(ini, "cache", "disk"), "100M");
  sd_ini_free(ini);

  ini = parse_text("[profile]\nhost = h\n[cache]\nattr_ttl = 5s\nmetadata_ttl = 60s\n");
  SD_REQUIRE(ini != NULL);
  SD_REQUIRE(sd_profile_from_ini(ini, &p, &bad) == SD_OK);
  SD_CHECK_EQ_INT(p.attr_ttl_ms, 5000);
  sd_ini_free(ini);
}

/* Keys are written only when they differ from the default or are already present. */
SD_TEST(profile_m3_round_trip)
{
  sd_ini *ini = parse_text("[profile]\nhost = h\n");
  sd_profile p;
  const char *bad = NULL;
  SD_REQUIRE(ini != NULL);
  SD_REQUIRE(sd_profile_from_ini(ini, &p, &bad) == SD_OK);
  SD_REQUIRE(sd_profile_to_ini(&p, &ini) == SD_OK);
  SD_CHECK(sd_ini_get(ini, "profile", "scope") == NULL);
  SD_CHECK(sd_ini_get(ini, "security", "trust") == NULL);
  SD_CHECK(sd_ini_get(ini, "mount", "shell_active_files") == NULL);
  SD_CHECK(sd_ini_get(ini, "mount", "hide_dotfiles") == NULL);
  SD_CHECK(sd_ini_get(ini, "mount", "umask") == NULL);
  SD_CHECK(sd_ini_get(ini, "cache", "attr_ttl") == NULL);
  SD_CHECK(sd_ini_get(ini, "cache", "open_revalidate") == NULL);
  SD_CHECK(sd_ini_get(ini, "cache", "max_readahead") == NULL);
  SD_CHECK(sd_ini_get(ini, "mount", "fs_name") == NULL);
  SD_CHECK(sd_ini_get(ini, "mount", "remote_charset") == NULL);
  SD_CHECK(sd_ini_get(ini, "mount", "autostart") == NULL);
  SD_CHECK(sd_ini_get(ini, "security", "crypto_backend") == NULL);

  /* changed values are written, and parsing the result gives the same profile */
  p.hide_dotfiles = 0;
  p.shell_active_files = 0;
  p.umask = 511;
  p.attr_ttl_ms = 90000;
  p.open_revalidate_ms = -1;
  p.max_readahead = 4u * 1024u * 1024u;
  p.autostart = SD_PROFILE_AUTOSTART_LOGON;
  p.autostart_sessions = SD_PROFILE_SESSIONS_CONSOLE;
  p.open_after_mount = 1;
  p.remote_case = 2;
  p.case_sensitive = 1;
  p.identity_probe_exec = 1;
  p.trust = SD_PROFILE_TRUST_TRUSTED;
  p.crypto_backend = SD_PROFILE_CRYPTO_OWN;
  strcpy_s(p.fs_name, sizeof(p.fs_name), "exFAT");
  strcpy_s(p.remote_charset, sizeof(p.remote_charset), "cp1252");
  SD_REQUIRE(sd_profile_to_ini(&p, &ini) == SD_OK);
  SD_CHECK_STR(sd_ini_get(ini, "mount", "hide_dotfiles"), "no");
  SD_CHECK_STR(sd_ini_get(ini, "mount", "shell_active_files"), "show");
  SD_CHECK_STR(sd_ini_get(ini, "mount", "umask"), "777");
  SD_CHECK_STR(sd_ini_get(ini, "cache", "attr_ttl"), "90s");
  SD_CHECK_STR(sd_ini_get(ini, "cache", "open_revalidate"), "never");
  SD_CHECK_STR(sd_ini_get(ini, "cache", "max_readahead"), "4M");
  SD_CHECK_STR(sd_ini_get(ini, "mount", "autostart"), "logon");
  SD_CHECK_STR(sd_ini_get(ini, "mount", "autostart_sessions"), "console");
  SD_CHECK_STR(sd_ini_get(ini, "mount", "open_after_mount"), "yes");
  SD_CHECK_STR(sd_ini_get(ini, "mount", "remote_case"), "insensitive");
  SD_CHECK_STR(sd_ini_get(ini, "mount", "case"), "sensitive");
  SD_CHECK_STR(sd_ini_get(ini, "mount", "identity_probe"), "exec");
  SD_CHECK_STR(sd_ini_get(ini, "mount", "fs_name"), "exFAT");
  SD_CHECK_STR(sd_ini_get(ini, "mount", "remote_charset"), "cp1252");
  SD_CHECK_STR(sd_ini_get(ini, "security", "trust"), "trusted");
  SD_CHECK_STR(sd_ini_get(ini, "security", "crypto_backend"), "own");
  {
    sd_profile *q = (sd_profile *)sd_alloc(sizeof(*q));
    SD_REQUIRE(q != NULL);
    SD_REQUIRE(sd_profile_from_ini(ini, q, &bad) == SD_OK);
    SD_CHECK_EQ_INT(q->umask, 511);
    SD_CHECK_EQ_INT(q->attr_ttl_ms, 90000);
    SD_CHECK_EQ_INT(q->open_revalidate_ms, -1);
    SD_CHECK_EQ_INT(q->max_readahead, 4u * 1024u * 1024u);
    SD_CHECK_EQ_INT(q->autostart, SD_PROFILE_AUTOSTART_LOGON);
    SD_CHECK_EQ_INT(q->remote_case, 2);
    SD_CHECK_EQ_INT(sd_profile_block_shell_active(q), 0);
    SD_CHECK_STR(q->fs_name, "exFAT");
    sd_free(q);
  }

  /* back to the defaults: the keys stay (they are present), and the default values are written */
  p.hide_dotfiles = 1;
  p.shell_active_files = SD_PROFILE_UNSET;
  SD_REQUIRE(sd_profile_to_ini(&p, &ini) == SD_OK);
  SD_CHECK(sd_ini_get(ini, "mount", "shell_active_files") == NULL);   /* the unset value removes the key */
  SD_CHECK_STR(sd_ini_get(ini, "mount", "hide_dotfiles"), "yes");
  sd_ini_free(ini);
}
