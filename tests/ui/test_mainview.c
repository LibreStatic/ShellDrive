/* Main window list (apps/shelldrive-ui/ui_mainview_model.c, 03 §7.5, §7.6): status kinds, the Security column, groups and
   the description of outdated algorithms. */
#include <windows.h>
#include <string.h>

#include "sd_test.h"
#include "sd_base/sd_json.h"
#include "sd_config/sd_config.h"
#include "ui_mainview_model.h"

static sd_json *parse(const char *text)
{
  sd_json *j = NULL;
  if (sd_json_parse(text, strlen(text), 0, &j) != SD_OK)
    return NULL;
  return j;
}

SD_TEST(mainview_security_flags_come_from_the_warning_codes)
{
  sd_json *j = parse("{\"warnings\":[{\"code\":\"legacy_algorithms\",\"mount_id\":\"m-1\"},"
                     "{\"code\":\"write_failed\",\"mount_id\":\"m-1\"},{\"code\":\"terrapin_exposed\",\"mount_id\":\"m-2\"},"
                     "{\"code\":\"legacy_algorithms\"}]}");
  const sd_json *w = sd_json_get(j, "warnings");
  SD_CHECK(j != NULL);
  SD_CHECK_EQ_INT((int)ui_mv_sec_from_warnings(w, "m-1"), (int)UI_MV_SEC_LEGACY);
  SD_CHECK_EQ_INT((int)ui_mv_sec_from_warnings(w, "m-2"), (int)UI_MV_SEC_TERRAPIN);
  SD_CHECK_EQ_INT((int)ui_mv_sec_from_warnings(w, "m-3"), 0);
  SD_CHECK_EQ_INT((int)ui_mv_sec_from_warnings(w, ""), 0);
  SD_CHECK_EQ_INT((int)ui_mv_sec_from_warnings(NULL, "m-1"), 0);
  SD_CHECK_EQ_INT((int)ui_mv_sec_flag("legacy_algorithms"), (int)UI_MV_SEC_LEGACY);
  SD_CHECK_EQ_INT((int)ui_mv_sec_flag("terrapin_exposed"), (int)UI_MV_SEC_TERRAPIN);
  SD_CHECK_EQ_INT((int)ui_mv_sec_flag("write_failed"), 0);
  SD_CHECK_EQ_INT((int)ui_mv_sec_flag(NULL), 0);
  sd_json_free(j);
}

SD_TEST(mainview_both_warnings_of_one_mount_are_kept)
{
  sd_json *j = parse("{\"warnings\":[{\"code\":\"legacy_algorithms\",\"mount_id\":\"m\"},"
                     "{\"code\":\"terrapin_exposed\",\"mount_id\":\"m\"}]}");
  SD_CHECK_EQ_INT((int)ui_mv_sec_from_warnings(sd_json_get(j, "warnings"), "m"),
                  (int)(UI_MV_SEC_LEGACY | UI_MV_SEC_TERRAPIN));
  sd_json_free(j);
}

SD_TEST(mainview_algorithm_names_are_filtered_and_joined)
{
  sd_json *j = parse("{\"algorithms\":[\"3des-cbc\",\"hmac-sha1\",\"bad name\",\"x;y\",\"\",5]}");
  char csv[UI_MV_ALGOS_MAX];
  char names[16][64];
  SD_CHECK_EQ_INT((int)ui_mv_algos_join(j, csv, sizeof(csv)), 2);
  SD_CHECK_STR(csv, "3des-cbc,hmac-sha1");
  SD_CHECK_EQ_INT((int)ui_mv_algos_split(csv, names, 16), 2);
  SD_CHECK_STR(names[1], "hmac-sha1");
  sd_json_free(j);
  /* no list: empty, and a tiny buffer never overflows */
  j = parse("{}");
  SD_CHECK_EQ_INT((int)ui_mv_algos_join(j, csv, sizeof(csv)), 0);
  SD_CHECK_STR(csv, "");
  sd_json_free(j);
  j = parse("{\"algorithms\":[\"3des-cbc\",\"hmac-sha1\"]}");
  {
    char tiny[12];
    SD_CHECK_EQ_INT((int)ui_mv_algos_join(j, tiny, sizeof(tiny)), 1);
    SD_CHECK_STR(tiny, "3des-cbc");
  }
  sd_json_free(j);
}

SD_TEST(mainview_dont_warn_again_hash_ignores_order)
{
  char a[80], b[80], c[80];
  SD_CHECK_EQ_INT(ui_mv_algos_hash("3des-cbc,hmac-sha1", a), 1);
  SD_CHECK_EQ_INT(ui_mv_algos_hash("hmac-sha1,3des-cbc", b), 1);
  SD_CHECK_STR(a, b);
  SD_CHECK(strncmp(a, "sha256:", 7) == 0);
  /* a different set has a different value, so it warns again (7.6) */
  SD_CHECK_EQ_INT(ui_mv_algos_hash("3des-cbc", c), 1);
  SD_CHECK(strcmp(a, c) != 0);
  SD_CHECK_EQ_INT(ui_mv_algos_hash("", c), 0);
}

SD_TEST(mainview_status_kinds_and_icons)
{
  SD_CHECK_EQ_INT((int)ui_mv_status_of("", "", 0), (int)UI_MV_ST_NOT_MOUNTED);
  SD_CHECK_EQ_INT((int)ui_mv_status_of(NULL, NULL, 0), (int)UI_MV_ST_NOT_MOUNTED);
  SD_CHECK_EQ_INT((int)ui_mv_status_of("mounted", "ready", 0), (int)UI_MV_ST_MOUNTED);
  SD_CHECK_EQ_INT((int)ui_mv_status_of("connecting", "", 0), (int)UI_MV_ST_CONNECTING);
  SD_CHECK_EQ_INT((int)ui_mv_status_of("failed", "failed", 0), (int)UI_MV_ST_FAILED);
  SD_CHECK_EQ_INT((int)ui_mv_status_of("auth_required", "", 0), (int)UI_MV_ST_AUTH_REQUIRED);
  SD_CHECK_EQ_INT((int)ui_mv_status_of("future_state", "", 0), (int)UI_MV_ST_UNKNOWN);
  /* offline while the session waits to retry is "Reconnecting (n)"; offline without a retry stays offline */
  SD_CHECK_EQ_INT((int)ui_mv_status_of("offline", "reconnect_wait", 3), (int)UI_MV_ST_RECONNECTING);
  SD_CHECK_EQ_INT((int)ui_mv_status_of("offline", "reconnect_wait", 0), (int)UI_MV_ST_OFFLINE);
  SD_CHECK_EQ_INT((int)ui_mv_status_of("offline", "disconnected", 2), (int)UI_MV_ST_OFFLINE);
  SD_CHECK_EQ_INT((int)ui_mv_status_icon(UI_MV_ST_MOUNTED), (int)UI_MV_ICON_OK);
  SD_CHECK_EQ_INT((int)ui_mv_status_icon(UI_MV_ST_RECONNECTING), (int)UI_MV_ICON_WARN);
  SD_CHECK_EQ_INT((int)ui_mv_status_icon(UI_MV_ST_FAILED), (int)UI_MV_ICON_WARN);
  SD_CHECK_EQ_INT((int)ui_mv_status_icon(UI_MV_ST_CONNECTING), (int)UI_MV_ICON_IDLE);
  SD_CHECK_EQ_INT((int)ui_mv_status_icon(UI_MV_ST_NOT_MOUNTED), (int)UI_MV_ICON_NONE);
  SD_CHECK_EQ_INT((int)ui_mv_sec_icon(0), (int)UI_MV_ICON_NONE);
  SD_CHECK_EQ_INT((int)ui_mv_sec_icon(UI_MV_SEC_TERRAPIN), (int)UI_MV_ICON_WARN);
}

SD_TEST(mainview_groups_follow_the_scope)
{
  SD_CHECK_EQ_INT((int)ui_mv_group_of_scope(SD_PROFILE_SCOPE_USER), (int)UI_MV_GROUP_MINE);
  SD_CHECK_EQ_INT((int)ui_mv_group_of_scope(SD_PROFILE_SCOPE_USERS), (int)UI_MV_GROUP_ORG);
  SD_CHECK_EQ_INT((int)ui_mv_group_of_scope(SD_PROFILE_SCOPE_SERVICE), (int)UI_MV_GROUP_GLOBAL);
  SD_CHECK_EQ_INT((int)ui_mv_group_of_scope(-1), (int)UI_MV_GROUP_MINE);   /* an ad-hoc mount */
  /* a machine template is read-only in the list (no Edit, Duplicate, Delete); the user's and the global ones are not */
  SD_CHECK(ui_mv_scope_read_only(SD_PROFILE_SCOPE_USERS));
  SD_CHECK(!ui_mv_scope_read_only(SD_PROFILE_SCOPE_USER));
  SD_CHECK(!ui_mv_scope_read_only(SD_PROFILE_SCOPE_SERVICE));
  SD_CHECK(!ui_mv_scope_read_only(-1));
}

SD_TEST(mainview_algorithm_categories_and_reasons)
{
  ui_mv_cat c;
  ui_mv_why w;
  ui_mv_algo_info("3des-cbc", &c, &w);
  SD_CHECK_EQ_INT((int)c, (int)UI_MV_CAT_CIPHER);
  SD_CHECK_EQ_INT((int)w, (int)UI_MV_WHY_CBC);
  ui_mv_algo_info("aes128-cbc", &c, &w);
  SD_CHECK_EQ_INT((int)w, (int)UI_MV_WHY_CBC);
  ui_mv_algo_info("hmac-sha1-etm@openssh.com", &c, &w);
  SD_CHECK_EQ_INT((int)c, (int)UI_MV_CAT_MAC);
  SD_CHECK_EQ_INT((int)w, (int)UI_MV_WHY_MAC_SHA1);
  ui_mv_algo_info("diffie-hellman-group1-sha1", &c, &w);
  SD_CHECK_EQ_INT((int)c, (int)UI_MV_CAT_KEX);
  SD_CHECK_EQ_INT((int)w, (int)UI_MV_WHY_KEX_SHA1);
  ui_mv_algo_info("ssh-rsa", &c, &w);
  SD_CHECK_EQ_INT((int)c, (int)UI_MV_CAT_HOSTKEY);
  SD_CHECK_EQ_INT((int)w, (int)UI_MV_WHY_HOSTKEY_SHA1);
  ui_mv_algo_info("something-new", &c, &w);
  SD_CHECK_EQ_INT((int)c, (int)UI_MV_CAT_OTHER);
  SD_CHECK_EQ_INT((int)w, (int)UI_MV_WHY_OTHER);
  ui_mv_algo_info(NULL, &c, &w);
  SD_CHECK_EQ_INT((int)c, (int)UI_MV_CAT_OTHER);
}

SD_TEST(mainview_list_security_fields_are_read_from_the_mount)
{
  sd_json *j = parse("{\"mounts\":[{\"mount_id\":\"m-1\",\"legacy\":true,\"terrapin_exposed\":true,"
                     "\"legacy_algorithms\":[{\"category\":\"cipher\",\"name\":\"3des-cbc\"},"
                     "{\"category\":\"mac\",\"name\":\"hmac-sha1\"},{\"category\":\"weird\",\"name\":\"x-new\"},"
                     "{\"category\":\"kex\",\"name\":\"bad name;\"},{\"category\":\"kex\"}]},"
                     "{\"mount_id\":\"m-2\",\"legacy\":false,\"terrapin_exposed\":false,\"legacy_algorithms\":[]},"
                     "{\"mount_id\":\"m-3\"}],"
                     "\"warnings\":[{\"code\":\"legacy_algorithms\",\"mount_id\":\"m-2\"},"
                     "{\"code\":\"terrapin_exposed\",\"mount_id\":\"m-3\"}]}");
  const sd_json *mounts = sd_json_get(j, "mounts");
  const sd_json *warnings = sd_json_get(j, "warnings");
  ui_mv_security s;
  char names[4][64];
  SD_CHECK(j != NULL);
  ui_mv_security_from_mount(sd_json_at(mounts, 0), warnings, "m-1", &s);
  SD_CHECK_EQ_INT(s.from_mount, 1);
  SD_CHECK_EQ_INT((int)s.sec, (int)(UI_MV_SEC_LEGACY | UI_MV_SEC_TERRAPIN));
  SD_CHECK_EQ_INT((int)s.n_algos, 3);                /* the name with a space and the entry without a name are dropped */
  SD_CHECK_STR(s.algos, "3des-cbc,hmac-sha1,x-new");
  SD_CHECK_EQ_INT((int)s.cats[0], (int)UI_MV_CAT_CIPHER);
  SD_CHECK_EQ_INT((int)s.cats[1], (int)UI_MV_CAT_MAC);
  SD_CHECK_EQ_INT((int)s.cats[2], (int)UI_MV_CAT_OTHER);
  /* names and categories stay aligned for the dialog and for the "Don't warn again" hash */
  SD_CHECK_EQ_INT((int)ui_mv_algos_split(s.algos, names, 4), 3);
  SD_CHECK_STR(names[2], "x-new");
  /* the mount's own fields win over a stale warning in the ring */
  ui_mv_security_from_mount(sd_json_at(mounts, 1), warnings, "m-2", &s);
  SD_CHECK_EQ_INT(s.from_mount, 1);
  SD_CHECK_EQ_INT((int)s.sec, 0);
  SD_CHECK_EQ_INT((int)s.n_algos, 0);
  /* an agent that sends no such fields: the warnings ring */
  ui_mv_security_from_mount(sd_json_at(mounts, 2), warnings, "m-3", &s);
  SD_CHECK_EQ_INT(s.from_mount, 0);
  SD_CHECK_EQ_INT((int)s.sec, (int)UI_MV_SEC_TERRAPIN);
  sd_json_free(j);
}

SD_TEST(mainview_legacy_flag_without_a_list_keeps_the_names_unknown)
{
  sd_json *j = parse("{\"mount_id\":\"m\",\"legacy\":true}");
  ui_mv_security s;
  SD_CHECK(j != NULL);
  ui_mv_security_from_mount(j, NULL, "m", &s);
  SD_CHECK_EQ_INT((int)s.sec, (int)UI_MV_SEC_LEGACY);
  SD_CHECK_EQ_INT((int)s.n_algos, 0);
  sd_json_free(j);
}

SD_TEST(mainview_scope_tokens_give_the_groups)
{
  SD_CHECK_EQ_INT(ui_mv_scope_of_token("user"), SD_PROFILE_SCOPE_USER);
  SD_CHECK_EQ_INT(ui_mv_scope_of_token("machine_template"), SD_PROFILE_SCOPE_USERS);
  SD_CHECK_EQ_INT(ui_mv_scope_of_token("global"), SD_PROFILE_SCOPE_SERVICE);
  SD_CHECK_EQ_INT(ui_mv_scope_of_token("elsewhere"), -1);
  SD_CHECK_EQ_INT(ui_mv_scope_of_token(NULL), -1);
  /* a mount from the organization or from all users lands in its own group, one without a scope in "My connections" */
  SD_CHECK_EQ_INT((int)ui_mv_group_of_scope(ui_mv_scope_of_token("machine_template")), (int)UI_MV_GROUP_ORG);
  SD_CHECK_EQ_INT((int)ui_mv_group_of_scope(ui_mv_scope_of_token("global")), (int)UI_MV_GROUP_GLOBAL);
  SD_CHECK_EQ_INT((int)ui_mv_group_of_scope(ui_mv_scope_of_token(NULL)), (int)UI_MV_GROUP_MINE);
  SD_CHECK_EQ_INT((int)ui_mv_cat_of_token("kex"), (int)UI_MV_CAT_KEX);
  SD_CHECK_EQ_INT((int)ui_mv_cat_of_token("hostkey"), (int)UI_MV_CAT_HOSTKEY);
  SD_CHECK_EQ_INT((int)ui_mv_cat_of_token("cipher"), (int)UI_MV_CAT_CIPHER);
  SD_CHECK_EQ_INT((int)ui_mv_cat_of_token("mac"), (int)UI_MV_CAT_MAC);
  SD_CHECK_EQ_INT((int)ui_mv_cat_of_token("compression"), (int)UI_MV_CAT_OTHER);
  SD_CHECK_EQ_INT((int)ui_mv_cat_of_token(NULL), (int)UI_MV_CAT_OTHER);
}
