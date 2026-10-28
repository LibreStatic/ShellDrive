/* Tray notices (apps/shelldrive-ui/ui_notice_model.c, 03 7.7): which change of the agent's state leads to which notice,
   the [ui] notify_<kind> switch of each, and the once-per-(profile, proxy) rule. */
#include <windows.h>
#include <string.h>

#include "sd_test.h"
#include "sd_config/sd_config.h"
#include "ui_notice_model.h"

SD_TEST(notice_mount_state_changes)
{
  /* connection lost: only a mounted drive that goes offline; the reconnect attempts that follow are not new notices */
  SD_CHECK_EQ_INT((int)ui_nt_of_mount_state("mounted", "offline", NULL), (int)UI_NT_CONNECTION_LOST);
  SD_CHECK_EQ_INT((int)ui_nt_of_mount_state("offline", "offline", NULL), (int)UI_NT_NONE);
  SD_CHECK_EQ_INT((int)ui_nt_of_mount_state("connecting", "offline", NULL), (int)UI_NT_NONE);
  /* reconnected: offline -> mounted; mounted: anything else -> mounted; connection details of a mounted drive: nothing */
  SD_CHECK_EQ_INT((int)ui_nt_of_mount_state("offline", "mounted", NULL), (int)UI_NT_RECONNECTED);
  SD_CHECK_EQ_INT((int)ui_nt_of_mount_state("connecting", "mounted", NULL), (int)UI_NT_MOUNTED);
  SD_CHECK_EQ_INT((int)ui_nt_of_mount_state("authenticating", "mounted", NULL), (int)UI_NT_MOUNTED);
  SD_CHECK_EQ_INT((int)ui_nt_of_mount_state("", "mounted", NULL), (int)UI_NT_MOUNTED);     /* a mount the UI had not listed */
  SD_CHECK_EQ_INT((int)ui_nt_of_mount_state(NULL, "mounted", NULL), (int)UI_NT_MOUNTED);
  SD_CHECK_EQ_INT((int)ui_nt_of_mount_state("mounted", "mounted", NULL), (int)UI_NT_NONE);
  /* mount failed, once */
  SD_CHECK_EQ_INT((int)ui_nt_of_mount_state("connecting", "failed", "auth_failed"), (int)UI_NT_MOUNT_FAILED);
  SD_CHECK_EQ_INT((int)ui_nt_of_mount_state("connecting", "failed", NULL), (int)UI_NT_MOUNT_FAILED);
  SD_CHECK_EQ_INT((int)ui_nt_of_mount_state("failed", "failed", "auth_failed"), (int)UI_NT_NONE);
  /* a changed key and a wrong key type have their own balloons that cannot be switched off (5.4) */
  SD_CHECK_EQ_INT((int)ui_nt_of_mount_state("connecting", "failed", "host_key_mismatch"), (int)UI_NT_NONE);
  SD_CHECK_EQ_INT((int)ui_nt_of_mount_state("connecting", "failed", "host_key_type_unavailable"), (int)UI_NT_NONE);
  /* other states are the plain state entries of the event list */
  SD_CHECK_EQ_INT((int)ui_nt_of_mount_state("mounted", "unmounting", NULL), (int)UI_NT_NONE);
  SD_CHECK_EQ_INT((int)ui_nt_of_mount_state("unmounting", "unmounted", NULL), (int)UI_NT_NONE);
  SD_CHECK_EQ_INT((int)ui_nt_of_mount_state("mounted", "auth_required", NULL), (int)UI_NT_NONE);
  SD_CHECK_EQ_INT((int)ui_nt_of_mount_state("mounted", "", NULL), (int)UI_NT_NONE);
  SD_CHECK_EQ_INT((int)ui_nt_of_mount_state("mounted", NULL, NULL), (int)UI_NT_NONE);
}

SD_TEST(notice_warning_codes)
{
  /* the agent's code is proxy_cleartext (03 3.8); the settings backend maps proxy_password, both are the same notice */
  SD_CHECK_EQ_INT((int)ui_nt_of_warning_code("proxy_cleartext"), (int)UI_NT_PROXY_PASSWORD);
  SD_CHECK_EQ_INT((int)ui_nt_of_warning_code("proxy_password"), (int)UI_NT_PROXY_PASSWORD);
  SD_CHECK_EQ_INT((int)ui_nt_of_warning_code("pool_limited"), (int)UI_NT_POOL_LIMITED);
  SD_CHECK_EQ_INT((int)ui_nt_of_warning_code("disk_cache_refused"), (int)UI_NT_DISK_CACHE);
  /* handled elsewhere or without a notice here */
  SD_CHECK_EQ_INT((int)ui_nt_of_warning_code("legacy_algorithms"), (int)UI_NT_NONE);
  SD_CHECK_EQ_INT((int)ui_nt_of_warning_code("write_failed"), (int)UI_NT_NONE);
  SD_CHECK_EQ_INT((int)ui_nt_of_warning_code(NULL), (int)UI_NT_NONE);
}

SD_TEST(notice_every_kind_has_its_switch)
{
  sd_settings s;
  SD_CHECK_EQ_INT(ui_nt_switch_of(UI_NT_CONNECTION_LOST), (int)SD_NOTIFY_CONNECTION_LOST);
  SD_CHECK_EQ_INT(ui_nt_switch_of(UI_NT_RECONNECTED), (int)SD_NOTIFY_RECONNECTED);
  SD_CHECK_EQ_INT(ui_nt_switch_of(UI_NT_MOUNT_FAILED), (int)SD_NOTIFY_MOUNT_FAILED);
  SD_CHECK_EQ_INT(ui_nt_switch_of(UI_NT_MOUNTED), (int)SD_NOTIFY_MOUNTED);
  SD_CHECK_EQ_INT(ui_nt_switch_of(UI_NT_PROXY_PASSWORD), (int)SD_NOTIFY_PROXY_PASSWORD);
  SD_CHECK_EQ_INT(ui_nt_switch_of(UI_NT_POOL_LIMITED), (int)SD_NOTIFY_POOL_LIMITED);
  SD_CHECK_EQ_INT(ui_nt_switch_of(UI_NT_SERVICE_ATTENTION), (int)SD_NOTIFY_SERVICE_ATTENTION);
  SD_CHECK_EQ_INT(ui_nt_switch_of(UI_NT_HOSTKEYS_SAVED), (int)SD_NOTIFY_HOSTKEYS_SAVED);
  SD_CHECK_EQ_INT(ui_nt_switch_of(UI_NT_DISK_CACHE), (int)SD_NOTIFY_DISK_CACHE);
  SD_CHECK_EQ_INT(ui_nt_switch_of(UI_NT_NONE), -1);
  /* the defaults of 7.7: lost, reconnected, failed on; mounted and the pool limit off; everything under the master */
  sd_settings_defaults(&s);
  SD_CHECK_EQ_INT(sd_settings_notify_on(&s, ui_nt_switch_of(UI_NT_CONNECTION_LOST)), 1);
  SD_CHECK_EQ_INT(sd_settings_notify_on(&s, ui_nt_switch_of(UI_NT_RECONNECTED)), 1);
  SD_CHECK_EQ_INT(sd_settings_notify_on(&s, ui_nt_switch_of(UI_NT_MOUNT_FAILED)), 1);
  SD_CHECK_EQ_INT(sd_settings_notify_on(&s, ui_nt_switch_of(UI_NT_MOUNTED)), 0);
  SD_CHECK_EQ_INT(sd_settings_notify_on(&s, ui_nt_switch_of(UI_NT_POOL_LIMITED)), 0);
  SD_CHECK_EQ_INT(sd_settings_notify_on(&s, ui_nt_switch_of(UI_NT_DISK_CACHE)), 1);
  s.notify = 0;
  SD_CHECK_EQ_INT(sd_settings_notify_on(&s, ui_nt_switch_of(UI_NT_CONNECTION_LOST)), 0);
}

SD_TEST(notice_attention_only_when_the_count_grows)
{
  SD_CHECK_EQ_INT(ui_nt_attention_grew(0, 1), 1);
  SD_CHECK_EQ_INT(ui_nt_attention_grew(1, 3), 1);
  SD_CHECK_EQ_INT(ui_nt_attention_grew(3, 3), 0);
  SD_CHECK_EQ_INT(ui_nt_attention_grew(3, 1), 0);
  SD_CHECK_EQ_INT(ui_nt_attention_grew(2, 0), 0);
  SD_CHECK_EQ_INT(ui_nt_attention_grew(0, 0), 0);
}

SD_TEST(notice_proxy_password_once_per_profile_and_proxy)
{
  ui_nt_once o;
  char k1[UI_NT_ONCE_KEY_MAX], k2[UI_NT_ONCE_KEY_MAX], k3[UI_NT_ONCE_KEY_MAX];
  size_t i;
  memset(&o, 0, sizeof(o));
  SD_CHECK_EQ_INT(ui_nt_once_key("p1", "socks.corp:1080", k1, sizeof(k1)), 1);
  SD_CHECK_EQ_INT(ui_nt_once_key("p1", "other.corp:8080", k2, sizeof(k2)), 1);
  SD_CHECK_EQ_INT(ui_nt_once_key("p2", "socks.corp:1080", k3, sizeof(k3)), 1);
  SD_CHECK_EQ_INT(ui_nt_once_take(&o, k1), 1);
  SD_CHECK_EQ_INT(ui_nt_once_take(&o, k1), 0);       /* the same profile and proxy again: silent */
  SD_CHECK_EQ_INT(ui_nt_once_take(&o, k2), 1);       /* another proxy of the profile */
  SD_CHECK_EQ_INT(ui_nt_once_take(&o, k3), 1);       /* another profile with the same proxy */
  SD_CHECK_EQ_INT(ui_nt_once_take(&o, k3), 0);
  SD_CHECK_EQ_INT(ui_nt_once_take(&o, NULL), 0);
  /* the oldest keys are forgotten when more than the table holds are seen */
  for (i = 0; i < UI_NT_ONCE_SLOTS; i++) {
    char k[8];
    k[0] = 'x';
    k[1] = (char)('a' + (i % 26));
    k[2] = (char)('a' + (i / 26));
    k[3] = 0;
    SD_CHECK_EQ_INT(ui_nt_once_take(&o, k), 1);
  }
  SD_CHECK_EQ_INT(ui_nt_once_take(&o, k1), 1);
  /* a key that does not fit is refused, not cut silently */
  SD_CHECK_EQ_INT(ui_nt_once_key("0123456789", "0123456789", k1, 10), 0);
}

SD_TEST(notice_hostkey_source_warning_has_its_notice_and_switch)
{
  sd_settings s;
  SD_CHECK_EQ_INT((int)ui_nt_of_warning_code("hostkey_source_insecure"), (int)UI_NT_HOSTKEYS_SOURCE);
  SD_CHECK_EQ_INT(ui_nt_switch_of(UI_NT_HOSTKEYS_SOURCE), (int)SD_NOTIFY_HOSTKEYS_SOURCE);
  /* the switch is the one the agent and the settings map for this code, and it is on by default (7.7) */
  SD_CHECK_EQ_INT(sd_notify_kind_from_code("hostkey_source_insecure"), (int)SD_NOTIFY_HOSTKEYS_SOURCE);
  sd_settings_defaults(&s);
  SD_CHECK_EQ_INT(sd_settings_notify_on(&s, ui_nt_switch_of(UI_NT_HOSTKEYS_SOURCE)), 1);
  s.notify_kind[SD_NOTIFY_HOSTKEYS_SOURCE] = 0;
  SD_CHECK_EQ_INT(sd_settings_notify_on(&s, ui_nt_switch_of(UI_NT_HOSTKEYS_SOURCE)), 0);
  s.notify_kind[SD_NOTIFY_HOSTKEYS_SOURCE] = 1;
  s.notify = 0;
  SD_CHECK_EQ_INT(sd_settings_notify_on(&s, ui_nt_switch_of(UI_NT_HOSTKEYS_SOURCE)), 0);
}

SD_TEST(notice_source_names)
{
  SD_CHECK_STR(ui_nt_source_name("openssh"), "OpenSSH");
  SD_CHECK_STR(ui_nt_source_name("putty"), "PuTTY");
  SD_CHECK(ui_nt_source_name("registry") == NULL);       /* an unknown detail is not shown as a name */
  SD_CHECK(ui_nt_source_name("") == NULL);
  SD_CHECK(ui_nt_source_name(NULL) == NULL);
}

SD_TEST(notice_reconnect_reason_makes_the_reconnected_notice)
{
  /* offline -> mounted is a reconnect with or without a reason */
  SD_CHECK_EQ_INT((int)ui_nt_of_mount_state_r("offline", "mounted", NULL, "timeout"), (int)UI_NT_RECONNECTED);
  SD_CHECK_EQ_INT((int)ui_nt_of_mount_state_r("offline", "mounted", NULL, NULL), (int)UI_NT_RECONNECTED);
  /* connecting and authenticating come between offline and mounted: the reason says it was a reconnect */
  SD_CHECK_EQ_INT((int)ui_nt_of_mount_state_r("connecting", "mounted", NULL, "disconnected"), (int)UI_NT_RECONNECTED);
  SD_CHECK_EQ_INT((int)ui_nt_of_mount_state_r("authenticating", "mounted", NULL, "timeout"), (int)UI_NT_RECONNECTED);
  /* a first mount carries no reason */
  SD_CHECK_EQ_INT((int)ui_nt_of_mount_state_r("connecting", "mounted", NULL, NULL), (int)UI_NT_MOUNTED);
  SD_CHECK_EQ_INT((int)ui_nt_of_mount_state_r("connecting", "mounted", NULL, ""), (int)UI_NT_MOUNTED);
  /* the same state again is no notice, reason or not */
  SD_CHECK_EQ_INT((int)ui_nt_of_mount_state_r("mounted", "mounted", NULL, "timeout"), (int)UI_NT_NONE);
  /* the reason does not change the other states */
  SD_CHECK_EQ_INT((int)ui_nt_of_mount_state_r("mounted", "offline", NULL, "timeout"), (int)UI_NT_CONNECTION_LOST);
  SD_CHECK_EQ_INT((int)ui_nt_of_mount_state_r("connecting", "connecting", NULL, "timeout"), (int)UI_NT_NONE);
}

SD_TEST(notice_reason_codes_known_and_unknown)
{
  static const char *const known[UI_NT_REASONS] = {
    "disconnected", "timeout", "dns_failed", "conn_refused", "net_unreachable", "protocol", "auth_failed",
    "proxy_connect_failed"
  };
  int i, seen = 0;
  for (i = 0; i < UI_NT_REASONS; i++) {
    SD_CHECK_EQ_INT(ui_nt_reason_index(known[i]), i);
    seen |= 1 << i;
  }
  SD_CHECK_EQ_INT(seen, (1 << UI_NT_REASONS) - 1);
  /* any other code is shown as it is (the caller prints the code) */
  SD_CHECK_EQ_INT(ui_nt_reason_index("something_new"), -1);
  SD_CHECK_EQ_INT(ui_nt_reason_index(""), -1);
  SD_CHECK_EQ_INT(ui_nt_reason_index(NULL), -1);
  SD_CHECK_EQ_INT(ui_nt_reason_index("Timeout"), -1);     /* codes are exact */
}
