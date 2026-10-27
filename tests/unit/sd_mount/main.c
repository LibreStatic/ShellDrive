#include "sd_test.h"

SD_TEST_DECL(mount_tofu_password_mount_unmount);
SD_TEST_DECL(mount_second_connection_skips_tofu);
SD_TEST_DECL(mount_hostkey_rejected_fails);
SD_TEST_DECL(mount_hostkey_once_is_not_stored);
SD_TEST_DECL(mount_mismatch_is_hard_failure_with_details);
SD_TEST_DECL(mount_wrong_password_fails_auth);
SD_TEST_DECL(mount_passphrase_and_identity);
SD_TEST_DECL(mount_unreachable_and_no_dokany);
SD_TEST_DECL(mount_stop_while_prompting);
SD_TEST_DECL(mount_rejects_bad_params_and_names);
SD_TEST_DECL(mount_backend_selection);
SD_TEST_DECL(mount_m3_test_only_probe);
SD_TEST_DECL(mount_m3_refresh_stats_cache_and_stop);
SD_TEST_DECL(mount_m3_webdav_attach_port);
SD_TEST_DECL(mount_token_only_params_reach_webdav_cfg);
SD_TEST_DECL(mount_token_only_refused_for_global);
SD_TEST_DECL(mount_token_consent_accept_and_once);
SD_TEST_DECL(mount_token_consent_reject_fails);
SD_TEST_DECL(mount_token_only_asks_before_webdav_start);
SD_TEST_DECL(mount_reconnect_keeps_drive);
SD_TEST_DECL(mount_write_failed_and_identity);
SD_TEST_DECL(mount_m2_chain_and_proxies);
SD_TEST_DECL(mount_m2_autofill_rules);
SD_TEST_DECL(mount_m2_save_after_success);
SD_TEST_DECL(mount_m2_kbdint_password_round_and_otp);
SD_TEST_DECL(mount_m2_legacy_warn_ask_refuse);
SD_TEST_DECL(mount_m2_password_change);
SD_TEST_DECL(mount_m2_hostkeys_announced);
SD_TEST_DECL(mount_m2_pool_needs_noninteractive_auth);

static const sd_test_case k_tests[] = {
  SD_TEST_ENTRY(mount_tofu_password_mount_unmount),
  SD_TEST_ENTRY(mount_second_connection_skips_tofu),
  SD_TEST_ENTRY(mount_hostkey_rejected_fails),
  SD_TEST_ENTRY(mount_hostkey_once_is_not_stored),
  SD_TEST_ENTRY(mount_mismatch_is_hard_failure_with_details),
  SD_TEST_ENTRY(mount_wrong_password_fails_auth),
  SD_TEST_ENTRY(mount_passphrase_and_identity),
  SD_TEST_ENTRY(mount_unreachable_and_no_dokany),
  SD_TEST_ENTRY(mount_stop_while_prompting),
  SD_TEST_ENTRY(mount_rejects_bad_params_and_names),
  SD_TEST_ENTRY(mount_backend_selection),
  SD_TEST_ENTRY(mount_m3_test_only_probe),
  SD_TEST_ENTRY(mount_m3_refresh_stats_cache_and_stop),
  SD_TEST_ENTRY(mount_m3_webdav_attach_port),
  SD_TEST_ENTRY(mount_token_only_params_reach_webdav_cfg),
  SD_TEST_ENTRY(mount_token_only_refused_for_global),
  SD_TEST_ENTRY(mount_token_consent_accept_and_once),
  SD_TEST_ENTRY(mount_token_consent_reject_fails),
  SD_TEST_ENTRY(mount_token_only_asks_before_webdav_start),
  SD_TEST_ENTRY(mount_reconnect_keeps_drive),
  SD_TEST_ENTRY(mount_write_failed_and_identity),
  SD_TEST_ENTRY(mount_m2_chain_and_proxies),
  SD_TEST_ENTRY(mount_m2_autofill_rules),
  SD_TEST_ENTRY(mount_m2_save_after_success),
  SD_TEST_ENTRY(mount_m2_kbdint_password_round_and_otp),
  SD_TEST_ENTRY(mount_m2_legacy_warn_ask_refuse),
  SD_TEST_ENTRY(mount_m2_password_change),
  SD_TEST_ENTRY(mount_m2_hostkeys_announced),
  SD_TEST_ENTRY(mount_m2_pool_needs_noninteractive_auth),
};

int main(int argc, char **argv)
{
  return sd_test_main(k_tests, SD_COUNTOF(k_tests), argc, argv);
}
