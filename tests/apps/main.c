#include "sd_test.h"

SD_TEST_DECL(cli_split_follows_msvc_rules);
SD_TEST_DECL(cli_parse_mount_forms);
SD_TEST_DECL(cli_parse_errors);
SD_TEST_DECL(cli_parse_other_commands);
SD_TEST_DECL(cli_parse_mount_m2_options);
SD_TEST_DECL(cli_parse_profile_hostkey_status);
SD_TEST_DECL(smoke_version_help_usage);
SD_TEST_DECL(smoke_mount_prompts_and_errors);
SD_TEST_DECL(smoke_mount_m2_flags_and_prompts);
SD_TEST_DECL(smoke_status_and_pool_flag);
SD_TEST_DECL(smoke_profile_import);
SD_TEST_DECL(smoke_hostkey_commands);
SD_TEST_DECL(m3_ui_only_prompts_and_answers);
SD_TEST_DECL(m3_prompt_deadline_timeout);
SD_TEST_DECL(m3_queue_evicts_and_drains_to_ui);
SD_TEST_DECL(m3_initiator_gone_keeps_prompts_for_ui);
SD_TEST_DECL(m3_initiator_gone_without_ui_cancels);
SD_TEST_DECL(m3_new_methods_and_list_warnings);
SD_TEST_DECL(m4_update_consent_and_disabled_check);
SD_TEST_DECL(m3_snapshot_and_icon_follow_mount);
SD_TEST_DECL(m3_network_location_entries_at_start);
SD_TEST_DECL(m3_profile_test_results_and_errors);
SD_TEST_DECL(m3_config_changed_and_agent_stopping);
SD_TEST_DECL(m3_refresh_cache_attach_and_status_stats);
SD_TEST_DECL(m3_cache_clear_refuses_queued_writes);
SD_TEST_DECL(m3_autostart_and_open_after_mount);
SD_TEST_DECL(cli_parse_m3_commands);
SD_TEST_DECL(agent_shutdown_event_stops_agent);
SD_TEST_DECL(m3_webdav_token_only_question_routes_to_ui);

static const sd_test_case k_tests[] = {
  SD_TEST_ENTRY(cli_split_follows_msvc_rules),
  SD_TEST_ENTRY(cli_parse_mount_forms),
  SD_TEST_ENTRY(cli_parse_errors),
  SD_TEST_ENTRY(cli_parse_other_commands),
  SD_TEST_ENTRY(cli_parse_mount_m2_options),
  SD_TEST_ENTRY(cli_parse_profile_hostkey_status),
  SD_TEST_ENTRY(smoke_version_help_usage),
  SD_TEST_ENTRY(smoke_mount_prompts_and_errors),
  SD_TEST_ENTRY(smoke_mount_m2_flags_and_prompts),
  SD_TEST_ENTRY(smoke_status_and_pool_flag),
  SD_TEST_ENTRY(smoke_profile_import),
  SD_TEST_ENTRY(smoke_hostkey_commands),
  SD_TEST_ENTRY(m3_ui_only_prompts_and_answers),
  SD_TEST_ENTRY(m3_prompt_deadline_timeout),
  SD_TEST_ENTRY(m3_queue_evicts_and_drains_to_ui),
  SD_TEST_ENTRY(m3_initiator_gone_keeps_prompts_for_ui),
  SD_TEST_ENTRY(m3_initiator_gone_without_ui_cancels),
  SD_TEST_ENTRY(m3_new_methods_and_list_warnings),
  SD_TEST_ENTRY(m4_update_consent_and_disabled_check),
  SD_TEST_ENTRY(m3_snapshot_and_icon_follow_mount),
  SD_TEST_ENTRY(m3_network_location_entries_at_start),
  SD_TEST_ENTRY(m3_profile_test_results_and_errors),
  SD_TEST_ENTRY(m3_config_changed_and_agent_stopping),
  SD_TEST_ENTRY(m3_refresh_cache_attach_and_status_stats),
  SD_TEST_ENTRY(m3_cache_clear_refuses_queued_writes),
  SD_TEST_ENTRY(m3_autostart_and_open_after_mount),
  SD_TEST_ENTRY(cli_parse_m3_commands),
  SD_TEST_ENTRY(agent_shutdown_event_stops_agent),
  SD_TEST_ENTRY(m3_webdav_token_only_question_routes_to_ui),
};

int main(int argc, char **argv)
{
  return sd_test_main(k_tests, SD_COUNTOF(k_tests), argc, argv);
}
