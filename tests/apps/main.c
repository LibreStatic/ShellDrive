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
};

int main(int argc, char **argv)
{
  return sd_test_main(k_tests, SD_COUNTOF(k_tests), argc, argv);
}
