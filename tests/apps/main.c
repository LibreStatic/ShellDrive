#include "sd_test.h"

SD_TEST_DECL(cli_split_follows_msvc_rules);
SD_TEST_DECL(cli_parse_mount_forms);
SD_TEST_DECL(cli_parse_errors);
SD_TEST_DECL(cli_parse_other_commands);
SD_TEST_DECL(smoke_version_help_usage);
SD_TEST_DECL(smoke_mount_prompts_and_errors);

static const sd_test_case k_tests[] = {
  SD_TEST_ENTRY(cli_split_follows_msvc_rules),
  SD_TEST_ENTRY(cli_parse_mount_forms),
  SD_TEST_ENTRY(cli_parse_errors),
  SD_TEST_ENTRY(cli_parse_other_commands),
  SD_TEST_ENTRY(smoke_version_help_usage),
  SD_TEST_ENTRY(smoke_mount_prompts_and_errors),
};

int main(int argc, char **argv)
{
  return sd_test_main(k_tests, SD_COUNTOF(k_tests), argc, argv);
}
