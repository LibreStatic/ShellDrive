#include "sd_test.h"

SD_TEST_DECL(policy_table_is_complete);
SD_TEST_DECL(policy_kinds_match_readers);
SD_TEST_DECL(policy_type_mismatch_reads_absent);

static const sd_test_case k_tests[] = {
  SD_TEST_ENTRY(policy_table_is_complete),
  SD_TEST_ENTRY(policy_kinds_match_readers),
  SD_TEST_ENTRY(policy_type_mismatch_reads_absent),
};

int main(int argc, char **argv)
{
  return sd_test_main(k_tests, SD_COUNTOF(k_tests), argc, argv);
}
