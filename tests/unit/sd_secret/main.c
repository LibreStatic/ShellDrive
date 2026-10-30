#include "sd_test.h"

SD_TEST_DECL(secret_target_names);
SD_TEST_DECL(secret_credman_round_trip);
SD_TEST_DECL(secret_dpapi_round_trip);
SD_TEST_DECL(secret_dpapi_file_layout);
SD_TEST_DECL(secret_key_files);

static const sd_test_case k_tests[] = {
  SD_TEST_ENTRY(secret_target_names),
  SD_TEST_ENTRY(secret_credman_round_trip),
  SD_TEST_ENTRY(secret_dpapi_round_trip),
  SD_TEST_ENTRY(secret_dpapi_file_layout),
  SD_TEST_ENTRY(secret_key_files),
};

int main(int argc, char **argv)
{
  return sd_test_main(k_tests, SD_COUNTOF(k_tests), argc, argv);
}
