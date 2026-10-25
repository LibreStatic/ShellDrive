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
};

int main(int argc, char **argv)
{
  return sd_test_main(k_tests, SD_COUNTOF(k_tests), argc, argv);
}
