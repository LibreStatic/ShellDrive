/* Test driver of tests/e2e: the service core runs in this process (e2e_host.c), the CLI runs as a child process. */
#include "sd_test.h"

SD_TEST_DECL(e2e_status_reaches_the_service_over_the_pipe);
SD_TEST_DECL(e2e_status_without_an_installed_service_does_not_query_the_pipe);
SD_TEST_DECL(e2e_service_mount_and_unmount_need_elevation);
SD_TEST_DECL(e2e_hostkey_offer_is_listed_and_accepted_into_the_machine_store);
SD_TEST_DECL(e2e_secret_set_and_delete_machine_proxy_through_the_service);
SD_TEST_DECL(e2e_core_stops_and_the_cli_no_longer_reaches_the_pipe);

static const sd_test_case k_tests[] = {
  SD_TEST_ENTRY(e2e_status_reaches_the_service_over_the_pipe),
  SD_TEST_ENTRY(e2e_status_without_an_installed_service_does_not_query_the_pipe),
  SD_TEST_ENTRY(e2e_service_mount_and_unmount_need_elevation),
  SD_TEST_ENTRY(e2e_hostkey_offer_is_listed_and_accepted_into_the_machine_store),
  SD_TEST_ENTRY(e2e_secret_set_and_delete_machine_proxy_through_the_service),
  SD_TEST_ENTRY(e2e_core_stops_and_the_cli_no_longer_reaches_the_pipe),
};

int main(int argc, char **argv)
{
  return sd_test_main(k_tests, SD_COUNTOF(k_tests), argc, argv);
}
