#include "sd_test.h"

SD_TEST_DECL(dokan_abi_layout_x64);
SD_TEST_DECL(dokan_ntstatus_table);
SD_TEST_DECL(dokan_probe_and_deny_list);

static const sd_test_case k_tests[] = {
  SD_TEST_ENTRY(dokan_abi_layout_x64),
  SD_TEST_ENTRY(dokan_ntstatus_table),
  SD_TEST_ENTRY(dokan_probe_and_deny_list),
};

int main(int argc, char **argv)
{
  return sd_test_main(k_tests, SD_COUNTOF(k_tests), argc, argv);
}
