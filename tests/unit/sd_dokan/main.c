#include "sd_test.h"

SD_TEST_DECL(dokan_abi_layout_x64);
SD_TEST_DECL(dokan_ntstatus_table);
SD_TEST_DECL(dokan_probe_and_deny_list);
SD_TEST_DECL(dokan_cache_hit_expiry_and_keys);
SD_TEST_DECL(dokan_cache_different_token_object_misses);
SD_TEST_DECL(dokan_cache_changed_modified_id_misses);
SD_TEST_DECL(dokan_cache_wraps_and_refreshes);
SD_TEST_DECL(dokan_cache_failures_are_not_stored);
SD_TEST_DECL(dokan_cache_is_bounded_and_evicts_oldest);

static const sd_test_case k_tests[] = {
  SD_TEST_ENTRY(dokan_abi_layout_x64),
  SD_TEST_ENTRY(dokan_ntstatus_table),
  SD_TEST_ENTRY(dokan_probe_and_deny_list),
  SD_TEST_ENTRY(dokan_cache_hit_expiry_and_keys),
  SD_TEST_ENTRY(dokan_cache_different_token_object_misses),
  SD_TEST_ENTRY(dokan_cache_changed_modified_id_misses),
  SD_TEST_ENTRY(dokan_cache_wraps_and_refreshes),
  SD_TEST_ENTRY(dokan_cache_failures_are_not_stored),
  SD_TEST_ENTRY(dokan_cache_is_bounded_and_evicts_oldest),
};

int main(int argc, char **argv)
{
  return sd_test_main(k_tests, SD_COUNTOF(k_tests), argc, argv);
}
