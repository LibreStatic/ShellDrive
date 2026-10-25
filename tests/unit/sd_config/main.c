#include "sd_test.h"

SD_TEST_DECL(ini_parses_grammar);
SD_TEST_DECL(ini_round_trip_preserves_everything);
SD_TEST_DECL(ini_duplicates_ansi_and_limits);
SD_TEST_DECL(ini_value_helpers);
SD_TEST_DECL(profile_from_and_to_ini);
SD_TEST_DECL(profile_defaults_and_validation);
SD_TEST_DECL(host_spec_and_letters);
SD_TEST_DECL(profile_files_save_find_enum_delete);
SD_TEST_DECL(config_paths_and_expansion);
SD_TEST_DECL(profile_m1_keys);
SD_TEST_DECL(cache_dir_and_identity_cache);
SD_TEST_DECL(settings_log_level_and_cache_memory);

static const sd_test_case k_tests[] = {
  SD_TEST_ENTRY(ini_parses_grammar),
  SD_TEST_ENTRY(ini_round_trip_preserves_everything),
  SD_TEST_ENTRY(ini_duplicates_ansi_and_limits),
  SD_TEST_ENTRY(ini_value_helpers),
  SD_TEST_ENTRY(profile_from_and_to_ini),
  SD_TEST_ENTRY(profile_defaults_and_validation),
  SD_TEST_ENTRY(host_spec_and_letters),
  SD_TEST_ENTRY(profile_files_save_find_enum_delete),
  SD_TEST_ENTRY(config_paths_and_expansion),
  SD_TEST_ENTRY(profile_m1_keys),
  SD_TEST_ENTRY(cache_dir_and_identity_cache),
  SD_TEST_ENTRY(settings_log_level_and_cache_memory),
};

int main(int argc, char **argv)
{
  return sd_test_main(k_tests, SD_COUNTOF(k_tests), argc, argv);
}
