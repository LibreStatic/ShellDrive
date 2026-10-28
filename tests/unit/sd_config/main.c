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
SD_TEST_DECL(profile_m2_keys_round_trip);
SD_TEST_DECL(proxy_spec_and_jump_parse);
SD_TEST_DECL(chain_resolution);
SD_TEST_DECL(legacy_set_hash);
SD_TEST_DECL(import_putty_reg_export);
SD_TEST_DECL(import_putty_test_registry_key);
SD_TEST_DECL(import_ssh_config);
SD_TEST_DECL(import_duplicates_and_write);
SD_TEST_DECL(profile_m3_defaults);
SD_TEST_DECL(profile_m3_umask_octal);
SD_TEST_DECL(profile_m3_key_values_and_bounds);
SD_TEST_DECL(profile_m3_values_and_derived_shell_active);
SD_TEST_DECL(profile_m3_legacy_cache_names);
SD_TEST_DECL(profile_m3_round_trip);
SD_TEST_DECL(menu_entry_sanitizing);
SD_TEST_DECL(menu_format_layout);
SD_TEST_DECL(menu_format_caps);
SD_TEST_DECL(menu_writer_through_profile_store);

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
  SD_TEST_ENTRY(profile_m2_keys_round_trip),
  SD_TEST_ENTRY(proxy_spec_and_jump_parse),
  SD_TEST_ENTRY(chain_resolution),
  SD_TEST_ENTRY(legacy_set_hash),
  SD_TEST_ENTRY(import_putty_reg_export),
  SD_TEST_ENTRY(import_putty_test_registry_key),
  SD_TEST_ENTRY(import_ssh_config),
  SD_TEST_ENTRY(import_duplicates_and_write),
  SD_TEST_ENTRY(profile_m3_defaults),
  SD_TEST_ENTRY(profile_m3_umask_octal),
  SD_TEST_ENTRY(profile_m3_key_values_and_bounds),
  SD_TEST_ENTRY(profile_m3_values_and_derived_shell_active),
  SD_TEST_ENTRY(profile_m3_legacy_cache_names),
  SD_TEST_ENTRY(profile_m3_round_trip),
  SD_TEST_ENTRY(menu_entry_sanitizing),
  SD_TEST_ENTRY(menu_format_layout),
  SD_TEST_ENTRY(menu_format_caps),
  SD_TEST_ENTRY(menu_writer_through_profile_store),
};

int main(int argc, char **argv)
{
  return sd_test_main(k_tests, SD_COUNTOF(k_tests), argc, argv);
}
