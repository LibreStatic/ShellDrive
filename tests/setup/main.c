/* sd-test-setup: tests of the setup engine (docs/design/04 §6). See the test files for what each covers. */
#include <windows.h>

#include "sd_test.h"

SD_TEST_DECL(setup_flavour_table);
SD_TEST_DECL(setup_flavour_names);
SD_TEST_DECL(setup_detect_host_runs);
SD_TEST_DECL(setup_args_valid);
SD_TEST_DECL(setup_args_rejected);
SD_TEST_DECL(setup_version_order);
SD_TEST_DECL(setup_dokany_plan);
SD_TEST_DECL(setup_cab_names);
SD_TEST_DECL(setup_payload_table);
SD_TEST_DECL(setup_sha256_vectors);
SD_TEST_DECL(setup_messages_format);
SD_TEST_DECL(setup_messages_other_locale);
SD_TEST_DECL(setup_cab_extract_good);
SD_TEST_DECL(setup_cab_traversal_refused);
SD_TEST_DECL(setup_cab_size_limits);
SD_TEST_DECL(setup_cab_damaged_payload);
SD_TEST_DECL(setup_user_install_repair_uninstall);
SD_TEST_DECL(setup_user_newer_version_refused);
SD_TEST_DECL(setup_user_damaged_payload_refused);
SD_TEST_DECL(setup_user_traversal_refused);
SD_TEST_DECL(setup_portable_roundtrip);
SD_TEST_DECL(setup_machine_mode_not_in_this_build);
SD_TEST_DECL(setup_shortcut_and_log_files);
SD_TEST_DECL(setup_current_sid_format);
SD_TEST_DECL(setup_flow_first_page);
SD_TEST_DECL(setup_flow_interactive_pages);
SD_TEST_DECL(setup_flow_terminates_for_every_input);
SD_TEST_DECL(setup_flow_dokany_view_states);
SD_TEST_DECL(setup_flow_dokany_plan_by_mode);
SD_TEST_DECL(setup_flow_names_and_titles);
SD_TEST_DECL(setup_programdata_trust);
SD_TEST_DECL(setup_stage_dir_fresh_names);
SD_TEST_DECL(setup_dokany_pe_vcr_state);
SD_TEST_DECL(setup_dokany_pe_malformed_fails_closed);
SD_TEST_DECL(setup_dokany_choose_chain);
SD_TEST_DECL(setup_dokany_command_lines);
SD_TEST_DECL(setup_dokany_run_gate);

static const sd_test_case k_tests[] = {
  SD_TEST_ENTRY(setup_flavour_table),
  SD_TEST_ENTRY(setup_flavour_names),
  SD_TEST_ENTRY(setup_detect_host_runs),
  SD_TEST_ENTRY(setup_args_valid),
  SD_TEST_ENTRY(setup_args_rejected),
  SD_TEST_ENTRY(setup_version_order),
  SD_TEST_ENTRY(setup_dokany_plan),
  SD_TEST_ENTRY(setup_cab_names),
  SD_TEST_ENTRY(setup_payload_table),
  SD_TEST_ENTRY(setup_sha256_vectors),
  SD_TEST_ENTRY(setup_messages_format),
  SD_TEST_ENTRY(setup_messages_other_locale),
  SD_TEST_ENTRY(setup_cab_extract_good),
  SD_TEST_ENTRY(setup_cab_traversal_refused),
  SD_TEST_ENTRY(setup_cab_size_limits),
  SD_TEST_ENTRY(setup_cab_damaged_payload),
  SD_TEST_ENTRY(setup_user_install_repair_uninstall),
  SD_TEST_ENTRY(setup_user_newer_version_refused),
  SD_TEST_ENTRY(setup_user_damaged_payload_refused),
  SD_TEST_ENTRY(setup_user_traversal_refused),
  SD_TEST_ENTRY(setup_portable_roundtrip),
  SD_TEST_ENTRY(setup_machine_mode_not_in_this_build),
  SD_TEST_ENTRY(setup_shortcut_and_log_files),
  SD_TEST_ENTRY(setup_current_sid_format),
  SD_TEST_ENTRY(setup_flow_first_page),
  SD_TEST_ENTRY(setup_flow_interactive_pages),
  SD_TEST_ENTRY(setup_flow_terminates_for_every_input),
  SD_TEST_ENTRY(setup_flow_dokany_view_states),
  SD_TEST_ENTRY(setup_flow_dokany_plan_by_mode),
  SD_TEST_ENTRY(setup_flow_names_and_titles),
  SD_TEST_ENTRY(setup_programdata_trust),
  SD_TEST_ENTRY(setup_stage_dir_fresh_names),
  SD_TEST_ENTRY(setup_dokany_pe_vcr_state),
  SD_TEST_ENTRY(setup_dokany_pe_malformed_fails_closed),
  SD_TEST_ENTRY(setup_dokany_choose_chain),
  SD_TEST_ENTRY(setup_dokany_command_lines),
  SD_TEST_ENTRY(setup_dokany_run_gate),
};

int main(int argc, char **argv)
{
  return sd_test_main(k_tests, SD_COUNTOF(k_tests), argc, argv);
}
