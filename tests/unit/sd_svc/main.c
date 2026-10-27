#include "sd_test.h"

SD_TEST_DECL(decide_table);
SD_TEST_DECL(acl_resolves_names_and_fails_closed);
SD_TEST_DECL(validate_profile_refusals);
SD_TEST_DECL(volume_sddl_is_valid_and_lists_every_entry);
SD_TEST_DECL(identity_path_must_stay_under_the_service_folder);
SD_TEST_DECL(svc_core_starts_and_answers_hello_and_selftest);
SD_TEST_DECL(svc_loads_only_valid_service_profiles);
SD_TEST_DECL(svc_non_admin_token_cannot_call_admin_methods);
SD_TEST_DECL(svc_admin_mounts_reports_and_unmounts);
SD_TEST_DECL(svc_mount_without_prompt_ui_fails_with_prompt_unavailable);
SD_TEST_DECL(svc_host_key_prompt_is_refused_even_with_an_admin_ui);
SD_TEST_DECL(svc_admin_answers_a_password_prompt_on_the_pipe);
SD_TEST_DECL(svc_secret_round_trip_is_dpapi_service_scope);
SD_TEST_DECL(svc_list_hides_mounts_outside_service_access_from_users);
SD_TEST_DECL(svc_core_stops_and_leaves_nothing_behind);

static const sd_test_case k_tests[] = {
  SD_TEST_ENTRY(decide_table),
  SD_TEST_ENTRY(acl_resolves_names_and_fails_closed),
  SD_TEST_ENTRY(validate_profile_refusals),
  SD_TEST_ENTRY(volume_sddl_is_valid_and_lists_every_entry),
  SD_TEST_ENTRY(identity_path_must_stay_under_the_service_folder),
  SD_TEST_ENTRY(svc_core_starts_and_answers_hello_and_selftest),
  SD_TEST_ENTRY(svc_loads_only_valid_service_profiles),
  SD_TEST_ENTRY(svc_non_admin_token_cannot_call_admin_methods),
  SD_TEST_ENTRY(svc_admin_mounts_reports_and_unmounts),
  SD_TEST_ENTRY(svc_mount_without_prompt_ui_fails_with_prompt_unavailable),
  SD_TEST_ENTRY(svc_host_key_prompt_is_refused_even_with_an_admin_ui),
  SD_TEST_ENTRY(svc_admin_answers_a_password_prompt_on_the_pipe),
  SD_TEST_ENTRY(svc_secret_round_trip_is_dpapi_service_scope),
  SD_TEST_ENTRY(svc_list_hides_mounts_outside_service_access_from_users),
  SD_TEST_ENTRY(svc_core_stops_and_leaves_nothing_behind),
};

int main(int argc, char **argv)
{
  return sd_test_main(k_tests, SD_COUNTOF(k_tests), argc, argv);
}
