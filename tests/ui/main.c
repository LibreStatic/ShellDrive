/* UI unit tests (tests/ui): harness entry point. The cases are in test_wire.c, test_dpi.c, test_dlg.c,
   test_prompt.c and test_profile.c. The prompt dialogs themselves are checked by the smoke test (shelldrive-ui --test-prompts). */
#include "sd_test.h"

SD_TEST_DECL(dlg_empty_template_parses);
SD_TEST_DECL(dlg_items_aligned_and_counted);
SD_TEST_DECL(dlg_controls_have_expected_classes_and_ids);
SD_TEST_DECL(dlg_title_and_font_are_encoded);
SD_TEST_DECL(dlg_layout_stays_inside_the_dialog);
SD_TEST_DECL(dlg_button_row_is_right_aligned);
SD_TEST_DECL(dlg_buttons_wrap_when_they_do_not_fit);
SD_TEST_DECL(dlg_multiline_height_is_capped);
SD_TEST_DECL(dlg_rejects_too_many_items_and_bad_input);
SD_TEST_DECL(dlg_parse_rejects_truncated_blob);
SD_TEST_DECL(prompt_kind_names);
SD_TEST_DECL(prompt_parse_hostkey_new_identity);
SD_TEST_DECL(prompt_parse_hostkey_changed_variant);
SD_TEST_DECL(prompt_parse_password_and_passphrase);
SD_TEST_DECL(prompt_parse_kbdint_items_and_echo);
SD_TEST_DECL(prompt_parse_password_change_three_fields);
SD_TEST_DECL(prompt_parse_legacy_and_proxy);
SD_TEST_DECL(prompt_parse_rejects_bad_requests);
SD_TEST_DECL(prompt_server_text_is_sanitized);
SD_TEST_DECL(prompt_server_text_is_capped);
SD_TEST_DECL(prompt_parse_sanitizes_names_and_text);
SD_TEST_DECL(prompt_fixtures_have_their_fields);
SD_TEST_DECL(answer_accept_has_no_responses);
SD_TEST_DECL(answer_responses_are_escaped_and_utf8);
SD_TEST_DECL(answer_wipes_the_secrets_it_was_given);
SD_TEST_DECL(answer_wipes_inputs_even_on_error);
SD_TEST_DECL(answer_rejects_bad_arguments);

SD_TEST_DECL(wire_roundtrip_and_empty);
SD_TEST_DECL(wire_rejects_bad_header);
SD_TEST_DECL(wire_rejects_truncated_and_trailing);
SD_TEST_DECL(wire_rejects_bad_units);
SD_TEST_DECL(wire_rejects_too_many_or_too_long);
SD_TEST_DECL(verbs_show_tray_prompt);
SD_TEST_DECL(verbs_unmount_drive);
SD_TEST_DECL(verbs_mount_profile_id);
SD_TEST_DECL(verbs_reconnect_and_mount_file);
SD_TEST_DECL(verbs_open_drive);
SD_TEST_DECL(verbs_unknown_are_rejected);

SD_TEST_DECL(sdmount_accepts_one_profile_line);
SD_TEST_DECL(sdmount_rejects_anything_else);
SD_TEST_DECL(sdmount_size_limit);
SD_TEST_DECL(profile_form_round_trip);
SD_TEST_DECL(profile_form_set_rejects_bad_text);
SD_TEST_DECL(profile_form_validation_fields);
SD_TEST_DECL(free_drive_letters);
SD_TEST_DECL(json_escape_and_mount_params);
SD_TEST_DECL(dpi_scale_rounding_and_clamp);
SD_TEST_DECL(dpi_font_height);

/* test_logs.c, test_hostkeys.c and test_settings.c: the M3 models and their file paths. */
SD_TEST_DECL(logs_cursor_appends_records_in_order);
SD_TEST_DECL(logs_reset_clears_or_keeps_by_dropped_count);
SD_TEST_DECL(logs_malformed_reply_changes_nothing);
SD_TEST_DECL(logs_keeps_the_newest_records_only);
SD_TEST_DECL(logs_filters_by_level_and_search);
SD_TEST_DECL(logs_level_names);
SD_TEST_DECL(hk_row_plain_and_bracketed_hosts);
SD_TEST_DECL(hk_row_lists_wildcards_and_hashed_entries);
SD_TEST_DECL(hk_row_cells_and_source_labels);
SD_TEST_DECL(hk_announcement_cells);
SD_TEST_DECL(hk_store_enumeration_and_remove);
SD_TEST_DECL(settings_model_defaults_and_mapping);
SD_TEST_DECL(settings_model_round_trip_keeps_other_fields);
SD_TEST_DECL(settings_save_load_round_trip_in_a_temp_root);
SD_TEST_DECL(settings_cache_budget_parsing);
SD_TEST_DECL(settings_language_index_and_run_command);

/* test_notify.c, test_dark.c and test_wizard.c: the balloon rate limit, the dark mode decision and the wizard's
   should-show logic. */
SD_TEST_DECL(notify_limit_one_per_subject_and_kind);
SD_TEST_DECL(notify_limit_is_per_subject_and_kind);
SD_TEST_DECL(notify_clock_going_back_is_not_a_burst);
SD_TEST_DECL(notify_table_is_bounded_and_keeps_recent_pairs);
SD_TEST_DECL(notify_interval_is_one_minute);
SD_TEST_DECL(dark_needs_build_22000_and_the_api);
SD_TEST_DECL(dark_follows_the_app_theme_value);
SD_TEST_DECL(dark_stays_light_on_older_systems);
SD_TEST_DECL(wizard_opens_for_an_empty_store_only_once);
SD_TEST_DECL(wizard_never_opens_for_tray_or_prompt_host);

static const sd_test_case k_tests[] = {
  SD_TEST_ENTRY(dlg_empty_template_parses),
  SD_TEST_ENTRY(dlg_items_aligned_and_counted),
  SD_TEST_ENTRY(dlg_controls_have_expected_classes_and_ids),
  SD_TEST_ENTRY(dlg_title_and_font_are_encoded),
  SD_TEST_ENTRY(dlg_layout_stays_inside_the_dialog),
  SD_TEST_ENTRY(dlg_button_row_is_right_aligned),
  SD_TEST_ENTRY(dlg_buttons_wrap_when_they_do_not_fit),
  SD_TEST_ENTRY(dlg_multiline_height_is_capped),
  SD_TEST_ENTRY(dlg_rejects_too_many_items_and_bad_input),
  SD_TEST_ENTRY(dlg_parse_rejects_truncated_blob),
  SD_TEST_ENTRY(prompt_kind_names),
  SD_TEST_ENTRY(prompt_parse_hostkey_new_identity),
  SD_TEST_ENTRY(prompt_parse_hostkey_changed_variant),
  SD_TEST_ENTRY(prompt_parse_password_and_passphrase),
  SD_TEST_ENTRY(prompt_parse_kbdint_items_and_echo),
  SD_TEST_ENTRY(prompt_parse_password_change_three_fields),
  SD_TEST_ENTRY(prompt_parse_legacy_and_proxy),
  SD_TEST_ENTRY(prompt_parse_rejects_bad_requests),
  SD_TEST_ENTRY(prompt_server_text_is_sanitized),
  SD_TEST_ENTRY(prompt_server_text_is_capped),
  SD_TEST_ENTRY(prompt_parse_sanitizes_names_and_text),
  SD_TEST_ENTRY(prompt_fixtures_have_their_fields),
  SD_TEST_ENTRY(answer_accept_has_no_responses),
  SD_TEST_ENTRY(answer_responses_are_escaped_and_utf8),
  SD_TEST_ENTRY(answer_wipes_the_secrets_it_was_given),
  SD_TEST_ENTRY(answer_wipes_inputs_even_on_error),
  SD_TEST_ENTRY(answer_rejects_bad_arguments),
  SD_TEST_ENTRY(wire_roundtrip_and_empty),
  SD_TEST_ENTRY(wire_rejects_bad_header),
  SD_TEST_ENTRY(wire_rejects_truncated_and_trailing),
  SD_TEST_ENTRY(wire_rejects_bad_units),
  SD_TEST_ENTRY(wire_rejects_too_many_or_too_long),
  SD_TEST_ENTRY(verbs_show_tray_prompt),
  SD_TEST_ENTRY(verbs_unmount_drive),
  SD_TEST_ENTRY(verbs_mount_profile_id),
  SD_TEST_ENTRY(verbs_reconnect_and_mount_file),
  SD_TEST_ENTRY(verbs_open_drive),
  SD_TEST_ENTRY(verbs_unknown_are_rejected),
  SD_TEST_ENTRY(sdmount_accepts_one_profile_line),
  SD_TEST_ENTRY(sdmount_rejects_anything_else),
  SD_TEST_ENTRY(sdmount_size_limit),
  SD_TEST_ENTRY(profile_form_round_trip),
  SD_TEST_ENTRY(profile_form_set_rejects_bad_text),
  SD_TEST_ENTRY(profile_form_validation_fields),
  SD_TEST_ENTRY(free_drive_letters),
  SD_TEST_ENTRY(json_escape_and_mount_params),
  SD_TEST_ENTRY(dpi_scale_rounding_and_clamp),
  SD_TEST_ENTRY(dpi_font_height),
  SD_TEST_ENTRY(logs_cursor_appends_records_in_order),
  SD_TEST_ENTRY(logs_reset_clears_or_keeps_by_dropped_count),
  SD_TEST_ENTRY(logs_malformed_reply_changes_nothing),
  SD_TEST_ENTRY(logs_keeps_the_newest_records_only),
  SD_TEST_ENTRY(logs_filters_by_level_and_search),
  SD_TEST_ENTRY(logs_level_names),
  SD_TEST_ENTRY(hk_row_plain_and_bracketed_hosts),
  SD_TEST_ENTRY(hk_row_lists_wildcards_and_hashed_entries),
  SD_TEST_ENTRY(hk_row_cells_and_source_labels),
  SD_TEST_ENTRY(hk_announcement_cells),
  SD_TEST_ENTRY(hk_store_enumeration_and_remove),
  SD_TEST_ENTRY(settings_model_defaults_and_mapping),
  SD_TEST_ENTRY(settings_model_round_trip_keeps_other_fields),
  SD_TEST_ENTRY(settings_save_load_round_trip_in_a_temp_root),
  SD_TEST_ENTRY(settings_cache_budget_parsing),
  SD_TEST_ENTRY(settings_language_index_and_run_command),
  SD_TEST_ENTRY(notify_limit_one_per_subject_and_kind),
  SD_TEST_ENTRY(notify_limit_is_per_subject_and_kind),
  SD_TEST_ENTRY(notify_clock_going_back_is_not_a_burst),
  SD_TEST_ENTRY(notify_table_is_bounded_and_keeps_recent_pairs),
  SD_TEST_ENTRY(notify_interval_is_one_minute),
  SD_TEST_ENTRY(dark_needs_build_22000_and_the_api),
  SD_TEST_ENTRY(dark_follows_the_app_theme_value),
  SD_TEST_ENTRY(dark_stays_light_on_older_systems),
  SD_TEST_ENTRY(wizard_opens_for_an_empty_store_only_once),
  SD_TEST_ENTRY(wizard_never_opens_for_tray_or_prompt_host),
};

int main(int argc, char **argv)
{
  return sd_test_main(k_tests, SD_COUNTOF(k_tests), argc, argv);
}
