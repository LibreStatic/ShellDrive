#include "sd_test.h"

SD_TEST_DECL(json_parses_values);
SD_TEST_DECL(json_unicode_escapes);
SD_TEST_DECL(json_rejects_malformed);
SD_TEST_DECL(json_depth_limit);
SD_TEST_DECL(json_integer_bounds);
SD_TEST_DECL(json_writer_roundtrip);
SD_TEST_DECL(json_writer_misuse);
SD_TEST_DECL(json_alloc_failure);
SD_TEST_DECL(ipc_exit_codes_cover_every_err);
SD_TEST_DECL(ipc_names_follow_d45);
SD_TEST_DECL(ipc_named_objects_owner_checked);
SD_TEST_DECL(ipc_roundtrip_call_error_event);
SD_TEST_DECL(ipc_deferred_reply_roundtrip);
SD_TEST_DECL(ipc_large_messages_and_cap);
SD_TEST_DECL(ipc_server_closes_bad_clients);
SD_TEST_DECL(ipc_instance_quota_and_rate_limit);
SD_TEST_DECL(ipc_first_instance_detects_squatting);
SD_TEST_DECL(ipc_client_rejects_foreign_owner);
SD_TEST_DECL(ipc_client_rejects_squatted_pipe);
SD_TEST_DECL(ipc_connect_without_server);
SD_TEST_DECL(ipc_instance_turnover_under_load);
SD_TEST_DECL(m3_topic_validation);
SD_TEST_DECL(m3_subscribe_drops_invalid_topics_and_features_in_hello);
SD_TEST_DECL(m3_broadcast_counts_recipients);
SD_TEST_DECL(m3_state_section_create_open);
SD_TEST_DECL(m3_owner_label_fails_closed);

static const sd_test_case k_tests[] = {
  SD_TEST_ENTRY(json_parses_values),
  SD_TEST_ENTRY(json_unicode_escapes),
  SD_TEST_ENTRY(json_rejects_malformed),
  SD_TEST_ENTRY(json_depth_limit),
  SD_TEST_ENTRY(json_integer_bounds),
  SD_TEST_ENTRY(json_writer_roundtrip),
  SD_TEST_ENTRY(json_writer_misuse),
  SD_TEST_ENTRY(json_alloc_failure),
  SD_TEST_ENTRY(ipc_exit_codes_cover_every_err),
  SD_TEST_ENTRY(ipc_names_follow_d45),
  SD_TEST_ENTRY(ipc_named_objects_owner_checked),
  SD_TEST_ENTRY(ipc_roundtrip_call_error_event),
  SD_TEST_ENTRY(ipc_deferred_reply_roundtrip),
  SD_TEST_ENTRY(ipc_large_messages_and_cap),
  SD_TEST_ENTRY(ipc_server_closes_bad_clients),
  SD_TEST_ENTRY(ipc_instance_quota_and_rate_limit),
  SD_TEST_ENTRY(ipc_first_instance_detects_squatting),
  SD_TEST_ENTRY(ipc_client_rejects_foreign_owner),
  SD_TEST_ENTRY(ipc_client_rejects_squatted_pipe),
  SD_TEST_ENTRY(ipc_connect_without_server),
  SD_TEST_ENTRY(ipc_instance_turnover_under_load),
  SD_TEST_ENTRY(m3_topic_validation),
  SD_TEST_ENTRY(m3_subscribe_drops_invalid_topics_and_features_in_hello),
  SD_TEST_ENTRY(m3_broadcast_counts_recipients),
  SD_TEST_ENTRY(m3_state_section_create_open),
  SD_TEST_ENTRY(m3_owner_label_fails_closed),
};

int main(int argc, char **argv)
{
  return sd_test_main(k_tests, SD_COUNTOF(k_tests), argc, argv);
}
