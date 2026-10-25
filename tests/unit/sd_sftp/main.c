/* sd-test-sftp: codec fixtures, scripted-session and M1 reconnect/channel tests (run everywhere). */
#include "sd_platform/sd_log.h"
#include "sd_test.h"

SD_TEST_DECL(proto_status_mapping);
SD_TEST_DECL(proto_attrs_decode_canned);
SD_TEST_DECL(proto_attrs_reject_malformed);
SD_TEST_DECL(proto_attrs_encode);
SD_TEST_DECL(proto_version_parse);
SD_TEST_DECL(proto_limits_effective);
SD_TEST_DECL(proto_limits_and_statvfs_parse);
SD_TEST_DECL(proto_dirent_filter);
SD_TEST_DECL(proto_packet_framing);
SD_TEST_DECL(proto_win_drive_path);
SD_TEST_DECL(session_handshake_canned);
SD_TEST_DECL(session_handshake_minimal_server);
SD_TEST_DECL(session_pipelining_window_requests);
SD_TEST_DECL(session_pipelining_window_configurable);
SD_TEST_DECL(session_pipelining_window_bytes);
SD_TEST_DECL(session_short_read_reissue_and_eof);
SD_TEST_DECL(session_write_chunking);
SD_TEST_DECL(session_deadline_expiry);
SD_TEST_DECL(session_cancel);
SD_TEST_DECL(session_busy_backpressure);
SD_TEST_DECL(session_refine_errors);
SD_TEST_DECL(session_readdir_filters_entries);
SD_TEST_DECL(session_symlink_argument_order);
SD_TEST_DECL(session_protocol_error_fails_session);
SD_TEST_DECL(session_hangup_marks_handles_stale);
SD_TEST_DECL(session_close_completes_pending_with_shutdown);
SD_TEST_DECL(session_wait_ready_queues_before_start);
SD_TEST_DECL(reconnect_after_idle_drop);
SD_TEST_DECL(reconnect_drop_during_pipelined_reads);
SD_TEST_DECL(reconnect_drop_during_pipelined_writes);
SD_TEST_DECL(reconnect_drop_during_open_and_readdir);
SD_TEST_DECL(reconnect_mutating_ops_maybe_executed);
SD_TEST_DECL(reconnect_wait_ready_survives_outage);
SD_TEST_DECL(channels_meta_and_bulk_classes);
SD_TEST_DECL(channels_degrade_to_one);
SD_TEST_DECL(channels_one_by_option_or_transport);
SD_TEST_DECL(reconnect_backoff_jitter_and_retries);
SD_TEST_DECL(reconnect_permanent_failure_and_reconnect_now);
SD_TEST_DECL(reconnect_auth_required_and_max_attempts);
SD_TEST_DECL(reconnect_stop_and_disabled);
SD_TEST_DECL(reconnect_ready_info_reread_and_reopen_gone);
SD_TEST_DECL(reconnect_close_during_backoff);

static const sd_test_case k_tests[] = {
  SD_TEST_ENTRY(proto_status_mapping),
  SD_TEST_ENTRY(proto_attrs_decode_canned),
  SD_TEST_ENTRY(proto_attrs_reject_malformed),
  SD_TEST_ENTRY(proto_attrs_encode),
  SD_TEST_ENTRY(proto_version_parse),
  SD_TEST_ENTRY(proto_limits_effective),
  SD_TEST_ENTRY(proto_limits_and_statvfs_parse),
  SD_TEST_ENTRY(proto_dirent_filter),
  SD_TEST_ENTRY(proto_packet_framing),
  SD_TEST_ENTRY(proto_win_drive_path),
  SD_TEST_ENTRY(session_handshake_canned),
  SD_TEST_ENTRY(session_handshake_minimal_server),
  SD_TEST_ENTRY(session_pipelining_window_requests),
  SD_TEST_ENTRY(session_pipelining_window_configurable),
  SD_TEST_ENTRY(session_pipelining_window_bytes),
  SD_TEST_ENTRY(session_short_read_reissue_and_eof),
  SD_TEST_ENTRY(session_write_chunking),
  SD_TEST_ENTRY(session_deadline_expiry),
  SD_TEST_ENTRY(session_cancel),
  SD_TEST_ENTRY(session_busy_backpressure),
  SD_TEST_ENTRY(session_refine_errors),
  SD_TEST_ENTRY(session_readdir_filters_entries),
  SD_TEST_ENTRY(session_symlink_argument_order),
  SD_TEST_ENTRY(session_protocol_error_fails_session),
  SD_TEST_ENTRY(session_hangup_marks_handles_stale),
  SD_TEST_ENTRY(session_close_completes_pending_with_shutdown),
  SD_TEST_ENTRY(session_wait_ready_queues_before_start),
  SD_TEST_ENTRY(reconnect_after_idle_drop),
  SD_TEST_ENTRY(reconnect_drop_during_pipelined_reads),
  SD_TEST_ENTRY(reconnect_drop_during_pipelined_writes),
  SD_TEST_ENTRY(reconnect_drop_during_open_and_readdir),
  SD_TEST_ENTRY(reconnect_mutating_ops_maybe_executed),
  SD_TEST_ENTRY(reconnect_wait_ready_survives_outage),
  SD_TEST_ENTRY(channels_meta_and_bulk_classes),
  SD_TEST_ENTRY(channels_degrade_to_one),
  SD_TEST_ENTRY(channels_one_by_option_or_transport),
  SD_TEST_ENTRY(reconnect_backoff_jitter_and_retries),
  SD_TEST_ENTRY(reconnect_permanent_failure_and_reconnect_now),
  SD_TEST_ENTRY(reconnect_auth_required_and_max_attempts),
  SD_TEST_ENTRY(reconnect_stop_and_disabled),
  SD_TEST_ENTRY(reconnect_ready_info_reread_and_reopen_gone),
  SD_TEST_ENTRY(reconnect_close_during_backoff),
};

int main(int argc, char **argv)
{
  sd_log_set_level(SD_LOG_ERROR);
  return sd_test_main(k_tests, SD_COUNTOF(k_tests), argc, argv);
}
