#include "sd_test.h"

SD_TEST_DECL(webdav_http_parses_request);
SD_TEST_DECL(webdav_http_incremental_and_framing);
SD_TEST_DECL(webdav_http_rejects);
SD_TEST_DECL(webdav_chunked_decoding);
SD_TEST_DECL(webdav_path_decoding_rules);
SD_TEST_DECL(webdav_href_and_token);
SD_TEST_DECL(webdav_host_header_dns_rebinding);
SD_TEST_DECL(webdav_destination_parsing);
SD_TEST_DECL(webdav_xml_parser);
SD_TEST_DECL(webdav_xml_rejects);
SD_TEST_DECL(webdav_values);
SD_TEST_DECL(webdav_server_gate_before_auth);
SD_TEST_DECL(webdav_server_auth_and_methods);
SD_TEST_DECL(webdav_server_rejects_other_sid);
SD_TEST_DECL(webdav_service_server_admits_a_member);
SD_TEST_DECL(webdav_service_server_refuses_a_non_member);
SD_TEST_DECL(webdav_server_read_only_export);
SD_TEST_DECL(webdav_server_slowloris_and_quotas);
SD_TEST_DECL(webdav_token_only_decision_matrix);
SD_TEST_DECL(webdav_token_selftest_verdict);
SD_TEST_DECL(webdav_token_only_gate_per_mode);
SD_TEST_DECL(webdav_token_only_selftest);
SD_TEST_DECL(webdav_token_only_mount_refused);
SD_TEST_DECL(webdav_server_ipv6_loopback);
SD_TEST_DECL(webdav_server_office_save_sequence);
SD_TEST_DECL(webdav_server_replacing_move_drops_replaced_children_locks);
SD_TEST_DECL(webdav_server_link_down_miss_is_503_not_404);
SD_TEST_DECL(webdav_server_cached_miss_is_503_while_link_down);

static const sd_test_case k_tests[] = {
  SD_TEST_ENTRY(webdav_http_parses_request),
  SD_TEST_ENTRY(webdav_http_incremental_and_framing),
  SD_TEST_ENTRY(webdav_http_rejects),
  SD_TEST_ENTRY(webdav_chunked_decoding),
  SD_TEST_ENTRY(webdav_path_decoding_rules),
  SD_TEST_ENTRY(webdav_href_and_token),
  SD_TEST_ENTRY(webdav_host_header_dns_rebinding),
  SD_TEST_ENTRY(webdav_destination_parsing),
  SD_TEST_ENTRY(webdav_xml_parser),
  SD_TEST_ENTRY(webdav_xml_rejects),
  SD_TEST_ENTRY(webdav_values),
  SD_TEST_ENTRY(webdav_server_gate_before_auth),
  SD_TEST_ENTRY(webdav_server_auth_and_methods),
  SD_TEST_ENTRY(webdav_server_rejects_other_sid),
  SD_TEST_ENTRY(webdav_service_server_admits_a_member),
  SD_TEST_ENTRY(webdav_service_server_refuses_a_non_member),
  SD_TEST_ENTRY(webdav_server_read_only_export),
  SD_TEST_ENTRY(webdav_server_slowloris_and_quotas),
  SD_TEST_ENTRY(webdav_server_ipv6_loopback),
  SD_TEST_ENTRY(webdav_server_office_save_sequence),
  SD_TEST_ENTRY(webdav_server_replacing_move_drops_replaced_children_locks),
  SD_TEST_ENTRY(webdav_server_link_down_miss_is_503_not_404),
  SD_TEST_ENTRY(webdav_server_cached_miss_is_503_while_link_down),
  SD_TEST_ENTRY(webdav_token_only_decision_matrix),
  SD_TEST_ENTRY(webdav_token_selftest_verdict),
  SD_TEST_ENTRY(webdav_token_only_gate_per_mode),
  SD_TEST_ENTRY(webdav_token_only_selftest),
  SD_TEST_ENTRY(webdav_token_only_mount_refused),
};

int main(int argc, char **argv)
{
  return sd_test_main(k_tests, SD_COUNTOF(k_tests), argc, argv);
}
