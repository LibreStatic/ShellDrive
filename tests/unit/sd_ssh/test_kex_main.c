/* sd-test-ssh-transport: unit tests of the M2 transport area (01 §4, §7): algorithm lists, legacy
 * classification, Terrapin rules, every KEX method against an in-process mock server, host key
 * signatures and certificates, CBC/SHA-1 packet protection, known_hosts M2 (hashed entries,
 * @cert-authority, live OpenSSH/PuTTY sources, UpdateHostKeys review helpers). */
#include "sd_test.h"

SD_TEST_DECL(tr_lists_static_order_modern_first);
SD_TEST_DECL(tr_lists_refuse_removes_legacy);
SD_TEST_DECL(tr_lists_stored_types_map_to_algorithms);
SD_TEST_DECL(tr_lists_terrapin_cbc_without_etm);
SD_TEST_DECL(tr_lists_terrapin_exposed_cbc_etm_only);
SD_TEST_DECL(tr_lists_fetch_hostkey_only);
SD_TEST_DECL(tr_legacy_mask_and_names);
SD_TEST_DECL(tr_hostkey_algs_for_type);
SD_TEST_DECL(tr_kex_methods_against_mock_server);
SD_TEST_DECL(tr_kex_rejects_bad_server_values);
SD_TEST_DECL(tr_kex_derive_long_outputs);
SD_TEST_DECL(tr_hostkey_signatures);
SD_TEST_DECL(tr_cert_parse_and_host_checks);
SD_TEST_DECL(tr_packet_cbc_and_sha1_roundtrip);
SD_TEST_DECL(tr_packet_cbc_mac_failure_discards);
SD_TEST_DECL(tr_kh_hashed_entries);
SD_TEST_DECL(tr_kh_cert_authority);
SD_TEST_DECL(tr_kh_live_openssh_source);
SD_TEST_DECL(tr_kh_live_source_insecure_is_skipped);
SD_TEST_DECL(tr_kh_putty_values);
SD_TEST_DECL(tr_kh_putty_registry_source);
SD_TEST_DECL(tr_kh_apply_hostkeys_and_remove_key);
SD_TEST_DECL(tr_kh_list_all_comments_and_origin);
SD_TEST_DECL(tr_fetch_key_never_becomes_pinned);

static const sd_test_case k_tests[] = {
  SD_TEST_ENTRY(tr_lists_static_order_modern_first),
  SD_TEST_ENTRY(tr_lists_refuse_removes_legacy),
  SD_TEST_ENTRY(tr_lists_stored_types_map_to_algorithms),
  SD_TEST_ENTRY(tr_lists_terrapin_cbc_without_etm),
  SD_TEST_ENTRY(tr_lists_terrapin_exposed_cbc_etm_only),
  SD_TEST_ENTRY(tr_lists_fetch_hostkey_only),
  SD_TEST_ENTRY(tr_legacy_mask_and_names),
  SD_TEST_ENTRY(tr_hostkey_algs_for_type),
  SD_TEST_ENTRY(tr_kex_methods_against_mock_server),
  SD_TEST_ENTRY(tr_kex_rejects_bad_server_values),
  SD_TEST_ENTRY(tr_kex_derive_long_outputs),
  SD_TEST_ENTRY(tr_hostkey_signatures),
  SD_TEST_ENTRY(tr_cert_parse_and_host_checks),
  SD_TEST_ENTRY(tr_packet_cbc_and_sha1_roundtrip),
  SD_TEST_ENTRY(tr_packet_cbc_mac_failure_discards),
  SD_TEST_ENTRY(tr_kh_hashed_entries),
  SD_TEST_ENTRY(tr_kh_cert_authority),
  SD_TEST_ENTRY(tr_kh_live_openssh_source),
  SD_TEST_ENTRY(tr_kh_live_source_insecure_is_skipped),
  SD_TEST_ENTRY(tr_kh_putty_values),
  SD_TEST_ENTRY(tr_kh_putty_registry_source),
  SD_TEST_ENTRY(tr_kh_apply_hostkeys_and_remove_key),
  SD_TEST_ENTRY(tr_kh_list_all_comments_and_origin),
  SD_TEST_ENTRY(tr_fetch_key_never_becomes_pinned),
};

int main(int argc, char **argv)
{
  return sd_test_main(k_tests, SD_COUNTOF(k_tests), argc, argv);
}
