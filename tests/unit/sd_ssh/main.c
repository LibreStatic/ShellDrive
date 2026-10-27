/* sd_ssh unit tests (no network). Interop tests against the WSL sshd fixture live in
 * test_interop.c (sd-test-ssh-interop.exe, CTest label "interop"). */
#include "sd_test.h"

SD_TEST_DECL(ssh_pick_first_client_match);
SD_TEST_DECL(ssh_lists_strict_server_keeps_static_order);
SD_TEST_DECL(ssh_lists_terrapin_drops_chacha_without_strict);
SD_TEST_DECL(ssh_lists_terrapin_exposed_only_chacha);
SD_TEST_DECL(ssh_lists_fallback_ranks_aes_first);
SD_TEST_DECL(ssh_lists_hostkey_restricted_to_stored_types);
SD_TEST_DECL(ssh_lists_disabled_and_unavailable);
SD_TEST_DECL(ssh_negotiate_reports_category);
SD_TEST_DECL(ssh_kexinit_parse_rejects_truncated);
SD_TEST_DECL(ssh_version_lines);
SD_TEST_DECL(ssh_base64_roundtrip);
SD_TEST_DECL(ssh_packet_plain_framing);
SD_TEST_DECL(ssh_packet_rejects_bad_framing);
SD_TEST_DECL(ssh_packet_ciphers_roundtrip);
SD_TEST_DECL(ssh_kh_patterns);
SD_TEST_DECL(ssh_kh_lookup_names);
SD_TEST_DECL(ssh_kh_check_statuses);
SD_TEST_DECL(ssh_kh_stored_types_for_tmr04);
SD_TEST_DECL(ssh_kh_user_store_add_check_remove);
SD_TEST_DECL(ssh_kh_fingerprint);
SD_TEST_DECL(ssh_key_probe_plain_and_encrypted);
SD_TEST_DECL(ssh_key_load_plain);
SD_TEST_DECL(ssh_key_load_encrypted);
SD_TEST_DECL(ssh_key_unsupported_and_malformed);
SD_TEST_DECL(ssh_key_serialize_roundtrip);
SD_TEST_DECL(ssh_conn_config_validation);
SD_TEST_DECL(ssh_proxy_system_decision);
SD_TEST_DECL(ssh_proxy_system_policy_boundary);
SD_TEST_DECL(ssh_prompt_lifecycle);
SD_TEST_DECL(ssh_secret_cache_roundtrip);
SD_TEST_DECL(ssh_conn_connect_again_after_failure);

static const sd_test_case k_tests[] = {
  SD_TEST_ENTRY(ssh_pick_first_client_match),
  SD_TEST_ENTRY(ssh_lists_strict_server_keeps_static_order),
  SD_TEST_ENTRY(ssh_lists_terrapin_drops_chacha_without_strict),
  SD_TEST_ENTRY(ssh_lists_terrapin_exposed_only_chacha),
  SD_TEST_ENTRY(ssh_lists_fallback_ranks_aes_first),
  SD_TEST_ENTRY(ssh_lists_hostkey_restricted_to_stored_types),
  SD_TEST_ENTRY(ssh_lists_disabled_and_unavailable),
  SD_TEST_ENTRY(ssh_negotiate_reports_category),
  SD_TEST_ENTRY(ssh_kexinit_parse_rejects_truncated),
  SD_TEST_ENTRY(ssh_version_lines),
  SD_TEST_ENTRY(ssh_base64_roundtrip),
  SD_TEST_ENTRY(ssh_packet_plain_framing),
  SD_TEST_ENTRY(ssh_packet_rejects_bad_framing),
  SD_TEST_ENTRY(ssh_packet_ciphers_roundtrip),
  SD_TEST_ENTRY(ssh_kh_patterns),
  SD_TEST_ENTRY(ssh_kh_lookup_names),
  SD_TEST_ENTRY(ssh_kh_check_statuses),
  SD_TEST_ENTRY(ssh_kh_stored_types_for_tmr04),
  SD_TEST_ENTRY(ssh_kh_user_store_add_check_remove),
  SD_TEST_ENTRY(ssh_kh_fingerprint),
  SD_TEST_ENTRY(ssh_key_probe_plain_and_encrypted),
  SD_TEST_ENTRY(ssh_key_load_plain),
  SD_TEST_ENTRY(ssh_key_load_encrypted),
  SD_TEST_ENTRY(ssh_key_unsupported_and_malformed),
  SD_TEST_ENTRY(ssh_key_serialize_roundtrip),
  SD_TEST_ENTRY(ssh_conn_config_validation),
  SD_TEST_ENTRY(ssh_proxy_system_decision),
  SD_TEST_ENTRY(ssh_proxy_system_policy_boundary),
  SD_TEST_ENTRY(ssh_prompt_lifecycle),
  SD_TEST_ENTRY(ssh_secret_cache_roundtrip),
  SD_TEST_ENTRY(ssh_conn_connect_again_after_failure),
};

int main(int argc, char **argv)
{
  return sd_test_main(k_tests, SD_COUNTOF(k_tests), argc, argv);
}
