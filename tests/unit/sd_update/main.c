/* sd_update unit tests (04 §9, TM-R36/R37/R23; TST-31): pure verification, state, and the engine over a
 * loopback server with test keys made by sd-updsign. Runs with -LE "matrix|bench|interop" like the rest. */
#include <windows.h>

#include "sd_test.h"
#include "sd_platform/sd_platform.h"

SD_TEST_DECL(versions_compare);
SD_TEST_DECL(time_strict);
SD_TEST_DECL(base64_canonical);
SD_TEST_DECL(manifest_parse_fields);
SD_TEST_DECL(chain_valid);
SD_TEST_DECL(manifest_byte_flip_is_refused);
SD_TEST_DECL(manifest_wrong_key_is_refused);
SD_TEST_DECL(beta_key_cannot_sign_stable_and_stable_cannot_sign_beta);
SD_TEST_DECL(manifest_expired_and_freshness);
SD_TEST_DECL(manifest_serial_rollback_refused);
SD_TEST_DECL(keyset_expired_key_refused);
SD_TEST_DECL(keyset_revoked_key_refused);
SD_TEST_DECL(keyset_tamper_and_rollback);
SD_TEST_DECL(keyset_signed_by_unknown_root_refused);
SD_TEST_DECL(keyset_rotation_needs_both_roots);
SD_TEST_DECL(product_and_format_version);
SD_TEST_DECL(manifest_strict_syntax);
SD_TEST_DECL(manifest_dokany_deny_and_unknown_keys);
SD_TEST_DECL(select_file_by_mode_and_flavour);
SD_TEST_DECL(res_names_are_stable);
SD_TEST_DECL(state_serial_is_per_channel);
SD_TEST_DECL(state_machine_copy_counts_as_maximum);
SD_TEST_DECL(state_legacy_serial_is_migrated_once);
SD_TEST_DECL(state_verified_blobs_and_manifest);
SD_TEST_DECL(engine_check_stage_apply_success);
SD_TEST_DECL(engine_selftest_failure_restores_previous_version);
SD_TEST_DECL(engine_up_to_date_offers_nothing);
SD_TEST_DECL(engine_serial_rollback_and_same_serial_bytes);
SD_TEST_DECL(engine_expired_manifest_changes_no_state);
SD_TEST_DECL(engine_https_fallback_to_http_mirror);
SD_TEST_DECL(engine_stage_refuses_redirect_oversize_and_bad_digest);
SD_TEST_DECL(engine_setup_run_exit_code);
SD_TEST_DECL(engine_cleanup_keeps_current_version);
SD_TEST_DECL(engine_detects_a_known_flavour);

static const sd_test_case k_tests[] = {
  SD_TEST_ENTRY(versions_compare),
  SD_TEST_ENTRY(time_strict),
  SD_TEST_ENTRY(base64_canonical),
  SD_TEST_ENTRY(manifest_parse_fields),
  SD_TEST_ENTRY(chain_valid),
  SD_TEST_ENTRY(manifest_byte_flip_is_refused),
  SD_TEST_ENTRY(manifest_wrong_key_is_refused),
  SD_TEST_ENTRY(beta_key_cannot_sign_stable_and_stable_cannot_sign_beta),
  SD_TEST_ENTRY(manifest_expired_and_freshness),
  SD_TEST_ENTRY(manifest_serial_rollback_refused),
  SD_TEST_ENTRY(keyset_expired_key_refused),
  SD_TEST_ENTRY(keyset_revoked_key_refused),
  SD_TEST_ENTRY(keyset_tamper_and_rollback),
  SD_TEST_ENTRY(keyset_signed_by_unknown_root_refused),
  SD_TEST_ENTRY(keyset_rotation_needs_both_roots),
  SD_TEST_ENTRY(product_and_format_version),
  SD_TEST_ENTRY(manifest_strict_syntax),
  SD_TEST_ENTRY(manifest_dokany_deny_and_unknown_keys),
  SD_TEST_ENTRY(select_file_by_mode_and_flavour),
  SD_TEST_ENTRY(res_names_are_stable),
  SD_TEST_ENTRY(state_serial_is_per_channel),
  SD_TEST_ENTRY(state_machine_copy_counts_as_maximum),
  SD_TEST_ENTRY(state_legacy_serial_is_migrated_once),
  SD_TEST_ENTRY(state_verified_blobs_and_manifest),
  SD_TEST_ENTRY(engine_check_stage_apply_success),
  SD_TEST_ENTRY(engine_selftest_failure_restores_previous_version),
  SD_TEST_ENTRY(engine_up_to_date_offers_nothing),
  SD_TEST_ENTRY(engine_serial_rollback_and_same_serial_bytes),
  SD_TEST_ENTRY(engine_expired_manifest_changes_no_state),
  SD_TEST_ENTRY(engine_https_fallback_to_http_mirror),
  SD_TEST_ENTRY(engine_stage_refuses_redirect_oversize_and_bad_digest),
  SD_TEST_ENTRY(engine_setup_run_exit_code),
  SD_TEST_ENTRY(engine_cleanup_keeps_current_version),
  SD_TEST_ENTRY(engine_detects_a_known_flavour),
};

int main(int argc, char **argv)
{
  if (sd_platform_init() != SD_OK)
    return 2;
  return sd_test_main(k_tests, SD_COUNTOF(k_tests), argc, argv);
}
