/* sd_ssh `auth` area unit tests (sd-test-ssh_auth.exe, no network): key file formats, certificates,
 * DPAPI-kept keys, agent clients against in-test fake agents, and the userauth state machine
 * against a scripted server. Interop: test_auth_interop.c. */
#include "sd_test.h"

SD_TEST_DECL(ssh_keyfmt_probe_load_sign_all);
SD_TEST_DECL(ssh_keyfmt_unsupported);
SD_TEST_DECL(ssh_keyfmt_truncation_and_corruption);
SD_TEST_DECL(ssh_keyfmt_certificates);
SD_TEST_DECL(ssh_keyfmt_pubkey_files);
SD_TEST_DECL(ssh_keyfmt_dpapi_roundtrip);
SD_TEST_DECL(ssh_keyfmt_md5_and_der);
SD_TEST_DECL(ssh_agent_pipe_fake);
SD_TEST_DECL(ssh_agent_pageant_fake);
SD_TEST_DECL(ssh_agent_windows_openssh_probe);
SD_TEST_DECL(ssh_agent_reply_bounds);
SD_TEST_DECL(ssh_auth_password_change);
SD_TEST_DECL(ssh_auth_kbdint_otp_rounds);
SD_TEST_DECL(ssh_auth_publickey_cert_first);
SD_TEST_DECL(ssh_auth_rsa_algorithms);
SD_TEST_DECL(ssh_auth_passphrase_after_pk_ok);
SD_TEST_DECL(ssh_auth_expired_cert_skipped);
SD_TEST_DECL(ssh_auth_agent_keys);
SD_TEST_DECL(ssh_auth_attempt_limit);

static const sd_test_case k_tests[] = {
  SD_TEST_ENTRY(ssh_keyfmt_probe_load_sign_all),
  SD_TEST_ENTRY(ssh_keyfmt_unsupported),
  SD_TEST_ENTRY(ssh_keyfmt_truncation_and_corruption),
  SD_TEST_ENTRY(ssh_keyfmt_certificates),
  SD_TEST_ENTRY(ssh_keyfmt_pubkey_files),
  SD_TEST_ENTRY(ssh_keyfmt_dpapi_roundtrip),
  SD_TEST_ENTRY(ssh_keyfmt_md5_and_der),
  SD_TEST_ENTRY(ssh_agent_pipe_fake),
  SD_TEST_ENTRY(ssh_agent_pageant_fake),
  SD_TEST_ENTRY(ssh_agent_windows_openssh_probe),
  SD_TEST_ENTRY(ssh_agent_reply_bounds),
  SD_TEST_ENTRY(ssh_auth_password_change),
  SD_TEST_ENTRY(ssh_auth_kbdint_otp_rounds),
  SD_TEST_ENTRY(ssh_auth_publickey_cert_first),
  SD_TEST_ENTRY(ssh_auth_rsa_algorithms),
  SD_TEST_ENTRY(ssh_auth_passphrase_after_pk_ok),
  SD_TEST_ENTRY(ssh_auth_expired_cert_skipped),
  SD_TEST_ENTRY(ssh_auth_agent_keys),
  SD_TEST_ENTRY(ssh_auth_attempt_limit),
};

int main(int argc, char **argv)
{
  return sd_test_main(k_tests, SD_COUNTOF(k_tests), argc, argv);
}
