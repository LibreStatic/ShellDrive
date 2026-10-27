# Group Policy checks (03 §3.5, 04 §8.6): the generated ADMX/ADML against the table, the policy catalogs
# through sdl10n, and no raw policy reads outside src/sd_policy. The generated files come from the ALL build.

set(_table "${CMAKE_SOURCE_DIR}/res/policy/policies.txt")

add_test(NAME policy.admx_structure
  COMMAND powershell -NoProfile -ExecutionPolicy Bypass -File "${CMAKE_CURRENT_SOURCE_DIR}/check-admx.ps1"
          -Dir "${SD_POLICY_DIR}" -Table "${_table}")
set_tests_properties(policy.admx_structure PROPERTIES LABELS policy TIMEOUT 120)

add_test(NAME policy.no_raw_reads
  COMMAND powershell -NoProfile -ExecutionPolicy Bypass -File "${CMAKE_CURRENT_SOURCE_DIR}/check-raw-reads.ps1"
          -Root "${CMAKE_SOURCE_DIR}" -Table "${_table}")
set_tests_properties(policy.no_raw_reads PROPERTIES LABELS policy TIMEOUT 120)

add_test(NAME l10n.policy_catalogs_complete
  COMMAND sdl10n --check --domain "${CMAKE_SOURCE_DIR}/l10n/policy")
set_tests_properties(l10n.policy_catalogs_complete PROPERTIES LABELS l10n)
