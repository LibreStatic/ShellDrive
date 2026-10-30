# Log privacy source check (03 §10.1, TM-R31): a %s conversion that formats a host, user, lookup name or remote path
# fails the build's test run, and every call's conversions must match its arguments (/analyze does not read the
# restricted sd_log format). The runtime filter itself is tested in tests/unit/sd_platform.

add_test(NAME logpriv.source_check
  COMMAND powershell -NoProfile -ExecutionPolicy Bypass -File "${CMAKE_CURRENT_SOURCE_DIR}/check-log-privacy.ps1"
          -Root "${CMAKE_SOURCE_DIR}")
set_tests_properties(logpriv.source_check PROPERTIES LABELS logpriv TIMEOUT 120)

# The fixture holds one unmigrated host, one user and one count mismatch; the check must reject it.
add_test(NAME logpriv.source_check_detects_fixture
  COMMAND powershell -NoProfile -ExecutionPolicy Bypass -File "${CMAKE_CURRENT_SOURCE_DIR}/check-log-privacy.ps1"
          -Root "${CMAKE_CURRENT_SOURCE_DIR}/fixtures")
set_tests_properties(logpriv.source_check_detects_fixture PROPERTIES LABELS logpriv TIMEOUT 120 WILL_FAIL TRUE)
