# Runs "sdl10n --check" on DOMAIN and checks its diagnostics (03 §9.2 self-tests).
#   SDL10N     the tool
#   DOMAIN     the domain directory
#   ALLOW      1 to pass --allow-incomplete
#   EXPECT_RC  the expected exit code
#   EXPECT     regexes that must match the diagnostics, separated by "@@" ("" = none)
#   FORBID     a regex that must not match the diagnostics ("" = none)
set(_args --check --domain "${DOMAIN}")
if(ALLOW)
  list(APPEND _args --allow-incomplete)
endif()
execute_process(COMMAND "${SDL10N}" ${_args}
                RESULT_VARIABLE rc
                OUTPUT_VARIABLE out
                ERROR_VARIABLE err)
string(APPEND out "${err}")
if(NOT rc EQUAL EXPECT_RC)
  message(FATAL_ERROR "sdl10n exit code ${rc}, expected ${EXPECT_RC}:\n${out}")
endif()
if(EXPECT)
  string(REPLACE "@@" ";" _expects "${EXPECT}")
  foreach(_re IN LISTS _expects)
    if(NOT out MATCHES "${_re}")
      message(FATAL_ERROR "missing diagnostic matching '${_re}':\n${out}")
    endif()
  endforeach()
endif()
if(FORBID AND out MATCHES "${FORBID}")
  message(FATAL_ERROR "unexpected diagnostic matching '${FORBID}':\n${out}")
endif()
