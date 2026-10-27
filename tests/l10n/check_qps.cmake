# Checks the qps-ploc table of sdl10n (03 §9.1): generated with --qps, absent without it.
#   SDL10N     the tool
#   DOMAIN     the domain directory
#   WORK       a scratch directory
#   QPS_EXPECT strings that must appear in the table, separated by "@@"
file(MAKE_DIRECTORY "${WORK}")
execute_process(COMMAND "${SDL10N}" --name qps_test --qps --allow-incomplete --domain "${DOMAIN}"
                        --out-c "${WORK}/qps.c" --out-h "${WORK}/qps_ids.h"
                RESULT_VARIABLE rc
                ERROR_VARIABLE err)
if(NOT rc EQUAL 0)
  message(FATAL_ERROR "sdl10n --qps failed (${rc}): ${err}")
endif()
file(READ "${WORK}/qps.c" _qps)
string(FIND "${_qps}" "k_qps_ploc[] = {" _pos)
if(_pos LESS 0)
  message(FATAL_ERROR "sdl10n --qps wrote no qps-ploc table")
endif()
string(REPLACE "@@" ";" _expects "${QPS_EXPECT}")
foreach(_s IN LISTS _expects)
  string(FIND "${_qps}" "${_s}" _pos)
  if(_pos LESS 0)
    message(FATAL_ERROR "qps-ploc table lacks '${_s}'")
  endif()
endforeach()

execute_process(COMMAND "${SDL10N}" --name qps_test --allow-incomplete --domain "${DOMAIN}"
                        --out-c "${WORK}/plain.c" --out-h "${WORK}/plain_ids.h"
                RESULT_VARIABLE rc
                ERROR_VARIABLE err)
if(NOT rc EQUAL 0)
  message(FATAL_ERROR "sdl10n failed without --qps (${rc}): ${err}")
endif()
file(READ "${WORK}/plain.c" _plain)
string(FIND "${_plain}" "k_qps_ploc" _pos)
if(NOT _pos EQUAL -1)
  message(FATAL_ERROR "qps-ploc table present without --qps (Release builds must not ship it)")
endif()
