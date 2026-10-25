# CTest driver for cpucheck.refuses_without_sse2: runs the entry-thunk fixture with the refusal forced and
# checks both the message and the exit status. A direct add_test cannot do this: the fixture exits with
# STATUS_ILLEGAL_INSTRUCTION (0xC000001D) by design, which CTest reports as "***Exception: Illegal" and
# fails before PASS_REGULAR_EXPRESSION is looked at.
#   cmake -DFIXTURE=<path> -P expect_refusal.cmake
set(ENV{SD_CPUCHECK_SIMULATE_NO_SSE2} 1)
execute_process(COMMAND "${FIXTURE}" RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err)
set(all "${out}${err}")
message(STATUS "exit status: ${rc}")
message(STATUS "output: ${all}")
if(all MATCHES "cpucheck fixture ran")
  message(FATAL_ERROR "the fixture started although the refusal was forced")
endif()
if(NOT all MATCHES "x86-ia32")
  message(FATAL_ERROR "the refusal text does not name the x86-ia32 build")
endif()
# kwsys reports the NTSTATUS as text ("Illegal instruction") or as the number, depending on the version
if(NOT (rc MATCHES "[Ii]llegal" OR rc STREQUAL "-1073741795" OR rc STREQUAL "3221225501"))
  message(FATAL_ERROR "expected exit status 0xC000001D (STATUS_ILLEGAL_INSTRUCTION), got '${rc}'")
endif()
