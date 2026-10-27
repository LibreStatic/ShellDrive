# Constant-time timing tests (01 section 2.4 rule 9, 2.7.5; TST-03). Opt-in: configure with -DSD_CT_TIMING=ON.
# Excluded from the default run by construction (the test is registered only with the option), labelled ct, and run
# once on a quiet machine with: ctest -L ct --output-on-failure. Results are reported in docs/review/d38-pass1.md.
add_executable(sd-ct-dudect ct_dudect.c)
target_link_libraries(sd-ct-dudect PRIVATE sd_crypto sd_base sd_platform)
set_target_properties(sd-ct-dudect PROPERTIES FOLDER "tests/ct")
add_test(NAME ct.dudect COMMAND sd-ct-dudect)
# Timing measurement: RUN_SERIAL, no other test may load the machine meanwhile.
set_tests_properties(ct.dudect PROPERTIES LABELS ct TIMEOUT 1800 RUN_SERIAL TRUE)
