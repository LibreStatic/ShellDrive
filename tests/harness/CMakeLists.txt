# Unit-test harness shared by every sd-test-<module>.exe.

add_library(sd_test_harness STATIC sd_test.c sd_test.h)
target_include_directories(sd_test_harness PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(sd_test_harness PUBLIC sd_headers sd_base sd_platform)
set_target_properties(sd_test_harness PROPERTIES FOLDER "tests")
