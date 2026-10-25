# Version information (04 §12.1): VERSION holds MAJOR.MINOR.PATCH[-pre]; BUILD is the CI run number
# (SD_BUILD_NUMBER, 0 for local builds); the git commit (12 hex) and a dirty flag come from git at
# configure time (re-run configure to refresh them).

file(READ "${CMAKE_SOURCE_DIR}/VERSION" SD_VERSION_FULL)
string(STRIP "${SD_VERSION_FULL}" SD_VERSION_FULL)
if(NOT SD_VERSION_FULL MATCHES "^([0-9]+)\\.([0-9]+)\\.([0-9]+)(-[0-9A-Za-z.]+)?$")
  message(FATAL_ERROR "VERSION must be MAJOR.MINOR.PATCH[-prerelease], got '${SD_VERSION_FULL}'.")
endif()
set(SD_VERSION_MAJOR ${CMAKE_MATCH_1})
set(SD_VERSION_MINOR ${CMAKE_MATCH_2})
set(SD_VERSION_PATCH ${CMAKE_MATCH_3})

set(SD_BUILD_NUMBER "0" CACHE STRING "Build number for FILEVERSION (CI run number; 0 locally)")

set(SD_GIT_COMMIT "unknown")
set(SD_BUILD_DIRTY 0)
find_package(Git QUIET)
if(GIT_FOUND)
  execute_process(COMMAND "${GIT_EXECUTABLE}" rev-parse --short=12 HEAD
                  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}" OUTPUT_VARIABLE _sd_commit
                  RESULT_VARIABLE _sd_rc OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
  if(_sd_rc EQUAL 0)
    set(SD_GIT_COMMIT "${_sd_commit}")
    execute_process(COMMAND "${GIT_EXECUTABLE}" status --porcelain --untracked-files=no
                    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}" OUTPUT_VARIABLE _sd_status
                    OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
    if(NOT _sd_status STREQUAL "")
      set(SD_BUILD_DIRTY 1)
    endif()
  endif()
endif()

set(SD_GENERATED_DIR "${CMAKE_BINARY_DIR}/generated")
configure_file("${CMAKE_SOURCE_DIR}/include/sd/version.h.in" "${SD_GENERATED_DIR}/sd/version.h" @ONLY)

# Cross-cutting headers (include/sd/) plus the generated version header.
add_library(sd_headers INTERFACE)
target_include_directories(sd_headers INTERFACE "${CMAKE_SOURCE_DIR}/include" "${SD_GENERATED_DIR}")

message(STATUS "ShellDrive version ${SD_VERSION_FULL} build ${SD_BUILD_NUMBER} commit ${SD_GIT_COMMIT}"
               " dirty=${SD_BUILD_DIRTY}")
