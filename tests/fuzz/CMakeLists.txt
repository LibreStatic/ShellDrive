# Fuzz targets (01 section 12.2, 04 section 11.2; TST-01, TST-02). Test-only, never shipped (TST-30).
#
# Each target is one harness in harness/fuzz_<name>.c defining sd_fuzz_one() (include/sd_fuzz.h), linked with the
# module libraries it parses with. Built in every flavour:
#   sd-fuzz-<name>.exe     replay driver (replay/sd_fuzz_replay.c): runs corpus/<name>/ and a fixed number of
#                          deterministic mutations. CTest test fuzz.<name> (label fuzz, part of the normal run).
#   sd-fuzz-<name>-libfuzzer.exe   only with -DSD_FUZZ=ON (libFuzzer, MSVC /fsanitize=fuzzer; cmake/SdOptions.cmake):
#                          run it with a corpus directory, e.g. sd-fuzz-json-libfuzzer.exe corpus\json -max_total_time=300
#
# Adding a target: add harness/fuzz_<name>.c, corpus/<name>/ seeds, and one sd_add_fuzz_target line below.

set(SD_FUZZ_CORPUS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/corpus")

function(sd_add_fuzz_target name)
  cmake_parse_arguments(F "" "MUTATIONS" "DEPS;PRIVATE_INCLUDES" ${ARGN})
  set(_harness "${CMAKE_CURRENT_SOURCE_DIR}/harness/fuzz_${name}.c")
  set(_entry "${CMAKE_CURRENT_SOURCE_DIR}/replay/libfuzzer_entry.c")
  set(_replay "${CMAKE_CURRENT_SOURCE_DIR}/replay/sd_fuzz_replay.c")
  set(_exe sd-fuzz-${name})
  set(_manifest "${CMAKE_CURRENT_BINARY_DIR}/${_exe}.manifest")
  sd_manifest_configure("${_manifest}" "${_exe}" FALSE)

  add_executable(${_exe} "${_harness}" "${_entry}" "${_replay}" "${_manifest}")
  target_include_directories(${_exe} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/include")
  foreach(_d IN LISTS F_PRIVATE_INCLUDES)
    target_include_directories(${_exe} PRIVATE "${_d}")
  endforeach()
  target_link_libraries(${_exe} PRIVATE ${F_DEPS} sd_base sd_platform)
  set_target_properties(${_exe} PROPERTIES FOLDER "tests/fuzz")
  set(_replay_args "${SD_FUZZ_CORPUS_DIR}/${name}")
  if(F_MUTATIONS)
    list(APPEND _replay_args "${F_MUTATIONS}")
  endif()
  add_test(NAME fuzz.${name} COMMAND ${_exe} ${_replay_args})
  set_tests_properties(fuzz.${name} PROPERTIES LABELS fuzz TIMEOUT 120)

  if(SD_FUZZ)
    set(_lf ${_exe}-libfuzzer)
    add_executable(${_lf} "${_harness}" "${_entry}" "${_manifest}")
    target_include_directories(${_lf} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/include")
    foreach(_d IN LISTS F_PRIVATE_INCLUDES)
      target_include_directories(${_lf} PRIVATE "${_d}")
    endforeach()
    target_link_libraries(${_lf} PRIVATE ${F_DEPS} sd_base sd_platform)
    set_target_properties(${_lf} PROPERTIES FOLDER "tests/fuzz")
  endif()
endfunction()

sd_add_fuzz_target(json DEPS sd_base)
sd_add_fuzz_target(ini DEPS sd_config)
sd_add_fuzz_target(utf_names DEPS sd_base)
sd_add_fuzz_target(text_sanitize DEPS sd_base)
# KDF-protected key files cost seconds each under ASan (Debug x86): fewer mutations keep the run short.
sd_add_fuzz_target(keyfile DEPS sd_ssh sd_crypto MUTATIONS 200)
sd_add_fuzz_target(known_hosts DEPS sd_ssh sd_crypto PRIVATE_INCLUDES "${CMAKE_SOURCE_DIR}/src/sd_ssh")
sd_add_fuzz_target(cert DEPS sd_ssh sd_crypto)
sd_add_fuzz_target(kexinit DEPS sd_ssh sd_crypto PRIVATE_INCLUDES "${CMAKE_SOURCE_DIR}/src/sd_ssh")
sd_add_fuzz_target(sftp_reply DEPS sd_sftp sd_ssh sd_crypto PRIVATE_INCLUDES "${CMAKE_SOURCE_DIR}/src/sd_sftp")
sd_add_fuzz_target(wd_http DEPS sd_webdav PRIVATE_INCLUDES "${CMAKE_SOURCE_DIR}/src/sd_webdav")
sd_add_fuzz_target(wd_xml DEPS sd_webdav PRIVATE_INCLUDES "${CMAKE_SOURCE_DIR}/src/sd_webdav")
sd_add_fuzz_target(state DEPS sd_state)
sd_add_fuzz_target(manifest DEPS sd_update sd_crypto)
sd_add_fuzz_target(inflate DEPS sd_ssh sd_crypto PRIVATE_INCLUDES "${CMAKE_SOURCE_DIR}/src/sd_ssh")
