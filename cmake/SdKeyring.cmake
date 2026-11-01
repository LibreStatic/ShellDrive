# Compiled-in release keys (docs/design/04 §9.3). `sd-release keyring` verifies the signed keyset of
# installer/keys/ against the two root public keys and generates the two include files that every shipping binary
# compiles in: the stub's payload keyring (setup_keyring.inc) and the host's update trust (update_trust.inc). The
# files are generated into the build tree, deterministically (04 §12.2), and the generated directory goes FIRST on
# the include path of the targets that include them, so the generated file wins over the placeholder in the source
# tree (the includes are angle form for exactly that reason; MSVC searches the including file's own directory
# before the include path for quoted includes).
#
#   sd_keyring_setup()         called once by the root CMakeLists.txt, after the build-time tools exist. It sets:
#     SD_KEYRING_DIR           directory of the generated include files; empty when installer/keys/ is absent.
#     SD_KEYRING_TARGET        the custom target that generates them ("sd_keyring"); empty likewise.
#
# Without installer/keys/ nothing changes: the repository placeholders are used, which hold no keys, so no payload
# verifies and every update verification fails closed until the release pipeline provides the key files.

set(SD_KEYRING_DIR "")
set(SD_KEYRING_TARGET "")

function(sd_keyring_setup)
  set(_roots "${CMAKE_SOURCE_DIR}/installer/keys/roots.txt")
  set(_keyset "${CMAKE_SOURCE_DIR}/installer/keys/keyset.txt")
  if(NOT EXISTS "${_roots}" OR NOT EXISTS "${_keyset}")
    return()
  endif()
  set(_dir "${SD_GENERATED_DIR}/keyring")
  set(_setup_inc "${_dir}/setup_keyring.inc")
  set(_trust_inc "${_dir}/update_trust.inc")
  sd_tool_depends(sd-release _sd_keyring_tool_dep)
  add_custom_command(
    OUTPUT "${_setup_inc}" "${_trust_inc}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${_dir}"
    COMMAND $<TARGET_FILE:sd-release> keyring --roots "${_roots}" --keyset "${_keyset}"
            --out-setup "${_setup_inc}" --out-trust "${_trust_inc}"
    DEPENDS ${_sd_keyring_tool_dep} "${_roots}" "${_keyset}"
    COMMENT "sd-release keyring: compiled-in release keys (04 §9.3)"
    VERBATIM)
  add_custom_target(sd_keyring DEPENDS "${_setup_inc}" "${_trust_inc}")
  sd_add_tool_dependency(sd_keyring sd-release)
  set_target_properties(sd_keyring PROPERTIES FOLDER "tools")
  set(SD_KEYRING_DIR "${_dir}" PARENT_SCOPE)
  set(SD_KEYRING_TARGET "sd_keyring" PARENT_SCOPE)
endfunction()
