# CTest label msi (opt-in: -DSD_BUILD_MSI=ON, docs/design/04 §8). Build the package first:
#   cmake --build build/<preset> --target msi
#   ctest --test-dir build/<preset> -C Release -L msi
# sd-test-msi reads the package through msi.dll (tables, transforms with the language check) and runs an
# administrative install (msiexec /a: files only, no registry, service or custom action) into the build tree.
#
# An ARM64 or ARM32 tree builds sd-test-msi in its nested x64 build (cmake/SdHostTools.cmake), so its msi.* tests run on
# this host like the x86 and x64 ones; the ARM ctest presets select only them (CMakePresets.json).

if(SD_HOST_TOOLS_ONLY)
  # The nested x64 build of an ARM tree: the test tool only.
  add_executable(sd-test-msi sd-test-msi.c)
  target_link_libraries(sd-test-msi PRIVATE msi.lib)
  set_target_properties(sd-test-msi PROPERTIES FOLDER "tests")
  return()
endif()

# Scratch folder of the administrative install (inside the build tree, removed with it).
file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/msi-admin")

if(SD_CROSS_HOST_TOOLS)
  # sd-test-msi is the imported x64 tool. Nothing else pulls the package into an ARM build when the setup payload does
  # not carry it, so this target does (the tests read the file).
  add_custom_target(sd_msi_for_tests ALL)
  add_dependencies(sd_msi_for_tests msi sd_host_tools)
  set_target_properties(sd_msi_for_tests PROPERTIES FOLDER "tests")
else()
  add_executable(sd-test-msi sd-test-msi.c)
  target_link_libraries(sd-test-msi PRIVATE msi.lib)
  set_target_properties(sd-test-msi PROPERTIES FOLDER "tests")
  # The package must exist before these tests run: on the x64 flavours no setup payload pulls the msi target into the
  # build, so the test tool depends on it.
  if(TARGET msi)
    add_dependencies(sd-test-msi msi)
  endif()
endif()

add_test(NAME msi.${SD_FLAVOUR}.tables
         COMMAND sd-test-msi tables "${SD_MSI_PACKAGE}" "${SD_MSI_TEST_VERSION}" "${SD_MSI_TEST_UPGRADE}"
                 "${SD_MSI_TEST_PLATFORM}" "${SD_MSI_TEST_INSTALLER}" "${SD_MSI_TEST_LAUNCH_COUNT}"
                 "${SD_MSI_TEST_SHELLEXT32}" "${SD_MSI_TEST_UI}")
set_tests_properties(msi.${SD_FLAVOUR}.tables PROPERTIES LABELS msi TIMEOUT 300)

add_test(NAME msi.${SD_FLAVOUR}.admin
         COMMAND sd-test-msi admin "${SD_MSI_PACKAGE}" "${CMAKE_BINARY_DIR}/msi-admin/${SD_FLAVOUR}"
                 "${SD_MSI_TEST_PLATFORM}" "${SD_MSI_TEST_SHELLEXT32}" "${SD_MSI_TEST_UI}")
# msiexec runs one installation at a time per machine (Windows Installer service): windows_installer.
set_tests_properties(msi.${SD_FLAVOUR}.admin PROPERTIES LABELS msi TIMEOUT 900 RESOURCE_LOCK windows_installer)

# WixUI string overrides (packaging/msi/wixui): every id of the dialog set in every override, and the Spanish register
# lint (docs/dev/m4-notes.md). Plain CMake script, no package needed.
add_test(NAME msi.${SD_FLAVOUR}.wixui
         COMMAND "${CMAKE_COMMAND}" "-DSD_SRC=${CMAKE_SOURCE_DIR}" "-DSD_WIX_DIR=${SD_WIX_DIR}"
                 -P "${CMAKE_CURRENT_SOURCE_DIR}/check-wixui.cmake")
set_tests_properties(msi.${SD_FLAVOUR}.wixui PROPERTIES LABELS msi TIMEOUT 60)

# The 32-bit shell extension of the x64 and ARM64 packages (04 §6.2, §8.3): the x86-sse2 DLL of the nested x86 configure
# (cmake/SdShellExtX86.cmake) has the rules of its own flavour. The nested build runs the same audits after its link;
# these tests repeat them on the file the package carries, with the arguments of sd_add_import_audit and
# sd_add_isa_check (cmake/SdModule.cmake) for SD_FLAVOUR=x86-sse2. An ARM tree has no sd-isacheck (it audits x86 code
# only, 04 §2.4), so there only the nested build's own ISA audit covers the DLL.
if(SD_MSI_TEST_SHELLEXT32)
  add_test(NAME importcheck.shelldrive-shellext.x86-sse2
           COMMAND sd-importcheck --floor "${CMAKE_SOURCE_DIR}/tests/os-imports/xp-sp3-x86.txt"
                   --subsystem 5.01 --forbid-cfg --require-safeseh "${SD_MSI_TEST_X86_DLL}")
  set_tests_properties(importcheck.shelldrive-shellext.x86-sse2 PROPERTIES LABELS importcheck)
  if(TARGET sd-isacheck)
    add_test(NAME isacheck.shelldrive-shellext.x86-sse2
             COMMAND sd-isacheck --floor sse2
                     --allow "${CMAKE_SOURCE_DIR}/tools/sd-isacheck/crt-allow.txt"
                     --allow "${CMAKE_SOURCE_DIR}/tools/sd-isacheck/hw-allow.txt"
                     "${SD_MSI_TEST_X86_DLL}")
    set_tests_properties(isacheck.shelldrive-shellext.x86-sse2 PROPERTIES LABELS isacheck)
  endif()
endif()
