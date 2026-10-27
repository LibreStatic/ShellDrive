# CTest label msi (opt-in: -DSD_BUILD_MSI=ON, docs/design/04 §8). Build the package first:
#   cmake --build build/<preset> --target msi
#   ctest --test-dir build/<preset> -C Release -L msi
# sd-test-msi reads the package through msi.dll (tables, transforms with the language check) and runs an
# administrative install (msiexec /a: files only, no registry, service or custom action) into the build tree.

# Scratch folder of the administrative install (inside the build tree, removed with it).
file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/msi-admin")

add_executable(sd-test-msi sd-test-msi.c)
target_link_libraries(sd-test-msi PRIVATE msi.lib)
set_target_properties(sd-test-msi PROPERTIES FOLDER "tests")

add_test(NAME msi.${SD_FLAVOUR}.tables
         COMMAND sd-test-msi tables "${SD_MSI_PACKAGE}" "${SD_MSI_TEST_VERSION}" "${SD_MSI_TEST_UPGRADE}"
                 "${SD_MSI_TEST_PLATFORM}" "${SD_MSI_TEST_INSTALLER}" "${SD_MSI_TEST_LAUNCH_COUNT}")
set_tests_properties(msi.${SD_FLAVOUR}.tables PROPERTIES LABELS msi TIMEOUT 300)

add_test(NAME msi.${SD_FLAVOUR}.admin
         COMMAND sd-test-msi admin "${SD_MSI_PACKAGE}" "${CMAKE_BINARY_DIR}/msi-admin/${SD_FLAVOUR}")
# msiexec runs one installation at a time per machine (Windows Installer service): windows_installer.
set_tests_properties(msi.${SD_FLAVOUR}.admin PROPERTIES LABELS msi TIMEOUT 900 RESOURCE_LOCK windows_installer)

# WixUI string overrides (packaging/msi/wixui): every id of the dialog set in every override, and the Spanish register
# lint (docs/dev/m4-notes.md). Plain CMake script, no package needed.
add_test(NAME msi.${SD_FLAVOUR}.wixui
         COMMAND "${CMAKE_COMMAND}" "-DSD_SRC=${CMAKE_SOURCE_DIR}" "-DSD_WIX_DIR=${SD_WIX_DIR}"
                 -P "${CMAKE_CURRENT_SOURCE_DIR}/check-wixui.cmake")
set_tests_properties(msi.${SD_FLAVOUR}.wixui PROPERTIES LABELS msi TIMEOUT 60)
