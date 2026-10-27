# Builds the per-machine MSI of one flavour and embeds its language transforms (docs/design/04 §8).
#
#   cmake -D<variables> -P build-msi.cmake
#
# Run by the msi target of packaging/msi/CMakeLists.txt after the binaries of the flavour are built. Every step
# must succeed: a non-zero exit of candle, light, torch, sd-msigen or sd-msiembed fails the build.
#
# Variables (all required):
#   SD_MSI_FLAVOUR, SD_MSI_FAMILY (the UpgradeCode family: x86, x64, arm32, arm64), SD_MSI_VERSION
#   SD_MSI_ARCH (candle -arch: x86, x64, arm64), SD_MSI_INSTALLER_VERSION (301 or 500), SD_MSI_PF (the
#   Program Files folder property), SD_MSI_WIN64 (yes or no), SD_MSI_LAUNCH (none or win10),
#   SD_MSI_WITH_SERVICE (0 or 1), SD_MSI_UPGRADE_CODE
#   SD_MSI_BIN (the folder of the four binaries), SD_MSI_ICON, SD_MSI_SRC (packaging/msi), SD_MSI_GEN (build
#   folder for generated files), SD_MSI_OUT (the final package is SD_MSI_OUT/ShellDrive-<version>-<flavour>.msi),
#   SD_MSI_REG (packaging/registration.txt), SD_MSI_PO (l10n/installer), SD_MSI_WIX (WiX root folder),
#   SD_MSI_LICENSE (the LICENSE file of the repository: the license page of the dialog set), SD_MSIGEN, SD_MSIEMBED
#   (tool paths).

foreach(_v IN ITEMS SD_MSI_FLAVOUR SD_MSI_FAMILY SD_MSI_VERSION SD_MSI_ARCH SD_MSI_INSTALLER_VERSION SD_MSI_PF
                    SD_MSI_WIN64 SD_MSI_LAUNCH SD_MSI_WITH_SERVICE SD_MSI_UPGRADE_CODE SD_MSI_BIN SD_MSI_ICON
                    SD_MSI_SRC SD_MSI_GEN SD_MSI_OUT SD_MSI_REG SD_MSI_PO SD_MSI_WIX SD_MSI_LICENSE SD_MSIGEN SD_MSIEMBED)
  if("${${_v}}" STREQUAL "")
    message(FATAL_ERROR "build-msi.cmake: ${_v} is not set")
  endif()
endforeach()

set(_wix_bin "${SD_MSI_WIX}/bin")
set(_wix_ui "${SD_MSI_WIX}/SDK/wixui")
set(_candle "${_wix_bin}/candle.exe")
set(_light "${_wix_bin}/light.exe")
set(_torch "${_wix_bin}/torch.exe")
foreach(_t IN ITEMS "${_candle}" "${_light}" "${_torch}" "${SD_MSIGEN}" "${SD_MSIEMBED}")
  if(NOT EXISTS "${_t}")
    message(FATAL_ERROR "build-msi.cmake: missing tool ${_t} (WiX: set the WIX environment variable, 04 §8.1)")
  endif()
endforeach()

# step NAME COMMAND...: runs one tool and fails the build with its output on error.
function(sd_msi_step what)
  execute_process(COMMAND ${ARGN} RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _err)
  if(NOT _out STREQUAL "")
    message(STATUS "${_out}")
  endif()
  if(NOT _err STREQUAL "")
    message(STATUS "${_err}")
  endif()
  if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "${what} failed (${_rc})")
  endif()
endfunction()

set(_work "${SD_MSI_GEN}/msi-${SD_MSI_FLAVOUR}")
file(MAKE_DIRECTORY "${_work}" "${SD_MSI_OUT}")
set(_name "ShellDrive-${SD_MSI_VERSION}-${SD_MSI_FLAVOUR}")
set(_base "${_work}/${_name}.base.msi")
set(_final "${SD_MSI_OUT}/${_name}.msi")

# 1. GUIDs of this flavour: the ProductCode and PackageCode change with every version (04 §8.2, §12.2), the
#    component GUIDs are per UpgradeCode family so that two families never share a component.
execute_process(COMMAND "${SD_MSIGEN}" guid --seed "${SD_MSI_FLAVOUR}|${SD_MSI_VERSION}|product"
                OUTPUT_VARIABLE _product_code OUTPUT_STRIP_TRAILING_WHITESPACE RESULT_VARIABLE _rc)
if(NOT _rc EQUAL 0)
  message(FATAL_ERROR "sd-msigen guid (product) failed")
endif()
execute_process(COMMAND "${SD_MSIGEN}" guid --seed "${SD_MSI_FLAVOUR}|${SD_MSI_VERSION}|package"
                OUTPUT_VARIABLE _package_code OUTPUT_STRIP_TRAILING_WHITESPACE RESULT_VARIABLE _rc)
if(NOT _rc EQUAL 0)
  message(FATAL_ERROR "sd-msigen guid (package) failed")
endif()

set(_components C_Core_Cli C_Core_Host C_Core_Ui C_ShellExt C_StartMenu C_Ini_Update C_Ini_UpdateUrl
                C_Ini_Backend C_LinkedConn C_Rm_Secrets C_Rm_Keys C_Rm_Data C_Rm_DataProfiles
                C_Rm_DataState C_Rm_DataService)
set(_guids_file "${_work}/Guids.wxi")
file(WRITE "${_guids_file}" "<Include>\n<?define SD_PRODUCT_CODE = \"${_product_code}\" ?>\n<?define SD_PACKAGE_CODE = \"${_package_code}\" ?>\n")
foreach(_c IN LISTS _components)
  execute_process(COMMAND "${SD_MSIGEN}" guid --seed "${SD_MSI_FAMILY}|${_c}"
                  OUTPUT_VARIABLE _g OUTPUT_STRIP_TRAILING_WHITESPACE RESULT_VARIABLE _rc)
  if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "sd-msigen guid (${_c}) failed")
  endif()
  file(APPEND "${_guids_file}" "<?define G_${_c} = \"${_g}\" ?>\n")
endforeach()
file(APPEND "${_guids_file}" "</Include>\n")

# 2. Registry rows (packaging/registration.txt) and the WiX localization files of every culture.
sd_msi_step("sd-msigen registry" "${SD_MSIGEN}" registry --in "${SD_MSI_REG}" --out "${_work}/Registry.wxi"
            --flavour "${SD_MSI_FLAVOUR}" --family "${SD_MSI_FAMILY}" --win64 "${SD_MSI_WIN64}")

# 2b. The license page (WixUILicenseRtf): the LICENSE file of the repository, converted to RTF for this build. The text
#     is the only source; no RTF copy is checked in. Backslash, braces and line ends are escaped as RTF needs.
file(READ "${SD_MSI_LICENSE}" _license_text)
string(REPLACE "\r\n" "\n" _license_text "${_license_text}")
string(REPLACE "\\" "\\\\" _license_text "${_license_text}")
string(REPLACE "{" "\\{" _license_text "${_license_text}")
string(REPLACE "}" "\\}" _license_text "${_license_text}")
string(REPLACE "\n" "\\par\n" _license_text "${_license_text}")
set(_license_rtf "${_work}/License.rtf")
file(WRITE "${_license_rtf}"
     "{\\rtf1\\ansi\\ansicpg1252\\deff0{\\fonttbl{\\f0\\fnil\\fcharset0 Tahoma;}}\\viewkind4\\uc1\\pard\\f0\\fs16 ${_license_text}\\par\n}\n")

set(_langs en es fr pt-BR it de)
set(_cultures en-US es-ES fr-FR pt-BR it-IT de-DE)
set(_lcid_en 1033)
set(_lcid_es 3082)
set(_lcid_fr 1036)
set(_lcid_pt-BR 1046)
set(_lcid_it 1040)
set(_lcid_de 1031)
foreach(_l IN LISTS _langs)
  list(FIND _langs "${_l}" _i)
  list(GET _cultures ${_i} _cu)
  sd_msi_step("sd-msigen wxl (${_l})" "${SD_MSIGEN}" wxl --po "${SD_MSI_PO}/${_l}.po" --culture "${_cu}"
              --lcid "${_lcid_${_l}}" --out "${_work}/ShellDrive.${_l}.wxl")
endforeach()

# 3. candle (per flavour; the same objects serve every culture) and light for the en-US base package.
set(_obj "${_work}/ShellDrive.wixobj")
sd_msi_step("candle" "${_candle}" -nologo -arch "${SD_MSI_ARCH}"
            "-I${_work}" "-I${SD_MSI_SRC}" -sw1091
            "-dSD_VERSION=${SD_MSI_VERSION}" "-dSD_FLAVOUR=${SD_MSI_FLAVOUR}"
            "-dSD_UPGRADE_CODE=${SD_MSI_UPGRADE_CODE}" "-dSD_INSTALLER_VERSION=${SD_MSI_INSTALLER_VERSION}"
            "-dSD_PF_DIR=${SD_MSI_PF}" "-dSD_WIN64=${SD_MSI_WIN64}" "-dSD_BIN_DIR=${SD_MSI_BIN}"
            "-dSD_ICON=${SD_MSI_ICON}" "-dSD_LAUNCH=${SD_MSI_LAUNCH}" "-dSD_WITH_SERVICE=${SD_MSI_WITH_SERVICE}"
            "-dSD_LICENSE_RTF=${_license_rtf}"
            -out "${_obj}" "${SD_MSI_SRC}/ShellDrive.wxs")

# ICE suppressions (justified in 04 §8.3; every other ICE stays on):
#   ICE61  same-version upgrade: AllowSameVersionUpgrades lets a flavour switch at the same version replace the
#          other flavour of the same UpgradeCode (04 §8.2).
#   ICE38, ICE43, ICE90  the Start menu shortcut is in ProgramMenuFolder, which is the all-users Start menu under
#          ALLUSERS=1 (InstallScope perMachine); ICE checks the path statically as the user profile.
#   ICE63  the signal-shutdown hook must run between InstallInitialize and RemoveExistingProducts so the agents
#          release their files before a major upgrade removes the old product (04 §8.3).
sd_msi_step("light (en-US)" "${_light}" -nologo -sice:ICE61 -sice:ICE38 -sice:ICE43 -sice:ICE90 -sice:ICE63 -ext WixUIExtension
            -cultures:en-US -loc "${_wix_ui}/WixUI_en-us.wxl" -loc "${_work}/ShellDrive.en.wxl"
            -out "${_base}" "${_obj}")

# 4. One localized package per language, compared with the base by torch into a language transform (C43).
set(_translated es fr pt-BR it de)
set(_wixui_es "WixUI_es-es.wxl")
set(_wixui_fr "WixUI_fr-fr.wxl")
set(_wixui_pt-BR "WixUI_pt-BR.wxl")
set(_wixui_it "WixUI_it-it.wxl")
set(_wixui_de "WixUI_de-de.wxl")
foreach(_l IN LISTS _translated)
  list(FIND _langs "${_l}" _i)
  list(GET _cultures ${_i} _cu)
  set(_loc "${_work}/loc-${_l}.msi")
  set(_mst "${_work}/${_l}.mst")
  # Project overrides of the WiX stock dialog strings (packaging/msi/wixui, one complete file per culture; the stock
  # files are not edited). light takes the first definition of an overridable string, so the override goes first.
  string(TOLOWER "${_cu}" _cu_lc)
  set(_loc_args)
  if(EXISTS "${SD_MSI_SRC}/wixui/WixUI_${_cu_lc}.wxl")
    list(APPEND _loc_args -loc "${SD_MSI_SRC}/wixui/WixUI_${_cu_lc}.wxl")
  endif()
  list(APPEND _loc_args -loc "${_wix_ui}/${_wixui_${_l}}")
  # Intermediate localized packages are not shipped: their ICE run would repeat the base package's (-sval).
  sd_msi_step("light (${_l})" "${_light}" -nologo -sval -ext WixUIExtension
              -cultures:${_cu} ${_loc_args} -loc "${_work}/ShellDrive.${_l}.wxl"
              -out "${_loc}" "${_obj}")
  sd_msi_step("torch (${_l})" "${_torch}" -nologo -t language "${_base}" "${_loc}" -out "${_mst}")
endforeach()

# 5. The shipped package: the base copy with every transform embedded under each LCID of its language.
file(COPY_FILE "${_base}" "${_final}" ONLY_IF_DIFFERENT RESULT _rc)
if(NOT _rc EQUAL 0)
  message(FATAL_ERROR "copy of the base package failed: ${_rc}")
endif()
foreach(_l IN LISTS _translated)
  execute_process(COMMAND "${SD_MSIGEN}" lcids --lang "${_l}" OUTPUT_VARIABLE _lcids
                  OUTPUT_STRIP_TRAILING_WHITESPACE RESULT_VARIABLE _rc)
  if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "sd-msigen lcids (${_l}) failed")
  endif()
  string(REPLACE " " ";" _lcids "${_lcids}")
  set(_args --db "${_final}" --mst "${_work}/${_l}.mst")
  foreach(_id IN LISTS _lcids)
    list(APPEND _args --lcid "${_id}")
  endforeach()
  sd_msi_step("sd-msiembed (${_l})" "${SD_MSIEMBED}" ${_args})
endforeach()

message(STATUS "msi: ${_final}")
