# Message catalog generation (03 §9). PO sources live in l10n/<domain>/<lang>.po.
#
#   sd_add_l10n_catalog(<name> DOMAINS <domain>...)
#
# Runs tools/sdl10n at build time and creates the static library sd_l10n_catalog_<name> holding the
# generated tables, plus the generated header <sd_l10n_<name>_ids.h> with one SD_MSG_* id per entry.
# The build FAILS when any locale is missing a string, has a placeholder mismatch, lacks a CLDR
# plural form, has a non-canonical Plural-Forms header, or breaks the register, mnemonic or length
# rules (03 §9.2), unless the developer configures with -DSD_L10N_ALLOW_INCOMPLETE=ON (missing strings
# then fall back to English at run time).
#
# Debug builds also get the qps-ploc pseudo-locale when SD_L10N_QPS is ON (default); Release tables
# never contain it. The output directory depends on the configuration because the Visual Studio build
# tree is shared by Debug and Release.

set(SD_LANGS en es fr pt-BR it de)

function(sd_add_l10n_catalog name)
  cmake_parse_arguments(L "" "" "DOMAINS" ${ARGN})
  set(_outdir "${SD_GENERATED_DIR}/l10n/$<CONFIG>")
  set(_c "${_outdir}/sd_l10n_${name}.c")
  set(_h "${_outdir}/sd_l10n_${name}_ids.h")
  set(_args --name "${name}" --out-c "${_c}" --out-h "${_h}")
  set(_deps "")
  foreach(_d IN LISTS L_DOMAINS)
    list(APPEND _args --domain "${CMAKE_SOURCE_DIR}/l10n/${_d}")
    foreach(_lang IN LISTS SD_LANGS)
      list(APPEND _deps "${CMAKE_SOURCE_DIR}/l10n/${_d}/${_lang}.po")
    endforeach()
  endforeach()
  if(SD_L10N_ALLOW_INCOMPLETE)
    list(APPEND _args --allow-incomplete)
  endif()
  if(SD_L10N_QPS)
    list(APPEND _args "$<IF:$<CONFIG:Debug>,--qps,--no-qps>")
  else()
    list(APPEND _args --no-qps)
  endif()
  sd_tool_depends(sdl10n _tool_dep)
  add_custom_command(
    OUTPUT "${_c}" "${_h}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${_outdir}"
    COMMAND "$<TARGET_FILE:sdl10n>" ${_args}
    DEPENDS ${_tool_dep} ${_deps}
    COMMENT "sdl10n: catalog '${name}' (${L_DOMAINS})"
    VERBATIM)
  add_library(sd_l10n_catalog_${name} STATIC "${_c}" "${_h}")
  sd_add_tool_dependency(sd_l10n_catalog_${name} sdl10n)
  target_include_directories(sd_l10n_catalog_${name} PUBLIC "${_outdir}")
  target_link_libraries(sd_l10n_catalog_${name} PUBLIC sd_l10n)
  set_target_properties(sd_l10n_catalog_${name} PROPERTIES FOLDER "l10n")
endfunction()
