# CTest check of the WixUI string overrides of the MSI (packaging/msi/wixui, docs/dev/m4-notes.md).
#
#   cmake -DSD_SRC=<repo> -DSD_WIX_DIR=<WiX 3.14 root> -P check-wixui.cmake
#
# 1. Coverage: every id of packaging/msi/wixui/dialog-set.txt (the WixUI strings the package's dialog set shows)
#    is defined exactly once in every WixUI_<culture>.wxl override, has a non-empty value, and exists in the WiX
#    stock WixUI_en-us.wxl. An override defines no other id.
# 2. Register lint: the Spanish overrides (voseo, AGENTS.md) contain no usted or tu forms. The list of known forms
#    is small on purpose; it covers the usted and tu pronouns and the imperative and present forms below.

cmake_minimum_required(VERSION 3.12)  # policies for IN_LIST and the CMake script mode

foreach(_v IN ITEMS SD_SRC SD_WIX_DIR)
  if("${${_v}}" STREQUAL "")
    message(FATAL_ERROR "check-wixui: ${_v} is not set")
  endif()
endforeach()

set(_dir "${SD_SRC}/packaging/msi/wixui")
set(_stock "${SD_WIX_DIR}/SDK/wixui/WixUI_en-us.wxl")
set(_failures 0)

# The ids of the dialog set (comment lines start with #).
file(STRINGS "${_dir}/dialog-set.txt" _raw)
set(_ids)
foreach(_l IN LISTS _raw)
  string(STRIP "${_l}" _l)
  if(_l STREQUAL "" OR _l MATCHES "^#")
    continue()
  endif()
  if(NOT _l MATCHES "^[A-Za-z0-9_]+$")
    message(SEND_ERROR "dialog-set.txt: not an id: ${_l}")
    math(EXPR _failures "${_failures} + 1")
  endif()
  list(APPEND _ids "${_l}")
endforeach()
list(LENGTH _ids _count)
if(_count EQUAL 0)
  message(FATAL_ERROR "dialog-set.txt lists no ids")
endif()

# Every id must be a stock WixUI string.
file(READ "${_stock}" _stock_text)
foreach(_id IN LISTS _ids)
  string(FIND "${_stock_text}" "<String Id=\"${_id}\" Overridable=\"yes\">" _pos)
  if(_pos EQUAL -1)
    message(SEND_ERROR "dialog-set.txt: ${_id} is not a WixUI stock string")
    math(EXPR _failures "${_failures} + 1")
  endif()
endforeach()

# Coverage of each override file.
file(GLOB _overrides "${_dir}/WixUI_*.wxl")
if(_overrides STREQUAL "")
  message(FATAL_ERROR "no WixUI_*.wxl overrides in ${_dir}")
endif()
foreach(_file IN LISTS _overrides)
  get_filename_component(_name "${_file}" NAME)
  file(READ "${_file}" _text)
  string(REGEX MATCHALL "<String Id=\"[A-Za-z0-9_]+\"" _tags "${_text}")
  set(_defined)
  foreach(_t IN LISTS _tags)
    string(REGEX REPLACE "^<String Id=\"([A-Za-z0-9_]+)\"$" "\\1" _d "${_t}")
    list(APPEND _defined "${_d}")
  endforeach()
  foreach(_id IN LISTS _ids)
    set(_n 0)
    foreach(_d IN LISTS _defined)
      if(_d STREQUAL _id)
        math(EXPR _n "${_n} + 1")
      endif()
    endforeach()
    if(NOT _n EQUAL 1)
      message(SEND_ERROR "${_name}: ${_id} is defined ${_n} times (expected once)")
      math(EXPR _failures "${_failures} + 1")
    endif()
  endforeach()
  foreach(_d IN LISTS _defined)
    list(FIND _ids "${_d}" _i)
    if(_i EQUAL -1)
      message(SEND_ERROR "${_name}: ${_d} is not in dialog-set.txt")
      math(EXPR _failures "${_failures} + 1")
    endif()
  endforeach()
  if(_text MATCHES "Overridable=\"yes\"></String>")
    message(SEND_ERROR "${_name}: an empty value")
    math(EXPR _failures "${_failures} + 1")
  endif()
endforeach()

# Register lint of the Spanish overrides (voseo): usted and tu forms, with known imperatives and present forms.
set(_es_forbidden
    usted ustedes ud uds "tú"
    haga seleccione vuelva espere pulse ejecute elija escriba acepte instale cancele "continúe" finalice reinicie
    lea quite cambie actualice revise desea
    haz pulsa elige escribe acepta instala vuelve espera quita "continúa" finaliza reinicia selecciona cancela ejecuta revisa)
file(READ "${_dir}/WixUI_es-es.wxl" _es)
# ';' is a list separator in CMake: the text has none that matters for the lint, so it becomes a space.
string(REPLACE ";" " " _es "${_es}")
string(REPLACE "\n" ";" _es_lines "${_es}")
foreach(_line IN LISTS _es_lines)
  if(NOT _line MATCHES "<String Id=\"([A-Za-z0-9_]+)\" Overridable=\"yes\">(.*)</String>")
    continue()
  endif()
  set(_id "${CMAKE_MATCH_1}")
  set(_value "${CMAKE_MATCH_2}")
  # Markup and placeholders are not words: WiX font tags, [Property] references and the &amp; mnemonics.
  string(REGEX REPLACE "\\{\\\\[A-Za-z_]+\\}" " " _value "${_value}")
  string(REGEX REPLACE "\\[[A-Za-z_]+\\]" " " _value "${_value}")
  string(REPLACE "&amp;" " " _value "${_value}")
  foreach(_p IN ITEMS "," "." "¿" "?" "¡" "!" "(" ")" "\"" "'" ":" "-" "/" "{" "}" "&" "<" ">")
    string(REPLACE "${_p}" " " _value "${_value}")
  endforeach()
  string(TOLOWER "${_value}" _value)
  string(REPLACE " " ";" _words "${_value}")
  foreach(_w IN LISTS _words)
    if(_w STREQUAL "")
      continue()
    endif()
    if(_w IN_LIST _es_forbidden)
      message(SEND_ERROR "WixUI_es-es.wxl: ${_id} uses the usted or tu form '${_w}' (voseo, AGENTS.md)")
      math(EXPR _failures "${_failures} + 1")
    endif()
  endforeach()
endforeach()

if(_failures GREATER 0)
  message(FATAL_ERROR "check-wixui: ${_failures} problem(s)")
endif()
message(STATUS "check-wixui: ${_count} ids in every override, Spanish register clean")
