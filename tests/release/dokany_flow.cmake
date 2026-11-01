# dokany.lock verification (docs/design/04 §7.3; TM-R23, D32): `sd-release dokany verify` end to end with fake
# upstream files. Run by ctest as
#   cmake -DSD_RELEASE=<sd-release.exe> -DWORK=<scratch dir> -P dokany_flow.cmake
#
# The fake files are small text files written here; the lock is generated from their real sizes and SHA-256
# (`sd-release hash`), the way installer/dokany/dokany.lock was recorded. Nothing is downloaded. Exit codes
# checked: 0 ok, 1 usage, 2 malformed lock, 3 a file is missing or its size or SHA-256 differs. Any failed step
# stops the script with FATAL_ERROR.

if(NOT SD_RELEASE OR NOT WORK)
  message(FATAL_ERROR "SD_RELEASE and WORK are required")
endif()

file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}/files")

# rel(<expected exit code> <output variable> <sd-release arguments...>): as in release_flow.cmake, but the
# variable receives stdout AND stderr — the refusals of `dokany verify` are printed on stderr.
function(rel expect out_var)
  execute_process(COMMAND "${SD_RELEASE}" ${ARGN}
                  WORKING_DIRECTORY "${WORK}"
                  RESULT_VARIABLE rc
                  OUTPUT_VARIABLE out
                  ERROR_VARIABLE err)
  if(NOT rc EQUAL expect)
    message(FATAL_ERROR "sd-release ${ARGN}: exit ${rc}, expected ${expect}\n${out}${err}")
  endif()
  set(${out_var} "${out}${err}" PARENT_SCOPE)
endfunction()

function(expect_contains text needle)
  string(FIND "${text}" "${needle}" pos)
  if(pos EQUAL -1)
    message(FATAL_ERROR "expected '${needle}' in:\n${text}")
  endif()
endfunction()

# hash_of(<file name relative to WORK> <out hash> <out size>)
function(hash_of f out_hash out_size)
  rel(0 out hash "files/${f}")
  if(NOT out MATCHES "^sha256:([0-9a-f]+) ([0-9]+) ")
    message(FATAL_ERROR "hash output: ${out}")
  endif()
  set(${out_hash} "${CMAKE_MATCH_1}" PARENT_SCOPE)
  set(${out_size} "${CMAKE_MATCH_2}" PARENT_SCOPE)
endfunction()

# ---- the fake upstream files and the lock generated from them ----
file(WRITE "${WORK}/files/Dokan_x64.msi" "fake x64 msi bytes for the dokany test\n")
file(WRITE "${WORK}/files/Dokan_x86.msi" "fake x86 msi bytes\n")
file(WRITE "${WORK}/files/DokanSetup.exe" "fake bundle bytes\n")
hash_of("Dokan_x64.msi" H64 S64)
hash_of("Dokan_x86.msi" H86 S86)
hash_of("DokanSetup.exe" HB SB)

set(X64_LINE "file x64 msi Dokan_x64.msi ${S64} ${H64} {31A8F445-2AC6-494B-819C-4F4E1B2AECF1} none")
set(LOCK_TEXT
"# test lock for the dokany test
dokany-lock 1
version 2.3.1.1000
min-api 2.1.0
signer-cn LEOSAC
signer-issuer-cn Certum Extended Validation Code Signing 2021 CA
url-upstream https://github.com/dokan-dev/dokany/releases/download/v2.3.1.1000/
url-mirror -
checked 2026-11-01
${X64_LINE}
file x86 msi Dokan_x86.msi ${S86} ${H86} {B08DE90A-F064-4ADC-99AC-2EC933417CC5} none
file all bundle DokanSetup.exe ${SB} ${HB} - -
")
file(WRITE "${WORK}/lock.txt" "${LOCK_TEXT}")

# ---- ok: every file matches, whole lock or one arch plus the bundle ----
rel(0 out dokany verify --lock lock.txt --dir files)
expect_contains("${out}" "OK x64 msi Dokan_x64.msi ${S64} sha256:${H64}")
expect_contains("${out}" "OK x86 msi Dokan_x86.msi ${S86} sha256:${H86}")
expect_contains("${out}" "OK all bundle DokanSetup.exe ${SB} sha256:${HB}")
expect_contains("${out}" "dokany ok files 3")
rel(0 out dokany verify --lock lock.txt --dir files --arch x64)
expect_contains("${out}" "dokany ok files 2")

# ---- one file differs: exit 3, the others still reported ----
file(APPEND "${WORK}/files/Dokan_x86.msi" "one byte too many")
rel(3 out dokany verify --lock lock.txt --dir files)
expect_contains("${out}" "OK x64 msi Dokan_x64.msi")
expect_contains("${out}" "Dokan_x86.msi")
# --arch x64 only checks the x64 file and the bundle: still ok with a broken x86 file.
rel(0 out dokany verify --lock lock.txt --dir files --arch x64)
expect_contains("${out}" "dokany ok files 2")

# ---- --arch of an arch with only the bundle pinned: the bundle alone is checked, exit 0 ----
rel(0 out dokany verify --lock lock.txt --dir files --arch arm64)
expect_contains("${out}" "OK all bundle DokanSetup.exe")
expect_contains("${out}" "dokany ok files 1")

# ---- an arch the lock pins nowhere (no matching row and no bundle row): exit 3 ----
file(WRITE "${WORK}/lock-nobundle.txt"
"# no bundle row
dokany-lock 1
version 2.3.1.1000
min-api 2.1.0
checked 2026-11-01
file x64 msi Dokan_x64.msi ${S64} ${H64} {31A8F445-2AC6-494B-819C-4F4E1B2AECF1} none
")
rel(3 out dokany verify --lock lock-nobundle.txt --dir files --arch arm64)
expect_contains("${out}" "pins no file for arch arm64")

# ---- a missing file: exit 3 ----
file(REMOVE "${WORK}/files/Dokan_x86.msi")
rel(3 out dokany verify --lock lock.txt --dir files --arch x86)
expect_contains("${out}" "missing Dokan_x86.msi")

# ---- a lock whose size or hash differs from the files: exit 3 ----
file(WRITE "${WORK}/files/Dokan_x86.msi" "fake x86 msi bytes\n")
string(REPLACE "file x64 msi Dokan_x64.msi ${S64}" "file x64 msi Dokan_x64.msi 12345"
       lock_bad_size "${LOCK_TEXT}")
file(WRITE "${WORK}/lock-size.txt" "${lock_bad_size}")
rel(3 out dokany verify --lock lock-size.txt --dir files --arch x64)
expect_contains("${out}" "the lock pins 12345")
string(REPLACE "${H64}" "0000000000000000000000000000000000000000000000000000000000000000"
       lock_bad_hash "${LOCK_TEXT}")
file(WRITE "${WORK}/lock-hash.txt" "${lock_bad_hash}")
rel(3 out dokany verify --lock lock-hash.txt --dir files --arch x64)
expect_contains("${out}" "sha256 ")

# ---- malformed locks: exit 2 ----
# a wrong format version, no value after the key, a key line in the place of the header
foreach(bad_header IN ITEMS "dokany-lock 2" "dokany-lock" "version 2.3.1.1000")
  string(REPLACE "dokany-lock 1" "${bad_header}" lock_magic "${LOCK_TEXT}")
  file(WRITE "${WORK}/lock-magic.txt" "${lock_magic}")
  rel(2 out dokany verify --lock lock-magic.txt --dir files)
endforeach()
# no header line at all
file(WRITE "${WORK}/lock-nomagic.txt"
"# no header
version 2.3.1.1000
checked 2026-11-01
file all bundle DokanSetup.exe ${SB} ${HB} - -
")
rel(2 out dokany verify --lock lock-nomagic.txt --dir files)

# unknown key, duplicate key, invalid version, invalid date
foreach(bad_kv IN ITEMS
    "signer-street 39 rue Principale"
    "version 2.3.1.1000|version 2.3.1.1000"
    "version two"
    "checked 2026-13-40")
  string(REPLACE "|" "\n" bad_kv "${bad_kv}")
  string(REPLACE "min-api 2.1.0" "min-api 2.1.0\n${bad_kv}" lock_key "${LOCK_TEXT}")
  file(WRITE "${WORK}/lock-key.txt" "${lock_key}")
  rel(2 out dokany verify --lock lock-key.txt --dir files)
endforeach()

# malformed file lines (the whole x64 line replaced by a broken one)
string(TOUPPER "${H64}" H64_UP)
foreach(bad_line IN ITEMS
    "file x64 msi Dokan_x64.msi"
    "file x64 msi Dokan_x64.msi ${S64} ${H64} {31A8F445-2AC6-494B-819C-4F4E1B2AECF1}"
    "file x64 msi Dokan_x64.msi ${S64} ${H64_UP} {31A8F445-2AC6-494B-819C-4F4E1B2AECF1} none"
    "file x64 msi Dokan_x64.msi ${S64} ${H64} 31A8F445-2AC6-494B-819C-4F4E1B2AECF1 none"
    "file x64 msi Dokan_x64.msi ${S64} ${H64} {31A8F445-2AC6-494B-819C-4F4E1B2AECF1} maybe"
    "file x64 msi ..\\evil ${S64} ${H64} - none"
    "file x64 msi Dokan_x64.msi ${S64} ${H64} {31A8F445-2AC6-494B-819C-4F4E1B2AECF1} none extra"
    "file x64 msi Dokan_x64.msi ${S64} ${H64} {31A8F445-2AC6-494B-819C-4F4E1B2AECF1} none ")
  string(REPLACE "${X64_LINE}" "${bad_line}" lock_key "${LOCK_TEXT}")
  file(WRITE "${WORK}/lock-key.txt" "${lock_key}")
  rel(2 out dokany verify --lock lock-key.txt --dir files)
endforeach()

# duplicate file line (same arch and form)
string(REPLACE "file x86 msi Dokan_x86.msi" "file x64 msi Dokan_x64.msi" lock_dup "${LOCK_TEXT}")
file(WRITE "${WORK}/lock-dup.txt" "${lock_dup}")
rel(2 out dokany verify --lock lock-dup.txt --dir files)

# a tab is not printable per the grammar
string(REPLACE "signer-cn LEOSAC" "signer-cn LEOSAC\t" lock_tab "${LOCK_TEXT}")
file(WRITE "${WORK}/lock-tab.txt" "${lock_tab}")
rel(2 out dokany verify --lock lock-tab.txt --dir files)

# ---- usage: exit 1 ----
rel(1 out dokany verify --lock lock.txt)
rel(1 out dokany verify --dir files)
rel(1 out dokany frobnicate)

message(STATUS "dokany flow: all checks passed")
