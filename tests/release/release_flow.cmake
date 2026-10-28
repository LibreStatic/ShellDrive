# sd-release end to end (docs/design/04 §6.1, §9.2, §9.3, §12.3; TM-R36, TM-R37, TM-R38). Run by ctest as
#   cmake -DSD_RELEASE=<sd-release.exe> -DWORK=<scratch dir> -P release_flow.cmake
#
# Every key here is a TEST key: the seeds are fixed strings in this file, used only in this test, never a release key
# and never in installer/keys/. Nothing touches the network. Any failed step stops the script with FATAL_ERROR.

if(NOT SD_RELEASE OR NOT WORK)
  message(FATAL_ERROR "SD_RELEASE and WORK are required")
endif()

set(SEED_STABLE "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
set(SEED_BETA   "a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0")

file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}")
file(MAKE_DIRECTORY "${WORK}/root")

# rel(<expected exit code> <output variable> <sd-release arguments...>)
function(rel expect out_var)
  execute_process(COMMAND "${SD_RELEASE}" ${ARGN}
                  WORKING_DIRECTORY "${WORK}"
                  RESULT_VARIABLE rc
                  OUTPUT_VARIABLE out
                  ERROR_VARIABLE err)
  if(NOT rc EQUAL expect)
    message(FATAL_ERROR "sd-release ${ARGN}: exit ${rc}, expected ${expect}\n${out}${err}")
  endif()
  set(${out_var} "${out}" PARENT_SCOPE)
endfunction()

function(expect_contains text needle)
  string(FIND "${text}" "${needle}" pos)
  if(pos EQUAL -1)
    message(FATAL_ERROR "expected '${needle}' in:\n${text}")
  endif()
endfunction()

# ---- keys: public keys and key IDs from the seed files ----
file(WRITE "${WORK}/stable.seed" "${SEED_STABLE}\n")
file(WRITE "${WORK}/beta.seed" "${SEED_BETA}\n")
rel(0 pub_out pubkey --seed stable.seed)
string(REGEX REPLACE "^pub ([0-9a-f]+) kid ([0-9a-f]+).*" "\\1" PUB_STABLE "${pub_out}")
string(REGEX REPLACE "^pub ([0-9a-f]+) kid ([0-9a-f]+).*" "\\2" KID_STABLE "${pub_out}")
string(LENGTH "${PUB_STABLE}" n)
if(NOT n EQUAL 64)
  message(FATAL_ERROR "pubkey output: ${pub_out}")
endif()
file(WRITE "${WORK}/stable.pub" "${PUB_STABLE}\n")
rel(0 pub_beta_out pubkey --seed beta.seed)
string(REGEX REPLACE "^pub ([0-9a-f]+) kid.*" "\\1" PUB_BETA "${pub_beta_out}")
file(WRITE "${WORK}/beta.pub" "${PUB_BETA}\n")

# ---- payload table (one flavour per setup EXE) ----
file(WRITE "${WORK}/payload.cab" "MSCF test payload bytes, not a real cabinet")
rel(0 out table --channel stable --flavour x86-ia32 --cab payload.cab --out table.txt)
file(READ "${WORK}/table.txt" table_text)
expect_contains("${table_text}" "shelldrive-payload-table 1\nproduct com.librestatic.shelldrive\nchannel stable\nx86-ia32 ")
rel(0 out check-table --table table.txt --cab payload.cab)
expect_contains("${out}" "OK x86-ia32 ")
file(WRITE "${WORK}/other.cab" "a different payload")
rel(3 out check-table --table table.txt --cab other.cab)
rel(1 out table --channel gamma --flavour x86-ia32 --cab payload.cab --out bad.txt)
rel(1 out table --channel stable --flavour X86 --cab payload.cab --out bad.txt)

# ---- payload signature (TM-R38): session 1 of 2 signs the tables ----
rel(0 out session --kind payload --out "${WORK}" table.txt)
file(READ "${WORK}/SESSION.txt" session_text)
expect_contains("${session_text}" "kind payload")
expect_contains("${session_text}" "message sha256:")
rel(0 out sign --kind payload --seed stable.seed --in table.txt --out payload.sig --sig-only)
file(READ "${WORK}/payload.sig" sig_text)
string(LENGTH "${sig_text}" n)
if(NOT n EQUAL 118)
  message(FATAL_ERROR "payload sig line is ${n} bytes, expected 118")
endif()
rel(0 out verify --kind payload --pub stable.pub --in table.txt --sig payload.sig)
expect_contains("${out}" "OK payload")
# The same table with one changed digit: refused.
file(READ "${WORK}/table.txt" t)
string(REPLACE "x86-ia32 " "x86-ia33 " t_bad "${t}")
file(WRITE "${WORK}/table_bad.txt" "${t_bad}")
rel(3 out verify --kind payload --pub stable.pub --in table_bad.txt --sig payload.sig)
# A beta key does not verify a stable signature (channel and key binding, TM-R37).
rel(3 out verify --kind payload --pub beta.pub --in table.txt --sig payload.sig)
# Domain separation: the sums domain does not verify a payload signature.
rel(0 out sign --kind sums --seed stable.seed --in table.txt --out sums.sig --sig-only)
rel(3 out verify --kind payload --pub stable.pub --in table.txt --sig sums.sig)
# A body without its final LF is not signed.
file(WRITE "${WORK}/nolf.txt" "x")
rel(2 out sign --kind payload --seed stable.seed --in nolf.txt --out bad.sig --sig-only)

# ---- manifest (04 §9.2): stable, 29 days, verified whole ----
file(WRITE "${WORK}/root/setup.exe" "setup stand-in bytes for the manifest file line")
rel(0 out hash root/setup.exe)
expect_contains("${out}" "sha256:")
set(SPEC_STABLE
"product com.librestatic.shelldrive
channel stable
keyset 1
serial 2026102401
version 1.0.0
released 2026-10-24T12:00:00Z
expires 2026-11-23T00:00:00Z
notes https://github.com/LibreStatic/ShellDrive/releases/tag/v1.0.0
min-os x64-modern 10.0
base https://github.com/LibreStatic/ShellDrive/releases/download/v1.0.0/
file setup-universal ShellDrive-1.0.0-setup.exe setup.exe
")
file(WRITE "${WORK}/spec.txt" "${SPEC_STABLE}")
rel(0 out manifest --spec spec.txt --root "${WORK}/root" --out body.txt)
file(READ "${WORK}/body.txt" body_text)
expect_contains("${body_text}" "shelldrive-manifest 1\n")
expect_contains("${body_text}" "file setup-universal ShellDrive-1.0.0-setup.exe ")
expect_contains("${body_text}" " sha256:")
rel(0 out sign --kind manifest --seed stable.seed --in body.txt --out manifest.txt)
rel(0 out verify --kind manifest --pub stable.pub --in manifest.txt)
expect_contains("${out}" "manifest channel stable serial 2026102401")
expect_contains("${out}" "OK manifest")
file(READ "${WORK}/manifest.txt" m_text)
string(REPLACE "serial 2026102401" "serial 2026102402" m_bad "${m_text}")
file(WRITE "${WORK}/manifest_bad.txt" "${m_bad}")
rel(3 out verify --kind manifest --pub stable.pub --in manifest_bad.txt)
rel(3 out verify --kind manifest --pub beta.pub --in manifest.txt)
rel(1 out verify --kind manifest --pub stable.pub --in manifest.txt --sig payload.sig)

# Freshness (TM-R36): stable at most 30 days, beta at most 14 days.
string(REPLACE "expires 2026-11-23T00:00:00Z" "expires 2026-12-30T00:00:00Z" long_spec "${SPEC_STABLE}")
file(WRITE "${WORK}/spec_long.txt" "${long_spec}")
rel(1 out manifest --spec spec_long.txt --root "${WORK}/root" --out body_long.txt)
string(REPLACE "channel stable" "channel beta" beta_spec "${SPEC_STABLE}")
string(REPLACE "expires 2026-11-23T00:00:00Z" "expires 2026-11-06T12:00:00Z" beta_ok "${beta_spec}")
string(REPLACE "expires 2026-11-23T00:00:00Z" "expires 2026-11-08T12:00:00Z" beta_long "${beta_spec}")
file(WRITE "${WORK}/spec_beta_ok.txt" "${beta_ok}")
file(WRITE "${WORK}/spec_beta_long.txt" "${beta_long}")
rel(0 out manifest --spec spec_beta_ok.txt --root "${WORK}/root" --out body_beta.txt)
rel(1 out manifest --spec spec_beta_long.txt --root "${WORK}/root" --out body_beta_long.txt)
# A file name with a separator is refused.
string(REPLACE "setup.exe" "..\\evil.exe" evil_spec "${SPEC_STABLE}")
file(WRITE "${WORK}/spec_evil.txt" "${evil_spec}")
rel(1 out manifest --spec spec_evil.txt --root "${WORK}/root" --out body_evil.txt)

# ---- SHA256SUMS (session 2 of 2 signs the sums file with the same stable key) ----
rel(0 out sums --out SHA256SUMS root/setup.exe payload.cab)
file(READ "${WORK}/SHA256SUMS" sums_text)
expect_contains("${sums_text}" "  setup.exe\n")
rel(0 out sign --kind sums --seed stable.seed --in SHA256SUMS --out sums.sig --sig-only)
rel(0 out verify --kind sums --pub stable.pub --in SHA256SUMS --sig sums.sig)
expect_contains("${out}" "OK sums")
string(REPLACE "setup.exe" "setup.ex3" sums_bad "${sums_text}")
file(WRITE "${WORK}/SHA256SUMS_bad" "${sums_bad}")
rel(3 out verify --kind sums --pub stable.pub --in SHA256SUMS_bad --sig sums.sig)

message(STATUS "release flow: all checks passed")
