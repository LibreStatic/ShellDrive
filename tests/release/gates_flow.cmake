# Release gates record (docs/design/04 §12.3; r21). Run by ctest as
#   cmake -DSD_RELEASE=<sd-release.exe> -DWORK=<scratch dir> -P gates_flow.cmake
#
# The seed is a TEST seed, used only here; the records are fixtures. Exit codes checked: 0 ok, 1 usage,
# 2 malformed record or I/O, 3 refused. Any failed step stops the script with FATAL_ERROR.

if(NOT SD_RELEASE OR NOT WORK)
  message(FATAL_ERROR "SD_RELEASE and WORK are required")
endif()

set(SEED_TEST "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
set(C "0123456789abcdef0123456789abcdef01234567")
set(OTHER "fedcba9876543210fedcba9876543210fedcba98")

file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}")

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

# put(<name> <text>): WORK/<name>. On Windows file(WRITE) is text mode, so every "\n" is written as CRLF; the record
# reader takes CRLF as LF, which is why the valid fixtures pass. A bare CR is written as is (see bare_cr.txt).
function(put name text)
  file(WRITE "${WORK}/${name}" "${text}")
endfunction()

set(STABLE_OK "release-gates 1
version 1.0.0
commit ${C}
channel stable
gate ci-local pass 2026-10-26 FacuM
gate lab pass 2026-10-27 FacuM all VMs
gate review-pass1 pass 2026-06-12 FacuM
gate authenticode pass 2026-10-20 FacuM
gate review-pass2 pass 2026-10-27 FacuM
gate p3-tests pass 2026-10-27 FacuM
gate rebuild pass 2026-10-28 FacuM
approved FacuM 2026-10-28
")

set(BETA_OK "release-gates 1
version 1.0.0
commit ${C}
channel beta
gate ci-local pass 2026-10-26 FacuM
gate lab waived 2026-10-27 FacuM two VMs deferred to the next beta
gate review-pass1 pass 2026-06-12 FacuM
gate authenticode pass 2026-10-20 FacuM
approved FacuM 2026-10-28
")

# ---- valid records ----
put(stable.txt "${STABLE_OK}")
rel(0 out gates check stable.txt --version 1.0.0 --commit ${C})
expect_contains("${out}" "gates ok version 1.0.0 commit ${C} channel stable")

put(beta.txt "${BETA_OK}")
rel(0 out gates check beta.txt --version 1.0.0 --commit ${C})
expect_contains("${out}" "channel beta")

# Comment and blank lines are allowed anywhere before approved.
put(comments.txt "# written by the maintainer\n\n${STABLE_OK}")
rel(0 out gates check comments.txt --version 1.0.0 --commit ${C})

# ---- wrong version or commit: refused (3) ----
rel(3 out gates check stable.txt --version 1.0.1 --commit ${C})
rel(3 out gates check stable.txt --version 1.0.0 --commit ${OTHER})

# ---- a required gate missing or failed: refused (3) ----
string(REPLACE "gate rebuild pass 2026-10-28 FacuM\n" "" t "${STABLE_OK}")
put(missing_gate.txt "${t}")
rel(3 out gates check missing_gate.txt --version 1.0.0 --commit ${C})

string(REPLACE "gate lab pass 2026-10-27 FacuM all VMs" "gate lab fail 2026-10-27 FacuM all VMs" t "${STABLE_OK}")
put(failed_gate.txt "${t}")
rel(3 out gates check failed_gate.txt --version 1.0.0 --commit ${C})

string(REPLACE "gate lab waived 2026-10-27 FacuM two VMs deferred to the next beta\n" "" t "${BETA_OK}")
put(beta_missing_lab.txt "${t}")
rel(3 out gates check beta_missing_lab.txt --version 1.0.0 --commit ${C})

# ---- waivers: refused where the table does not allow them (3) ----
string(REPLACE "gate ci-local pass 2026-10-26 FacuM" "gate ci-local waived 2026-10-26 FacuM not allowed" t "${STABLE_OK}")
put(waived_ci.txt "${t}")
rel(3 out gates check waived_ci.txt --version 1.0.0 --commit ${C})

string(REPLACE "gate lab pass 2026-10-27 FacuM all VMs" "gate lab waived 2026-10-27 FacuM slow VM" t "${STABLE_OK}")
put(waived_lab_stable.txt "${t}")
rel(3 out gates check waived_lab_stable.txt --version 1.0.0 --commit ${C})

string(REPLACE "gate ci-local pass 2026-10-26 FacuM" "gate ci-local waived 2026-10-26 FacuM not allowed" t "${BETA_OK}")
put(waived_ci_beta.txt "${t}")
rel(3 out gates check waived_ci_beta.txt --version 1.0.0 --commit ${C})

# A waived lab gate needs its note (malformed, 2).
string(REPLACE "gate lab waived 2026-10-27 FacuM two VMs deferred to the next beta" "gate lab waived 2026-10-27 FacuM" t "${BETA_OK}")
put(waived_no_note.txt "${t}")
rel(2 out gates check waived_no_note.txt --version 1.0.0 --commit ${C})

# ---- not approved: refused (3) ----
string(REPLACE "approved FacuM 2026-10-28\n" "" t "${STABLE_OK}")
put(not_approved.txt "${t}")
rel(3 out gates check not_approved.txt --version 1.0.0 --commit ${C})

# ---- channel rules: a gate not allowed on the channel is malformed (2) ----
string(REPLACE "approved FacuM 2026-10-28\n" "gate review-pass2 pass 2026-10-27 FacuM\napproved FacuM 2026-10-28\n" t "${BETA_OK}")
put(beta_pass2.txt "${t}")
rel(2 out gates check beta_pass2.txt --version 1.0.0 --commit ${C})

# ---- malformed lines: exit 2 ----
string(REPLACE "release-gates 1" "release-gates 2" t "${STABLE_OK}")
put(bad_magic.txt "${t}")
rel(2 out gates check bad_magic.txt --version 1.0.0 --commit ${C})

put(crlf.txt "${STABLE_OK}")
rel(0 out gates check crlf.txt --version 1.0.0 --commit ${C})

# A CR that is not part of a CRLF pair is refused (2).
string(REPLACE "approved FacuM" "\rapproved FacuM" t "${STABLE_OK}")
put(bare_cr.txt "${t}")
rel(2 out gates check bare_cr.txt --version 1.0.0 --commit ${C})

string(REPLACE "gate lab pass" "gate labb pass" t "${STABLE_OK}")
put(unknown_gate.txt "${t}")
rel(2 out gates check unknown_gate.txt --version 1.0.0 --commit ${C})

string(REPLACE "approved FacuM 2026-10-28\n" "gate ci-local pass 2026-10-26 FacuM\napproved FacuM 2026-10-28\n" t "${STABLE_OK}")
put(duplicate_gate.txt "${t}")
rel(2 out gates check duplicate_gate.txt --version 1.0.0 --commit ${C})

string(REPLACE "gate lab pass" "gate  lab pass" t "${STABLE_OK}")
put(double_space.txt "${t}")
rel(2 out gates check double_space.txt --version 1.0.0 --commit ${C})

string(REPLACE "2026-10-27 FacuM all VMs" "2026-13-27 FacuM all VMs" t "${STABLE_OK}")
put(bad_date.txt "${t}")
rel(2 out gates check bad_date.txt --version 1.0.0 --commit ${C})

string(REPLACE "gate lab pass" "gate lab passed" t "${STABLE_OK}")
put(bad_status.txt "${t}")
rel(2 out gates check bad_status.txt --version 1.0.0 --commit ${C})

string(REPLACE "commit ${C}" "commit 0123456789ABCDEF0123456789abcdef01234567" t "${STABLE_OK}")
put(upper_commit.txt "${t}")
rel(2 out gates check upper_commit.txt --version 1.0.0 --commit ${C})

string(REPLACE "channel stable\n" "" t "${STABLE_OK}")
put(missing_header.txt "${t}")
rel(2 out gates check missing_header.txt --version 1.0.0 --commit ${C})

set(t "${STABLE_OK}gate rebuild pass 2026-10-28 FacuM\n")
put(after_approved.txt "${t}")
rel(2 out gates check after_approved.txt --version 1.0.0 --commit ${C})

string(REPLACE "approved FacuM 2026-10-28\n" "approved FacuM 2026-10-28 \n" t "${STABLE_OK}")
put(trailing_space.txt "${t}")
rel(2 out gates check trailing_space.txt --version 1.0.0 --commit ${C})

string(REPLACE "approved FacuM 2026-10-28\n" "approved FacuM 2026-10-28" t "${STABLE_OK}")
put(no_final_lf.txt "${t}")
rel(2 out gates check no_final_lf.txt --version 1.0.0 --commit ${C})

string(REPLACE "approved FacuM 2026-10-28\n" "bogus line\napproved FacuM 2026-10-28\n" t "${STABLE_OK}")
put(unknown_line.txt "${t}")
rel(2 out gates check unknown_line.txt --version 1.0.0 --commit ${C})

string(ASCII 195 169 e_acute)
string(REPLACE "all VMs" "caf${e_acute}" t "${STABLE_OK}")
put(non_ascii.txt "${t}")
rel(2 out gates check non_ascii.txt --version 1.0.0 --commit ${C})

rel(2 out gates check missing_file_does_not_exist.txt --version 1.0.0 --commit ${C})
rel(1 out gates check stable.txt --version 1.0.0)

# ---- sign refuses unless the record validates (04 §12.3) ----
put(stable.seed "${SEED_TEST}\n")
put(body.txt "sums body for the gate test\n")
put(payload_body.txt "shelldrive-payload-table 1\nchannel stable\n")
put(manifest_body.txt "shelldrive-manifest 1\nchannel stable\nversion 1.0.1\n")

rel(1 out sign --kind sums --seed stable.seed --in body.txt --out nogate.sig --sig-only)

rel(0 out sign --kind sums --seed stable.seed --in body.txt --out ok.sig --sig-only
    --gates stable.txt --version 1.0.0 --commit ${C})
expect_contains("${out}" "signed kind sums")
if(NOT EXISTS "${WORK}/ok.sig")
  message(FATAL_ERROR "sign with a valid gates record wrote no signature")
endif()

rel(3 out sign --kind sums --seed stable.seed --in body.txt --out refused.sig --sig-only
    --gates failed_gate.txt --version 1.0.0 --commit ${C})
if(EXISTS "${WORK}/refused.sig")
  message(FATAL_ERROR "sign wrote a signature for a refused gates record")
endif()
rel(3 out sign --kind sums --seed stable.seed --in body.txt --out refused.sig --sig-only
    --gates stable.txt --version 1.0.0 --commit ${OTHER})
rel(2 out sign --kind sums --seed stable.seed --in body.txt --out refused.sig --sig-only
    --gates bad_date.txt --version 1.0.0 --commit ${C})

# The body's channel must be the record's channel.
rel(3 out sign --kind payload --seed stable.seed --in payload_body.txt --out refused.sig --sig-only
    --gates beta.txt --version 1.0.0 --commit ${C})
rel(0 out sign --kind payload --seed stable.seed --in payload_body.txt --out payload.sig --sig-only
    --gates stable.txt --version 1.0.0 --commit ${C})

# A manifest's version must be the record's version.
rel(3 out sign --kind manifest --seed stable.seed --in manifest_body.txt --out refused.sig
    --gates stable.txt --version 1.0.0 --commit ${C})

# Missing gates arguments are a usage error.
rel(1 out sign --kind sums --seed stable.seed --in body.txt --out nogate.sig --sig-only)

message(STATUS "release gates: all checks passed")
