# Reproducible-build checks (04 §12.2), opt-in: label repro, excluded from the default ctest run like bench.
# Each test builds its preset twice (Release, two build directories, one fixed source path) and compares the
# outputs with tools/check-repro.ps1. Run with: ctest --preset <preset> -L repro
#
# One test per tree, this tree's own flavour: a check builds its preset twice, which needs that flavour's
# whole toolchain here — and the runners that skip the v141_xp setup step (04 §11.1) cannot build the x86
# trees at all. The analysis and fuzz trees ship nothing: no check there.
foreach(_p x64-modern x64-xp x86-ia32 x86-sse2)
  if(SD_FLAVOUR STREQUAL _p)
    add_test(NAME repro.${_p}
      COMMAND powershell -NoProfile -ExecutionPolicy Bypass -File "${CMAKE_SOURCE_DIR}/tools/check-repro.ps1"
              -Preset ${_p} -Config Release)
    # Both builds use the same build\repro-a / build\repro-b folders and the first free subst drive: one at a time.
    set_tests_properties(repro.${_p} PROPERTIES LABELS repro TIMEOUT 14400 RESOURCE_LOCK "drive_letter;repro_builds")
  endif()
endforeach()
