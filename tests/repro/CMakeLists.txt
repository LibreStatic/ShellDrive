# Reproducible-build checks (04 §12.2), opt-in: label repro, excluded from the default ctest run like bench.
# Each test builds its preset twice (Release, two build directories, one fixed source path) and compares the
# outputs with tools/check-repro.ps1. Run with: ctest --preset <preset> -L repro

foreach(_p x64-modern x86-ia32)
  add_test(NAME repro.${_p}
    COMMAND powershell -NoProfile -ExecutionPolicy Bypass -File "${CMAKE_SOURCE_DIR}/tools/check-repro.ps1"
            -Preset ${_p} -Config Release)
  # Both builds use the same build\repro-a / build\repro-b folders and the first free subst drive: one at a time.
  set_tests_properties(repro.${_p} PROPERTIES LABELS repro TIMEOUT 14400 RESOURCE_LOCK "drive_letter;repro_builds")
endforeach()
