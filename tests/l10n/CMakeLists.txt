# sdl10n self-tests: the build must fail on missing strings (M0 requirement, 03 §9.2) unless
# --allow-incomplete is passed, and must fail on structural errors in every case. Failure cases
# match the expected diagnostic, so a crash cannot pass. The register, mnemonic and length rules
# (03 §9.2) each have a failing and a passing fixture under fixtures/.

set(_fx "${CMAKE_CURRENT_SOURCE_DIR}/fixtures")
set(_check "${CMAKE_CURRENT_SOURCE_DIR}/check_diagnostics.cmake")
set(_qps "${CMAKE_CURRENT_SOURCE_DIR}/check_qps.cmake")

add_test(NAME l10n.real_catalogs_complete COMMAND sdl10n --check --domain "${CMAKE_SOURCE_DIR}/l10n/cli")
add_test(NAME l10n.empty_catalogs_check
         COMMAND sdl10n --check --domain "${CMAKE_SOURCE_DIR}/l10n/common"
                 --domain "${CMAKE_SOURCE_DIR}/l10n/ui" --domain "${CMAKE_SOURCE_DIR}/l10n/shell")
add_test(NAME l10n.missing_string_fails COMMAND sdl10n --check --domain "${_fx}/missing")
set_tests_properties(l10n.missing_string_fails PROPERTIES
  PASS_REGULAR_EXPRESSION "es.po:0: error: missing translation for 'cli.usage'")
add_test(NAME l10n.missing_string_allowed COMMAND sdl10n --check --allow-incomplete --domain "${_fx}/missing")
add_test(NAME l10n.missing_plural_form_fails
         COMMAND sdl10n --check --allow-incomplete --domain "${_fx}/bad_plural")
set_tests_properties(l10n.missing_plural_form_fails PROPERTIES
  PASS_REGULAR_EXPRESSION "error: 'cli.mounted_count' needs exactly 3 plural forms")
add_test(NAME l10n.placeholder_mismatch_fails
         COMMAND sdl10n --check --allow-incomplete --domain "${_fx}/bad_placeholder")
set_tests_properties(l10n.placeholder_mismatch_fails PROPERTIES
  PASS_REGULAR_EXPRESSION "error: placeholders of 'cli.unknown_command'")
add_test(NAME l10n.plural_header_fails
         COMMAND sdl10n --check --allow-incomplete --domain "${_fx}/bad_header")
set_tests_properties(l10n.plural_header_fails PROPERTIES
  PASS_REGULAR_EXPRESSION "error: Plural-Forms must be")

# Register lint (03 §9.2): wrong-register words fail; voseo, vous, lowercase sie/ihr and the
# translator opt-out pass.
add_test(NAME l10n.register_wrong_fails
         COMMAND ${CMAKE_COMMAND} -DSDL10N=$<TARGET_FILE:sdl10n> -DDOMAIN=${_fx}/register_bad -DALLOW=1
                 -DEXPECT_RC=1
                 "-DEXPECT=es.po:[0-9]+: error: 'reg.choose' form 0 uses .elija.*not the es register@@fr.po:[0-9]+: error: 'reg.choose' form 0 uses .choisis.*not the fr register@@it.po:[0-9]+: error: 'reg.choose' form 0 uses .scelga.*not the it register@@de.po:[0-9]+: error: 'reg.choose' form 0 uses .Sie.*not the de register@@es.po:[0-9]+: error: 'reg.pronoun' form 0 uses .t"
                 -P ${_check})
add_test(NAME l10n.register_correct_passes
         COMMAND ${CMAKE_COMMAND} -DSDL10N=$<TARGET_FILE:sdl10n> -DDOMAIN=${_fx}/register_ok -DALLOW=1
                 -DEXPECT_RC=0 "-DFORBID=error:"
                 -P ${_check})

# Mnemonics (03 §9.2): a dropped mnemonic is an error; duplicates are warnings within one group only.
add_test(NAME l10n.mnemonic_dropped_fails
         COMMAND ${CMAKE_COMMAND} -DSDL10N=$<TARGET_FILE:sdl10n> -DDOMAIN=${_fx}/mnemonic_drop -DALLOW=1
                 -DEXPECT_RC=1 "-DEXPECT='menu.edit.copy' form 0 drops the &-mnemonic"
                 -P ${_check})
add_test(NAME l10n.mnemonic_duplicates_warn
         COMMAND ${CMAKE_COMMAND} -DSDL10N=$<TARGET_FILE:sdl10n> -DDOMAIN=${_fx}/mnemonic_dup -DALLOW=1
                 -DEXPECT_RC=0
                 "-DEXPECT='menu.file.save' and 'menu.file.open' share the &a mnemonic@@'menu.edit.paste' uses the &p mnemonic twice"
                 -P ${_check})
add_test(NAME l10n.mnemonic_distinct_passes
         COMMAND ${CMAKE_COMMAND} -DSDL10N=$<TARGET_FILE:sdl10n> -DDOMAIN=${_fx}/mnemonic_ok -DALLOW=1
                 -DEXPECT_RC=0 "-DFORBID=share the &|twice in one|drops the &"
                 -P ${_check})

# Length (sdl10n:maxlen=N, N includes the NUL): one character too long fails, the limit passes.
add_test(NAME l10n.maxlen_exceeded_fails
         COMMAND ${CMAKE_COMMAND} -DSDL10N=$<TARGET_FILE:sdl10n> -DDOMAIN=${_fx}/maxlen_bad -DALLOW=1
                 -DEXPECT_RC=1 "-DEXPECT='ui.tip.drive' form 0 is 8 UTF-16 units; sdl10n:maxlen=7 allows 6"
                 -P ${_check})
add_test(NAME l10n.maxlen_within_passes
         COMMAND ${CMAKE_COMMAND} -DSDL10N=$<TARGET_FILE:sdl10n> -DDOMAIN=${_fx}/maxlen_ok -DALLOW=1
                 -DEXPECT_RC=0 "-DFORBID=error:"
                 -P ${_check})

# qps-ploc (03 §9.1): generated with --qps from en, placeholders and mnemonics kept, absent otherwise.
add_test(NAME l10n.qps_table_generated
         COMMAND ${CMAKE_COMMAND} -DSDL10N=$<TARGET_FILE:sdl10n> -DDOMAIN=${CMAKE_SOURCE_DIR}/l10n/cli
                 "-DWORK=${CMAKE_CURRENT_BINARY_DIR}/qps" "-DQPS_EXPECT={version}~"
                 -P ${_qps})
add_test(NAME l10n.qps_keeps_mnemonics
         COMMAND ${CMAKE_COMMAND} -DSDL10N=$<TARGET_FILE:sdl10n> -DDOMAIN=${_fx}/mnemonic_ok
                 "-DWORK=${CMAKE_CURRENT_BINARY_DIR}/qps_mn" "-DQPS_EXPECT=&O@@&S"
                 -P ${_qps})

set_tests_properties(l10n.real_catalogs_complete l10n.empty_catalogs_check
                     l10n.missing_string_fails l10n.missing_string_allowed
                     l10n.missing_plural_form_fails l10n.placeholder_mismatch_fails l10n.plural_header_fails
                     l10n.register_wrong_fails l10n.register_correct_passes
                     l10n.mnemonic_dropped_fails l10n.mnemonic_duplicates_warn l10n.mnemonic_distinct_passes
                     l10n.maxlen_exceeded_fails l10n.maxlen_within_passes
                     l10n.qps_table_generated l10n.qps_keeps_mnemonics
                     PROPERTIES LABELS l10n)
