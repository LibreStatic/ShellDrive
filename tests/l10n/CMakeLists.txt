# sdl10n self-tests: the build must fail on missing strings (M0 requirement, 03 §9.2) unless
# --allow-incomplete is passed, and must fail on structural errors in every case. Failure cases
# match the expected diagnostic, so a crash cannot pass.

set(_fx "${CMAKE_CURRENT_SOURCE_DIR}/fixtures")

add_test(NAME l10n.real_catalogs_complete COMMAND sdl10n --check --domain "${CMAKE_SOURCE_DIR}/l10n/cli")
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

set_tests_properties(l10n.real_catalogs_complete l10n.missing_string_fails l10n.missing_string_allowed
                     l10n.missing_plural_form_fails l10n.placeholder_mismatch_fails l10n.plural_header_fails
                     PROPERTIES LABELS l10n)
