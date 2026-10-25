#include "sd_test.h"

SD_TEST_DECL(l10n_plural_categories_cldr);
SD_TEST_DECL(l10n_parse_lang_codes);
SD_TEST_DECL(l10n_format_and_fallbacks);

static const sd_test_case k_tests[] = {
  SD_TEST_ENTRY(l10n_plural_categories_cldr),
  SD_TEST_ENTRY(l10n_parse_lang_codes),
  SD_TEST_ENTRY(l10n_format_and_fallbacks),
};

int main(int argc, char **argv)
{
  return sd_test_main(k_tests, SD_COUNTOF(k_tests), argc, argv);
}
