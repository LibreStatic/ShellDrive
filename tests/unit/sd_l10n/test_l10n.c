/* sd_l10n runtime: CLDR plural categories (03 §9.4), language parsing, formatting and fallbacks,
 * against a small hand-written catalog with the generated table layout. */
#include <windows.h>
#include <string.h>

#include "sd_test.h"
#include "sd_l10n/sd_l10n.h"
#include "sd_base/sd_mem.h"

#define N SD_PLURAL_CAT_COUNT
#define NONPL(s) NULL, NULL, NULL, NULL, NULL, (s)

static const char *const k_keys[] = { "t.greet", "t.files", "t.esc", "t.only_en" };
static const char *const k_parg[] = { NULL, "count", NULL, NULL };
static const char *const k_en[] = {
  NONPL("Hello {name}!"),
  NULL, "{count} file", NULL, NULL, NULL, "{count} files",
  NONPL("{{literal}} and {missing} and {name}"),
  NONPL("English only"),
};
static const char *const k_es[] = {
  NONPL("¡Hola {name}!"),
  NULL, "{count} archivo", NULL, NULL, "{count} de archivos", "{count} archivos",
  NONPL("{{literal}} y {missing} y {name}"),
  NONPL(NULL),
};
static const char *const k_fr[] = {
  NONPL("Bonjour {name} !"),
  NULL, "{count} fichier", NULL, NULL, "{count} de fichiers", "{count} fichiers",
  NONPL("{{literal}} et {missing} et {name}"),
  NONPL(NULL),
};
static const sd_l10n_catalog k_cat = {
  SD_L10N_CATALOG_ABI, 4, "test", k_keys, k_parg,
  { k_en, k_es, k_fr, k_en, k_en, k_en },
  1u << SD_LANG_EN
};

SD_TEST(l10n_plural_categories_cldr)
{
  static const long long samples[] = { 0, 1, 2, 5, 21, 1000000, 2000000, 1000001 };
  /* expected category per language for each sample */
  static const sd_plural_cat en[] = { SD_PLURAL_OTHER, SD_PLURAL_ONE, SD_PLURAL_OTHER, SD_PLURAL_OTHER,
                                      SD_PLURAL_OTHER, SD_PLURAL_OTHER, SD_PLURAL_OTHER, SD_PLURAL_OTHER };
  static const sd_plural_cat es[] = { SD_PLURAL_OTHER, SD_PLURAL_ONE, SD_PLURAL_OTHER, SD_PLURAL_OTHER,
                                      SD_PLURAL_OTHER, SD_PLURAL_MANY, SD_PLURAL_MANY, SD_PLURAL_OTHER };
  static const sd_plural_cat fr[] = { SD_PLURAL_ONE, SD_PLURAL_ONE, SD_PLURAL_OTHER, SD_PLURAL_OTHER,
                                      SD_PLURAL_OTHER, SD_PLURAL_MANY, SD_PLURAL_MANY, SD_PLURAL_OTHER };
  size_t i;
  for (i = 0; i < SD_COUNTOF(samples); i++) {
    SD_CHECK_EQ_INT(sd_l10n_plural_category(SD_LANG_EN, samples[i]), en[i]);
    SD_CHECK_EQ_INT(sd_l10n_plural_category(SD_LANG_DE, samples[i]), en[i]);
    SD_CHECK_EQ_INT(sd_l10n_plural_category(SD_LANG_ES, samples[i]), es[i]);
    SD_CHECK_EQ_INT(sd_l10n_plural_category(SD_LANG_IT, samples[i]), es[i]);
    SD_CHECK_EQ_INT(sd_l10n_plural_category(SD_LANG_FR, samples[i]), fr[i]);
    SD_CHECK_EQ_INT(sd_l10n_plural_category(SD_LANG_PT_BR, samples[i]), fr[i]);
  }
}

SD_TEST(l10n_parse_lang_codes)
{
  sd_lang l = SD_LANG_EN;
  SD_CHECK(sd_l10n_parse_lang(L"es", &l) && l == SD_LANG_ES);
  SD_CHECK(sd_l10n_parse_lang(L"pt", &l) && l == SD_LANG_PT_BR);
  SD_CHECK(sd_l10n_parse_lang(L"pt-BR", &l) && l == SD_LANG_PT_BR);
  SD_CHECK(sd_l10n_parse_lang(L"PT-pt", &l) && l == SD_LANG_PT_BR);   /* pt-* -> pt-BR (9.3) */
  SD_CHECK(sd_l10n_parse_lang(L"es-AR", &l) && l == SD_LANG_ES);
  SD_CHECK(sd_l10n_parse_lang(L"de_CH", &l) && l == SD_LANG_DE);
  SD_CHECK(sd_l10n_parse_lang(L"IT", &l) && l == SD_LANG_IT);
  SD_CHECK(!sd_l10n_parse_lang(L"ja", &l));
  SD_CHECK(!sd_l10n_parse_lang(L"", &l));
  SD_CHECK_STR(sd_l10n_lang_code(SD_LANG_PT_BR), "pt-BR");
  SD_CHECK_STR(sd_l10n_lang_code((sd_lang)99), "en");
}

SD_TEST(l10n_format_and_fallbacks)
{
  wchar_t buf[128], *w;
  sd_arg args[2];
  args[0].name = "name"; args[0].type = SD_ARG_STR; args[0].v.s = L"Ana";
  args[1].name = "count"; args[1].type = SD_ARG_INT; args[1].v.i = 1;
  SD_CHECK(sd_l10n_init(&k_cat, L"es") == SD_LANG_ES);
  SD_CHECK(sd_l10n_lang() == SD_LANG_ES);
  SD_CHECK(sd_l10n_format(buf, SD_COUNTOF(buf), 0, args, 1) > 0);
  SD_CHECK(wcscmp(buf, L"\x00a1Hola Ana!") == 0);
  SD_CHECK(sd_l10n_format(buf, SD_COUNTOF(buf), 1, args + 1, 1) > 0);
  SD_CHECK(wcscmp(buf, L"1 archivo") == 0);
  args[1].v.i = 1000000;
  SD_CHECK(sd_l10n_format(buf, SD_COUNTOF(buf), 1, args + 1, 1) > 0);
  SD_CHECK(wcsstr(buf, L"de archivos") != NULL);                  /* CLDR "many" */
  args[1].v.i = 3;
  w = sd_l10n_format_alloc(1, args + 1, 1);
  SD_REQUIRE(w != NULL);
  SD_CHECK(wcscmp(w, L"3 archivos") == 0);
  sd_free(w);
  /* escapes, missing argument rendered literally */
  SD_CHECK(sd_l10n_format(buf, SD_COUNTOF(buf), 2, args, 1) > 0);
  SD_CHECK(wcscmp(buf, L"{literal} y {missing} y Ana") == 0);
  /* missing translation falls back to English; unknown id to "" */
  SD_CHECK(wcscmp(sd_l10n_get(3), L"English only") == 0);
  SD_CHECK(sd_l10n_get(3) == sd_l10n_get(3));                    /* cached */
  SD_CHECK(wcscmp(sd_l10n_get(99), L"") == 0);
  /* buffer too small: -1, truncated and terminated */
  SD_CHECK(sd_l10n_format(buf, 4, 0, args, 1) == -1);
  SD_CHECK(wcslen(buf) == 3);
  /* French: 0 is "one" */
  SD_CHECK(sd_l10n_init(&k_cat, L"fr") == SD_LANG_FR);
  args[1].v.i = 0;
  SD_CHECK(sd_l10n_format(buf, SD_COUNTOF(buf), 1, args + 1, 1) > 0);
  SD_CHECK(wcscmp(buf, L"0 fichier") == 0);
  SD_CHECK(sd_l10n_init(&k_cat, L"en") == SD_LANG_EN);
  args[1].v.i = 1234567;
  SD_CHECK(sd_l10n_format(buf, SD_COUNTOF(buf), 1, args + 1, 1) > 0);
  SD_CHECK(wcsstr(buf, L"files") != NULL);
  SD_CHECK(buf[0] == L'1');
  SD_CHECK(wcslen(buf) > wcslen(L"1234567 files") - 1);          /* grouping per user locale */
}
