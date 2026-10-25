#include "sd_test.h"

SD_TEST_DECL(buf_reads_integers);
SD_TEST_DECL(buf_short_input_is_sticky);
SD_TEST_DECL(buf_string_respects_max);
SD_TEST_DECL(buf_trailing_data_fails_done);
SD_TEST_DECL(buf_mpint_rfc4251_examples);
SD_TEST_DECL(buf_name_list);
SD_TEST_DECL(buf_sub_reader);
SD_TEST_DECL(buf_writer_roundtrip);
SD_TEST_DECL(buf_writer_limits);
SD_TEST_DECL(buf_writer_patch_and_secret);
SD_TEST_DECL(buf_writer_alloc_failure);
SD_TEST_DECL(utf8_to_utf16_basic);
SD_TEST_DECL(utf8_rejects_invalid);
SD_TEST_DECL(utf16_to_utf8_and_surrogates);
SD_TEST_DECL(utf_alloc_variants);
SD_TEST_DECL(name_mapping_is_lossless);
SD_TEST_DECL(name_escape_values);
SD_TEST_DECL(name_from_wide_rejects);
SD_TEST_DECL(name_component_check);
SD_TEST_DECL(text_sanitize_server);
SD_TEST_DECL(err_names_unique_and_stable);
SD_TEST_DECL(err_ipc_spellings);
SD_TEST_DECL(checked_arithmetic);

static const sd_test_case k_tests[] = {
  SD_TEST_ENTRY(buf_reads_integers),
  SD_TEST_ENTRY(buf_short_input_is_sticky),
  SD_TEST_ENTRY(buf_string_respects_max),
  SD_TEST_ENTRY(buf_trailing_data_fails_done),
  SD_TEST_ENTRY(buf_mpint_rfc4251_examples),
  SD_TEST_ENTRY(buf_name_list),
  SD_TEST_ENTRY(buf_sub_reader),
  SD_TEST_ENTRY(buf_writer_roundtrip),
  SD_TEST_ENTRY(buf_writer_limits),
  SD_TEST_ENTRY(buf_writer_patch_and_secret),
  SD_TEST_ENTRY(buf_writer_alloc_failure),
  SD_TEST_ENTRY(utf8_to_utf16_basic),
  SD_TEST_ENTRY(utf8_rejects_invalid),
  SD_TEST_ENTRY(utf16_to_utf8_and_surrogates),
  SD_TEST_ENTRY(utf_alloc_variants),
  SD_TEST_ENTRY(name_mapping_is_lossless),
  SD_TEST_ENTRY(name_escape_values),
  SD_TEST_ENTRY(name_from_wide_rejects),
  SD_TEST_ENTRY(name_component_check),
  SD_TEST_ENTRY(text_sanitize_server),
  SD_TEST_ENTRY(err_names_unique_and_stable),
  SD_TEST_ENTRY(err_ipc_spellings),
  SD_TEST_ENTRY(checked_arithmetic),
};

int main(int argc, char **argv)
{
  return sd_test_main(k_tests, SD_COUNTOF(k_tests), argc, argv);
}
