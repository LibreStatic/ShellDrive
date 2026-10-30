#include "sd_test.h"

SD_TEST_DECL(state_round_trip);
SD_TEST_DECL(state_truncation_is_safe);
SD_TEST_DECL(state_torn_reads_never_mix);
SD_TEST_DECL(state_odd_seq_is_no_data);
SD_TEST_DECL(state_corrupt_header_is_no_data);
SD_TEST_DECL(state_bad_entries_are_dropped);
SD_TEST_DECL(state_v1_reader_accepts_v2_writer);
SD_TEST_DECL(state_unknown_layout_is_no_data);
SD_TEST_DECL(state_section_round_trip);
SD_TEST_DECL(state_squatted_low_label_is_refused);

static const sd_test_case k_tests[] = {
  SD_TEST_ENTRY(state_round_trip),
  SD_TEST_ENTRY(state_truncation_is_safe),
  SD_TEST_ENTRY(state_torn_reads_never_mix),
  SD_TEST_ENTRY(state_odd_seq_is_no_data),
  SD_TEST_ENTRY(state_corrupt_header_is_no_data),
  SD_TEST_ENTRY(state_bad_entries_are_dropped),
  SD_TEST_ENTRY(state_v1_reader_accepts_v2_writer),
  SD_TEST_ENTRY(state_unknown_layout_is_no_data),
  SD_TEST_ENTRY(state_section_round_trip),
  SD_TEST_ENTRY(state_squatted_low_label_is_refused),
};

int main(int argc, char **argv)
{
  return sd_test_main(k_tests, SD_COUNTOF(k_tests), argc, argv);
}
