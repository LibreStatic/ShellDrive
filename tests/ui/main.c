/* UI unit tests (tests/ui): harness entry point. The cases are in test_wire.c and test_dpi.c. */
#include "sd_test.h"

SD_TEST_DECL(wire_roundtrip_and_empty);
SD_TEST_DECL(wire_rejects_bad_header);
SD_TEST_DECL(wire_rejects_truncated_and_trailing);
SD_TEST_DECL(wire_rejects_bad_units);
SD_TEST_DECL(wire_rejects_too_many_or_too_long);
SD_TEST_DECL(verbs_show_tray_prompt);
SD_TEST_DECL(verbs_unmount_drive);
SD_TEST_DECL(verbs_mount_profile_id);
SD_TEST_DECL(verbs_reconnect_and_mount_file);
SD_TEST_DECL(verbs_unknown_are_rejected);
SD_TEST_DECL(dpi_scale_rounding_and_clamp);
SD_TEST_DECL(dpi_font_height);

static const sd_test_case k_tests[] = {
  SD_TEST_ENTRY(wire_roundtrip_and_empty),
  SD_TEST_ENTRY(wire_rejects_bad_header),
  SD_TEST_ENTRY(wire_rejects_truncated_and_trailing),
  SD_TEST_ENTRY(wire_rejects_bad_units),
  SD_TEST_ENTRY(wire_rejects_too_many_or_too_long),
  SD_TEST_ENTRY(verbs_show_tray_prompt),
  SD_TEST_ENTRY(verbs_unmount_drive),
  SD_TEST_ENTRY(verbs_mount_profile_id),
  SD_TEST_ENTRY(verbs_reconnect_and_mount_file),
  SD_TEST_ENTRY(verbs_unknown_are_rejected),
  SD_TEST_ENTRY(dpi_scale_rounding_and_clamp),
  SD_TEST_ENTRY(dpi_font_height),
};

int main(int argc, char **argv)
{
  return sd_test_main(k_tests, SD_COUNTOF(k_tests), argc, argv);
}
