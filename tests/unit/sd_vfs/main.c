#include "sd_test.h"

SD_TEST_DECL(vfs_err_table_covers_every_value);
SD_TEST_DECL(vfs_stage2_forward);
SD_TEST_DECL(vfs_stage2_inverse_decodes_only_produced_codes);
SD_TEST_DECL(vfs_name_roundtrip_bytes);
SD_TEST_DECL(vfs_input_checks);
SD_TEST_DECL(vfs_shell_active_set);
SD_TEST_DECL(vfs_case_collisions_mangle_by_byte_order);
SD_TEST_DECL(vfs_identical_display_names_collide_in_sensitive_view);
SD_TEST_DECL(vfs_mount_rejects_later_milestones);
SD_TEST_DECL(vfs_create_write_read_roundtrip);
SD_TEST_DECL(vfs_dispositions);
SD_TEST_DECL(vfs_case_insensitive_lookup_and_collisions);
SD_TEST_DECL(vfs_listing_maps_names_and_drops_malformed_entries);
SD_TEST_DECL(vfs_symlinks_follow_inside);
SD_TEST_DECL(vfs_symlinks_hide);
SD_TEST_DECL(vfs_read_only_mount);
SD_TEST_DECL(vfs_delete_semantics);
SD_TEST_DECL(vfs_rename_semantics);
SD_TEST_DECL(vfs_rename_replace_without_posix_rename);
SD_TEST_DECL(vfs_share_modes);
SD_TEST_DECL(vfs_metadata_cache_and_negative_entries);
SD_TEST_DECL(vfs_attributes_times_and_truncate);
SD_TEST_DECL(vfs_security_descriptor_and_statfs);
SD_TEST_DECL(vfs_concurrent_writers);

static const sd_test_case k_tests[] = {
  SD_TEST_ENTRY(vfs_err_table_covers_every_value),
  SD_TEST_ENTRY(vfs_stage2_forward),
  SD_TEST_ENTRY(vfs_stage2_inverse_decodes_only_produced_codes),
  SD_TEST_ENTRY(vfs_name_roundtrip_bytes),
  SD_TEST_ENTRY(vfs_input_checks),
  SD_TEST_ENTRY(vfs_shell_active_set),
  SD_TEST_ENTRY(vfs_case_collisions_mangle_by_byte_order),
  SD_TEST_ENTRY(vfs_identical_display_names_collide_in_sensitive_view),
  SD_TEST_ENTRY(vfs_mount_rejects_later_milestones),
  SD_TEST_ENTRY(vfs_create_write_read_roundtrip),
  SD_TEST_ENTRY(vfs_dispositions),
  SD_TEST_ENTRY(vfs_case_insensitive_lookup_and_collisions),
  SD_TEST_ENTRY(vfs_listing_maps_names_and_drops_malformed_entries),
  SD_TEST_ENTRY(vfs_symlinks_follow_inside),
  SD_TEST_ENTRY(vfs_symlinks_hide),
  SD_TEST_ENTRY(vfs_read_only_mount),
  SD_TEST_ENTRY(vfs_delete_semantics),
  SD_TEST_ENTRY(vfs_rename_semantics),
  SD_TEST_ENTRY(vfs_rename_replace_without_posix_rename),
  SD_TEST_ENTRY(vfs_share_modes),
  SD_TEST_ENTRY(vfs_metadata_cache_and_negative_entries),
  SD_TEST_ENTRY(vfs_attributes_times_and_truncate),
  SD_TEST_ENTRY(vfs_security_descriptor_and_statfs),
  SD_TEST_ENTRY(vfs_concurrent_writers),
};

int main(int argc, char **argv)
{
  return sd_test_main(k_tests, SD_COUNTOF(k_tests), argc, argv);
}
