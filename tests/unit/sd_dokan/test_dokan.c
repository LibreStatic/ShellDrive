/* sd_dokan unit tests: ABI layout, NTSTATUS table, probe/version gate on this machine. */
#include <windows.h>
#include <stddef.h>
#include <string.h>

#include "dokan_internal.h"
#include "sd_test.h"

SD_TEST(dokan_abi_layout_x64)
{
  /* Also pinned by static asserts in dokan_abi.h; repeated here so a failure names the field.
     The x86 values follow from the same declarations (PVOID64 GlobalContext keeps 8-byte alignment). */
  SD_CHECK_EQ_INT(offsetof(SD_DOKAN_OPTIONS, Options), 0x04);
  SD_CHECK_EQ_INT(offsetof(SD_DOKAN_OPTIONS, MountPoint), 0x10);
#if defined(_WIN64)
  SD_CHECK_EQ_INT(offsetof(SD_DOKAN_OPTIONS, UNCName), 0x18);
  SD_CHECK_EQ_INT(offsetof(SD_DOKAN_OPTIONS, AllocationUnitSize), 0x24);
  SD_CHECK_EQ_INT(offsetof(SD_DOKAN_OPTIONS, SectorSize), 0x28);
  SD_CHECK_EQ_INT(sizeof(SD_DOKAN_OPTIONS), 0x4030);
  SD_CHECK_EQ_INT(sizeof(SD_DOKAN_FILE_INFO), 0x30);
  SD_CHECK_EQ_INT(offsetof(SD_DOKAN_FILE_INFO, IsDirectory), 0x24);
  SD_CHECK_EQ_INT(offsetof(SD_DOKAN_FILE_INFO, DeletePending), 0x25);
  SD_CHECK_EQ_INT(offsetof(SD_DOKAN_FILE_INFO, PagingIo), 0x26);
  SD_CHECK_EQ_INT(offsetof(SD_DOKAN_FILE_INFO, WriteToEndOfFile), 0x29);
#else
  SD_CHECK_EQ_INT(offsetof(SD_DOKAN_OPTIONS, UNCName), 0x14);
  SD_CHECK_EQ_INT(offsetof(SD_DOKAN_OPTIONS, AllocationUnitSize), 0x1C);
  SD_CHECK_EQ_INT(offsetof(SD_DOKAN_OPTIONS, SectorSize), 0x20);
  SD_CHECK_EQ_INT(sizeof(SD_DOKAN_OPTIONS), 0x4028);
  SD_CHECK_EQ_INT(sizeof(SD_DOKAN_FILE_INFO), 0x28);
  SD_CHECK_EQ_INT(offsetof(SD_DOKAN_FILE_INFO, IsDirectory), 0x1C);
  SD_CHECK_EQ_INT(offsetof(SD_DOKAN_FILE_INFO, DeletePending), 0x1D);
  SD_CHECK_EQ_INT(offsetof(SD_DOKAN_FILE_INFO, PagingIo), 0x1E);
  SD_CHECK_EQ_INT(offsetof(SD_DOKAN_FILE_INFO, WriteToEndOfFile), 0x21);
#endif
  SD_CHECK_EQ_INT(sizeof(SD_DOKAN_OPERATIONS), 25 * sizeof(void *));
  SD_CHECK_EQ_INT(SD_DOKAN_OPTION_CURRENT_SESSION, 0x80);
  SD_CHECK_EQ_INT(SD_DOKAN_OPTION_NETWORK, 0x10);
  SD_CHECK_EQ_INT(SD_DOKAN_OPTION_WRITE_PROTECT, 0x08);
}

SD_TEST(dokan_ntstatus_table)
{
  static const struct { sd_vfs_status s; LONG nt; } k[] = {
    { SD_VFS_OK, 0 },
    { SD_VFS_E_NOT_FOUND, (LONG)0xC0000034L }, { SD_VFS_E_PATH_NOT_FOUND, (LONG)0xC000003AL },
    { SD_VFS_E_EXISTS, (LONG)0xC0000035L }, { SD_VFS_E_ACCESS_DENIED, (LONG)0xC0000022L },
    { SD_VFS_E_READ_ONLY, (LONG)0xC00000A2L }, { SD_VFS_E_SHARING, (LONG)0xC0000043L },
    { SD_VFS_E_DELETE_PENDING, (LONG)0xC0000056L }, { SD_VFS_E_CANNOT_DELETE, (LONG)0xC0000121L },
    { SD_VFS_E_NOT_EMPTY, (LONG)0xC0000101L }, { SD_VFS_E_IS_DIR, (LONG)0xC00000BAL },
    { SD_VFS_E_NOT_DIR, (LONG)0xC0000103L }, { SD_VFS_E_INVALID_NAME, (LONG)0xC0000033L },
    { SD_VFS_E_NAME_TOO_LONG, (LONG)0xC0000106L }, { SD_VFS_E_NO_SPACE, (LONG)0xC000007FL },
    { SD_VFS_E_QUOTA, (LONG)0xC0000044L }, { SD_VFS_E_TOO_LARGE, (LONG)0xC0000904L },
    { SD_VFS_E_DISCONNECTED, (LONG)0xC000020CL }, { SD_VFS_E_STALE, (LONG)0xC0000098L },
    { SD_VFS_E_TIMEOUT, (LONG)0xC00000B5L }, { SD_VFS_E_UNSUPPORTED, (LONG)0xC00000BBL },
    { SD_VFS_E_NO_MEMORY, (LONG)0xC000009AL }, { SD_VFS_E_IO, (LONG)0xC00000E9L },
    { SD_VFS_E_CANCELLED, (LONG)0xC0000120L }, { SD_VFS_E_END_OF_FILE, (LONG)0xC0000011L },
  };
  size_t i;
  SD_CHECK_EQ_INT(SD_COUNTOF(k), SD_VFS_STATUS_COUNT);    /* one row per status (02 §8) */
  for (i = 0; i < SD_COUNTOF(k); i++) {
    SD_CHECK_EQ_INT(k[i].s, (int)i);
    SD_CHECK_EQ_INT(sd_vfs_to_ntstatus(k[i].s), k[i].nt);
  }
}

SD_TEST(dokan_probe_and_deny_list)
{
  sd_dokan_probe_info info;
  sd_dokan_avail a = sd_dokan_probe(NULL, &info);
  sd_dokan_deny_range r;
  sd_dokan_deny deny;
  if (a == SD_DOKAN_NOT_INSTALLED || a == SD_DOKAN_OS_UNSUPPORTED || a == SD_DOKAN_DRIVER_MISSING ||
      a == SD_DOKAN_WOW64) {
    SD_CHECK(sd_dokan_api_get() == NULL);
    return;                                 /* nothing more to check on this machine */
  }
  SD_REQUIRE(a == SD_DOKAN_OK);
  SD_CHECK(info.lib_version >= 210);
  SD_CHECK(info.driver_version >= 210);
  SD_CHECK(sd_dokan_api_get() != NULL);
  r.from = info.lib_version;
  r.to = info.lib_version;
  r.reason = "test advisory";
  deny.ranges = &r;
  deny.count = 1;
  SD_CHECK_EQ_INT(sd_dokan_probe(&deny, &info), SD_DOKAN_DENIED);
  SD_CHECK(info.deny_reason && strcmp(info.deny_reason, "test advisory") == 0);
  SD_CHECK_EQ_INT(sd_dokan_probe(NULL, &info), SD_DOKAN_OK);
}
