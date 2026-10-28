/* sd_dokan unit tests: ABI layout, NTSTATUS table, probe/version gate on this machine. */
#include <windows.h>
#include <stddef.h>
#include <string.h>

#include "dokan_cache.h"
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

/* ---- requestor identity cache (02 6.7: 60 s per (logon LUID, SID); dokan_cache.c) ---- */

/* S-1-5-21-1-2-3-1001 (alice); S-1-5-32-545 BUILTIN\Users, S-1-5-32-544 BUILTIN\Administrators */
static const unsigned char k_alice_sid[] = { 1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0xE9, 3, 0, 0 };
static const unsigned char k_bob_sid[]   = { 1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0xEA, 3, 0, 0 };
static const unsigned char k_users_sid[] = { 1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 33, 2, 0, 0 };
static const unsigned char k_admins_sid[] = { 1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0 };

static LUID luid_of(DWORD low)
{
  LUID l;
  l.LowPart = low;
  l.HighPart = 0;
  return l;
}

/* Stores the two groups for (luid, elev, user) at time `now`; returns TRUE when a later get returns both groups. */
static BOOL cache_has(dk_cache *c, LUID luid, DWORD elev, const unsigned char *user, DWORD now)
{
  PSID *g = NULL;
  UINT n = 0;
  BOOL hit = dk_cache_get(c, &luid, elev, (PSID)(void *)user, now, &g, &n);
  if (hit) {
    /* a hit must return the stored groups in full; a wrong copy counts as a miss so the caller's check fails */
    if (!(n == 2 && g != NULL && EqualSid(g[0], (PSID)(void *)k_users_sid) &&
          EqualSid(g[1], (PSID)(void *)k_admins_sid)))
      hit = FALSE;
    dk_groups_free(g, n);
  }
  return hit;
}

SD_TEST(dokan_cache_hit_expiry_and_keys)
{
  dk_cache *c = dk_cache_new();
  PSID groups[2];
  LUID l1 = luid_of(0x100);
  SD_REQUIRE(c != NULL);
  groups[0] = (PSID)(void *)k_users_sid;
  groups[1] = (PSID)(void *)k_admins_sid;
  dk_cache_put(c, &l1, 2, (PSID)(void *)k_alice_sid, groups, 2, 1000);
  SD_CHECK(cache_has(c, l1, 2, k_alice_sid, 1000));                  /* same key: hit */
  SD_CHECK(cache_has(c, l1, 2, k_alice_sid, 1000 + DK_CACHE_TTL_MS - 1));  /* just inside 60 s */
  /* different LUID, elevation type or SID: never a hit (a filtered and an elevated token share the LUID) */
  SD_CHECK(!cache_has(c, luid_of(0x101), 2, k_alice_sid, 1000));
  SD_CHECK(!cache_has(c, l1, 1, k_alice_sid, 1000));
  SD_CHECK(!cache_has(c, l1, 2, k_bob_sid, 1000));
  /* expired at 60 s: a miss, and the entry is dropped */
  SD_CHECK(!cache_has(c, l1, 2, k_alice_sid, 1000 + DK_CACHE_TTL_MS));
  SD_CHECK(!cache_has(c, l1, 2, k_alice_sid, 1000));
  dk_cache_free(c);
}

SD_TEST(dokan_cache_wraps_and_refreshes)
{
  dk_cache *c = dk_cache_new();
  PSID groups[2];
  LUID l1 = luid_of(0x200);
  SD_REQUIRE(c != NULL);
  groups[0] = (PSID)(void *)k_users_sid;
  groups[1] = (PSID)(void *)k_admins_sid;
  /* GetTickCount wraps every 49.7 days: an entry stored just before the wrap is still fresh after it */
  dk_cache_put(c, &l1, 0, (PSID)(void *)k_alice_sid, groups, 2, 0xFFFFFF00u);
  SD_CHECK(cache_has(c, l1, 0, k_alice_sid, 0x00000010u));
  /* a second put for the same requestor refreshes it in place: the new time counts */
  dk_cache_put(c, &l1, 0, (PSID)(void *)k_alice_sid, groups, 2, 0x00000100u);
  SD_CHECK(cache_has(c, l1, 0, k_alice_sid, 0x00000200u));
  dk_cache_free(c);
}

SD_TEST(dokan_cache_failures_are_not_stored)
{
  dk_cache *c = dk_cache_new();
  PSID groups[2];
  LUID l1 = luid_of(0x300);
  SD_REQUIRE(c != NULL);
  groups[0] = (PSID)(void *)k_users_sid;
  groups[1] = (PSID)(void *)k_admins_sid;
  /* a store without a valid user SID (what a failed token query yields) keeps nothing */
  dk_cache_put(c, &l1, 0, NULL, groups, 2, 1000);
  SD_CHECK(!cache_has(c, l1, 0, k_alice_sid, 1000));
  dk_cache_free(c);
}

SD_TEST(dokan_cache_is_bounded_and_evicts_oldest)
{
  dk_cache *c = dk_cache_new();
  PSID groups[2];
  DWORD i;
  SD_REQUIRE(c != NULL);
  groups[0] = (PSID)(void *)k_users_sid;
  groups[1] = (PSID)(void *)k_admins_sid;
  for (i = 0; i < DK_CACHE_SLOTS + 8; i++) {
    LUID lu = luid_of(i + 1);
    dk_cache_put(c, &lu, 0, (PSID)(void *)k_alice_sid, groups, 2, 1000);
  }
  /* the first 8 inserts were evicted, the newest DK_CACHE_SLOTS are still there */
  SD_CHECK(!cache_has(c, luid_of(1), 0, k_alice_sid, 1000));
  SD_CHECK(!cache_has(c, luid_of(8), 0, k_alice_sid, 1000));
  SD_CHECK(cache_has(c, luid_of(9), 0, k_alice_sid, 1000));
  SD_CHECK(cache_has(c, luid_of(DK_CACHE_SLOTS + 8), 0, k_alice_sid, 1000));
  dk_cache_free(c);
}
