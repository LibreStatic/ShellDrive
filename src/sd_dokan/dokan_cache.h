/* Requestor identity cache for global Dokany mounts (02 6.7, M5). Private to sd_dokan.
 *
 * An entry is the enabled groups of one requestor token, keyed by (TokenId, ModifiedId, user SID) and kept for
 * DK_CACHE_TTL_MS. TokenId identifies one token object: a filtered (UAC), restricted or duplicated token has its own,
 * even when it shares the logon LUID, so its groups never come from another token's entry. ModifiedId changes when
 * the token's groups or privileges are adjusted (AdjustTokenGroups / AdjustTokenPrivileges), so an entry made before
 * such a change is not reused. Repeated opens that present the same token object hit the same entry.
 *
 * Only successful identities are stored; a failed token query never reaches dk_cache_put. Lookups return copies,
 * so an entry evicted by another thread cannot leave the caller with a dangling pointer. The table is bounded and
 * guarded by one critical section. Times are GetTickCount values passed in by the caller (32-bit, wrap-safe). */
#ifndef SD_DOKAN_CACHE_H
#define SD_DOKAN_CACHE_H

#include <windows.h>

#define DK_CACHE_TTL_MS 60000u
#define DK_CACHE_SLOTS  32u

typedef struct dk_cache dk_cache;

dk_cache *dk_cache_new(void);            /* NULL on allocation failure: the caller then reads the token every time */
void      dk_cache_free(dk_cache *c);

/* TRUE on a fresh entry: *groups (release with dk_groups_free) and *n_groups hold copies of its groups. A miss, an
   expired entry (which is dropped) or an allocation failure returns FALSE and the caller reads the token itself. */
BOOL dk_cache_get(dk_cache *c, const LUID *token_id, const LUID *modified_id, PSID user, DWORD now, PSID **groups,
                  UINT *n_groups);

/* Stores a successful identity; copies everything it keeps. Allocation failure stores nothing. */
void dk_cache_put(dk_cache *c, const LUID *token_id, const LUID *modified_id, PSID user, PSID const *groups,
                  UINT n_groups, DWORD now);

void dk_groups_free(PSID *groups, UINT n);

#endif /* SD_DOKAN_CACHE_H */
