/* Synthesized security descriptors, per-user form (02 §3.3, TM-R22). Advisory only: Dokany does no
 * access check against it. Global-mount DACLs (D35) are M5. Thread safety: pure, any thread. */
#include <windows.h>

#include "sd_base/sd_mem.h"
#include "vfs_internal.h"

static DWORD bits_to_rights(uint32_t bits, BOOL dir)
{
  DWORD r = 0;
  if (bits & 4) r |= FILE_GENERIC_READ | (dir ? (FILE_LIST_DIRECTORY | FILE_TRAVERSE) : 0);
  if (bits & 2) r |= FILE_GENERIC_WRITE | DELETE |
                     (dir ? (FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_DELETE_CHILD) : 0);
  if (bits & 1) r |= FILE_GENERIC_EXECUTE;
  return r;
}

sd_vfs_status vfs_build_sd(sd_vfs *v, const vfs_attr *a, BOOL is_dir, SECURITY_INFORMATION si,
                           PSECURITY_DESCRIPTOR out, ULONG len, ULONG *needed)
{
  SID_IDENTIFIER_AUTHORITY unix_auth = { { 0, 0, 0, 0, 0, 22 } };   /* S-1-22 (Samba, NFS client) */
  SID_IDENTIFIER_AUTHORITY nt_auth = SECURITY_NT_AUTHORITY;
  PSID owner_unix = NULL, group = NULL, admins = NULL, system = NULL, mount_owner = v->owner_sid;
  PSID owner;
  PACL acl = NULL;
  DWORD acl_len, rights, sz, off, olen = 0, glen = 0;
  BOOL ours = !v->uid_known || !(a->valid & SD_SFTP_ATTR_UIDGID) || a->uid == v->uid;
  sd_vfs_status st = SD_VFS_E_NO_MEMORY;
  if (needed) *needed = 0;

  if (!AllocateAndInitializeSid(&nt_auth, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0,
                                0, &admins) ||
      !AllocateAndInitializeSid(&nt_auth, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &system) ||
      !AllocateAndInitializeSid(&unix_auth, 2, 2, a->gid, 0, 0, 0, 0, 0, 0, &group))
    goto out;
  if (!ours && !AllocateAndInitializeSid(&unix_auth, 2, 1, a->uid, 0, 0, 0, 0, 0, 0, &owner_unix))
    goto out;
  owner = ours && mount_owner ? mount_owner : (owner_unix ? owner_unix : admins);
  if (!mount_owner)
    mount_owner = admins;

  /* Owner ACE from the u bits (+ what Explorer's Security tab needs), Administrators the same,
     SYSTEM full control if allow_system. No group/other ACEs (T-41). */
  rights = bits_to_rights((a->mode >> 6) & 7u, is_dir) | READ_CONTROL | WRITE_DAC | WRITE_OWNER |
           FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE;
  if (v->read_only)
    rights &= ~(DWORD)(FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | DELETE | FILE_DELETE_CHILD);
  acl_len = sizeof(ACL) + 3 * (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD)) + GetLengthSid(mount_owner) +
            GetLengthSid(admins) + GetLengthSid(system);
  acl = (PACL)sd_alloc(acl_len);
  if (!acl || !InitializeAcl(acl, acl_len, ACL_REVISION) ||
      !AddAccessAllowedAce(acl, ACL_REVISION, rights, mount_owner) ||
      !AddAccessAllowedAce(acl, ACL_REVISION, rights, admins) ||
      (v->allow_system && !AddAccessAllowedAce(acl, ACL_REVISION, FILE_ALL_ACCESS, system)))
    goto out;
  /* Self-relative layout written directly (only XP-floor advapi32 imports): header, owner, group,
     DACL. */
  if (si & OWNER_SECURITY_INFORMATION) olen = GetLengthSid(owner);
  if (si & GROUP_SECURITY_INFORMATION) glen = GetLengthSid(group);
  sz = (DWORD)sizeof(SECURITY_DESCRIPTOR_RELATIVE) + olen + glen +
       ((si & DACL_SECURITY_INFORMATION) ? acl->AclSize : 0);
  if (needed) *needed = sz;
  st = SD_VFS_OK;
  if (out && len >= sz) {
    SECURITY_DESCRIPTOR_RELATIVE *h = (SECURITY_DESCRIPTOR_RELATIVE *)out;
    BYTE *p = (BYTE *)out;
    memset(h, 0, sizeof(*h));
    h->Revision = SECURITY_DESCRIPTOR_REVISION;
    h->Control = SE_SELF_RELATIVE;
    off = sizeof(*h);
    if (olen) {
      CopySid(olen, p + off, owner);
      h->Owner = off;
      off += olen;
    }
    if (glen) {
      CopySid(glen, p + off, group);
      h->Group = off;
      off += glen;
    }
    if (si & DACL_SECURITY_INFORMATION) {
      memcpy(p + off, acl, acl->AclSize);
      h->Dacl = off;
      h->Control |= SE_DACL_PRESENT | SE_DACL_PROTECTED;
    }
  }
out:
  if (owner_unix) FreeSid(owner_unix);
  if (group) FreeSid(group);
  if (admins) FreeSid(admins);
  if (system) FreeSid(system);
  sd_free(acl);
  return st;
}
