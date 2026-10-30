/* Reader of the agent's state section, layout v1 (03 §8.2.1; TM-R26). See shellext_snapshot.h.
 *
 * Production path: sd_ipc_state_open checks the owner and the mandatory label on the handle (fail closed).
 * Test builds (SD_SHELLEXT_TEST): SHELLDRIVE_TEST_STATE_NAME, when set, names a section created by the test
 * under a test-only name; the same owner and label rules are applied by sx_owner_and_label_ok below.
 *
 * Everything after the copy works on the local buffer only: the mapped view is read exactly twice per try
 * (the seq counter and the copy), so a concurrent writer can change the view but never the parsed data. */
#include <windows.h>
#include <aclapi.h>
#include <string.h>

#include "sd_base/sd_err.h"
#include "sd_base/sd_mem.h"
#include "sd_ipc/sd_ipc.h"
#include "shellext_snapshot.h"

#ifndef LABEL_SECURITY_INFORMATION
#define LABEL_SECURITY_INFORMATION 0x00000010L
#endif
#ifndef SECURITY_MANDATORY_MEDIUM_RID
#define SECURITY_MANDATORY_MEDIUM_RID 0x00002000L
#endif
#ifndef SYSTEM_MANDATORY_LABEL_ACE_TYPE
#define SYSTEM_MANDATORY_LABEL_ACE_TYPE 0x11
#endif

#define SHX_SEQ_OFFSET     20u
#define SHX_TRIES          3u
#define SHX_SLOT_MOUNT_ID  24u     /* WCHAR[32] */
#define SHX_SLOT_PROFILE   88u     /* WCHAR[32] */
#define SHX_SLOT_NAME      152u    /* WCHAR[128] */
#define SHX_SLOT_TARGET    408u    /* WCHAR[260] */
#define SHX_SLOT_LABEL     928u    /* WCHAR[64] */
#define SHX_SLOT_URL       1056u   /* WCHAR[320] */

/* Layout of SYSTEM_MANDATORY_LABEL_ACE, declared here so the SDK version does not matter. */
typedef struct shx_label_ace {
  ACE_HEADER Header;
  ACCESS_MASK Mask;
  DWORD SidStart;
} shx_label_ace;

static uint32_t rd16(const unsigned char *p)
{
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8);
}

static uint32_t rd32(const unsigned char *p)
{
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Well-formed UTF-16 up to the first NUL of a fixed slot of `units` code units. A slot without NUL is
   valid (the slot length is the string length, 03 §8.2.1). */
static int sx_slot_utf16_ok(const unsigned char *p, uint32_t units)
{
  uint32_t i;
  for (i = 0; i < units; i++) {
    uint32_t c = rd16(p + 2u * i);
    if (c == 0)
      return 1;
    if (c >= 0xDC00u && c <= 0xDFFFu)
      return 0;
    if (c >= 0xD800u && c <= 0xDBFFu) {
      uint32_t d;
      if (i + 1 >= units)
        return 0;
      d = rd16(p + 2u * (i + 1));
      if (d < 0xDC00u || d > 0xDFFFu)
        return 0;
      i++;
    }
  }
  return 1;
}

/* Empty, or exactly 32 hex digits (03 §8.2.1: profile_id). */
static int sx_profile_id_ok(const unsigned char *p)
{
  uint32_t i;
  if (rd16(p) == 0)
    return 1;
  for (i = 0; i < 32; i++) {
    uint32_t c = rd16(p + 2u * i);
    int hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    if (!hex)
      return 0;
  }
  return 1;
}

static int sx_parse_entry(const unsigned char *e, shx_entry *o)
{
  uint32_t flags = rd32(e);
  uint32_t state = rd32(e + 4);
  uint32_t backend = rd32(e + 8);
  uint32_t letter = rd16(e + 16);

  if ((flags & SHX_F_IN_USE) == 0)
    return 0;
  if (flags & ~SHX_F_KNOWN_MASK)
    return 0;
  if (letter != 0 && (letter < 'A' || letter > 'Z'))
    return 0;
  if (!sx_slot_utf16_ok(e + SHX_SLOT_MOUNT_ID, 32) || !sx_slot_utf16_ok(e + SHX_SLOT_NAME, 128) ||
      !sx_slot_utf16_ok(e + SHX_SLOT_TARGET, 260) || !sx_slot_utf16_ok(e + SHX_SLOT_LABEL, 64) ||
      !sx_slot_utf16_ok(e + SHX_SLOT_URL, 320))
    return 0;
  if (!sx_profile_id_ok(e + SHX_SLOT_PROFILE))
    return 0;

  /* Unknown enumeration values are read as 0 (not a reason to drop the entry). */
  if (state > SHX_STATE_UNMOUNTED)
    state = SHX_STATE_UNKNOWN;
  if (backend > 2u)
    backend = 0;

  o->flags = flags;
  o->state = state;
  o->backend = backend;
  o->mount_num = rd32(e + 12);
  o->letter = (WCHAR)letter;
  /* The URL slot was validated as well-formed UTF-16 above; a full slot without NUL gets one here. */
  memcpy(o->remote_url, e + SHX_SLOT_URL, 320u * sizeof(WCHAR));
  o->remote_url[320] = 0;
  if ((flags & SHX_F_HAS_REMOTE_URL) == 0)
    o->remote_url[0] = 0;
  return 1;
}

/* Validates the whole local copy and copies the valid entries out. */
static size_t sx_parse(const unsigned char *b, uint32_t total, shx_entry *out, size_t max)
{
  uint32_t hs, es, ec, i;
  size_t count = 0;

  if (rd32(b) != SHX_SNAP_MAGIC)
    return 0;
  if (rd16(b + 4) != 1u && rd16(b + 4) != 2u)       /* layout 2 only adds fields after the v1 tail */
    return 0;
  hs = rd16(b + 6);
  if (hs < SHX_SNAP_HEADER_BYTES || hs > total)
    return 0;
  if (rd32(b + 8) != total || total > SHX_SNAP_MAX_BYTES)
    return 0;
  es = rd32(b + 12);
  if (es < SHX_SNAP_ENTRY_BYTES || es > 4096u || (es % 8u) != 0)
    return 0;
  ec = rd32(b + 16);
  if (ec > SHX_SNAP_MAX_ENTRIES)
    return 0;
  /* ec <= 128 and es <= 4096 keep the product below 2^19, so this sum cannot wrap. */
  if (total != hs + ec * es)
    return 0;

  for (i = 0; i < ec && count < max; i++) {
    shx_entry ent;
    if (sx_parse_entry(b + hs + i * es, &ent)) {
      out[count] = ent;
      count++;
    }
  }
  return count;
}

#ifdef SD_SHELLEXT_TEST
/* Owner must be the current user and the mandatory label absent or at least medium (TM-R26). */
static int sx_owner_and_label_ok(HANDLE h)
{
  PSID owner = NULL;
  PACL sacl = NULL;
  PSECURITY_DESCRIPTOR sd = NULL;
  HANDLE tok = NULL;
  TOKEN_USER *tu = NULL;
  DWORD len = 0;
  WORD i;
  int ok = 0;

  if (GetSecurityInfo(h, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION, &owner,
                      NULL, NULL, &sacl, &sd) != ERROR_SUCCESS)
    return 0;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok))
    goto done;
  GetTokenInformation(tok, TokenUser, NULL, 0, &len);
  if (len == 0)
    goto done;
  tu = (TOKEN_USER *)sd_alloc(len);
  if (tu == NULL || !GetTokenInformation(tok, TokenUser, tu, len, &len))
    goto done;
  if (owner == NULL || !EqualSid(owner, tu->User.Sid))
    goto done;
  ok = 1;
  if (sacl != NULL) {
    for (i = 0; i < sacl->AceCount; i++) {
      LPVOID ace = NULL;
      if (!GetAce(sacl, i, &ace) || ace == NULL) {
        ok = 0;
        break;
      }
      if (((ACE_HEADER *)ace)->AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE) {
        PSID ls = (PSID)&((shx_label_ace *)ace)->SidStart;
        UCHAR n = *GetSidSubAuthorityCount(ls);
        if (n == 0 || *GetSidSubAuthority(ls, (DWORD)(n - 1)) < SECURITY_MANDATORY_MEDIUM_RID)
          ok = 0;
        break;
      }
    }
  }
done:
  if (tok != NULL)
    CloseHandle(tok);
  if (tu != NULL)
    sd_free(tu);
  if (sd != NULL)
    LocalFree(sd);
  return ok;
}

static HANDLE sx_open_test_section(void)
{
  wchar_t name[260];
  DWORD n = GetEnvironmentVariableW(L"SHELLDRIVE_TEST_STATE_NAME", name, 260);
  HANDLE h;
  if (n == 0 || n >= 260)
    return NULL;
  h = OpenFileMappingW(FILE_MAP_READ | READ_CONTROL, FALSE, name);
  if (h == NULL)
    return NULL;
  if (!sx_owner_and_label_ok(h)) {
    CloseHandle(h);
    return NULL;
  }
  return h;
}
#endif

static HANDLE sx_open_section(void)
{
  HANDLE h = NULL;
#ifdef SD_SHELLEXT_TEST
  if (GetEnvironmentVariableW(L"SHELLDRIVE_TEST_STATE_NAME", NULL, 0) != 0)
    return sx_open_test_section();
#endif
  if (sd_ipc_state_open(&h) != SD_OK)
    return NULL;
  return h;
}

size_t shx_snapshot_read(shx_entry *out, size_t max)
{
  HANDLE h;
  unsigned char *view;
  unsigned char *copy = NULL;
  unsigned char hdr[SHX_SNAP_HEADER_BYTES];
  uint32_t seq1 = 0, seq2 = 0, total = 0;
  unsigned attempt;
  size_t count = 0;

  if (out == NULL || max == 0)
    return 0;
  h = sx_open_section();
  if (h == NULL)
    return 0;
  view = (unsigned char *)MapViewOfFile(h, FILE_MAP_READ, 0, 0, SHX_SNAP_MAX_BYTES);
  if (view == NULL) {
    CloseHandle(h);
    return 0;
  }

  for (attempt = 0; attempt < SHX_TRIES; attempt++) {
    seq1 = *(const volatile uint32_t *)(view + SHX_SEQ_OFFSET);
    if (seq1 & 1u)
      continue;                         /* a write is in progress */
    memcpy(hdr, view, SHX_SNAP_HEADER_BYTES);
    MemoryBarrier();
    total = rd32(hdr + 8);
    if (total >= SHX_SNAP_HEADER_BYTES && total <= SHX_SNAP_MAX_BYTES) {
      copy = (unsigned char *)sd_alloc(total);
      if (copy == NULL)
        break;
      memcpy(copy, view, total);
    }
    MemoryBarrier();
    seq2 = *(const volatile uint32_t *)(view + SHX_SEQ_OFFSET);
    if (seq2 != seq1) {
      if (copy != NULL)
        sd_free(copy);
      copy = NULL;
      continue;                         /* the writer published while we copied */
    }
    break;                              /* stable: either a copy to parse or a stable bad header */
  }
  UnmapViewOfFile(view);
  CloseHandle(h);

  if (copy != NULL) {
    count = sx_parse(copy, total, out, max);
    sd_free(copy);
  }
  return count;
}
