/* sd_state: codec round trip, truncation, the seqlock reader under a live writer, corrupt headers and
 * entries, layout skew, and the section (owner/label checks through sd_ipc). */
#include <windows.h>
#include <sddl.h>
#include <stdio.h>
#include <string.h>

#include "sd_test.h"
#include "sd_state/sd_state.h"
#include "sd_ipc/sd_ipc.h"
#include "sd_base/sd_mem.h"
#include "sd_platform/sd_platform.h"

#define BUF_SIZE SD_STATE_MAX_BYTES

/* ---- helpers ---- */

static uint8_t *new_buf(void)
{
  return (uint8_t *)sd_calloc(1, BUF_SIZE);
}

static void put_entry(sd_state_entry *e, uint32_t num, wchar_t letter, const wchar_t *label)
{
  memset(e, 0, sizeof(*e));
  e->flags = SD_STATE_EF_READ_ONLY;
  e->state = SD_STATE_S_MOUNTED;
  e->backend = SD_STATE_B_WEBDAV;
  e->mount_num = num;
  e->letter = (uint16_t)letter;
  _snwprintf_s(e->mount_id, SD_STATE_ID_CCH + 1u, _TRUNCATE, L"m-%u", (unsigned)num);
  wcscpy_s(e->profile_id, SD_STATE_ID_CCH + 1u, L"7f3c2a90d1e44b6c9a0e5b21c4d7f8aa");
  _snwprintf_s(e->profile_name, SD_STATE_NAME_CCH + 1u, _TRUNCATE, L"Profile %u", (unsigned)num);
  _snwprintf_s(e->target, SD_STATE_TARGET_CCH + 1u, _TRUNCATE, L"%lc:", (wint_t)letter);
  wcscpy_s(e->label, SD_STATE_LABEL_CCH + 1u, label);
  wcscpy_s(e->remote_url, SD_STATE_URL_CCH + 1u, L"sftp://alice@new.test:22/home/alice");
}

static int wcs_eq(const wchar_t *a, const wchar_t *b)
{
  return wcscmp(a, b) == 0;
}

/* writes two entries with the v1 layout; returns the buffer (caller frees) */
static uint8_t *good_buffer(void)
{
  sd_state_entry e[2];
  sd_state_publish p;
  uint8_t *b = new_buf();
  put_entry(&e[0], 1, L'X', L"Work");
  put_entry(&e[1], 2, L'Y', L"Backups");
  memset(&p, 0, sizeof(p));
  p.entries = e;
  p.entry_count = 2;
  if (b == NULL || sd_state_publish_buffer(b, BUF_SIZE, &p, NULL) != SD_OK) {
    sd_free(b);
    return NULL;
  }
  return b;
}

static void wr32le(uint8_t *p, uint32_t v)
{
  p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static uint32_t rd32le(const uint8_t *p)
{
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static sd_err read_copy(const uint8_t *b, sd_state_snapshot *snap)
{
  return sd_state_read_buffer(b, BUF_SIZE, snap);
}

/* ---- round trip and truncation ---- */

SD_TEST(state_round_trip)
{
  uint8_t *b = good_buffer();
  sd_state_snapshot *s = NULL;
  SD_REQUIRE(b != NULL);
  SD_REQUIRE(sd_state_snapshot_new(&s) == SD_OK);
  SD_REQUIRE(read_copy(b, s) == SD_OK);
  SD_CHECK(s->count == 2);
  SD_CHECK(s->dropped == 0);
  SD_CHECK(s->header.layout_version == 1);
  SD_CHECK(s->header.entry_size == SD_STATE_ENTRY_SIZE);
  SD_CHECK(s->header.entry_count == 2);
  SD_CHECK(s->header.seq % 2 == 0);
  SD_CHECK(s->entries[0].letter == 'X' && s->entries[1].letter == 'Y');
  SD_CHECK(wcs_eq(s->entries[0].mount_id, L"m-1"));
  SD_CHECK(wcs_eq(s->entries[1].label, L"Backups"));
  SD_CHECK(wcs_eq(s->entries[0].profile_id, L"7f3c2a90d1e44b6c9a0e5b21c4d7f8aa"));
  SD_CHECK(wcs_eq(s->entries[0].remote_url, L"sftp://alice@new.test:22/home/alice"));
  SD_CHECK(s->entries[0].flags & SD_STATE_EF_IN_USE);
  SD_CHECK(s->entries[0].flags & SD_STATE_EF_HAS_REMOTE_URL);
  SD_CHECK(s->entries[0].state == SD_STATE_S_MOUNTED && s->entries[0].backend == SD_STATE_B_WEBDAV);
  SD_CHECK(s->header.writer_pid == GetCurrentProcessId());
  SD_CHECK(s->header.published_filetime != 0);
  sd_state_snapshot_free(s);
  sd_free(b);
}

SD_TEST(state_truncation_is_safe)
{
  sd_state_entry e;
  sd_state_publish p;
  uint8_t *b = new_buf();
  sd_state_snapshot *s = NULL;
  wchar_t longlabel[80];
  uint32_t cuts = 99, i;
  int cut;
  SD_REQUIRE(b != NULL);
  SD_REQUIRE(sd_state_snapshot_new(&s) == SD_OK);
  /* 70 units into a 64-unit slot: cut to 63 units + NUL, the caller flags the entry */
  for (i = 0; i < 70; i++) longlabel[i] = L'a';
  longlabel[70] = 0;
  put_entry(&e, 1, L'X', L"");
  cut = sd_state_set_string(e.label, SD_STATE_LABEL_CCH, longlabel);
  SD_CHECK(cut == 1 && wcslen(e.label) == SD_STATE_LABEL_CCH - 1u);
  if (cut) e.flags |= SD_STATE_EF_TRUNCATED;
  memset(&p, 0, sizeof(p));
  p.entries = &e;
  p.entry_count = 1;
  SD_REQUIRE(sd_state_publish_buffer(b, BUF_SIZE, &p, &cuts) == SD_OK);
  SD_CHECK(cuts == 0);                          /* already cut by the producer: nothing left to cut here */
  SD_REQUIRE(read_copy(b, s) == SD_OK);
  SD_REQUIRE(s->count == 1);
  SD_CHECK(wcslen(s->entries[0].label) == SD_STATE_LABEL_CCH - 1u);
  SD_CHECK(s->entries[0].flags & SD_STATE_EF_TRUNCATED);

  /* a surrogate pair straddling the cut is not split: 62 units, then a pair at 62..63 */
  for (i = 0; i < 62; i++) longlabel[i] = L'b';
  longlabel[62] = 0xD83D;
  longlabel[63] = 0xDE00;
  for (i = 64; i < 70; i++) longlabel[i] = L'c';
  longlabel[70] = 0;
  cut = sd_state_set_string(e.label, SD_STATE_LABEL_CCH, longlabel);
  SD_CHECK(cut == 1 && wcslen(e.label) == 62);
  SD_CHECK(e.label[61] == L'b' && e.label[62] == 0);
  SD_REQUIRE(sd_state_publish_buffer(b, BUF_SIZE, &p, &cuts) == SD_OK);
  SD_REQUIRE(read_copy(b, s) == SD_OK);
  SD_REQUIRE(s->count == 1);
  SD_CHECK(wcslen(s->entries[0].label) == 62);            /* the high half is dropped with the cut */
  SD_CHECK(s->entries[0].label[61] == L'b');
  /* a string that fits whole is copied and not flagged */
  SD_CHECK(sd_state_set_string(e.label, SD_STATE_LABEL_CCH, L"Work") == 0 && wcscmp(e.label, L"Work") == 0);

  sd_state_snapshot_free(s);
  sd_free(b);
}

/* ---- seqlock reader under a live writer ---- */

typedef struct torn_ctx {
  uint8_t *buf;
  volatile LONG stop;
  volatile LONG published;
} torn_ctx;

static DWORD WINAPI torn_writer(LPVOID arg)
{
  torn_ctx *c = (torn_ctx *)arg;
  sd_state_entry *e = (sd_state_entry *)sd_calloc(16, sizeof(sd_state_entry));   /* 16 entries: off the thread stack */
  if (e == NULL)
    return 0;
  sd_state_publish p;
  uint32_t gen = 1, i;
  while (!InterlockedCompareExchange(&c->stop, 0, 0)) {
    /* every entry of one publish carries the same generation; a torn read would mix two */
    for (i = 0; i < 16; i++) {
      put_entry(&e[i], gen, L'X', L"gen");
      _snwprintf_s(e[i].label, SD_STATE_LABEL_CCH + 1u, _TRUNCATE, L"gen-%u", (unsigned)gen);
    }
    memset(&p, 0, sizeof(p));
    p.entries = e;
    p.entry_count = 16;
    (void)sd_state_publish_buffer(c->buf, BUF_SIZE, &p, NULL);
    InterlockedIncrement(&c->published);
    gen++;
  }
  sd_free(e);
  return 0;
}

SD_TEST(state_torn_reads_never_mix)
{
  torn_ctx c;
  HANDLE th;
  sd_state_snapshot *s = NULL;
  uint32_t ok = 0, busy = 0, i, j;
  memset(&c, 0, sizeof(c));
  c.buf = new_buf();
  SD_REQUIRE(c.buf != NULL);
  SD_REQUIRE(sd_state_snapshot_new(&s) == SD_OK);
  /* seed so that the first reads have data */
  {
    sd_state_entry e[1];
    sd_state_publish p;
    put_entry(&e[0], 0, L'X', L"seed");
    memset(&p, 0, sizeof(p));
    p.entries = e;
    p.entry_count = 1;
    SD_REQUIRE(sd_state_publish_buffer(c.buf, BUF_SIZE, &p, NULL) == SD_OK);
  }
  th = CreateThread(NULL, 0, torn_writer, &c, 0, NULL);
  SD_REQUIRE(th != NULL);
  for (i = 0; i < 20000; i++) {
    sd_err e = read_copy(c.buf, s);
    if (e == SD_OK) {
      ok++;
      SD_CHECK(s->header.seq % 2 == 0);
      if (s->count == 1) {
        /* the seed, read before the writer thread's first publish */
        SD_CHECK(s->entries[0].mount_num == 0);
        continue;
      }
      SD_CHECK(s->count == 16);
      for (j = 1; j < s->count; j++) {
        if (s->entries[j].mount_num != s->entries[0].mount_num) {
          SD_CHECK(s->entries[j].mount_num == s->entries[0].mount_num);   /* a torn snapshot: fail */
          break;
        }
      }
    } else {
      SD_CHECK(e == SD_E_BUSY);
      busy++;
    }
  }
  /* on a loaded machine the writer thread may not have been scheduled yet: give it up to 10 s to publish */
  for (i = 0; i < 1000 && InterlockedCompareExchange((volatile LONG *)&c.published, 0, 0) == 0; i++)
    Sleep(10);
  InterlockedExchange(&c.stop, 1);
  WaitForSingleObject(th, INFINITE);
  CloseHandle(th);
  SD_CHECK(ok > 0);                                 /* the reader gets through, not only "no data" */
  SD_CHECK(c.published > 0);
  (void)busy;
  sd_state_snapshot_free(s);
  sd_free(c.buf);
}

/* A seq that stays odd (a writer stopped mid-write) is "no data", after three tries. */
SD_TEST(state_odd_seq_is_no_data)
{
  uint8_t *b = good_buffer();
  sd_state_snapshot *s = NULL;
  SD_REQUIRE(b != NULL);
  SD_REQUIRE(sd_state_snapshot_new(&s) == SD_OK);
  wr32le(b + 20, rd32le(b + 20) + 1u);             /* odd */
  SD_CHECK(read_copy(b, s) == SD_E_BUSY);
  SD_CHECK(s->count == 0);
  /* the publish repairs a stale odd seq and reads are good again */
  {
    sd_state_entry e[1];
    sd_state_publish p;
    put_entry(&e[0], 3, L'Z', L"again");
    memset(&p, 0, sizeof(p));
    p.entries = e;
    p.entry_count = 1;
    SD_REQUIRE(sd_state_publish_buffer(b, BUF_SIZE, &p, NULL) == SD_OK);
  }
  SD_REQUIRE(read_copy(b, s) == SD_OK);
  SD_CHECK(s->count == 1 && s->entries[0].letter == 'Z');
  sd_state_snapshot_free(s);
  sd_free(b);
}

/* ---- corrupt header fields: every one is "no data" ---- */

typedef struct corrupt_case {
  const char *name;
  uint32_t off;
  uint32_t value;
  int bytes;                      /* 2 or 4 */
} corrupt_case;

SD_TEST(state_corrupt_header_is_no_data)
{
  static const corrupt_case k[] = {
    { "magic", 0, 0x12345678u, 4 },
    { "layout 0", 4, 0, 2 },
    { "layout 3", 4, 3, 2 },
    { "header_size 32", 6, 32, 2 },
    { "header_size past total", 6, 0x1000u, 2 },
    { "total too small", 8, 64, 4 },
    { "total off by one entry", 8, 64 + 2 * 1792 + 1792, 4 },
    { "total above 256 KiB", 8, 262145u, 4 },
    { "entry_size 1791", 12, 1791, 4 },
    { "entry_size 1796 (not x8)", 12, 1796, 4 },
    { "entry_size 8192", 12, 8192, 4 },
    { "entry_count 129", 16, 129, 4 },
    { "entry_count huge", 16, 0xFFFFFFFFu, 4 },
  };
  uint32_t i;
  sd_state_snapshot *s = NULL;
  SD_REQUIRE(sd_state_snapshot_new(&s) == SD_OK);
  for (i = 0; i < sizeof(k) / sizeof(k[0]); i++) {
    uint8_t *b = good_buffer();
    SD_REQUIRE(b != NULL);
    if (k[i].bytes == 2) {
      b[k[i].off] = (uint8_t)k[i].value;
      b[k[i].off + 1] = (uint8_t)(k[i].value >> 8);
    } else {
      wr32le(b + k[i].off, k[i].value);
    }
    SD_CHECK(read_copy(b, s) != SD_OK);
    sd_free(b);
  }
  sd_state_snapshot_free(s);
}

/* ---- corrupt entries are dropped, the rest stays ---- */

SD_TEST(state_bad_entries_are_dropped)
{
  uint8_t *b = good_buffer();
  sd_state_snapshot *s = NULL;
  uint8_t *e0, *e1;
  SD_REQUIRE(b != NULL);
  SD_REQUIRE(sd_state_snapshot_new(&s) == SD_OK);
  e0 = b + 64;
  e1 = b + 64 + SD_STATE_ENTRY_SIZE;

  /* IN_USE cleared: entry 0 dropped */
  wr32le(e0, 0);
  SD_REQUIRE(read_copy(b, s) == SD_OK);
  SD_CHECK(s->count == 1 && s->dropped == 1 && s->entries[0].letter == 'Y');
  wr32le(e0, SD_STATE_EF_IN_USE | SD_STATE_EF_READ_ONLY);

  /* letter out of range */
  e1[16] = 0x7F; e1[17] = 0;
  SD_REQUIRE(read_copy(b, s) == SD_OK);
  SD_CHECK(s->count == 1 && s->dropped == 1);
  e1[16] = 'Y';

  /* profile_id not hex (uppercase is not the lowercase form) */
  e0[88] = 'G';
  SD_REQUIRE(read_copy(b, s) == SD_OK);
  SD_CHECK(s->count == 1 && s->dropped == 1);
  e0[88] = '7';

  /* unpaired low surrogate in the label of entry 1 */
  e1[928] = 0x00; e1[929] = 0xDC;
  SD_REQUIRE(read_copy(b, s) == SD_OK);
  SD_CHECK(s->count == 1 && s->dropped == 1);
  e1[928] = 'B'; e1[929] = 0;

  /* unknown state and backend read as unknown, the entry is kept */
  wr32le(e0 + 4, 99);
  wr32le(e0 + 8, 7);
  SD_REQUIRE(read_copy(b, s) == SD_OK);
  SD_CHECK(s->count == 2 && s->entries[0].state == SD_STATE_S_UNKNOWN && s->entries[0].backend == SD_STATE_B_UNKNOWN);

  /* unknown flag bits are ignored */
  wr32le(e0, SD_STATE_EF_IN_USE | 0x80000000u);
  SD_REQUIRE(read_copy(b, s) == SD_OK);
  SD_CHECK(s->count == 2 && s->entries[0].flags == SD_STATE_EF_IN_USE);

  sd_state_snapshot_free(s);
  sd_free(b);
}

/* ---- layout skew ---- */

/* A v2 writer (larger stride, extra fields after the v1 tail): a v1 reader reads the v1 fields. */
SD_TEST(state_v1_reader_accepts_v2_writer)
{
  sd_state_entry e[2];
  sd_state_publish p;
  uint8_t *b = new_buf();
  sd_state_snapshot *s = NULL;
  SD_REQUIRE(b != NULL);
  SD_REQUIRE(sd_state_snapshot_new(&s) == SD_OK);
  put_entry(&e[0], 1, L'X', L"Work");
  put_entry(&e[1], 2, L'Y', L"Backups");
  memset(&p, 0, sizeof(p));
  p.entries = e;
  p.entry_count = 2;
  SD_REQUIRE(sd_state_publish_layout(b, BUF_SIZE, &p, 2, 2048, NULL) == SD_OK);
  /* garbage in the v2 extension must not matter to a v1 reader */
  memset(b + 64 + 1792, 0xAB, 2048 - 1792);
  memset(b + 64 + 2048 + 1792, 0xCD, 2048 - 1792);
  SD_REQUIRE(read_copy(b, s) == SD_OK);
  SD_CHECK(s->header.layout_version == 2);
  SD_CHECK(s->header.entry_size == 2048);
  SD_REQUIRE(s->count == 2);
  SD_CHECK(s->entries[1].letter == 'Y');
  SD_CHECK(wcs_eq(s->entries[1].label, L"Backups"));
  /* a v2 stride at 4096 is still readable */
  SD_REQUIRE(sd_state_publish_layout(b, BUF_SIZE, &p, 2, 4096, NULL) == SD_OK);
  SD_REQUIRE(read_copy(b, s) == SD_OK);
  SD_CHECK(s->count == 2 && s->entries[0].letter == 'X');
  sd_state_snapshot_free(s);
  sd_free(b);
}

/* Unknown layouts: 0, 3 and a future 9 are "no data" for a v1 reader, and the writer of another layout
   produces them only through the test entry point. */
SD_TEST(state_unknown_layout_is_no_data)
{
  uint32_t layouts[3] = { 0, 3, 9 };
  uint32_t i;
  sd_state_entry e[1];
  sd_state_publish p;
  uint8_t *b = new_buf();
  sd_state_snapshot *s = NULL;
  SD_REQUIRE(b != NULL);
  SD_REQUIRE(sd_state_snapshot_new(&s) == SD_OK);
  put_entry(&e[0], 1, L'X', L"Work");
  memset(&p, 0, sizeof(p));
  p.entries = e;
  p.entry_count = 1;
  for (i = 0; i < 3; i++) {
    /* the codec refuses to write layout 0, so that case is patched in after a layout 1 publish */
    SD_REQUIRE(sd_state_publish_layout(b, BUF_SIZE, &p, layouts[i] ? layouts[i] : 1u, SD_STATE_ENTRY_SIZE,
                                       NULL) == SD_OK);
    if (layouts[i] == 0)
      b[4] = 0;
    SD_CHECK(read_copy(b, s) != SD_OK);
  }
  sd_state_snapshot_free(s);
  sd_free(b);
}

/* ---- the section: create, publish, read, close; squatting ---- */

static void set_test_suffix(void)
{
  sd_ipc_set_instance_suffix(L"statetest");
}

SD_TEST(state_section_round_trip)
{
  sd_state_writer *w = NULL;
  sd_state_snapshot *s = NULL;
  sd_state_entry e[1];
  sd_state_publish p;
  set_test_suffix();
  SD_REQUIRE(sd_state_snapshot_new(&s) == SD_OK);
  SD_CHECK(sd_state_read_section(s) == SD_E_NOT_FOUND);  /* no writer yet */
  SD_REQUIRE(sd_state_writer_open(&w) == SD_OK);
  put_entry(&e[0], 4, L'R', L"Reports");
  memset(&p, 0, sizeof(p));
  p.entries = e;
  p.entry_count = 1;
  SD_REQUIRE(sd_state_writer_publish(w, &p, NULL) == SD_OK);
  SD_REQUIRE(sd_state_read_section(s) == SD_OK);
  SD_CHECK(s->count == 1 && s->entries[0].letter == 'R');
  SD_CHECK(wcs_eq(s->entries[0].label, L"Reports"));
  /* shutdown: empty with the shutting-down flag */
  memset(&p, 0, sizeof(p));
  p.flags = SD_STATE_HF_SHUTTING_DOWN;
  SD_REQUIRE(sd_state_writer_publish(w, &p, NULL) == SD_OK);
  SD_REQUIRE(sd_state_read_section(s) == SD_OK);
  SD_CHECK(s->count == 0 && (s->header.flags & SD_STATE_HF_SHUTTING_DOWN));
  sd_state_writer_close(w);
  /* no handle left: the section is gone */
  SD_CHECK(sd_state_read_section(s) == SD_E_NOT_FOUND);
  sd_state_snapshot_free(s);
  sd_ipc_set_instance_suffix(NULL);
}

/* A section created by someone else with a low integrity label is squatted: the reader and the writer
   refuse it (fail closed). Owner squatting by another user needs an administrator and is not tested
   here (03 §2.2 covers it through the same owner check). Vista+ only: labels do not exist on XP. */
SD_TEST(state_squatted_low_label_is_refused)
{
  wchar_t name[160];
  HANDLE h;
  PSECURITY_DESCRIPTOR sd = NULL;
  SECURITY_ATTRIBUTES sa;
  sd_state_snapshot *s = NULL;
  sd_state_writer *w = NULL;
  if (!sd_os_at_least(6, 0, 0))
    return;                                /* no mandatory labels on XP */
  set_test_suffix();
  SD_REQUIRE(sd_ipc_object_name(SD_IPC_OBJ_STATE, name, sizeof(name) / sizeof(name[0])) == SD_OK);
  SD_REQUIRE(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;GA;;;OW)S:(ML;;NW;;;LW)", SDDL_REVISION_1,
                                                                   &sd, NULL));
  sa.nLength = sizeof(sa);
  sa.lpSecurityDescriptor = sd;
  sa.bInheritHandle = FALSE;
  h = CreateFileMappingW(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE, 0, SD_STATE_MAX_BYTES, name);
  LocalFree(sd);
  SD_REQUIRE(h != NULL);
  SD_REQUIRE(sd_state_snapshot_new(&s) == SD_OK);
  SD_CHECK(sd_state_read_section(s) == SD_E_ACCESS_DENIED);
  SD_CHECK(sd_state_writer_open(&w) == SD_E_ACCESS_DENIED);
  SD_CHECK(w == NULL);
  CloseHandle(h);
  sd_state_snapshot_free(s);
  sd_ipc_set_instance_suffix(NULL);
}
