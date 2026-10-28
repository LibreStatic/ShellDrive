/* M1 sd_vfs behavior against the fake sd_sftp: read-ahead and the block cache (memory and disk
 * tiers, coherency), single-flight misses, write-behind (window, sticky errors, grace retransmit,
 * write_failed), reconnect (lazy re-open, identity check, serving cached data while disconnected)
 * and identity without exec (02 §3.4, §4, §5). */
#include <windows.h>
#include <process.h>
#include <sddl.h>
#include <stdio.h>
#include <string.h>

#include "fake_sftp.h"
#include "sd_base/sd_mem.h"
#include "sd_platform/sd_time.h"
#include "sd_test.h"
#include "sd_vfs/sd_vfs.h"

#define SHARE_ALL (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
#define OLD_MTIME 1600000000ll

typedef struct ev_log {
  volatile LONG write_failed, identity, notices, state;
  UINT64 wf_bytes;
  sd_vfs_status wf_status;
  char last_code[64], last_detail[160];
} ev_log;

static void on_event(void *ctx, const sd_vfs_event *ev)
{
  ev_log *l = (ev_log *)ctx;
  switch (ev->kind) {
    case SD_VFS_EV_WRITE_FAILED:
      l->wf_bytes = ev->bytes;
      l->wf_status = ev->status;
      InterlockedIncrement(&l->write_failed);
      break;
    case SD_VFS_EV_IDENTITY: InterlockedIncrement(&l->identity); break;
    case SD_VFS_EV_STATE: InterlockedIncrement(&l->state); break;
    case SD_VFS_EV_NOTICE:
      if (ev->code) strncpy_s(l->last_code, sizeof(l->last_code), ev->code, _TRUNCATE);
      if (ev->detail) strncpy_s(l->last_detail, sizeof(l->last_detail), ev->detail, _TRUNCATE);
      InterlockedIncrement(&l->notices);
      break;
    default: break;
  }
}

typedef struct fixture { sd_sftp_session *s; sd_vfs *v; sd_vfs_options o; ev_log ev; } fixture;

static void opts(sd_vfs_options *o)
{
  memset(o, 0, sizeof(*o));
  o->struct_size = sizeof(*o);
  o->hide_dotfiles = TRUE;
  o->map_readonly = TRUE;
  o->allow_system = TRUE;
  o->fsync_on_flush = TRUE;
  o->symlinks = SD_SYMLINK_FOLLOW_INSIDE;
  o->request_timeout_ms = 10000;
  o->offline_wait_ms = 200;
}

static int fx_start(fixture *f, const fake_config *cfg, const sd_vfs_options *o)
{
  memset(f, 0, sizeof(*f));
  f->s = fake_session_create(cfg);
  if (o) f->o = *o; else opts(&f->o);
  return sd_vfs_mount(f->s, &f->o, on_event, &f->ev, &f->v) == SD_VFS_OK;
}

static void fx_unmount(fixture *f)
{
  if (f->v) {
    sd_vfs_quiesce(f->v, 2000);
    sd_vfs_unmount(f->v);
    f->v = NULL;
  }
}

static void fx_done(fixture *f)
{
  fx_unmount(f);
  fake_session_destroy(f->s);
}

static sd_vfs_status vopen(fixture *f, const WCHAR *p, UINT32 access, UINT32 disp, UINT32 opts_, sd_vfs_handle **h)
{
  BOOL existed, dir;
  return sd_vfs_create(f->v, p, NULL, access, SHARE_ALL, disp, opts_, 0, h, &existed, &dir);
}

static void vclose(sd_vfs_handle *h)
{
  sd_vfs_cleanup(h, FALSE);
  sd_vfs_close(h);
}

static uint8_t *pattern(size_t n, uint32_t seed)
{
  uint8_t *p = (uint8_t *)sd_alloc(n);
  size_t i;
  uint32_t x = seed * 2654435761u + 1;
  if (!p)
    return NULL;
  for (i = 0; i < n; i++) {
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    p[i] = (uint8_t)x;
  }
  return p;
}

static double now_s(void)
{
  LARGE_INTEGER c, fq;
  QueryPerformanceCounter(&c);
  QueryPerformanceFrequency(&fq);
  return (double)c.QuadPart / (double)fq.QuadPart;
}

/* Sequential reads of `chunk` bytes over the whole file; returns MiB/s, checks the content. */
static double seq_read(fixture *f, const WCHAR *path, UINT32 opts_, const uint8_t *expect, uint32_t size,
                       uint32_t chunk, int *ok)
{
  sd_vfs_handle *h = NULL;
  uint8_t *buf = (uint8_t *)sd_alloc(chunk);
  uint32_t off = 0, got = 0;
  double t0, t1;
  *ok = 0;
  if (!buf || vopen(f, path, GENERIC_READ, SD_VFS_FILE_OPEN, opts_, &h) != SD_VFS_OK) {
    sd_free(buf);
    return 0;
  }
  *ok = 1;
  t0 = now_s();
  while (off < size) {
    if (sd_vfs_read(h, off, buf, chunk, &got) != SD_VFS_OK || got == 0) {
      *ok = 0;
      break;
    }
    if (memcmp(buf, expect + off, got) != 0)
      *ok = 0;
    off += got;
  }
  t1 = now_s();
  vclose(h);
  sd_free(buf);
  return ((double)off / (1024.0 * 1024.0)) / (t1 - t0 > 1e-6 ? t1 - t0 : 1e-6);
}

/* ---- read-ahead ---- */

SD_TEST(vfs_readahead_4k_sequential_throughput)
{
  enum { SIZE = 64u << 20, NORA = 8u << 20 };
  fixture f;
  fake_config cfg;
  uint8_t *data = pattern(SIZE, 7);
  double ra, nora;
  int ok;
  SD_REQUIRE(data);
  memset(&cfg, 0, sizeof(cfg));
  cfg.latency_ms = 10;                      /* simulated round trip: one request is not enough */
  SD_REQUIRE(fx_start(&f, &cfg, NULL));
  SD_REQUIRE(fake_put(f.s, "/home/user/big.bin", data, SIZE, 0644) == 0);
  SD_REQUIRE(fake_put(f.s, "/home/user/nora.bin", data, NORA, 0644) == 0);
  ra = seq_read(&f, L"\\big.bin", 0, data, SIZE, 4096, &ok);
  SD_CHECK(ok);
  nora = seq_read(&f, L"\\nora.bin", SD_VFS_FILE_RANDOM_ACCESS, data, NORA, 4096, &ok);
  SD_CHECK(ok);
  printf("  4 KiB sequential reads, 10 ms latency: %.1f MiB/s with read-ahead, %.1f MiB/s without\n", ra, nora);
  SD_CHECK(ra >= 50.0);                     /* M1 target (docs/dev/m0-acceptance.md gap) */
  SD_CHECK(ra > nora);
  fx_done(&f);
  sd_free(data);
}

typedef struct sf_arg { fixture *f; HANDLE go; LONG ok; uint8_t buf[4096]; } sf_arg;

static unsigned __stdcall sf_reader(void *p)
{
  sf_arg *a = (sf_arg *)p;
  sd_vfs_handle *h = NULL;
  UINT32 got = 0;
  if (vopen(a->f, L"\\one.bin", GENERIC_READ, SD_VFS_FILE_OPEN, SD_VFS_FILE_RANDOM_ACCESS, &h) != SD_VFS_OK)
    return 0;
  WaitForSingleObject(a->go, INFINITE);
  if (sd_vfs_read(h, 1000, a->buf, sizeof(a->buf), &got) == SD_VFS_OK && got == sizeof(a->buf))
    a->ok = 1;
  vclose(h);
  return 0;
}

SD_TEST(vfs_single_flight_concurrent_misses)
{
  enum { N = 8 };
  fixture f;
  fake_config cfg;
  sf_arg *a = (sf_arg *)sd_calloc(N, sizeof(sf_arg));
  HANDLE th[N], go;
  uint8_t *data = pattern(256 * 1024, 3);
  int i;
  SD_REQUIRE(data && a);
  memset(&cfg, 0, sizeof(cfg));
  cfg.latency_ms = 100;
  SD_REQUIRE(fx_start(&f, &cfg, NULL));
  fake_put(f.s, "/home/user/one.bin", data, 256 * 1024, 0644);
  go = CreateEventW(NULL, TRUE, FALSE, NULL);
  SD_REQUIRE(go != NULL);
  for (i = 0; i < N; i++) {
    a[i].f = &f;
    a[i].go = go;
    a[i].ok = 0;
    th[i] = (HANDLE)_beginthreadex(NULL, 0, sf_reader, &a[i], 0, NULL);
    SD_REQUIRE(th[i] != NULL);
  }
  Sleep(1500);                              /* every thread has its handle (opens are slow: 100 ms) */
  fake_reset_counts(f.s);
  SetEvent(go);
  WaitForMultipleObjects(N, th, TRUE, INFINITE);
  for (i = 0; i < N; i++) {
    CloseHandle(th[i]);
    SD_CHECK(a[i].ok);
    SD_CHECK_MEM(a[i].buf, data + 1000, sizeof(a[i].buf));
  }
  SD_CHECK_EQ_INT(fake_count(f.s, FOP_READ), 1);   /* one wire read for 8 concurrent misses */
  CloseHandle(go);
  fx_done(&f);
  sd_free(data);
  sd_free(a);
}

/* ---- coherency (02 §4.2) ---- */

static sd_vfs_status read_at(fixture *f, const WCHAR *path, UINT64 off, void *buf, UINT32 len, UINT32 *got)
{
  sd_vfs_handle *h = NULL;
  sd_vfs_status st = vopen(f, path, GENERIC_READ, SD_VFS_FILE_OPEN, SD_VFS_FILE_RANDOM_ACCESS, &h);
  if (st != SD_VFS_OK)
    return st;
  st = sd_vfs_read(h, off, buf, len, got);
  vclose(h);
  return st;
}

SD_TEST(vfs_cache_coherency_by_validator)
{
  fixture f;
  sd_vfs_options o;
  char buf[16];
  UINT32 got = 0;
  uint32_t reads;
  opts(&o);
  o.open_revalidate_ms = 1;                 /* every open revalidates (close-to-open) */
  /* The pauses below must exceed one sd_tick_ms() step (GetTickCount64: 15.6 ms by default), or the
     "1 ms" revalidation age can read as 0 and the open is served from the attribute cache. */
  o.attr_ttl_ms = 300;
  SD_REQUIRE(fx_start(&f, NULL, &o));
  fake_put(f.s, "/home/user/c.txt", "version-1", 9, 0644);
  fake_set_mtime(f.s, "/home/user/c.txt", OLD_MTIME);
  SD_CHECK_EQ_INT(read_at(&f, L"\\c.txt", 0, buf, sizeof(buf), &got), SD_VFS_OK);
  SD_CHECK(got == 9 && memcmp(buf, "version-1", 9) == 0);
  reads = fake_count(f.s, FOP_READ);
  Sleep(40);
  /* Unchanged validator: served from the cache (only the lstat goes out). */
  SD_CHECK_EQ_INT(read_at(&f, L"\\c.txt", 0, buf, sizeof(buf), &got), SD_VFS_OK);
  SD_CHECK(got == 9 && memcmp(buf, "version-1", 9) == 0);
  SD_CHECK_EQ_INT(fake_count(f.s, FOP_READ), reads);
  /* Same size, new mtime: the blocks are dropped. */
  fake_overwrite(f.s, "/home/user/c.txt", "version-2", 9, OLD_MTIME + 60);
  Sleep(40);
  SD_CHECK_EQ_INT(read_at(&f, L"\\c.txt", 0, buf, sizeof(buf), &got), SD_VFS_OK);
  SD_CHECK(got == 9 && memcmp(buf, "version-2", 9) == 0);
  /* New size, same mtime: dropped too. */
  fake_overwrite(f.s, "/home/user/c.txt", "version-3!", 10, OLD_MTIME + 60);
  Sleep(40);
  SD_CHECK_EQ_INT(read_at(&f, L"\\c.txt", 0, buf, sizeof(buf), &got), SD_VFS_OK);
  SD_CHECK(got == 10 && memcmp(buf, "version-3!", 10) == 0);

  /* Hot blocks (mtime within 2 s of the server's clock) are not trusted past attr_ttl even when
     the validator did not change (1-second mtime granularity can hide a rewrite). */
  {
    int64_t t = 0;
    fake_put(f.s, "/home/user/hot.txt", "hot-aaaa", 8, 0644);
    t = fake_mtime(f.s, "/home/user/hot.txt");
    SD_CHECK_EQ_INT(read_at(&f, L"\\hot.txt", 0, buf, sizeof(buf), &got), SD_VFS_OK);
    fake_overwrite(f.s, "/home/user/hot.txt", "hot-bbbb", 8, t);   /* same size and mtime */
    Sleep(400);
    SD_CHECK_EQ_INT(read_at(&f, L"\\hot.txt", 0, buf, sizeof(buf), &got), SD_VFS_OK);
    SD_CHECK(got == 8 && memcmp(buf, "hot-bbbb", 8) == 0);
  }
  fx_done(&f);
}

SD_TEST(vfs_cache_local_writes_update_blocks)
{
  fixture f;
  sd_vfs_handle *h = NULL;
  uint8_t *data = pattern(600 * 1024, 11), *back = (uint8_t *)sd_alloc(600 * 1024);
  UINT32 got = 0, done = 0;
  uint32_t reads;
  SD_REQUIRE(data && back);
  SD_REQUIRE(fx_start(&f, NULL, NULL));
  fake_put(f.s, "/home/user/w.bin", data, 600 * 1024, 0644);
  fake_set_mtime(f.s, "/home/user/w.bin", OLD_MTIME);
  SD_REQUIRE(vopen(&f, L"\\w.bin", GENERIC_READ | GENERIC_WRITE, SD_VFS_FILE_OPEN, 0, &h) == SD_VFS_OK);
  SD_CHECK_EQ_INT(sd_vfs_read(h, 0, back, 600 * 1024, &got), SD_VFS_OK);
  SD_CHECK_EQ_INT(got, 600 * 1024);
  reads = fake_count(f.s, FOP_READ);
  memset(data + 300000, 'Z', 1000);         /* inside block 1 */
  SD_CHECK_EQ_INT(sd_vfs_write(h, 300000, data + 300000, 1000, &done, FALSE), SD_VFS_OK);
  memset(data + 262000, 'Y', 300);          /* across the boundary of blocks 0 and 1 */
  SD_CHECK_EQ_INT(sd_vfs_write(h, 262000, data + 262000, 300, &done, FALSE), SD_VFS_OK);
  SD_CHECK_EQ_INT(sd_vfs_write(h, 600 * 1024, "END", 3, &done, FALSE), SD_VFS_OK);   /* extends */
  memset(back, 0, 600 * 1024);
  SD_CHECK_EQ_INT(sd_vfs_read(h, 0, back, 600 * 1024, &got), SD_VFS_OK);
  SD_CHECK_MEM(back, data, 600 * 1024);
  SD_CHECK_EQ_INT(fake_count(f.s, FOP_READ), reads);   /* served from the updated blocks */
  SD_CHECK_EQ_INT(sd_vfs_read(h, 600 * 1024, back, 16, &got), SD_VFS_OK);
  SD_CHECK(got == 3 && memcmp(back, "END", 3) == 0);
  vclose(h);
  fx_done(&f);
  sd_free(data);
  sd_free(back);
}

/* ---- write-behind (02 §4.4) ---- */

static void wb_opts(sd_vfs_options *o)
{
  opts(o);
  o->write_mode = SD_VFS_WRITE_BEHIND;
}

SD_TEST(vfs_write_behind_queues_and_flushes)
{
  fixture f;
  sd_vfs_options o;
  sd_vfs_handle *h = NULL;
  uint8_t *data = pattern(3 * 65536, 5), *back = (uint8_t *)sd_alloc(3 * 65536 + 16);
  UINT32 done = 0, got = 0;
  int i;
  SD_REQUIRE(data && back);
  wb_opts(&o);
  SD_REQUIRE(fx_start(&f, NULL, &o));
  SD_REQUIRE(vopen(&f, L"\\wb.bin", GENERIC_READ | GENERIC_WRITE, SD_VFS_FILE_CREATE, 0, &h) == SD_VFS_OK);
  fake_hold_writes(f.s, 1);                 /* acks never arrive while held */
  for (i = 0; i < 3; i++) {
    SD_CHECK_EQ_INT(sd_vfs_write(h, (UINT64)i * 65536, data + i * 65536, 65536, &done, FALSE), SD_VFS_OK);
    SD_CHECK_EQ_INT(done, 65536);           /* returns once queued */
  }
  SD_CHECK_EQ_INT(fake_get(f.s, "/home/user/wb.bin", NULL, 0), 0);
  /* Reads see the queued data. */
  SD_CHECK_EQ_INT(sd_vfs_read(h, 0, back, 3 * 65536 + 16, &got), SD_VFS_OK);
  SD_CHECK_EQ_INT(got, 3 * 65536);
  SD_CHECK_MEM(back, data, 3 * 65536);
  fake_hold_writes(f.s, 0);
  SD_CHECK_EQ_INT(sd_vfs_flush(h), SD_VFS_OK);
  SD_CHECK_EQ_INT(fake_get(f.s, "/home/user/wb.bin", back, 3 * 65536), 3 * 65536);
  SD_CHECK_MEM(back, data, 3 * 65536);
  SD_CHECK(fake_count(f.s, FOP_FSYNC) == 1);
  /* Small random writes coalesce, then go out within ~500 ms (background timer). */
  SD_CHECK_EQ_INT(sd_vfs_write(h, 1000, "ab", 2, &done, FALSE), SD_VFS_OK);
  SD_CHECK_EQ_INT(sd_vfs_write(h, 900, "cd", 2, &done, FALSE), SD_VFS_OK);   /* not sequential either */
  {
    uint64_t t0 = sd_tick_ms();
    for (;;) {
      fake_get(f.s, "/home/user/wb.bin", back, 3 * 65536);
      if ((memcmp(back + 1000, "ab", 2) == 0 && memcmp(back + 900, "cd", 2) == 0) || sd_tick_ms() - t0 > 10000) break;
      Sleep(20);
    }
    SD_CHECK(sd_tick_ms() - t0 >= 300);     /* held back to coalesce, not sent at once */
  }
  SD_CHECK_MEM(back + 1000, "ab", 2);
  SD_CHECK_MEM(back + 900, "cd", 2);
  vclose(h);
  SD_CHECK_EQ_INT(f.ev.write_failed, 0);
  fx_done(&f);
  sd_free(data);
  sd_free(back);
}

SD_TEST(vfs_write_behind_window_backpressure)
{
  fixture f;
  sd_vfs_options o;
  sd_vfs_handle *h = NULL;
  uint8_t *data = pattern(1u << 20, 9), *back = (uint8_t *)sd_alloc(4u << 20);
  UINT32 done = 0;
  int i;
  SD_REQUIRE(data && back);
  wb_opts(&o);
  o.wb_window = 1u << 20;                   /* small window: the writer must wait for acks */
  SD_REQUIRE(fx_start(&f, NULL, &o));
  SD_REQUIRE(vopen(&f, L"\\bp.bin", GENERIC_WRITE, SD_VFS_FILE_CREATE, 0, &h) == SD_VFS_OK);
  for (i = 0; i < 4; i++)
    SD_CHECK_EQ_INT(sd_vfs_write(h, (UINT64)i << 20, data, 1u << 20, &done, FALSE), SD_VFS_OK);
  vclose(h);                                /* cleanup drains synchronously */
  SD_CHECK_EQ_INT(fake_get(f.s, "/home/user/bp.bin", back, 4u << 20), 4u << 20);
  for (i = 0; i < 4; i++)
    SD_CHECK_MEM(back + ((size_t)i << 20), data, 1u << 20);
  fx_done(&f);
  sd_free(data);
  sd_free(back);
}

SD_TEST(vfs_write_behind_sticky_error)
{
  fixture f;
  sd_vfs_options o;
  sd_vfs_handle *h = NULL;
  UINT32 done = 0;
  wb_opts(&o);
  SD_REQUIRE(fx_start(&f, NULL, &o));
  SD_REQUIRE(vopen(&f, L"\\s.bin", GENERIC_WRITE, SD_VFS_FILE_CREATE, 0, &h) == SD_VFS_OK);
  fake_fail_next(f.s, FOP_WRITE, SD_E_NO_SPACE);
  SD_CHECK_EQ_INT(sd_vfs_write(h, 0, "first", 5, &done, FALSE), SD_VFS_OK);   /* accepted */
  SD_CHECK_EQ_INT(sd_vfs_flush(h), SD_VFS_E_NO_SPACE);                         /* the ack failed */
  SD_CHECK_EQ_INT(sd_vfs_write(h, 5, "second", 6, &done, FALSE), SD_VFS_E_NO_SPACE);   /* sticky */
  SD_CHECK_EQ_INT(sd_vfs_flush(h), SD_VFS_E_NO_SPACE);
  SD_CHECK_EQ_INT(f.ev.write_failed, 0);
  vclose(h);                                /* Cleanup cannot fail: write_failed instead */
  SD_CHECK_EQ_INT(f.ev.write_failed, 1);
  SD_CHECK_EQ_INT(f.ev.wf_status, SD_VFS_E_NO_SPACE);
  SD_CHECK_EQ_U64(f.ev.wf_bytes, 5);
  /* The error lasts until the last handle closes; a new open writes again. */
  SD_REQUIRE(vopen(&f, L"\\s.bin", GENERIC_WRITE, SD_VFS_FILE_OPEN, 0, &h) == SD_VFS_OK);
  SD_CHECK_EQ_INT(sd_vfs_write(h, 0, "again", 5, &done, FALSE), SD_VFS_OK);
  SD_CHECK_EQ_INT(sd_vfs_flush(h), SD_VFS_OK);
  vclose(h);
  SD_CHECK_EQ_INT(f.ev.write_failed, 1);
  {
    char b[8];
    SD_CHECK_EQ_INT(fake_get(f.s, "/home/user/s.bin", b, sizeof(b)), 5);
    SD_CHECK_MEM(b, "again", 5);
  }
  fx_done(&f);
}

SD_TEST(vfs_write_behind_grace_retransmit)
{
  fixture f;
  sd_vfs_options o;
  sd_vfs_handle *h = NULL;
  uint8_t *data = pattern(128 * 1024, 21), *back = (uint8_t *)sd_alloc(128 * 1024);
  UINT32 done = 0;
  uint32_t writes;
  SD_REQUIRE(data && back);
  wb_opts(&o);
  SD_REQUIRE(fx_start(&f, NULL, &o));
  SD_REQUIRE(vopen(&f, L"\\g.bin", GENERIC_WRITE, SD_VFS_FILE_CREATE, 0, &h) == SD_VFS_OK);
  fake_hold_writes(f.s, 1);
  SD_CHECK_EQ_INT(sd_vfs_write(h, 0, data, 128 * 1024, &done, FALSE), SD_VFS_OK);
  {
    uint64_t end = sd_tick_ms() + 5000;
    while (fake_held_writes(f.s) == 0 && sd_tick_ms() < end) Sleep(5);
  }
  SD_CHECK(fake_held_writes(f.s) > 0);      /* sent, not acknowledged */
  fake_disconnect(f.s);                     /* in flight -> DISCONNECTED, maybe_executed */
  fake_hold_writes(f.s, 0);
  /* New writes during the outage fail fast; the accepted data waits for the link. */
  SD_CHECK_EQ_INT(sd_vfs_write(h, 128 * 1024, "x", 1, &done, FALSE), SD_VFS_E_DISCONNECTED);
  Sleep(300);
  writes = fake_count(f.s, FOP_WRITE);
  fake_reconnect(f.s);
  SD_CHECK_EQ_INT(sd_vfs_flush(h), SD_VFS_OK);   /* re-open, identity check, retransmit */
  SD_CHECK(fake_count(f.s, FOP_WRITE) > writes);
  SD_CHECK(fake_count(f.s, FOP_REOPEN) >= 1);
  SD_CHECK_EQ_INT(fake_get(f.s, "/home/user/g.bin", back, 128 * 1024), 128 * 1024);
  SD_CHECK_MEM(back, data, 128 * 1024);
  vclose(h);
  SD_CHECK_EQ_INT(f.ev.write_failed, 0);
  fx_done(&f);
  sd_free(data);
  sd_free(back);
}

SD_TEST(vfs_write_behind_grace_expiry)
{
  fixture f;
  sd_vfs_options o;
  sd_vfs_handle *h = NULL;
  UINT32 done = 0;
  wb_opts(&o);
  o.reconnect_grace_ms = 300;
  SD_REQUIRE(fx_start(&f, NULL, &o));
  SD_REQUIRE(vopen(&f, L"\\e.bin", GENERIC_WRITE, SD_VFS_FILE_CREATE, 0, &h) == SD_VFS_OK);
  fake_hold_writes(f.s, 1);
  SD_CHECK_EQ_INT(sd_vfs_write(h, 0, "lost data", 9, &done, FALSE), SD_VFS_OK);
  {
    uint64_t end = sd_tick_ms() + 5000;
    while (fake_held_writes(f.s) == 0 && sd_tick_ms() < end) Sleep(5);
  }
  fake_disconnect(f.s);
  fake_hold_writes(f.s, 0);
  {
    uint64_t end = sd_tick_ms() + 5000;     /* the background timer expires the grace */
    while (f.ev.write_failed == 0 && sd_tick_ms() < end) Sleep(20);
  }
  SD_CHECK_EQ_INT(f.ev.write_failed, 1);
  SD_CHECK_EQ_INT(f.ev.wf_status, SD_VFS_E_DISCONNECTED);
  SD_CHECK_EQ_U64(f.ev.wf_bytes, 9);
  fake_reconnect(f.s);
  SD_CHECK_EQ_INT(sd_vfs_flush(h), SD_VFS_E_DISCONNECTED);   /* sticky */
  vclose(h);
  SD_CHECK_EQ_INT(f.ev.write_failed, 1);    /* raised once */
  SD_CHECK_EQ_INT(fake_get(f.s, "/home/user/e.bin", NULL, 0), 0);
  fx_done(&f);
}

SD_TEST(vfs_write_behind_conflict_after_reconnect)
{
  fixture f;
  sd_vfs_options o;
  sd_vfs_handle *h = NULL;
  UINT32 done = 0, got = 0;
  char b[16];
  wb_opts(&o);
  SD_REQUIRE(fx_start(&f, NULL, &o));
  fake_put(f.s, "/home/user/c.txt", "AAAA", 4, 0644);
  fake_set_mtime(f.s, "/home/user/c.txt", OLD_MTIME);
  SD_REQUIRE(vopen(&f, L"\\c.txt", GENERIC_READ | GENERIC_WRITE, SD_VFS_FILE_OPEN, 0, &h) == SD_VFS_OK);
  fake_hold_writes(f.s, 1);
  SD_CHECK_EQ_INT(sd_vfs_write(h, 0, "BB", 2, &done, FALSE), SD_VFS_OK);
  {
    uint64_t end = sd_tick_ms() + 5000;
    while (fake_held_writes(f.s) == 0 && sd_tick_ms() < end) Sleep(5);
  }
  fake_disconnect(f.s);
  fake_hold_writes(f.s, 0);
  fake_overwrite(f.s, "/home/user/c.txt", "someone else", 12, OLD_MTIME + 100);   /* changed meanwhile */
  fake_reconnect(f.s);
  SD_CHECK_EQ_INT(sd_vfs_flush(h), SD_VFS_E_STALE);     /* conflicted: writes discarded */
  SD_CHECK_EQ_INT(f.ev.write_failed, 1);
  SD_CHECK_EQ_INT(f.ev.wf_status, SD_VFS_E_STALE);
  SD_CHECK_EQ_INT(sd_vfs_read(h, 0, b, sizeof(b), &got), SD_VFS_E_STALE);
  SD_CHECK_EQ_INT(sd_vfs_write(h, 0, "C", 1, &done, FALSE), SD_VFS_E_STALE);
  vclose(h);
  SD_CHECK_EQ_INT(fake_get(f.s, "/home/user/c.txt", b, sizeof(b)), 12);
  SD_CHECK_MEM(b, "someone else", 12);
  /* A new handle sees the server's content. */
  SD_CHECK_EQ_INT(read_at(&f, L"\\c.txt", 0, b, sizeof(b), &got), SD_VFS_OK);
  SD_CHECK(got == 12 && memcmp(b, "someone else", 12) == 0);
  fx_done(&f);
}

/* ---- reconnect (02 §5) ---- */

SD_TEST(vfs_reconnect_serves_cache_and_reopens)
{
  fixture f;
  sd_vfs_handle *h = NULL, *w = NULL;
  uint8_t *data = pattern(4u << 20, 13), *back = (uint8_t *)sd_alloc(65536);
  UINT32 got = 0, done = 0;
  uint64_t t0;
  sd_vfs_status st;
  SD_REQUIRE(data && back);
  SD_REQUIRE(fx_start(&f, NULL, NULL));
  fake_put(f.s, "/home/user/r.bin", data, 4u << 20, 0644);
  fake_set_mtime(f.s, "/home/user/r.bin", OLD_MTIME);
  SD_REQUIRE(vopen(&f, L"\\r.bin", GENERIC_READ, SD_VFS_FILE_OPEN, SD_VFS_FILE_RANDOM_ACCESS, &h) == SD_VFS_OK);
  SD_REQUIRE(vopen(&f, L"\\r.bin", GENERIC_WRITE, SD_VFS_FILE_OPEN, 0, &w) == SD_VFS_OK);
  SD_CHECK_EQ_INT(sd_vfs_read(h, 0, back, 65536, &got), SD_VFS_OK);
  fake_disconnect(f.s);
  /* Cached block: served while disconnected. */
  memset(back, 0, 65536);
  SD_CHECK_EQ_INT(sd_vfs_read(h, 4096, back, 65536, &got), SD_VFS_OK);
  SD_CHECK_EQ_INT(got, 65536);
  SD_CHECK_MEM(back, data + 4096, 65536);
  /* Not cached: waits offline_wait (200 ms), then DISCONNECTED. */
  t0 = sd_tick_ms();
  st = sd_vfs_read(h, 3u << 20, back, 4096, &got);
  SD_CHECK_EQ_INT(st, SD_VFS_E_DISCONNECTED);
  SD_CHECK(sd_tick_ms() - t0 >= 150);
  /* Writes fail fast; so do opens with write access. */
  t0 = sd_tick_ms();
  SD_CHECK_EQ_INT(sd_vfs_write(w, 0, "x", 1, &done, FALSE), SD_VFS_E_DISCONNECTED);
  SD_CHECK(sd_tick_ms() - t0 < 100);
  {
    sd_vfs_handle *x = NULL;
    SD_CHECK_EQ_INT(vopen(&f, L"\\r.bin", GENERIC_WRITE, SD_VFS_FILE_OPEN, 0, &x), SD_VFS_E_DISCONNECTED);
  }
  fake_reconnect(f.s);
  fake_reset_counts(f.s);
  SD_CHECK_EQ_INT(sd_vfs_read(h, 3u << 20, back, 4096, &got), SD_VFS_OK);
  SD_CHECK_MEM(back, data + (3u << 20), 4096);
  SD_CHECK_EQ_INT(fake_count(f.s, FOP_REOPEN), 1);      /* the stale handle reopened lazily */
  SD_CHECK_EQ_INT(sd_vfs_write(w, 0, "Q", 1, &done, FALSE), SD_VFS_OK);
  SD_CHECK(f.ev.state >= 1);
  vclose(h);
  vclose(w);
  fx_done(&f);
  sd_free(data);
  sd_free(back);
}

SD_TEST(vfs_reconnect_detects_remote_change)
{
  fixture f;
  sd_vfs_handle *h = NULL;
  char b[16];
  UINT32 got = 0;
  SD_REQUIRE(fx_start(&f, NULL, NULL));
  fake_put(f.s, "/home/user/m.txt", "before", 6, 0644);
  fake_set_mtime(f.s, "/home/user/m.txt", OLD_MTIME);
  SD_REQUIRE(vopen(&f, L"\\m.txt", GENERIC_READ, SD_VFS_FILE_OPEN, SD_VFS_FILE_RANDOM_ACCESS, &h) == SD_VFS_OK);
  SD_CHECK_EQ_INT(sd_vfs_read(h, 0, b, sizeof(b), &got), SD_VFS_OK);
  SD_CHECK(got == 6 && memcmp(b, "before", 6) == 0);
  fake_disconnect(f.s);
  fake_overwrite(f.s, "/home/user/m.txt", "after!", 6, OLD_MTIME + 5);
  /* Disconnected: the cached content is served as it was. */
  SD_CHECK_EQ_INT(sd_vfs_read(h, 0, b, sizeof(b), &got), SD_VFS_OK);
  SD_CHECK(got == 6 && memcmp(b, "before", 6) == 0);
  fake_reconnect(f.s);
  /* The first use after the reconnect reopens the handle; the identity check sees the change,
     drops the cached blocks and the read handle sees the new content. */
  SD_CHECK_EQ_INT(sd_vfs_read(h, 0, b, sizeof(b), &got), SD_VFS_OK);
  SD_CHECK(got == 6 && memcmp(b, "after!", 6) == 0);
  SD_CHECK_EQ_INT(fake_count(f.s, FOP_REOPEN), 1);
  vclose(h);
  fx_done(&f);
}

typedef struct wt_arg { sd_vfs_handle *h; sd_vfs_status st; UINT32 done; } wt_arg;

static unsigned __stdcall wt_writer(void *p)
{
  wt_arg *a = (wt_arg *)p;
  a->st = sd_vfs_write(a->h, 0, "through", 7, &a->done, FALSE);
  return 0;
}

SD_TEST(vfs_write_through_disconnect_fails_the_call)
{
  fixture f;
  sd_vfs_handle *h = NULL;
  wt_arg a;
  HANDLE th;
  UINT32 done = 0;
  SD_REQUIRE(fx_start(&f, NULL, NULL));
  SD_REQUIRE(vopen(&f, L"\\t.txt", GENERIC_WRITE, SD_VFS_FILE_CREATE, 0, &h) == SD_VFS_OK);
  fake_hold_writes(f.s, 1);
  a.h = h;
  a.st = SD_VFS_OK;
  a.done = 0;
  th = (HANDLE)_beginthreadex(NULL, 0, wt_writer, &a, 0, NULL);
  SD_REQUIRE(th != NULL);
  {
    uint64_t end = sd_tick_ms() + 5000;
    while (fake_held_writes(f.s) == 0 && sd_tick_ms() < end) Sleep(5);
  }
  SD_CHECK(WaitForSingleObject(th, 100) == WAIT_TIMEOUT);   /* write-through: waits for the ack */
  fake_disconnect(f.s);
  fake_hold_writes(f.s, 0);
  WaitForSingleObject(th, INFINITE);
  CloseHandle(th);
  SD_CHECK_EQ_INT(a.st, SD_VFS_E_DISCONNECTED);         /* that WriteFile fails; nothing is sticky */
  SD_CHECK_EQ_INT(a.done, 0);
  fake_reconnect(f.s);
  SD_CHECK_EQ_INT(sd_vfs_write(h, 0, "again", 5, &done, FALSE), SD_VFS_OK);
  vclose(h);
  SD_CHECK_EQ_INT(f.ev.write_failed, 0);    /* never raised in write-through mode */
  {
    char b[8];
    SD_CHECK_EQ_INT(fake_get(f.s, "/home/user/t.txt", b, sizeof(b)), 5);
    SD_CHECK_MEM(b, "again", 5);
  }
  fx_done(&f);
}

/* ---- offline waits (02 §5.2) and negative entries while offline (02 §7.6) ---- */

typedef struct ow_arg {
  sd_vfs_handle *h;
  sd_vfs_status st;
  UINT32 got;
  uint8_t buf[4096];
  uint64_t t_end;
} ow_arg;

static unsigned __stdcall ow_reader(void *p)
{
  ow_arg *a = (ow_arg *)p;
  a->st = sd_vfs_read(a->h, 3u << 20, a->buf, sizeof(a->buf), &a->got);
  a->t_end = sd_tick_ms();
  return 0;
}

/* A 4 MiB file with one handle open and nothing cached past the first block, then the link goes down
   and a reader starts on an uncached block. */
/* Returns FALSE (and no thread) if the mount or the open failed; the caller checks it with SD_REQUIRE. */
static BOOL ow_setup_reader(fixture *f, const sd_vfs_options *o, sd_vfs_handle **h, ow_arg *a,
                            const uint8_t *data, HANDLE *th_out)
{
  *th_out = NULL;
  if (!fx_start(f, NULL, o))
    return FALSE;
  fake_put(f->s, "/home/user/w.bin", data, 4u << 20, 0644);
  fake_set_mtime(f->s, "/home/user/w.bin", OLD_MTIME);
  if (vopen(f, L"\\w.bin", GENERIC_READ, SD_VFS_FILE_OPEN, SD_VFS_FILE_RANDOM_ACCESS, h) != SD_VFS_OK)
    return FALSE;
  fake_disconnect(f->s);
  memset(a, 0, sizeof(*a));
  a->h = *h;
  a->st = SD_VFS_OK;
  *th_out = (HANDLE)_beginthreadex(NULL, 0, ow_reader, a, 0, NULL);
  return *th_out != NULL;
}

SD_TEST(vfs_offline_wait_completes_on_reconnect)
{
  fixture f;
  sd_vfs_options o;
  sd_vfs_handle *h = NULL;
  uint8_t *data = pattern(4u << 20, 31);
  ow_arg a;
  HANDLE th;
  uint64_t t_reconnect;
  SD_REQUIRE(data);
  opts(&o);
  o.offline_wait_ms = 5000;             /* the wait must end at the reconnect, not at this deadline */
  SD_REQUIRE(ow_setup_reader(&f, &o, &h, &a, data, &th));
  SD_REQUIRE(th != NULL);
  Sleep(300);
  SD_CHECK(WaitForSingleObject(th, 0) == WAIT_TIMEOUT);   /* still waiting for the link */
  t_reconnect = sd_tick_ms();
  fake_reconnect(f.s);
  SD_REQUIRE(WaitForSingleObject(th, 3000) == WAIT_OBJECT_0);
  CloseHandle(th);
  SD_CHECK_EQ_INT(a.st, SD_VFS_OK);
  SD_CHECK_EQ_INT(a.got, 4096);
  SD_CHECK_MEM(a.buf, data + (3u << 20), 4096);
  SD_CHECK(a.t_end - t_reconnect < 2000);  /* served right after the READY, well before offline_wait */
  vclose(h);
  fx_done(&f);
  sd_free(data);
}

SD_TEST(vfs_offline_wait_cancel_returns_promptly)
{
  fixture f;
  sd_vfs_options o;
  sd_vfs_handle *h = NULL;
  uint8_t *data = pattern(4u << 20, 32);
  ow_arg a;
  HANDLE th;
  uint64_t t0;
  SD_REQUIRE(data);
  opts(&o);
  o.offline_wait_ms = 10000;            /* only the cancel can end the wait within the test bound */
  SD_REQUIRE(ow_setup_reader(&f, &o, &h, &a, data, &th));
  SD_REQUIRE(th != NULL);
  Sleep(300);
  SD_CHECK(WaitForSingleObject(th, 0) == WAIT_TIMEOUT);
  t0 = sd_tick_ms();
  sd_vfs_quiesce(f.v, 2000);            /* quiesce and unmount cancel the offline waiters */
  SD_REQUIRE(WaitForSingleObject(th, 2000) == WAIT_OBJECT_0);
  CloseHandle(th);
  SD_CHECK(a.t_end - t0 < 2000);
  SD_CHECK_EQ_INT(a.st, SD_VFS_E_DISCONNECTED);
  vclose(h);
  fx_done(&f);
  sd_free(data);
}

SD_TEST(vfs_offline_negative_lookup_is_disconnected)
{
  fixture f;
  sd_vfs_info info;
  SD_REQUIRE(fx_start(&f, NULL, NULL));
  fake_put(f.s, "/home/user/present.txt", "x", 1, 0644);
  SD_CHECK_EQ_INT(sd_vfs_stat_path(f.v, NULL, L"\\present.txt", &info), SD_VFS_OK);
  SD_CHECK_EQ_INT(sd_vfs_stat_path(f.v, NULL, L"\\gone.txt", &info), SD_VFS_E_NOT_FOUND);   /* verified miss */
  fake_disconnect(f.s);
  /* A cached miss while the link is down is DISCONNECTED (WebDAV 503), never NOT_FOUND (02 §7.6). */
  SD_CHECK_EQ_INT(sd_vfs_stat_path(f.v, NULL, L"\\gone.txt", &info), SD_VFS_E_DISCONNECTED);
  SD_CHECK_EQ_INT(sd_vfs_stat_path(f.v, NULL, L"\\present.txt", &info), SD_VFS_OK);
  fake_reconnect(f.s);
  SD_CHECK_EQ_INT(sd_vfs_stat_path(f.v, NULL, L"\\gone.txt", &info), SD_VFS_E_NOT_FOUND);   /* online again */
  fx_done(&f);
}

/* 02 §5.2: a name the vfs has no entry for fails at once while offline (no offline_wait, so Explorer probes do not
   stall); entries already known keep being served. */
SD_TEST(vfs_offline_unknown_lookup_fails_at_once)
{
  fixture f;
  sd_vfs_options o;
  sd_vfs_info info;
  uint64_t t0;
  opts(&o);
  o.offline_wait_ms = 5000;             /* a lookup that waited would take this long; the bound below is far under it */
  SD_REQUIRE(fx_start(&f, NULL, &o));
  fake_put(f.s, "/home/user/known.txt", "x", 1, 0644);
  SD_CHECK_EQ_INT(sd_vfs_stat_path(f.v, NULL, L"\\known.txt", &info), SD_VFS_OK);
  fake_disconnect(f.s);
  t0 = sd_tick_ms();
  SD_CHECK_EQ_INT(sd_vfs_stat_path(f.v, NULL, L"\\never-cached.txt", &info), SD_VFS_E_DISCONNECTED);
  SD_CHECK(sd_tick_ms() - t0 < 1000);
  SD_CHECK_EQ_INT(sd_vfs_stat_path(f.v, NULL, L"\\known.txt", &info), SD_VFS_OK);      /* known entry: served */
  fake_reconnect(f.s);
  SD_CHECK_EQ_INT(sd_vfs_stat_path(f.v, NULL, L"\\never-cached.txt", &info), SD_VFS_E_NOT_FOUND);
  fx_done(&f);
}

/* ---- identity without exec (D10, 02 §3.4) ---- */

SD_TEST(vfs_identity_home_owner_then_first_create)
{
  fixture f;
  fake_config cfg;
  sd_vfs_identity id;
  sd_vfs_handle *h = NULL;
  memset(&cfg, 0, sizeof(cfg));
  cfg.uid = 1234;
  cfg.home_uid_set = 1;
  cfg.home_uid = 2000;                      /* shared home owned by another account */
  SD_REQUIRE(fx_start(&f, &cfg, NULL));
  sd_vfs_get_identity(f.v, &id);
  SD_CHECK(id.uid_known && !id.definitive && id.uid == 2000);   /* provisional */
  SD_REQUIRE(vopen(&f, L"\\mine.txt", GENERIC_WRITE, SD_VFS_FILE_CREATE, 0, &h) == SD_VFS_OK);
  vclose(h);
  sd_vfs_get_identity(f.v, &id);
  SD_CHECK(id.uid_known && id.definitive && id.uid == 1234);    /* confirmed by the created file */
  SD_CHECK_EQ_INT(f.ev.identity, 1);
  fx_done(&f);

  /* Root-owned home with a non-root account: unknown until the first create. */
  cfg.home_uid = 0;
  SD_REQUIRE(fx_start(&f, &cfg, NULL));
  sd_vfs_get_identity(f.v, &id);
  SD_CHECK(!id.uid_known);
  SD_REQUIRE(vopen(&f, L"\\d", FILE_LIST_DIRECTORY, SD_VFS_FILE_CREATE, SD_VFS_FILE_DIRECTORY_FILE, &h) == SD_VFS_OK);
  vclose(h);
  sd_vfs_get_identity(f.v, &id);
  SD_CHECK(id.uid_known && id.definitive && id.uid == 1234);
  fx_done(&f);

  /* M1 integration regression: a home owned by the account itself gives the right provisional uid;
     the first create only confirms it, and IDENTITY must still be raised (the host stores the
     identity when it becomes definitive; no event meant it was never cached). */
  cfg.home_uid = 1234;
  SD_REQUIRE(fx_start(&f, &cfg, NULL));
  sd_vfs_get_identity(f.v, &id);
  SD_CHECK(id.uid_known && !id.definitive && id.uid == 1234);
  SD_REQUIRE(vopen(&f, L"\\same.txt", GENERIC_WRITE, SD_VFS_FILE_CREATE, 0, &h) == SD_VFS_OK);
  vclose(h);
  sd_vfs_get_identity(f.v, &id);
  SD_CHECK(id.uid_known && id.definitive && id.uid == 1234);
  SD_CHECK_EQ_INT(f.ev.identity, 1);
  fx_done(&f);
  cfg.home_uid = 0;

  /* The host's cached identity starts the mount definitive. */
  {
    sd_vfs_options o;
    sd_vfs_identity known;
    memset(&known, 0, sizeof(known));
    known.uid_known = known.definitive = TRUE;
    known.uid = 1234;
    known.gid = 1000;
    opts(&o);
    o.known_identity = &known;
    SD_REQUIRE(fx_start(&f, &cfg, &o));
    sd_vfs_get_identity(f.v, &id);
    SD_CHECK(id.uid_known && id.definitive && id.uid == 1234);
    fx_done(&f);
  }
}

/* ---- disk tier (02 §4.2, TM-R29) ---- */

static BOOL user_sid_str(WCHAR *out, size_t cap)
{
  HANDLE tok;
  BYTE buf[256];
  DWORD n = 0;
  LPWSTR s = NULL;
  BOOL ok = FALSE;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok))
    return FALSE;
  if (GetTokenInformation(tok, TokenUser, buf, sizeof(buf), &n) && ConvertSidToStringSidW(((TOKEN_USER *)buf)->User.Sid, &s)) {
    wcsncpy_s(out, cap, s, _TRUNCATE);
    LocalFree(s);
    ok = TRUE;
  }
  CloseHandle(tok);
  return ok;
}

/* Creates <temp>\sd-vfs-m1-<pid>-<tag> with the given DACL SDDL (%s = the user's SID). */
static BOOL make_dir(WCHAR *out, size_t cap, const WCHAR *tag, const WCHAR *sddl_fmt)
{
  WCHAR tmp[MAX_PATH], sid[200], sddl[600];
  SECURITY_ATTRIBUTES sa;
  PSECURITY_DESCRIPTOR sd = NULL;
  BOOL ok;
  if (!GetTempPathW(MAX_PATH, tmp) || !user_sid_str(sid, SD_COUNTOF(sid)))
    return FALSE;
  _snwprintf_s(out, cap, _TRUNCATE, L"%ssd-vfs-m1-%lu-%s", tmp, (unsigned long)GetCurrentProcessId(), tag);
  if (!sddl_fmt)
    return CreateDirectoryW(out, NULL) || GetLastError() == ERROR_ALREADY_EXISTS;
  _snwprintf_s(sddl, SD_COUNTOF(sddl), _TRUNCATE, sddl_fmt, sid, sid);
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sd, NULL))
    return FALSE;
  sa.nLength = sizeof(sa);
  sa.lpSecurityDescriptor = sd;
  sa.bInheritHandle = FALSE;
  ok = CreateDirectoryW(out, &sa);
  LocalFree(sd);
  return ok;
}

static void remove_dir(const WCHAR *dir)
{
  WCHAR pat[MAX_PATH + 8], p[MAX_PATH + 80];
  WIN32_FIND_DATAW fd;
  HANDLE h;
  _snwprintf_s(pat, SD_COUNTOF(pat), _TRUNCATE, L"%s\\*", dir);
  h = FindFirstFileW(pat, &fd);
  if (h != INVALID_HANDLE_VALUE) {
    do {
      if (fd.cFileName[0] == L'.') continue;
      _snwprintf_s(p, SD_COUNTOF(p), _TRUNCATE, L"%s\\%s", dir, fd.cFileName);
      DeleteFileW(p);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
  }
  RemoveDirectoryW(dir);
}

static uint64_t dir_bytes(const WCHAR *dir, uint32_t *files)
{
  WCHAR pat[MAX_PATH + 8];
  WIN32_FIND_DATAW fd;
  HANDLE h;
  uint64_t total = 0;
  *files = 0;
  _snwprintf_s(pat, SD_COUNTOF(pat), _TRUNCATE, L"%s\\*", dir);
  h = FindFirstFileW(pat, &fd);
  if (h == INVALID_HANDLE_VALUE)
    return 0;
  do {
    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
    total += ((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
    (*files)++;
  } while (FindNextFileW(h, &fd));
  FindClose(h);
  return total;
}

#define PROTECTED_DACL L"O:%sD:P(A;OICI;FA;;;%s)(A;OICI;FA;;;SY)"

SD_TEST(vfs_disk_cache_persists_across_mounts)
{
  fixture f;
  sd_vfs_options o;
  WCHAR dir[MAX_PATH];
  uint8_t *data = pattern(1u << 20, 17), *back = (uint8_t *)sd_alloc(1u << 20);
  UINT32 got = 0;
  uint32_t reads, files = 0;
  SD_REQUIRE(data && back);
  SD_REQUIRE(make_dir(dir, SD_COUNTOF(dir), L"cache", PROTECTED_DACL));
  opts(&o);
  o.disk_cache_mb = 64;
  o.disk_cache_dir = dir;
  SD_REQUIRE(fx_start(&f, NULL, &o));
  SD_CHECK_EQ_INT(f.ev.notices, 0);         /* accepted: protected DACL, NTFS */
  fake_put(f.s, "/home/user/d.bin", data, 1u << 20, 0644);
  fake_set_mtime(f.s, "/home/user/d.bin", OLD_MTIME);
  SD_CHECK_EQ_INT(read_at(&f, L"\\d.bin", 0, back, 1u << 20, &got), SD_VFS_OK);
  SD_CHECK_MEM(back, data, 1u << 20);
  fx_unmount(&f);
  dir_bytes(dir, &files);
  SD_CHECK_EQ_INT(files, 2);                /* one data file and one header */

  /* A new mount (cold memory tier) reads the blocks from disk. */
  SD_REQUIRE(sd_vfs_mount(f.s, &f.o, on_event, &f.ev, &f.v) == SD_VFS_OK);
  reads = fake_count(f.s, FOP_READ);
  memset(back, 0, 1u << 20);
  SD_CHECK_EQ_INT(read_at(&f, L"\\d.bin", 0, back, 1u << 20, &got), SD_VFS_OK);
  SD_CHECK_MEM(back, data, 1u << 20);
  SD_CHECK_EQ_INT(fake_count(f.s, FOP_READ), reads);
  fx_unmount(&f);

  /* Changed on the server: the validator in the header no longer matches. */
  data[0] ^= 0xFF;
  fake_overwrite(f.s, "/home/user/d.bin", data, 1u << 20, OLD_MTIME + 1);
  SD_REQUIRE(sd_vfs_mount(f.s, &f.o, on_event, &f.ev, &f.v) == SD_VFS_OK);
  SD_CHECK_EQ_INT(read_at(&f, L"\\d.bin", 0, back, 1u << 20, &got), SD_VFS_OK);
  SD_CHECK_MEM(back, data, 1u << 20);
  SD_CHECK(fake_count(f.s, FOP_READ) > reads);
  fx_done(&f);
  remove_dir(dir);
  sd_free(data);
  sd_free(back);
}

SD_TEST(vfs_disk_cache_refused_unsafe_directories)
{
  fixture f;
  sd_vfs_options o;
  WCHAR dir[MAX_PATH], target[MAX_PATH], cmd[3 * MAX_PATH];
  /* Another account (Everyone) may read: refused. */
  SD_REQUIRE(make_dir(dir, SD_COUNTOF(dir), L"open", L"O:%sD:P(A;OICI;FA;;;%s)(A;OICI;FR;;;WD)"));
  opts(&o);
  o.disk_cache_mb = 64;
  o.disk_cache_dir = dir;
  SD_REQUIRE(fx_start(&f, NULL, &o));
  SD_CHECK(strcmp(f.ev.last_code, "disk_cache_refused") == 0);
  SD_CHECK(strstr(f.ev.last_detail, "another account") != NULL);
  fx_done(&f);
  remove_dir(dir);

  /* Missing directory: refused (sd_vfs creates nothing outside what it is given). */
  SD_REQUIRE(fx_start(&f, NULL, &o));
  SD_CHECK(strcmp(f.ev.last_code, "disk_cache_refused") == 0);
  fx_done(&f);
  SD_CHECK(GetFileAttributesW(dir) == INVALID_FILE_ATTRIBUTES);

  /* A junction is refused even when its target is safe. */
  SD_REQUIRE(make_dir(target, SD_COUNTOF(target), L"jtarget", PROTECTED_DACL));
  _snwprintf_s(dir, SD_COUNTOF(dir), _TRUNCATE, L"%s-link", target);
  _snwprintf_s(cmd, SD_COUNTOF(cmd), _TRUNCATE, L"cmd /c mklink /J \"%s\" \"%s\" >nul 2>nul", dir, target);
  if (_wsystem(cmd) == 0 && GetFileAttributesW(dir) != INVALID_FILE_ATTRIBUTES) {
    o.disk_cache_dir = dir;
    SD_REQUIRE(fx_start(&f, NULL, &o));
    SD_CHECK(strcmp(f.ev.last_code, "disk_cache_refused") == 0);
    SD_CHECK(strstr(f.ev.last_detail, "reparse") != NULL);
    fx_done(&f);
    RemoveDirectoryW(dir);
  }
  remove_dir(target);
}

SD_TEST(vfs_disk_cache_trim_to_limit)
{
  fixture f;
  sd_vfs_options o;
  WCHAR dir[MAX_PATH];
  uint8_t *data = pattern(1u << 20, 19), *back = (uint8_t *)sd_alloc(1u << 20);
  UINT32 got = 0;
  uint32_t files = 0;
  int i;
  SD_REQUIRE(data && back);
  SD_REQUIRE(make_dir(dir, SD_COUNTOF(dir), L"trim", PROTECTED_DACL));
  opts(&o);
  o.disk_cache_mb = 2;
  o.disk_cache_dir = dir;
  SD_REQUIRE(fx_start(&f, NULL, &o));
  for (i = 0; i < 4; i++) {
    char p[64];
    WCHAR w[32];
    sprintf_s(p, sizeof(p), "/home/user/t%d.bin", i);
    fake_put(f.s, p, data, 1u << 20, 0644);
    fake_set_mtime(f.s, p, OLD_MTIME);
    _snwprintf_s(w, SD_COUNTOF(w), _TRUNCATE, L"\\t%d.bin", i);
    SD_CHECK_EQ_INT(read_at(&f, w, 0, back, 1u << 20, &got), SD_VFS_OK);
  }
  fx_unmount(&f);
  SD_CHECK(dir_bytes(dir, &files) > (2u << 20));      /* over the limit until the next trim */
  SD_REQUIRE(sd_vfs_mount(f.s, &f.o, on_event, &f.ev, &f.v) == SD_VFS_OK);   /* trims at startup */
  SD_CHECK(dir_bytes(dir, &files) <= (2u << 20));
  SD_CHECK(files >= 2);
  fx_done(&f);
  remove_dir(dir);
  sd_free(data);
  sd_free(back);
}
