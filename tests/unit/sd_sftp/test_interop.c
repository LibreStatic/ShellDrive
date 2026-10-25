/* Interop tests against OpenSSH sftp-server (see main_interop.c). */
#include <stdio.h>
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_platform/sd_time.h"
#include "sd_test.h"
#include "interop.h"

#define TMO 30000u

static const char *P(const char *rel)
{
  static char bufs[8][512];
  static int k;
  char *b = bufs[k++ & 7];
  sprintf_s(b, 512, "%s/%s", g_dir, rel);
  return b;
}

static sd_sftp_reqopt opt_t(uint32_t ms) { sd_sftp_reqopt o; o.flags = 0; o.timeout_ms = ms; o.token_out = NULL; return o; }

static sd_err write_file(const char *path, const void *data, uint32_t len)
{
  sd_sftp_file *f;
  sd_err e = sd_sftp_open_sync(g_s, path, SD_SFTP_O_WRITE | SD_SFTP_O_CREAT | SD_SFTP_O_TRUNC, NULL, &f, NULL, TMO);
  if (e != SD_OK) return e;
  if (len) e = sd_sftp_write_sync(f, 0, data, len, TMO);
  if (e != SD_OK) { (void)sd_sftp_close_sync(f, TMO); return e; }
  return sd_sftp_close_sync(f, TMO);
}

static sd_err read_file(const char *path, char *out, uint32_t cap, uint32_t *got)
{
  sd_sftp_file *f;
  sd_err e = sd_sftp_open_sync(g_s, path, SD_SFTP_O_READ, NULL, &f, NULL, TMO);
  *got = 0;
  if (e != SD_OK) return e;
  e = sd_sftp_read_sync(f, 0, out, cap, got, TMO);
  (void)sd_sftp_close_sync(f, TMO);
  return e == SD_E_EOF ? SD_OK : e;
}

/* async helper: run one request and wait */
#define RUN(w, kind, call) (waiter_reset((w), (kind)), (call) == SD_OK && waiter_wait((w), TMO) ? (w)->err : SD_E_INTERNAL)

SD_TEST(interop_crud)
{
  waiter w;
  sd_sftp_reqopt o = opt_t(TMO);
  sd_sftp_attrs a;
  sd_sftp_file *f;
  char buf[64];
  uint32_t got;
  waiter_init(&w, g_s);

  SD_CHECK_EQ_INT(sd_sftp_mkdir_sync(g_s, P("crud"), NULL, TMO), SD_OK);
  SD_CHECK_EQ_INT(sd_sftp_stat_sync(g_s, P("crud"), &a, TMO), SD_OK);
  SD_CHECK(SD_SFTP_IS_DIR(&a));
  SD_CHECK_EQ_INT(write_file(P("crud/hello.txt"), "hello world", 11), SD_OK);
  SD_CHECK_EQ_INT(sd_sftp_stat_sync(g_s, P("crud/hello.txt"), &a, TMO), SD_OK);
  SD_CHECK(SD_SFTP_IS_REG(&a) && a.size == 11 && (a.valid & SD_SFTP_ATTR_TIMES));
  SD_CHECK_EQ_INT(read_file(P("crud/hello.txt"), buf, sizeof(buf), &got), SD_OK);
  SD_CHECK(got == 11 && memcmp(buf, "hello world", 11) == 0);

  /* open returns attrs (OPEN + FSTAT), fstat, fsetstat (truncate), read past EOF */
  SD_REQUIRE(sd_sftp_open_sync(g_s, P("crud/hello.txt"), SD_SFTP_O_READ | SD_SFTP_O_WRITE, NULL, &f, &a, TMO) == SD_OK);
  SD_CHECK_EQ_U64(a.size, 11);
  memset(&a, 0, sizeof(a));
  a.valid = SD_SFTP_ATTR_SIZE; a.size = 5;
  SD_CHECK_EQ_INT(RUN(&w, W_STAT, sd_sftp_fsetstat(f, &a, &o, waiter_cb, &w)), SD_OK);
  SD_CHECK_EQ_INT(RUN(&w, W_STAT, sd_sftp_fstat(f, &o, waiter_cb, &w)), SD_OK);
  SD_CHECK_EQ_U64(w.attrs.size, 5);
  SD_CHECK_EQ_INT(sd_sftp_read_sync(f, 5, buf, 10, &got, TMO), SD_E_EOF);
  SD_CHECK_EQ_INT(sd_sftp_write_sync(f, 5, "!", 1, TMO), SD_OK);
  SD_CHECK_EQ_INT(sd_sftp_close_sync(f, TMO), SD_OK);
  SD_CHECK_EQ_INT(read_file(P("crud/hello.txt"), buf, sizeof(buf), &got), SD_OK);
  SD_CHECK(got == 6 && memcmp(buf, "hello!", 6) == 0);

  /* setstat: permissions and times */
  memset(&a, 0, sizeof(a));
  a.valid = SD_SFTP_ATTR_PERM | SD_SFTP_ATTR_TIMES; a.perm = 0640; a.atime = 1000000000; a.mtime = 1234567890;
  SD_CHECK_EQ_INT(RUN(&w, W_STAT, sd_sftp_setstat(g_s, P("crud/hello.txt"), &a, 0, &o, waiter_cb, &w)), SD_OK);
  SD_CHECK_EQ_INT(sd_sftp_lstat_sync(g_s, P("crud/hello.txt"), &a, TMO), SD_OK);
  SD_CHECK_EQ_U64(a.perm & 07777, 0640);
  SD_CHECK_EQ_U64(a.mtime, 1234567890);

  /* symlink (OpenSSH argument order), readlink, lstat vs stat, realpath */
  SD_CHECK_EQ_INT(RUN(&w, W_STAT, sd_sftp_symlink(g_s, P("crud/link"), "hello.txt", &o, waiter_cb, &w)), SD_OK);
  SD_CHECK_EQ_INT(RUN(&w, W_NAME, sd_sftp_readlink(g_s, P("crud/link"), &o, waiter_cb, &w)), SD_OK);
  SD_CHECK_STR(w.path, "hello.txt");
  SD_CHECK_EQ_INT(sd_sftp_lstat_sync(g_s, P("crud/link"), &a, TMO), SD_OK);
  SD_CHECK(SD_SFTP_IS_LNK(&a));
  SD_CHECK_EQ_INT(sd_sftp_stat_sync(g_s, P("crud/link"), &a, TMO), SD_OK);
  SD_CHECK(SD_SFTP_IS_REG(&a) && a.size == 6);
  {
    char rp[512];
    SD_CHECK_EQ_INT(sd_sftp_realpath_sync(g_s, P("crud/../crud/./hello.txt"), rp, sizeof(rp), TMO), SD_OK);
    SD_CHECK_STR(rp, P("crud/hello.txt"));
  }

  /* rename, remove, rmdir */
  SD_CHECK_EQ_INT(sd_sftp_rename_sync(g_s, P("crud/hello.txt"), P("crud/renamed.txt"), 0, TMO), SD_OK);
  SD_CHECK_EQ_INT(sd_sftp_stat_sync(g_s, P("crud/hello.txt"), &a, TMO), SD_E_NOT_FOUND);
  SD_CHECK_EQ_INT(sd_sftp_remove_sync(g_s, P("crud/renamed.txt"), TMO), SD_OK);
  SD_CHECK_EQ_INT(sd_sftp_remove_sync(g_s, P("crud/link"), TMO), SD_OK);
  SD_CHECK_EQ_INT(sd_sftp_rmdir_sync(g_s, P("crud"), TMO), SD_OK);
  SD_CHECK_EQ_INT(sd_sftp_lstat_sync(g_s, P("crud"), &a, TMO), SD_E_NOT_FOUND);
  waiter_free(&w);
}

SD_TEST(interop_extensions)
{
  waiter w;
  sd_sftp_reqopt o = opt_t(TMO);
  sd_sftp_file *f;
  sd_sftp_attrs a;
  waiter_init(&w, g_s);
  SD_CHECK(sd_sftp_has_ext(g_s, SD_SFTP_EXT_POSIX_RENAME));
  SD_CHECK(sd_sftp_has_ext(g_s, SD_SFTP_EXT_STATVFS));
  SD_CHECK(sd_sftp_has_ext(g_s, SD_SFTP_EXT_FSYNC));
  SD_CHECK(sd_sftp_has_ext(g_s, SD_SFTP_EXT_LIMITS));
  SD_CHECK(sd_sftp_has_ext(g_s, SD_SFTP_EXT_HARDLINK));
  SD_CHECK(g_ev.max_read >= 32768 && g_ev.max_read <= 255 * 1024);
  SD_CHECK(g_ev.quirks & SD_SFTP_QUIRK_SYMLINK_OPENSSH_ORDER);

  SD_CHECK_EQ_INT(RUN(&w, W_VFS, sd_sftp_statvfs_path(g_s, g_dir, &o, waiter_cb, &w)), SD_OK);
  SD_CHECK(w.vfs.bsize > 0 && w.vfs.blocks > 0 && w.vfs.namemax >= 255);

  SD_REQUIRE(sd_sftp_open_sync(g_s, P("ext.bin"), SD_SFTP_O_WRITE | SD_SFTP_O_CREAT | SD_SFTP_O_TRUNC, NULL, &f, NULL, TMO) == SD_OK);
  SD_CHECK_EQ_INT(sd_sftp_write_sync(f, 0, "abc", 3, TMO), SD_OK);
  SD_CHECK_EQ_INT(RUN(&w, W_STAT, sd_sftp_fsync(f, &o, waiter_cb, &w)), SD_OK);
  SD_CHECK_EQ_INT(RUN(&w, W_VFS, sd_sftp_fstatvfs(f, &o, waiter_cb, &w)), SD_OK);
  SD_CHECK_EQ_INT(sd_sftp_close_sync(f, TMO), SD_OK);

  SD_CHECK_EQ_INT(RUN(&w, W_STAT, sd_sftp_hardlink(g_s, P("ext.bin"), P("ext.hard"), &o, waiter_cb, &w)), SD_OK);
  SD_CHECK_EQ_INT(sd_sftp_stat_sync(g_s, P("ext.hard"), &a, TMO), SD_OK);
  SD_CHECK_EQ_U64(a.size, 3);
  SD_CHECK_EQ_INT(RUN(&w, W_STAT, sd_sftp_hardlink(g_s, P("ext.bin"), P("ext.hard"), &o, waiter_cb, &w)), SD_E_EXISTS);

  /* lsetstat on a symlink changes the link, not the target */
  SD_CHECK_EQ_INT(RUN(&w, W_STAT, sd_sftp_symlink(g_s, P("ext.lnk"), "ext.bin", &o, waiter_cb, &w)), SD_OK);
  if (sd_sftp_has_ext(g_s, SD_SFTP_EXT_LSETSTAT)) {
    memset(&a, 0, sizeof(a));
    a.valid = SD_SFTP_ATTR_TIMES; a.atime = 1111111111; a.mtime = 1111111111;
    SD_CHECK_EQ_INT(RUN(&w, W_STAT, sd_sftp_setstat(g_s, P("ext.lnk"), &a, 1, &o, waiter_cb, &w)), SD_OK);
    SD_CHECK_EQ_INT(sd_sftp_lstat_sync(g_s, P("ext.lnk"), &a, TMO), SD_OK);
    SD_CHECK_EQ_U64(a.mtime, 1111111111);
    SD_CHECK_EQ_INT(sd_sftp_stat_sync(g_s, P("ext.bin"), &a, TMO), SD_OK);
    SD_CHECK(a.mtime != 1111111111);
  }
  if (sd_sftp_has_ext(g_s, SD_SFTP_EXT_EXPAND_PATH)) {
    SD_CHECK_EQ_INT(RUN(&w, W_NAME, sd_sftp_expand_path(g_s, "~", &o, waiter_cb, &w)), SD_OK);
    SD_CHECK(w.path[0] == '/');
  }
  waiter_free(&w);
}

typedef struct dir_count { volatile LONG seen; int bad; char *bitmap; } dir_count;

static void dir_count_cb(waiter *w, const sd_sftp_completion *c)
{
  dir_count *dc = (dir_count *)w->user;
  uint32_t i;
  for (i = 0; i < c->u.readdir.count; i++) {
    const sd_sftp_dirent *d = &c->u.readdir.ents[i];
    int n;
    if (d->name_len != 6 || d->name[0] != 'f' || sscanf_s(d->name + 1, "%5d", &n) != 1 || n < 1 || n > 10000 ||
        dc->bitmap[n]) { dc->bad++; continue; }
    if (!SD_SFTP_IS_REG(&d->attrs) || d->longname_len == 0) dc->bad++;
    dc->bitmap[n] = 1;
    dc->seen++;
  }
}

SD_TEST(interop_readdir_10k)
{
  waiter w;
  sd_sftp_reqopt o = opt_t(TMO);
  sd_sftp_file *d;
  dir_count dc;
  char cmd[512];
  int batches = 0;
  DWORD t0;
  memset(&dc, 0, sizeof(dc));
  dc.bitmap = (char *)sd_calloc(1, 10001);
  SD_REQUIRE(dc.bitmap != NULL);
  sprintf_s(cmd, sizeof(cmd), "mkdir -p %s/big && cd %s/big && seq -f 'f%%05g' 1 10000 | xargs touch", g_dir, g_dir);
  SD_REQUIRE(interop_wsl(cmd, 120000) == 0);
  waiter_init(&w, g_s);
  w.user = &dc;
  t0 = (DWORD)sd_tick_ms();
  SD_REQUIRE(RUN(&w, W_OPEN, sd_sftp_opendir(g_s, P("big"), &o, waiter_cb, &w)) == SD_OK);
  d = w.file;
  for (;;) {
    waiter_reset(&w, W_DIR);
    w.dir_cb = dir_count_cb;
    if (sd_sftp_readdir(d, &o, waiter_cb, &w) != SD_OK || !waiter_wait(&w, TMO)) { SD_CHECK(0); break; }
    if (w.err != SD_OK) { SD_CHECK_EQ_INT(w.err, SD_OK); break; }
    if (w.eof) break;
    batches++;
  }
  printf("  readdir: 10000 entries in %d batches, %lu ms\n", batches, (DWORD)sd_tick_ms() - t0);
  SD_CHECK_EQ_INT(dc.seen, 10000);
  SD_CHECK_EQ_INT(dc.bad, 0);
  SD_CHECK(batches > 1);
  SD_CHECK_EQ_INT(sd_sftp_close_sync(d, TMO), SD_OK);
  SD_CHECK_EQ_INT(sd_sftp_rmdir_sync(g_s, P("big"), TMO), SD_E_NOT_EMPTY);   /* refinement on a real server */
  waiter_free(&w);
  sd_free(dc.bitmap);
}

static uint64_t fnv1a(const uint8_t *p, size_t n)
{
  uint64_t h = 1469598103934665603ull;
  size_t i;
  for (i = 0; i < n; i++) { h ^= p[i]; h *= 1099511628211ull; }
  return h;
}

typedef struct chunk_ctx { volatile LONG pending, errors; sd_event done; } chunk_ctx;

static void chunk_cb(void *ctx, const sd_sftp_completion *c)
{
  chunk_ctx *k = (chunk_ctx *)ctx;
  if (c->err != SD_OK) InterlockedIncrement(&k->errors);
  if (InterlockedDecrement(&k->pending) == 0) sd_event_set(&k->done);
}

SD_TEST(interop_pipelined_64mib)
{
  const uint32_t size = 64u * 1024u * 1024u;
  uint8_t *src = (uint8_t *)sd_alloc(size), *dst = (uint8_t *)sd_alloc(size);
  sd_sftp_file *f;
  sd_sftp_attrs a;
  sd_sftp_reqopt o = opt_t(120000);
  uint64_t x = 0x9E3779B97F4A7C15ull, h_src;
  uint32_t i, got = 0, chunk;
  DWORD t0, t_w, t_r, t_rv;
  chunk_ctx k;
  SD_REQUIRE(src && dst);
  for (i = 0; i < size / 8; i++) {      /* xorshift64 pattern */
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    memcpy(src + (size_t)i * 8, &x, 8);
  }
  h_src = fnv1a(src, size);

  /* one 64 MiB write: split into max_write chunks and pipelined inside sd_sftp */
  SD_REQUIRE(sd_sftp_open_sync(g_s, P("big.bin"), SD_SFTP_O_WRITE | SD_SFTP_O_CREAT | SD_SFTP_O_TRUNC, NULL, &f, NULL, TMO) == SD_OK);
  t0 = (DWORD)sd_tick_ms();
  SD_CHECK_EQ_INT(sd_sftp_write_sync(f, 0, src, size, 120000), SD_OK);
  t_w = (DWORD)sd_tick_ms() - t0;
  SD_CHECK_EQ_INT(sd_sftp_close_sync(f, TMO), SD_OK);
  SD_CHECK_EQ_INT(sd_sftp_stat_sync(g_s, P("big.bin"), &a, TMO), SD_OK);
  SD_CHECK_EQ_U64(a.size, size);

  /* one 64 MiB read */
  SD_REQUIRE(sd_sftp_open_sync(g_s, P("big.bin"), SD_SFTP_O_READ, NULL, &f, NULL, TMO) == SD_OK);
  memset(dst, 0, size);
  t0 = (DWORD)sd_tick_ms();
  SD_CHECK_EQ_INT(sd_sftp_read_sync(f, 0, dst, size, &got, 120000), SD_OK);
  t_r = (DWORD)sd_tick_ms() - t0;
  SD_CHECK_EQ_U64(got, size);
  SD_CHECK(fnv1a(dst, size) == h_src);
  SD_CHECK(memcmp(dst, src, size) == 0);

  /* VFS style: chunk-sized reads, all submitted at once (sd_sftp queues beyond the window) */
  memset(dst, 0, size);
  chunk = (uint32_t)g_ev.max_read;
  k.pending = 1; k.errors = 0;
  (void)sd_event_init(&k.done, 1, 0);
  t0 = (DWORD)sd_tick_ms();
  for (i = 0; i < size; i += chunk) {
    uint32_t n = size - i < chunk ? size - i : chunk;
    InterlockedIncrement(&k.pending);
    if (sd_sftp_read(f, i, dst + i, n, &o, chunk_cb, &k) != SD_OK) { InterlockedDecrement(&k.pending); k.errors++; }
  }
  if (InterlockedDecrement(&k.pending) == 0) sd_event_set(&k.done);
  SD_CHECK(sd_event_wait(&k.done, 120000) == SD_OK);
  t_rv = (DWORD)sd_tick_ms() - t0;
  sd_event_destroy(&k.done);
  SD_CHECK_EQ_INT(k.errors, 0);
  SD_CHECK(memcmp(dst, src, size) == 0);
  SD_CHECK_EQ_INT(sd_sftp_close_sync(f, TMO), SD_OK);

  printf("  64 MiB: write %lu ms (%.1f MiB/s), read %lu ms (%.1f MiB/s), chunked read %lu ms (%.1f MiB/s); "
         "chunk %u, checksum %016llx\n",
         t_w, t_w ? 64000.0 / t_w : 0.0, t_r, t_r ? 64000.0 / t_r : 0.0, t_rv, t_rv ? 64000.0 / t_rv : 0.0,
         chunk, (unsigned long long)h_src);
  {
    sd_sftp_stats st;
    if (sd_sftp_session_stats(g_s, &st) == SD_OK)
      printf("  stats: srtt %u ms, rx %llu B, tx %llu B\n", st.total.srtt_ms,
             (unsigned long long)st.total.rx_total, (unsigned long long)st.total.tx_total);
  }
  SD_CHECK_EQ_INT(sd_sftp_remove_sync(g_s, P("big.bin"), TMO), SD_OK);
  sd_free(src);
  sd_free(dst);
}

SD_TEST(interop_rename_overwrite)
{
  char buf[16];
  uint32_t got;
  sd_sftp_attrs a;
  SD_REQUIRE(write_file(P("ra"), "AAAA", 4) == SD_OK);
  SD_REQUIRE(write_file(P("rb"), "BB", 2) == SD_OK);
  /* plain SFTP rename never replaces: refined to EXISTS */
  SD_CHECK_EQ_INT(sd_sftp_rename_sync(g_s, P("ra"), P("rb"), 0, TMO), SD_E_EXISTS);
  SD_CHECK_EQ_INT(read_file(P("rb"), buf, sizeof(buf), &got), SD_OK);
  SD_CHECK(got == 2);
  /* posix-rename replaces atomically */
  SD_CHECK_EQ_INT(sd_sftp_rename_sync(g_s, P("ra"), P("rb"), SD_SFTP_RENAME_OVERWRITE, TMO), SD_OK);
  SD_CHECK_EQ_INT(read_file(P("rb"), buf, sizeof(buf), &got), SD_OK);
  SD_CHECK(got == 4 && memcmp(buf, "AAAA", 4) == 0);
  SD_CHECK_EQ_INT(sd_sftp_stat_sync(g_s, P("ra"), &a, TMO), SD_E_NOT_FOUND);
  /* rename onto a fresh name, and of a missing source */
  SD_CHECK_EQ_INT(sd_sftp_rename_sync(g_s, P("rb"), P("rc"), 0, TMO), SD_OK);
  SD_CHECK_EQ_INT(sd_sftp_rename_sync(g_s, P("nope"), P("rd"), 0, TMO), SD_E_NOT_FOUND);
  /* directories: overwrite onto a non-empty directory fails */
  SD_CHECK_EQ_INT(sd_sftp_mkdir_sync(g_s, P("rdir1"), NULL, TMO), SD_OK);
  SD_CHECK_EQ_INT(sd_sftp_mkdir_sync(g_s, P("rdir2"), NULL, TMO), SD_OK);
  SD_CHECK_EQ_INT(write_file(P("rdir2/x"), "x", 1), SD_OK);
  SD_CHECK(sd_sftp_rename_sync(g_s, P("rdir1"), P("rdir2"), SD_SFTP_RENAME_OVERWRITE, TMO) != SD_OK);
  SD_CHECK_EQ_INT(sd_sftp_remove_sync(g_s, P("rc"), TMO), SD_OK);
}

SD_TEST(interop_error_mapping)
{
  sd_sftp_attrs a;
  sd_sftp_file *f = NULL;
  char buf[8];
  uint32_t got;
  SD_CHECK_EQ_INT(sd_sftp_stat_sync(g_s, P("does-not-exist"), &a, TMO), SD_E_NOT_FOUND);
  SD_CHECK_EQ_INT(sd_sftp_open_sync(g_s, P("missing-dir/x"), SD_SFTP_O_WRITE | SD_SFTP_O_CREAT, NULL, &f, NULL, TMO),
                  SD_E_NOT_FOUND);
  /* EEXIST (FAILURE refined) */
  SD_REQUIRE(sd_sftp_mkdir_sync(g_s, P("e1"), NULL, TMO) == SD_OK);
  SD_CHECK_EQ_INT(sd_sftp_mkdir_sync(g_s, P("e1"), NULL, TMO), SD_E_EXISTS);
  SD_REQUIRE(write_file(P("e1/file"), "data", 4) == SD_OK);
  SD_CHECK_EQ_INT(sd_sftp_open_sync(g_s, P("e1/file"), SD_SFTP_O_WRITE | SD_SFTP_O_CREAT | SD_SFTP_O_EXCL, NULL, &f, NULL,
                                    TMO), SD_E_EXISTS);
  /* ENOTEMPTY (FAILURE refined through OPENDIR/READDIR), EISDIR on remove */
  SD_CHECK_EQ_INT(sd_sftp_rmdir_sync(g_s, P("e1"), TMO), SD_E_NOT_EMPTY);
  SD_CHECK_EQ_INT(sd_sftp_remove_sync(g_s, P("e1"), TMO), SD_E_IS_A_DIRECTORY);
  /* EACCES: needs a non-root server user */
  if (g_ev.uid != 0) {
    sd_sftp_attrs p;
    memset(&p, 0, sizeof(p));
    p.valid = SD_SFTP_ATTR_PERM;
    p.perm = 0;
    SD_REQUIRE(write_file(P("e1/secret"), "s", 1) == SD_OK);
    {
      waiter w;
      sd_sftp_reqopt o = opt_t(TMO);
      waiter_init(&w, g_s);
      SD_CHECK_EQ_INT(RUN(&w, W_STAT, sd_sftp_setstat(g_s, P("e1/secret"), &p, 0, &o, waiter_cb, &w)), SD_OK);
      p.perm = 0500;
      SD_CHECK_EQ_INT(RUN(&w, W_STAT, sd_sftp_setstat(g_s, P("e1"), &p, 0, &o, waiter_cb, &w)), SD_OK);
      waiter_free(&w);
    }
    SD_CHECK_EQ_INT(read_file(P("e1/secret"), buf, sizeof(buf), &got), SD_E_ACCESS_DENIED);
    SD_CHECK_EQ_INT(sd_sftp_mkdir_sync(g_s, P("e1/sub"), NULL, TMO), SD_E_ACCESS_DENIED);
    SD_CHECK_EQ_INT(sd_sftp_remove_sync(g_s, P("e1/file"), TMO), SD_E_ACCESS_DENIED);
    p.perm = 0700;
    {
      waiter w;
      sd_sftp_reqopt o = opt_t(TMO);
      waiter_init(&w, g_s);
      SD_CHECK_EQ_INT(RUN(&w, W_STAT, sd_sftp_setstat(g_s, P("e1"), &p, 0, &o, waiter_cb, &w)), SD_OK);
      waiter_free(&w);
    }
  } else {
    printf("  (server runs as root: EACCES cases skipped)\n");
  }
  SD_CHECK_EQ_INT(sd_sftp_remove_sync(g_s, P("e1/file"), TMO), SD_OK);
  (void)sd_sftp_remove_sync(g_s, P("e1/secret"), TMO);
  SD_CHECK_EQ_INT(sd_sftp_rmdir_sync(g_s, P("e1"), TMO), SD_OK);
}

SD_TEST(interop_deadline_expiry)
{
  waiter w;
  sd_sftp_reqopt o = opt_t(300);
  sd_sftp_attrs a;
  DWORD t0, el;
  waiter_init(&w, g_s);
  proc_pause(g_proc, 1);                 /* the server's replies are held back: a stalled server */
  t0 = (DWORD)sd_tick_ms();
  SD_CHECK_EQ_INT(RUN(&w, W_STAT, sd_sftp_stat(g_s, g_dir, &o, waiter_cb, &w)), SD_E_TIMEOUT);
  el = (DWORD)sd_tick_ms() - t0;
  SD_CHECK(w.maybe_executed);
  SD_CHECK(el >= 250 && el < 3000);
  SD_CHECK_EQ_INT(sd_sftp_stat_sync(g_s, g_dir, &a, 200), SD_E_TIMEOUT);
  proc_pause(g_proc, 0);                 /* late replies arrive and are discarded */
  SD_CHECK_EQ_INT(sd_sftp_stat_sync(g_s, g_dir, &a, TMO), SD_OK);
  SD_CHECK(SD_SFTP_IS_DIR(&a));
  SD_CHECK_EQ_INT(sd_sftp_session_state(g_s), SD_SFTP_ST_READY);
  waiter_free(&w);
}
