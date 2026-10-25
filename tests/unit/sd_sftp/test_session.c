/* Session-level tests against a scripted fake server (no SSH, no network): handshake bytes,
 * pipelining window, chunking, short reads, deadlines, cancellation, back-pressure, error
 * refinement probes, readdir filtering, symlink argument order, protocol errors, close. */
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_platform/sd_time.h"
#include "sd_test.h"
#include "sftp_proto.h"
#include "sftp_test_tp.h"
#include "test_util.h"

#define HOLD_MAX 2048

typedef struct srv srv;
struct srv {
  fake_srv *f;
  int minimal;              /* announce no extensions */
  int no_limits;
  int (*hook)(srv *sv, uint8_t type, uint32_t id, sd_rd *rd);
  uint8_t init_bytes[16]; size_t init_n;
  uint32_t startup_order[4]; int startup_n;
  /* held requests */
  volatile LONG nheld;
  uint32_t held_id[HOLD_MAX]; uint64_t held_off[HOLD_MAX]; uint32_t held_len[HOLD_MAX]; uint8_t held_type[HOLD_MAX];
  volatile LONG reads_seen;
  /* misc capture */
  char s1[256], s2[256];
  uint32_t u[8];
  uint64_t file_size;
  volatile LONG probes;
  uint8_t *wdata; uint64_t wlen; uint32_t woffs[16]; uint32_t wlens[16]; int nw;
};

static uint8_t pat(uint64_t o) { return (uint8_t)(o * 7u + (o >> 9)); }

static void span_to(char *dst, size_t cap, sd_span s)
{
  size_t n = s.n < cap - 1 ? s.n : cap - 1;
  if (n) memcpy(dst, s.p, n);
  dst[n] = 0;
}

static void send_version(srv *sv)
{
  static const char *const exts[][2] = {
    { "posix-rename@openssh.com", "1" }, { "statvfs@openssh.com", "2" }, { "fstatvfs@openssh.com", "2" },
    { "hardlink@openssh.com", "1" }, { "fsync@openssh.com", "1" }, { "lsetstat@openssh.com", "1" },
    { "limits@openssh.com", "1" }, { "expand-path@openssh.com", "1" }, { "copy-data", "1" },
    { "home-directory", "1" }, { "users-groups-by-id@openssh.com", "1" }, { "x-unknown@example.org", "7" },
  };
  sd_wr w;
  size_t i;
  sd_wr_init(&w, 65536);
  sd_wr_u32(&w, 0); sd_wr_u8(&w, SFTP_VERSION); sd_wr_u32(&w, 3);
  if (!sv->minimal)
    for (i = 0; i < SD_COUNTOF(exts); i++) {
      if (sv->no_limits && i == 6) continue;
      sd_wr_cstring(&w, exts[i][0]); sd_wr_cstring(&w, exts[i][1]);
    }
  fake_reply_wr(sv->f, &w);
}

static void reply_name(srv *sv, uint32_t id, const char *name)
{
  sd_wr w;
  pk_begin(&w, SFTP_NAME, id);
  sd_wr_u32(&w, 1);
  sd_wr_cstring(&w, name); sd_wr_cstring(&w, "");
  sd_wr_u32(&w, 0);
  fake_reply_wr(sv->f, &w);
}

static void reply_attrs(srv *sv, uint32_t id, uint32_t perm, uint64_t size)
{
  sd_wr w;
  pk_begin(&w, SFTP_ATTRS, id);
  pk_attrs_body(&w, perm, size);
  fake_reply_wr(sv->f, &w);
}

static void srv_handler(fake_srv *f, void *ctx, const uint8_t *pkt, size_t n)
{
  srv *sv = (srv *)ctx;
  uint8_t type = pkt[0];
  uint32_t id;
  sd_rd rd;
  if (type == SFTP_INIT) {
    sv->init_n = n + 4 < sizeof(sv->init_bytes) ? n + 4 : sizeof(sv->init_bytes);
    sd_store_be32(sv->init_bytes, (uint32_t)n);
    memcpy(sv->init_bytes + 4, pkt, sv->init_n - 4);
    send_version(sv);
    return;
  }
  sd_rd_init(&rd, pkt + 1, n - 1);
  id = sd_rd_u32(&rd);
  if (sv->hook) {
    sd_rd copy = rd;
    if (sv->hook(sv, type, id, &copy)) return;
  }
  if (type == SFTP_EXTENDED) {
    sd_span nm = sd_rd_string(&rd, 256);
    if (nm.n == 18 && memcmp(nm.p, "limits@openssh.com", 18) == 0) {
      sd_wr w;
      if (sv->startup_n < 4) sv->startup_order[sv->startup_n++] = 1;
      pk_begin(&w, SFTP_EXTENDED_REPLY, id);
      sd_wr_u64(&w, 262144); sd_wr_u64(&w, 261120); sd_wr_u64(&w, 261120); sd_wr_u64(&w, 1024);
      fake_reply_wr(f, &w);
      return;
    }
  }
  if (type == SFTP_REALPATH) {
    sd_span p = sd_rd_string(&rd, 4096);
    if (p.n == 1 && p.p[0] == '.') {
      if (sv->startup_n < 4) sv->startup_order[sv->startup_n++] = 2;
      reply_name(sv, id, "/home/u");
      return;
    }
  }
  if (type == SFTP_STAT) {
    sd_span p = sd_rd_string(&rd, 4096);
    if (p.n == 7 && memcmp(p.p, "/home/u", 7) == 0) {
      if (sv->startup_n < 4) sv->startup_order[sv->startup_n++] = 3;
      reply_attrs(sv, id, 040755, 4096);
      return;
    }
  }
  pk_status(f, id, SFTP_FX_OP_UNSUPPORTED, "unsupported in fake");
}

typedef struct fx { srv sv; sd_sftp_session *s; evlog ev; } fx;

static int fx_start(fx *x, const sd_sftp_options *opt)
{
  sd_sftp_transport t;
  evlog_init(&x->ev);
  x->sv.f = fake_new(srv_handler, &x->sv);
  if (!x->sv.f) return 0;
  fake_transport(x->sv.f, &t);
  if (sd_sftp_session_create_transport(&t, opt, evlog_cb, &x->ev, &x->s) != SD_OK) { fake_free_if_unused(x->sv.f); return 0; }
  if (sd_sftp_session_start(x->s) != SD_OK) return 0;
  if (sd_event_wait(&x->ev.ready, 5000) != SD_OK) return 0;
  return sd_sftp_session_state(x->s) == SD_SFTP_ST_READY;
}

static void fx_stop(fx *x)
{
  if (x->s) {
    (void)sd_sftp_session_close(x->s);
    (void)sd_event_wait(&x->ev.ended, 5000);
    if (sd_sftp_session_state(x->s) != SD_SFTP_ST_CLOSED) {
      /* FAILED sessions still need an explicit close to reach CLOSED */
      sd_event_reset(&x->ev.ended);
      (void)sd_event_wait(&x->ev.ended, 2000);
    }
    sd_sftp_session_destroy(x->s);
  }
  evlog_free(&x->ev);
  sd_free(x->sv.wdata);
}

static fx *fx_new(void) { return (fx *)sd_calloc(1, sizeof(fx)); }

/* ---- handshake ---- */

SD_TEST(session_handshake_canned)
{
  static const uint8_t init3[] = { 0, 0, 0, 5, 1, 0, 0, 0, 3 };
  fx *x = fx_new();
  sd_sftp_server_info info;
  char home[64];
  SD_REQUIRE(x != NULL);
  SD_REQUIRE(fx_start(x, NULL));
  SD_CHECK(x->sv.init_n == sizeof(init3));
  SD_CHECK_MEM(x->sv.init_bytes, init3, sizeof(init3));
  SD_CHECK(x->sv.startup_n == 3 && x->sv.startup_order[0] == 1 && x->sv.startup_order[1] == 2 &&
           x->sv.startup_order[2] == 3);
  SD_CHECK(evlog_has(&x->ev, SD_SFTP_ST_CONNECTING));
  SD_CHECK_EQ_U64(x->ev.ext, 0x7FF);
  SD_CHECK_EQ_U64(x->ev.ext_count, 12);
  SD_CHECK_EQ_U64(x->ev.max_read, 261120);
  SD_CHECK_EQ_U64(x->ev.max_write, 261120);
  SD_CHECK(x->ev.quirks & SD_SFTP_QUIRK_SYMLINK_OPENSSH_ORDER);
  SD_CHECK(!(x->ev.quirks & SD_SFTP_QUIRK_WIN_DRIVE_PATHS));
  SD_CHECK_EQ_U64(x->ev.uid, 1000);
  SD_CHECK_STR(x->ev.home, "/home/u");
  SD_CHECK(sd_sftp_has_ext(x->s, SD_SFTP_EXT_POSIX_RENAME));
  SD_CHECK(sd_sftp_has_ext(x->s, SD_SFTP_EXT_LIMITS | SD_SFTP_EXT_FSYNC));
  SD_CHECK(sd_sftp_session_info(x->s, &info, home, sizeof(home)) == SD_OK);
  SD_CHECK_STR(info.home, "/home/u");
  SD_CHECK_EQ_U64(info.generation, 1);
  SD_CHECK_EQ_U64(info.version, 3);
  SD_CHECK_EQ_U64(info.channels, 1);
  SD_CHECK(info.identity.source == SD_SFTP_ID_HOME_OWNER);
  SD_CHECK_STR(info.ext_list[11].name, "x-unknown@example.org");
  SD_CHECK_STR(info.ext_list[11].version, "7");
  fx_stop(x);
  SD_CHECK(evlog_has(&x->ev, SD_SFTP_ST_CLOSED));
  sd_free(x);
}

SD_TEST(session_handshake_minimal_server)
{
  fx *x = fx_new();
  waiter w;
  sd_sftp_reqopt o = { 0, 2000, NULL };
  SD_REQUIRE(x != NULL);
  x->sv.minimal = 1;
  SD_REQUIRE(fx_start(x, NULL));
  SD_CHECK_EQ_U64(x->ev.ext, 0);
  SD_CHECK_EQ_U64(x->ev.max_read, 32768);
  SD_CHECK(!(x->ev.quirks & SD_SFTP_QUIRK_SYMLINK_OPENSSH_ORDER));
  SD_CHECK(x->sv.startup_n == 2);     /* no limits request */
  waiter_init(&w, x->s);
  /* extension-backed calls complete with UNSUPPORTED through the callback */
  waiter_reset(&w, W_STAT);
  SD_REQUIRE(sd_sftp_rename(x->s, "/a", "/b", SD_SFTP_RENAME_OVERWRITE, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 3000));
  SD_CHECK_EQ_INT(w.err, SD_E_UNSUPPORTED);
  waiter_reset(&w, W_VFS);
  SD_REQUIRE(sd_sftp_statvfs_path(x->s, "/", &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 3000));
  SD_CHECK_EQ_INT(w.err, SD_E_UNSUPPORTED);
  waiter_reset(&w, W_STAT);
  SD_REQUIRE(sd_sftp_setstat(x->s, "/a", &w.attrs, 1, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 3000));
  SD_CHECK_EQ_INT(w.err, SD_E_UNSUPPORTED);
  waiter_free(&w);
  fx_stop(x);
  sd_free(x);
}

/* ---- pipelining window ---- */

static int hold_reads_hook(srv *sv, uint8_t type, uint32_t id, sd_rd *rd)
{
  sd_span h;
  LONG i;
  if (type != SFTP_READ) return 0;
  h = sd_rd_string(rd, 256);
  SD_UNUSED(h);
  i = sv->nheld;
  if (i >= HOLD_MAX) return 0;
  sv->held_id[i] = id;
  sv->held_off[i] = sd_rd_u64(rd);
  sv->held_len[i] = sd_rd_u32(rd);
  InterlockedIncrement(&sv->reads_seen);
  InterlockedExchange(&sv->nheld, i + 1);
  return 1;
}

static int open_hook(srv *sv, uint8_t type, uint32_t id, sd_rd *rd)
{
  SD_UNUSED(rd);
  if (type == SFTP_OPEN || type == SFTP_OPENDIR) { pk_handle(sv->f, id, type == SFTP_OPEN ? "fh" : "dh"); return 1; }
  if (type == SFTP_FSTAT) { reply_attrs(sv, id, 0100644, sv->file_size); return 1; }
  if (type == SFTP_CLOSE) { pk_status(sv->f, id, 0, ""); return 1; }
  return 0;
}

static int window_hook(srv *sv, uint8_t type, uint32_t id, sd_rd *rd)
{
  return open_hook(sv, type, id, rd) || hold_reads_hook(sv, type, id, rd);
}

static void flush_held(void *arg)
{
  srv *sv = (srv *)arg;
  LONG i, n = sv->nheld;
  for (i = 0; i < n; i++) {
    sd_wr w;
    uint32_t k;
    pk_begin(&w, SFTP_DATA, sv->held_id[i]);
    sd_wr_u32(&w, sv->held_len[i]);
    for (k = 0; k < sv->held_len[i]; k++) sd_wr_u8(&w, pat(sv->held_off[i] + k));
    fake_reply_wr(sv->f, &w);
  }
  InterlockedExchange(&sv->nheld, 0);
}

static sd_sftp_file *open_file(fx *x, const char *path, uint32_t flags)
{
  waiter w;
  sd_sftp_reqopt o = { 0, 3000, NULL };
  sd_sftp_file *f = NULL;
  waiter_init(&w, x->s);
  waiter_reset(&w, W_OPEN);
  if (sd_sftp_open(x->s, path, flags, NULL, NULL, &o, waiter_cb, &w) == SD_OK && waiter_wait(&w, 3000) &&
      w.err == SD_OK)
    f = w.file;
  waiter_free(&w);
  return f;
}

/* Measures the largest number of READs the client keeps outstanding. */
static LONG run_window(fx *x, uint32_t total_len, uint8_t *buf, waiter *w)
{
  sd_sftp_file *f = open_file(x, "/big", SD_SFTP_O_READ);
  sd_sftp_reqopt o = { 0, 20000, NULL };
  LONG max_held = 0, last = -1;
  int stable = 0;
  if (!f) return -1;
  waiter_reset(w, W_RW);
  if (sd_sftp_read(f, 0, buf, total_len, &o, waiter_cb, w) != SD_OK) return -1;
  while (!waiter_wait(w, 20)) {
    LONG n = x->sv.nheld;
    if (n == last && n > 0) {
      if (++stable >= 3) {
        if (n > max_held) max_held = n;
        fake_run(x->sv.f, flush_held, &x->sv);
        stable = 0; last = -1;
        Sleep(20);
      }
    } else { stable = 0; last = n; }
  }
  sd_sftp_file_release(f);
  return max_held;
}

SD_TEST(session_pipelining_window_requests)
{
  fx *x = fx_new();
  waiter w;
  uint32_t total = 100u * 32768u, i;
  uint8_t *buf = (uint8_t *)sd_alloc(total);
  LONG max_held;
  int ok = 1;
  SD_REQUIRE(x != NULL && buf != NULL);
  x->sv.no_limits = 1;            /* 32 KiB chunks: the 64-request window is the limit */
  x->sv.hook = window_hook;
  SD_REQUIRE(fx_start(x, NULL));
  waiter_init(&w, x->s);
  max_held = run_window(x, total, buf, &w);
  SD_CHECK_EQ_INT(max_held, 64);
  SD_CHECK_EQ_INT(w.err, SD_OK);
  SD_CHECK_EQ_U64(w.bytes, total);
  SD_CHECK_EQ_INT(x->sv.reads_seen, 100);
  SD_CHECK(w.on_io_thread);
  for (i = 0; i < total && ok; i++) ok = buf[i] == pat(i);
  SD_CHECK(ok);
  waiter_free(&w);
  fx_stop(x);
  sd_free(buf);
  sd_free(x);
}

SD_TEST(session_pipelining_window_configurable)
{
  fx *x = fx_new();
  waiter w;
  sd_sftp_options opt;
  uint32_t total = 300u * 32768u;
  uint8_t *buf = (uint8_t *)sd_alloc(total);
  SD_REQUIRE(x != NULL && buf != NULL);
  sd_sftp_options_init(&opt);
  opt.max_inflight_reqs = 200;
  opt.max_inflight_bytes = 64u * 1024u * 1024u;
  x->sv.no_limits = 1;
  x->sv.hook = window_hook;
  SD_REQUIRE(fx_start(x, &opt));
  waiter_init(&w, x->s);
  SD_CHECK_EQ_INT(run_window(x, total, buf, &w), 200);
  SD_CHECK_EQ_INT(w.err, SD_OK);
  SD_CHECK_EQ_U64(w.bytes, total);
  waiter_free(&w);
  fx_stop(x);
  sd_free(buf);
  sd_free(x);
}

SD_TEST(session_pipelining_window_bytes)
{
  fx *x = fx_new();
  waiter w;
  uint32_t total = 40u * 261120u;
  uint8_t *buf = (uint8_t *)sd_alloc(total);
  SD_REQUIRE(x != NULL && buf != NULL);
  x->sv.hook = window_hook;        /* limits: 255 KiB chunks, the 8 MiB byte window is the limit */
  SD_REQUIRE(fx_start(x, NULL));
  waiter_init(&w, x->s);
  SD_CHECK_EQ_INT(run_window(x, total, buf, &w), 32);
  SD_CHECK_EQ_U64(w.bytes, total);
  SD_CHECK_EQ_INT(x->sv.reads_seen, 40);
  waiter_free(&w);
  fx_stop(x);
  sd_free(buf);
  sd_free(x);
}

/* ---- short reads and EOF ---- */

static int short_read_hook(srv *sv, uint8_t type, uint32_t id, sd_rd *rd)
{
  if (open_hook(sv, type, id, rd)) return 1;
  if (type == SFTP_READ) {
    sd_wr w;
    uint64_t off;
    uint32_t len, k;
    (void)sd_rd_string(rd, 256);
    off = sd_rd_u64(rd);
    len = sd_rd_u32(rd);
    InterlockedIncrement(&sv->reads_seen);
    if (off >= sv->file_size) { pk_status(sv->f, id, SFTP_FX_EOF, "EOF"); return 1; }
    if (off + len > sv->file_size) len = (uint32_t)(sv->file_size - off);
    if (off == 0) len /= 2;             /* first chunk comes back short */
    pk_begin(&w, SFTP_DATA, id);
    sd_wr_u32(&w, len);
    for (k = 0; k < len; k++) sd_wr_u8(&w, pat(off + k));
    fake_reply_wr(sv->f, &w);
    return 1;
  }
  return 0;
}

SD_TEST(session_short_read_reissue_and_eof)
{
  fx *x = fx_new();
  waiter w;
  sd_sftp_reqopt o = { 0, 5000, NULL };
  sd_sftp_file *f;
  uint8_t *buf = (uint8_t *)sd_alloc(65536);
  uint32_t i;
  int ok = 1;
  SD_REQUIRE(x != NULL && buf != NULL);
  x->sv.no_limits = 1;
  x->sv.file_size = 50000;
  x->sv.hook = short_read_hook;
  SD_REQUIRE(fx_start(x, NULL));
  f = open_file(x, "/f", SD_SFTP_O_READ);
  SD_REQUIRE(f != NULL);
  waiter_init(&w, x->s);
  waiter_reset(&w, W_RW);
  memset(buf, 0xEE, 65536);
  SD_REQUIRE(sd_sftp_read(f, 0, buf, 65536, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_OK);
  SD_CHECK_EQ_U64(w.bytes, 50000);
  SD_CHECK(w.eof);
  for (i = 0; i < 50000 && ok; i++) ok = buf[i] == pat(i);
  SD_CHECK(ok);
  SD_CHECK(x->sv.reads_seen >= 4);      /* 2 chunks + reissue of the short one + EOF probe */
  /* read entirely past EOF */
  waiter_reset(&w, W_RW);
  SD_REQUIRE(sd_sftp_read(f, 50000, buf, 100, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_E_EOF);
  SD_CHECK(w.eof && w.bytes == 0);
  /* sync wrapper over the same path */
  {
    uint32_t got = 0;
    SD_CHECK_EQ_INT(sd_sftp_read_sync(f, 49990, buf, 100, &got, 5000), SD_OK);
    SD_CHECK_EQ_U64(got, 10);
  }
  SD_CHECK_EQ_INT(sd_sftp_close_sync(f, 5000), SD_OK);
  waiter_free(&w);
  fx_stop(x);
  sd_free(buf);
  sd_free(x);
}

/* ---- writes: chunking and ordering ---- */

static int write_hook(srv *sv, uint8_t type, uint32_t id, sd_rd *rd)
{
  if (open_hook(sv, type, id, rd)) { if (type == SFTP_CLOSE) sv->u[0] = (uint32_t)sv->nw; return 1; }
  if (type == SFTP_WRITE) {
    sd_span d;
    uint64_t off;
    (void)sd_rd_string(rd, 256);
    off = sd_rd_u64(rd);
    d = sd_rd_string(rd, 1u << 20);
    if (sv->nw < 16) { sv->woffs[sv->nw] = (uint32_t)off; sv->wlens[sv->nw] = (uint32_t)d.n; sv->nw++; }
    if (off + d.n <= sv->wlen) memcpy(sv->wdata + off, d.p, d.n);
    pk_status(sv->f, id, 0, "");
    return 1;
  }
  return 0;
}

SD_TEST(session_write_chunking)
{
  fx *x = fx_new();
  waiter w;
  sd_sftp_reqopt o = { 0, 5000, NULL };
  sd_sftp_file *f;
  uint8_t *src = (uint8_t *)sd_alloc(100000);
  uint32_t i;
  SD_REQUIRE(x != NULL && src != NULL);
  for (i = 0; i < 100000; i++) src[i] = pat(i + 3);
  x->sv.no_limits = 1;
  x->sv.wlen = 100000;
  x->sv.wdata = (uint8_t *)sd_calloc(1, 100000);
  x->sv.hook = write_hook;
  SD_REQUIRE(fx_start(x, NULL));
  f = open_file(x, "/w", SD_SFTP_O_WRITE | SD_SFTP_O_CREAT | SD_SFTP_O_TRUNC);
  SD_REQUIRE(f != NULL);
  waiter_init(&w, x->s);
  waiter_reset(&w, W_RW);
  SD_REQUIRE(sd_sftp_write(f, 0, src, 100000, &o, waiter_cb, &w) == SD_OK);
  /* close queued right behind the write, without waiting: must go out after all chunks */
  {
    waiter wc;
    waiter_init(&wc, x->s);
    waiter_reset(&wc, W_STAT);
    SD_REQUIRE(sd_sftp_close(f, &o, waiter_cb, &wc) == SD_OK);
    SD_REQUIRE(waiter_wait(&wc, 5000));
    SD_CHECK_EQ_INT(wc.err, SD_OK);
    waiter_free(&wc);
  }
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_OK);
  SD_CHECK_EQ_U64(w.bytes, 100000);
  SD_CHECK_EQ_INT(x->sv.nw, 4);
  SD_CHECK(x->sv.woffs[0] == 0 && x->sv.woffs[1] == 32768 && x->sv.woffs[2] == 65536 && x->sv.woffs[3] == 98304);
  SD_CHECK(x->sv.wlens[0] == 32768 && x->sv.wlens[3] == 100000 - 98304);
  SD_CHECK_EQ_U64(x->sv.u[0], 4);       /* CLOSE arrived after the fourth WRITE */
  SD_CHECK_MEM(x->sv.wdata, src, 100000);
  /* operations on a closed handle fail locally */
  waiter_free(&w);
  fx_stop(x);
  sd_free(src);
  sd_free(x);
}

/* ---- deadlines, cancellation, back-pressure ---- */

static int hold_stat_hook(srv *sv, uint8_t type, uint32_t id, sd_rd *rd)
{
  sd_span p;
  if (type != SFTP_STAT) return 0;
  p = sd_rd_string(rd, 4096);
  if (p.n >= 5 && memcmp(p.p, "/slow", 5) == 0) {
    LONG i = sv->nheld;
    sv->held_id[i] = id;
    InterlockedExchange(&sv->nheld, i + 1);
    return 1;
  }
  if (p.n == 5 && memcmp(p.p, "/fast", 5) == 0) {
    LONG i, n = sv->nheld;
    for (i = 0; i < n; i++) reply_attrs(sv, sv->held_id[i], 0100644, 1);   /* late replies first */
    InterlockedExchange(&sv->nheld, 0);
    reply_attrs(sv, id, 0100600, 7);
    return 1;
  }
  return 0;
}

static void flush_held_attrs(void *arg)
{
  srv *sv = (srv *)arg;
  LONG i, n = sv->nheld;
  for (i = 0; i < n; i++) reply_attrs(sv, sv->held_id[i], 0100644, 1);
  InterlockedExchange(&sv->nheld, 0);
}

SD_TEST(session_deadline_expiry)
{
  fx *x = fx_new();
  waiter w;
  sd_sftp_reqopt o = { 0, 200, NULL };
  uint64_t t0;
  DWORD el;
  SD_REQUIRE(x != NULL);
  x->sv.hook = hold_stat_hook;
  SD_REQUIRE(fx_start(x, NULL));
  waiter_init(&w, x->s);
  waiter_reset(&w, W_STAT);
  t0 = (DWORD)sd_tick_ms();
  SD_REQUIRE(sd_sftp_stat(x->s, "/slow", &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 3000));
  el = (DWORD)((DWORD)sd_tick_ms() - t0);
  SD_CHECK_EQ_INT(w.err, SD_E_TIMEOUT);
  SD_CHECK(w.maybe_executed);
  SD_CHECK(el >= 150 && el < 1500);
  SD_CHECK_EQ_INT(w.calls, 1);
  /* the late reply is discarded; the session stays usable */
  waiter_reset(&w, W_STAT);
  o.timeout_ms = 3000;
  SD_REQUIRE(sd_sftp_stat(x->s, "/fast", &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 3000));
  SD_CHECK_EQ_INT(w.err, SD_OK);
  SD_CHECK_EQ_U64(w.attrs.size, 7);
  SD_CHECK_EQ_INT(sd_sftp_session_state(x->s), SD_SFTP_ST_READY);
  /* sync wrapper with its own deadline */
  {
    sd_sftp_attrs a;
    SD_CHECK_EQ_INT(sd_sftp_stat_sync(x->s, "/slow2", &a, 150), SD_E_TIMEOUT);
  }
  waiter_free(&w);
  fx_stop(x);
  sd_free(x);
}

SD_TEST(session_cancel)
{
  fx *x = fx_new();
  waiter w;
  sd_sftp_req *tok = NULL;
  sd_sftp_reqopt o = { 0, 10000, NULL };
  SD_REQUIRE(x != NULL);
  x->sv.hook = hold_stat_hook;
  SD_REQUIRE(fx_start(x, NULL));
  waiter_init(&w, x->s);
  waiter_reset(&w, W_STAT);
  o.token_out = &tok;
  SD_REQUIRE(sd_sftp_stat(x->s, "/slow", &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(tok != NULL);
  while (x->sv.nheld == 0) Sleep(1);
  SD_CHECK_EQ_INT(sd_sftp_cancel(tok), SD_OK);
  SD_REQUIRE(waiter_wait(&w, 3000));
  SD_CHECK_EQ_INT(w.err, SD_E_CANCELLED);
  SD_CHECK(w.maybe_executed);
  SD_CHECK_EQ_INT(sd_sftp_cancel(tok), SD_E_INVALID_PARAM);   /* already completed: harmless */
  waiter_reset(&w, W_STAT);
  o.token_out = NULL;
  SD_REQUIRE(sd_sftp_stat(x->s, "/fast", &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 3000));
  SD_CHECK_EQ_INT(w.err, SD_OK);
  SD_CHECK_EQ_INT(w.calls, 1);
  waiter_free(&w);
  fx_stop(x);
  sd_free(x);
}

SD_TEST(session_busy_backpressure)
{
  fx *x = fx_new();
  waiter w[5];
  sd_sftp_options opt;
  sd_sftp_reqopt o = { 0, 10000, NULL };
  int i;
  SD_REQUIRE(x != NULL);
  sd_sftp_options_init(&opt);
  opt.max_queued_reqs = 4;
  x->sv.hook = hold_stat_hook;
  SD_REQUIRE(fx_start(x, &opt));
  for (i = 0; i < 5; i++) { waiter_init(&w[i], x->s); waiter_reset(&w[i], W_STAT); }
  for (i = 0; i < 4; i++) SD_CHECK_EQ_INT(sd_sftp_stat(x->s, "/slow", &o, waiter_cb, &w[i]), SD_OK);
  SD_CHECK_EQ_INT(sd_sftp_stat(x->s, "/slow", &o, waiter_cb, &w[4]), SD_E_BUSY);
  while (x->sv.nheld < 4) Sleep(1);
  SD_CHECK_EQ_INT(sd_sftp_stat(x->s, "/fast", &o, waiter_cb, &w[4]), SD_E_BUSY);
  fake_run(x->sv.f, flush_held_attrs, &x->sv);
  for (i = 0; i < 4; i++) {
    SD_REQUIRE(waiter_wait(&w[i], 3000));
    SD_CHECK_EQ_INT(w[i].err, SD_OK);
  }
  SD_CHECK_EQ_INT(w[4].calls, 0);
  for (i = 0; i < 5; i++) waiter_free(&w[i]);
  fx_stop(x);
  sd_free(x);
}

/* ---- error refinement ---- */

static int refine_hook(srv *sv, uint8_t type, uint32_t id, sd_rd *rd)
{
  sd_span p = { NULL, 0 };
  if (type == SFTP_MKDIR || type == SFTP_RMDIR || type == SFTP_REMOVE || type == SFTP_LSTAT || type == SFTP_OPENDIR ||
      type == SFTP_OPEN || type == SFTP_RENAME)
    p = sd_rd_string(rd, 4096);
  switch (type) {
  case SFTP_MKDIR: case SFTP_RMDIR: case SFTP_REMOVE: case SFTP_RENAME:
    pk_status(sv->f, id, SFTP_FX_FAILURE, "Failure");
    return 1;
  case SFTP_OPEN:
    pk_status(sv->f, id, SFTP_FX_FAILURE, "Failure");
    return 1;
  case SFTP_LSTAT:
    InterlockedIncrement(&sv->probes);
    span_to(sv->s1, sizeof(sv->s1), p);
    if (strcmp(sv->s1, "/missing") == 0) pk_status(sv->f, id, SFTP_FX_NO_SUCH_FILE, "No such file");
    else if (strncmp(sv->s1, "/file", 5) == 0) reply_attrs(sv, id, 0100644, 1);
    else reply_attrs(sv, id, 040755, 4096);
    return 1;
  case SFTP_OPENDIR:
    pk_handle(sv->f, id, "probe-h");
    return 1;
  case SFTP_READDIR: {
    sd_wr w;
    sv->u[1]++;
    if (strcmp(sv->s1, "/empty") == 0 && sv->u[1] > 1) { pk_status(sv->f, id, SFTP_FX_EOF, ""); return 1; }
    pk_begin(&w, SFTP_NAME, id);
    if (sv->u[1] == 1) {
      sd_wr_u32(&w, 2);
      sd_wr_cstring(&w, "."); sd_wr_cstring(&w, ""); sd_wr_u32(&w, 0);
      sd_wr_cstring(&w, ".."); sd_wr_cstring(&w, ""); sd_wr_u32(&w, 0);
    } else {
      sd_wr_u32(&w, 1);
      sd_wr_cstring(&w, "child"); sd_wr_cstring(&w, ""); sd_wr_u32(&w, 0);
    }
    fake_reply_wr(sv->f, &w);
    return 1;
  }
  case SFTP_CLOSE:
    sv->u[2]++;
    pk_status(sv->f, id, 0, "");
    return 1;
  default:
    return 0;
  }
}

static sd_err do_path_op(fx *x, int op, const char *p, const char *p2, uint32_t flags, uint32_t reqflags, waiter *w)
{
  sd_sftp_reqopt o = { 0, 5000, NULL };
  sd_err e;
  o.flags = reqflags;
  waiter_reset(w, op == 4 ? W_OPEN : W_STAT);
  switch (op) {
  case 0: e = sd_sftp_mkdir(x->s, p, NULL, &o, waiter_cb, w); break;
  case 1: e = sd_sftp_rmdir(x->s, p, &o, waiter_cb, w); break;
  case 2: e = sd_sftp_remove(x->s, p, &o, waiter_cb, w); break;
  case 3: e = sd_sftp_rename(x->s, p, p2, flags, &o, waiter_cb, w); break;
  case 4: e = sd_sftp_open(x->s, p, flags, NULL, NULL, &o, waiter_cb, w); break;
  default: e = SD_E_INTERNAL;
  }
  if (e != SD_OK) return e;
  if (!waiter_wait(w, 5000)) return SD_E_INTERNAL;
  return w->err;
}

SD_TEST(session_refine_errors)
{
  fx *x = fx_new();
  waiter w;
  SD_REQUIRE(x != NULL);
  x->sv.hook = refine_hook;
  SD_REQUIRE(fx_start(x, NULL));
  waiter_init(&w, x->s);

  SD_CHECK_EQ_INT(do_path_op(x, 0, "/dir", NULL, 0, 0, &w), SD_E_EXISTS);     /* mkdir: LSTAT finds it */
  SD_CHECK_EQ_U64(w.sftp_status, SFTP_FX_FAILURE);
  SD_CHECK_STR(w.msg, "Failure");
  SD_CHECK_EQ_INT(do_path_op(x, 0, "/missing", NULL, 0, 0, &w), SD_E_FAILURE);
  SD_CHECK_EQ_INT(do_path_op(x, 0, "/dir", NULL, 0, SD_SFTP_REQ_NO_REFINE, &w), SD_E_FAILURE);

  x->sv.u[1] = 0; x->sv.u[2] = 0;
  SD_CHECK_EQ_INT(do_path_op(x, 1, "/full", NULL, 0, 0, &w), SD_E_NOT_EMPTY);   /* rmdir: OPENDIR+READDIR */
  SD_CHECK_EQ_U64(x->sv.u[1], 2);       /* "." / ".." batch, then the child */
  SD_CHECK_EQ_U64(x->sv.u[2], 1);       /* probe handle closed */
  x->sv.u[1] = 0; x->sv.u[2] = 0;
  SD_CHECK_EQ_INT(do_path_op(x, 1, "/empty", NULL, 0, 0, &w), SD_E_FAILURE);
  SD_CHECK_EQ_U64(x->sv.u[2], 1);
  SD_CHECK_EQ_INT(do_path_op(x, 1, "/file1", NULL, 0, 0, &w), SD_E_NOT_A_DIRECTORY);

  SD_CHECK_EQ_INT(do_path_op(x, 2, "/dir", NULL, 0, 0, &w), SD_E_IS_A_DIRECTORY);  /* remove a directory */
  SD_CHECK_EQ_INT(do_path_op(x, 2, "/file1", NULL, 0, 0, &w), SD_E_FAILURE);

  SD_CHECK_EQ_INT(do_path_op(x, 3, "/a", "/file2", 0, 0, &w), SD_E_EXISTS);   /* rename onto existing */
  SD_CHECK_EQ_INT(do_path_op(x, 4, "/file3", NULL, SD_SFTP_O_WRITE | SD_SFTP_O_CREAT | SD_SFTP_O_EXCL, 0, &w),
                  SD_E_EXISTS);
  SD_CHECK_EQ_INT(do_path_op(x, 4, "/file3", NULL, SD_SFTP_O_WRITE | SD_SFTP_O_CREAT, 0, &w), SD_E_FAILURE);
  SD_CHECK_STR(x->sv.s1, "/file3");      /* last probe target */
  waiter_free(&w);
  fx_stop(x);
  sd_free(x);
}

/* ---- readdir filtering (TM-R12) ---- */

static int dir_hook(srv *sv, uint8_t type, uint32_t id, sd_rd *rd)
{
  if (type == SFTP_OPENDIR) { pk_handle(sv->f, id, "dh"); return 1; }
  if (type == SFTP_CLOSE) { pk_status(sv->f, id, 0, ""); return 1; }
  if (type == SFTP_READDIR) {
    sd_wr w;
    SD_UNUSED(rd);
    if (sv->u[3]++ > 0) { pk_status(sv->f, id, SFTP_FX_EOF, "End of file"); return 1; }
    pk_begin(&w, SFTP_NAME, id);
    sd_wr_u32(&w, 6);
    sd_wr_cstring(&w, "."); sd_wr_cstring(&w, "drwxr-xr-x . "); sd_wr_u32(&w, 0);
    sd_wr_cstring(&w, ".."); sd_wr_cstring(&w, ""); sd_wr_u32(&w, 0);
    sd_wr_cstring(&w, ""); sd_wr_cstring(&w, ""); sd_wr_u32(&w, 0);
    sd_wr_cstring(&w, "a/b"); sd_wr_cstring(&w, ""); sd_wr_u32(&w, 0);
    sd_wr_cstring(&w, "ok1"); sd_wr_cstring(&w, "-rw-r--r-- 1 u u 5 ok1\x1b[31m"); pk_attrs_body(&w, 0100644, 5);
    sd_wr_cstring(&w, "\xC3\xA9t\xFF"); sd_wr_cstring(&w, ""); /* raw bytes, invalid UTF-8 kept */
    sd_wr_u32(&w, 0x80000000u); sd_wr_u32(&w, 1); sd_wr_cstring(&w, "x@y"); sd_wr_cstring(&w, "v");
    fake_reply_wr(sv->f, &w);
    return 1;
  }
  return 0;
}

static void dir_capture(waiter *w, const sd_sftp_completion *c)
{
  if (c->u.readdir.count == 2) {
    w->sftp_status = c->u.readdir.ents[0].attrs.valid;
    w->bytes = (uint32_t)c->u.readdir.ents[0].attrs.size;
    w->maybe_executed = (int)c->u.readdir.ents[1].attrs.ext_count;
    w->path_len = c->u.readdir.ents[0].longname_len;
    memcpy(w->path, c->u.readdir.ents[0].longname, w->path_len);
    w->path[w->path_len] = 0;
  }
}

SD_TEST(session_readdir_filters_entries)
{
  fx *x = fx_new();
  waiter w;
  sd_sftp_reqopt o = { 0, 5000, NULL };
  sd_sftp_file *d;
  SD_REQUIRE(x != NULL);
  x->sv.hook = dir_hook;
  SD_REQUIRE(fx_start(x, NULL));
  waiter_init(&w, x->s);
  waiter_reset(&w, W_OPEN);
  SD_REQUIRE(sd_sftp_opendir(x->s, "/d", &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000) && w.err == SD_OK && w.file);
  d = w.file;
  waiter_reset(&w, W_DIR);
  w.dir_cb = dir_capture;
  SD_REQUIRE(sd_sftp_readdir(d, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_OK);
  SD_CHECK_EQ_U64(w.count, 2);
  SD_CHECK_EQ_U64(w.dropped, 2);        /* "" and "a/b"; "." and ".." silently */
  SD_CHECK_STR(w.names[0], "ok1");
  SD_CHECK_STR(w.names[1], "\xC3\xA9t\xFF");
  SD_CHECK_EQ_U64(w.sftp_status, 0xF);
  SD_CHECK_EQ_U64(w.bytes, 5);
  SD_CHECK_EQ_INT(w.maybe_executed, 1); /* extended pair passed through */
  SD_CHECK_STR(w.path, "-rw-r--r-- 1 u u 5 ok1[31m");   /* ESC removed by sanitizing */
  SD_CHECK(!w.eof);
  waiter_reset(&w, W_DIR);
  w.dir_cb = NULL;
  SD_REQUIRE(sd_sftp_readdir(d, &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_OK);
  SD_CHECK(w.eof && w.count == 0);
  /* readdir on a closed handle: the handle reference was handed over by close */
  sd_sftp_file_addref(d);
  SD_CHECK_EQ_INT(sd_sftp_close_sync(d, 5000), SD_OK);
  SD_CHECK_EQ_INT(sd_sftp_readdir(d, &o, waiter_cb, &w), SD_E_INVALID_PARAM);
  sd_sftp_file_release(d);
  waiter_free(&w);
  fx_stop(x);
  sd_free(x);
}

/* ---- symlink argument order ---- */

static int symlink_hook(srv *sv, uint8_t type, uint32_t id, sd_rd *rd)
{
  if (type == SFTP_SYMLINK) {
    span_to(sv->s1, sizeof(sv->s1), sd_rd_string(rd, 4096));
    span_to(sv->s2, sizeof(sv->s2), sd_rd_string(rd, 4096));
    pk_status(sv->f, id, 0, "");
    return 1;
  }
  return 0;
}

static void symlink_case(sd_test_ctx *sd_t_, uint32_t flags, int minimal, const char *first)
{
  fx *x = fx_new();
  sd_sftp_options opt;
  waiter w;
  sd_sftp_reqopt o = { 0, 5000, NULL };
  SD_REQUIRE(x != NULL);
  sd_sftp_options_init(&opt);
  opt.flags |= flags;
  x->sv.minimal = minimal;
  x->sv.hook = symlink_hook;
  SD_REQUIRE(fx_start(x, &opt));
  waiter_init(&w, x->s);
  waiter_reset(&w, W_STAT);
  SD_REQUIRE(sd_sftp_symlink(x->s, "/link", "/target", &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_OK);
  SD_CHECK_STR(x->sv.s1, first);
  waiter_free(&w);
  fx_stop(x);
  sd_free(x);
}

SD_TEST(session_symlink_argument_order)
{
  symlink_case(sd_t_, 0, 0, "/target");                                 /* OpenSSH detected */
  symlink_case(sd_t_, 0, 1, "/link");                                   /* draft order */
  symlink_case(sd_t_, SD_SFTP_OPT_SYMLINK_ORDER_DRAFT, 0, "/link");
  symlink_case(sd_t_, SD_SFTP_OPT_SYMLINK_ORDER_OPENSSH, 1, "/target");
}

/* ---- protocol errors and connection loss ---- */

static int bad_id_hook(srv *sv, uint8_t type, uint32_t id, sd_rd *rd)
{
  if (type == SFTP_STAT) {
    sd_span p = sd_rd_string(rd, 4096);
    if (p.n == 2 && memcmp(p.p, "/x", 2) == 0) { reply_attrs(sv, id + 1000, 0100644, 1); return 1; }
    return 0;
  }
  if (type == SFTP_LSTAT) { InterlockedIncrement(&sv->probes); return 1; }   /* swallowed */
  return 0;
}

SD_TEST(session_protocol_error_fails_session)
{
  fx *x = fx_new();
  waiter w, w2;
  sd_sftp_reqopt o = { 0, 5000, NULL };
  SD_REQUIRE(x != NULL);
  x->sv.hook = bad_id_hook;
  SD_REQUIRE(fx_start(x, NULL));
  waiter_init(&w, x->s);
  waiter_init(&w2, x->s);
  waiter_reset(&w, W_STAT);
  waiter_reset(&w2, W_STAT);
  SD_REQUIRE(sd_sftp_lstat(x->s, "/pending", &o, waiter_cb, &w2) == SD_OK);
  while (x->sv.probes == 0) Sleep(1);
  SD_REQUIRE(sd_sftp_stat(x->s, "/x", &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_REQUIRE(waiter_wait(&w2, 5000));
  SD_CHECK_EQ_INT(w.err, SD_E_DISCONNECTED);
  SD_CHECK_EQ_INT(w2.err, SD_E_DISCONNECTED);
  SD_CHECK(w2.maybe_executed);
  SD_REQUIRE(sd_event_wait(&x->ev.ended, 5000) == SD_OK);
  SD_CHECK(evlog_has(&x->ev, SD_SFTP_ST_DISCONNECTED));
  SD_CHECK(evlog_has(&x->ev, SD_SFTP_ST_FAILED));
  SD_CHECK_EQ_INT(sd_sftp_stat(x->s, "/y", &o, waiter_cb, &w), SD_E_DISCONNECTED);
  waiter_free(&w);
  waiter_free(&w2);
  fx_stop(x);
  SD_CHECK(evlog_has(&x->ev, SD_SFTP_ST_CLOSED));
  sd_free(x);
}

SD_TEST(session_hangup_marks_handles_stale)
{
  fx *x = fx_new();
  waiter w;
  sd_sftp_reqopt o = { 0, 5000, NULL };
  sd_sftp_file *f;
  sd_sftp_file_info fi;
  uint8_t b[8];
  SD_REQUIRE(x != NULL);
  x->sv.hook = open_hook;
  SD_REQUIRE(fx_start(x, NULL));
  f = open_file(x, "/f", SD_SFTP_O_READ);
  SD_REQUIRE(f != NULL);
  SD_CHECK(sd_sftp_file_get_info(f, &fi) == SD_OK && !fi.stale && fi.generation == 1 && strcmp(fi.path, "/f") == 0);
  fake_hangup(x->sv.f);
  SD_REQUIRE(sd_event_wait(&x->ev.ended, 5000) == SD_OK);
  SD_CHECK(sd_sftp_file_get_info(f, &fi) == SD_OK && fi.stale);
  waiter_init(&w, x->s);
  SD_CHECK_EQ_INT(sd_sftp_read(f, 0, b, sizeof(b), &o, waiter_cb, &w), SD_E_STALE_HANDLE);
  waiter_reset(&w, W_STAT);
  SD_CHECK_EQ_INT(sd_sftp_close(f, &o, waiter_cb, &w), SD_OK);      /* close of a stale handle: local success */
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_OK);
  waiter_free(&w);
  fx_stop(x);
  sd_free(x);
}

SD_TEST(session_close_completes_pending_with_shutdown)
{
  fx *x = fx_new();
  waiter w;
  sd_sftp_reqopt o = { 0, 10000, NULL };
  SD_REQUIRE(x != NULL);
  x->sv.hook = hold_stat_hook;
  SD_REQUIRE(fx_start(x, NULL));
  waiter_init(&w, x->s);
  waiter_reset(&w, W_STAT);
  SD_REQUIRE(sd_sftp_stat(x->s, "/slow", &o, waiter_cb, &w) == SD_OK);
  while (x->sv.nheld == 0) Sleep(1);
  SD_CHECK_EQ_INT(sd_sftp_session_close(x->s), SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_E_SHUTDOWN);
  SD_REQUIRE(sd_event_wait(&x->ev.ended, 5000) == SD_OK);
  SD_CHECK_EQ_INT(sd_sftp_session_state(x->s), SD_SFTP_ST_CLOSED);
  SD_CHECK_EQ_INT(sd_sftp_stat(x->s, "/x", &o, waiter_cb, &w), SD_E_SHUTDOWN);
  waiter_free(&w);
  fx_stop(x);
  sd_free(x);
}

SD_TEST(session_wait_ready_queues_before_start)
{
  fx *x = fx_new();
  sd_sftp_transport t;
  waiter w, w2;
  sd_sftp_reqopt o = { SD_SFTP_REQ_WAIT_READY, 5000, NULL };
  sd_sftp_reqopt plain = { 0, 5000, NULL };
  SD_REQUIRE(x != NULL);
  evlog_init(&x->ev);
  x->sv.f = fake_new(srv_handler, &x->sv);
  SD_REQUIRE(x->sv.f != NULL);
  fake_transport(x->sv.f, &t);
  SD_REQUIRE(sd_sftp_session_create_transport(&t, NULL, evlog_cb, &x->ev, &x->s) == SD_OK);
  waiter_init(&w, x->s);
  waiter_init(&w2, x->s);
  waiter_reset(&w, W_NAME);
  SD_CHECK_EQ_INT(sd_sftp_realpath(x->s, ".", &plain, waiter_cb, &w2), SD_E_DISCONNECTED);
  SD_REQUIRE(sd_sftp_realpath(x->s, ".", &o, waiter_cb, &w) == SD_OK);
  SD_REQUIRE(sd_sftp_session_start(x->s) == SD_OK);
  SD_REQUIRE(waiter_wait(&w, 5000));
  SD_CHECK_EQ_INT(w.err, SD_OK);
  SD_CHECK_STR(w.path, "/home/u");
  {
    char buf[64];
    SD_CHECK_EQ_INT(sd_sftp_realpath_sync(x->s, ".", buf, sizeof(buf), 5000), SD_OK);
    SD_CHECK_STR(buf, "/home/u");
    SD_CHECK_EQ_INT(sd_sftp_realpath_sync(x->s, ".", buf, 4, 5000), SD_E_NAME_TOO_LONG);
  }
  waiter_free(&w);
  waiter_free(&w2);
  fx_stop(x);
  sd_free(x);
}
