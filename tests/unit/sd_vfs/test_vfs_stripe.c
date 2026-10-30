/* Striping policy of the vfs side (02 §5.6): when sd_vfs opts a data handle into striping with
 * SD_SFTP_O_STRIPED against the in-memory fake sd_sftp. The fake reports a pool of `connections`
 * members (cfg.connections); fake_striped_opens counts the OPENs executed with the flag.
 *
 * Covered: the size threshold (file >= stripe_min_file, 8 MiB default, on sequential reads), the
 * sequential-write threshold (a write call >= 1 MiB stripes the handle, smaller sequential writes
 * only once the file is past the size threshold), the pool gate (connections = 1 never stripes) and
 * the exclusions (RANDOM_ACCESS handles, append-only access and writes at SD_VFS_EOF, directories,
 * which have no data handle at all). */
#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "fake_sftp.h"
#include "sd_base/sd_mem.h"
#include "sd_test.h"
#include "sd_vfs/sd_vfs.h"

typedef struct ev_log { LONG notices; } ev_log;

static void on_event(void *ctx, const sd_vfs_event *ev)
{
  ev_log *l = (ev_log *)ctx;
  if (ev->kind == SD_VFS_EV_NOTICE) InterlockedIncrement(&l->notices);
}

typedef struct fixture { sd_sftp_session *s; sd_vfs *v; sd_vfs_options o; ev_log ev; } fixture;

static void default_opts(sd_vfs_options *o)
{
  memset(o, 0, sizeof(*o));
  o->struct_size = sizeof(*o);
  o->hide_dotfiles = TRUE;
  o->map_readonly = TRUE;
  o->allow_system = TRUE;
  o->symlinks = SD_SYMLINK_FOLLOW_INSIDE;
  o->write_mode = SD_VFS_WRITE_THROUGH;
  o->request_timeout_ms = 10000;
}

static int fx_mount(fixture *f, uint32_t connections)
{
  fake_config cfg;
  memset(f, 0, sizeof(*f));
  memset(&cfg, 0, sizeof(cfg));
  cfg.connections = connections;
  f->s = fake_session_create(&cfg);
  default_opts(&f->o);
  return sd_vfs_mount(f->s, &f->o, on_event, &f->ev, &f->v) == SD_VFS_OK;
}

static void fx_done(fixture *f)
{
  if (f->v) {
    sd_vfs_quiesce(f->v, 1000);
    sd_vfs_unmount(f->v);
  }
  fake_session_destroy(f->s);
}

static sd_vfs_status vopen(fixture *f, const WCHAR *p, UINT32 access, UINT32 share, UINT32 disp, UINT32 opts,
                           sd_vfs_handle **h)
{
  BOOL existed, dir;
  return sd_vfs_create(f->v, p, NULL, access, share, disp, opts, 0, h, &existed, &dir);
}

static void vclose(sd_vfs_handle *h, BOOL del)
{
  sd_vfs_cleanup(h, del);
  sd_vfs_close(h);
}

#define SHARE_ALL (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
#define MIB (1024u * 1024u)

static BOOL readdir_true(void *ctx, const WCHAR *name, const sd_vfs_info *info)
{
  SD_UNUSED(info);
  *(BOOL *)ctx = name != NULL;
  return TRUE;
}

/* A size-lifting pattern so no block deduplicates anywhere. */
static void fill_pattern(uint8_t *p, uint32_t len, uint32_t seed)
{
  uint32_t i;
  for (i = 0; i < len; i++) p[i] = (uint8_t)(i * 31u + seed);
}

/* A 9 MiB file read sequentially through a SEQUENTIAL_ONLY handle stripes. */
SD_TEST(vfs_striping_size_threshold)
{
  fixture f;
  sd_vfs_handle *h = NULL;
  static uint8_t big[9 * MIB], buf[64 * 1024];
  uint32_t got = 0;
  fill_pattern(big, sizeof(big), 1);
  SD_REQUIRE(fx_mount(&f, 3));
  SD_REQUIRE(fake_put(f.s, "/home/user/big", big, sizeof(big), 0644) == 0);
  SD_REQUIRE(vopen(&f, L"\\big", GENERIC_READ, SHARE_ALL, SD_VFS_FILE_OPEN_IF,
                   SD_VFS_FILE_SEQUENTIAL_ONLY, &h) == SD_VFS_OK);
  SD_CHECK_EQ_INT(sd_vfs_read(h, 0, buf, sizeof(buf), &got), SD_VFS_OK);
  SD_CHECK_EQ_INT(got, sizeof(buf));
  SD_CHECK(fake_striped_opens(f.s) >= 1);
  vclose(h, FALSE);
  fx_done(&f);

  /* Just under the threshold: the same access pattern stays on the primary. */
  SD_REQUIRE(fx_mount(&f, 3));
  SD_REQUIRE(fake_put(f.s, "/home/user/mid", big, 7 * MIB, 0644) == 0);
  SD_REQUIRE(vopen(&f, L"\\mid", GENERIC_READ, SHARE_ALL, SD_VFS_FILE_OPEN_IF,
                   SD_VFS_FILE_SEQUENTIAL_ONLY, &h) == SD_VFS_OK);
  SD_CHECK_EQ_INT(sd_vfs_read(h, 0, buf, sizeof(buf), &got), SD_VFS_OK);
  SD_CHECK_EQ_INT(fake_striped_opens(f.s), 0);
  vclose(h, FALSE);
  fx_done(&f);

  /* Random access never stripes, whatever the size. */
  SD_REQUIRE(fx_mount(&f, 3));
  SD_REQUIRE(fake_put(f.s, "/home/user/big", big, sizeof(big), 0644) == 0);
  SD_REQUIRE(vopen(&f, L"\\big", GENERIC_READ, SHARE_ALL, SD_VFS_FILE_OPEN_IF,
                   SD_VFS_FILE_RANDOM_ACCESS, &h) == SD_VFS_OK);
  SD_CHECK_EQ_INT(sd_vfs_read(h, 0, buf, sizeof(buf), &got), SD_VFS_OK);
  SD_CHECK_EQ_INT(fake_striped_opens(f.s), 0);
  vclose(h, FALSE);
  fx_done(&f);
}

/* A sequential write call of 1 MiB or more stripes the handle at once; smaller sequential writes
   only once the file has grown past the size threshold. */
SD_TEST(vfs_striping_sequential_write_threshold)
{
  fixture f;
  sd_vfs_handle *h = NULL;
  static uint8_t one[MIB], chunk[256 * 1024];
  uint32_t done = 0, i;
  fill_pattern(one, sizeof(one), 2);
  fill_pattern(chunk, sizeof(chunk), 3);
  SD_REQUIRE(fx_mount(&f, 3));
  SD_REQUIRE(vopen(&f, L"\\new", GENERIC_WRITE, SHARE_ALL, SD_VFS_FILE_CREATE, 0, &h) == SD_VFS_OK);
  SD_CHECK_EQ_INT(sd_vfs_write(h, 0, one, sizeof(one), &done, FALSE), SD_VFS_OK);
  SD_CHECK_EQ_INT(done, sizeof(one));
  SD_CHECK(fake_striped_opens(f.s) >= 1);
  /* The handle is striped now; further writes reuse it without another striped open. */
  SD_CHECK_EQ_INT(sd_vfs_write(h, sizeof(one), one, sizeof(one), &done, FALSE), SD_VFS_OK);
  SD_CHECK_EQ_INT(fake_striped_opens(f.s), 1);
  vclose(h, FALSE);
  fx_done(&f);

  /* A stream of sequential 256 KiB writes only qualifies once the file passes 8 MiB: 32 of them
     reach exactly 8 MiB, and every write below saw a file under the threshold. The next one is
     the first sequential write on a file of 8 MiB and upgrades the handle. */
  SD_REQUIRE(fx_mount(&f, 3));
  SD_REQUIRE(vopen(&f, L"\\grow", GENERIC_WRITE, SHARE_ALL, SD_VFS_FILE_CREATE, 0, &h) == SD_VFS_OK);
  for (i = 0; i < 32; i++)
    SD_CHECK_EQ_INT(sd_vfs_write(h, (UINT64)i * sizeof(chunk), chunk, sizeof(chunk), &done, FALSE),
                    SD_VFS_OK);
  SD_CHECK_EQ_INT(fake_striped_opens(f.s), 0);
  SD_CHECK_EQ_INT(sd_vfs_write(h, (UINT64)i * sizeof(chunk), chunk, sizeof(chunk), &done, FALSE),
                  SD_VFS_OK);
  SD_CHECK(fake_striped_opens(f.s) >= 1);
  vclose(h, FALSE);
  fx_done(&f);

  /* One 1 MiB sequential write qualifies immediately, small random writes never do. */
  SD_REQUIRE(fx_mount(&f, 3));
  SD_REQUIRE(vopen(&f, L"\\rand", GENERIC_WRITE, SHARE_ALL, SD_VFS_FILE_CREATE, 0, &h) == SD_VFS_OK);
  SD_CHECK_EQ_INT(sd_vfs_write(h, 0, one, sizeof(one), &done, FALSE), SD_VFS_OK);
  SD_CHECK(fake_striped_opens(f.s) >= 1);
  vclose(h, FALSE);
  fx_done(&f);

  SD_REQUIRE(fx_mount(&f, 3));
  SD_REQUIRE(vopen(&f, L"\\rand", GENERIC_WRITE, SHARE_ALL, SD_VFS_FILE_CREATE, 0, &h) == SD_VFS_OK);
  for (i = 0; i < 4; i++)
    SD_CHECK_EQ_INT(sd_vfs_write(h, 3 * MIB + (UINT64)i * sizeof(chunk), chunk, sizeof(chunk), &done,
                                 FALSE), SD_VFS_OK);
  SD_CHECK_EQ_INT(fake_striped_opens(f.s), 0);
  vclose(h, FALSE);
  fx_done(&f);
}

/* Write-behind: the deferred kick sends the qualified stream striped (the trigger was evaluated
   when the writes were queued). */
SD_TEST(vfs_striping_write_behind_kick)
{
  fixture f;
  sd_vfs_handle *h = NULL;
  static uint8_t chunk[256 * 1024];
  uint32_t done = 0, i;
  fill_pattern(chunk, sizeof(chunk), 4);
  SD_REQUIRE(fx_mount(&f, 3));
  f.o.write_mode = SD_VFS_WRITE_BEHIND;
  SD_REQUIRE(vopen(&f, L"\\wb", GENERIC_WRITE, SHARE_ALL, SD_VFS_FILE_CREATE, 0, &h) == SD_VFS_OK);
  for (i = 0; i < 40; i++)
    SD_CHECK_EQ_INT(sd_vfs_write(h, (UINT64)i * sizeof(chunk), chunk, sizeof(chunk), &done, FALSE),
                    SD_VFS_OK);
  SD_CHECK_EQ_INT(sd_vfs_flush(h), SD_VFS_OK);
  SD_CHECK(fake_striped_opens(f.s) >= 1);
  vclose(h, FALSE);
  fx_done(&f);
}

/* The pool gate: connections = 1 never stripes, whatever the size or write pattern. */
SD_TEST(vfs_striping_needs_more_than_the_primary)
{
  fixture f;
  sd_vfs_handle *h = NULL;
  static uint8_t big[9 * MIB], one[MIB];
  uint32_t got = 0, done = 0;
  fill_pattern(big, sizeof(big), 5);
  fill_pattern(one, sizeof(one), 6);
  SD_REQUIRE(fx_mount(&f, 1));
  SD_REQUIRE(fake_put(f.s, "/home/user/big", big, sizeof(big), 0644) == 0);
  SD_REQUIRE(vopen(&f, L"\\big", GENERIC_READ, SHARE_ALL, SD_VFS_FILE_OPEN_IF,
                   SD_VFS_FILE_SEQUENTIAL_ONLY, &h) == SD_VFS_OK);
  SD_CHECK_EQ_INT(sd_vfs_read(h, 0, big, sizeof(big), &got), SD_VFS_OK);
  SD_CHECK_EQ_INT(fake_striped_opens(f.s), 0);
  vclose(h, FALSE);
  SD_REQUIRE(vopen(&f, L"\\w", GENERIC_WRITE, SHARE_ALL, SD_VFS_FILE_CREATE, 0, &h) == SD_VFS_OK);
  SD_CHECK_EQ_INT(sd_vfs_write(h, 0, one, sizeof(one), &done, FALSE), SD_VFS_OK);
  SD_CHECK_EQ_INT(fake_striped_opens(f.s), 0);
  vclose(h, FALSE);
  fx_done(&f);
}

/* APPEND and directories never stripe: append-only handles and SD_VFS_EOF writes are not
   sequential, and directories have no data handle at all. */
SD_TEST(vfs_striping_append_and_directory_excluded)
{
  fixture f;
  sd_vfs_handle *h = NULL;
  static uint8_t one[MIB];
  uint32_t done = 0;
  fill_pattern(one, sizeof(one), 7);
  SD_REQUIRE(fx_mount(&f, 3));
  SD_REQUIRE(fake_put(f.s, "/home/user/f", "data", 4, 0644) == 0);
  fake_mkdir(f.s, "/home/user/d", 0755);
  /* Append-only access: even a 1 MiB write stays unstriped. */
  SD_REQUIRE(vopen(&f, L"\\f", FILE_APPEND_DATA, SHARE_ALL, SD_VFS_FILE_OPEN_IF, 0, &h) == SD_VFS_OK);
  SD_CHECK_EQ_INT(sd_vfs_write(h, SD_VFS_EOF, one, sizeof(one), &done, FALSE), SD_VFS_OK);
  SD_CHECK_EQ_INT(done, sizeof(one));
  SD_CHECK(fake_count(f.s, FOP_WRITE) >= 1);
  SD_CHECK_EQ_INT(fake_striped_opens(f.s), 0);
  vclose(h, FALSE);
  /* An explicit offset on an append-only handle is the same access class. */
  SD_REQUIRE(vopen(&f, L"\\f", FILE_APPEND_DATA, SHARE_ALL, SD_VFS_FILE_OPEN_IF, 0, &h) == SD_VFS_OK);
  SD_CHECK_EQ_INT(sd_vfs_write(h, 0, one, sizeof(one), &done, FALSE), SD_VFS_OK);
  SD_CHECK_EQ_INT(fake_striped_opens(f.s), 0);
  vclose(h, FALSE);
  /* Directories: opendir/readdir only, no data OPEN at all (counters start clean). */
  fake_reset_counts(f.s);
  SD_REQUIRE(vopen(&f, L"\\d", GENERIC_READ, SHARE_ALL, SD_VFS_FILE_OPEN_IF,
                   SD_VFS_FILE_DIRECTORY_FILE, &h) == SD_VFS_OK);
  {
    BOOL seen = FALSE;
    SD_CHECK_EQ_INT(sd_vfs_readdir(h, readdir_true, &seen), SD_VFS_OK);
  }
  SD_CHECK(fake_count(f.s, FOP_OPENDIR) >= 1);
  SD_CHECK_EQ_INT(fake_count(f.s, FOP_OPEN), 0);
  SD_CHECK_EQ_INT(fake_striped_opens(f.s), 0);
  vclose(h, FALSE);
  fx_done(&f);
}
