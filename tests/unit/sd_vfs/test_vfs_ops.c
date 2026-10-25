/* sd_vfs operations against the in-memory fake sd_sftp. */
#include <windows.h>
#include <process.h>
#include <stdio.h>
#include <string.h>

#include "fake_sftp.h"
#include "sd_base/sd_mem.h"
#include "sd_test.h"
#include "sd_vfs/sd_vfs.h"

typedef struct ev_log { LONG notices, delete_failed, identity; char last_code[64]; } ev_log;

static void on_event(void *ctx, const sd_vfs_event *ev)
{
  ev_log *l = (ev_log *)ctx;
  if (ev->kind == SD_VFS_EV_NOTICE) {
    InterlockedIncrement(&l->notices);
    if (ev->code) strncpy_s(l->last_code, sizeof(l->last_code), ev->code, _TRUNCATE);
  } else if (ev->kind == SD_VFS_EV_DELETE_FAILED) {
    InterlockedIncrement(&l->delete_failed);
  } else if (ev->kind == SD_VFS_EV_IDENTITY) {
    InterlockedIncrement(&l->identity);
  }
}

typedef struct fixture { sd_sftp_session *s; sd_vfs *v; sd_vfs_options o; ev_log ev; } fixture;

static void default_opts(sd_vfs_options *o)
{
  memset(o, 0, sizeof(*o));
  o->struct_size = sizeof(*o);
  o->hide_dotfiles = TRUE;
  o->map_readonly = TRUE;
  o->allow_system = TRUE;
  o->fsync_on_flush = TRUE;
  o->symlinks = SD_SYMLINK_FOLLOW_INSIDE;
  o->write_mode = SD_VFS_WRITE_THROUGH;
  o->request_timeout_ms = 10000;
}

static int fx_mount(fixture *f, const fake_config *cfg, const sd_vfs_options *o)
{
  memset(f, 0, sizeof(*f));
  f->s = fake_session_create(cfg);
  if (o) f->o = *o; else default_opts(&f->o);
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

typedef struct list_ctx { WCHAR names[64][64]; sd_vfs_info info[64]; int n; } list_ctx;

static BOOL collect(void *ctx, const WCHAR *name, const sd_vfs_info *info)
{
  list_ctx *l = (list_ctx *)ctx;
  if (l->n < 64) {
    wcsncpy_s(l->names[l->n], 64, name, _TRUNCATE);
    l->info[l->n] = *info;
    l->n++;
  }
  return TRUE;
}

static int list_find(const list_ctx *l, const WCHAR *name)
{
  int i;
  for (i = 0; i < l->n; i++)
    if (wcscmp(l->names[i], name) == 0) return i;
  return -1;
}

static sd_vfs_status vlist(fixture *f, const WCHAR *dir, list_ctx *l)
{
  sd_vfs_handle *h = NULL;
  sd_vfs_status st;
  memset(l, 0, sizeof(*l));
  st = vopen(f, dir, FILE_LIST_DIRECTORY, SHARE_ALL, SD_VFS_FILE_OPEN, SD_VFS_FILE_DIRECTORY_FILE, &h);
  if (st != SD_VFS_OK) return st;
  st = sd_vfs_readdir(h, collect, l);
  vclose(h, FALSE);
  return st;
}

SD_TEST(vfs_mount_rejects_later_milestones)
{
  sd_sftp_session *s = fake_session_create(NULL);
  sd_vfs_options o;
  sd_vfs *v = NULL;
  default_opts(&o);
  o.write_mode = SD_VFS_WRITE_BEHIND;
  SD_CHECK_EQ_INT(sd_vfs_mount(s, &o, NULL, NULL, &v), SD_VFS_E_UNSUPPORTED);
  default_opts(&o);
  o.global_mount = TRUE;
  SD_CHECK_EQ_INT(sd_vfs_mount(s, &o, NULL, NULL, &v), SD_VFS_E_UNSUPPORTED);
  default_opts(&o);
  o.remote_root = "/does/not/exist";
  SD_CHECK_EQ_INT(sd_vfs_mount(s, &o, NULL, NULL, &v), SD_VFS_E_NOT_FOUND);
  fake_session_destroy(s);
}

SD_TEST(vfs_create_write_read_roundtrip)
{
  fixture f;
  sd_vfs_handle *h = NULL;
  uint8_t *buf = (uint8_t *)sd_alloc(3u << 20), *back = (uint8_t *)sd_alloc(3u << 20);
  UINT32 done = 0, got = 0, i;
  BOOL existed = TRUE, dir = TRUE;
  sd_vfs_info info;
  SD_REQUIRE(buf && back);
  SD_REQUIRE(fx_mount(&f, NULL, NULL));
  for (i = 0; i < (3u << 20); i++) buf[i] = (uint8_t)(i * 7 + (i >> 9));
  SD_REQUIRE(sd_vfs_create(f.v, L"\\data.bin", NULL, GENERIC_READ | GENERIC_WRITE, 0, SD_VFS_FILE_CREATE,
                           SD_VFS_FILE_NON_DIRECTORY_FILE, FILE_ATTRIBUTE_NORMAL, &h, &existed, &dir) == SD_VFS_OK);
  SD_CHECK(!existed && !dir);
  SD_CHECK_EQ_INT(sd_vfs_write(h, 0, buf, 3u << 20, &done, FALSE), SD_VFS_OK);
  SD_CHECK_EQ_U64(done, 3u << 20);
  /* append via SD_VFS_EOF */
  SD_CHECK_EQ_INT(sd_vfs_write(h, SD_VFS_EOF, "tail", 4, &done, FALSE), SD_VFS_OK);
  SD_CHECK_EQ_INT(sd_vfs_getattr(h, &info), SD_VFS_OK);
  SD_CHECK_EQ_U64(info.size, (3u << 20) + 4);
  SD_CHECK_EQ_INT(sd_vfs_flush(h), SD_VFS_OK);
  SD_CHECK(fake_count(f.s, FOP_FSYNC) == 1);
  vclose(h, FALSE);
  SD_CHECK_EQ_U64(fake_get(f.s, "/home/user/data.bin", NULL, 0), (3u << 20) + 4);
  SD_CHECK(fake_open_handles(f.s) == 0);

  SD_REQUIRE(vopen(&f, L"\\DATA.BIN", GENERIC_READ, FILE_SHARE_READ, SD_VFS_FILE_OPEN, 0, &h) == SD_VFS_OK);
  SD_CHECK_EQ_INT(sd_vfs_read(h, 0, back, 3u << 20, &got), SD_VFS_OK);
  SD_CHECK_EQ_U64(got, 3u << 20);
  SD_CHECK_MEM(back, buf, 3u << 20);
  SD_CHECK_EQ_INT(sd_vfs_read(h, (3u << 20) + 2, back, 100, &got), SD_VFS_OK);   /* short read */
  SD_CHECK_EQ_U64(got, 2);
  SD_CHECK_EQ_INT(sd_vfs_read(h, (3u << 20) + 4, back, 100, &got), SD_VFS_E_END_OF_FILE);
  SD_CHECK_EQ_U64(got, 0);
  SD_CHECK_EQ_INT(sd_vfs_write(h, 0, buf, 10, &done, FALSE), SD_VFS_E_ACCESS_DENIED);   /* read-only handle */
  vclose(h, FALSE);
  sd_free(buf);
  sd_free(back);
  fx_done(&f);
}

SD_TEST(vfs_dispositions)
{
  fixture f;
  sd_vfs_handle *h = NULL;
  BOOL existed, dir;
  SD_REQUIRE(fx_mount(&f, NULL, NULL));
  fake_put(f.s, "/home/user/a.txt", "hello", 5, 0644);
  fake_mkdir(f.s, "/home/user/d", 0755);
  SD_CHECK_EQ_INT(vopen(&f, L"\\a.txt", GENERIC_READ, SHARE_ALL, SD_VFS_FILE_CREATE, 0, &h), SD_VFS_E_EXISTS);
  SD_CHECK_EQ_INT(vopen(&f, L"\\nope.txt", GENERIC_READ, SHARE_ALL, SD_VFS_FILE_OPEN, 0, &h), SD_VFS_E_NOT_FOUND);
  SD_CHECK_EQ_INT(vopen(&f, L"\\nodir\\x.txt", GENERIC_READ, SHARE_ALL, SD_VFS_FILE_OPEN, 0, &h),
                  SD_VFS_E_PATH_NOT_FOUND);
  SD_CHECK_EQ_INT(vopen(&f, L"\\a.txt\\x", GENERIC_READ, SHARE_ALL, SD_VFS_FILE_OPEN, 0, &h), SD_VFS_E_PATH_NOT_FOUND);
  SD_CHECK_EQ_INT(vopen(&f, L"\\d", GENERIC_READ, SHARE_ALL, SD_VFS_FILE_OPEN, SD_VFS_FILE_NON_DIRECTORY_FILE, &h),
                  SD_VFS_E_IS_DIR);
  SD_CHECK_EQ_INT(vopen(&f, L"\\a.txt", GENERIC_READ, SHARE_ALL, SD_VFS_FILE_OPEN, SD_VFS_FILE_DIRECTORY_FILE, &h),
                  SD_VFS_E_NOT_DIR);
  SD_CHECK_EQ_INT(vopen(&f, L"\\..\\x", GENERIC_READ, SHARE_ALL, SD_VFS_FILE_OPEN, 0, &h), SD_VFS_E_INVALID_NAME);
  SD_CHECK_EQ_INT(vopen(&f, L"\\a.txt:stream", GENERIC_READ, SHARE_ALL, SD_VFS_FILE_OPEN, 0, &h),
                  SD_VFS_E_INVALID_NAME);
  SD_REQUIRE(sd_vfs_create(f.v, L"\\a.txt", NULL, GENERIC_READ, SHARE_ALL, SD_VFS_FILE_OPEN_IF, 0, 0, &h, &existed,
                           &dir) == SD_VFS_OK);
  SD_CHECK(existed && !dir);
  vclose(h, FALSE);
  SD_REQUIRE(sd_vfs_create(f.v, L"\\a.txt", NULL, GENERIC_WRITE, SHARE_ALL, SD_VFS_FILE_OVERWRITE_IF, 0, 0, &h,
                           &existed, &dir) == SD_VFS_OK);
  SD_CHECK(existed);
  vclose(h, FALSE);
  SD_CHECK_EQ_INT(fake_get(f.s, "/home/user/a.txt", NULL, 0), 0);
  SD_REQUIRE(sd_vfs_create(f.v, L"\\d\\sub", NULL, FILE_LIST_DIRECTORY, SHARE_ALL, SD_VFS_FILE_CREATE,
                           SD_VFS_FILE_DIRECTORY_FILE, 0, &h, &existed, &dir) == SD_VFS_OK);
  SD_CHECK(dir && !existed);
  vclose(h, FALSE);
  SD_CHECK((fake_mode(f.s, "/home/user/d/sub") & 0170000u) == 0040000u);
  SD_CHECK_EQ_INT(fake_mode(f.s, "/home/user/d/sub") & 0777u, 0755u);   /* 0777 & ~umask 022 */
  /* Recycle bin creation is refused at the root (fixed-type mount). */
  SD_CHECK_EQ_INT(vopen(&f, L"\\$RECYCLE.BIN", GENERIC_READ, SHARE_ALL, SD_VFS_FILE_CREATE,
                        SD_VFS_FILE_DIRECTORY_FILE, &h), SD_VFS_E_ACCESS_DENIED);
  fx_done(&f);
}

SD_TEST(vfs_case_insensitive_lookup_and_collisions)
{
  fixture f;
  sd_vfs_handle *h = NULL;
  list_ctx l;
  char buf[16];
  UINT32 got = 0;
  SD_REQUIRE(fx_mount(&f, NULL, NULL));
  fake_put(f.s, "/home/user/README", "upper", 5, 0644);
  fake_put(f.s, "/home/user/readme", "lower", 5, 0644);
  fake_put(f.s, "/home/user/Notes.TXT", "notes", 5, 0644);
  SD_REQUIRE(vlist(&f, L"\\", &l) == SD_VFS_OK);
  SD_CHECK(list_find(&l, L"README") >= 0);
  SD_CHECK(list_find(&l, L"readme~c2") >= 0);
  SD_CHECK(list_find(&l, L"Notes.TXT") >= 0);
  /* Folded match; exact-case lstat fails first on a case-sensitive remote. */
  SD_REQUIRE(vopen(&f, L"\\notes.txt", GENERIC_READ, SHARE_ALL, SD_VFS_FILE_OPEN, 0, &h) == SD_VFS_OK);
  SD_CHECK_EQ_INT(sd_vfs_read(h, 0, buf, sizeof(buf), &got), SD_VFS_OK);
  SD_CHECK_MEM(buf, "notes", 5);
  vclose(h, FALSE);
  SD_REQUIRE(vopen(&f, L"\\readme~c2", GENERIC_READ, SHARE_ALL, SD_VFS_FILE_OPEN, 0, &h) == SD_VFS_OK);
  SD_CHECK_EQ_INT(sd_vfs_read(h, 0, buf, sizeof(buf), &got), SD_VFS_OK);
  SD_CHECK_MEM(buf, "lower", 5);
  vclose(h, FALSE);
  /* A create that folds onto an existing name is a collision (02 §1.3). */
  SD_CHECK_EQ_INT(vopen(&f, L"\\NOTES.txt", GENERIC_WRITE, SHARE_ALL, SD_VFS_FILE_CREATE, 0, &h), SD_VFS_E_EXISTS);
  fx_done(&f);
}

SD_TEST(vfs_listing_maps_names_and_drops_malformed_entries)
{
  fixture f;
  list_ctx l;
  sd_vfs_handle *h = NULL;
  int i;
  SD_REQUIRE(fx_mount(&f, NULL, NULL));
  fake_put(f.s, "/home/user/a:b", "x", 1, 0644);
  fake_put(f.s, "/home/user/trail.", "y", 1, 0644);
  fake_put(f.s, "/home/user/.hidden", "z", 1, 0644);
  fake_put(f.s, "/home/user/a\xEF\x80\xBA" "b", "w", 1, 0644);   /* same display name as "a:b" */
  fake_mkfifo(f.s, "/home/user/fifo");
  fake_inject_dirent(f.s, "/home/user", "bad/name", 8, 0100644);
  fake_inject_dirent(f.s, "/home/user", ".", 1, 040755);
  fake_inject_dirent(f.s, "/home/user", "..", 2, 040755);
  fake_inject_dirent(f.s, "/home/user", "nul\0x", 5, 0100644);
  fake_inject_dirent(f.s, "/home/user", "", 0, 0100644);
  fake_inject_dirent(f.s, "/home/user", "trail.", 6, 0100644);   /* duplicate raw name */
  SD_REQUIRE(vlist(&f, L"\\", &l) == SD_VFS_OK);
  SD_CHECK_EQ_INT(l.n, 4);
  SD_CHECK(list_find(&l, L"a\xF03A" L"b") >= 0);
  SD_CHECK(list_find(&l, L"a\xF03A" L"b~c2") >= 0);
  SD_CHECK(list_find(&l, L"trail\xF02E") >= 0);
  i = list_find(&l, L".hidden");
  SD_REQUIRE(i >= 0);
  SD_CHECK((l.info[i].win_attrs & FILE_ATTRIBUTE_HIDDEN) != 0);
  SD_CHECK(list_find(&l, L"fifo") < 0);                             /* special files hidden */
  SD_CHECK(f.ev.notices >= 1);
  SD_CHECK(strcmp(f.ev.last_code, "dirent_dropped") == 0);
  SD_REQUIRE(vopen(&f, L"\\trail\xF02E", GENERIC_READ, SHARE_ALL, SD_VFS_FILE_OPEN, 0, &h) == SD_VFS_OK);
  vclose(h, FALSE);
  SD_REQUIRE(vopen(&f, L"\\a\xF03A" L"b~c2", GENERIC_READ, SHARE_ALL, SD_VFS_FILE_OPEN, 0, &h) == SD_VFS_OK);
  {
    char c = 0;
    UINT32 got = 0;
    SD_CHECK_EQ_INT(sd_vfs_read(h, 0, &c, 1, &got), SD_VFS_OK);
    SD_CHECK(c == 'w');
  }
  vclose(h, FALSE);
  /* A new file named with a PUA colon is created as a real ':' on the server. */
  SD_REQUIRE(vopen(&f, L"\\new\xF03A" L"x", GENERIC_WRITE, SHARE_ALL, SD_VFS_FILE_CREATE, 0, &h) == SD_VFS_OK);
  vclose(h, FALSE);
  SD_CHECK(fake_exists(f.s, "/home/user/new:x"));
  fx_done(&f);
}

SD_TEST(vfs_symlinks_follow_inside)
{
  fixture f;
  sd_vfs_options o;
  list_ctx l;
  sd_vfs_handle *h = NULL;
  int i;
  char c = 0;
  UINT32 got = 0;
  default_opts(&o);
  o.remote_root = "root";
  memset(&f, 0, sizeof(f));
  f.s = fake_session_create(NULL);
  fake_mkdir(f.s, "/home/user/root", 0755);
  fake_mkdir(f.s, "/home/user/root/sub", 0755);
  fake_put(f.s, "/home/user/root/sub/f.txt", "S", 1, 0644);
  fake_mkdir(f.s, "/home/user/secret", 0700);
  fake_put(f.s, "/home/user/secret/key", "K", 1, 0600);
  fake_symlink(f.s, "/home/user/root/in", "sub");
  fake_symlink(f.s, "/home/user/root/out", "/home/user/secret");
  fake_symlink(f.s, "/home/user/root/dead", "nope");
  fake_symlink(f.s, "/home/user/root/fl", "sub/f.txt");
  f.o = o;
  SD_REQUIRE(sd_vfs_mount(f.s, &f.o, on_event, &f.ev, &f.v) == SD_VFS_OK);

  SD_REQUIRE(vlist(&f, L"\\", &l) == SD_VFS_OK);
  i = list_find(&l, L"in");
  SD_REQUIRE(i >= 0);
  SD_CHECK((l.info[i].win_attrs & FILE_ATTRIBUTE_DIRECTORY) != 0);
  i = list_find(&l, L"out");
  SD_REQUIRE(i >= 0);
  SD_CHECK_EQ_INT(l.info[i].win_attrs, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
  SD_CHECK_EQ_U64(l.info[i].size, 0);
  i = list_find(&l, L"dead");
  SD_REQUIRE(i >= 0);
  SD_CHECK_EQ_INT(l.info[i].win_attrs, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
  i = list_find(&l, L"fl");
  SD_REQUIRE(i >= 0);
  SD_CHECK_EQ_U64(l.info[i].size, 1);
  SD_CHECK(strcmp(f.ev.last_code, "symlink_outside_root") == 0);

  SD_CHECK_EQ_INT(vopen(&f, L"\\out\\key", GENERIC_READ, SHARE_ALL, SD_VFS_FILE_OPEN, 0, &h), SD_VFS_E_PATH_NOT_FOUND);
  SD_CHECK_EQ_INT(vopen(&f, L"\\out", GENERIC_READ, SHARE_ALL, SD_VFS_FILE_OPEN, 0, &h), SD_VFS_E_NOT_FOUND);
  SD_CHECK_EQ_INT(vopen(&f, L"\\dead", GENERIC_READ, SHARE_ALL, SD_VFS_FILE_OPEN, 0, &h), SD_VFS_E_NOT_FOUND);
  /* Attribute-only open of a bad link works (delete/rename act on the link). */
  SD_REQUIRE(vopen(&f, L"\\out", FILE_READ_ATTRIBUTES | DELETE, SHARE_ALL, SD_VFS_FILE_OPEN, 0, &h) == SD_VFS_OK);
  SD_CHECK_EQ_INT(sd_vfs_can_delete(h), SD_VFS_OK);
  vclose(h, TRUE);
  SD_CHECK(!fake_exists(f.s, "/home/user/root/out"));
  SD_CHECK(fake_exists(f.s, "/home/user/secret/key"));
  SD_REQUIRE(vopen(&f, L"\\in\\f.txt", GENERIC_READ, SHARE_ALL, SD_VFS_FILE_OPEN, 0, &h) == SD_VFS_OK);
  SD_CHECK_EQ_INT(sd_vfs_read(h, 0, &c, 1, &got), SD_VFS_OK);
  SD_CHECK(c == 'S');
  vclose(h, FALSE);
  fx_done(&f);
}

SD_TEST(vfs_symlinks_hide)
{
  fixture f;
  sd_vfs_options o;
  list_ctx l;
  sd_vfs_handle *h = NULL;
  default_opts(&o);
  o.symlinks = SD_SYMLINK_HIDE;
  memset(&f, 0, sizeof(f));
  f.s = fake_session_create(NULL);
  fake_put(f.s, "/home/user/f", "x", 1, 0644);
  fake_symlink(f.s, "/home/user/l", "f");
  f.o = o;
  SD_REQUIRE(sd_vfs_mount(f.s, &f.o, on_event, &f.ev, &f.v) == SD_VFS_OK);
  SD_REQUIRE(vlist(&f, L"\\", &l) == SD_VFS_OK);
  SD_CHECK_EQ_INT(l.n, 1);
  SD_CHECK_EQ_INT(vopen(&f, L"\\l", GENERIC_READ, SHARE_ALL, SD_VFS_FILE_OPEN, 0, &h), SD_VFS_E_NOT_FOUND);
  fx_done(&f);
}

SD_TEST(vfs_read_only_mount)
{
  fixture f;
  sd_vfs_options o;
  sd_vfs_handle *h = NULL;
  sd_vfs_info info;
  default_opts(&o);
  o.read_only = TRUE;
  memset(&f, 0, sizeof(f));
  f.s = fake_session_create(NULL);
  fake_put(f.s, "/home/user/f", "data", 4, 0644);
  f.o = o;
  SD_REQUIRE(sd_vfs_mount(f.s, &f.o, on_event, &f.ev, &f.v) == SD_VFS_OK);
  SD_CHECK_EQ_INT(vopen(&f, L"\\new", GENERIC_WRITE, SHARE_ALL, SD_VFS_FILE_CREATE, 0, &h), SD_VFS_E_READ_ONLY);
  SD_CHECK_EQ_INT(vopen(&f, L"\\f", GENERIC_WRITE, SHARE_ALL, SD_VFS_FILE_OPEN, 0, &h), SD_VFS_E_READ_ONLY);
  SD_CHECK_EQ_INT(vopen(&f, L"\\f", GENERIC_READ, SHARE_ALL, SD_VFS_FILE_OVERWRITE, 0, &h), SD_VFS_E_READ_ONLY);
  SD_REQUIRE(vopen(&f, L"\\f", GENERIC_READ | MAXIMUM_ALLOWED, SHARE_ALL, SD_VFS_FILE_OPEN_IF, 0, &h) == SD_VFS_OK);
  SD_CHECK_EQ_INT(sd_vfs_getattr(h, &info), SD_VFS_OK);
  SD_CHECK((info.win_attrs & FILE_ATTRIBUTE_READONLY) != 0);
  SD_CHECK_EQ_INT(sd_vfs_can_delete(h), SD_VFS_E_READ_ONLY);
  SD_CHECK_EQ_INT(sd_vfs_rename(h, L"\\g", FALSE), SD_VFS_E_READ_ONLY);
  vclose(h, FALSE);
  fx_done(&f);
}

SD_TEST(vfs_delete_semantics)
{
  fixture f;
  sd_vfs_handle *h = NULL, *h2 = NULL;
  SD_REQUIRE(fx_mount(&f, NULL, NULL));
  fake_put(f.s, "/home/user/f", "data", 4, 0644);
  fake_mkdir(f.s, "/home/user/d", 0755);
  fake_put(f.s, "/home/user/d/x", "x", 1, 0644);
  fake_put(f.s, "/home/user/ro", "r", 1, 0444);
  /* Non-empty directory. */
  SD_REQUIRE(vopen(&f, L"\\d", DELETE, SHARE_ALL, SD_VFS_FILE_OPEN, 0, &h) == SD_VFS_OK);
  SD_CHECK_EQ_INT(sd_vfs_can_delete(h), SD_VFS_E_NOT_EMPTY);
  vclose(h, FALSE);
  SD_CHECK_EQ_INT(vopen(&f, L"\\d", DELETE, SHARE_ALL, SD_VFS_FILE_OPEN, SD_VFS_FILE_DELETE_ON_CLOSE, &h),
                  SD_VFS_E_NOT_EMPTY);
  /* Read-only attribute: cannot delete. */
  SD_REQUIRE(vopen(&f, L"\\ro", DELETE, SHARE_ALL, SD_VFS_FILE_OPEN, 0, &h) == SD_VFS_OK);
  SD_CHECK_EQ_INT(sd_vfs_can_delete(h), SD_VFS_E_CANNOT_DELETE);
  vclose(h, FALSE);
  /* Delete happens at the last cleanup; meanwhile new opens see DELETE_PENDING. */
  SD_REQUIRE(vopen(&f, L"\\f", GENERIC_READ, SHARE_ALL, SD_VFS_FILE_OPEN, 0, &h2) == SD_VFS_OK);
  SD_REQUIRE(vopen(&f, L"\\f", DELETE, SHARE_ALL, SD_VFS_FILE_OPEN, 0, &h) == SD_VFS_OK);
  SD_CHECK_EQ_INT(sd_vfs_can_delete(h), SD_VFS_OK);
  vclose(h, TRUE);
  SD_CHECK(fake_exists(f.s, "/home/user/f"));
  {
    sd_vfs_handle *h3 = NULL;
    SD_CHECK_EQ_INT(vopen(&f, L"\\f", GENERIC_READ, SHARE_ALL, SD_VFS_FILE_OPEN, 0, &h3), SD_VFS_E_DELETE_PENDING);
  }
  vclose(h2, FALSE);
  SD_CHECK(!fake_exists(f.s, "/home/user/f"));
  SD_CHECK_EQ_INT(vopen(&f, L"\\f", GENERIC_READ, SHARE_ALL, SD_VFS_FILE_OPEN, 0, &h), SD_VFS_E_NOT_FOUND);
  /* FILE_DELETE_ON_CLOSE. */
  SD_REQUIRE(vopen(&f, L"\\d\\x", DELETE, SHARE_ALL, SD_VFS_FILE_OPEN, SD_VFS_FILE_DELETE_ON_CLOSE, &h) == SD_VFS_OK);
  vclose(h, FALSE);
  SD_CHECK(!fake_exists(f.s, "/home/user/d/x"));
  SD_CHECK_EQ_INT(sd_vfs_delete_path(f.v, NULL, L"\\d", FALSE), SD_VFS_OK);
  SD_CHECK(!fake_exists(f.s, "/home/user/d"));
  /* A failed delete at cleanup raises SD_VFS_EV_DELETE_FAILED. */
  fake_put(f.s, "/home/user/g", "g", 1, 0644);
  SD_REQUIRE(vopen(&f, L"\\g", DELETE, SHARE_ALL, SD_VFS_FILE_OPEN, 0, &h) == SD_VFS_OK);
  fake_fail_next(f.s, FOP_REMOVE, SD_E_ACCESS_DENIED);
  SD_CHECK_EQ_INT(sd_vfs_cleanup(h, TRUE), SD_VFS_E_ACCESS_DENIED);
  sd_vfs_close(h);
  SD_CHECK(f.ev.delete_failed == 1);
  SD_CHECK(fake_exists(f.s, "/home/user/g"));
  fx_done(&f);
}

SD_TEST(vfs_rename_semantics)
{
  fixture f;
  sd_vfs_handle *h = NULL, *hc = NULL;
  UINT32 done = 0;
  list_ctx l;
  SD_REQUIRE(fx_mount(&f, NULL, NULL));
  fake_put(f.s, "/home/user/a", "A", 1, 0644);
  fake_put(f.s, "/home/user/b", "B", 1, 0644);
  fake_mkdir(f.s, "/home/user/dir", 0755);
  fake_put(f.s, "/home/user/dir/child", "", 0, 0644);
  fake_mkdir(f.s, "/home/user/dst", 0755);

  SD_REQUIRE(vopen(&f, L"\\a", DELETE, SHARE_ALL, SD_VFS_FILE_OPEN, 0, &h) == SD_VFS_OK);
  SD_CHECK_EQ_INT(sd_vfs_rename(h, L"\\b", FALSE), SD_VFS_E_EXISTS);
  SD_CHECK_EQ_INT(sd_vfs_rename(h, L"\\b", TRUE), SD_VFS_OK);
  vclose(h, FALSE);
  SD_CHECK(!fake_exists(f.s, "/home/user/a"));
  {
    char c = 0;
    fake_get(f.s, "/home/user/b", &c, 1);
    SD_CHECK(c == 'A');
  }
  /* Rename onto a directory with replace: ACCESS_DENIED (NTFS). */
  SD_REQUIRE(vopen(&f, L"\\b", DELETE, SHARE_ALL, SD_VFS_FILE_OPEN, 0, &h) == SD_VFS_OK);
  SD_CHECK_EQ_INT(sd_vfs_rename(h, L"\\dst", TRUE), SD_VFS_E_ACCESS_DENIED);
  SD_CHECK_EQ_INT(sd_vfs_rename(h, L"\\nodir\\b", FALSE), SD_VFS_E_PATH_NOT_FOUND);
  /* Case-only rename. */
  SD_CHECK_EQ_INT(sd_vfs_rename(h, L"\\B", FALSE), SD_VFS_OK);
  vclose(h, FALSE);
  SD_CHECK(fake_exists(f.s, "/home/user/B"));
  SD_CHECK(!fake_exists(f.s, "/home/user/b"));
  SD_REQUIRE(vlist(&f, L"\\", &l) == SD_VFS_OK);
  SD_CHECK(list_find(&l, L"B") >= 0 && list_find(&l, L"b") < 0);

  /* Moving a directory keeps an open child handle working, at the new path. */
  SD_REQUIRE(vopen(&f, L"\\dir\\child", GENERIC_WRITE, SHARE_ALL, SD_VFS_FILE_OPEN, 0, &hc) == SD_VFS_OK);
  SD_REQUIRE(vopen(&f, L"\\dir", DELETE, SHARE_ALL, SD_VFS_FILE_OPEN, 0, &h) == SD_VFS_OK);
  SD_CHECK_EQ_INT(sd_vfs_rename(h, L"\\dst\\moved", FALSE), SD_VFS_OK);
  vclose(h, FALSE);
  SD_CHECK_EQ_INT(sd_vfs_write(hc, 0, "Z", 1, &done, FALSE), SD_VFS_OK);
  vclose(hc, FALSE);
  SD_CHECK_EQ_INT(fake_get(f.s, "/home/user/dst/moved/child", NULL, 0), 1);
  SD_REQUIRE(vopen(&f, L"\\dst\\moved\\child", GENERIC_READ, SHARE_ALL, SD_VFS_FILE_OPEN, 0, &h) == SD_VFS_OK);
  vclose(h, FALSE);
  SD_CHECK_EQ_INT(vopen(&f, L"\\dir\\child", GENERIC_READ, SHARE_ALL, SD_VFS_FILE_OPEN, 0, &h), SD_VFS_E_PATH_NOT_FOUND);
  SD_CHECK_EQ_INT(sd_vfs_rename_path(f.v, NULL, L"\\dst\\moved", L"\\back", FALSE), SD_VFS_OK);
  SD_CHECK(fake_exists(f.s, "/home/user/back/child"));
  fx_done(&f);
}

SD_TEST(vfs_rename_replace_without_posix_rename)
{
  fixture f;
  fake_config cfg;
  sd_vfs_handle *h = NULL;
  memset(&cfg, 0, sizeof(cfg));
  cfg.no_ext = 1;
  SD_REQUIRE(fx_mount(&f, &cfg, NULL));
  fake_put(f.s, "/home/user/a", "A", 1, 0644);
  fake_put(f.s, "/home/user/b", "B", 1, 0644);
  SD_REQUIRE(vopen(&f, L"\\a", DELETE, SHARE_ALL, SD_VFS_FILE_OPEN, 0, &h) == SD_VFS_OK);
  SD_CHECK_EQ_INT(sd_vfs_rename(h, L"\\b", TRUE), SD_VFS_OK);   /* remove + rename fallback */
  vclose(h, FALSE);
  SD_CHECK(!fake_exists(f.s, "/home/user/a"));
  SD_CHECK(fake_exists(f.s, "/home/user/b"));
  {
    sd_vfs_statfs fs;
    SD_CHECK_EQ_INT(sd_vfs_statfs_get(f.v, &fs), SD_VFS_OK);
    SD_CHECK(!fs.known);
    SD_CHECK_EQ_U64(fs.total, 2ull << 50);
    SD_CHECK_EQ_U64(fs.avail, 1ull << 50);
  }
  fx_done(&f);
}

SD_TEST(vfs_share_modes)
{
  fixture f;
  sd_vfs_handle *h = NULL, *h2 = NULL;
  SD_REQUIRE(fx_mount(&f, NULL, NULL));
  fake_put(f.s, "/home/user/f", "x", 1, 0644);
  SD_REQUIRE(vopen(&f, L"\\f", GENERIC_READ, 0, SD_VFS_FILE_OPEN, 0, &h) == SD_VFS_OK);
  SD_CHECK_EQ_INT(vopen(&f, L"\\f", GENERIC_READ, SHARE_ALL, SD_VFS_FILE_OPEN, 0, &h2), SD_VFS_E_SHARING);
  SD_REQUIRE(vopen(&f, L"\\f", FILE_READ_ATTRIBUTES, 0, SD_VFS_FILE_OPEN, 0, &h2) == SD_VFS_OK);
  vclose(h2, FALSE);
  vclose(h, FALSE);
  SD_REQUIRE(vopen(&f, L"\\f", GENERIC_READ, FILE_SHARE_READ, SD_VFS_FILE_OPEN, 0, &h) == SD_VFS_OK);
  SD_REQUIRE(vopen(&f, L"\\f", GENERIC_READ, FILE_SHARE_READ, SD_VFS_FILE_OPEN, 0, &h2) == SD_VFS_OK);
  vclose(h2, FALSE);
  SD_CHECK_EQ_INT(vopen(&f, L"\\f", GENERIC_WRITE, SHARE_ALL, SD_VFS_FILE_OPEN, 0, &h2), SD_VFS_E_SHARING);
  vclose(h, FALSE);
  fx_done(&f);
}

SD_TEST(vfs_metadata_cache_and_negative_entries)
{
  fixture f;
  sd_vfs_info info;
  SD_REQUIRE(fx_mount(&f, NULL, NULL));
  fake_put(f.s, "/home/user/f", "x", 1, 0644);
  fake_reset_counts(f.s);
  SD_CHECK_EQ_INT(sd_vfs_stat_path(f.v, L"\\f", &info), SD_VFS_OK);
  SD_CHECK_EQ_INT(sd_vfs_stat_path(f.v, L"\\F", &info), SD_VFS_OK);   /* folded key hit */
  SD_CHECK_EQ_INT(sd_vfs_stat_path(f.v, L"\\f", &info), SD_VFS_OK);
  SD_CHECK_EQ_INT(fake_count(f.s, FOP_LSTAT), 1);
  SD_CHECK_EQ_INT(sd_vfs_stat_path(f.v, L"\\missing", &info), SD_VFS_E_NOT_FOUND);
  {
    uint32_t before = fake_count(f.s, FOP_LSTAT) + fake_count(f.s, FOP_OPENDIR);
    SD_CHECK_EQ_INT(sd_vfs_stat_path(f.v, L"\\missing", &info), SD_VFS_E_NOT_FOUND);
    SD_CHECK_EQ_INT(fake_count(f.s, FOP_LSTAT) + fake_count(f.s, FOP_OPENDIR), before);
  }
  /* Offline: cached entries are served ignoring TTL; unknown names are DISCONNECTED, not NOT_FOUND. */
  fake_mkdir(f.s, "/home/user/d", 0755);
  sd_vfs_refresh(f.v, NULL);
  SD_CHECK_EQ_INT(sd_vfs_stat_path(f.v, L"\\d", &info), SD_VFS_OK);
  fake_set_state(f.s, SD_SFTP_ST_DISCONNECTED);
  SD_CHECK_EQ_INT(sd_vfs_stat_path(f.v, L"\\f", &info), SD_VFS_OK);
  SD_CHECK_EQ_INT(sd_vfs_stat_path(f.v, L"\\d\\other", &info), SD_VFS_E_DISCONNECTED);
  {
    sd_vfs_handle *h = NULL;
    SD_CHECK_EQ_INT(vopen(&f, L"\\new", GENERIC_WRITE, SHARE_ALL, SD_VFS_FILE_CREATE, 0, &h), SD_VFS_E_DISCONNECTED);
  }
  fake_set_state(f.s, SD_SFTP_ST_READY);
  fx_done(&f);
}

SD_TEST(vfs_attributes_times_and_truncate)
{
  fixture f;
  sd_vfs_handle *h = NULL;
  sd_vfs_info info;
  FILETIME ft;
  uint64_t t = (uint64_t)(1600000000ll + 11644473600ll) * 10000000ull;
  SD_REQUIRE(fx_mount(&f, NULL, NULL));
  fake_put(f.s, "/home/user/f", "0123456789", 10, 0644);
  fake_put(f.s, "/home/user/x.lnk", "[shortcut]", 10, 0644);
  ft.dwLowDateTime = (DWORD)t;
  ft.dwHighDateTime = (DWORD)(t >> 32);
  SD_REQUIRE(vopen(&f, L"\\f", FILE_WRITE_ATTRIBUTES, SHARE_ALL, SD_VFS_FILE_OPEN, 0, &h) == SD_VFS_OK);
  SD_CHECK_EQ_INT(sd_vfs_set_times(h, NULL, NULL, &ft), SD_VFS_OK);
  SD_CHECK_EQ_INT(fake_mtime(f.s, "/home/user/f"), 1600000000);
  SD_CHECK_EQ_INT(sd_vfs_set_winattrs(h, FILE_ATTRIBUTE_READONLY), SD_VFS_OK);
  SD_CHECK_EQ_INT(fake_mode(f.s, "/home/user/f") & 0777u, 0444u);
  SD_CHECK_EQ_INT(sd_vfs_getattr(h, &info), SD_VFS_OK);
  SD_CHECK((info.win_attrs & FILE_ATTRIBUTE_READONLY) != 0);
  SD_CHECK_EQ_INT(sd_vfs_set_winattrs(h, FILE_ATTRIBUTE_NORMAL), SD_VFS_OK);
  SD_CHECK_EQ_INT(fake_mode(f.s, "/home/user/f") & 0777u, 0644u);
  vclose(h, FALSE);
  /* Times set on a writing handle are applied at cleanup, after the data. */
  SD_REQUIRE(vopen(&f, L"\\f", GENERIC_WRITE, SHARE_ALL, SD_VFS_FILE_OPEN, 0, &h) == SD_VFS_OK);
  SD_CHECK_EQ_INT(sd_vfs_set_times(h, NULL, NULL, &ft), SD_VFS_OK);
  SD_CHECK_EQ_INT(sd_vfs_truncate(h, 4), SD_VFS_OK);
  SD_CHECK(fake_mtime(f.s, "/home/user/f") != 1600000000);
  vclose(h, FALSE);
  SD_CHECK_EQ_INT(fake_mtime(f.s, "/home/user/f"), 1600000000);
  SD_CHECK_EQ_INT(fake_get(f.s, "/home/user/f", NULL, 0), 4);
  /* Shell-active files: listed, attribute opens work, data reads are blocked (TM-R14). */
  SD_CHECK_EQ_INT(vopen(&f, L"\\x.lnk", GENERIC_READ, SHARE_ALL, SD_VFS_FILE_OPEN, 0, &h), SD_VFS_OK);
  vclose(h, FALSE);
  {
    sd_vfs_options o;
    fixture g;
    default_opts(&o);
    o.block_shell_active = TRUE;
    memset(&g, 0, sizeof(g));
    g.s = fake_session_create(NULL);
    fake_put(g.s, "/home/user/x.lnk", "[shortcut]", 10, 0644);
    g.o = o;
    SD_REQUIRE(sd_vfs_mount(g.s, &g.o, on_event, &g.ev, &g.v) == SD_VFS_OK);
    SD_CHECK_EQ_INT(vopen(&g, L"\\X.LNK", GENERIC_READ, SHARE_ALL, SD_VFS_FILE_OPEN, 0, &h), SD_VFS_E_ACCESS_DENIED);
    SD_CHECK(strcmp(g.ev.last_code, "shell_active_blocked") == 0);
    SD_REQUIRE(vopen(&g, L"\\x.lnk", FILE_READ_ATTRIBUTES | DELETE, SHARE_ALL, SD_VFS_FILE_OPEN, 0, &h) == SD_VFS_OK);
    vclose(h, FALSE);
    fx_done(&g);
  }
  fx_done(&f);
}

SD_TEST(vfs_security_descriptor_and_statfs)
{
  fixture f;
  sd_vfs_handle *h = NULL;
  ULONG needed = 0;
  BYTE buf[1024];
  PSID owner = NULL;
  BOOL def = FALSE;
  sd_vfs_statfs fs;
  sd_vfs_volume vol;
  SD_REQUIRE(fx_mount(&f, NULL, NULL));
  fake_put(f.s, "/home/user/f", "x", 1, 0644);
  SD_REQUIRE(vopen(&f, L"\\f", READ_CONTROL, SHARE_ALL, SD_VFS_FILE_OPEN, 0, &h) == SD_VFS_OK);
  SD_CHECK_EQ_INT(sd_vfs_get_sd(h, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                                    DACL_SECURITY_INFORMATION, NULL, 0, &needed), SD_VFS_OK);
  SD_REQUIRE(needed > 0 && needed <= sizeof(buf));
  SD_CHECK_EQ_INT(sd_vfs_get_sd(h, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                                    DACL_SECURITY_INFORMATION, buf, sizeof(buf), &needed), SD_VFS_OK);
  SD_CHECK(IsValidSecurityDescriptor(buf));
  SD_CHECK(GetSecurityDescriptorOwner(buf, &owner, &def) && owner && IsValidSid(owner));
  vclose(h, FALSE);
  SD_CHECK_EQ_INT(sd_vfs_statfs_get(f.v, &fs), SD_VFS_OK);
  SD_CHECK(fs.known);
  SD_CHECK_EQ_U64(fs.total, 1000000ull * 4096);
  SD_CHECK_EQ_U64(fs.free, 500000ull * 4096);
  SD_CHECK_EQ_U64(fs.avail, 400000ull * 4096);
  sd_vfs_get_volume(f.v, &vol);
  SD_CHECK(vol.fs_name && wcscmp(vol.fs_name, L"NTFS") == 0);   /* D23 */
  SD_CHECK(vol.owner_sid && IsValidSid(vol.owner_sid));
  fx_done(&f);
}

/* Concurrent writers on separate files and on one file (non-overlapping ranges). */
typedef struct thr_arg { fixture *f; int idx; sd_vfs_handle *shared; LONG ok; } thr_arg;

static unsigned __stdcall writer_thread(void *p)
{
  thr_arg *a = (thr_arg *)p;
  enum { BLK = 65536 };
  uint8_t *block = (uint8_t *)sd_alloc(BLK);   /* off the stack */
  UINT32 done, i;
  WCHAR name[32];
  sd_vfs_handle *h = NULL;
  BOOL ex, dir;
  if (!block)
    return 0;
  memset(block, 'a' + a->idx, BLK);
  _snwprintf_s(name, 32, _TRUNCATE, L"\\t%d.bin", a->idx);
  if (sd_vfs_create(a->f->v, name, NULL, GENERIC_WRITE, 0, SD_VFS_FILE_CREATE, 0, 0, &h, &ex, &dir) != SD_VFS_OK) {
    sd_free(block);
    return 0;
  }
  for (i = 0; i < 16; i++) {
    if (sd_vfs_write(h, (UINT64)i * BLK, block, BLK, &done, FALSE) != SD_VFS_OK ||
        sd_vfs_write(a->shared, ((UINT64)i * 8 + a->idx) * BLK, block, BLK, &done, FALSE) != SD_VFS_OK)
      break;
  }
  if (i == 16)
    a->ok = 1;
  sd_vfs_cleanup(h, FALSE);
  sd_vfs_close(h);
  sd_free(block);
  return 0;
}

SD_TEST(vfs_concurrent_writers)
{
  fixture f;
  thr_arg args[8];
  HANDLE th[8];
  sd_vfs_handle *shared = NULL;
  int i;
  uint8_t *data;
  SD_REQUIRE(fx_mount(&f, NULL, NULL));
  SD_REQUIRE(vopen(&f, L"\\shared.bin", GENERIC_WRITE, SHARE_ALL, SD_VFS_FILE_CREATE, 0, &shared) == SD_VFS_OK);
  for (i = 0; i < 8; i++) {
    args[i].f = &f;
    args[i].idx = i;
    args[i].shared = shared;
    args[i].ok = 0;
    th[i] = (HANDLE)_beginthreadex(NULL, 0, writer_thread, &args[i], 0, NULL);
    SD_REQUIRE(th[i] != NULL);
  }
  WaitForMultipleObjects(8, th, TRUE, INFINITE);
  for (i = 0; i < 8; i++) {
    CloseHandle(th[i]);
    SD_CHECK(args[i].ok);
  }
  vclose(shared, FALSE);
  data = (uint8_t *)sd_alloc(128 * 65536);
  SD_REQUIRE(data);
  SD_CHECK_EQ_INT(fake_get(f.s, "/home/user/shared.bin", data, 128 * 65536), 128 * 65536);
  for (i = 0; i < 128; i++)
    SD_CHECK(data[(size_t)i * 65536] == (uint8_t)('a' + (i % 8)));
  sd_free(data);
  fx_done(&f);
}
