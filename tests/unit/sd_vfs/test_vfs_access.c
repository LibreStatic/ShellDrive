/* Per-request access check (M5, 02 6.7, 7.7, TM-R24): per-user owner rule and global service_access /
   service_access_write rules, against the in-memory fake sd_sftp. The SIDs are fixed byte images (IsValidSid and
   EqualSid need nothing else); the frontends build the same caller shape from the requestor token. */
#include <windows.h>
#include <string.h>
#include <wchar.h>

#include "fake_sftp.h"
#include "sd_test.h"
#include "sd_vfs/sd_vfs.h"
#include "vfs_internal.h"

#define SHARE_ALL (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
#define PSID_OF(a) ((PSID)(void *)(a))

/* S-1-5-21-1-2-3-1001 (alice), -1002 (bob), -1003 (carol) */
static const unsigned char k_alice[] = { 1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0xE9, 3, 0, 0 };
static const unsigned char k_bob[]   = { 1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0xEA, 3, 0, 0 };
static const unsigned char k_carol[] = { 1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0xEB, 3, 0, 0 };
/* S-1-5-32-545 BUILTIN\Users, S-1-5-32-544 BUILTIN\Administrators, S-1-5-18 LocalSystem */
static const unsigned char k_users[]  = { 1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 33, 2, 0, 0 };
static const unsigned char k_admins[] = { 1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0 };
static const unsigned char k_system[] = { 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0 };

typedef struct afx { sd_sftp_session *s; sd_vfs *v; sd_vfs_options o; } afx;

static void noop_event(void *ctx, const sd_vfs_event *ev)
{
  (void)ctx;
  (void)ev;
}

/* Per-user defaults (the mount owner is the process user unless set) and global defaults (SYSTEM owner, as the
   service mounts it). */
static void user_opts(sd_vfs_options *o)
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

static void global_opts(sd_vfs_options *o, const PSID *acc, UINT nacc, const PSID *wr, UINT nwr)
{
  user_opts(o);
  o->global_mount = TRUE;
  o->owner_sid = PSID_OF(k_system);
  o->access_sids = acc;
  o->n_access = nacc;
  o->write_sids = wr;
  o->n_write = nwr;
}

static void afx_init(afx *f, const sd_vfs_options *o)
{
  memset(f, 0, sizeof(*f));
  f->s = fake_session_create(NULL);
  fake_put(f->s, "f", "data", 4, 0644);
  fake_mkdir(f->s, "d", 0755);
  f->o = *o;
}

static sd_vfs_status afx_mount(afx *f)
{
  return sd_vfs_mount(f->s, &f->o, noop_event, NULL, &f->v);
}

static void afx_done(afx *f)
{
  if (f->v) {
    sd_vfs_quiesce(f->v, 1000);
    sd_vfs_unmount(f->v);
  }
  fake_session_destroy(f->s);
}

static sd_vfs_caller caller_of(PSID sid, BOOL can_write, const PSID *groups, UINT n)
{
  sd_vfs_caller c;
  c.sid = sid;
  c.can_write = can_write;
  c.groups = groups;
  c.n_groups = n;
  return c;
}

static sd_vfs_status open_as(afx *f, const sd_vfs_caller *c, const WCHAR *path, UINT32 access, UINT32 disp,
                             sd_vfs_handle **h)
{
  BOOL existed = FALSE, dir = FALSE;
  return sd_vfs_create(f->v, path, c, access, SHARE_ALL, disp, 0, 0, h, &existed, &dir);
}

static void close_h(sd_vfs_handle *h)
{
  sd_vfs_cleanup(h, FALSE);
  sd_vfs_close(h);
}

SD_TEST(vfs_access_global_mount_needs_service_access)
{
  afx f;
  sd_vfs_options o;
  PSID acc[1];
  global_opts(&o, NULL, 0, NULL, 0);
  afx_init(&f, &o);
  SD_CHECK_EQ_INT(afx_mount(&f), SD_VFS_E_ACCESS_DENIED);        /* scope = service without service_access (D35) */
  SD_CHECK(f.v == NULL);
  acc[0] = PSID_OF(k_alice);
  global_opts(&f.o, acc, 1, NULL, 0);                              /* empty write list is fine */
  SD_CHECK_EQ_INT(afx_mount(&f), SD_VFS_OK);
  afx_done(&f);
}

SD_TEST(vfs_access_per_user_owner_only)
{
  afx f;
  sd_vfs_options o;
  sd_vfs_caller alice, bob, nobody;
  sd_vfs_handle *h = NULL;
  sd_vfs_info info;
  user_opts(&o);
  o.owner_sid = PSID_OF(k_alice);
  afx_init(&f, &o);
  SD_REQUIRE(afx_mount(&f) == SD_VFS_OK);
  alice = caller_of(PSID_OF(k_alice), TRUE, NULL, 0);
  bob = caller_of(PSID_OF(k_bob), TRUE, NULL, 0);
  nobody = caller_of(NULL, TRUE, NULL, 0);
  SD_CHECK_EQ_INT(open_as(&f, &alice, L"\\f", GENERIC_READ, SD_VFS_FILE_OPEN, &h), SD_VFS_OK);
  close_h(h);
  SD_CHECK_EQ_INT(open_as(&f, &bob, L"\\f", GENERIC_READ, SD_VFS_FILE_OPEN, &h), SD_VFS_E_ACCESS_DENIED);
  SD_CHECK_EQ_INT(open_as(&f, &nobody, L"\\f", GENERIC_READ, SD_VFS_FILE_OPEN, &h), SD_VFS_E_ACCESS_DENIED);
  SD_CHECK_EQ_INT(sd_vfs_stat_path(f.v, &bob, L"\\f", &info), SD_VFS_E_ACCESS_DENIED);
  SD_CHECK_EQ_INT(sd_vfs_stat_path(f.v, &alice, L"\\f", &info), SD_VFS_OK);
  /* host-internal calls (no requestor) keep the M1 behaviour on a per-user mount */
  SD_CHECK_EQ_INT(open_as(&f, NULL, L"\\f", GENERIC_READ, SD_VFS_FILE_OPEN, &h), SD_VFS_OK);
  close_h(h);
  afx_done(&f);
}

SD_TEST(vfs_access_read_needs_access_list)
{
  afx f;
  sd_vfs_options o;
  PSID acc[1];
  sd_vfs_caller alice, bob;
  sd_vfs_handle *h = NULL;
  sd_vfs_info info;
  acc[0] = PSID_OF(k_alice);
  global_opts(&o, acc, 1, NULL, 0);
  afx_init(&f, &o);
  SD_REQUIRE(afx_mount(&f) == SD_VFS_OK);
  alice = caller_of(PSID_OF(k_alice), TRUE, NULL, 0);
  bob = caller_of(PSID_OF(k_bob), TRUE, NULL, 0);
  SD_CHECK_EQ_INT(open_as(&f, &alice, L"\\f", GENERIC_READ, SD_VFS_FILE_OPEN, &h), SD_VFS_OK);
  close_h(h);
  SD_CHECK_EQ_INT(open_as(&f, &bob, L"\\f", GENERIC_READ, SD_VFS_FILE_OPEN, &h), SD_VFS_E_ACCESS_DENIED);
  SD_CHECK_EQ_INT(open_as(&f, &bob, L"\\d", GENERIC_READ, SD_VFS_FILE_OPEN, &h), SD_VFS_E_ACCESS_DENIED);
  SD_CHECK_EQ_INT(sd_vfs_stat_path(f.v, &bob, L"\\f", &info), SD_VFS_E_ACCESS_DENIED);
  SD_CHECK_EQ_INT(sd_vfs_stat_path(f.v, &alice, L"\\f", &info), SD_VFS_OK);
  SD_CHECK_EQ_INT(open_as(&f, NULL, L"\\f", GENERIC_READ, SD_VFS_FILE_OPEN, &h), SD_VFS_E_ACCESS_DENIED);
  afx_done(&f);
}

SD_TEST(vfs_access_member_without_write_is_read_only)
{
  afx f;
  sd_vfs_options o;
  PSID acc[1];
  sd_vfs_caller alice;
  sd_vfs_handle *h = NULL;
  acc[0] = PSID_OF(k_alice);
  global_opts(&o, acc, 1, NULL, 0);                 /* service_access_write empty: members are read-only */
  afx_init(&f, &o);
  SD_REQUIRE(afx_mount(&f) == SD_VFS_OK);
  alice = caller_of(PSID_OF(k_alice), TRUE, NULL, 0);
  SD_CHECK_EQ_INT(open_as(&f, &alice, L"\\f", GENERIC_READ | MAXIMUM_ALLOWED, SD_VFS_FILE_OPEN, &h), SD_VFS_OK);
  close_h(h);
  SD_CHECK_EQ_INT(open_as(&f, &alice, L"\\f", GENERIC_WRITE, SD_VFS_FILE_OPEN, &h), SD_VFS_E_ACCESS_DENIED);
  SD_CHECK_EQ_INT(open_as(&f, &alice, L"\\f", DELETE, SD_VFS_FILE_OPEN, &h), SD_VFS_E_ACCESS_DENIED);
  SD_CHECK_EQ_INT(open_as(&f, &alice, L"\\new", GENERIC_READ, SD_VFS_FILE_CREATE, &h), SD_VFS_E_ACCESS_DENIED);
  SD_CHECK_EQ_INT(open_as(&f, &alice, L"\\f", GENERIC_READ, SD_VFS_FILE_OVERWRITE, &h), SD_VFS_E_ACCESS_DENIED);
  SD_CHECK_EQ_INT(open_as(&f, &alice, L"\\f", GENERIC_READ, SD_VFS_FILE_OPEN_IF, &h), SD_VFS_E_ACCESS_DENIED);
  SD_CHECK_EQ_INT(sd_vfs_delete_path(f.v, &alice, L"\\f", FALSE), SD_VFS_E_ACCESS_DENIED);
  SD_CHECK_EQ_INT(sd_vfs_rename_path(f.v, &alice, L"\\f", L"\\g", FALSE), SD_VFS_E_ACCESS_DENIED);
  SD_CHECK(fake_exists(f.s, "f") != 0);
  SD_CHECK(fake_exists(f.s, "new") == 0);
  SD_CHECK(fake_exists(f.s, "g") == 0);
  afx_done(&f);
}

SD_TEST(vfs_access_write_list_grants_write)
{
  afx f;
  sd_vfs_options o;
  PSID acc[2], wr[1];
  sd_vfs_caller alice, bob, alice_ro;
  sd_vfs_handle *h = NULL;
  acc[0] = PSID_OF(k_alice);
  acc[1] = PSID_OF(k_bob);
  wr[0] = PSID_OF(k_alice);
  global_opts(&o, acc, 2, wr, 1);
  afx_init(&f, &o);
  SD_REQUIRE(afx_mount(&f) == SD_VFS_OK);
  alice = caller_of(PSID_OF(k_alice), TRUE, NULL, 0);
  bob = caller_of(PSID_OF(k_bob), TRUE, NULL, 0);
  alice_ro = caller_of(PSID_OF(k_alice), FALSE, NULL, 0);     /* the frontend restricts alice to read */
  SD_CHECK_EQ_INT(open_as(&f, &alice, L"\\f", GENERIC_WRITE, SD_VFS_FILE_OPEN, &h), SD_VFS_OK);
  close_h(h);
  SD_CHECK_EQ_INT(open_as(&f, &bob, L"\\f", GENERIC_WRITE, SD_VFS_FILE_OPEN, &h), SD_VFS_E_ACCESS_DENIED);
  SD_CHECK_EQ_INT(open_as(&f, &bob, L"\\f", GENERIC_READ, SD_VFS_FILE_OPEN, &h), SD_VFS_OK);
  close_h(h);
  SD_CHECK_EQ_INT(open_as(&f, &alice_ro, L"\\f", GENERIC_WRITE, SD_VFS_FILE_OPEN, &h), SD_VFS_E_ACCESS_DENIED);
  SD_CHECK_EQ_INT(sd_vfs_rename_path(f.v, &alice, L"\\f", L"\\g", FALSE), SD_VFS_OK);
  SD_CHECK_EQ_INT(sd_vfs_rename_path(f.v, &bob, L"\\g", L"\\f", FALSE), SD_VFS_E_ACCESS_DENIED);
  SD_CHECK(fake_exists(f.s, "g") != 0);
  afx_done(&f);
}

SD_TEST(vfs_access_groups_match_and_admins_write)
{
  afx f;
  sd_vfs_options o;
  PSID acc[1], g_user[1], g_both[2];
  sd_vfs_caller carol_user, carol_admin, carol_none;
  sd_vfs_handle *h = NULL;
  acc[0] = PSID_OF(k_users);                  /* service_access = BUILTIN\Users */
  global_opts(&o, acc, 1, NULL, 0);           /* no write list: only Administrators may write */
  afx_init(&f, &o);
  SD_REQUIRE(afx_mount(&f) == SD_VFS_OK);
  g_user[0] = PSID_OF(k_users);
  g_both[0] = PSID_OF(k_users);
  g_both[1] = PSID_OF(k_admins);
  carol_user = caller_of(PSID_OF(k_carol), TRUE, g_user, 1);
  carol_admin = caller_of(PSID_OF(k_carol), TRUE, g_both, 2);
  carol_none = caller_of(PSID_OF(k_carol), TRUE, NULL, 0);
  SD_CHECK_EQ_INT(open_as(&f, &carol_user, L"\\f", GENERIC_READ, SD_VFS_FILE_OPEN, &h), SD_VFS_OK);
  close_h(h);
  SD_CHECK_EQ_INT(open_as(&f, &carol_none, L"\\f", GENERIC_READ, SD_VFS_FILE_OPEN, &h), SD_VFS_E_ACCESS_DENIED);
  SD_CHECK_EQ_INT(open_as(&f, &carol_user, L"\\f", GENERIC_WRITE, SD_VFS_FILE_OPEN, &h), SD_VFS_E_ACCESS_DENIED);
  SD_CHECK_EQ_INT(open_as(&f, &carol_admin, L"\\f", GENERIC_WRITE, SD_VFS_FILE_OPEN, &h), SD_VFS_OK);
  close_h(h);
  afx_done(&f);
}

SD_TEST(vfs_access_group_in_write_list)
{
  afx f;
  sd_vfs_options o;
  PSID acc[1], wr[1], g_user[1];
  sd_vfs_caller carol;
  sd_vfs_handle *h = NULL;
  acc[0] = PSID_OF(k_users);
  wr[0] = PSID_OF(k_users);                   /* service_access_write = BUILTIN\Users: every member writes */
  global_opts(&o, acc, 1, wr, 1);
  afx_init(&f, &o);
  SD_REQUIRE(afx_mount(&f) == SD_VFS_OK);
  g_user[0] = PSID_OF(k_users);
  carol = caller_of(PSID_OF(k_carol), TRUE, g_user, 1);
  SD_CHECK_EQ_INT(open_as(&f, &carol, L"\\f", GENERIC_WRITE, SD_VFS_FILE_OPEN, &h), SD_VFS_OK);
  close_h(h);
  afx_done(&f);
}

SD_TEST(vfs_access_system_needs_allow_system)
{
  afx f;
  sd_vfs_options o;
  PSID acc[1];
  sd_vfs_caller sys;
  sd_vfs_handle *h = NULL;
  acc[0] = PSID_OF(k_alice);                  /* SYSTEM is not listed */
  global_opts(&o, acc, 1, NULL, 0);
  afx_init(&f, &o);
  SD_REQUIRE(afx_mount(&f) == SD_VFS_OK);
  sys = caller_of(PSID_OF(k_system), TRUE, NULL, 0);
  SD_CHECK_EQ_INT(open_as(&f, &sys, L"\\f", GENERIC_WRITE, SD_VFS_FILE_OPEN, &h), SD_VFS_OK);   /* allow_system: full */
  close_h(h);
  afx_done(&f);

  global_opts(&o, acc, 1, NULL, 0);
  o.allow_system = FALSE;
  afx_init(&f, &o);
  SD_REQUIRE(afx_mount(&f) == SD_VFS_OK);
  sys = caller_of(PSID_OF(k_system), TRUE, NULL, 0);
  SD_CHECK_EQ_INT(open_as(&f, &sys, L"\\f", GENERIC_READ, SD_VFS_FILE_OPEN, &h), SD_VFS_E_ACCESS_DENIED);
  afx_done(&f);
}

SD_TEST(vfs_access_frontend_write_flag_restricts_members)
{
  afx f;
  sd_vfs_options o;
  PSID acc[1], wr[1];
  sd_vfs_caller alice_flag_off;
  sd_vfs_handle *h = NULL;
  acc[0] = PSID_OF(k_alice);
  wr[0] = PSID_OF(k_alice);
  global_opts(&o, acc, 1, wr, 1);
  afx_init(&f, &o);
  SD_REQUIRE(afx_mount(&f) == SD_VFS_OK);
  alice_flag_off = caller_of(PSID_OF(k_alice), FALSE, NULL, 0);
  SD_CHECK_EQ_INT(open_as(&f, &alice_flag_off, L"\\f", GENERIC_WRITE, SD_VFS_FILE_OPEN, &h), SD_VFS_E_ACCESS_DENIED);
  SD_CHECK_EQ_INT(open_as(&f, &alice_flag_off, L"\\f", GENERIC_READ, SD_VFS_FILE_OPEN, &h), SD_VFS_OK);
  close_h(h);
  afx_done(&f);
}

/* ---- audit (M5, 03 10.3 Event 1200): raised after successful changes on a global mount, coalesced per 60 s ---- */

static uint64_t g_now;                  /* the fake clock the vfs reads through v->audit_now */
static int g_audits;                    /* SD_VFS_EV_AUDIT events seen by audit_cb */
static char g_last_op[16];
static WCHAR g_last_path[64];
static BOOL g_last_alice;

static uint64_t fake_now(void)
{
  return g_now;
}

static void audit_cb(void *ctx, const sd_vfs_event *ev)
{
  (void)ctx;
  if (ev->kind != SD_VFS_EV_AUDIT)
    return;
  g_audits++;
  strcpy_s(g_last_op, sizeof(g_last_op), ev->op ? ev->op : "");
  wcscpy_s(g_last_path, SD_COUNTOF(g_last_path), ev->path ? ev->path : L"");
  g_last_alice = ev->caller_sid && EqualSid(ev->caller_sid, PSID_OF(k_alice));
}

static void audit_reset(void)
{
  g_audits = 0;
  g_last_op[0] = 0;
  g_last_path[0] = 0;
  g_last_alice = FALSE;
}

/* Mounts with the audit callback and the fake clock. */
static sd_vfs_status afx_mount_audit(afx *f)
{
  sd_vfs_status st = sd_vfs_mount(f->s, &f->o, audit_cb, NULL, &f->v);
  if (st == SD_VFS_OK)
    f->v->audit_now = fake_now;
  return st;
}

SD_TEST(vfs_audit_raised_for_global_changes)
{
  afx f;
  sd_vfs_options o;
  PSID acc[1], wr[1];
  sd_vfs_caller alice, carol;
  sd_vfs_handle *h = NULL;
  acc[0] = PSID_OF(k_alice);
  wr[0] = PSID_OF(k_alice);
  global_opts(&o, acc, 1, wr, 1);
  afx_init(&f, &o);
  SD_REQUIRE(afx_mount_audit(&f) == SD_VFS_OK);
  g_now = 0;
  audit_reset();
  alice = caller_of(PSID_OF(k_alice), TRUE, NULL, 0);
  carol = caller_of(PSID_OF(k_carol), TRUE, NULL, 0);
  /* reads and denied opens raise nothing */
  SD_CHECK_EQ_INT(open_as(&f, &alice, L"\\f", GENERIC_READ, SD_VFS_FILE_OPEN, &h), SD_VFS_OK);
  close_h(h);
  SD_CHECK_EQ_INT(open_as(&f, &carol, L"\\f", GENERIC_WRITE, SD_VFS_FILE_OPEN, &h), SD_VFS_E_ACCESS_DENIED);
  SD_CHECK_EQ_INT(g_audits, 0);
  /* a create, then a write open of an existing file: one event per open */
  SD_CHECK_EQ_INT(open_as(&f, &alice, L"\\new", GENERIC_WRITE, SD_VFS_FILE_CREATE, &h), SD_VFS_OK);
  SD_CHECK_EQ_INT(g_audits, 1);
  SD_CHECK(strcmp(g_last_op, "create") == 0 && g_last_alice && _wcsicmp(g_last_path, L"\\new") == 0);
  close_h(h);                           /* cleanup without a delete raises nothing more */
  SD_CHECK_EQ_INT(g_audits, 1);
  g_now += VFS_AUDIT_WINDOW_MS;         /* a new window, so the next event is not coalesced away */
  SD_CHECK_EQ_INT(open_as(&f, &alice, L"\\f", GENERIC_WRITE, SD_VFS_FILE_OPEN, &h), SD_VFS_OK);
  SD_CHECK_EQ_INT(g_audits, 2);
  SD_CHECK(strcmp(g_last_op, "write_open") == 0);
  close_h(h);
  /* attribute change through a write handle, then a rename and a delete */
  SD_CHECK_EQ_INT(open_as(&f, &alice, L"\\f", GENERIC_WRITE, SD_VFS_FILE_OPEN, &h), SD_VFS_OK);
  SD_CHECK_EQ_INT(sd_vfs_set_winattrs(h, FILE_ATTRIBUTE_NORMAL), SD_VFS_OK);
  SD_CHECK(strcmp(g_last_op, "setattr") == 0);
  close_h(h);
  SD_CHECK_EQ_INT(sd_vfs_rename_path(f.v, &alice, L"\\new", L"\\new2", FALSE), SD_VFS_OK);
  SD_CHECK(strcmp(g_last_op, "rename") == 0);
  g_now += VFS_AUDIT_WINDOW_MS;
  SD_CHECK_EQ_INT(sd_vfs_delete_path(f.v, &alice, L"\\new2", FALSE), SD_VFS_OK);
  SD_CHECK(strcmp(g_last_op, "delete") == 0 && _wcsicmp(g_last_path, L"\\new2") == 0);
  SD_CHECK(fake_exists(f.s, "new2") == 0);
  SD_CHECK_EQ_INT(g_audits, 5);
  afx_done(&f);
}

SD_TEST(vfs_audit_coalesces_per_window)
{
  afx f;
  sd_vfs_options o;
  PSID acc[2], wr[2];
  sd_vfs_caller alice, bob;
  sd_vfs_handle *h = NULL;
  acc[0] = PSID_OF(k_alice);
  acc[1] = PSID_OF(k_bob);
  wr[0] = PSID_OF(k_alice);
  wr[1] = PSID_OF(k_bob);
  global_opts(&o, acc, 2, wr, 2);
  afx_init(&f, &o);
  SD_REQUIRE(afx_mount_audit(&f) == SD_VFS_OK);
  alice = caller_of(PSID_OF(k_alice), TRUE, NULL, 0);
  bob = caller_of(PSID_OF(k_bob), TRUE, NULL, 0);
  audit_reset();
  g_now = 1000;
  SD_CHECK_EQ_INT(open_as(&f, &alice, L"\\f", GENERIC_WRITE, SD_VFS_FILE_OPEN, &h), SD_VFS_OK);
  close_h(h);
  SD_CHECK_EQ_INT(g_audits, 1);
  /* the same requestor, operation and path inside the window: coalesced */
  g_now = 1000 + VFS_AUDIT_WINDOW_MS - 1;
  SD_CHECK_EQ_INT(open_as(&f, &alice, L"\\f", GENERIC_WRITE, SD_VFS_FILE_OPEN, &h), SD_VFS_OK);
  close_h(h);
  SD_CHECK_EQ_INT(g_audits, 1);
  /* another requestor, another path, or another operation is not a repeat */
  SD_CHECK_EQ_INT(open_as(&f, &bob, L"\\f", GENERIC_WRITE, SD_VFS_FILE_OPEN, &h), SD_VFS_OK);
  close_h(h);
  SD_CHECK_EQ_INT(g_audits, 2);
  SD_CHECK_EQ_INT(open_as(&f, &alice, L"\\d\\x", GENERIC_WRITE, SD_VFS_FILE_CREATE, &h), SD_VFS_OK);
  close_h(h);
  SD_CHECK_EQ_INT(g_audits, 3);
  /* the window is measured from the last raised event: at 60 s it is raised again */
  g_now = 1000 + VFS_AUDIT_WINDOW_MS;
  SD_CHECK_EQ_INT(open_as(&f, &alice, L"\\f", GENERIC_WRITE, SD_VFS_FILE_OPEN, &h), SD_VFS_OK);
  close_h(h);
  SD_CHECK_EQ_INT(g_audits, 4);
  afx_done(&f);
}

SD_TEST(vfs_audit_never_raised_on_per_user_mount)
{
  afx f;
  sd_vfs_options o;
  sd_vfs_caller alice;
  sd_vfs_handle *h = NULL;
  user_opts(&o);
  o.owner_sid = PSID_OF(k_alice);
  afx_init(&f, &o);
  SD_REQUIRE(sd_vfs_mount(f.s, &f.o, audit_cb, NULL, &f.v) == SD_VFS_OK);
  audit_reset();
  alice = caller_of(PSID_OF(k_alice), TRUE, NULL, 0);
  SD_CHECK_EQ_INT(open_as(&f, &alice, L"\\new", GENERIC_WRITE, SD_VFS_FILE_CREATE, &h), SD_VFS_OK);
  close_h(h);
  SD_CHECK_EQ_INT(sd_vfs_delete_path(f.v, &alice, L"\\new", FALSE), SD_VFS_OK);
  SD_CHECK_EQ_INT(g_audits, 0);       /* per-user mounts are the owner's own drive: no audit (02 6.7) */
  afx_done(&f);
}
