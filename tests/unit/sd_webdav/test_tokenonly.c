/* sd_webdav token-only mode (TM-R19, 02 §7.4): the decision matrix, the token gate in each mode on one
 * loopback server (a token-only export and a plain export side by side), the WinHTTP self-test end to end,
 * and the refusal of a token-only mount before anything is started. The tests never write the registry. */
#define _CRT_SECURE_NO_WARNINGS /* test code: sprintf into sized buffers */
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "fake_sftp.h"
#include "sd_base/sd_mem.h"
#include "sd_test.h"
#include "sd_webdav/sd_webdav.h"
#include "wd_client_util.h"
#include "wd_server.h"

/* ---- decision (pure) ---- */

static sd_webdav_tok_input tok_ok_input(void)
{
  sd_webdav_tok_input in;
  memset(&in, 0, sizeof(in));
  in.policy = -1;               /* absent: the default (1) */
  in.confirmed = TRUE;
  in.active_sessions = 1;
  return in;
}

SD_TEST(webdav_token_only_decision_matrix)
{
  sd_webdav_tok_input in = tok_ok_input();
  SD_CHECK(sd_webdav_token_only_decide(&in) == SD_WD_TOK_OK);

  /* AllowWebDavTokenOnly: absent and 1 allow, 0 forbids, any other value is refused (fail closed) */
  in = tok_ok_input();
  in.policy = 1;
  SD_CHECK(sd_webdav_token_only_decide(&in) == SD_WD_TOK_OK);
  in = tok_ok_input();
  in.policy = 0;
  SD_CHECK(sd_webdav_token_only_decide(&in) == SD_WD_TOK_FORBIDDEN_POLICY);
  in = tok_ok_input();
  in.policy = 2;
  SD_CHECK(sd_webdav_token_only_decide(&in) == SD_WD_TOK_FORBIDDEN_POLICY);

  /* every enable is confirmed by the user: no confirmation, no mode */
  in = tok_ok_input();
  in.confirmed = FALSE;
  SD_CHECK(sd_webdav_token_only_decide(&in) == SD_WD_TOK_NOT_CONFIRMED);

  /* RDSH (or a remote session) refuses */
  in = tok_ok_input();
  in.rdsh = TRUE;
  SD_CHECK(sd_webdav_token_only_decide(&in) == SD_WD_TOK_RDSH);

  /* more than one active session refuses; an unknown count refuses too */
  in = tok_ok_input();
  in.active_sessions = 2;
  SD_CHECK(sd_webdav_token_only_decide(&in) == SD_WD_TOK_SESSIONS);
  in = tok_ok_input();
  in.active_sessions = 0xFFFFFFFFu;
  SD_CHECK(sd_webdav_token_only_decide(&in) == SD_WD_TOK_SESSIONS);
  in = tok_ok_input();
  in.active_sessions = 0;
  SD_CHECK(sd_webdav_token_only_decide(&in) == SD_WD_TOK_OK);

  /* global mounts are refused whatever else holds */
  in = tok_ok_input();
  in.global = TRUE;
  SD_CHECK(sd_webdav_token_only_decide(&in) == SD_WD_TOK_FORBIDDEN_GLOBAL);

  /* order: global, policy, confirmation, RDSH, sessions */
  in = tok_ok_input();
  in.global = TRUE;
  in.policy = 0;
  in.confirmed = FALSE;
  in.rdsh = TRUE;
  in.active_sessions = 9;
  SD_CHECK(sd_webdav_token_only_decide(&in) == SD_WD_TOK_FORBIDDEN_GLOBAL);
  in.global = FALSE;
  SD_CHECK(sd_webdav_token_only_decide(&in) == SD_WD_TOK_FORBIDDEN_POLICY);
  in.policy = -1;
  SD_CHECK(sd_webdav_token_only_decide(&in) == SD_WD_TOK_NOT_CONFIRMED);
  in.confirmed = TRUE;
  SD_CHECK(sd_webdav_token_only_decide(&in) == SD_WD_TOK_RDSH);
  in.rdsh = FALSE;
  SD_CHECK(sd_webdav_token_only_decide(&in) == SD_WD_TOK_SESSIONS);

  SD_CHECK(sd_webdav_token_only_decide(NULL) != SD_WD_TOK_OK);
  SD_CHECK(sd_webdav_tok_verdict_name(SD_WD_TOK_FORBIDDEN_POLICY) != NULL);
}

/* ---- self-test verdict (pure) ---- */

SD_TEST(webdav_token_selftest_verdict)
{
  /* the token must be accepted (2xx, 207 included) */
  SD_CHECK(wd_selftest_verdict(207, 401) == 1);
  SD_CHECK(wd_selftest_verdict(200, 404) == 1);
  SD_CHECK(wd_selftest_verdict(207, 403) == 1);
  SD_CHECK(wd_selftest_verdict(401, 401) == 0);
  SD_CHECK(wd_selftest_verdict(404, 401) == 0);
  SD_CHECK(wd_selftest_verdict(0, 401) == 0);
  /* a request without the token must be refused with a 4xx; success or no answer is a failure */
  SD_CHECK(wd_selftest_verdict(207, 207) == 0);
  SD_CHECK(wd_selftest_verdict(207, 200) == 0);
  SD_CHECK(wd_selftest_verdict(207, 500) == 0);
  SD_CHECK(wd_selftest_verdict(207, 0) == 0);
  SD_CHECK(wd_selftest_verdict(207, -1) == 0);
}

/* ---- server: the token gate in each mode ---- */

typedef struct tfix {
  sd_sftp_session *s;
  sd_vfs *v;
  sd_webdav_server *srv;
  sd_webdav_export *tok;          /* token-only export */
  sd_webdav_export *plain;        /* ordinary export (SSPI required) */
  uint16_t port;
  char tok_prefix[64];
  char plain_prefix[64];
} tfix;

static int tfx_up(tfix *f)
{
  sd_vfs_options o;
  sd_webdav_server_cfg sc;
  sd_webdav_export_cfg ec;
  memset(f, 0, sizeof(*f));
  f->s = fake_session_create(NULL);
  if (f->s == NULL)
    return -1;
  fake_put(f->s, "/home/user/hello.txt", "hello world", 11, 0644);
  memset(&o, 0, sizeof(o));
  o.struct_size = sizeof(o);
  o.hide_dotfiles = TRUE;
  o.map_readonly = TRUE;
  o.allow_system = TRUE;
  o.fsync_on_flush = TRUE;
  o.request_timeout_ms = 50000;
  o.volume_label = L"SD Test";
  if (sd_vfs_mount(f->s, &o, NULL, NULL, &f->v) != SD_VFS_OK)
    return -1;
  memset(&sc, 0, sizeof(sc));
  sc.struct_size = sizeof(sc);
  if (sd_webdav_server_start(&sc, &f->srv) != SD_OK)
    return -1;
  f->port = sd_webdav_server_port(f->srv);
  memset(&ec, 0, sizeof(ec));
  ec.struct_size = sizeof(ec);
  ec.label = L"Token";
  ec.token_only = TRUE;
  if (sd_webdav_export_add(f->srv, f->v, &ec, &f->tok) != SD_OK)
    return -1;
  ec.label = L"Plain";
  ec.token_only = FALSE;
  if (sd_webdav_export_add(f->srv, f->v, &ec, &f->plain) != SD_OK)
    return -1;
  strcpy_s(f->tok_prefix, sizeof(f->tok_prefix), sd_webdav_export_prefix(f->tok));
  strcpy_s(f->plain_prefix, sizeof(f->plain_prefix), sd_webdav_export_prefix(f->plain));
  return 0;
}

static void tfx_down(tfix *f)
{
  if (f->tok) sd_webdav_export_remove(f->tok);
  if (f->plain) sd_webdav_export_remove(f->plain);
  if (f->srv) sd_webdav_server_stop(f->srv);
  if (f->v) {
    sd_vfs_quiesce(f->v, 5000);
    sd_vfs_unmount(f->v);
  }
  if (f->s) fake_session_destroy(f->s);
}

static tc_conn *tconn(uint16_t port)
{
  tc_conn *c = (tc_conn *)sd_calloc(1, sizeof(tc_conn));
  if (c && tc_connect(c, port, 0) != 0) {
    sd_free(c);
    return NULL;
  }
  return c;
}

static void tconn_free(tc_conn *c)
{
  if (c) {
    tc_close(c);
    sd_free(c);
  }
}

/* PROPFIND depth 0 on "<prefix>/" without credentials. */
static int propfind_plain(tc_conn *c, uint16_t port, const char *prefix, tc_resp *r)
{
  char path[160];
  _snprintf_s(path, sizeof(path), _TRUNCATE, "%s/", prefix);
  return tc_request(c, port, "PROPFIND", path, "Depth: 0\r\n", NULL, 0, r);
}

SD_TEST(webdav_token_only_gate_per_mode)
{
  tfix f;
  tc_conn *c;
  tc_resp r;
  char path[160], v[256];
  SD_REQUIRE(tfx_up(&f) == 0);

  /* token-only mode on: the token alone is accepted, with no challenge */
  c = tconn(f.port);
  SD_REQUIRE(c != NULL);
  SD_REQUIRE(propfind_plain(c, f.port, f.tok_prefix, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 207);
  SD_CHECK(!tc_header(&r, "WWW-Authenticate", v, sizeof(v)));
  tc_resp_free(&r);

  /* a wrong token of the right shape is an unknown prefix: 404, nothing learned */
  SD_REQUIRE(tc_request(c, f.port, "PROPFIND", "/s-aaaaaaaaaaaaaaaaaaaaaaaaaa/", "Depth: 0\r\n", NULL, 0, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 404);
  SD_CHECK(!tc_header(&r, "WWW-Authenticate", v, sizeof(v)));
  tc_resp_free(&r);

  /* the token-only export is writable without credentials */
  _snprintf_s(path, sizeof(path), _TRUNCATE, "%s/new.txt", f.tok_prefix);
  SD_REQUIRE(tc_request(c, f.port, "PUT", path, NULL, "data", 4, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 201);
  tc_resp_free(&r);
  SD_CHECK(fake_exists(f.s, "/home/user/new.txt"));

  /* the token of the token-only export does not open the ordinary export: 401 even on this connection,
     which has already answered a token-only request (no authentication bypass through a shared socket) */
  SD_REQUIRE(propfind_plain(c, f.port, f.plain_prefix, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 401);
  SD_CHECK(tc_header(&r, "WWW-Authenticate", v, sizeof(v)));
  tc_resp_free(&r);

  /* the root, which belongs to no export, always needs SSPI */
  SD_REQUIRE(tc_request(c, f.port, "PROPFIND", "/", "Depth: 0\r\n", NULL, 0, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 401);
  tc_resp_free(&r);

  /* the ordinary export still works with SSPI on the same connection */
  _snprintf_s(path, sizeof(path), _TRUNCATE, "%s/", f.plain_prefix);
  SD_REQUIRE(tc_authenticate(c, f.port, path) == 207);
  tconn_free(c);

  /* token-only mode off (an ordinary export): the token alone is refused with a challenge */
  c = tconn(f.port);
  SD_REQUIRE(c != NULL);
  SD_REQUIRE(propfind_plain(c, f.port, f.plain_prefix, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 401);
  SD_CHECK(tc_header(&r, "WWW-Authenticate", v, sizeof(v)));
  tc_resp_free(&r);
  tconn_free(c);

  tfx_down(&f);
}

/* ---- self-test end to end (WinHTTP against the loopback server) ---- */

SD_TEST(webdav_token_only_selftest)
{
  tfix f;
  uint32_t step = 0, err = 0;
  sd_err e;
  SD_REQUIRE(tfx_up(&f) == 0);
  wd_server_dbg_enable(1);      /* diagnostic ring: this test is the WinHTTP-vs-server oracle */
  /* token accepted, token-less refused; on failure the probe's step and Win32 error say why */
  e = sd_webdav_token_selftest(f.port, f.tok_prefix);
  if (e != SD_OK) {
    int ts = 0, ps = 0, n, i;
    char ring[WD_SERVER_DBG_N][96];
    wd_selftest_last_diag(&step, &err);
    wd_selftest_last_statuses(&ts, &ps);
    sd_test_fail(sd_t_, __FILE__, __LINE__, "selftest(token) = %s at step %lu (Win32 %lu, token %d, plain %d)",
                 sd_err_name(e), (unsigned long)step, (unsigned long)err, ts, ps);
    n = wd_server_dbg_last(ring, WD_SERVER_DBG_N);
    for (i = n - 1; i >= 0; i--)
      sd_test_fail(sd_t_, __FILE__, __LINE__, "server saw: %s", ring[i]);
  }
  SD_CHECK(e == SD_OK);
  /* an ordinary export does not accept its token alone: the self-test fails */
  e = sd_webdav_token_selftest(f.port, f.plain_prefix);
  if (e != SD_E_AUTH_FAILED) {
    wd_selftest_last_diag(&step, &err);
    sd_test_fail(sd_t_, __FILE__, __LINE__, "selftest(plain) = %s at step %lu (Win32 %lu)",
                 sd_err_name(e), (unsigned long)step, (unsigned long)err);
  }
  SD_CHECK(e == SD_E_AUTH_FAILED);
  /* an unknown token is refused */
  e = sd_webdav_token_selftest(f.port, "/s-aaaaaaaaaaaaaaaaaaaaaaaaaa");
  if (e != SD_E_AUTH_FAILED) {
    wd_selftest_last_diag(&step, &err);
    sd_test_fail(sd_t_, __FILE__, __LINE__, "selftest(unknown) = %s at step %lu (Win32 %lu)",
                 sd_err_name(e), (unsigned long)step, (unsigned long)err);
  }
  SD_CHECK(e == SD_E_AUTH_FAILED);
  /* bad arguments */
  SD_CHECK(sd_webdav_token_selftest(0, f.tok_prefix) == SD_E_INVALID_PARAM);
  SD_CHECK(sd_webdav_token_selftest(f.port, "s-aaaaaaaaaaaaaaaaaaaaaaaaaa") == SD_E_INVALID_PARAM);
  SD_CHECK(sd_webdav_token_selftest(f.port, NULL) == SD_E_INVALID_PARAM);
  wd_server_dbg_enable(0);
  tfx_down(&f);
}

/* ---- mount: refused before anything is started ---- */

SD_TEST(webdav_token_only_mount_refused)
{
  sd_webdav_mount_cfg mc;
  sd_webdav_mount *m = (sd_webdav_mount *)(uintptr_t)0x10;   /* must be overwritten with NULL */
  sd_vfs *dummy = (sd_vfs *)(uintptr_t)0x10;                 /* never dereferenced: refused first */
  memset(&mc, 0, sizeof(mc));
  mc.struct_size = sizeof(mc);
  mc.letter = L'Z';
  mc.token_only = TRUE;

  /* not confirmed by the user */
  mc.token_only_confirmed = FALSE;
  SD_CHECK(sd_webdav_mount_start(dummy, &mc, &m) == SD_E_ACCESS_DENIED);
  SD_CHECK(m == NULL);

  /* a global (service) mount never uses token-only, even when confirmed */
  m = (sd_webdav_mount *)(uintptr_t)0x10;
  mc.token_only_confirmed = TRUE;
  mc.global = TRUE;
  SD_CHECK(sd_webdav_mount_start(dummy, &mc, &m) == SD_E_ACCESS_DENIED);
  SD_CHECK(m == NULL);
}
