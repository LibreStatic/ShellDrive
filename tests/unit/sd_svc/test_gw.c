/* Global WebDAV mechanism choice (apps/shelldrive-host/svc_gw.c) and the per-user attach seam (svc_gw_attach.c).
   Pure logic and a fake attach seam: no WNet call, no SCM, no drive, no second logon session. */
#include <windows.h>
#include <string.h>
#include <wchar.h>

#include "sd_test.h"
#include "svc_gw.h"
#include "svc_gw_attach.h"

static void go_table(svc_gw_table *t)
{
  int i;
  for (i = 0; i < SVC_GW_OS_COUNT; i++) {
    t->system[i] = SVC_GW_UNVERIFIED;
    t->link[i] = SVC_GW_UNVERIFIED;
  }
}

static void ready(svc_gw_input *in, svc_gw_family f, svc_gw_mode m)
{
  memset(in, 0, sizeof(*in));
  in->family = f;
  in->mode = m;
  in->service_running = 1;
  in->client = SVC_GW_CLIENT_RUNNING;
  in->token_only = 0;
}

SD_TEST(gw_family_from_version)
{
  SD_CHECK_EQ_INT(svc_gw_family_of(5, 1), SVC_GW_OS_XP_2003);
  SD_CHECK_EQ_INT(svc_gw_family_of(5, 2), SVC_GW_OS_XP_2003);
  SD_CHECK_EQ_INT(svc_gw_family_of(6, 0), SVC_GW_OS_VISTA_7);
  SD_CHECK_EQ_INT(svc_gw_family_of(6, 1), SVC_GW_OS_VISTA_7);
  SD_CHECK_EQ_INT(svc_gw_family_of(6, 2), SVC_GW_OS_8_81);
  SD_CHECK_EQ_INT(svc_gw_family_of(6, 3), SVC_GW_OS_8_81);
  SD_CHECK_EQ_INT(svc_gw_family_of(10, 0), SVC_GW_OS_10_11);
  /* 2000, 6.4 (Windows 10 preview) and anything else are not in the matrix */
  SD_CHECK_EQ_INT(svc_gw_family_of(5, 0), SVC_GW_OS_UNKNOWN);
  SD_CHECK_EQ_INT(svc_gw_family_of(6, 4), SVC_GW_OS_UNKNOWN);
  SD_CHECK_EQ_INT(svc_gw_family_of(7, 0), SVC_GW_OS_UNKNOWN);
  SD_CHECK_EQ_INT(svc_gw_family_of(4, 0), SVC_GW_OS_UNKNOWN);
}

SD_TEST(gw_mode_parses_the_four_names_only)
{
  SD_CHECK_EQ_INT(svc_gw_mode_parse("auto"), SVC_GW_MODE_AUTO);
  SD_CHECK_EQ_INT(svc_gw_mode_parse("system"), SVC_GW_MODE_SYSTEM);
  SD_CHECK_EQ_INT(svc_gw_mode_parse("link"), SVC_GW_MODE_LINK);
  SD_CHECK_EQ_INT(svc_gw_mode_parse("attach"), SVC_GW_MODE_ATTACH);
  SD_CHECK_EQ_INT(svc_gw_mode_parse("Auto"), SVC_GW_MODE_INVALID);
  SD_CHECK_EQ_INT(svc_gw_mode_parse("dokany"), SVC_GW_MODE_INVALID);
  SD_CHECK_EQ_INT(svc_gw_mode_parse(""), SVC_GW_MODE_INVALID);
  SD_CHECK_EQ_INT(svc_gw_mode_parse(NULL), SVC_GW_MODE_INVALID);
}

/* The shipped table selects nothing: every cell is UNVERIFIED until a lab run says GO. */
SD_TEST(gw_compiled_table_has_no_go_cell)
{
  const svc_gw_table *t = svc_gw_compiled_table();
  int i;
  SD_REQUIRE(t != NULL);
  for (i = 0; i < SVC_GW_OS_COUNT; i++) {
    SD_CHECK_EQ_INT(t->system[i], SVC_GW_UNVERIFIED);
    SD_CHECK_EQ_INT(t->link[i], SVC_GW_UNVERIFIED);
  }
}

/* With the shipped table, auto is attach on every supported family (the go/no-go outcome of the spike). */
SD_TEST(gw_auto_is_attach_on_every_family_until_a_lab_go)
{
  svc_gw_family f;
  for (f = SVC_GW_OS_XP_2003; f < SVC_GW_OS_COUNT; f++) {
    svc_gw_input in;
    svc_gw_verdict v;
    ready(&in, f, SVC_GW_MODE_AUTO);
    svc_gw_decide(&in, &v);
    SD_CHECK_EQ_INT(v.mech, SVC_GW_ATTACH);
    SD_CHECK_EQ_INT(v.reason, SVC_GW_R_OK);
  }
}

/* An explicit system or link request for a cell that is not GO is refused. It does not degrade to attach. */
SD_TEST(gw_explicit_system_and_link_refuse_unverified_cells)
{
  svc_gw_family f;
  for (f = SVC_GW_OS_XP_2003; f < SVC_GW_OS_COUNT; f++) {
    svc_gw_input in;
    svc_gw_verdict v;
    ready(&in, f, SVC_GW_MODE_SYSTEM);
    svc_gw_decide(&in, &v);
    SD_CHECK_EQ_INT(v.mech, SVC_GW_REFUSE);
    SD_CHECK_EQ_INT(v.reason, SVC_GW_R_NOT_VERIFIED_SYSTEM);
    ready(&in, f, SVC_GW_MODE_LINK);
    svc_gw_decide(&in, &v);
    SD_CHECK_EQ_INT(v.mech, SVC_GW_REFUSE);
    SD_CHECK_EQ_INT(v.reason, SVC_GW_R_NOT_VERIFIED_LINK);
  }
}

/* Injected tables: a GO cell is chosen, system before link, a NOGO cell is never chosen. */
SD_TEST(gw_go_cells_select_system_then_link)
{
  svc_gw_table t;
  svc_gw_input in;
  svc_gw_verdict v;

  go_table(&t);
  t.system[SVC_GW_OS_XP_2003] = SVC_GW_GO;
  t.link[SVC_GW_OS_VISTA_7] = SVC_GW_GO;
  t.system[SVC_GW_OS_10_11] = SVC_GW_NOGO;
  t.link[SVC_GW_OS_10_11] = SVC_GW_GO;
  t.system[SVC_GW_OS_8_81] = SVC_GW_GO;
  t.link[SVC_GW_OS_8_81] = SVC_GW_GO;

  ready(&in, SVC_GW_OS_XP_2003, SVC_GW_MODE_AUTO);
  svc_gw_decide_with(&t, &in, &v);
  SD_CHECK_EQ_INT(v.mech, SVC_GW_SYSTEM);

  ready(&in, SVC_GW_OS_VISTA_7, SVC_GW_MODE_AUTO);
  svc_gw_decide_with(&t, &in, &v);
  SD_CHECK_EQ_INT(v.mech, SVC_GW_LINK);

  ready(&in, SVC_GW_OS_10_11, SVC_GW_MODE_AUTO);
  svc_gw_decide_with(&t, &in, &v);
  SD_CHECK_EQ_INT(v.mech, SVC_GW_LINK);
  ready(&in, SVC_GW_OS_10_11, SVC_GW_MODE_SYSTEM);
  svc_gw_decide_with(&t, &in, &v);
  SD_CHECK_EQ_INT(v.mech, SVC_GW_REFUSE);
  SD_CHECK_EQ_INT(v.reason, SVC_GW_R_NOT_VERIFIED_SYSTEM);

  ready(&in, SVC_GW_OS_8_81, SVC_GW_MODE_AUTO);
  svc_gw_decide_with(&t, &in, &v);
  SD_CHECK_EQ_INT(v.mech, SVC_GW_SYSTEM);

  /* an explicit GO choice is honored, and attach is still available on the same OS */
  ready(&in, SVC_GW_OS_VISTA_7, SVC_GW_MODE_LINK);
  svc_gw_decide_with(&t, &in, &v);
  SD_CHECK_EQ_INT(v.mech, SVC_GW_LINK);
  ready(&in, SVC_GW_OS_VISTA_7, SVC_GW_MODE_ATTACH);
  svc_gw_decide_with(&t, &in, &v);
  SD_CHECK_EQ_INT(v.mech, SVC_GW_ATTACH);
}

/* TM-R19: token-only is refused for every global mount, whatever the mode, the table or the state. */
SD_TEST(gw_token_only_is_refused_for_global_mounts)
{
  svc_gw_table t;
  svc_gw_family f;
  svc_gw_mode m;
  go_table(&t);
  for (f = SVC_GW_OS_XP_2003; f < SVC_GW_OS_COUNT; f++) {
    for (m = SVC_GW_MODE_AUTO; m <= SVC_GW_MODE_ATTACH; m++) {
      svc_gw_input in;
      svc_gw_verdict v;
      t.system[f] = SVC_GW_GO;
      t.link[f] = SVC_GW_GO;
      ready(&in, f, m);
      in.token_only = 1;
      svc_gw_decide_with(&t, &in, &v);
      SD_CHECK_EQ_INT(v.mech, SVC_GW_REFUSE);
      SD_CHECK_EQ_INT(v.reason, SVC_GW_R_TOKEN_ONLY);
      SD_CHECK_STR(svc_gw_reason_code(v.reason), "usage");
    }
  }
}

/* The refusals of the machine state, one at a time, and the order they are checked in. */
SD_TEST(gw_machine_state_refusals)
{
  svc_gw_input in;
  svc_gw_verdict v;

  ready(&in, SVC_GW_OS_VISTA_7, SVC_GW_MODE_AUTO);
  in.service_running = 0;
  svc_gw_decide(&in, &v);
  SD_CHECK_EQ_INT(v.mech, SVC_GW_REFUSE);
  SD_CHECK_EQ_INT(v.reason, SVC_GW_R_SERVICE_DOWN);

  ready(&in, SVC_GW_OS_UNKNOWN, SVC_GW_MODE_AUTO);
  svc_gw_decide(&in, &v);
  SD_CHECK_EQ_INT(v.reason, SVC_GW_R_OS);

  ready(&in, SVC_GW_OS_VISTA_7, SVC_GW_MODE_INVALID);
  svc_gw_decide(&in, &v);
  SD_CHECK_EQ_INT(v.reason, SVC_GW_R_MODE);

  ready(&in, SVC_GW_OS_XP_2003, SVC_GW_MODE_AUTO);
  in.client = SVC_GW_CLIENT_MISSING;
  svc_gw_decide(&in, &v);
  SD_CHECK_EQ_INT(v.reason, SVC_GW_R_CLIENT_MISSING);
  in.client = SVC_GW_CLIENT_DISABLED;
  svc_gw_decide(&in, &v);
  SD_CHECK_EQ_INT(v.reason, SVC_GW_R_CLIENT_DISABLED);
  in.client = SVC_GW_CLIENT_UNKNOWN;
  svc_gw_decide(&in, &v);
  SD_CHECK_EQ_INT(v.reason, SVC_GW_R_CLIENT_UNKNOWN);

  /* stopped is fine: the mount starts WebClient (02 §7.2) */
  in.client = SVC_GW_CLIENT_STOPPED;
  svc_gw_decide(&in, &v);
  SD_CHECK_EQ_INT(v.mech, SVC_GW_ATTACH);

  /* order: token-only first, then the mode, then the service, then the OS, then the client */
  ready(&in, SVC_GW_OS_UNKNOWN, SVC_GW_MODE_INVALID);
  in.service_running = 0;
  in.token_only = 1;
  svc_gw_decide(&in, &v);
  SD_CHECK_EQ_INT(v.reason, SVC_GW_R_TOKEN_ONLY);
  in.token_only = 0;
  svc_gw_decide(&in, &v);
  SD_CHECK_EQ_INT(v.reason, SVC_GW_R_MODE);
  in.mode = SVC_GW_MODE_AUTO;
  svc_gw_decide(&in, &v);
  SD_CHECK_EQ_INT(v.reason, SVC_GW_R_SERVICE_DOWN);
  in.service_running = 1;
  svc_gw_decide(&in, &v);
  SD_CHECK_EQ_INT(v.reason, SVC_GW_R_OS);
}

SD_TEST(gw_reason_codes_use_the_ipc_vocabulary)
{
  SD_CHECK_STR(svc_gw_reason_code(SVC_GW_R_OK), "");
  SD_CHECK_STR(svc_gw_reason_code(SVC_GW_R_MODE), "usage");
  SD_CHECK_STR(svc_gw_reason_code(SVC_GW_R_CLIENT_DISABLED), "webclient_disabled");
  SD_CHECK_STR(svc_gw_reason_code(SVC_GW_R_CLIENT_MISSING), "backend_unavailable");
  SD_CHECK_STR(svc_gw_reason_code(SVC_GW_R_NOT_VERIFIED_LINK), "backend_unavailable");
  SD_CHECK_STR(svc_gw_mech_name(SVC_GW_ATTACH), "attach");
  SD_CHECK_STR(svc_gw_mech_name(SVC_GW_REFUSE), "refuse");
}

/* ---- attach seam ---- */

typedef struct fake_attach {
  int calls;
  wchar_t letter;
  wchar_t remote[256];
  int xp;
  DWORD rc;
  int cancel_calls;
} fake_attach;

static DWORD fake_add(void *ctx, wchar_t letter, const wchar_t *remote, int xp_form)
{
  fake_attach *f = (fake_attach *)ctx;
  f->calls++;
  f->letter = letter;
  {
    size_t i = 0;
    while (i < 255 && remote[i] != 0) {
      f->remote[i] = remote[i];
      i++;
    }
    f->remote[i] = 0;
  }
  f->xp = xp_form;
  return f->rc;
}

static DWORD fake_cancel(void *ctx, wchar_t letter)
{
  fake_attach *f = (fake_attach *)ctx;
  (void)letter;
  f->cancel_calls++;
  return f->rc;
}

static void fake_ops(svc_gw_attach_ops *ops, fake_attach *f)
{
  ops->ctx = f;
  ops->add = fake_add;
  ops->cancel = fake_cancel;
}

SD_TEST(gw_attach_remote_shapes)
{
  SD_CHECK(svc_gw_attach_remote_ok(L"\\\\localhost@8080\\DavWWWRoot\\s-abcdefghijklmnopqrstuvwxy2", 0));
  SD_CHECK(svc_gw_attach_remote_ok(L"\\\\localhost@1\\DavWWWRoot\\s-aaaaaaaaaaaaaaaaaaaaaaaaaa", 0));
  SD_CHECK(svc_gw_attach_remote_ok(L"http://localhost:49152/s-abcdefghijklmnopqrstuvwxy2", 1));
  SD_CHECK(svc_gw_attach_remote_ok(L"\\\\localhost@65535\\DavWWWRoot\\s-abcdefghijklmnopqrstuvwxy2", 0));

  /* refused: wrong port, host, token length or alphabet, extra segments, wrong form for the flag, NULL */
  SD_CHECK(!svc_gw_attach_remote_ok(L"\\\\localhost@0\\DavWWWRoot\\s-abcdefghijklmnopqrstuvwxy2", 0));
  SD_CHECK(!svc_gw_attach_remote_ok(L"\\\\localhost@065\\DavWWWRoot\\s-abcdefghijklmnopqrstuvwxy2", 0));
  SD_CHECK(!svc_gw_attach_remote_ok(L"\\\\localhost@65536\\DavWWWRoot\\s-abcdefghijklmnopqrstuvwxy2", 0));
  SD_CHECK(!svc_gw_attach_remote_ok(L"\\\\example.com@8080\\DavWWWRoot\\s-abcdefghijklmnopqrstuvwxy2", 0));
  SD_CHECK(!svc_gw_attach_remote_ok(L"\\\\localhost@8080\\DavWWWRoot\\s-abcdefghijklmnopqrstuvwxy", 0));
  SD_CHECK(!svc_gw_attach_remote_ok(L"\\\\localhost@8080\\DavWWWRoot\\s-abcdefghijklmnopqrstuvwxy2a", 0));
  SD_CHECK(!svc_gw_attach_remote_ok(L"\\\\localhost@8080\\DavWWWRoot\\s-ABCDEFGHIJKLMNOPQRSTUVWXY2", 0));
  SD_CHECK(!svc_gw_attach_remote_ok(L"\\\\localhost@8080\\DavWWWRoot\\s-abcdefghijklmnopqrstuvwx18", 0));
  SD_CHECK(!svc_gw_attach_remote_ok(L"\\\\localhost@8080\\DavWWWRoot\\s-abcdefghijklmnopqrstuvwxy2\\sub", 0));
  SD_CHECK(!svc_gw_attach_remote_ok(L"http://localhost:8080/s-abcdefghijklmnopqrstuvwxy2", 0));
  SD_CHECK(!svc_gw_attach_remote_ok(L"\\\\localhost@8080\\DavWWWRoot\\s-abcdefghijklmnopqrstuvwxy2", 1));
  SD_CHECK(!svc_gw_attach_remote_ok(NULL, 0));
}

SD_TEST(gw_attach_map_calls_the_seam_with_the_xp_form_flag)
{
  fake_attach f;
  svc_gw_attach_ops ops;
  DWORD rc = 1;
  sd_err e;
  memset(&f, 0, sizeof(f));
  fake_ops(&ops, &f);

  e = svc_gw_attach_map(&ops, L'Z', L"\\\\localhost@8080\\DavWWWRoot\\s-abcdefghijklmnopqrstuvwxy2", 0, &rc);
  SD_CHECK_EQ_INT(e, SD_OK);
  SD_CHECK_EQ_INT(rc, NO_ERROR);
  SD_CHECK_EQ_INT(f.calls, 1);
  SD_CHECK(f.letter == L'Z');
  SD_CHECK(f.xp == 0);
  SD_CHECK(wcscmp(f.remote, L"\\\\localhost@8080\\DavWWWRoot\\s-abcdefghijklmnopqrstuvwxy2") == 0);

  f.calls = 0;
  e = svc_gw_attach_map(&ops, L'Y', L"http://localhost:49152/s-abcdefghijklmnopqrstuvwxy2", 1, &rc);
  SD_CHECK_EQ_INT(e, SD_OK);
  SD_CHECK(f.xp == 1);
  SD_CHECK(f.letter == L'Y');
}

SD_TEST(gw_attach_map_refuses_bad_input_without_calling_the_seam)
{
  fake_attach f;
  svc_gw_attach_ops ops;
  sd_err e;
  memset(&f, 0, sizeof(f));
  fake_ops(&ops, &f);

  e = svc_gw_attach_map(&ops, L'z', L"\\\\localhost@8080\\DavWWWRoot\\s-abcdefghijklmnopqrstuvwxy2", 0, NULL);
  SD_CHECK_EQ_INT(e, SD_E_INVALID_PARAM);                 /* lower-case letter */
  e = svc_gw_attach_map(&ops, L'1', L"\\\\localhost@8080\\DavWWWRoot\\s-abcdefghijklmnopqrstuvwxy2", 0, NULL);
  SD_CHECK_EQ_INT(e, SD_E_INVALID_PARAM);
  e = svc_gw_attach_map(&ops, L'Z', L"\\\\example.com\\share", 0, NULL);
  SD_CHECK_EQ_INT(e, SD_E_INVALID_PARAM);
  e = svc_gw_attach_map(NULL, L'Z', L"\\\\localhost@8080\\DavWWWRoot\\s-abcdefghijklmnopqrstuvwxy2", 0, NULL);
  SD_CHECK_EQ_INT(e, SD_E_INVALID_PARAM);
  SD_CHECK_EQ_INT(f.calls, 0);
}

SD_TEST(gw_attach_map_maps_win32_errors)
{
  fake_attach f;
  svc_gw_attach_ops ops;
  DWORD rc = 0;
  sd_err e;
  memset(&f, 0, sizeof(f));
  fake_ops(&ops, &f);

  f.rc = ERROR_ALREADY_ASSIGNED;
  e = svc_gw_attach_map(&ops, L'Z', L"\\\\localhost@8080\\DavWWWRoot\\s-abcdefghijklmnopqrstuvwxy2", 0, &rc);
  SD_CHECK_EQ_INT(e, SD_E_EXISTS);
  SD_CHECK_EQ_INT(rc, ERROR_ALREADY_ASSIGNED);

  f.rc = ERROR_BAD_NETPATH;
  e = svc_gw_attach_map(&ops, L'Z', L"\\\\localhost@8080\\DavWWWRoot\\s-abcdefghijklmnopqrstuvwxy2", 0, &rc);
  SD_CHECK_EQ_INT(e, SD_E_FAILURE);
  SD_CHECK_EQ_INT(rc, ERROR_BAD_NETPATH);
}

SD_TEST(gw_attach_unmap_calls_cancel)
{
  fake_attach f;
  svc_gw_attach_ops ops;
  DWORD rc = 0;
  memset(&f, 0, sizeof(f));
  fake_ops(&ops, &f);
  SD_CHECK_EQ_INT(svc_gw_attach_unmap(&ops, L'Z', &rc), SD_OK);
  SD_CHECK_EQ_INT(f.cancel_calls, 1);
  f.rc = ERROR_NOT_CONNECTED;
  SD_CHECK_EQ_INT(svc_gw_attach_unmap(&ops, L'Z', &rc), SD_E_FAILURE);
  SD_CHECK_EQ_INT(rc, ERROR_NOT_CONNECTED);
  SD_CHECK_EQ_INT(svc_gw_attach_unmap(&ops, L'!', NULL), SD_E_INVALID_PARAM);
}
