/* sd_webdav server over raw loopback sockets: the pre-authentication gate (Host, Origin/Sec-Fetch 403,
 * token 404 before 401, challenge), SSPI Negotiate with the caller SID check (owner mismatch -> 403),
 * slowloris deadlines and unauthenticated-connection quotas (TM-R20), and the WebDAV methods against
 * the fake-backed sd_vfs. */
#define _CRT_SECURE_NO_WARNINGS /* test code: sprintf into sized buffers */
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "fake_sftp.h"
#include "sd_base/sd_mem.h"
#include "sd_platform/sd_time.h"
#include "sd_test.h"
#include "sd_webdav/sd_webdav.h"
#include "wd_client_util.h"

typedef struct fixture {
  sd_sftp_session *s;
  sd_vfs *v;
  sd_webdav_server *srv;
  sd_webdav_export *ex;
  uint16_t port;
  char prefix[64];
} fixture;

static int fx_up(fixture *f, const sd_webdav_server_cfg *override, BOOL read_only)
{
  sd_vfs_options o;
  sd_webdav_server_cfg sc;
  sd_webdav_export_cfg ec;
  memset(f, 0, sizeof(*f));
  f->s = fake_session_create(NULL);
  fake_put(f->s, "/home/user/hello.txt", "hello world", 11, 0644);
  fake_mkdir(f->s, "/home/user/docs", 0755);
  fake_put(f->s, "/home/user/docs/a.txt", "AAAA", 4, 0644);
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
  if (override) {
    sc = *override;
  } else {
    memset(&sc, 0, sizeof(sc));
  }
  sc.struct_size = sizeof(sc);
  sc.no_ipv6 = FALSE;
  if (sd_webdav_server_start(&sc, &f->srv) != SD_OK)
    return -1;
  f->port = sd_webdav_server_port(f->srv);
  memset(&ec, 0, sizeof(ec));
  ec.struct_size = sizeof(ec);
  ec.read_only = read_only;
  ec.label = L"Test";
  if (sd_webdav_export_add(f->srv, f->v, &ec, &f->ex) != SD_OK)
    return -1;
  strcpy_s(f->prefix, sizeof(f->prefix), sd_webdav_export_prefix(f->ex));
  return 0;
}

static void fx_down(fixture *f)
{
  if (f->ex) sd_webdav_export_remove(f->ex);
  if (f->srv) sd_webdav_server_stop(f->srv);
  if (f->v) {
    sd_vfs_quiesce(f->v, 5000);
    sd_vfs_unmount(f->v);
  }
  if (f->s) fake_session_destroy(f->s);
}

static tc_conn *conn_new(uint16_t port)
{
  tc_conn *c = (tc_conn *)sd_calloc(1, sizeof(tc_conn));
  if (c && tc_connect(c, port, 0) != 0) {
    sd_free(c);
    return NULL;
  }
  return c;
}

static void conn_free(tc_conn *c)
{
  if (c) {
    tc_close(c);
    sd_free(c);
  }
}

static int raw(tc_conn *c, const char *req, tc_resp *r)
{
  if (tc_send(c, req, strlen(req)) != 0)
    return -1;
  return tc_read(c, r, 0, 10000);
}

SD_TEST(webdav_server_gate_before_auth)
{
  fixture f;
  tc_conn *c;
  tc_resp r;
  char req[1024], v[256];
  SD_REQUIRE(fx_up(&f, NULL, FALSE) == 0);
  c = conn_new(f.port);
  SD_REQUIRE(c != NULL);
  /* OPTIONS needs no authentication and advertises DAV (XP needs it on "/") */
  SD_REQUIRE(tc_request(c, f.port, "OPTIONS", "/", NULL, NULL, 0, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 200);
  SD_CHECK(tc_header(&r, "DAV", v, sizeof(v)) && strcmp(v, "1, 2") == 0);
  SD_CHECK(tc_header(&r, "Allow", v, sizeof(v)) && strstr(v, "LOCK") != NULL && strstr(v, "PUT") != NULL);
  tc_resp_free(&r);
  /* unknown or malformed prefix: 404 without a challenge */
  SD_REQUIRE(tc_request(c, f.port, "PROPFIND", "/s-aaaaaaaaaaaaaaaaaaaaaaaaaa/", "Depth: 0\r\n", NULL, 0, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 404);
  SD_CHECK(!tc_header(&r, "WWW-Authenticate", v, sizeof(v)));
  tc_resp_free(&r);
  SD_REQUIRE(tc_request(c, f.port, "GET", "/_vti_inf.html", NULL, NULL, 0, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 404);
  tc_resp_free(&r);
  /* valid prefix without credentials: 401 with both schemes */
  _snprintf_s(req, sizeof(req), _TRUNCATE, "%s/", f.prefix);
  SD_REQUIRE(tc_request(c, f.port, "PROPFIND", req, "Depth: 0\r\n", NULL, 0, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 401);
  SD_CHECK(strstr(r.head, "WWW-Authenticate: Negotiate\r\n") != NULL);
  SD_CHECK(strstr(r.head, "WWW-Authenticate: NTLM\r\n") != NULL);
  SD_CHECK(!r.closed);
  tc_resp_free(&r);
  /* a body before authentication is drained (<= 64 KiB) and the connection stays usable */
  {
    static char body[1000];
    memset(body, 'x', sizeof(body));
    SD_REQUIRE(tc_request(c, f.port, "PUT", req, NULL, body, sizeof(body), &r) == 0);
    SD_CHECK_EQ_INT(r.status, 401);
    tc_resp_free(&r);
    SD_REQUIRE(tc_request(c, f.port, "OPTIONS", req, NULL, NULL, 0, &r) == 0);
    SD_CHECK_EQ_INT(r.status, 200);
    tc_resp_free(&r);
  }
  conn_free(c);

  /* Origin / Sec-Fetch-*: 403 before the token check, no challenge, connection closed */
  c = conn_new(f.port);
  SD_REQUIRE(c != NULL);
  _snprintf_s(req, sizeof(req), _TRUNCATE, "PROPFIND %s/ HTTP/1.1\r\nHost: localhost:%u\r\nOrigin: http://evil\r\n\r\n",
              f.prefix, (unsigned)f.port);
  SD_REQUIRE(raw(c, req, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 403);
  SD_CHECK(!tc_header(&r, "WWW-Authenticate", v, sizeof(v)));
  tc_resp_free(&r);
  SD_CHECK(tc_wait_closed(c, 3000));
  conn_free(c);
  c = conn_new(f.port);
  SD_REQUIRE(c != NULL);
  _snprintf_s(req, sizeof(req), _TRUNCATE, "GET /s-bbbbbbbbbbbbbbbbbbbbbbbbbb/x HTTP/1.1\r\nHost: localhost:%u\r\n"
              "Sec-Fetch-Mode: no-cors\r\n\r\n", (unsigned)f.port);
  SD_REQUIRE(raw(c, req, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 403);                     /* not 404: nothing learned about prefixes */
  tc_resp_free(&r);
  conn_free(c);

  /* Host header: DNS rebinding and duplicates */
  {
    static const char *const hosts[] = { "Host: evil.example:%u\r\n", "Host: localhost:1\r\n",
                                         "Host: localhost:%u\r\nHost: localhost:%u\r\n", "" };
    size_t i;
    for (i = 0; i < SD_COUNTOF(hosts); i++) {
      char hl[128];
      c = conn_new(f.port);
      SD_REQUIRE(c != NULL);
      _snprintf_s(hl, sizeof(hl), _TRUNCATE, hosts[i], (unsigned)f.port, (unsigned)f.port);
      _snprintf_s(req, sizeof(req), _TRUNCATE, "OPTIONS / HTTP/1.1\r\n%s\r\n", hl);
      SD_REQUIRE(raw(c, req, &r) == 0);
      SD_CHECK_EQ_INT(r.status, 400);
      tc_resp_free(&r);
      conn_free(c);
    }
  }
  /* bad targets: 400 */
  {
    static const char *const targets[] = { "/s-x/%2e%2e/", "/a%2Fb", "/x?y", "//", "/%00" };
    size_t i;
    for (i = 0; i < SD_COUNTOF(targets); i++) {
      c = conn_new(f.port);
      SD_REQUIRE(c != NULL);
      SD_REQUIRE(tc_request(c, f.port, "PROPFIND", targets[i], NULL, NULL, 0, &r) == 0);
      SD_CHECK_EQ_INT(r.status, 400);
      tc_resp_free(&r);
      conn_free(c);
    }
  }
  /* request line / header limits */
  {
    char *big = (char *)sd_alloc(40000);
    size_t o;
    SD_REQUIRE(big != NULL);
    c = conn_new(f.port);
    SD_REQUIRE(c != NULL);
    o = (size_t)sprintf(big, "GET / HTTP/1.1\r\nHost: localhost:%u\r\nX: ", (unsigned)f.port);
    memset(big + o, 'a', 33000);
    o += 33000;
    memcpy(big + o, "\r\n\r\n", 5);
    SD_REQUIRE(raw(c, big, &r) == 0);
    SD_CHECK_EQ_INT(r.status, 431);
    tc_resp_free(&r);
    SD_CHECK(tc_wait_closed(c, 3000));
    conn_free(c);
    sd_free(big);
  }
  /* a large body before authentication closes the connection after the 401 */
  {
    c = conn_new(f.port);
    SD_REQUIRE(c != NULL);
    _snprintf_s(req, sizeof(req), _TRUNCATE, "PUT %s/big HTTP/1.1\r\nHost: localhost:%u\r\nContent-Length: 1000000\r\n\r\n",
                f.prefix, (unsigned)f.port);
    SD_REQUIRE(raw(c, req, &r) == 0);
    SD_CHECK_EQ_INT(r.status, 401);
    SD_CHECK(r.closed);
    tc_resp_free(&r);
    conn_free(c);
  }
  fx_down(&f);
}

static int request_auth(tc_conn *c, const fixture *f, const char *method, const char *rel, const char *extra,
                        const void *body, size_t n, tc_resp *r)
{
  char path[1024];
  _snprintf_s(path, sizeof(path), _TRUNCATE, "%s%s", f->prefix, rel);
  return tc_request(c, f->port, method, path, extra, body, n, r);
}

SD_TEST(webdav_server_auth_and_methods)
{
  fixture f;
  tc_conn *c;
  tc_resp r;
  char v[512], extra[512], tok[128];
  long long n;
  char buf[64];
  SD_REQUIRE(fx_up(&f, NULL, FALSE) == 0);
  c = conn_new(f.port);
  SD_REQUIRE(c != NULL);
  SD_REQUIRE(tc_authenticate(c, f.port, f.prefix) == 207);
  /* the connection stays authenticated */
  SD_REQUIRE(request_auth(c, &f, "PROPFIND", "/", "Depth: 1\r\n", NULL, 0, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 207);
  SD_CHECK(strstr(r.body, "hello.txt") != NULL);
  SD_CHECK(strstr(r.body, "docs/</D:href>") != NULL);
  SD_CHECK(strstr(r.body, "<D:collection/>") != NULL);
  SD_CHECK(strstr(r.body, "Win32FileAttributes") != NULL);
  tc_resp_free(&r);
  /* infinite depth is refused */
  SD_REQUIRE(request_auth(c, &f, "PROPFIND", "/", NULL, NULL, 0, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 403);
  SD_CHECK(strstr(r.body, "propfind-finite-depth") != NULL);
  tc_resp_free(&r);
  /* prop request with an unknown property and quota on the root */
  {
    static const char pf[] = "<?xml version=\"1.0\"?><D:propfind xmlns:D=\"DAV:\"><D:prop><D:quota-available-bytes/>"
                             "<D:getcontentlength/><F:nope xmlns:F=\"urn:x\"/></D:prop></D:propfind>";
    SD_REQUIRE(request_auth(c, &f, "PROPFIND", "/", "Depth: 0\r\n", pf, sizeof(pf) - 1, &r) == 0);
    SD_CHECK_EQ_INT(r.status, 207);
    SD_CHECK(strstr(r.body, "quota-available-bytes>") != NULL);
    SD_CHECK(strstr(r.body, "404 Not Found") != NULL);
    tc_resp_free(&r);
  }
  /* GET, HEAD, Range */
  SD_REQUIRE(request_auth(c, &f, "GET", "/hello.txt", NULL, NULL, 0, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 200);
  SD_CHECK(r.body_n == 11 && memcmp(r.body, "hello world", 11) == 0);
  SD_CHECK(tc_header(&r, "ETag", v, sizeof(v)));
  tc_resp_free(&r);
  SD_REQUIRE(request_auth(c, &f, "GET", "/hello.txt", "Range: bytes=6-\r\n", NULL, 0, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 206);
  SD_CHECK(r.body_n == 5 && memcmp(r.body, "world", 5) == 0);
  SD_CHECK(tc_header(&r, "Content-Range", v, sizeof(v)) && strcmp(v, "bytes 6-10/11") == 0);
  tc_resp_free(&r);
  SD_REQUIRE(request_auth(c, &f, "GET", "/hello.txt", "Range: bytes=50-\r\n", NULL, 0, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 416);
  tc_resp_free(&r);
  SD_REQUIRE(request_auth(c, &f, "HEAD", "/hello.txt", NULL, NULL, 0, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 200);
  SD_CHECK(tc_header(&r, "Content-Length", v, sizeof(v)) && strcmp(v, "11") == 0);
  tc_resp_free(&r);
  SD_REQUIRE(request_auth(c, &f, "GET", "/missing", NULL, NULL, 0, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 404);
  tc_resp_free(&r);
  /* PUT new (201), replace (204), chunked */
  SD_REQUIRE(request_auth(c, &f, "PUT", "/new.bin", NULL, "0123456789", 10, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 201);
  tc_resp_free(&r);
  n = fake_get(f.s, "/home/user/new.bin", buf, sizeof(buf));
  SD_CHECK(n == 10 && memcmp(buf, "0123456789", 10) == 0);
  {
    char req[512];
    static const char chunks[] = "3\r\nabc\r\n2;x=y\r\nde\r\n0\r\n\r\n";
    _snprintf_s(req, sizeof(req), _TRUNCATE, "PUT %s/new.bin HTTP/1.1\r\nHost: localhost:%u\r\n"
                "Transfer-Encoding: chunked\r\n\r\n", f.prefix, (unsigned)f.port);
    SD_REQUIRE(tc_send(c, req, strlen(req)) == 0);
    SD_REQUIRE(tc_send(c, chunks, sizeof(chunks) - 1) == 0);
    SD_REQUIRE(tc_read(c, &r, 0, 5000) == 0);
    SD_CHECK_EQ_INT(r.status, 204);
    tc_resp_free(&r);
    n = fake_get(f.s, "/home/user/new.bin", buf, sizeof(buf));
    SD_CHECK(n == 5 && memcmp(buf, "abcde", 5) == 0);
  }
  /* MKCOL, MOVE, COPY, DELETE */
  SD_REQUIRE(request_auth(c, &f, "MKCOL", "/dir%20one", NULL, NULL, 0, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 201);
  tc_resp_free(&r);
  SD_REQUIRE(request_auth(c, &f, "MKCOL", "/dir%20one", NULL, NULL, 0, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 405);
  tc_resp_free(&r);
  SD_REQUIRE(request_auth(c, &f, "MKCOL", "/nope/sub", NULL, NULL, 0, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 409);
  tc_resp_free(&r);
  _snprintf_s(extra, sizeof(extra), _TRUNCATE, "Destination: http://localhost:%u%s/dir%%20one/moved.bin\r\n",
              (unsigned)f.port, f.prefix);
  SD_REQUIRE(request_auth(c, &f, "MOVE", "/new.bin", extra, NULL, 0, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 201);
  tc_resp_free(&r);
  SD_CHECK(fake_exists(f.s, "/home/user/dir one/moved.bin"));
  SD_CHECK(!fake_exists(f.s, "/home/user/new.bin"));
  _snprintf_s(extra, sizeof(extra), _TRUNCATE, "Destination: http://localhost:%u%s/hello.txt\r\nOverwrite: F\r\n",
              (unsigned)f.port, f.prefix);
  SD_REQUIRE(request_auth(c, &f, "MOVE", "/dir%20one/moved.bin", extra, NULL, 0, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 412);
  tc_resp_free(&r);
  _snprintf_s(extra, sizeof(extra), _TRUNCATE, "Destination: http://localhost:%u/s-cccccccccccccccccccccccccc/x\r\n",
              (unsigned)f.port);
  SD_REQUIRE(request_auth(c, &f, "MOVE", "/dir%20one/moved.bin", extra, NULL, 0, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 502);                     /* another token */
  tc_resp_free(&r);
  /* M1 acceptance regression: a case-only MOVE (Explorer/PowerShell "Case.txt" -> "case.TXT") was 403
     because the case-insensitive same-resource check caught it; it is a rename. MOVE onto the exact
     same URL stays 403. */
  _snprintf_s(extra, sizeof(extra), _TRUNCATE, "Destination: http://localhost:%u%s/dir%%20one/Moved.BIN\r\n",
              (unsigned)f.port, f.prefix);
  SD_REQUIRE(request_auth(c, &f, "MOVE", "/dir%20one/moved.bin", extra, NULL, 0, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 201);
  tc_resp_free(&r);
  SD_CHECK(fake_exists(f.s, "/home/user/dir one/Moved.BIN"));
  SD_CHECK(!fake_exists(f.s, "/home/user/dir one/moved.bin"));
  SD_REQUIRE(request_auth(c, &f, "MOVE", "/dir%20one/Moved.BIN", extra, NULL, 0, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 403);
  tc_resp_free(&r);
  _snprintf_s(extra, sizeof(extra), _TRUNCATE, "Destination: http://localhost:%u%s/copy\r\n", (unsigned)f.port, f.prefix);
  SD_REQUIRE(request_auth(c, &f, "COPY", "/docs", extra, NULL, 0, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 201);
  tc_resp_free(&r);
  n = fake_get(f.s, "/home/user/copy/a.txt", buf, sizeof(buf));
  SD_CHECK(n == 4 && memcmp(buf, "AAAA", 4) == 0);
  SD_REQUIRE(request_auth(c, &f, "DELETE", "/copy", NULL, NULL, 0, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 204);
  tc_resp_free(&r);
  SD_CHECK(!fake_exists(f.s, "/home/user/copy"));
  /* PROPPATCH Win32 times */
  {
    static const char pp[] = "<?xml version=\"1.0\"?><D:propertyupdate xmlns:D=\"DAV:\" xmlns:Z=\"urn:schemas-microsoft-com:\">"
                             "<D:set><D:prop><Z:Win32LastModifiedTime>Sun, 06 Nov 1994 08:49:37 GMT</Z:Win32LastModifiedTime>"
                             "<Z:Win32FileAttributes>00000020</Z:Win32FileAttributes><X:dead xmlns:X=\"urn:x\">1</X:dead>"
                             "</D:prop></D:set></D:propertyupdate>";
    SD_REQUIRE(request_auth(c, &f, "PROPPATCH", "/hello.txt", NULL, pp, sizeof(pp) - 1, &r) == 0);
    SD_CHECK_EQ_INT(r.status, 207);
    SD_CHECK(strstr(r.body, "200 OK") != NULL && strstr(r.body, "Win32LastModifiedTime") != NULL);
    tc_resp_free(&r);
    SD_CHECK_EQ_INT(fake_mtime(f.s, "/home/user/hello.txt"), 784111777);
  }
  /* LOCK / 423 / UNLOCK, LOCK on an unmapped URL creates the file */
  {
    static const char li[] = "<?xml version=\"1.0\"?><D:lockinfo xmlns:D=\"DAV:\"><D:lockscope><D:exclusive/></D:lockscope>"
                             "<D:locktype><D:write/></D:locktype><D:owner><D:href>me</D:href></D:owner></D:lockinfo>";
    SD_REQUIRE(request_auth(c, &f, "LOCK", "/hello.txt", "Timeout: Second-60\r\n", li, sizeof(li) - 1, &r) == 0);
    SD_CHECK_EQ_INT(r.status, 200);
    SD_REQUIRE(tc_header(&r, "Lock-Token", tok, sizeof(tok)));
    SD_CHECK(strstr(r.body, "<D:href>me</D:href>") != NULL);
    tc_resp_free(&r);
    SD_REQUIRE(request_auth(c, &f, "PUT", "/hello.txt", NULL, "x", 1, &r) == 0);
    SD_CHECK_EQ_INT(r.status, 423);
    tc_resp_free(&r);
    SD_REQUIRE(request_auth(c, &f, "LOCK", "/hello.txt", NULL, li, sizeof(li) - 1, &r) == 0);
    SD_CHECK_EQ_INT(r.status, 423);
    tc_resp_free(&r);
    _snprintf_s(extra, sizeof(extra), _TRUNCATE, "If: (%s)\r\n", tok);
    SD_REQUIRE(request_auth(c, &f, "PUT", "/hello.txt", extra, "locked", 6, &r) == 0);
    SD_CHECK_EQ_INT(r.status, 204);
    tc_resp_free(&r);
    SD_REQUIRE(request_auth(c, &f, "LOCK", "/hello.txt", extra, NULL, 0, &r) == 0);   /* refresh */
    SD_CHECK_EQ_INT(r.status, 200);
    tc_resp_free(&r);
    _snprintf_s(extra, sizeof(extra), _TRUNCATE, "Lock-Token: %s\r\n", tok);
    SD_REQUIRE(request_auth(c, &f, "UNLOCK", "/hello.txt", extra, NULL, 0, &r) == 0);
    SD_CHECK_EQ_INT(r.status, 204);
    tc_resp_free(&r);
    SD_REQUIRE(request_auth(c, &f, "UNLOCK", "/hello.txt", extra, NULL, 0, &r) == 0);
    SD_CHECK_EQ_INT(r.status, 409);
    tc_resp_free(&r);
    SD_REQUIRE(request_auth(c, &f, "LOCK", "/fresh.docx", NULL, li, sizeof(li) - 1, &r) == 0);
    SD_CHECK_EQ_INT(r.status, 201);
    tc_resp_free(&r);
    SD_CHECK(fake_exists(f.s, "/home/user/fresh.docx"));
  }
  /* unknown and unsupported methods */
  SD_REQUIRE(request_auth(c, &f, "POST", "/hello.txt", NULL, NULL, 0, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 405);
  tc_resp_free(&r);
  SD_REQUIRE(request_auth(c, &f, "SEARCH", "/", NULL, NULL, 0, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 501);
  tc_resp_free(&r);
  /* PROPFIND on "/" lists nothing */
  SD_REQUIRE(tc_request(c, f.port, "PROPFIND", "/", "Depth: 1\r\n", NULL, 0, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 207);
  SD_CHECK(strstr(r.body, f.prefix + 1) == NULL);
  tc_resp_free(&r);
  conn_free(c);
  fx_down(&f);
}

SD_TEST(webdav_server_rejects_other_sid)
{
  fixture f;
  sd_webdav_server_cfg sc;
  tc_conn *c;
  uint8_t sid[SECURITY_MAX_SID_SIZE];
  DWORD sl = sizeof(sid);
  SD_REQUIRE(CreateWellKnownSid(WinLocalSystemSid, NULL, sid, &sl));
  memset(&sc, 0, sizeof(sc));
  sc.owner_sid = (PSID)sid;
  SD_REQUIRE(fx_up(&f, &sc, FALSE) == 0);
  c = conn_new(f.port);
  SD_REQUIRE(c != NULL);
  SD_CHECK_EQ_INT(tc_authenticate(c, f.port, f.prefix), 403);   /* authenticated, but not the owner */
  SD_CHECK(tc_wait_closed(c, 3000));
  conn_free(c);
  fx_down(&f);
}

/* 02 §7.7: a service (global) server. The vfs is global with access_sid as the only service_access entry, the
   server's owner is SYSTEM and service_mode is on, so the connection-level owner check is off and sd_vfs decides. */
static int fx_up_service(fixture *f, PSID access_sid)
{
  sd_vfs_options o;
  sd_webdav_server_cfg sc;
  sd_webdav_export_cfg ec;
  static uint8_t system_sid[SECURITY_MAX_SID_SIZE];
  DWORD sl = sizeof(system_sid);
  PSID acc[1];
  memset(f, 0, sizeof(*f));
  if (!CreateWellKnownSid(WinLocalSystemSid, NULL, system_sid, &sl))
    return -1;
  f->s = fake_session_create(NULL);
  fake_put(f->s, "/home/user/hello.txt", "hello world", 11, 0644);
  memset(&o, 0, sizeof(o));
  o.struct_size = sizeof(o);
  o.request_timeout_ms = 50000;
  o.volume_label = L"SD Global";
  o.global_mount = TRUE;
  acc[0] = access_sid;
  o.access_sids = acc;
  o.n_access = 1;
  if (sd_vfs_mount(f->s, &o, NULL, NULL, &f->v) != SD_VFS_OK)
    return -1;
  memset(&sc, 0, sizeof(sc));
  sc.struct_size = sizeof(sc);
  sc.owner_sid = (PSID)system_sid;
  sc.service_mode = TRUE;
  if (sd_webdav_server_start(&sc, &f->srv) != SD_OK)
    return -1;
  f->port = sd_webdav_server_port(f->srv);
  memset(&ec, 0, sizeof(ec));
  ec.struct_size = sizeof(ec);
  ec.label = L"Global";
  if (sd_webdav_export_add(f->srv, f->v, &ec, &f->ex) != SD_OK)
    return -1;
  strcpy_s(f->prefix, sizeof(f->prefix), sd_webdav_export_prefix(f->ex));
  return 0;
}

/* The token user of this process, in a static buffer. */
static PSID self_sid(void)
{
  static uint8_t buf[256];
  HANDLE tok = NULL;
  DWORD n = 0;
  PSID s = NULL;
  if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
    if (GetTokenInformation(tok, TokenUser, buf, sizeof(buf), &n))
      s = ((TOKEN_USER *)buf)->User.Sid;
    CloseHandle(tok);
  }
  return s;
}

/* 02 §7.7, G7 shape: a member of service_access reaches the export of a service server whose owner is SYSTEM (the
   per-user server answers 403 here, webdav_server_rejects_other_sid). */
SD_TEST(webdav_service_server_admits_a_member)
{
  fixture f;
  tc_conn *c;
  PSID me = self_sid();
  SD_REQUIRE(me != NULL);
  SD_REQUIRE(fx_up_service(&f, me) == 0);
  c = conn_new(f.port);
  SD_REQUIRE(c != NULL);
  SD_CHECK_EQ_INT(tc_authenticate(c, f.port, f.prefix), 207);
  conn_free(c);
  fx_down(&f);
}

/* 02 §7.7, G7: the same server, a service_access list that names someone else. Authentication succeeds (the server
   no longer checks an owner), and sd_vfs refuses the request: no listing reaches a non-member. */
SD_TEST(webdav_service_server_refuses_a_non_member)
{
  fixture f;
  tc_conn *c;
  uint8_t other[SECURITY_MAX_SID_SIZE];
  DWORD sl = sizeof(other);
  int st;
  SD_REQUIRE(CreateWellKnownSid(WinLocalServiceSid, NULL, other, &sl));
  SD_REQUIRE(fx_up_service(&f, (PSID)other) == 0);
  c = conn_new(f.port);
  SD_REQUIRE(c != NULL);
  st = tc_authenticate(c, f.port, f.prefix);
  SD_CHECK(st == 403 || st == 404);
  SD_CHECK(st != 207);
  conn_free(c);
  fx_down(&f);
}

SD_TEST(webdav_server_read_only_export)
{
  fixture f;
  tc_conn *c;
  tc_resp r;
  char v[256];
  SD_REQUIRE(fx_up(&f, NULL, TRUE) == 0);
  c = conn_new(f.port);
  SD_REQUIRE(c != NULL);
  SD_REQUIRE(request_auth(c, &f, "OPTIONS", "/", NULL, NULL, 0, &r) == 0);
  SD_CHECK(tc_header(&r, "Allow", v, sizeof(v)) && strstr(v, "PUT") == NULL);
  tc_resp_free(&r);
  SD_REQUIRE(tc_authenticate(c, f.port, f.prefix) == 207);
  SD_REQUIRE(request_auth(c, &f, "PUT", "/x", NULL, "abc", 3, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 403);
  tc_resp_free(&r);
  SD_REQUIRE(request_auth(c, &f, "LOCK", "/hello.txt", NULL, "<x/>", 4, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 403);
  tc_resp_free(&r);
  conn_free(c);
  fx_down(&f);
}

SD_TEST(webdav_server_slowloris_and_quotas)
{
  fixture f;
  sd_webdav_server_cfg sc;
  tc_conn *a, *b, *c, *d;
  tc_resp r;
  uint64_t t0;
  memset(&sc, 0, sizeof(sc));
  sc.header_timeout_ms = 400;
  sc.auth_timeout_ms = 1500;
  sc.max_unauth = 3;
  sc.max_unauth_per_process = 2;
  SD_REQUIRE(fx_up(&f, &sc, FALSE) == 0);
  /* incomplete head: closed after the header deadline */
  a = conn_new(f.port);
  SD_REQUIRE(a != NULL);
  SD_REQUIRE(tc_send(a, "OPTIONS / HTTP/1.1\r\nHost: loc", 29) == 0);
  t0 = sd_tick_ms();
  SD_CHECK(tc_wait_closed(a, 5000));
  SD_CHECK(sd_tick_ms() - t0 < 3000);
  conn_free(a);
  /* drip-fed requests keep the connection alive only until the authentication deadline */
  a = conn_new(f.port);
  SD_REQUIRE(a != NULL);
  t0 = sd_tick_ms();
  while (sd_tick_ms() - t0 < 4000) {
    if (tc_request(a, f.port, "OPTIONS", "/", NULL, NULL, 0, &r) != 0) break;
    tc_resp_free(&r);
    Sleep(200);
  }
  SD_CHECK(sd_tick_ms() - t0 < 3500);                /* closed at ~1.5 s */
  conn_free(a);
  /* per-process quota (2): the third unauthenticated connection of this process is refused */
  a = conn_new(f.port);
  b = conn_new(f.port);
  SD_REQUIRE(a && b);
  Sleep(200);
  c = conn_new(f.port);
  SD_REQUIRE(c != NULL);
  SD_CHECK(tc_wait_closed(c, 2000));
  conn_free(c);
  /* an authenticated connection no longer counts */
  SD_CHECK_EQ_INT(tc_authenticate(a, f.port, f.prefix), 207);
  Sleep(100);
  d = conn_new(f.port);
  SD_REQUIRE(d != NULL);
  SD_CHECK(tc_request(d, f.port, "OPTIONS", "/", NULL, NULL, 0, &r) == 0 && r.status == 200);
  tc_resp_free(&r);
  conn_free(a);
  conn_free(b);
  conn_free(d);
  fx_down(&f);
}

SD_TEST(webdav_server_ipv6_loopback)
{
  fixture f;
  tc_conn *c;
  tc_resp r;
  SD_REQUIRE(fx_up(&f, NULL, FALSE) == 0);
  c = (tc_conn *)sd_calloc(1, sizeof(tc_conn));
  SD_REQUIRE(c != NULL);
  if (tc_connect(c, f.port, 1) == 0) {
    char req[256];
    _snprintf_s(req, sizeof(req), _TRUNCATE, "OPTIONS / HTTP/1.1\r\nHost: [::1]:%u\r\n\r\n", (unsigned)f.port);
    SD_REQUIRE(raw(c, req, &r) == 0);
    SD_CHECK_EQ_INT(r.status, 200);
    tc_resp_free(&r);
    tc_close(c);
  } else {
    printf("  (no IPv6 loopback on this machine)\n");
  }
  sd_free(c);
  fx_down(&f);
}

static const char k_lock_body[] =
    "<?xml version=\"1.0\"?><D:lockinfo xmlns:D=\"DAV:\"><D:lockscope><D:exclusive/></D:lockscope>"
    "<D:locktype><D:write/></D:locktype><D:owner><D:href>office</D:href></D:owner></D:lockinfo>";

/* Office / LibreOffice save (02 §7.5, §7.6): LOCK the document, write a temp file, MOVE the temp over the
   locked document with Overwrite: T and If: (<token>), read the lock back, UNLOCK the document. The
   replacing MOVE keeps the destination lock on the URL, so the final UNLOCK is 204, not 409. Two save cycles
   prove the lock is still usable after a save, and a stray token is refused. */
SD_TEST(webdav_server_office_save_sequence)
{
  fixture f;
  tc_conn *c;
  tc_resp r;
  char tok[128], bare[128], extra[512], buf[64];
  int cycle;
  SD_REQUIRE(fx_up(&f, NULL, FALSE) == 0);
  c = conn_new(f.port);
  SD_REQUIRE(c != NULL);
  SD_REQUIRE(tc_authenticate(c, f.port, f.prefix) == 207);
  SD_REQUIRE(request_auth(c, &f, "PUT", "/doc.docx", NULL, "version one", 11, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 201);
  tc_resp_free(&r);
  for (cycle = 0; cycle < 2; cycle++) {
    static const char *const bodies[2] = {"version two", "version three"};
    static const char *const temps[2] = {"/~WRL0001.tmp", "/~WRL0002.tmp"};
    size_t bl = strlen(bodies[cycle]);
    SD_REQUIRE(request_auth(c, &f, "LOCK", "/doc.docx", NULL, k_lock_body, sizeof(k_lock_body) - 1, &r) == 0);
    SD_CHECK_EQ_INT(r.status, 200);
    SD_REQUIRE(tc_header(&r, "Lock-Token", tok, sizeof(tok)));
    tc_resp_free(&r);
    strcpy_s(bare, sizeof(bare), tok + 1);
    bare[strlen(bare) - 1] = '\0';                      /* opaquelocktoken:<uuid> without <> */
    SD_REQUIRE(request_auth(c, &f, "PUT", temps[cycle], NULL, bodies[cycle], bl, &r) == 0);
    SD_CHECK_EQ_INT(r.status, 201);
    tc_resp_free(&r);
    _snprintf_s(extra, sizeof(extra), _TRUNCATE, "Destination: http://localhost:%u%s/doc.docx\r\nOverwrite: T\r\n",
                (unsigned)f.port, f.prefix);
    SD_REQUIRE(request_auth(c, &f, "MOVE", temps[cycle], extra, NULL, 0, &r) == 0);
    SD_CHECK_EQ_INT(r.status, 423);                     /* no token for the locked destination */
    tc_resp_free(&r);
    SD_CHECK(fake_exists(f.s, cycle ? "/home/user/~WRL0002.tmp" : "/home/user/~WRL0001.tmp"));  /* refused: kept */
    _snprintf_s(extra, sizeof(extra), _TRUNCATE,
                "Destination: http://localhost:%u%s/doc.docx\r\nOverwrite: T\r\n"
                "If: (<opaquelocktoken:00000000-0000-0000-0000-000000000000>)\r\n",
                (unsigned)f.port, f.prefix);
    SD_REQUIRE(request_auth(c, &f, "MOVE", temps[cycle], extra, NULL, 0, &r) == 0);
    SD_CHECK_EQ_INT(r.status, 423);                    /* a token that is not the lock */
    tc_resp_free(&r);
    _snprintf_s(extra, sizeof(extra), _TRUNCATE,
                "Destination: http://localhost:%u%s/doc.docx\r\nOverwrite: T\r\nIf: (%s)\r\n",
                (unsigned)f.port, f.prefix, tok);
    SD_REQUIRE(request_auth(c, &f, "MOVE", temps[cycle], extra, NULL, 0, &r) == 0);
    SD_CHECK_EQ_INT(r.status, 204);                    /* replaced under the lock */
    tc_resp_free(&r);
    SD_CHECK(!fake_exists(f.s, "/home/user/~WRL0001.tmp") && !fake_exists(f.s, "/home/user/~WRL0002.tmp"));
    SD_CHECK(fake_get(f.s, "/home/user/doc.docx", buf, sizeof(buf)) == (long long)bl);
    SD_CHECK(memcmp(buf, bodies[cycle], bl) == 0);
    /* the lock is still listed on the document after the replacing MOVE */
    SD_REQUIRE(request_auth(c, &f, "PROPFIND", "/doc.docx", "Depth: 0\r\n", NULL, 0, &r) == 0);
    SD_CHECK_EQ_INT(r.status, 207);
    SD_CHECK(strstr(r.body, bare) != NULL);
    tc_resp_free(&r);
    _snprintf_s(extra, sizeof(extra), _TRUNCATE, "Lock-Token: %s\r\n", tok);
    SD_REQUIRE(request_auth(c, &f, "UNLOCK", "/doc.docx", extra, NULL, 0, &r) == 0);
    SD_CHECK_EQ_INT(r.status, 204);                    /* the final UNLOCK of Office's save */
    tc_resp_free(&r);
    SD_REQUIRE(request_auth(c, &f, "UNLOCK", "/doc.docx", extra, NULL, 0, &r) == 0);
    SD_CHECK_EQ_INT(r.status, 409);                    /* already released */
    tc_resp_free(&r);
    SD_REQUIRE(request_auth(c, &f, "PUT", "/doc.docx", NULL, "unlocked", 8, &r) == 0);
    SD_CHECK_EQ_INT(r.status, 204);                    /* no lock left: a plain write is allowed */
    tc_resp_free(&r);
  }
  conn_free(c);
  fx_down(&f);
}

/* A replacing MOVE of a collection onto a destination collection with a locked child: the child's lock goes
   with the replaced child (02 §7.5), so a child created later under the same name is not locked. */
SD_TEST(webdav_server_replacing_move_drops_replaced_children_locks)
{
  fixture f;
  tc_conn *c;
  tc_resp r;
  char tok[128], extra[512];
  SD_REQUIRE(fx_up(&f, NULL, FALSE) == 0);
  c = conn_new(f.port);
  SD_REQUIRE(c != NULL);
  SD_REQUIRE(tc_authenticate(c, f.port, f.prefix) == 207);
  SD_REQUIRE(request_auth(c, &f, "MKCOL", "/tree-a", NULL, NULL, 0, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 201);
  tc_resp_free(&r);
  SD_REQUIRE(request_auth(c, &f, "PUT", "/tree-a/x.txt", NULL, "xx", 2, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 201);
  tc_resp_free(&r);
  SD_REQUIRE(request_auth(c, &f, "MKCOL", "/tree-b", NULL, NULL, 0, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 201);
  tc_resp_free(&r);
  SD_REQUIRE(request_auth(c, &f, "PUT", "/tree-b/inner.txt", NULL, "in", 2, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 201);
  tc_resp_free(&r);
  SD_REQUIRE(request_auth(c, &f, "LOCK", "/tree-b/inner.txt", NULL, k_lock_body, sizeof(k_lock_body) - 1, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 200);
  SD_REQUIRE(tc_header(&r, "Lock-Token", tok, sizeof(tok)));
  tc_resp_free(&r);
  _snprintf_s(extra, sizeof(extra), _TRUNCATE, "Destination: http://localhost:%u%s/tree-b\r\nOverwrite: T\r\n",
              (unsigned)f.port, f.prefix);
  SD_REQUIRE(request_auth(c, &f, "MOVE", "/tree-a", extra, NULL, 0, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 423);                       /* the locked child is under the destination */
  tc_resp_free(&r);
  _snprintf_s(extra, sizeof(extra), _TRUNCATE,
              "Destination: http://localhost:%u%s/tree-b\r\nOverwrite: T\r\nIf: (%s)\r\n",
              (unsigned)f.port, f.prefix, tok);
  SD_REQUIRE(request_auth(c, &f, "MOVE", "/tree-a", extra, NULL, 0, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 204);
  tc_resp_free(&r);
  SD_CHECK(!fake_exists(f.s, "/home/user/tree-b/inner.txt"));
  SD_CHECK(fake_exists(f.s, "/home/user/tree-b/x.txt"));
  SD_REQUIRE(request_auth(c, &f, "PUT", "/tree-b/inner.txt", NULL, "new", 3, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 201);                      /* not 423: the replaced child's lock is gone */
  tc_resp_free(&r);
  _snprintf_s(extra, sizeof(extra), _TRUNCATE, "Lock-Token: %s\r\n", tok);
  SD_REQUIRE(request_auth(c, &f, "UNLOCK", "/tree-b/inner.txt", extra, NULL, 0, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 409);
  tc_resp_free(&r);
  conn_free(c);
  fx_down(&f);
}

/* WebClient caches a failed lookup for 60 s (FileNotFoundCacheLifeTimeInSec, 02 §7.1). While the link to the
   source is down, a miss is not "does not exist", so it must not be answered 404: 503 + Retry-After makes the
   redirector retry. Once the link is READY again the same miss is a real 404. */
SD_TEST(webdav_server_link_down_miss_is_503_not_404)
{
  fixture f;
  tc_conn *c;
  tc_resp r;
  char v[64];
  SD_REQUIRE(fx_up(&f, NULL, FALSE) == 0);
  c = conn_new(f.port);
  SD_REQUIRE(c != NULL);
  SD_REQUIRE(tc_authenticate(c, f.port, f.prefix) == 207);
  fake_disconnect(f.s);
  SD_REQUIRE(request_auth(c, &f, "GET", "/never-listed.txt", NULL, NULL, 0, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 503);
  SD_CHECK(tc_header(&r, "Retry-After", v, sizeof(v)));
  tc_resp_free(&r);
  SD_REQUIRE(request_auth(c, &f, "PROPFIND", "/never-listed.txt", "Depth: 0\r\n", NULL, 0, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 503);
  tc_resp_free(&r);
  fake_reconnect(f.s);
  SD_REQUIRE(request_auth(c, &f, "GET", "/never-listed.txt", NULL, NULL, 0, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 404);
  tc_resp_free(&r);
  conn_free(c);
  fx_down(&f);
}

/* The vfs keeps a negative entry for a name it verified missing (02 §4.1). While the link is down that entry
   must still report DISCONNECTED: a 404 here would reach the redirector, which caches it for ~60 s (02 §7.6). */
SD_TEST(webdav_server_cached_miss_is_503_while_link_down)
{
  fixture f;
  tc_conn *c;
  tc_resp r;
  char v[64];
  SD_REQUIRE(fx_up(&f, NULL, FALSE) == 0);
  c = conn_new(f.port);
  SD_REQUIRE(c != NULL);
  SD_REQUIRE(tc_authenticate(c, f.port, f.prefix) == 207);
  SD_REQUIRE(request_auth(c, &f, "GET", "/cached-miss.txt", NULL, NULL, 0, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 404);            /* online: a verified miss, now in the vfs cache */
  tc_resp_free(&r);
  fake_disconnect(f.s);
  SD_REQUIRE(request_auth(c, &f, "GET", "/cached-miss.txt", NULL, NULL, 0, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 503);
  SD_CHECK(tc_header(&r, "Retry-After", v, sizeof(v)));
  tc_resp_free(&r);
  fake_reconnect(f.s);
  SD_REQUIRE(request_auth(c, &f, "GET", "/cached-miss.txt", NULL, NULL, 0, &r) == 0);
  SD_CHECK_EQ_INT(r.status, 404);
  tc_resp_free(&r);
  conn_free(c);
  fx_down(&f);
}
