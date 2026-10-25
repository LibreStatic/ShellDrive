/* sd_webdav protocol helpers: HTTP head parser and limits, chunked decoding, request-target decoding
 * (TM-R11/TM-R12: never '/', '\', NUL, controls, '.', '..'), Host/Destination checks, XML parser,
 * encodings and header values. */
#define _CRT_SECURE_NO_WARNINGS /* test code: sprintf into sized buffers */
#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "sd_base/sd_mem.h"
#include "sd_test.h"
#include "wd_proto.h"

static int parse(const char *s, wd_req *r, int *status)
{
  return wd_http_parse_head(s, strlen(s), r, status);
}

SD_TEST(webdav_http_parses_request)
{
  wd_req r;
  int st = 0;
  uint32_t n = 0;
  const wd_hdr *h;
  const char *req = "PROPFIND /s-x/a%20b HTTP/1.1\r\nHost: localhost:8080\r\nDepth:  1 \r\n"
                    "Content-Length: 12\r\nX-A: 1\r\nx-a: 2\r\n\r\nBODY";
  SD_REQUIRE(parse(req, &r, &st) == WD_PARSE_DONE);
  SD_CHECK_STR(r.method, "PROPFIND");
  SD_CHECK(r.tlen == 10 && memcmp(r.target, "/s-x/a%20b", 10) == 0);
  SD_CHECK_EQ_INT(r.minor, 1);
  SD_CHECK(r.has_length && r.length == 12);
  SD_CHECK_EQ_INT(r.close, 0);
  SD_CHECK_EQ_U64(r.head_len, strlen(req) - 4);
  h = wd_req_header(&r, "depth", NULL);
  SD_REQUIRE(h != NULL);
  SD_CHECK(h->vlen == 1 && h->val[0] == '1');           /* OWS trimmed */
  h = wd_req_header(&r, "X-A", &n);
  SD_CHECK(h != NULL && n == 2);
  SD_CHECK(wd_req_has_prefix_header(&r, "x-"));
  SD_CHECK(!wd_req_has_prefix_header(&r, "Sec-Fetch-"));
}

SD_TEST(webdav_http_incremental_and_framing)
{
  wd_req r;
  int st;
  const char *full = "GET / HTTP/1.1\r\nHost: a\r\n\r\n";
  size_t i;
  for (i = 0; i < strlen(full); i++)
    SD_CHECK(wd_http_parse_head(full, i, &r, &st) == WD_PARSE_MORE);
  SD_CHECK(wd_http_parse_head(full, strlen(full), &r, &st) == WD_PARSE_DONE);
  /* leading CRLF (keep-alive leftovers) is ignored */
  SD_CHECK(parse("\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\n", &r, &st) == WD_PARSE_DONE);
  SD_CHECK(parse("GET / HTTP/1.0\r\nHost: a\r\n\r\n", &r, &st) == WD_PARSE_DONE && r.close == 1);
  SD_CHECK(parse("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n", &r, &st) == WD_PARSE_DONE && r.close == 0);
  SD_CHECK(parse("GET / HTTP/1.1\r\nConnection: Keep-Alive, close\r\n\r\n", &r, &st) == WD_PARSE_DONE && r.close == 1);
  SD_CHECK(parse("PUT /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\nExpect: 100-continue\r\n\r\n", &r, &st) ==
           WD_PARSE_DONE && r.chunked && r.expect_continue);
}

SD_TEST(webdav_http_rejects)
{
  wd_req r;
  int st;
  char *big;
  size_t i, o;
  st = 0;
  SD_CHECK(parse("GET / HTTP/1.1\nHost: a\r\n\r\n", &r, &st) == WD_PARSE_ERROR && st == 400);       /* bare LF */
  SD_CHECK(parse("GET / HTTP/1.1\r\nHost: a\r\n folded\r\n\r\n", &r, &st) == WD_PARSE_ERROR && st == 400);
  SD_CHECK(parse("GET / HTTP/1.1\r\nBad Name: a\r\n\r\n", &r, &st) == WD_PARSE_ERROR && st == 400);
  SD_CHECK(parse("GET / HTTP/1.1\r\n: a\r\n\r\n", &r, &st) == WD_PARSE_ERROR);
  SD_CHECK(parse("GET / HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n", &r, &st) == WD_PARSE_ERROR);
  SD_CHECK(parse("GET / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n", &r, &st) == WD_PARSE_ERROR);
  SD_CHECK(parse("GET / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n", &r, &st) == WD_PARSE_DONE);
  SD_CHECK(parse("GET / HTTP/1.1\r\nContent-Length: -1\r\n\r\n", &r, &st) == WD_PARSE_ERROR);
  SD_CHECK(parse("GET / HTTP/1.1\r\nContent-Length: 99999999999999999999\r\n\r\n", &r, &st) == WD_PARSE_ERROR);
  SD_CHECK(parse("GET / HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n", &r, &st) == WD_PARSE_ERROR && st == 501);
  SD_CHECK(parse("GET / HTTP/1.1\r\nExpect: something\r\n\r\n", &r, &st) == WD_PARSE_ERROR && st == 417);
  SD_CHECK(parse("GET / HTTP/2.0\r\n\r\n", &r, &st) == WD_PARSE_ERROR && st == 505);
  SD_CHECK(parse("GET / FOO/1.1\r\n\r\n", &r, &st) == WD_PARSE_ERROR && st == 400);
  SD_CHECK(parse("GET  / HTTP/1.1\r\n\r\n", &r, &st) == WD_PARSE_ERROR);
  SD_CHECK(parse("GET /\x01 HTTP/1.1\r\n\r\n", &r, &st) == WD_PARSE_ERROR);
  SD_CHECK(parse("GET / HTTP/1.1\r\nA: b\x7f\r\n\r\n", &r, &st) == WD_PARSE_ERROR);
  /* limits: request line 8 KiB, head 32 KiB, 64 fields */
  big = (char *)sd_alloc(64 * 1024);
  SD_REQUIRE(big != NULL);
  memcpy(big, "GET /", 5);
  memset(big + 5, 'a', 9000);
  memcpy(big + 9005, " HTTP/1.1\r\n\r\n", 14);
  SD_CHECK(parse(big, &r, &st) == WD_PARSE_ERROR && st == 414);
  SD_CHECK(wd_http_parse_head(big, 8500, &r, &st) == WD_PARSE_ERROR && st == 414);   /* before the line ends */
  o = (size_t)sprintf(big, "GET / HTTP/1.1\r\n");
  for (i = 0; i < 65; i++)
    o += (size_t)sprintf(big + o, "H%u: v\r\n", (unsigned)i);
  sprintf(big + o, "\r\n");
  SD_CHECK(parse(big, &r, &st) == WD_PARSE_ERROR && st == 431);
  o = (size_t)sprintf(big, "GET / HTTP/1.1\r\nAuthorization: Negotiate ");
  memset(big + o, 'A', 33 * 1024);
  o += 33 * 1024;
  sprintf(big + o, "\r\n\r\n");
  SD_CHECK(parse(big, &r, &st) == WD_PARSE_ERROR && st == 431);
  SD_CHECK(wd_http_parse_head(big, 33 * 1024, &r, &st) == WD_PARSE_ERROR && st == 431);   /* incomplete too */
  sd_free(big);
}

static int dechunk(const char *in, size_t n, size_t step, char *out, size_t *out_n)
{
  wd_chunked c;
  size_t pos = 0;
  *out_n = 0;
  wd_chunked_init(&c);
  while (pos < n && !c.done) {
    size_t avail = SD_MIN(step, n - pos), used = 0, dn = 0;
    const char *d;
    if (wd_chunked_feed(&c, in + pos, avail, &used, &d, &dn) != 0)
      return -1;
    memcpy(out + *out_n, d ? d : "", dn);
    *out_n += dn;
    pos += used;
  }
  return c.done ? 0 : 1;
}

SD_TEST(webdav_chunked_decoding)
{
  static const char ok[] = "5\r\nhello\r\nA;ext=1\r\n0123456789\r\n0\r\nTrailer: x\r\n\r\n";
  char out[64];
  size_t n, step;
  for (step = 1; step <= sizeof(ok); step++) {
    SD_CHECK(dechunk(ok, sizeof(ok) - 1, step, out, &n) == 0);
    SD_CHECK(n == 15 && memcmp(out, "hello0123456789", 15) == 0);
  }
  SD_CHECK(dechunk("0\r\n\r\n", 5, 5, out, &n) == 0 && n == 0);
  SD_CHECK(dechunk("x\r\n", 3, 3, out, &n) == -1);
  SD_CHECK(dechunk("5\r\nhelloXX", 10, 10, out, &n) == -1);            /* missing CRLF after data */
  SD_CHECK(dechunk("5\nhello\r\n", 9, 9, out, &n) == -1);             /* bare LF */
  SD_CHECK(dechunk("00000000000000000000001\r\n", 25, 25, out, &n) == -1);   /* chunk line > limits */
  SD_CHECK(dechunk("1;aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n", 45, 45, out, &n) == -1);  /* > 32 bytes */
  SD_CHECK(dechunk("FFFFFFFFFFFFFFFFF\r\n", 19, 19, out, &n) == -1);  /* overflow */
}

static int dec(const char *t, wd_path *p)
{
  return wd_path_decode(t, strlen(t), p);
}

SD_TEST(webdav_path_decoding_rules)
{
  static const char *const bad[] = {
    "", "a", "*", "/a?b", "/a#b", "//", "/a//b", "/a//", "/%2F", "/a%2fb", "/a%5Cb", "/a%5cb", "/a%00", "/a\\b",
    "/.", "/..", "/a/./b", "/a/../b", "/%2e", "/%2E%2e", "/%2e%2E/x", "/%4", "/%zz", "/%G0", "/a%", "/a%2",
    "/%01", "/%1f", "/%7f", "/%C0%AF", "/%E0%80%AF", "/%ED%A0%80", "/%F4%90%80%80", "/%FF", "/%C3",
  };
  wd_path p;
  WCHAR *w;
  size_t i;
  for (i = 0; i < SD_COUNTOF(bad); i++) {
    int rc = dec(bad[i], &p);
    if (rc != 400)
      sd_test_fail(sd_t_, __FILE__, __LINE__, "accepted bad target \"%s\" (%d)", bad[i], rc);
    wd_path_free(&p);
  }
  SD_REQUIRE(dec("/", &p) == 0);
  SD_CHECK(p.nseg == 0);
  wd_path_free(&p);
  SD_REQUIRE(dec("/s-tok/a%20b/%C3%A9t%C3%A9/", &p) == 0);
  SD_CHECK(p.nseg == 3 && p.trailing_slash);
  SD_CHECK_STR(p.seg[0], "s-tok");
  SD_CHECK_STR(p.seg[1], "a b");
  SD_CHECK_STR(p.seg[2], "\xC3\xA9t\xC3\xA9");
  w = wd_path_to_vfs(&p, 1);
  SD_REQUIRE(w != NULL);
  SD_CHECK(wcscmp(w, L"\\a b\\\x00E9t\x00E9") == 0);
  sd_free(w);
  w = wd_path_to_vfs(&p, 3);
  SD_CHECK(w != NULL && wcscmp(w, L"\\") == 0);
  sd_free(w);
  wd_path_free(&p);
  /* "..." and names that merely contain dots are fine */
  SD_REQUIRE(dec("/x/.../a..b/.hidden", &p) == 0);
  SD_CHECK(p.nseg == 4 && !p.trailing_slash);
  wd_path_free(&p);
  /* reserved characters other than '/' and '\' stay literal after decoding */
  SD_REQUIRE(dec("/x/a%3Ab%25c%23", &p) == 0);
  SD_CHECK_STR(p.seg[1], "a:b%c#");
  wd_path_free(&p);
}

SD_TEST(webdav_href_and_token)
{
  wd_sb b;
  char tok[WD_TOKEN_CHARS + 1], seg[40], tok2[WD_TOKEN_CHARS + 1];
  wd_sb_init(&b, 0);
  wd_href_seg(&b, "a b/c%\xC3\xA9~._-", 12);
  SD_CHECK_STR(b.p, "a%20b%2Fc%25%C3%A9~._-");
  wd_sb_free(&b);
  SD_REQUIRE(wd_make_token(tok) == 0);
  SD_REQUIRE(wd_make_token(tok2) == 0);
  SD_CHECK(strlen(tok) == 26);
  SD_CHECK(strcmp(tok, tok2) != 0);
  sprintf(seg, "s-%s", tok);
  SD_CHECK(wd_is_token_seg(seg));
  seg[5] = '1';                                       /* not base32 */
  SD_CHECK(!wd_is_token_seg(seg));
  SD_CHECK(!wd_is_token_seg("s-abc"));
  SD_CHECK(!wd_is_token_seg("x-aaaaaaaaaaaaaaaaaaaaaaaaaa"));
  SD_CHECK(!wd_is_token_seg("s-AAAAAAAAAAAAAAAAAAAAAAAAAA"));
  SD_CHECK(wd_is_token_seg("s-aaaaaaaaaaaaaaaaaaaaaaaaaa"));
  SD_CHECK(!wd_is_token_seg("s-aaaaaaaaaaaaaaaaaaaaaaaaaaa"));
  SD_CHECK(wd_ct_equal("abc", "abc", 3) && !wd_ct_equal("abc", "abd", 3));
}

SD_TEST(webdav_host_header_dns_rebinding)
{
  static const char *const good[] = { "localhost:8080", "LOCALHOST:8080", "127.0.0.1:8080", "[::1]:8080" };
  static const char *const bad[] = { "localhost", "localhost:80", "localhost.:8080", "evil.example:8080",
                                     "127.0.0.2:8080", "localhost:8080 ", "localhost:08080", "[::1]",
                                     "localhost:8080.evil", "127.0.0.1", "" };
  size_t i;
  for (i = 0; i < SD_COUNTOF(good); i++)
    SD_CHECK(wd_host_ok(good[i], strlen(good[i]), 8080));
  for (i = 0; i < SD_COUNTOF(bad); i++)
    if (wd_host_ok(bad[i], strlen(bad[i]), 8080))
      sd_test_fail(sd_t_, __FILE__, __LINE__, "accepted Host \"%s\"", bad[i]);
}

SD_TEST(webdav_destination_parsing)
{
  wd_path p;
  const char *h = "localhost:8080";
#define DST(s) wd_destination_parse((s), strlen(s), h, strlen(h), &p)
  SD_REQUIRE(DST("http://localhost:8080/s-t/new%20name") == 0);
  SD_CHECK(p.nseg == 2);
  SD_CHECK_STR(p.seg[1], "new name");
  wd_path_free(&p);
  SD_CHECK(DST("HTTP://LocalHost:8080/s-t/x") == 0);
  wd_path_free(&p);
  SD_CHECK(DST("http://localhost:8081/s-t/x") == 502);
  SD_CHECK(DST("http://127.0.0.1:8080/s-t/x") == 502);
  SD_CHECK(DST("http://evil/s-t/x") == 502);
  SD_CHECK(DST("http://u@localhost:8080/s-t/x") == 400);
  SD_CHECK(DST("http://localhost:8080/s-t/x?y") == 400);
  SD_CHECK(DST("http://localhost:8080/s-t/x#y") == 400);
  SD_CHECK(DST("https://localhost:8080/s-t/x") == 400);
  SD_CHECK(DST("/s-t/x") == 400);
  SD_CHECK(DST("http://localhost:8080/s-t/%2e%2e/x") == 400);
  SD_CHECK(DST("http://localhost:8080/s-t/a%2Fb") == 400);
  SD_CHECK(DST("http://localhost:8080") == 400);
#undef DST
}

static int xml(const char *s, wd_xdoc *d)
{
  return wd_xml_parse(s, strlen(s), d);
}

SD_TEST(webdav_xml_parser)
{
  wd_xdoc d;
  int root, prop, c;
  const char *pf = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<!-- c --><D:propfind xmlns:D=\"DAV:\" "
                   "xmlns:Z='urn:schemas-microsoft-com:'><D:prop><D:getcontentlength/><Z:Win32FileAttributes/>"
                   "<x xmlns=\"urn:other\"/></D:prop></D:propfind>";
  SD_REQUIRE(xml(pf, &d) == 0);
  root = wd_xml_child(&d, -1, "DAV:", "propfind");
  SD_REQUIRE(root == 0);
  prop = wd_xml_child(&d, root, "DAV:", "prop");
  SD_REQUIRE(prop >= 0);
  c = d.n[prop].child;
  SD_REQUIRE(c >= 0);
  SD_CHECK(wd_xml_is(&d, c, "DAV:", "getcontentlength"));
  c = d.n[c].next;
  SD_CHECK(wd_xml_is(&d, c, "urn:schemas-microsoft-com:", "Win32FileAttributes"));
  c = d.n[c].next;
  SD_CHECK(wd_xml_is(&d, c, "urn:other", "x"));
  SD_CHECK(d.n[c].next == -1);
  wd_xml_free(&d);

  /* default namespace, entities, CDATA, numeric references */
  SD_REQUIRE(xml("<propertyupdate xmlns=\"DAV:\"><set><prop><Win32LastModifiedTime xmlns=\"urn:schemas-microsoft-com:\">"
                 "a &amp; b &lt;&#65;&#x42;<![CDATA[<raw>]]>\xC3\xA9</Win32LastModifiedTime></prop></set></propertyupdate>",
                 &d) == 0);
  c = wd_xml_child(&d, wd_xml_child(&d, wd_xml_child(&d, 0, "DAV:", "set"), "DAV:", "prop"),
                   "urn:schemas-microsoft-com:", "Win32LastModifiedTime");
  SD_REQUIRE(c >= 0);
  SD_CHECK_STR(d.n[c].text, "a & b <AB<raw>\xC3\xA9");
  wd_xml_free(&d);

  /* owner text before child elements, and namespace scoping of a prefix redeclared in a child */
  SD_REQUIRE(xml("<a:lockinfo xmlns:a=\"DAV:\"><a:owner>  me <b/></a:owner><b:x xmlns:b=\"u1\"><b:y xmlns:b=\"u2\"/>"
                 "</b:x><c xmlns=\"\"/></a:lockinfo>", &d) == 0);
  c = wd_xml_child(&d, 0, "DAV:", "owner");
  SD_CHECK(c >= 0 && strcmp(d.n[c].text, "  me ") == 0);
  c = wd_xml_child(&d, 0, "u1", "x");
  SD_CHECK(c >= 0 && wd_xml_is(&d, d.n[c].child, "u2", "y"));
  SD_CHECK(wd_xml_child(&d, 0, "", "c") >= 0);
  wd_xml_free(&d);
}

SD_TEST(webdav_xml_rejects)
{
  static const char *const bad[] = {
    "<!DOCTYPE x [<!ENTITY e \"boom\">]><x>&e;</x>",
    "<x>&e;</x>",
    "<x>&#0;</x>",
    "<x>&#xD800;</x>",
    "<x>&#x110000;</x>",
    "<x></y>",
    "<x>",
    "<x/><y/>",
    "<x/>trailing",
    "text<x/>",
    "<p:x/>",
    "<x a=\"1/>",
    "<x a=1/>",
    "<x>\xC0\xAF</x>",
    "",
    "<x><!ENTITY y></x>",
  };
  char deep[2048];
  size_t i, o = 0;
  wd_xdoc d;
  for (i = 0; i < SD_COUNTOF(bad); i++) {
    if (wd_xml_parse(bad[i], strlen(bad[i]), &d) == 0) {
      sd_test_fail(sd_t_, __FILE__, __LINE__, "accepted bad XML #%u", (unsigned)i);
      wd_xml_free(&d);
    }
  }
  for (i = 0; i < 33; i++) o += (size_t)sprintf(deep + o, "<a>");
  for (i = 0; i < 33; i++) o += (size_t)sprintf(deep + o, "</a>");
  SD_CHECK(wd_xml_parse(deep, o, &d) == 400);
  o = 0;
  for (i = 0; i < 32; i++) o += (size_t)sprintf(deep + o, "<a>");
  for (i = 0; i < 32; i++) o += (size_t)sprintf(deep + o, "</a>");
  SD_CHECK(wd_xml_parse(deep, o, &d) == 0);
  wd_xml_free(&d);
  {
    char *huge = (char *)sd_alloc(WD_MAX_XML + 16);
    SD_REQUIRE(huge != NULL);
    memset(huge, ' ', WD_MAX_XML + 16);
    memcpy(huge, "<x>", 3);
    memcpy(huge + WD_MAX_XML + 10, "</x>", 4);
    SD_CHECK(wd_xml_parse(huge, WD_MAX_XML + 14, &d) == 400);
    sd_free(huge);
  }
}

SD_TEST(webdav_values)
{
  uint8_t raw[64], back[64];
  char b64[128], date[32];
  size_t i, n;
  uint64_t ft, f, l;
  char toks[4][80];
  for (i = 0; i < sizeof(raw); i++) raw[i] = (uint8_t)(i * 37 + 1);
  for (i = 0; i <= sizeof(raw); i++) {
    size_t el = wd_b64_encode(raw, i, b64, sizeof(b64));
    SD_REQUIRE(el == ((i + 2) / 3) * 4);
    SD_REQUIRE(wd_b64_decode(b64, el, back, sizeof(back), &n) == 0);
    SD_CHECK(n == i && memcmp(raw, back, i) == 0);
  }
  SD_CHECK(wd_b64_decode("TlRMTVNTUAAB==A", 15, back, sizeof(back), &n) != 0);
  SD_CHECK(wd_b64_decode("!!!!", 4, back, sizeof(back), &n) != 0);
  /* RFC 1123 */
  SD_REQUIRE(wd_parse_rfc1123("Sun, 06 Nov 1994 08:49:37 GMT", 29, &ft) == 0);
  wd_rfc1123(ft, date);
  SD_CHECK_STR(date, "Sun, 06 Nov 1994 08:49:37 GMT");
  wd_rfc3339(ft, date);
  SD_CHECK_STR(date, "1994-11-06T08:49:37Z");
  SD_CHECK(wd_parse_rfc1123("Sun, 06 Nov 1994 08:49:37", 25, &ft) != 0);
  SD_CHECK(wd_parse_rfc1123("Sun, 32 Nov 1994 08:49:37 GMT", 29, &ft) != 0);
  SD_CHECK(wd_parse_rfc1123("Sun, 06 Foo 1994 08:49:37 GMT", 29, &ft) != 0);
  /* Range */
  SD_CHECK(wd_range_parse("bytes=0-99", 10, 1000, &f, &l) == 1 && f == 0 && l == 99);
  SD_CHECK(wd_range_parse("bytes=900-", 10, 1000, &f, &l) == 1 && f == 900 && l == 999);
  SD_CHECK(wd_range_parse("bytes=-100", 10, 1000, &f, &l) == 1 && f == 900 && l == 999);
  SD_CHECK(wd_range_parse("bytes=-5000", 11, 1000, &f, &l) == 1 && f == 0 && l == 999);
  SD_CHECK(wd_range_parse("bytes=500-5000", 14, 1000, &f, &l) == 1 && l == 999);
  SD_CHECK(wd_range_parse("bytes=1000-", 11, 1000, &f, &l) == 416);
  SD_CHECK(wd_range_parse("bytes=0-1,5-6", 13, 1000, &f, &l) == 0);
  SD_CHECK(wd_range_parse("bytes=9-1", 9, 1000, &f, &l) == 0);
  SD_CHECK(wd_range_parse("items=0-1", 9, 1000, &f, &l) == 0);
  SD_CHECK(wd_range_parse("bytes=99999999999999999999-", 27, 1000, &f, &l) == 0);
  /* Timeout */
  SD_CHECK(wd_timeout_parse("Second-60", 9) == 60);
  SD_CHECK(wd_timeout_parse("Second-999999999999", 19) == 3600);
  SD_CHECK(wd_timeout_parse("Infinite, Second-4100000000", 27) == 3600);
  SD_CHECK(wd_timeout_parse("bogus", 5) == 3600);
  /* If */
  {
    const char *ifh = "<http://localhost:1/s-x/a> (<opaquelocktoken:1234-5678-aaaa> [\"etag\"]) "
                      "(Not <opaquelocktoken:zzzz-0000-bbbb>) <urn:foo>";
    SD_CHECK(wd_if_tokens(ifh, strlen(ifh), toks, 4) == 2);
    SD_CHECK_STR(toks[0], "opaquelocktoken:1234-5678-aaaa");
  }
}
