/* sd_json (src/sd_base/json.c): strict parser and validating writer. */
#include <string.h>

#include "sd_test.h"
#include "sd_base/sd_json.h"
#include "sd_base/sd_mem.h"

static sd_err parse(const char *s, sd_json **out)
{
  return sd_json_parse(s, strlen(s), 0, out);
}

static int rejects(const char *s)
{
  sd_json *v = NULL;
  sd_err e = parse(s, &v);
  sd_json_free(v);
  return e != SD_OK && v == NULL;
}

SD_TEST(json_parses_values)
{
  sd_json *v = NULL;
  int64_t i = 0;
  int b = 0;
  size_t n = 0;
  const char *s;
  SD_REQUIRE(parse(" {\"a\":1,\"b\":[true,false,null],\"c\":\"x\\ty\",\"d\":-9223372036854775808,"
                   "\"e\":1.5e3,\"f\":{}} ", &v) == SD_OK);
  SD_CHECK_EQ_INT(sd_json_type_of(v), SD_JSON_OBJECT);
  SD_CHECK_EQ_U64(sd_json_count(v), 6);
  SD_CHECK(sd_json_get_int64(v, "a", &i) && i == 1);
  SD_CHECK_EQ_U64(sd_json_count(sd_json_get(v, "b")), 3);
  SD_CHECK(sd_json_bool(sd_json_at(sd_json_get(v, "b"), 0), &b) && b == 1);
  SD_CHECK_EQ_INT(sd_json_type_of(sd_json_at(sd_json_get(v, "b"), 2)), SD_JSON_NULL);
  s = sd_json_str(sd_json_get(v, "c"), &n);
  SD_CHECK(s && n == 3 && memcmp(s, "x\ty", 3) == 0);
  SD_CHECK(sd_json_get_int64(v, "d", &i) && i == INT64_MIN);
  SD_CHECK(!sd_json_get_int64(v, "e", &i));            /* not integral */
  SD_CHECK_EQ_INT(sd_json_type_of(sd_json_get(v, "e")), SD_JSON_NUMBER);
  SD_CHECK_EQ_U64(sd_json_count(sd_json_get(v, "f")), 0);
  SD_CHECK_STR(sd_json_key_at(v, 2), "c");
  SD_CHECK(sd_json_get(v, "zz") == NULL);
  SD_CHECK(sd_json_get_str(v, "a") == NULL);
  sd_json_free(v);
}

SD_TEST(json_unicode_escapes)
{
  sd_json *v = NULL;
  size_t n = 0;
  const char *s;
  SD_REQUIRE(parse("\"\\u00e9\\ud83d\\ude00\\u0041\"", &v) == SD_OK);
  s = sd_json_str(v, &n);
  SD_CHECK(n == 2 + 4 + 1);
  SD_CHECK_MEM(s, "\xc3\xa9\xf0\x9f\x98\x80" "A", 7);
  sd_json_free(v);
  SD_REQUIRE(parse("\"a\\u0000b\"", &v) == SD_OK);     /* NUL allowed in values... */
  SD_CHECK(sd_json_str(v, &n) && n == 3);
  sd_json_free(v);
  SD_CHECK(rejects("{\"a\\u0000\":1}"));                /* ...but not in keys */
  SD_CHECK(rejects("\"\\ud800\""));                     /* unpaired high surrogate */
  SD_CHECK(rejects("\"\\udc00\""));                     /* lone low surrogate */
  SD_CHECK(rejects("\"\\ud800\\u0041\""));
  SD_CHECK(rejects("\"\xc3\x28\""));                    /* invalid UTF-8 */
  SD_CHECK(rejects("\"\xed\xa0\x80\""));                /* encoded surrogate */
}

SD_TEST(json_rejects_malformed)
{
  static const char *const bad[] = {
    "", " ", "{", "}", "[1,]", "{\"a\":1,}", "{\"a\" 1}", "{a:1}", "01", "-", "1.", ".5", "1e", "+1",
    "tru", "nul", "\"abc", "\"a\nb\"", "\"\\x\"", "[1 2]", "{\"a\":1}{}", "{\"a\":1,\"a\":2}", "NaN",
    "'x'", "[\"\\u12\"]", "1 2", "\xef\xbb\xbf{}"
  };
  size_t i;
  for (i = 0; i < SD_COUNTOF(bad); i++)
    if (!rejects(bad[i]))
      sd_test_fail(sd_t_, __FILE__, __LINE__, "accepted malformed input #%u: %s", (unsigned)i, bad[i]);
}

SD_TEST(json_depth_limit)
{
  char buf[200];
  sd_json *v = NULL;
  size_t i;
  for (i = 0; i < 33; i++) buf[i] = '[';
  for (i = 0; i < 33; i++) buf[33 + i] = ']';
  buf[66] = 0;
  SD_CHECK(sd_json_parse(buf, 66, 0, &v) != SD_OK);          /* default 32 */
  SD_CHECK(sd_json_parse(buf + 1, 64, 0, &v) == SD_OK);      /* 32 levels */
  sd_json_free(v);
  v = NULL;
  SD_CHECK(sd_json_parse("[[1]]", 5, 1, &v) != SD_OK);
  SD_CHECK(sd_json_parse("[1]", 3, 1, &v) == SD_OK);
  sd_json_free(v);
}

SD_TEST(json_integer_bounds)
{
  sd_json *v = NULL;
  int64_t i = 0;
  SD_REQUIRE(parse("[9223372036854775807,9223372036854775808,-9223372036854775809,0,-0]", &v) == SD_OK);
  SD_CHECK(sd_json_int64(sd_json_at(v, 0), &i) && i == INT64_MAX);
  SD_CHECK(!sd_json_int64(sd_json_at(v, 1), &i));
  SD_CHECK(!sd_json_int64(sd_json_at(v, 2), &i));
  SD_CHECK(sd_json_int64(sd_json_at(v, 3), &i) && i == 0);
  SD_CHECK(sd_json_int64(sd_json_at(v, 4), &i) && i == 0);
  sd_json_free(v);
}

SD_TEST(json_writer_roundtrip)
{
  sd_wr w;
  sd_json_writer jw;
  sd_json *v = NULL;
  size_t n;
  const char *s;
  sd_wr_init(&w, 4096);
  sd_jw_init(&jw, &w);
  sd_jw_obj_begin(&jw);
  sd_jw_key(&jw, "s"); sd_jw_cstr(&jw, "q\"b\\n\n\x01\x7f\xc3\xa9");
  sd_jw_key(&jw, "i"); sd_jw_int(&jw, INT64_MIN);
  sd_jw_key(&jw, "a"); sd_jw_arr_begin(&jw); sd_jw_bool(&jw, 1); sd_jw_null(&jw); sd_jw_int(&jw, 42); sd_jw_arr_end(&jw);
  sd_jw_key(&jw, "o"); sd_jw_obj_begin(&jw); sd_jw_obj_end(&jw);
  sd_jw_key(&jw, "r"); { static const char raw[] = " [1, {\"x\": 2.5}] "; sd_jw_raw(&jw, raw, sizeof(raw) - 1); }
  sd_jw_obj_end(&jw);
  SD_REQUIRE(sd_jw_finish(&jw) == SD_OK);
  SD_CHECK(memchr(w.p, '\n', w.len) == NULL);          /* control characters are escaped */
  SD_REQUIRE(sd_json_parse((const char *)w.p, w.len, 0, &v) == SD_OK);
  s = sd_json_str(sd_json_get(v, "s"), &n);
  SD_CHECK(s && n == 10 && memcmp(s, "q\"b\\n\n\x01\x7f\xc3\xa9", 10) == 0);
  SD_CHECK_EQ_U64(sd_json_count(sd_json_get(v, "r")), 2);
  {
    sd_wr w2;
    sd_json_writer j2;
    sd_wr_init(&w2, 4096);
    sd_jw_init(&j2, &w2);
    sd_jw_value(&j2, v);
    SD_CHECK(sd_jw_finish(&j2) == SD_OK);
    SD_CHECK_EQ_U64(w2.len, w.len);
    SD_CHECK_MEM(w2.p, w.p, w.len);                    /* writer output is canonical */
    sd_wr_free(&w2);
  }
  sd_json_free(v);
  sd_wr_free(&w);
}

SD_TEST(json_writer_misuse)
{
  sd_wr w;
  sd_json_writer jw;
  sd_wr_init(&w, 4096);
  sd_jw_init(&jw, &w);
  sd_jw_obj_begin(&jw);
  sd_jw_int(&jw, 1);                                     /* value without key */
  SD_CHECK(sd_jw_finish(&jw) != SD_OK);
  sd_wr_reset(&w);
  sd_jw_init(&jw, &w);
  sd_jw_arr_begin(&jw);
  sd_jw_obj_end(&jw);                                    /* mismatched close */
  SD_CHECK(sd_jw_finish(&jw) != SD_OK);
  sd_wr_reset(&w);
  sd_jw_init(&jw, &w);
  sd_jw_arr_begin(&jw);                                  /* unbalanced */
  SD_CHECK(sd_jw_finish(&jw) != SD_OK);
  sd_wr_reset(&w);
  sd_jw_init(&jw, &w);
  sd_jw_str(&jw, "\xff", 1);                             /* invalid UTF-8 */
  SD_CHECK(sd_jw_finish(&jw) != SD_OK);
  sd_wr_reset(&w);
  sd_jw_init(&jw, &w);
  sd_jw_int(&jw, 1);
  sd_jw_int(&jw, 2);                                     /* two top-level values */
  SD_CHECK(sd_jw_finish(&jw) != SD_OK);
  sd_wr_reset(&w);
  sd_jw_init(&jw, &w);
  sd_jw_raw(&jw, "{bad}", 5);
  SD_CHECK(sd_jw_finish(&jw) != SD_OK);
  sd_wr_reset(&w);
  sd_jw_init(&jw, &w);
  SD_CHECK(sd_jw_finish(&jw) != SD_OK);                  /* empty */
  sd_wr_free(&w);
  {
    sd_json_writer deep;
    int i;
    sd_wr_init(&w, 4096);
    sd_jw_init(&deep, &w);
    for (i = 0; i < 32; i++) sd_jw_arr_begin(&deep);     /* 32 > 31 */
    SD_CHECK(deep.err);
    sd_wr_free(&w);
  }
}

SD_TEST(json_alloc_failure)
{
  sd_json *v = NULL;
  unsigned k;
  for (k = 0; k < 2; k++) {   /* the document and its first arena block */
    sd_test_alloc_fail_after(k);
    SD_CHECK(parse("{\"a\":[1,2,3],\"b\":\"text\"}", &v) == SD_E_NO_MEMORY);
    sd_test_alloc_fail_off();
    SD_CHECK(v == NULL);
  }
}
