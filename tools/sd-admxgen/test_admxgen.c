/* Unit tests for sd-admxgen: escaping, table parsing and validation, PO parsing, enum, decimal, boolean and
 * text emission, the generated headers, and a full run over the real table and catalogs. CTest unit.admxgen. */
#define SD_ADMXGEN_NO_MAIN 1
#include "sd-admxgen.c"

static int g_failures = 0;

#define CHECK(c)                                                                                  \
  do {                                                                                            \
    if (!(c)) {                                                                                   \
      g_failures++;                                                                               \
      fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #c);                       \
    }                                                                                             \
  } while (0)

static int has(const sdg_sb *b, const char *s)
{
  return b->p != NULL && strstr(b->p, s) != NULL;
}

static int eq(const sdg_sb *b, const char *s)
{
  return b->p != NULL && strcmp(b->p, s) == 0;
}

static sdg_table g_tbl;

/* Parses table text with a fresh table; returns the errors it reported. */
static int parse_table(const char *text)
{
  sdg_nerrors = 0;
  sdg_parse_table_text(&g_tbl, text, "test.txt");
  return sdg_nerrors;
}

#define KEY "@key Software\\Policies\\LibreStatic\\ShellDrive\n"

static void test_escaping(void)
{
  sdg_sb b = { 0, 0, 0 };
  sdg_xml_escape(&b, "a&b<c>\"d'e");
  CHECK(eq(&b, "a&amp;b&lt;c&gt;&quot;d&apos;e"));
  sdg_sb_free(&b);

  sdg_sb_free(&b);
  CHECK(sdg_xml_escape(&b, "x\x01y") == 0);   /* control characters are rejected */
  sdg_sb_free(&b);

  sdg_c_escape(&b, "Software\\Policies \"x\"");
  CHECK(eq(&b, "Software\\\\Policies \\\"x\\\""));
  sdg_sb_free(&b);

  sdg_xml_escape(&b, "keeps\ttab");
  CHECK(eq(&b, "keeps\ttab"));
  sdg_sb_free(&b);
}

static void test_table_accepts_valid(void)
{
  int n = parse_table(KEY
    "E1|both|enum|0,1,2|xp|security\n"
    "# comment\n"
    "\n"
    "T1|both|text|1024|xp|network\n"
    "B1|machine|boolean|-|win11|interface\n");
  CHECK(n == 0);
  CHECK(g_tbl.npolicies == 3);
  CHECK(strcmp(g_tbl.key, "Software\\Policies\\LibreStatic\\ShellDrive") == 0);
  CHECK(g_tbl.policies[0].kind == SDG_ENUM && g_tbl.policies[0].numeric == 1);
  CHECK(g_tbl.policies[0].min == 0 && g_tbl.policies[0].max == 2);
  CHECK(g_tbl.policies[1].maxlen == 1024);
  CHECK(g_tbl.policies[2].cls == SDG_CLS_MACHINE && g_tbl.policies[2].win11 == 1);
}

static void test_table_rejects_invalid(void)
{
  CHECK(parse_table(KEY "X|foo|boolean|-|xp|security\n") == 1);             /* class */
  CHECK(parse_table(KEY "X|both|bool|-|xp|security\n") == 1);               /* type */
  CHECK(parse_table(KEY "X|both|boolean|-|xp\n") == 1);                     /* 5 fields */
  CHECK(parse_table(KEY "X|both|boolean|-|xp|security|extra\n") == 1);      /* 7 fields */
  CHECK(parse_table(KEY "X|both|boolean|-|xp|nowhere\n") == 1);             /* category */
  CHECK(parse_table(KEY "X|both|boolean|-|vista|security\n") == 1);         /* supported */
  CHECK(parse_table(KEY "X|both|boolean|-|xp|security\nX|both|boolean|-|xp|security\n") == 1); /* dup */
  CHECK(parse_table(KEY "1X|both|boolean|-|xp|security\n") == 1);           /* identifier */
  CHECK(parse_table(KEY "E|both|enum|0,stable|xp|security\n") == 1);        /* mixed enum */
  CHECK(parse_table(KEY "E|both|enum|a,a|xp|security\n") == 1);             /* duplicate value */
  CHECK(parse_table(KEY "E|both|enum|a b|xp|security\n") == 1);             /* not a token */
  CHECK(parse_table(KEY "D|both|decimal|9,3|xp|security\n") == 1);          /* min > max */
  CHECK(parse_table(KEY "D|both|decimal|-1,3|xp|security\n") == 1);         /* negative */
  CHECK(parse_table(KEY "T|both|text|0|xp|security\n") == 1);               /* maxlength */
  CHECK(parse_table(KEY "B|both|boolean|yes|xp|security\n") == 1);          /* boolean params */
  CHECK(parse_table("B|both|boolean|-|xp|security\n") == 1);                /* missing @key */
  CHECK(parse_table(KEY) == 1);                                             /* no policies */
}

static void test_po_parsing(void)
{
  static const char *const po =
    "msgid \"\"\n"
    "msgstr \"\"\n"
    "\"Language: en\\n\"\n"
    "\n"
    "#. A comment\n"
    "msgctxt \"policy.a.title\"\n"
    "msgid \"Hello \"\n"
    "\"world \\\"q\\\"\\n\"\n"
    "msgstr \"\"\n"
    "\n"
    "#, fuzzy\n"
    "msgctxt \"policy.b.title\"\n"
    "msgid \"Fuzzy\"\n"
    "msgstr \"x\"\n"
    "\n";
  sdg_catalog c;
  memset(&c, 0, sizeof(c));
  sdg_nerrors = 0;
  sdg_parse_po_text(&c, po, 1, "en.po");
  CHECK(sdg_nerrors == 0);
  CHECK(c.n == 2);
  CHECK(strcmp(sdg_po_get(&c, "policy.a.title"), "Hello world \"q\"\n") == 0);
  CHECK(sdg_po_get(&c, "policy.b.title") == NULL);             /* fuzzy entries are unusable */
  CHECK(sdg_po_get(&c, "policy.none") == NULL);

  memset(&c, 0, sizeof(c));
  sdg_nerrors = 0;
  sdg_parse_po_text(&c, "msgctxt \"policy.c.label\"\nmsgid \"Label\"\nmsgstr \"Etiqueta\"\n", 0, "es.po");
  CHECK(sdg_nerrors == 0);
  CHECK(strcmp(sdg_po_get(&c, "policy.c.label"), "Etiqueta") == 0);

  memset(&c, 0, sizeof(c));
  sdg_nerrors = 0;
  sdg_parse_po_text(&c, "msgctxt \"policy.d.label\"\nmsgid \"Empty\"\nmsgstr \"\"\n", 0, "fr.po");
  CHECK(sdg_po_get(&c, "policy.d.label") == NULL);             /* untranslated */

  memset(&c, 0, sizeof(c));
  sdg_nerrors = 0;
  sdg_parse_po_text(&c, "msgctxt \"policy.e\"\nmsgid \"One\"\nmsgid_plural \"Many\"\nmsgstr[0] \"\"\n", 1, "en.po");
  CHECK(sdg_nerrors >= 1);                                     /* plurals are rejected */
}

static void test_enum_and_decimal_emission(void)
{
  sdg_sb b = { 0, 0, 0 };
  int n = parse_table(KEY
    "E1|both|enum|0,1,2|xp|security\n"
    "E2|both|enum|stable,beta|xp|updates\n"
    "D1|both|decimal|0,100|xp|security\n"
    "B1|both|boolean|-|xp|security\n"
    "T1|both|text|10|xp|network\n");
  CHECK(n == 0);
  sdg_emit_admx(&b, &g_tbl);
  CHECK(has(&b, "<item displayName=\"$(string.policy_e1_opt_2)\">"));
  CHECK(has(&b, "<value><decimal value=\"2\"/></value>"));       /* numeric values are DWORD */
  CHECK(has(&b, "<value><string>stable</string></value>"));      /* text values are REG_SZ */
  CHECK(has(&b, "<decimal id=\"ID_D1\" valueName=\"D1\" required=\"true\" minValue=\"0\" maxValue=\"100\"/>"));
  CHECK(has(&b, "<text id=\"ID_T1\" valueName=\"T1\" required=\"false\" maxLength=\"10\"/>"));
  CHECK(has(&b, "<enabledValue><decimal value=\"1\"/></enabledValue>"));
  CHECK(has(&b, "<disabledValue><decimal value=\"0\"/></disabledValue>"));
  CHECK(has(&b, "presentation=\"$(presentation.P_E1)\""));
  CHECK(has(&b, "explainText=\"$(string.policy_e2_explain)\""));
  CHECK(has(&b, "key=\"Software\\Policies\\LibreStatic\\ShellDrive\""));
  CHECK(has(&b, "<presentation id=\"P_T1\"/>"));
  CHECK(!has(&b, "<presentation id=\"P_B1\"/>"));                 /* booleans have no presentation */
  sdg_sb_free(&b);
}

static void test_adml_reports_missing_keys(void)
{
  sdg_sb b = { 0, 0, 0 };
  sdg_catalog c;
  int n;
  parse_table(KEY "E1|both|enum|0,1|xp|security\n");
  memset(&c, 0, sizeof(c));
  sdg_nerrors = 0;
  n = sdg_emit_adml(&b, &g_tbl, &c, "en", "en.po");
  CHECK(n > 0);
  CHECK(sdg_nerrors == n);
  sdg_sb_free(&b);
}

static void test_headers(void)
{
  sdg_sb ids = { 0, 0, 0 }, tbl = { 0, 0, 0 };
  parse_table(KEY "LegacyAlgorithms|both|enum|0,1,2|xp|security\n"
                  "UILanguage|both|enum|en,es|xp|interface\n"
                  "ProxyServer|both|text|1024|xp|network\n");
  sdg_emit_ids_header(&ids, &g_tbl);
  CHECK(has(&ids, "SD_POLICY_LEGACYALGORITHMS = 0,"));
  CHECK(has(&ids, "SD_POLICY_UILANGUAGE = 1,"));
  CHECK(has(&ids, "SD_POLICY_ID_COUNT"));
  sdg_emit_table_header(&tbl, &g_tbl);
  CHECK(has(&tbl, "#define SD_POLICY_REGKEY L\"Software\\\\Policies\\\\LibreStatic\\\\ShellDrive\""));
  CHECK(has(&tbl, "{ L\"LegacyAlgorithms\", SD_POLICY_KIND_ENUM, SD_POLICY_REG_DWORD, 0UL, 2UL, 0UL },"));
  CHECK(has(&tbl, "{ L\"UILanguage\", SD_POLICY_KIND_ENUM, SD_POLICY_REG_SZ, 0UL, 0UL, 0UL },"));
  CHECK(has(&tbl, "{ L\"ProxyServer\", SD_POLICY_KIND_TEXT, SD_POLICY_REG_SZ, 0UL, 0UL, 1024UL },"));
  sdg_sb_free(&ids);
  sdg_sb_free(&tbl);
}

/* The real table and the six real catalogs generate without errors; the ADMX holds one element per table line. */
static void test_real_inputs(void)
{
  sdg_sb admx = { 0, 0, 0 }, adml = { 0, 0, 0 }, ids = { 0, 0, 0 }, tbl = { 0, 0, 0 };
  char *text;
  static sdg_catalog cats[SDG_NLOCALES];
  static sdg_table t;
  int i;
  char file[512];

  text = sdg_read_file(SD_ADMXGEN_TABLE);
  CHECK(text != NULL);
  if (text == NULL)
    return;
  sdg_nerrors = 0;
  sdg_parse_table_text(&t, text, SD_ADMXGEN_TABLE);
  free(text);
  CHECK(sdg_nerrors == 0);
  CHECK(t.npolicies == 21);

  for (i = 0; i < SDG_NLOCALES; i++) {
    sprintf(file, "%s/%s.po", SD_ADMXGEN_PO_DIR, sdg_locales[i].code);
    text = sdg_read_file(file);
    CHECK(text != NULL);
    if (text == NULL)
      return;
    sdg_parse_po_text(&cats[i], text, i == 0, file);
    free(text);
  }
  CHECK(sdg_nerrors == 0);

  sdg_emit_admx(&admx, &t);
  CHECK(has(&admx, "<policyDefinitions "));
  for (i = 0; i < SDG_NLOCALES; i++) {
    sdg_emit_adml(&adml, &t, &cats[i], sdg_locales[i].code, "real");
    adml.len = 0;
    if (adml.p)
      adml.p[0] = 0;
  }
  CHECK(sdg_nerrors == 0);
  sdg_emit_ids_header(&ids, &t);
  sdg_emit_table_header(&tbl, &t);
  CHECK(has(&ids, "SD_POLICY_LOGPRIVACY = 20,"));

  {
    size_t count = 0;
    const char *p = admx.p;
    while (p && (p = strstr(p, "<policy name=\"")) != NULL) {
      count++;
      p++;
    }
    CHECK(count == 21);
  }
  sdg_sb_free(&admx);
  sdg_sb_free(&adml);
  sdg_sb_free(&ids);
  sdg_sb_free(&tbl);
}

int main(void)
{
  sdg_diag = NULL;   /* the tests count errors; diagnostics are not needed on success */
  test_escaping();
  test_table_accepts_valid();
  test_table_rejects_invalid();
  test_po_parsing();
  test_enum_and_decimal_emission();
  test_adml_reports_missing_keys();
  test_headers();
  test_real_inputs();
  if (g_failures) {
    fprintf(stderr, "sd-admxgen unit tests: %d check(s) failed\n", g_failures);
    return 1;
  }
  printf("sd-admxgen unit tests: all passed\n");
  return 0;
}
