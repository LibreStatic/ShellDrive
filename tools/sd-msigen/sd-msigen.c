/* sd-msigen: build-time generator for the per-machine MSI packages (docs/design/04 §8).
 *
 *   sd-msigen guid --seed <text>
 *       Prints a deterministic GUID ({XXXXXXXX-XXXX-5XXX-XXXX-XXXXXXXXXXXX}) derived from <text>. Used for
 *       ProductCode, PackageCode and the registry component GUIDs, so two builds of one tree are byte-identical
 *       (04 §12.2). UpgradeCodes are not derived: they are fixed in 04 §8.2.
 *
 *   sd-msigen registry --in <packaging/registration.txt> --out <Registry.wxi> --flavour <name>
 *                      --family <name> --win64 yes|no --shellext32 yes|no --ui yes|no
 *       Turns the registry rows into a WiX include. Every row becomes one Component with one RegistryValue
 *       (HKLM); the components are grouped by feature into SD_RegCore (core), SD_RegAutostart (autostart),
 *       SD_RegShellExt (shellext, referenced by the ShellExt feature) and SD_RegShellExt32 (shellext32: the 32-bit
 *       view of the shell extension, Win64="no", written only with --shellext32 yes, 04 §8.3, 03 §8.5).
 *       --ui no (the ARM32 package: CLI and host only, 04 §5.1) leaves out the shellext and shellext32 rows and every
 *       row whose data names shelldrive-ui.exe (App Paths): the package has neither file.
 *       The rows of Software\Microsoft\Windows\CurrentVersion\Uninstall\ShellDrive are skipped: Windows Installer
 *       writes the Add/Remove Programs entry of an MSI itself (04 §6.7). [VERSION] becomes [ProductVersion],
 *       [INSTALLDIR] stays (MSI formats it), [INSTALLDIR32] becomes [SD_INSTALLDIR32] (the 32-bit folder, Program
 *       Files (x86)), [FLAVOUR] becomes the flavour name. [SIZEKB] is an error here.
 *
 *   sd-msigen wxl --po <l10n/installer/<lang>.po> --culture <xx-XX> --lcid <n> --out <file.wxl>
 *       Writes the WiX localization file of one culture from the msi.* entries of the installer catalog (the
 *       msgctxt without "msi." is the WiX string id). The English catalog supplies its msgid as text. Plural
 *       messages, fuzzy or empty translations and placeholders are errors (04 §8.6, D26).
 *
 *   sd-msigen lcids --lang <en|es|fr|pt-BR|it|de>
 *       Prints the LCIDs that receive the transform of one language, the build culture's LCID first (C43).
 *       This table is the single list of LCIDs of the MSI tooling.
 *
 * Build-time tool, never shipped. Plain C with stdio and the CRT only, built with every toolset (v141_xp too).
 */
#define _CRT_SECURE_NO_WARNINGS 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void die(const char *msg, const char *arg)
{
  fprintf(stderr, "sd-msigen: ");
  fprintf(stderr, msg, arg ? arg : "");
  fprintf(stderr, "\n");
  exit(1);
}

static void *xmalloc(size_t n)
{
  void *p = malloc(n ? n : 1);
  if (!p)
    die("out of memory", NULL);
  return p;
}

static char *xstrdup(const char *s)
{
  size_t n = strlen(s);
  char *p = (char *)xmalloc(n + 1);
  memcpy(p, s, n + 1);
  return p;
}

static const char *need_arg(int argc, char **argv, const char *name)
{
  int i;
  for (i = 1; i + 1 < argc; i++) {
    if (strcmp(argv[i], name) == 0)
      return argv[i + 1];
  }
  fprintf(stderr, "sd-msigen: missing option %s\n", name);
  exit(2);
}

/* Writes s with XML escaping. */
static void xml_put(FILE *f, const char *s)
{
  for (; *s; s++) {
    switch (*s) {
    case '&': fputs("&amp;", f); break;
    case '<': fputs("&lt;", f); break;
    case '>': fputs("&gt;", f); break;
    case '"': fputs("&quot;", f); break;
    case '\'': fputs("&apos;", f); break;
    default: fputc(*s, f); break;
    }
  }
}

/* ---- GUIDs ---- */

/* 64-bit FNV-1a with a chosen offset basis. Not cryptographic: the GUIDs need only be stable and distinct
 * among the few hundred names of one package. */
static unsigned long long fnv1a64(const char *s, unsigned long long basis)
{
  unsigned long long h = basis;
  for (; *s; s++) {
    h ^= (unsigned char)*s;
    h *= 1099511628211ULL;
  }
  return h;
}

static void make_guid(const char *seed, char *out, size_t cap)
{
  unsigned long long a = fnv1a64(seed, 14695981039346656037ULL);
  unsigned long long b = fnv1a64(seed, 0x6c62272e07bb0142ULL);
  unsigned char raw[16];
  int i;
  for (i = 0; i < 8; i++) {
    raw[i] = (unsigned char)(a >> (56 - 8 * i));
    raw[8 + i] = (unsigned char)(b >> (56 - 8 * i));
  }
  raw[6] = (unsigned char)((raw[6] & 0x0F) | 0x50); /* version 5 layout */
  raw[8] = (unsigned char)((raw[8] & 0x3F) | 0x80); /* RFC 4122 variant */
  sprintf_s(out, cap, "{%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
            raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
            raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15]);
}

static int cmd_guid(int argc, char **argv)
{
  char guid[64];
  make_guid(need_arg(argc, argv, "--seed"), guid, sizeof(guid));
  printf("%s\n", guid);
  return 0;
}

/* ---- line input ---- */

/* Reads one line (without the newline and a trailing CR). Returns NULL at the end of the file. */
static char *read_line(FILE *f)
{
  size_t cap = 256, n = 0;
  char *buf = (char *)xmalloc(cap);
  int c;
  while ((c = fgetc(f)) != EOF && c != '\n') {
    if (n + 1 >= cap) {
      char *bigger;
      cap *= 2;
      bigger = (char *)xmalloc(cap);
      memcpy(bigger, buf, n);
      free(buf);
      buf = bigger;
    }
    buf[n++] = (char)c;
  }
  if (c == EOF && n == 0) {
    free(buf);
    return NULL;
  }
  while (n > 0 && buf[n - 1] == '\r')
    n--;
  buf[n] = '\0';
  return buf;
}

/* ---- registry rows (packaging/registration.txt) ---- */

typedef struct {
  char *subkey, *name, *type, *data, *feature;
  int view32;
  char id[16];
  char guid[48];
} reg_item;

/* Splits one row of the form subkey|name|type|data|feature. Returns 0 for comments and blank lines. */
static int parse_reg_row(const char *line, reg_item *item)
{
  char *copy, *parts[5], *p;
  int n = 0;
  const char *s = line;
  while (*s == ' ' || *s == '\t')
    s++;
  if (*s == '\0' || *s == '#')
    return 0;
  copy = xstrdup(s);
  parts[n++] = copy;
  for (p = copy; *p; p++) {
    if (*p == '|') {
      *p = '\0';
      if (n == 5)
        die("registration.txt: more than 5 fields in row: %s", s);
      parts[n++] = p + 1;
    }
  }
  if (n != 5)
    die("registration.txt: row needs 5 fields: %s", s);
  item->subkey = parts[0];
  item->name = parts[1];
  item->type = parts[2];
  item->data = parts[3];
  item->feature = parts[4];
  return 1;
}

/* True when subkey is the Uninstall\ShellDrive key or one of its subkeys. */
static int is_uninstall_key(const char *subkey)
{
  static const char prefix[] = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\ShellDrive";
  size_t n = sizeof(prefix) - 1;
  return strncmp(subkey, prefix, n) == 0 && (subkey[n] == '\0' || subkey[n] == '\\');
}

/* Expands the placeholders of a data field into an MSI value (formatted by Windows Installer). */
static void msi_value(const char *data, const char *flavour, char *out, size_t cap)
{
  size_t n = 0;
  while (*data && n + 1 < cap) {
    if (strncmp(data, "[VERSION]", 9) == 0) {
      n += sprintf_s(out + n, cap - n, "%s", "[ProductVersion]");
      data += 9;
    } else if (strncmp(data, "[FLAVOUR]", 9) == 0) {
      n += sprintf_s(out + n, cap - n, "%s", flavour);
      data += 9;
    } else if (strncmp(data, "[INSTALLDIR32]", 14) == 0) {
      n += sprintf_s(out + n, cap - n, "%s", "[SD_INSTALLDIR32]");
      data += 14;
    } else if (strncmp(data, "[SIZEKB]", 8) == 0) {
      die("registration.txt: [SIZEKB] has no MSI property (used outside the Uninstall key): %s", data);
    } else {
      out[n++] = *data++;
    }
  }
  out[n] = '\0';
}

static int cmd_registry(int argc, char **argv)
{
  const char *in = need_arg(argc, argv, "--in");
  const char *out = need_arg(argc, argv, "--out");
  const char *flavour = need_arg(argc, argv, "--flavour");
  const char *family = need_arg(argc, argv, "--family");
  const char *win64 = need_arg(argc, argv, "--win64");
  const char *shellext32 = need_arg(argc, argv, "--shellext32");
  const char *ui = need_arg(argc, argv, "--ui");
  FILE *f, *o;
  char *line;
  reg_item *items = NULL;
  size_t count = 0, cap = 0, i;
  int first;

  if (strcmp(win64, "yes") != 0 && strcmp(win64, "no") != 0)
    die("--win64 must be yes or no%s", NULL);
  if (strcmp(shellext32, "yes") != 0 && strcmp(shellext32, "no") != 0)
    die("--shellext32 must be yes or no%s", NULL);
  if (strcmp(ui, "yes") != 0 && strcmp(ui, "no") != 0)
    die("--ui must be yes or no%s", NULL);
  if (strcmp(ui, "no") == 0 && strcmp(shellext32, "yes") == 0)
    die("--shellext32 yes needs --ui yes%s", NULL);
  f = fopen(in, "rb");
  if (!f)
    die("cannot open %s", in);

  /* Pass 1: the rows that the MSI writes, in file order. */
  while ((line = read_line(f)) != NULL) {
    reg_item item;
    if (parse_reg_row(line, &item)) {
      if (is_uninstall_key(item.subkey)) {
        /* skipped: Windows Installer writes this key for an MSI (04 §6.7) */
      } else {
        if (strcmp(item.type, "SZ") != 0 && strcmp(item.type, "DWORD") != 0)
          die("registration.txt: unknown type %s", item.type);
        if (strcmp(item.feature, "core") != 0 && strcmp(item.feature, "autostart") != 0 &&
            strcmp(item.feature, "shellext") != 0 && strcmp(item.feature, "shellext32") != 0)
          die("registration.txt: unknown feature %s", item.feature);
        item.view32 = strcmp(item.feature, "shellext32") == 0;
        if (item.view32 && strcmp(shellext32, "no") == 0) {
          /* the 32-bit view rows exist only in the packages that carry the x86 shell extension */
          free(line);
          continue;
        }
        if (strcmp(ui, "no") == 0 &&
            (strcmp(item.feature, "shellext") == 0 || strstr(item.data, "shelldrive-ui.exe") != NULL)) {
          /* no UI and no shell extension in this package: their rows would point at missing files */
          free(line);
          continue;
        }
        if (count == cap) {
          size_t ncap = cap ? cap * 2 : 32;
          reg_item *nitems = (reg_item *)xmalloc(ncap * sizeof(reg_item));
          if (count)
            memcpy(nitems, items, count * sizeof(reg_item));
          free(items);
          items = nitems;
          cap = ncap;
        }
        items[count] = item;
        sprintf_s(items[count].id, sizeof(items[count].id), "SD_Reg_%03u", (unsigned)count);
        {
          char seed[1024];
          sprintf_s(seed, sizeof(seed), "%s|registry|%s|%s%s", family, item.subkey, item.name,
                    item.view32 ? "|view32" : "");
          make_guid(seed, items[count].guid, sizeof(items[count].guid));
        }
        count++;
      }
    }
    free(line);
  }
  fclose(f);

  o = fopen(out, "wb");
  if (!o)
    die("cannot write %s", out);
  fputs("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n", o);
  fputs("<!-- Generated by tools/sd-msigen from packaging/registration.txt. Do not edit. -->\n", o);
  fputs("<Include xmlns=\"http://schemas.microsoft.com/wix/2006/wi\">\n", o);
  fputs("  <Fragment>\n    <DirectoryRef Id=\"TARGETDIR\">\n", o);
  for (i = 0; i < count; i++) {
    char value[2048];
    msi_value(items[i].data, flavour, value, sizeof(value));
    fprintf(o, "      <Component Id=\"%s\" Guid=\"%s\" Win64=\"%s\">\n", items[i].id, items[i].guid,
            items[i].view32 ? "no" : win64);
    fputs("        <RegistryValue Root=\"HKLM\" Key=\"", o);
    xml_put(o, items[i].subkey);
    fputs("\"", o);
    if (items[i].name[0]) {
      fputs(" Name=\"", o);
      xml_put(o, items[i].name);
      fputs("\"", o);
    }
    if (strcmp(items[i].type, "DWORD") == 0)
      fputs(" Type=\"integer\"", o);
    else
      fputs(" Type=\"string\"", o);
    fputs(" Value=\"", o);
    xml_put(o, value);
    fputs("\" KeyPath=\"yes\" />\n", o);
    fputs("      </Component>\n", o);
  }
  fputs("    </DirectoryRef>\n  </Fragment>\n", o);

  /* Feature groups: components are referenced by the feature tree in Product.wxs. */
  {
    static const char *groups[4] = { "core", "autostart", "shellext", "shellext32" };
    static const char *group_ids[4] = { "SD_RegCore", "SD_RegAutostart", "SD_RegShellExt", "SD_RegShellExt32" };
    int g;
    for (g = 0; g < 4; g++) {
      fprintf(o, "  <Fragment>\n    <ComponentGroup Id=\"%s\">\n", group_ids[g]);
      first = 1;
      for (i = 0; i < count; i++) {
        (void)first;
        if (strcmp(items[i].feature, groups[g]) == 0)
          fprintf(o, "      <ComponentRef Id=\"%s\" />\n", items[i].id);
      }
      fputs("    </ComponentGroup>\n  </Fragment>\n", o);
    }
  }
  fputs("</Include>\n", o);
  fclose(o);
  for (i = 0; i < count; i++) {
    free(items[i].subkey);
  }
  free(items);
  return 0;
}

/* ---- wxl ---- */

/* Appends the decoded form of one PO quoted body to dst (dst is NUL-terminated). */
static void po_decode_append(char **dst, size_t *len, size_t *cap, const char *in, size_t inlen)
{
  size_t k;
  for (k = 0; k < inlen; k++) {
    char c = in[k];
    if (*len + 2 >= *cap) {
      char *bigger;
      *cap = *cap * 2 + 64;
      bigger = (char *)xmalloc(*cap);
      memcpy(bigger, *dst, *len);
      free(*dst);
      *dst = bigger;
    }
    if (c == '\\' && k + 1 < inlen) {
      char e = in[++k];
      switch (e) {
      case 'n': c = '\n'; break;
      case 't': c = '\t'; break;
      case '"': c = '"'; break;
      case '\\': c = '\\'; break;
      default: (*dst)[(*len)++] = '\\'; c = e; break;
      }
    }
    (*dst)[(*len)++] = c;
  }
  (*dst)[*len] = '\0';
}

/* One PO field under construction. */
typedef struct {
  char *text;
  size_t len, cap;
} po_text;

static void po_text_init(po_text *t)
{
  t->cap = 64;
  t->len = 0;
  t->text = (char *)xmalloc(t->cap);
  t->text[0] = '\0';
}

static void po_text_free(po_text *t)
{
  free(t->text);
  t->text = NULL;
}

/* Adds the quoted part of one PO line (the text between the first and the last quote). */
static void po_text_quoted(po_text *t, const char *line)
{
  const char *a = strchr(line, '"');
  const char *b = strrchr(line, '"');
  if (!a || !b || b <= a)
    die("PO: malformed string line: %s", line);
  po_decode_append(&t->text, &t->len, &t->cap, a + 1, (size_t)(b - a - 1));
}

typedef struct {
  po_text ctxt, id, str;
  int has_ctxt, has_plural, fuzzy;
} po_entry;

/* Reads the next entry; returns 0 at the end of the file. */
static int po_next(FILE *f, po_entry *e)
{
  char *line;
  int field = 0; /* 1 msgctxt, 2 msgid, 3 msgstr, 4 msgid_plural, 5 msgstr[n] */
  int seen = 0;
  memset(e, 0, sizeof(*e));
  po_text_init(&e->ctxt);
  po_text_init(&e->id);
  po_text_init(&e->str);
  while ((line = read_line(f)) != NULL) {
    const char *s = line;
    while (*s == ' ' || *s == '\t')
      s++;
    if (*s == '\0') {
      free(line);
      if (seen)
        return 1;
      continue;
    }
    seen = 1;
    if (*s == '#') {
      if (s[1] == ',' && strstr(s, "fuzzy"))
        e->fuzzy = 1;
      field = 0;
    } else if (*s == '"') {
      if (field == 1)
        po_text_quoted(&e->ctxt, s);
      else if (field == 2)
        po_text_quoted(&e->id, s);
      else if (field == 3 || field == 5)
        po_text_quoted(&e->str, s);
    } else if (strncmp(s, "msgctxt", 7) == 0) {
      field = 1;
      e->has_ctxt = 1;
      e->ctxt.len = 0;
      e->ctxt.text[0] = '\0';
      po_text_quoted(&e->ctxt, s);
    } else if (strncmp(s, "msgid_plural", 12) == 0) {
      field = 4;
      e->has_plural = 1;
    } else if (strncmp(s, "msgid", 5) == 0) {
      field = 2;
      e->id.len = 0;
      e->id.text[0] = '\0';
      po_text_quoted(&e->id, s);
    } else if (strncmp(s, "msgstr[", 7) == 0) {
      field = 5;
      e->has_plural = 1;
      e->str.len = 0;
      e->str.text[0] = '\0';
      po_text_quoted(&e->str, s);
    } else if (strncmp(s, "msgstr", 6) == 0) {
      field = 3;
      e->str.len = 0;
      e->str.text[0] = '\0';
      po_text_quoted(&e->str, s);
    }
    free(line);
  }
  return seen;
}

static void po_entry_free(po_entry *e)
{
  po_text_free(&e->ctxt);
  po_text_free(&e->id);
  po_text_free(&e->str);
}

/* Writes the WiX id of a msi.* msgctxt (text after "msi."): each dot-separated segment is capitalized and the
 * dots are dropped, so msi.feature.core.title is written as FeatureCoreTitle (the loc. name in Product.wxs). */
static void put_wix_id(FILE *f, const char *s)
{
  int upper = 1;
  for (; *s; s++) {
    if (*s == '.') {
      upper = 1;
      continue;
    }
    fputc(upper && *s >= 'a' && *s <= 'z' ? *s - 'a' + 'A' : *s, f);
    upper = 0;
  }
}

static int cmd_wxl(int argc, char **argv)
{
  const char *po = need_arg(argc, argv, "--po");
  const char *culture = need_arg(argc, argv, "--culture");
  const char *lcid = need_arg(argc, argv, "--lcid");
  const char *out = need_arg(argc, argv, "--out");
  int is_en = strncmp(culture, "en-", 3) == 0;
  FILE *f = fopen(po, "rb");
  FILE *o;
  po_entry e;
  int count = 0, errors = 0;

  if (!f)
    die("cannot open %s", po);
  o = fopen(out, "wb");
  if (!o)
    die("cannot write %s", out);
  fputs("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n", o);
  fputs("<!-- Generated by tools/sd-msigen from l10n/installer. Do not edit. -->\n", o);
  fputs("<WixLocalization xmlns=\"http://schemas.microsoft.com/wix/2006/localization\" Culture=\"", o);
  xml_put(o, culture);
  fprintf(o, "\" Language=\"%s\" Codepage=\"1252\">\n", lcid);

  while (po_next(f, &e)) {
    const char *text;
    if (e.has_ctxt && strncmp(e.ctxt.text, "msi.", 4) == 0) {
      if (e.has_plural) {
        fprintf(stderr, "sd-msigen: %s: plural message in the MSI subset\n", e.ctxt.text);
        errors++;
      }
      if (e.fuzzy) {
        fprintf(stderr, "sd-msigen: %s: fuzzy translation in %s\n", e.ctxt.text, culture);
        errors++;
      }
      text = is_en ? e.id.text : e.str.text;
      if (!text || !*text) {
        fprintf(stderr, "sd-msigen: %s: empty text for %s\n", e.ctxt.text, culture);
        errors++;
      } else if (strchr(text, '{')) {
        fprintf(stderr, "sd-msigen: %s: placeholders are not allowed in MSI strings\n", e.ctxt.text);
        errors++;
      } else {
        fputs("  <String Id=\"", o);
        put_wix_id(o, e.ctxt.text + 4);
        fputs("\">", o);
        xml_put(o, text);
        fputs("</String>\n", o);
        count++;
      }
    }
    po_entry_free(&e);
  }
  fputs("</WixLocalization>\n", o);
  fclose(o);
  fclose(f);
  if (count == 0) {
    fprintf(stderr, "sd-msigen: no msi.* entries in %s\n", po);
    return 1;
  }
  return errors ? 1 : 0;
}

/* ---- lcids ---- */

typedef struct {
  const char *lang;
  const char *list; /* the build LCID first (the culture of the localized build) */
} lang_lcids;

static const lang_lcids g_lcids[] = {
  { "en", "1033" },
  /* Spanish (voseo text): es-ES build, every es-* LCID receives the same transform (C43). */
  { "es", "3082 11274 1034 2058 21514 4106 5130 6154 7178 8202 9226 10250 12298 13322 14346 15370 16394 17418 18442 19466 20490 22538" },
  { "fr", "1036 2060 3084 4108 5132 6156" },
  { "pt-BR", "1046 2070" },
  { "it", "1040 2064" },
  { "de", "1031 2055 3079 4103 5127" },
  { NULL, NULL }
};

static int cmd_lcids(int argc, char **argv)
{
  const char *lang = need_arg(argc, argv, "--lang");
  int i;
  for (i = 0; g_lcids[i].lang; i++) {
    if (strcmp(g_lcids[i].lang, lang) == 0) {
      printf("%s\n", g_lcids[i].list);
      return 0;
    }
  }
  fprintf(stderr, "sd-msigen: unknown language %s\n", lang);
  return 2;
}

int main(int argc, char **argv)
{
  if (argc < 2) {
    fprintf(stderr, "usage: sd-msigen guid|registry|wxl|lcids [options]\n");
    return 2;
  }
  if (strcmp(argv[1], "guid") == 0)
    return cmd_guid(argc, argv);
  if (strcmp(argv[1], "registry") == 0)
    return cmd_registry(argc, argv);
  if (strcmp(argv[1], "wxl") == 0)
    return cmd_wxl(argc, argv);
  if (strcmp(argv[1], "lcids") == 0)
    return cmd_lcids(argc, argv);
  fprintf(stderr, "sd-msigen: unknown command %s\n", argv[1]);
  return 2;
}
