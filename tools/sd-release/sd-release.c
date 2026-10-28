/* sd-release: the release signing tool (docs/design/04 §9.2, §9.3, §12.3; TM-R36, TM-R37, TM-R38, D42).
 * Build-time tool: it is never part of a shipping image. It has no network code and no key material of its own:
 * every seed is read from a file the maintainer names, and the repository holds none (TST-30).
 *
 *   sd-release hash       [--alg 256|512] FILE...           "sha256:<hex> <size> <path>" per file
 *   sd-release sums       --out SHA256SUMS FILE...          sha256sum-style lines of the release assets
 *   sd-release table      --channel C --flavour F --cab CAB --out TABLE
 *                                                           the PAYLOAD_TABLE text of one setup EXE (04 §6.1)
 *   sd-release check-table --table TABLE --cab CAB          the table against the rebuilt payload CAB
 *   sd-release manifest   --spec SPEC --root DIR --out BODY unsigned manifest.txt body: "file" lines are hashed
 *                                                           from DIR; freshness (TM-R36) is checked
 *   sd-release sign       --kind K --seed SEED --in BODY --out OUT [--sig-only]
 *                                                           ed25519 over domain || BODY; OUT is BODY + the sig line
 *                                                           (or the sig line alone with --sig-only)
 *   sd-release verify     --kind K --pub PUB --in FILE [--sig SIGFILE]
 *                                                           checks the signature: the last line of FILE, or SIGFILE;
 *                                                           a manifest must be whole (with its sig line) and parses
 *   sd-release pubkey     --seed SEED                       public key (hex) and key ID of a seed file
 *   sd-release session    --kind K --out DIR FILE...        writes DIR\SESSION.txt: the hashes an offline signing
 *                                                           session compares before it signs (D42)
 *
 * K is payload (PAYLOAD_SIG of a setup EXE), manifest, keyset or sums. The domain strings are those of sd_update.h
 * (manifest, keyset), setup_payload_sig.h (payload) and RL_SUMS_DOMAIN below (sums).
 * Seed and public key files hold 64 hex digits. Exit codes: 0 ok, 1 usage, 2 I/O or format error, 3 verification
 * failed. Messages are English (machine-readable output included). */
#define _CRT_SECURE_NO_WARNINGS 1
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sd_crypto/sd_crypto.h"
#include "sd_update/sd_update.h"
#include "setup_payload_sig.h"

#define RL_SUMS_DOMAIN   "com.librestatic.shelldrive sha256sums v1\n"
#define RL_MAX_BODY      (64u * 1024u)
#define RL_MAX_SIGFILE   256u
#define RL_STABLE_MAX_S  ((int64_t)SD_UPD_STABLE_MAX_DAYS * 86400)
#define RL_BETA_MAX_S    ((int64_t)SD_UPD_BETA_MAX_DAYS * 86400)
#define RL_SIG_LINE_LEN  118u     /* "sig ed25519 " + 16 hex + " " + 88 base64 + LF */
#define RL_MAGIC_LEN     22u      /* "shelldrive-manifest 1\n" */

enum { RC_OK = 0, RC_USAGE = 1, RC_IO = 2, RC_VERIFY = 3 };

/* ---- helpers ---- */

static int fail(int rc, const char *msg)
{
  fprintf(stderr, "sd-release: %s\n", msg);
  return rc;
}

/* Value of "--name value" among the options (argv[2] on). NULL when absent. */
static const char *opt(int argc, char **argv, const char *name)
{
  int i;
  for (i = 2; i + 1 < argc; i++) {
    if (strcmp(argv[i], name) == 0)
      return argv[i + 1];
  }
  return NULL;
}

static unsigned char *read_file(const char *path, size_t max, size_t *len)
{
  FILE *f = fopen(path, "rb");
  long n;
  unsigned char *p;

  if (f == NULL)
    return NULL;
  if (fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) < 0 || fseek(f, 0, SEEK_SET) != 0 || (size_t)n > max) {
    fclose(f);
    return NULL;
  }
  p = (unsigned char *)malloc((size_t)n + 1u);
  if (p == NULL) {
    fclose(f);
    return NULL;
  }
  if (fread(p, 1, (size_t)n, f) != (size_t)n) {
    free(p);
    fclose(f);
    return NULL;
  }
  fclose(f);
  p[n] = 0;
  *len = (size_t)n;
  return p;
}

static int write_file(const char *path, const void *p, size_t n)
{
  FILE *f = fopen(path, "wb");
  int ok;
  if (f == NULL)
    return -1;
  ok = fwrite(p, 1, n, f) == n;
  if (fclose(f) != 0)
    ok = 0;
  return ok ? 0 : -1;
}

/* Streams the file through the hash. size (optional) receives its length. 0 on success. The read buffer is on the
   heap: a 64 KB array on the stack trips /analyze (C6262). */
static int hash_file(const char *path, sd_hash_alg alg, uint8_t *out, unsigned long long *size)
{
  FILE *f = fopen(path, "rb");
  sd_hash_ctx c;
  unsigned char *buf;
  size_t n;
  unsigned long long total = 0;

  if (f == NULL)
    return -1;
  buf = (unsigned char *)malloc(65536);
  if (buf == NULL) {
    fclose(f);
    return -1;
  }
  sd_hash_init(&c, alg);
  while ((n = fread(buf, 1, 65536, f)) > 0) {
    sd_hash_update(&c, buf, n);
    total += n;
  }
  free(buf);
  if (ferror(f)) {
    fclose(f);
    return -1;
  }
  fclose(f);
  sd_hash_final(&c, out);
  if (size != NULL)
    *size = total;
  return 0;
}

static void to_hex(const uint8_t *in, size_t n, char *out)
{
  static const char h[] = "0123456789abcdef";
  size_t i;
  for (i = 0; i < n; i++) {
    out[2 * i] = h[in[i] >> 4];
    out[2 * i + 1] = h[in[i] & 15];
  }
  out[2 * n] = '\0';
}

/* Exactly n bytes from 2*n hex digits (either case). 0 on success. */
static int from_hex(const char *s, size_t n, uint8_t *out)
{
  size_t i;
  for (i = 0; i < n; i++) {
    int v[2], k;
    for (k = 0; k < 2; k++) {
      char c = s[2 * i + (size_t)k];
      if (c >= '0' && c <= '9')
        v[k] = c - '0';
      else if (c >= 'a' && c <= 'f')
        v[k] = c - 'a' + 10;
      else if (c >= 'A' && c <= 'F')
        v[k] = c - 'A' + 10;
      else
        return -1;
    }
    out[i] = (uint8_t)((v[0] << 4) | v[1]);
  }
  return 0;
}

/* Standard base64 with padding; out needs 4 * ceil(n / 3) + 1 bytes. */
static void b64_encode(const uint8_t *in, size_t n, char *out)
{
  static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  size_t i, o = 0;
  for (i = 0; i < n; i += 3) {
    uint32_t v = (uint32_t)in[i] << 16;
    size_t rem = n - i;
    if (rem > 1)
      v |= (uint32_t)in[i + 1] << 8;
    if (rem > 2)
      v |= (uint32_t)in[i + 2];
    out[o++] = tbl[(v >> 18) & 63];
    out[o++] = tbl[(v >> 12) & 63];
    out[o++] = rem > 1 ? tbl[(v >> 6) & 63] : '=';
    out[o++] = rem > 2 ? tbl[v & 63] : '=';
  }
  out[o] = '\0';
}

static int domain_for(const char *kind, const char **domain)
{
  if (strcmp(kind, "manifest") == 0)
    *domain = SD_UPD_DOMAIN_MANIFEST;
  else if (strcmp(kind, "keyset") == 0)
    *domain = SD_UPD_DOMAIN_KEYSET;
  else if (strcmp(kind, "payload") == 0)
    *domain = SD_SETUP_PSIG_DOMAIN;
  else if (strcmp(kind, "sums") == 0)
    *domain = RL_SUMS_DOMAIN;
  else
    return -1;
  return 0;
}

/* A file of 64 hex digits (a seed or a public key); surrounding white space allowed. 0 on success. */
static int read_key_hex(const char *path, uint8_t out[32])
{
  size_t n = 0;
  unsigned char *p = read_file(path, 256, &n);
  int rc = -1;
  if (p == NULL)
    return -1;
  while (n > 0 && (p[n - 1] == ' ' || p[n - 1] == '\r' || p[n - 1] == '\n' || p[n - 1] == '\t'))
    n--;
  if (n == 64 && from_hex((const char *)p, 32, out) == 0)
    rc = 0;
  free(p);
  return rc;
}

static int load_seed(const char *path, uint8_t seed[32], uint8_t pub[32])
{
  if (read_key_hex(path, seed) != 0)
    return -1;
  return sd_ed25519_pub_from_seed(pub, seed) == SD_OK ? 0 : -1;
}

/* The sig line "sig ed25519 <kid> <sig>" with LF: RL_SIG_LINE_LEN bytes; out needs one more for the NUL. */
static void make_sig_line(const uint8_t kid[8], const uint8_t sig[64], char out[RL_SIG_LINE_LEN + 1])
{
  char kh[17], b64[89];
  to_hex(kid, 8, kh);
  b64_encode(sig, 64, b64);
  snprintf(out, RL_SIG_LINE_LEN + 1, "sig ed25519 %s %s\n", kh, b64);
}

/* Parses a sig line of exactly RL_SIG_LINE_LEN bytes (LF included). 0 on success. */
static int parse_sig_line(const unsigned char *s, size_t n, uint8_t kid[8], uint8_t sig[64])
{
  if (n != RL_SIG_LINE_LEN || s[n - 1] != '\n')
    return -1;
  if (memcmp(s, "sig ed25519 ", 12) != 0 || s[28] != ' ')
    return -1;
  if (from_hex((const char *)s + 12, 8, kid) != 0)
    return -1;
  if (sd_setup_psig_b64_decode((const char *)s + 29, 88, sig, 64) != 64)
    return -1;
  return 0;
}

/* Offset of the last line when buf (n bytes) ends with a sig line of the exact length; -1 otherwise. */
static long last_sig_line(const unsigned char *buf, size_t n)
{
  size_t start;
  if (n < RL_SIG_LINE_LEN || buf[n - 1] != '\n')
    return -1;
  start = n - RL_SIG_LINE_LEN;
  if (start != 0 && buf[start - 1] != '\n')
    return -1;
  if (memcmp(buf + start, "sig ", 4) != 0)
    return -1;
  return (long)start;
}

/* Value of "key value" on a line of body (NUL-terminated). 0 when found and it fits cap. */
static int find_value(const char *body, const char *key, char *out, size_t cap)
{
  size_t kl = strlen(key);
  const char *p = body;
  while (*p != '\0') {
    const char *e = strchr(p, '\n');
    size_t len = e != NULL ? (size_t)(e - p) : strlen(p);
    if (len > kl + 1 && strncmp(p, key, kl) == 0 && p[kl] == ' ') {
      size_t vl = len - kl - 1;
      if (vl >= cap)
        return -1;
      memcpy(out, p + kl + 1, vl);
      out[vl] = '\0';
      return 0;
    }
    if (e == NULL)
      break;
    p = e + 1;
  }
  return -1;
}

/* A growing text buffer, capped at RL_MAX_BODY. */
typedef struct rl_buf {
  char *p;
  size_t n, cap;
} rl_buf;

static int buf_put(rl_buf *b, const char *s, size_t len)
{
  if (b->n + len + 1 > RL_MAX_BODY)
    return -1;
  if (b->n + len + 1 > b->cap) {
    size_t cap = b->cap ? b->cap : 4096;
    char *np;
    while (cap < b->n + len + 1)
      cap *= 2;
    if (cap > RL_MAX_BODY)
      cap = RL_MAX_BODY;
    np = (char *)realloc(b->p, cap);
    if (np == NULL)
      return -1;
    b->p = np;
    b->cap = cap;
  }
  memcpy(b->p + b->n, s, len);
  b->n += len;
  b->p[b->n] = '\0';
  return 0;
}

static const char *basename_of(const char *path)
{
  const char *b = path, *p;
  for (p = path; *p != '\0'; p++) {
    if (*p == '\\' || *p == '/')
      b = p + 1;
  }
  return b;
}

static int valid_flavour(const char *f)
{
  size_t i, n = strlen(f);
  if (n == 0 || n > 32)
    return 0;
  for (i = 0; i < n; i++) {
    char c = f[i];
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
      return 0;
  }
  return 1;
}

/* ---- commands ---- */

static int cmd_hash(int argc, char **argv)
{
  sd_hash_alg alg = SD_HASH_SHA256;
  int i, first = 2, count = 0;
  const char *a = opt(argc, argv, "--alg");
  if (a != NULL) {
    if (strcmp(a, "256") == 0)
      alg = SD_HASH_SHA256;
    else if (strcmp(a, "512") == 0)
      alg = SD_HASH_SHA512;
    else
      return fail(RC_USAGE, "--alg is 256 or 512");
    first = 4;
  }
  for (i = first; i < argc; i++) {
    uint8_t d[64];
    unsigned long long size = 0;
    char hx[129];
    if (hash_file(argv[i], alg, d, &size) != 0)
      return fail(RC_IO, "cannot read a file to hash");
    to_hex(d, sd_hash_len(alg), hx);
    printf("%s:%s %llu %s\n", alg == SD_HASH_SHA256 ? "sha256" : "sha512", hx, size, argv[i]);
    count++;
  }
  if (count == 0)
    return fail(RC_USAGE, "usage: sd-release hash [--alg 256|512] FILE...");
  return RC_OK;
}

static int cmd_sums(int argc, char **argv)
{
  const char *out = opt(argc, argv, "--out");
  rl_buf b;
  int i, count = 0, rc = RC_OK;
  memset(&b, 0, sizeof(b));
  if (out == NULL)
    return fail(RC_USAGE, "usage: sd-release sums --out SHA256SUMS FILE...");
  for (i = 2; i < argc && rc == RC_OK; i++) {
    uint8_t d[32];
    char line[256], hx[65];
    if (strcmp(argv[i], "--out") == 0) {
      i++;
      continue;
    }
    if (hash_file(argv[i], SD_HASH_SHA256, d, NULL) != 0) {
      rc = fail(RC_IO, "cannot read a file to hash");
      break;
    }
    to_hex(d, 32, hx);
    if (strlen(basename_of(argv[i])) > 128) {
      rc = fail(RC_USAGE, "file name too long");
      break;
    }
    snprintf(line, sizeof(line), "%s  %s\n", hx, basename_of(argv[i]));
    if (buf_put(&b, line, strlen(line)) != 0)
      rc = fail(RC_IO, "SHA256SUMS too large");
    count++;
  }
  if (rc == RC_OK && count == 0)
    rc = fail(RC_USAGE, "no files for SHA256SUMS");
  if (rc == RC_OK && write_file(out, b.p != NULL ? b.p : "", b.n) != 0)
    rc = fail(RC_IO, "cannot write SHA256SUMS");
  free(b.p);
  return rc;
}

static int cmd_table(int argc, char **argv)
{
  const char *channel = opt(argc, argv, "--channel"), *flavour = opt(argc, argv, "--flavour");
  const char *cab = opt(argc, argv, "--cab"), *out = opt(argc, argv, "--out");
  uint8_t d[32];
  unsigned long long size = 0;
  char hx[65], table[512];
  int n;
  if (channel == NULL || flavour == NULL || cab == NULL || out == NULL)
    return fail(RC_USAGE, "usage: sd-release table --channel C --flavour F --cab CAB --out TABLE");
  if (strcmp(channel, "stable") != 0 && strcmp(channel, "beta") != 0)
    return fail(RC_USAGE, "channel must be stable or beta");
  if (!valid_flavour(flavour))
    return fail(RC_USAGE, "flavour name: lower case letters, digits and '-'");
  if (hash_file(cab, SD_HASH_SHA256, d, &size) != 0 || size == 0)
    return fail(RC_IO, "cannot read the payload CAB");
  to_hex(d, 32, hx);
  n = snprintf(table, sizeof(table), "shelldrive-payload-table 1\nproduct %s\nchannel %s\n%s %s %llu\n",
               SD_SETUP_PSIG_PRODUCT, channel, flavour, hx, size);
  if (n <= 0 || (size_t)n >= sizeof(table))
    return fail(RC_IO, "table overflow");
  if (write_file(out, table, (size_t)n) != 0)
    return fail(RC_IO, "cannot write the table");
  return RC_OK;
}

/* The table must be the exact format of cmd_table: the magic, product and channel lines and one flavour line. */
static int cmd_check_table(int argc, char **argv)
{
  const char *tpath = opt(argc, argv, "--table"), *cab = opt(argc, argv, "--cab");
  size_t tn = 0, i = 0, line_no = 0;
  unsigned char *t;
  char channel[16], flavour[40], want[65], got[65], line[160];
  unsigned long long size = 0, want_size = 0;
  uint8_t d[32];
  int rc;
  if (tpath == NULL || cab == NULL)
    return fail(RC_USAGE, "usage: sd-release check-table --table TABLE --cab CAB");
  t = read_file(tpath, RL_MAX_BODY, &tn);
  if (t == NULL)
    return fail(RC_IO, "cannot read the table");
  rc = RC_OK;
  if (tn < 30 || memcmp(t, "shelldrive-payload-table 1\n", 27) != 0)
    rc = -1;
  if (rc == RC_OK && sd_setup_psig_table_channel(t, tn, channel, sizeof(channel)) != 0)
    rc = -1;
  if (rc == RC_OK && (strcmp(channel, "stable") != 0 && strcmp(channel, "beta") != 0))
    rc = -1;
  while (rc == RC_OK && i < tn) {
    size_t e = i;
    while (e < tn && t[e] != '\n')
      e++;
    if (e - i >= sizeof(line))
      rc = -1;
    else {
      memcpy(line, t + i, e - i);
      line[e - i] = '\0';
    }
    if (rc == RC_OK && line_no == 3) {
      char *sp = strchr(line, ' ');
      if (sp == NULL || (size_t)(sp - line) >= sizeof(flavour))
        rc = -1;
      else {
        *sp = '\0';
        strcpy(flavour, line);
        if (!valid_flavour(flavour) || sscanf(sp + 1, "%64s %llu", want, &want_size) != 2 || strlen(want) != 64)
          rc = -1;
      }
    } else if (rc == RC_OK && line_no > 3) {
      rc = -1;
    }
    line_no++;
    i = e + 1;
  }
  if (rc == RC_OK && line_no != 4)
    rc = -1;
  if (rc != RC_OK) {
    free(t);
    return fail(RC_IO, "malformed payload table");
  }
  if (hash_file(cab, SD_HASH_SHA256, d, &size) != 0) {
    free(t);
    return fail(RC_IO, "cannot read the CAB");
  }
  to_hex(d, 32, got);
  free(t);
  if (strcmp(want, got) != 0 || size != want_size)
    return fail(RC_VERIFY, "the CAB does not match the table");
  printf("OK %s %s %llu\n", flavour, got, size);
  return RC_OK;
}

/* Freshness and identity rules of a manifest body (TM-R36): product, channel, dates (expires <= released + 30 days
   for stable, + 14 days for beta), version and serial present. */
static int check_manifest_fields(const char *body)
{
  char ch[64], rel_s[32], exp_s[32], ver[40], serial[32];
  int64_t rel = 0, exp = 0, max;
  if (find_value(body, "product", ch, sizeof(ch)) != 0 || strcmp(ch, SD_UPD_PRODUCT) != 0)
    return fail(RC_USAGE, "product must be com.librestatic.shelldrive");
  if (find_value(body, "channel", ch, sizeof(ch)) != 0)
    return fail(RC_USAGE, "channel is missing");
  if (strcmp(ch, "stable") != 0 && strcmp(ch, "beta") != 0)
    return fail(RC_USAGE, "channel must be stable or beta");
  if (find_value(body, "released", rel_s, sizeof(rel_s)) != 0 || find_value(body, "expires", exp_s, sizeof(exp_s)) != 0)
    return fail(RC_USAGE, "released and expires are required");
  if (sd_upd_time_parse(rel_s, strlen(rel_s), &rel) != SD_UPD_OK ||
      sd_upd_time_parse(exp_s, strlen(exp_s), &exp) != SD_UPD_OK)
    return fail(RC_USAGE, "released or expires is not YYYY-MM-DDTHH:MM:SSZ");
  if (exp <= rel)
    return fail(RC_USAGE, "expires must be after released");
  max = strcmp(ch, "stable") == 0 ? RL_STABLE_MAX_S : RL_BETA_MAX_S;
  if (exp - rel > max)
    return fail(RC_USAGE, "expires is more than 30 days (stable) or 14 days (beta) after released (TM-R36)");
  if (find_value(body, "version", ver, sizeof(ver)) != 0)
    return fail(RC_USAGE, "version is missing");
  if (find_value(body, "serial", serial, sizeof(serial)) != 0)
    return fail(RC_USAGE, "serial is missing");
  return RC_OK;
}

static int cmd_manifest(int argc, char **argv)
{
  const char *spec = opt(argc, argv, "--spec"), *root = opt(argc, argv, "--root"), *out = opt(argc, argv, "--out");
  size_t sn = 0, i = 0;
  unsigned char *s;
  rl_buf b;
  int rc = RC_OK;
  if (spec == NULL || root == NULL || out == NULL)
    return fail(RC_USAGE, "usage: sd-release manifest --spec SPEC --root DIR --out BODY");
  s = read_file(spec, RL_MAX_BODY, &sn);
  if (s == NULL)
    return fail(RC_IO, "cannot read the spec (64 KB max)");
  {
    /* A spec saved on Windows may end its lines with CR LF; the body is LF only (04 §9.2). */
    size_t r, w = 0;
    for (r = 0; r < sn; r++) {
      if (s[r] == '\r' && r + 1 < sn && s[r + 1] == '\n')
        continue;
      s[w++] = s[r];
    }
    sn = w;
    s[sn] = '\0';
  }
  memset(&b, 0, sizeof(b));
  if (buf_put(&b, "shelldrive-manifest 1\n", RL_MAGIC_LEN) != 0) {
    free(s);
    return fail(RC_IO, "out of memory");
  }
  while (i < sn && rc == RC_OK) {
    size_t e = i, ll;
    const char *line;
    while (e < sn && s[e] != '\n')
      e++;
    line = (const char *)s + i;
    ll = e - i;
    if (ll == 0 || (ll >= 4 && memcmp(line, "sig ", 4) == 0) ||
        (ll >= 10 && memcmp(line, "shelldrive", 10) == 0)) {
      rc = fail(RC_USAGE, "spec lines: no blank lines, no sig lines, no manifest header line");
    } else if (ll >= 5 && memcmp(line, "file ", 5) == 0) {
      /* file <id> <name> <relative path>; the line written is file <id> <name> <size> sha256:<hex> */
      char id[40], name[160], rel[512], path[1024], fline[512], hx[65], tmp[1024];
      uint8_t d[32];
      unsigned long long size = 0;
      int nf;
      if (ll >= sizeof(tmp)) {
        rc = fail(RC_USAGE, "file line too long");
      } else {
        memcpy(tmp, line, ll);
        tmp[ll] = '\0';
        nf = sscanf(tmp + 5, "%39s %159s %511s", id, name, rel);
        if (nf != 3 || strlen(tmp + 5) != strlen(id) + strlen(name) + strlen(rel) + 2)
          rc = fail(RC_USAGE, "file line: file <id> <name> <relative path>");
        else if (strpbrk(name, "\\/:*?\"<>|") != NULL || name[0] == '.')
          rc = fail(RC_USAGE, "file name: no separators, no leading dot");
        else if (strlen(root) + strlen(rel) + 2 > sizeof(path))
          rc = fail(RC_USAGE, "file path too long");
        else {
          snprintf(path, sizeof(path), "%s\\%s", root, rel);
          if (hash_file(path, SD_HASH_SHA256, d, &size) != 0) {
            rc = fail(RC_IO, "cannot read a file of the manifest");
          } else {
            to_hex(d, 32, hx);
            snprintf(fline, sizeof(fline), "file %s %s %llu sha256:%s\n", id, name, size, hx);
            if (buf_put(&b, fline, strlen(fline)) != 0)
              rc = fail(RC_IO, "manifest too large");
          }
        }
      }
    } else if (buf_put(&b, line, ll) != 0 || buf_put(&b, "\n", 1) != 0) {
      rc = fail(RC_IO, "manifest too large");
    }
    i = e + 1;
  }
  if (rc == RC_OK && b.p != NULL)
    rc = check_manifest_fields(b.p + RL_MAGIC_LEN);
  if (rc == RC_OK && write_file(out, b.p, b.n) != 0)
    rc = fail(RC_IO, "cannot write the manifest body");
  free(s);
  free(b.p);
  return rc;
}

static int cmd_sign(int argc, char **argv)
{
  const char *kind = opt(argc, argv, "--kind"), *seed = opt(argc, argv, "--seed");
  const char *in = opt(argc, argv, "--in"), *out = opt(argc, argv, "--out");
  const char *domain = NULL;
  int sig_only = 0, i, rc = RC_OK;
  size_t bn = 0, total, dl;
  unsigned char *body, *msg, *full;
  uint8_t seedv[32], pub[32], kid[8], sig[64];
  char line[RL_SIG_LINE_LEN + 1], kh[17], ph[65];
  for (i = 2; i < argc; i++) {
    if (strcmp(argv[i], "--sig-only") == 0)
      sig_only = 1;
  }
  if (kind == NULL || seed == NULL || in == NULL || out == NULL || domain_for(kind, &domain) != 0)
    return fail(RC_USAGE, "usage: sd-release sign --kind manifest|keyset|payload|sums --seed SEED --in BODY --out OUT [--sig-only]");
  body = read_file(in, RL_MAX_BODY, &bn);
  if (body == NULL || bn == 0 || body[bn - 1] != '\n')
    return fail(RC_IO, "cannot read the body (64 KB max, LF at the end)");
  if (last_sig_line(body, bn) >= 0 || strncmp((const char *)body, "sig ", 4) == 0 ||
      strstr((const char *)body, "\nsig ") != NULL) {
    free(body);
    return fail(RC_USAGE, "the body already carries a sig line");
  }
  if (load_seed(seed, seedv, pub) != 0) {
    free(body);
    return fail(RC_IO, "cannot read the seed file (64 hex digits)");
  }
  dl = strlen(domain);
  total = dl + bn;
  msg = (unsigned char *)malloc(total);
  if (msg == NULL) {
    free(body);
    return fail(RC_IO, "out of memory");
  }
  memcpy(msg, domain, dl);
  memcpy(msg + dl, body, bn);
  if (sd_ed25519_sign(sig, seedv, pub, msg, total) != SD_OK) {
    rc = fail(RC_IO, "signing failed");
  }
  memset(seedv, 0, sizeof(seedv));
  free(msg);
  if (rc == RC_OK) {
    sd_upd_key_id(pub, kid);
    make_sig_line(kid, sig, line);
    full = (unsigned char *)malloc(bn + RL_SIG_LINE_LEN);
    if (full == NULL) {
      rc = fail(RC_IO, "out of memory");
    } else {
      size_t out_len = sig_only ? RL_SIG_LINE_LEN : bn + RL_SIG_LINE_LEN;
      const unsigned char *src = sig_only ? (const unsigned char *)line : full;
      if (!sig_only) {
        memcpy(full, body, bn);
        memcpy(full + bn, line, RL_SIG_LINE_LEN);
      }
      if (strcmp(kind, "manifest") == 0 && !sig_only) {
        /* The signed file must parse as a manifest (04 §9.2) before it is written. */
        sd_upd_manifest m;
        sd_upd_res r = sd_upd_manifest_parse(full, out_len, &m);
        if (r != SD_UPD_OK) {
          fprintf(stderr, "sd-release: the manifest does not parse (%s)\n", sd_upd_res_name(r));
          rc = RC_USAGE;
        }
      }
      if (rc == RC_OK && write_file(out, src, out_len) != 0)
        rc = fail(RC_IO, "cannot write the output");
      free(full);
    }
    if (rc == RC_OK) {
      to_hex(kid, 8, kh);
      to_hex(pub, 32, ph);
      printf("signed kind %s key %s pub %s\n", kind, kh, ph);
    }
  }
  free(body);
  return rc;
}

static int cmd_verify(int argc, char **argv)
{
  const char *kind = opt(argc, argv, "--kind"), *pubp = opt(argc, argv, "--pub");
  const char *in = opt(argc, argv, "--in"), *sigp = opt(argc, argv, "--sig");
  const char *domain = NULL;
  size_t fn = 0, sn = 0, bl = 0, dl;
  unsigned char *file = NULL, *sigb = NULL, *msg;
  const unsigned char *body, *sline;
  uint8_t pub[32], pub_kid[8], kid[8], sig[64];
  long start;
  int rc = RC_VERIFY;
  char kh[17];
  if (kind == NULL || pubp == NULL || in == NULL || domain_for(kind, &domain) != 0)
    return fail(RC_USAGE, "usage: sd-release verify --kind K --pub PUB --in FILE [--sig SIGFILE]");
  if (sigp != NULL && strcmp(kind, "manifest") == 0)
    return fail(RC_USAGE, "a manifest is verified whole (with its sig line): omit --sig");
  if (read_key_hex(pubp, pub) != 0)
    return fail(RC_IO, "cannot read the public key file (64 hex digits)");
  file = read_file(in, RL_MAX_BODY + RL_SIG_LINE_LEN, &fn);
  if (file == NULL)
    return fail(RC_IO, "cannot read the file to verify");
  if (sigp != NULL) {
    sigb = read_file(sigp, RL_MAX_SIGFILE, &sn);
    if (sigb == NULL || sn != RL_SIG_LINE_LEN) {
      free(file);
      free(sigb);
      return fail(RC_VERIFY, "the signature file holds one sig line");
    }
    body = file;
    bl = fn;
    sline = sigb;
  } else {
    start = last_sig_line(file, fn);
    if (start < 0) {
      free(file);
      return fail(RC_VERIFY, "the file does not end with a sig line");
    }
    body = file;
    bl = (size_t)start;
    sline = file + start;
    sn = RL_SIG_LINE_LEN;
  }
  if (parse_sig_line(sline, sn, kid, sig) != 0) {
    free(file);
    free(sigb);
    return fail(RC_VERIFY, "malformed sig line");
  }
  sd_upd_key_id(pub, pub_kid);
  if (memcmp(pub_kid, kid, 8) != 0) {
    free(file);
    free(sigb);
    return fail(RC_VERIFY, "the sig key ID does not match the public key");
  }
  dl = strlen(domain);
  msg = (unsigned char *)malloc(dl + bl + 1);
  if (msg == NULL) {
    free(file);
    free(sigb);
    return fail(RC_IO, "out of memory");
  }
  memcpy(msg, domain, dl);
  if (bl > 0)
    memcpy(msg + dl, body, bl);
  if (sd_ed25519_verify(sig, pub, msg, dl + bl) == SD_OK)
    rc = RC_OK;
  free(msg);
  if (rc != RC_OK) {
    free(file);
    free(sigb);
    return fail(RC_VERIFY, "signature does not verify");
  }
  if (strcmp(kind, "manifest") == 0) {
    sd_upd_manifest m;
    sd_upd_res r = sd_upd_manifest_parse(file, fn, &m);
    if (r != SD_UPD_OK) {
      free(file);
      free(sigb);
      fprintf(stderr, "sd-release: the manifest does not parse (%s)\n", sd_upd_res_name(r));
      return RC_VERIFY;
    }
    printf("manifest channel %s serial %llu version %s released %lld expires %lld files %u\n", m.channel,
           (unsigned long long)m.serial, m.version_str, (long long)m.released, (long long)m.expires,
           (unsigned)m.nfiles);
  }
  to_hex(kid, 8, kh);
  printf("OK %s key %s\n", kind, kh);
  free(file);
  free(sigb);
  return RC_OK;
}

static int cmd_pubkey(int argc, char **argv)
{
  const char *seed = opt(argc, argv, "--seed");
  uint8_t sd[32], pub[32], kid[8];
  char ph[65], kh[17];
  if (seed == NULL)
    return fail(RC_USAGE, "usage: sd-release pubkey --seed SEED");
  if (load_seed(seed, sd, pub) != 0)
    return fail(RC_IO, "cannot read the seed file (64 hex digits)");
  memset(sd, 0, sizeof(sd));
  sd_upd_key_id(pub, kid);
  to_hex(pub, 32, ph);
  to_hex(kid, 8, kh);
  printf("pub %s kid %s\n", ph, kh);
  return RC_OK;
}

/* SESSION.txt: what an offline signing session compares before it signs (04 §12.3 steps 5 and 7, D42). It lists
   the SHA-256 of every file; with exactly one body (not sums), it also gives the digest of the signed message,
   domain || body, which the signing machine prints again after signing. */
static int cmd_session(int argc, char **argv)
{
  const char *kind = opt(argc, argv, "--kind"), *dir = opt(argc, argv, "--out");
  const char *domain = NULL, *single = NULL;
  char path[1024], line[512];
  rl_buf b;
  int i, count = 0, rc = RC_OK;
  memset(&b, 0, sizeof(b));
  if (kind == NULL || dir == NULL || domain_for(kind, &domain) != 0)
    return fail(RC_USAGE, "usage: sd-release session --kind K --out DIR FILE...");
  snprintf(line, sizeof(line), "shelldrive-release-session 1\nkind %s\ndomain %.*s\n", kind,
           (int)(strlen(domain) - 1), domain);
  if (buf_put(&b, line, strlen(line)) != 0)
    rc = fail(RC_IO, "out of memory");
  for (i = 2; i < argc && rc == RC_OK; i++) {
    uint8_t d[32];
    char hx[65];
    if (strcmp(argv[i], "--kind") == 0 || strcmp(argv[i], "--out") == 0) {
      i++;
      continue;
    }
    if (hash_file(argv[i], SD_HASH_SHA256, d, NULL) != 0) {
      rc = fail(RC_IO, "cannot read a file of the session");
      break;
    }
    to_hex(d, 32, hx);
    snprintf(line, sizeof(line), "file sha256:%s %s\n", hx, basename_of(argv[i]));
    if (buf_put(&b, line, strlen(line)) != 0)
      rc = fail(RC_IO, "session too large");
    single = argv[i];
    count++;
  }
  if (rc == RC_OK && count == 0)
    rc = fail(RC_USAGE, "no files for the session");
  if (rc == RC_OK && count == 1 && strcmp(kind, "sums") != 0) {
    unsigned char *body;
    size_t bn = 0;
    sd_hash_ctx c;
    uint8_t md[32];
    char hx[65];
    body = read_file(single, RL_MAX_BODY, &bn);
    if (body == NULL) {
      rc = fail(RC_IO, "cannot read the body of the session");
    } else {
      sd_hash_init(&c, SD_HASH_SHA256);
      sd_hash_update(&c, domain, strlen(domain));
      sd_hash_update(&c, body, bn);
      sd_hash_final(&c, md);
      to_hex(md, 32, hx);
      snprintf(line, sizeof(line), "message sha256:%s\n", hx);
      if (buf_put(&b, line, strlen(line)) != 0)
        rc = fail(RC_IO, "session too large");
      free(body);
    }
  }
  if (rc == RC_OK) {
    snprintf(path, sizeof(path), "%s\\SESSION.txt", dir);
    if (write_file(path, b.p, b.n) != 0)
      rc = fail(RC_IO, "cannot write SESSION.txt");
    else
      printf("wrote %s\n", path);
  }
  free(b.p);
  return rc;
}

static void usage(void)
{
  fprintf(stderr, "usage: sd-release hash|sums|table|check-table|manifest|sign|verify|pubkey|session ... "
                  "(see the header of tools/sd-release/sd-release.c)\n");
}

int main(int argc, char **argv)
{
  if (argc < 2) {
    usage();
    return RC_USAGE;
  }
  if (strcmp(argv[1], "hash") == 0)
    return cmd_hash(argc, argv);
  if (strcmp(argv[1], "sums") == 0)
    return cmd_sums(argc, argv);
  if (strcmp(argv[1], "table") == 0)
    return cmd_table(argc, argv);
  if (strcmp(argv[1], "check-table") == 0)
    return cmd_check_table(argc, argv);
  if (strcmp(argv[1], "manifest") == 0)
    return cmd_manifest(argc, argv);
  if (strcmp(argv[1], "sign") == 0)
    return cmd_sign(argc, argv);
  if (strcmp(argv[1], "verify") == 0)
    return cmd_verify(argc, argv);
  if (strcmp(argv[1], "pubkey") == 0)
    return cmd_pubkey(argc, argv);
  if (strcmp(argv[1], "session") == 0)
    return cmd_session(argc, argv);
  usage();
  return RC_USAGE;
}
