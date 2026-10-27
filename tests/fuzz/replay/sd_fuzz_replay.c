/* sd-fuzz-replay driver: deterministic regression runner for one fuzz target (01 section 12.2).
 *
 *   sd-fuzz-<target>.exe <corpus-dir> [mutations] [seed]
 *
 * Runs every regular file of <corpus-dir> through sd_fuzz_one, then <mutations> inputs produced by a small
 * mutator seeded from [seed] (fixed default, so a failure reproduces). A violated invariant aborts the
 * process, which CTest reports as a failure. Test-only code, written for this tree (no third-party code). */
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sd_fuzz.h"

#define REPLAY_MAX_INPUT (64u * 1024u)  /* largest corpus file read: seeds may be bigger than mutations */
#define REPLAY_MUT_MAX 4096u            /* mutated inputs stay this small: fast, and enough for every parser */
#define REPLAY_MAX_FILES 1024u
#define REPLAY_DEFAULT_MUTATIONS 4000u
#define REPLAY_DEFAULT_SEED 0x5d0f2e1au

typedef struct corpus_entry {
  uint8_t *data;
  size_t size;
} corpus_entry;

typedef struct token {
  const char *bytes;
  size_t len;
} token;

#define TOK(s) { (s), sizeof(s) - 1 }

/* Tokens that matter to text and binary parsers: separators, quotes, NULs, numbers, markers. */
static const token k_tokens[] = {
  TOK("\n"), TOK("\r\n"), TOK(" "), TOK("\t"), TOK("\""), TOK("\\"), TOK("="), TOK(":"), TOK("["), TOK("]"),
  TOK("{"), TOK("}"), TOK("<"), TOK(">"), TOK("/"), TOK("&"), TOK(";"), TOK(","), TOK("\x00"), TOK("\xff"),
  TOK("\x7f"), TOK("\xef\xbb\xbf"), TOK("\xe2\x80\xae"), TOK("\xc0\xaf"), TOK("\xf4\x90\x80\x80"),
  TOK("0"), TOK("1"), TOK("-1"), TOK("2147483647"), TOK("4294967295"), TOK("18446744073709551615"),
  TOK("00000000"), TOK("\x01\x00\x00\x00"), TOK("[section]"), TOK("<!DOCTYPE x ["), TOK("<?xml "),
  TOK("<D:prop>"), TOK("HTTP/1.1 "), TOK("Content-Length: "), TOK("Transfer-Encoding: chunked\r\n"),
  TOK("ssh-ed25519"), TOK("ssh-rsa"), TOK("openssh-key-v1"), TOK("PuTTY-User-Key-File-2: "),
  TOK("Encryption: none\r\n"), TOK("-----BEGIN "), TOK("-----END "), TOK("\"version\":"), TOK("\"id\":")
};

static uint64_t g_rng;

static uint64_t rng_next(void)
{
  /* xorshift64*: deterministic, adequate for choosing mutations. */
  g_rng ^= g_rng >> 12;
  g_rng ^= g_rng << 25;
  g_rng ^= g_rng >> 27;
  return g_rng * 2685821657736338717ull;
}

static size_t rng_below(size_t n)
{
  return n ? (size_t)(rng_next() % n) : 0;
}

static size_t min_size(size_t a, size_t b)
{
  return a < b ? a : b;
}

/* Applies one random edit to buf (capacity REPLAY_MUT_MAX), updating *len. */
static void mutate_once(uint8_t *buf, size_t *len, const corpus_entry *other)
{
  size_t op = rng_below(9), pos = rng_below(*len + 1), n;
  switch (op) {
  case 0: /* flip one bit */
    if (*len) buf[rng_below(*len)] ^= (uint8_t)(1u << rng_below(8));
    break;
  case 1: /* random byte */
    if (*len) buf[rng_below(*len)] = (uint8_t)rng_next();
    break;
  case 2: { /* insert a token */
    const token *t = &k_tokens[rng_below(sizeof(k_tokens) / sizeof(k_tokens[0]))];
    if (*len + t->len <= REPLAY_MUT_MAX) {
      memmove(buf + pos + t->len, buf + pos, *len - pos);
      memcpy(buf + pos, t->bytes, t->len);
      *len += t->len;
    }
    break;
  }
  case 3: /* erase a run */
    if (*len) {
      n = 1 + rng_below(min_size(*len, 16));
      if (pos + n > *len) n = *len - pos;
      memmove(buf + pos, buf + pos + n, *len - pos - n);
      *len -= n;
    }
    break;
  case 4: /* duplicate a run */
    if (*len) {
      size_t from = rng_below(*len);
      n = 1 + rng_below(min_size(*len - from, 32));
      if (*len + n <= REPLAY_MUT_MAX) {
        memmove(buf + pos + n, buf + pos, *len - pos);
        memcpy(buf + pos, buf + from, n);
        *len += n;
      }
    }
    break;
  case 5: /* splice a run of another corpus entry */
    if (other && other->size) {
      size_t from = rng_below(other->size);
      n = 1 + rng_below(min_size(other->size - from, 64));
      if (pos + n <= REPLAY_MUT_MAX) {
        if (pos + n > *len) *len = pos + n;
        memcpy(buf + pos, other->data + from, n);
      }
    }
    break;
  case 6: /* +1 / -1 on a byte: length fields and counts */
    if (*len) buf[rng_below(*len)] += (uint8_t)(rng_below(2) ? 1 : 0xff);
    break;
  case 7: /* big-endian 32-bit field set to an extreme value */
    if (*len >= 4) {
      static const uint32_t ext[] = { 0u, 1u, 0x7fffffffu, 0x80000000u, 0xffffffffu, 0xfffffffeu, 255u, 256u, 65535u, 65536u };
      uint32_t v = ext[rng_below(sizeof(ext) / sizeof(ext[0]))];
      size_t p = rng_below(*len - 3);
      buf[p] = (uint8_t)(v >> 24);
      buf[p + 1] = (uint8_t)(v >> 16);
      buf[p + 2] = (uint8_t)(v >> 8);
      buf[p + 3] = (uint8_t)v;
    }
    break;
  default: /* truncate */
    *len = pos;
    break;
  }
}

static int read_file(const char *path, uint8_t **out, size_t *out_len)
{
  HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  LARGE_INTEGER sz;
  uint8_t *buf;
  DWORD got = 0;
  if (h == INVALID_HANDLE_VALUE) return 0;
  if (!GetFileSizeEx(h, &sz) || sz.QuadPart < 0 || sz.QuadPart > REPLAY_MAX_INPUT) {
    CloseHandle(h);
    return 0;
  }
  buf = (uint8_t *)malloc((size_t)sz.QuadPart + 1);
  if (!buf) {
    CloseHandle(h);
    return 0;
  }
  if (!ReadFile(h, buf, (DWORD)sz.QuadPart, &got, NULL) || got != (DWORD)sz.QuadPart) {
    free(buf);
    CloseHandle(h);
    return 0;
  }
  CloseHandle(h);
  *out = buf;
  *out_len = got;
  return 1;
}

static int load_corpus(const char *dir, corpus_entry *ents, size_t *count)
{
  char pattern[MAX_PATH];
  WIN32_FIND_DATAA fd;
  HANDLE f;
  size_t n = 0;
  int ok = 1;
  if (snprintf(pattern, sizeof(pattern), "%s\\*", dir) >= (int)sizeof(pattern)) return 0;
  f = FindFirstFileA(pattern, &fd);
  if (f == INVALID_HANDLE_VALUE) return 0;
  do {
    char path[MAX_PATH];
    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
    if (n >= REPLAY_MAX_FILES) break;
    if (snprintf(path, sizeof(path), "%s\\%s", dir, fd.cFileName) >= (int)sizeof(path)) { ok = 0; break; }
    ents[n].data = NULL;
    ents[n].size = 0;
    if (!read_file(path, &ents[n].data, &ents[n].size)) { ok = 0; break; }
    n++;
  } while (FindNextFileA(f, &fd));
  FindClose(f);
  *count = n;
  return ok;
}

/* C6001 is disabled for main: the analyzer cannot relate the loop bound to the entries load_corpus filled, and
   the table is calloc-zeroed, so every entry read here is initialized. */
#pragma warning(push)
#pragma warning(disable: 6001)
int main(int argc, char **argv)
{
  corpus_entry *ents;
  size_t count = 0, i;
  unsigned long mutations = REPLAY_DEFAULT_MUTATIONS;
  uint64_t seed = REPLAY_DEFAULT_SEED;
  uint8_t *work;
  size_t executed = 0;

  ents = (corpus_entry *)calloc(REPLAY_MAX_FILES, sizeof(*ents));
  if (!ents) return 1;
  if (argc < 2) {
    fprintf(stderr, "usage: sd-fuzz-<target> <corpus-dir> [mutations] [seed]\n");
    return 2;
  }
  if (argc > 2) mutations = strtoul(argv[2], NULL, 10);
  if (argc > 3) seed = strtoull(argv[3], NULL, 0);
  if (!load_corpus(argv[1], ents, &count) || count == 0) {
    fprintf(stderr, "sd-fuzz: cannot read corpus %s (or it is empty)\n", argv[1]);
    return 1;
  }

  /* Corpus replay: every seed and regression input must pass unchanged. */
  for (i = 0; i < count; i++) {
    sd_fuzz_one(ents[i].data, ents[i].size);
    executed++;
  }
  /* Degenerate inputs every parser sees. */
  sd_fuzz_one(NULL, 0);
  executed++;

  /* Deterministic mutations of corpus entries. */
  work = (uint8_t *)malloc(REPLAY_MUT_MAX + 1);
  if (!work) return 1;
  g_rng = seed ? seed : REPLAY_DEFAULT_SEED;
  for (i = 0; i < mutations; i++) {
    const corpus_entry *base = &ents[rng_below(count)];
    const corpus_entry *other = &ents[rng_below(count)];
    size_t len = min_size(base->size, REPLAY_MUT_MAX);
    unsigned rounds = 1 + (unsigned)rng_below(4), r;
    if (len) memcpy(work, base->data, len);
    for (r = 0; r < rounds; r++) mutate_once(work, &len, other);
    sd_fuzz_one(work, len);
    executed++;
  }
  free(work);
  for (i = 0; i < count; i++) free(ents[i].data);
  free(ents);

  printf("sd-fuzz: %u corpus inputs, %lu mutations, %llu inputs run, seed 0x%llx, no invariant failed\n",
         (unsigned)count, mutations, (unsigned long long)executed, (unsigned long long)seed);
  return 0;
}
#pragma warning(pop)
