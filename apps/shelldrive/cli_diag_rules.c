/* Pure rules of the diag checks; see cli_diag_rules.h. */
#include <stdio.h>
#include <string.h>

#include "cli_diag_rules.h"

#define RULE_PART_MAX 999999u

static int is_blank(char c)
{
  return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ',';
}

/* Parses a decimal number of exactly n characters (no sign, no blank); 0 on error. */
static int parse_num(const char *s, size_t n, unsigned *out)
{
  unsigned v = 0;
  size_t i;
  if (n == 0 || n > 6)
    return 0;
  for (i = 0; i < n; i++) {
    if (s[i] < '0' || s[i] > '9')
      return 0;
    v = v * 10u + (unsigned)(s[i] - '0');
  }
  if (v > RULE_PART_MAX)
    return 0;
  *out = v;
  return 1;
}

uint32_t diag_version_pack(unsigned major, unsigned minor, unsigned patch)
{
  if (major > RULE_PART_MAX || minor > 999u || patch > 999u)
    return 0;
  return major * 1000000u + minor * 1000u + patch;
}

uint32_t diag_version_parse(const char *s, size_t len)
{
  unsigned part[4] = { 0, 0, 0, 0 };
  int n = 0;
  size_t i = 0, start = 0;
  if (s == NULL)
    return 0;
  for (i = 0; i <= len; i++) {
    if (i == len || s[i] == '.') {
      if (n >= 4 || !parse_num(s + start, i - start, &part[n]))
        return 0;
      n++;
      start = i + 1;
    }
  }
  if (n < 2)
    return 0;
  return diag_version_pack(part[0], part[1], part[2]);
}

void diag_version_text(uint32_t packed, char *out, size_t cap)
{
  if (cap == 0)
    return;
  if (packed == 0) {
    out[0] = 0;
    return;
  }
  (void)sprintf_s(out, cap, "%u.%u.%u", (unsigned)(packed / 1000000u), (unsigned)((packed / 1000u) % 1000u),
                  (unsigned)(packed % 1000u));
}

/* One token of text: [*pos, *end) without blanks; returns 0 at the end of the text. */
static int next_token(const char *text, size_t len, size_t *pos, size_t *start, size_t *end)
{
  size_t i = *pos;
  while (i < len && is_blank(text[i]))
    i++;
  if (i >= len)
    return 0;
  *start = i;
  while (i < len && !is_blank(text[i]))
    i++;
  *end = i;
  *pos = i;
  return 1;
}

void diag_deny_parse(diag_deny_list *d, const char *text, size_t len)
{
  size_t line_start = 0;
  size_t i;
  /* walk line by line so that a token of another line never joins a deny line */
  for (i = 0; i <= len; i++) {
    if (i == len || text[i] == '\n') {
      size_t a, b, c, e, p = line_start;
      size_t dash;
      uint32_t from, to;
      diag_deny_range *rg;
      if (d->count < DIAG_DENY_MAX && next_token(text, i, &p, &a, &b) && b - a == 11 &&
          memcmp(text + a, "dokany-deny", 11) == 0 && next_token(text, i, &p, &c, &e)) {
        /* range: <min>-<max> */
        dash = c;
        while (dash < e && text[dash] != '-')
          dash++;
        if (dash < e && dash > c) {
          from = diag_version_parse(text + c, dash - c);
          to = diag_version_parse(text + dash + 1, e - dash - 1);
          if (from != 0 && to != 0 && from <= to) {
            size_t rs, re, rl;
            rg = &d->range[d->count];
            rg->from = from;
            rg->to = to;
            /* a line without a reason id still denies (the list is signed); the reason shows as "unspecified" */
            strcpy_s(rg->reason, sizeof(rg->reason), "unspecified");
            rs = 0;
            re = 0;
            if (next_token(text, i, &p, &rs, &re)) {
              rl = re - rs;
              if (rl >= DIAG_DENY_REASON)
                rl = DIAG_DENY_REASON - 1;
              memcpy(rg->reason, text + rs, rl);
              rg->reason[rl] = 0;
            }
            d->count++;
          }
        }
      }
      line_start = i + 1;
    }
  }
}

const char *diag_deny_match(const diag_deny_list *d, uint32_t ver)
{
  int i;
  if (ver == 0)
    return NULL;
  for (i = 0; i < d->count; i++)
    if (ver >= d->range[i].from && ver <= d->range[i].to)
      return d->range[i].reason;
  return NULL;
}

/* 1 when the token (len bytes at tok) is one of the tokens of list. */
static int token_in(const char *list, size_t ln, const char *tok, size_t len)
{
  size_t pos = 0, a, b;
  while (next_token(list, ln, &pos, &a, &b))
    if (b - a == len && memcmp(list + a, tok, len) == 0)
      return 1;
  return 0;
}

void diag_netloc_compare(const char *present, const char *wanted, int *missing, int *stale, int *wanted_count)
{
  size_t pl = strlen(present), wl = strlen(wanted), pos, a, b;
  *missing = 0;
  *stale = 0;
  *wanted_count = 0;
  pos = 0;
  while (next_token(wanted, wl, &pos, &a, &b)) {
    (*wanted_count)++;
    if (!token_in(present, pl, wanted + a, b - a))
      (*missing)++;
  }
  pos = 0;
  while (next_token(present, pl, &pos, &a, &b))
    if (!token_in(wanted, wl, present + a, b - a))
      (*stale)++;
}
