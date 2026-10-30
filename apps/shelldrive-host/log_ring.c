/* In-memory log ring (see log_ring.h). The sink parses the formatted line of sd_log:
 *   <ISO time> <pid> <tid> <LEVEL> <component> [<mount id>] <message>
 * Parsing never logs; the sink runs with the logger lock held. */
#include <windows.h>
#include <string.h>

#include "log_ring.h"
#include "sd_base/sd_mem.h"
#include "sd_platform/sd_log.h"
#include "sd_platform/sd_thread.h"

static struct {
  sd_mutex lock;
  log_ring_rec *recs;           /* LOG_RING_RECORDS slots, slot = (seq - 1) % LOG_RING_RECORDS */
  uint64_t next_seq;            /* seq of the next record (starts at 1) */
  int started;
} g_ring;

/* Copies the next whitespace-delimited token of [*p, end) into out (truncated). */
static void next_token(const char **p, const char *end, char *out, size_t cap)
{
  const char *s = *p;
  size_t n = 0;
  while (s < end && (*s == ' ' || *s == '\t')) s++;
  while (s < end && *s != ' ' && *s != '\t') {
    if (n + 1 < cap) out[n++] = *s;
    s++;
  }
  out[n] = 0;
  *p = s;
}

static int level_of(const char *tok)
{
  if (strcmp(tok, "ERROR") == 0) return SD_LOG_ERROR;
  if (strcmp(tok, "WARN") == 0) return SD_LOG_WARN;
  if (strcmp(tok, "DEBUG") == 0) return SD_LOG_DEBUG;
  if (strcmp(tok, "TRACE") == 0) return SD_LOG_TRACE;
  return SD_LOG_INFO;
}

static void parse_line(const char *line, size_t len, log_ring_rec *r)
{
  const char *p = line, *end = line + len;
  char tok[64];
  memset(r, 0, sizeof(*r));
  next_token(&p, end, r->time, sizeof(r->time));
  next_token(&p, end, tok, sizeof(tok));     /* pid */
  next_token(&p, end, tok, sizeof(tok));     /* tid */
  next_token(&p, end, tok, sizeof(tok));
  r->level = level_of(tok);
  next_token(&p, end, r->component, sizeof(r->component));
  while (p < end && *p == ' ') p++;
  if (p < end && *p == '[') {
    const char *q = p + 1;
    size_t n = 0;
    while (q < end && *q != ']' && n + 1 < sizeof(r->mount_id)) r->mount_id[n++] = *q++;
    r->mount_id[n] = 0;
    if (q < end && *q == ']') p = q + 1;
  }
  while (p < end && *p == ' ') p++;
  {
    size_t n = (size_t)(end - p);
    if (n > sizeof(r->text) - 1) n = sizeof(r->text) - 1;
    memcpy(r->text, p, n);
    r->text[n] = 0;
  }
}

static void ring_sink(void *ctx, sd_log_level level, const char *line, size_t len)
{
  log_ring_rec tmp;
  SD_UNUSED(ctx);
  SD_UNUSED(level);
  parse_line(line, len, &tmp);
  sd_mutex_lock(&g_ring.lock);
  tmp.seq = g_ring.next_seq++;
  g_ring.recs[(tmp.seq - 1) % LOG_RING_RECORDS] = tmp;
  sd_mutex_unlock(&g_ring.lock);
}

sd_err log_ring_start(void)
{
  if (g_ring.started)
    return SD_OK;
  g_ring.recs = (log_ring_rec *)sd_calloc(LOG_RING_RECORDS, sizeof(log_ring_rec));
  if (g_ring.recs == NULL)
    return SD_E_NO_MEMORY;
  sd_mutex_init(&g_ring.lock);
  g_ring.next_seq = 1;
  if (sd_log_add_sink(ring_sink, NULL) != SD_OK) {
    sd_free(g_ring.recs);
    g_ring.recs = NULL;
    return SD_E_INTERNAL;
  }
  g_ring.started = 1;
  return SD_OK;
}

void log_ring_stop(void)
{
  if (!g_ring.started)
    return;
  sd_log_remove_sink(ring_sink, NULL);
  g_ring.started = 0;
  sd_free(g_ring.recs);
  g_ring.recs = NULL;
}

void log_ring_scan(uint64_t from, uint64_t *oldest, uint64_t *newest, log_ring_fn fn, void *ctx)
{
  uint64_t first, last, s;
  if (oldest) *oldest = 0;
  if (newest) *newest = 0;
  if (!g_ring.started)
    return;
  sd_mutex_lock(&g_ring.lock);
  last = g_ring.next_seq - 1;
  first = last >= LOG_RING_RECORDS ? last - LOG_RING_RECORDS + 1 : (last ? 1 : 0);
  if (oldest) *oldest = first;
  if (newest) *newest = last;
  if (last && from < first) from = first;
  for (s = from; last && s <= last; s++) {
    if (!fn(ctx, &g_ring.recs[(s - 1) % LOG_RING_RECORDS]))
      break;
  }
  sd_mutex_unlock(&g_ring.lock);
}
