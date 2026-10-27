/* State snapshot producer (03 §8.2.1). See state_producer.h. */
#include <windows.h>
#include <string.h>

#include "state_producer.h"
#include "sd_base/sd_mem.h"
#include "sd_platform/sd_log.h"
#include "sd_state/sd_state.h"

#define SP_LOG "state"

static sd_state_writer *g_writer;
static sd_state_entry *g_entries;          /* SD_STATE_MAX_ENTRIES, allocated at open */

static void utf8_into(const char *s, wchar_t *dst, uint32_t cch, int *cut)
{
  wchar_t tmp[1024];           /* room for any UTF-8 input the agent stores (paths are at most 1024 bytes) */
  tmp[0] = 0;
  if (s && s[0]) {
    if (MultiByteToWideChar(CP_UTF8, 0, s, -1, tmp, (int)SD_COUNTOF(tmp)) == 0)
      tmp[0] = 0;
    tmp[SD_COUNTOF(tmp) - 1] = 0;
  }
  if (sd_state_set_string(dst, cch, tmp))
    *cut = 1;
}

sd_err host_state_open(void)
{
  sd_err e;
  if (g_writer != NULL)
    return SD_OK;
  g_entries = (sd_state_entry *)sd_calloc(SD_STATE_MAX_ENTRIES, sizeof(sd_state_entry));
  if (g_entries == NULL)
    return SD_E_NO_MEMORY;
  e = sd_state_writer_open(&g_writer);
  if (e != SD_OK) {
    g_writer = NULL;
    sd_free(g_entries);
    g_entries = NULL;
    return e;
  }
  host_state_publish(NULL, 0, 0);
  return SD_OK;
}

void host_state_publish(const host_state_src *items, uint32_t n, uint32_t flags)
{
  sd_state_publish p;
  uint32_t i, cuts = 0;
  sd_err e;
  if (g_writer == NULL || g_entries == NULL)
    return;
  if (n > SD_STATE_MAX_ENTRIES)
    n = SD_STATE_MAX_ENTRIES;
  memset(g_entries, 0, n * sizeof(sd_state_entry));
  for (i = 0; i < n; i++) {
    const host_state_src *s = &items[i];
    sd_state_entry *d = &g_entries[i];
    int cut = 0;
    d->flags = (s->read_only ? SD_STATE_EF_READ_ONLY : 0u) |
               (s->network_location ? SD_STATE_EF_NETWORK_LOCATION : 0u);
    d->state = s->state;
    d->backend = s->backend;
    d->mount_num = s->mount_num;
    d->letter = (uint16_t)((s->letter >= L'A' && s->letter <= L'Z') ? s->letter : 0);
    utf8_into(s->mount_id, d->mount_id, SD_STATE_ID_CCH, &cut);
    utf8_into(s->profile_id, d->profile_id, SD_STATE_ID_CCH, &cut);
    utf8_into(s->profile_name, d->profile_name, SD_STATE_NAME_CCH, &cut);
    if (d->letter) {
      wchar_t t[4];
      t[0] = (wchar_t)d->letter;
      t[1] = L':';
      t[2] = 0;
      (void)sd_state_set_string(d->target, SD_STATE_TARGET_CCH, t);
    }
    if (sd_state_set_string(d->label, SD_STATE_LABEL_CCH, s->label ? s->label : L""))
      cut = 1;
    utf8_into(s->remote_url, d->remote_url, SD_STATE_URL_CCH, &cut);
    if (cut)
      d->flags |= SD_STATE_EF_TRUNCATED;
  }
  memset(&p, 0, sizeof(p));
  p.entries = g_entries;
  p.entry_count = n;
  p.flags = flags;
  e = sd_state_writer_publish(g_writer, &p, &cuts);
  if (e != SD_OK)
    SD_LOGW(SP_LOG, "snapshot publish failed (%s)", sd_err_name(e));
  else if (cuts)
    SD_LOGW(SP_LOG, "snapshot: %u entries cut to their slots", (unsigned)cuts);
}

void host_state_close(void)
{
  if (g_writer == NULL)
    return;
  host_state_publish(NULL, 0, SD_STATE_HF_SHUTTING_DOWN);
  sd_state_writer_close(g_writer);
  g_writer = NULL;
  sd_free(g_entries);
  g_entries = NULL;
}
