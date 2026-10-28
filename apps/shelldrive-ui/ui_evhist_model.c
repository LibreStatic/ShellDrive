/* shelldrive-ui: the model of the agent's event history (ui_evhist_model.h). */
#include <string.h>

#include "ui_evhist_model.h"

static void put(char *dst, size_t cap, const char *src)
{
  size_t i = 0;
  if (src != NULL)
    for (; src[i] != 0 && i + 1 < cap; i++)
      dst[i] = src[i];
  dst[i] = 0;
}

static int known_event(const char *e)
{
  return e != NULL && (strcmp(e, "mount.state") == 0 || strcmp(e, "warning") == 0 ||
                       strcmp(e, "hostkeys.announced") == 0);
}

void ui_evh_init(ui_evh_state *s)
{
  memset(s, 0, sizeof(*s));
}

void ui_evh_note_live(ui_evh_state *s, const char *event, const char *mount_id, const char *key, long long now)
{
  ui_evh_live *l;
  if (s == NULL || !known_event(event))
    return;
  l = &s->live[s->next];
  memset(l, 0, sizeof(*l));
  l->used = 1;
  l->time = now;
  put(l->event, sizeof(l->event), event);
  put(l->mount_id, sizeof(l->mount_id), mount_id);
  put(l->key, sizeof(l->key), key);
  s->next = (s->next + 1) % UI_EVH_LIVE_SLOTS;
}

int ui_evh_parse(const sd_json *rec, ui_evh_rec *out)
{
  int64_t seq = 0, t = 0;
  const char *ev;
  if (rec == NULL || out == NULL)
    return 0;
  memset(out, 0, sizeof(*out));
  ev = sd_json_get_str(rec, "event");
  if (!known_event(ev) || !sd_json_get_int64(rec, "seq", &seq) || seq < 1)
    return 0;
  (void)sd_json_get_int64(rec, "time", &t);
  out->seq = (unsigned long long)seq;
  out->time = t;
  put(out->event, sizeof(out->event), ev);
  put(out->mount_id, sizeof(out->mount_id), sd_json_get_str(rec, "mount_id"));
  put(out->state, sizeof(out->state), sd_json_get_str(rec, "state"));
  put(out->code, sizeof(out->code), sd_json_get_str(rec, "code"));
  return 1;
}

void ui_evh_begin(ui_evh_state *s, unsigned long long last_seq)
{
  /* sequence numbers count from 1 in each agent process: a last_seq below the one imported is a new agent */
  s->min_seq = (s->imported_seq != 0 && last_seq >= s->imported_seq) ? s->imported_seq + 1 : 1;
}

int ui_evh_wanted(ui_evh_state *s, const ui_evh_rec *r)
{
  const char *key;
  size_t i;
  if (r->seq < s->min_seq)
    return 0;
  key = strcmp(r->event, "mount.state") == 0 ? r->state : (strcmp(r->event, "warning") == 0 ? r->code : "");
  for (i = 0; i < UI_EVH_LIVE_SLOTS; i++) {
    ui_evh_live *l = &s->live[i];
    long long d;
    if (!l->used || strcmp(l->event, r->event) != 0 || strcmp(l->mount_id, r->mount_id) != 0 ||
        strcmp(l->key, key) != 0)
      continue;
    d = l->time - r->time;
    if (d < 0)
      d = -d;
    if (d <= UI_EVH_MATCH_SECONDS) {
      l->used = 0;                 /* said once by the live event */
      return 0;
    }
  }
  return 1;
}

void ui_evh_end(ui_evh_state *s, unsigned long long last_seq)
{
  s->imported_seq = last_seq;
}

void ui_evh_track_init(ui_evh_track *t)
{
  memset(t, 0, sizeof(*t));
}

void ui_evh_track_step(ui_evh_track *t, const char *mount_id, const char *state, char prev[24])
{
  size_t i;
  prev[0] = 0;
  if (mount_id == NULL || mount_id[0] == 0)
    return;
  for (i = 0; i < UI_EVH_TRACK; i++) {
    if (t->id[i][0] != 0 && strcmp(t->id[i], mount_id) == 0) {
      put(prev, 24, t->state[i]);
      put(t->state[i], sizeof(t->state[i]), state);
      return;
    }
  }
  put(t->id[t->next], sizeof(t->id[t->next]), mount_id);
  put(t->state[t->next], sizeof(t->state[t->next]), state);
  t->next = (t->next + 1) % UI_EVH_TRACK;
}
