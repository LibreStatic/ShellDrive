/* shelldrive-ui: the updater consent model (see ui_update_model.h). Pure: no window, IPC or registry call. */
#include <windows.h>
#include <string.h>

#include "ui_update_model.h"

/* Copies s into dst (NUL-terminated, cut when too long). A NULL source gives "". */
static void copy_text(char *dst, size_t cch, const char *s)
{
  if (cch == 0)
    return;
  if (s == NULL)
    s = "";
  strncpy_s(dst, cch, s, _TRUNCATE);
}

static void copy_offer(ui_upd_offer *dst, const ui_upd_offer *src)
{
  copy_text(dst->version, sizeof(dst->version), src->version);
  copy_text(dst->channel, sizeof(dst->channel), src->channel);
  copy_text(dst->notes, sizeof(dst->notes), src->notes);
  copy_text(dst->file_id, sizeof(dst->file_id), src->file_id);
  dst->size = src->size;
}

void ui_upd_model_init(ui_upd_model *m)
{
  memset(m, 0, sizeof(*m));
  m->state = UI_UPD_IDLE;
  m->stage = UI_UPD_STAGE_NONE;
}

int ui_upd_begin_check(ui_upd_model *m)
{
  if (m->state != UI_UPD_IDLE && m->state != UI_UPD_AVAILABLE && m->state != UI_UPD_FAILED)
    return 0;
  m->state = UI_UPD_CHECKING;
  m->error[0] = '\0';
  return 1;
}

void ui_upd_on_check(ui_upd_model *m, const char *error, const ui_upd_check *r)
{
  if (error != NULL) {
    m->state = UI_UPD_FAILED;
    copy_text(m->error, sizeof(m->error), error);
    return;
  }
  m->checked = 1;
  m->error[0] = '\0';
  m->enabled = r->enabled ? 1 : 0;
  copy_text(m->reason, sizeof(m->reason), r->enabled ? "" : r->reason);
  if (r->channel[0] != '\0')
    copy_text(m->channel, sizeof(m->channel), r->channel);
  if (!r->enabled) {
    /* turned off: no check ran, so there is nothing offered and the old stale flag stays as it is */
    m->has_offer = 0;
    m->state = UI_UPD_IDLE;
    return;
  }
  m->stale = r->stale ? 1 : 0;
  if (!r->stale)
    m->stale_days = 0;
  if (r->available) {
    copy_offer(&m->offer, &r->offer);
    m->has_offer = 1;
    m->state = UI_UPD_AVAILABLE;
  } else {
    m->has_offer = 0;
    m->state = UI_UPD_IDLE;
  }
}

int ui_upd_begin_install(ui_upd_model *m)
{
  if (m->state != UI_UPD_AVAILABLE || !m->has_offer)
    return 0;
  m->state = UI_UPD_INSTALLING;
  m->stage = UI_UPD_STAGE_NONE;
  m->error[0] = '\0';
  return 1;
}

void ui_upd_on_apply(ui_upd_model *m, const char *error, int applied)
{
  if (error != NULL) {
    m->state = UI_UPD_FAILED;
    m->stage = UI_UPD_STAGE_FAILED;
    copy_text(m->error, sizeof(m->error), error);
    return;
  }
  m->checked = 1;
  m->error[0] = '\0';
  m->has_offer = 0;
  m->state = UI_UPD_IDLE;
  m->stage = applied ? UI_UPD_STAGE_DONE : UI_UPD_STAGE_NONE;
}

void ui_upd_on_progress(ui_upd_model *m, const char *stage)
{
  if (stage == NULL)
    return;
  if (strcmp(stage, "downloading") == 0)
    m->stage = UI_UPD_STAGE_DOWNLOADING;
  else if (strcmp(stage, "applying") == 0)
    m->stage = UI_UPD_STAGE_APPLYING;
  else if (strcmp(stage, "done") == 0)
    m->stage = UI_UPD_STAGE_DONE;
  else if (strcmp(stage, "failed") == 0)
    m->stage = UI_UPD_STAGE_FAILED;
  /* any other stage is ignored: the agent may add stages, and the window keeps the last known one */
}

int ui_upd_on_available(ui_upd_model *m, const ui_upd_offer *o)
{
  int fresh;

  if (m->state == UI_UPD_INSTALLING)
    return 0;
  copy_offer(&m->offer, o);
  m->has_offer = 1;
  if (m->state == UI_UPD_IDLE || m->state == UI_UPD_FAILED)
    m->state = UI_UPD_AVAILABLE;
  fresh = strcmp(m->announced, o->version) != 0;
  if (fresh)
    copy_text(m->announced, sizeof(m->announced), o->version);
  return fresh;
}

void ui_upd_on_stale(ui_upd_model *m, long long days)
{
  m->stale = 1;
  m->stale_days = days;
}

void ui_upd_on_agent_state(ui_upd_model *m, int up)
{
  if (up)
    return;
  if (m->state == UI_UPD_CHECKING || m->state == UI_UPD_INSTALLING) {
    m->state = UI_UPD_FAILED;
    copy_text(m->error, sizeof(m->error), "agent_disconnected");
  }
}

const char *ui_upd_effective_channel(const ui_upd_policy *p, const char *saved)
{
  if (p != NULL && p->channel_set && p->channel[0] != '\0')
    return p->channel;
  if (saved != NULL && saved[0] != '\0')
    return saved;
  return "stable";
}

ui_upd_status_kind ui_upd_status_of(const ui_upd_model *m, const ui_upd_policy *p)
{
  if (p != NULL && p->check_off)
    return UI_UPD_SHOW_OFF_POLICY;
  switch (m->state) {
  case UI_UPD_CHECKING:
    return UI_UPD_SHOW_CHECKING;
  case UI_UPD_INSTALLING:
    return UI_UPD_SHOW_INSTALLING;
  case UI_UPD_FAILED:
    return UI_UPD_SHOW_FAILED;
  case UI_UPD_AVAILABLE:
    return UI_UPD_SHOW_AVAILABLE;
  case UI_UPD_IDLE:
  default:
    break;
  }
  if (m->checked && !m->enabled)
    return strcmp(m->reason, "policy") == 0 ? UI_UPD_SHOW_OFF_POLICY : UI_UPD_SHOW_OFF_SETTINGS;
  if (m->checked)
    return UI_UPD_SHOW_CURRENT;
  return UI_UPD_SHOW_IDLE;
}

void ui_upd_view_of(const ui_upd_model *m, const ui_upd_policy *p, int agent_ok, int can_apply, ui_upd_view *v)
{
  int busy = m->state == UI_UPD_CHECKING || m->state == UI_UPD_INSTALLING;
  int policy_off = p != NULL && p->check_off;
  int channel_managed = p != NULL && p->channel_set;

  memset(v, 0, sizeof(*v));
  v->channel_managed = channel_managed;
  v->channel_enabled = agent_ok && !channel_managed && !busy;
  v->check_managed = policy_off;
  v->check_enabled = agent_ok && !policy_off && !busy && !(m->checked && !m->enabled);
  v->install_enabled = agent_ok && can_apply && m->state == UI_UPD_AVAILABLE && m->has_offer;
  v->notes_enabled = m->has_offer && m->offer.notes[0] != '\0';
}
