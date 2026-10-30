/* The updater consent model (apps/shelldrive-ui/ui_update_model.c): the state machine of Check now and Install,
   the offers and their balloons, the stale flag, the agent going away, the policy display and the enabled
   controls. Pure: no window, IPC or registry (the glue in ui_update.c is covered by --test-windows). */
#include <windows.h>
#include <string.h>

#include "sd_test.h"
#include "ui_update_model.h"

static void offer_of(ui_upd_offer *o, const char *version, const char *notes, unsigned long long size)
{
  memset(o, 0, sizeof(*o));
  strcpy_s(o->version, sizeof(o->version), version);
  strcpy_s(o->channel, sizeof(o->channel), "stable");
  strcpy_s(o->notes, sizeof(o->notes), notes);
  strcpy_s(o->file_id, sizeof(o->file_id), "shelldrive-setup");
  o->size = size;
}

static void check_of(ui_upd_check *c, int enabled, int available, const char *version)
{
  memset(c, 0, sizeof(*c));
  c->enabled = enabled;
  c->available = available;
  strcpy_s(c->channel, sizeof(c->channel), "stable");
  if (available)
    offer_of(&c->offer, version, "https://example.org/notes", 2048 * 1024);
}

SD_TEST(updater_check_then_install_flow)
{
  ui_upd_model m;
  ui_upd_check c;
  ui_upd_offer o;

  ui_upd_model_init(&m);
  SD_CHECK(m.state == UI_UPD_IDLE);
  SD_CHECK(!ui_upd_begin_install(&m));                 /* nothing offered yet */

  SD_CHECK(ui_upd_begin_check(&m));
  SD_CHECK(m.state == UI_UPD_CHECKING);
  SD_CHECK(!ui_upd_begin_check(&m));                   /* one check at a time */

  check_of(&c, 1, 1, "1.2.0");
  ui_upd_on_check(&m, NULL, &c);
  SD_CHECK(m.state == UI_UPD_AVAILABLE && m.has_offer && m.checked);
  SD_CHECK(strcmp(m.offer.version, "1.2.0") == 0);

  SD_CHECK(ui_upd_begin_install(&m));
  SD_CHECK(m.state == UI_UPD_INSTALLING);
  SD_CHECK(!ui_upd_begin_install(&m));                 /* not twice */
  SD_CHECK(!ui_upd_begin_check(&m));                   /* not while installing */

  ui_upd_on_progress(&m, "downloading");
  SD_CHECK(m.stage == UI_UPD_STAGE_DOWNLOADING);
  ui_upd_on_progress(&m, "applying");
  SD_CHECK(m.stage == UI_UPD_STAGE_APPLYING);
  ui_upd_on_progress(&m, "something-new");             /* unknown stages keep the last known one */
  SD_CHECK(m.stage == UI_UPD_STAGE_APPLYING);

  ui_upd_on_apply(&m, NULL, 1);
  SD_CHECK(m.state == UI_UPD_IDLE && m.stage == UI_UPD_STAGE_DONE && !m.has_offer);

  (void)o;
}

SD_TEST(updater_up_to_date_and_disabled_replies)
{
  ui_upd_model m;
  ui_upd_check c;
  ui_upd_policy none;

  memset(&none, 0, sizeof(none));
  ui_upd_model_init(&m);
  ui_upd_begin_check(&m);
  check_of(&c, 1, 0, "");
  ui_upd_on_check(&m, NULL, &c);
  SD_CHECK(m.state == UI_UPD_IDLE && m.checked && !m.has_offer);
  SD_CHECK(ui_upd_status_of(&m, &none) == UI_UPD_SHOW_CURRENT);

  /* the agent did not check: policy or settings turned it off */
  ui_upd_model_init(&m);
  ui_upd_begin_check(&m);
  memset(&c, 0, sizeof(c));
  c.enabled = 0;
  strcpy_s(c.reason, sizeof(c.reason), "policy");
  ui_upd_on_check(&m, NULL, &c);
  SD_CHECK(!m.enabled && m.state == UI_UPD_IDLE);
  SD_CHECK(ui_upd_status_of(&m, &none) == UI_UPD_SHOW_OFF_POLICY);

  ui_upd_model_init(&m);
  ui_upd_begin_check(&m);
  memset(&c, 0, sizeof(c));
  strcpy_s(c.reason, sizeof(c.reason), "settings");
  ui_upd_on_check(&m, NULL, &c);
  SD_CHECK(ui_upd_status_of(&m, &none) == UI_UPD_SHOW_OFF_SETTINGS);
}

SD_TEST(updater_check_failure_and_retry)
{
  ui_upd_model m;
  ui_upd_check c;
  ui_upd_policy none;

  memset(&none, 0, sizeof(none));
  ui_upd_model_init(&m);
  SD_CHECK(ui_upd_begin_check(&m));
  ui_upd_on_check(&m, "update_unavailable", NULL);
  SD_CHECK(m.state == UI_UPD_FAILED);
  SD_CHECK(strcmp(m.error, "update_unavailable") == 0);
  SD_CHECK(ui_upd_status_of(&m, &none) == UI_UPD_SHOW_FAILED);
  SD_CHECK(ui_upd_begin_check(&m));                    /* a failed check may be retried */
  SD_CHECK(m.error[0] == '\0');

  /* a reply that is not usable is a failure too (the glue passes the name) */
  ui_upd_on_check(&m, "update_bad_reply", NULL);
  SD_CHECK(m.state == UI_UPD_FAILED);

  check_of(&c, 1, 0, "");
  ui_upd_begin_check(&m);
  ui_upd_on_check(&m, NULL, &c);
  SD_CHECK(m.state == UI_UPD_IDLE && m.error[0] == '\0');
}

SD_TEST(updater_install_failure_keeps_the_offer)
{
  ui_upd_model m;
  ui_upd_check c;
  ui_upd_policy none;

  memset(&none, 0, sizeof(none));
  ui_upd_model_init(&m);
  ui_upd_begin_check(&m);
  check_of(&c, 1, 1, "2.0.0");
  ui_upd_on_check(&m, NULL, &c);
  SD_CHECK(ui_upd_begin_install(&m));
  ui_upd_on_progress(&m, "failed");
  ui_upd_on_apply(&m, "update_verify_failed", 0);
  SD_CHECK(m.state == UI_UPD_FAILED && m.stage == UI_UPD_STAGE_FAILED);
  SD_CHECK(m.has_offer && strcmp(m.offer.version, "2.0.0") == 0);
  SD_CHECK(ui_upd_status_of(&m, &none) == UI_UPD_SHOW_FAILED);
  SD_CHECK(!ui_upd_begin_install(&m));                 /* a new check comes first */

  /* up_to_date from the agent: nothing to install, the window says current */
  ui_upd_model_init(&m);
  ui_upd_begin_check(&m);
  check_of(&c, 1, 1, "2.0.0");
  ui_upd_on_check(&m, NULL, &c);
  ui_upd_begin_install(&m);
  ui_upd_on_apply(&m, NULL, 0);
  SD_CHECK(m.state == UI_UPD_IDLE && !m.has_offer);
}

SD_TEST(updater_offer_balloon_once_per_version)
{
  ui_upd_model m;
  ui_upd_offer a, b, c;

  ui_upd_model_init(&m);
  offer_of(&a, "3.1.0", "", 1000);
  offer_of(&b, "3.1.0", "", 1000);
  offer_of(&c, "3.2.0", "", 1000);
  SD_CHECK(ui_upd_on_available(&m, &a) == 1);         /* first announcement: balloon */
  SD_CHECK(m.state == UI_UPD_AVAILABLE);
  SD_CHECK(ui_upd_on_available(&m, &b) == 0);         /* same version: no second balloon */
  SD_CHECK(ui_upd_on_available(&m, &c) == 1);         /* newer version: balloon */
  SD_CHECK(strcmp(m.offer.version, "3.2.0") == 0);

  /* an offer while an install runs is not taken over */
  SD_CHECK(ui_upd_begin_install(&m));
  SD_CHECK(ui_upd_on_available(&m, &a) == 0);
  SD_CHECK(strcmp(m.offer.version, "3.2.0") == 0 && m.state == UI_UPD_INSTALLING);
}

SD_TEST(updater_stale_flag)
{
  ui_upd_model m;
  ui_upd_check c;
  ui_upd_policy none;

  memset(&none, 0, sizeof(none));
  ui_upd_model_init(&m);
  ui_upd_on_stale(&m, 16);
  SD_CHECK(m.stale && m.stale_days == 16);
  ui_upd_begin_check(&m);
  check_of(&c, 1, 0, "");
  c.stale = 1;
  ui_upd_on_check(&m, NULL, &c);
  SD_CHECK(m.stale);                                   /* still old: the reply says so */
  ui_upd_begin_check(&m);
  check_of(&c, 1, 0, "");
  ui_upd_on_check(&m, NULL, &c);
  SD_CHECK(!m.stale && m.stale_days == 0);             /* a good check clears it */
  SD_CHECK(ui_upd_status_of(&m, &none) == UI_UPD_SHOW_CURRENT);
}

SD_TEST(updater_agent_going_away)
{
  ui_upd_model m;
  ui_upd_check c;

  ui_upd_model_init(&m);
  ui_upd_begin_check(&m);
  ui_upd_on_agent_state(&m, 0);
  SD_CHECK(m.state == UI_UPD_FAILED && strcmp(m.error, "agent_disconnected") == 0);

  ui_upd_model_init(&m);
  ui_upd_begin_check(&m);
  check_of(&c, 1, 1, "4.0.0");
  ui_upd_on_check(&m, NULL, &c);
  ui_upd_begin_install(&m);
  ui_upd_on_agent_state(&m, 0);
  SD_CHECK(m.state == UI_UPD_FAILED);

  /* an idle window does not change when the agent comes back or goes away */
  ui_upd_model_init(&m);
  ui_upd_on_agent_state(&m, 0);
  ui_upd_on_agent_state(&m, 1);
  SD_CHECK(m.state == UI_UPD_IDLE && m.error[0] == '\0');
}

SD_TEST(updater_policy_display)
{
  ui_upd_model m;
  ui_upd_policy p;
  ui_upd_view v;

  ui_upd_model_init(&m);

  /* DisableUpdateCheck: checks are off and say so; the channel stays editable */
  memset(&p, 0, sizeof(p));
  p.check_off = 1;
  SD_CHECK(ui_upd_status_of(&m, &p) == UI_UPD_SHOW_OFF_POLICY);
  ui_upd_view_of(&m, &p, 1, 1, &v);
  SD_CHECK(v.check_managed && !v.check_enabled);
  SD_CHECK(!v.channel_managed && v.channel_enabled);

  /* UpdateChannel: the list is fixed and marked as managed */
  memset(&p, 0, sizeof(p));
  p.channel_set = 1;
  strcpy_s(p.channel, sizeof(p.channel), "beta");
  ui_upd_view_of(&m, &p, 1, 1, &v);
  SD_CHECK(v.channel_managed && !v.channel_enabled);
  SD_CHECK(!v.check_managed && v.check_enabled);
  SD_CHECK(strcmp(ui_upd_effective_channel(&p, "stable"), "beta") == 0);

  /* no policy: the saved channel, or stable when none is saved */
  memset(&p, 0, sizeof(p));
  SD_CHECK(strcmp(ui_upd_effective_channel(&p, "beta"), "beta") == 0);
  SD_CHECK(strcmp(ui_upd_effective_channel(&p, ""), "stable") == 0);
  SD_CHECK(strcmp(ui_upd_effective_channel(NULL, NULL), "stable") == 0);
}

SD_TEST(updater_view_enabled_rules)
{
  ui_upd_model m;
  ui_upd_check c;
  ui_upd_policy none;
  ui_upd_view v;

  memset(&none, 0, sizeof(none));
  ui_upd_model_init(&m);

  /* no agent: nothing is enabled */
  ui_upd_view_of(&m, &none, 0, 0, &v);
  SD_CHECK(!v.check_enabled && !v.channel_enabled && !v.install_enabled && !v.notes_enabled);

  /* agent without update.apply: check yes, install no */
  ui_upd_view_of(&m, &none, 1, 0, &v);
  SD_CHECK(v.check_enabled && v.channel_enabled && !v.install_enabled);

  /* an offer with notes: install and notes are enabled, while nothing runs */
  ui_upd_begin_check(&m);
  ui_upd_view_of(&m, &none, 1, 1, &v);
  SD_CHECK(!v.check_enabled);                          /* busy */
  check_of(&c, 1, 1, "5.0.0");
  ui_upd_on_check(&m, NULL, &c);
  ui_upd_view_of(&m, &none, 1, 1, &v);
  SD_CHECK(v.check_enabled && v.install_enabled && v.notes_enabled);
  ui_upd_begin_install(&m);
  ui_upd_view_of(&m, &none, 1, 1, &v);
  SD_CHECK(!v.check_enabled && !v.install_enabled && !v.channel_enabled);

  /* an offer without a notes link: the button stays off */
  ui_upd_model_init(&m);
  ui_upd_begin_check(&m);
  memset(&c, 0, sizeof(c));
  c.enabled = 1;
  c.available = 1;
  offer_of(&c.offer, "5.0.1", "", 10);
  ui_upd_on_check(&m, NULL, &c);
  ui_upd_view_of(&m, &none, 1, 1, &v);
  SD_CHECK(v.install_enabled && !v.notes_enabled);
}

SD_TEST(updater_progress_and_status_text_kinds)
{
  ui_upd_model m;
  ui_upd_policy none;
  ui_upd_check c;

  memset(&none, 0, sizeof(none));
  ui_upd_model_init(&m);
  SD_CHECK(ui_upd_status_of(&m, &none) == UI_UPD_SHOW_IDLE);
  ui_upd_begin_check(&m);
  SD_CHECK(ui_upd_status_of(&m, &none) == UI_UPD_SHOW_CHECKING);
  check_of(&c, 1, 1, "6.0.0");
  ui_upd_on_check(&m, NULL, &c);
  SD_CHECK(ui_upd_status_of(&m, &none) == UI_UPD_SHOW_AVAILABLE);
  ui_upd_begin_install(&m);
  SD_CHECK(ui_upd_status_of(&m, &none) == UI_UPD_SHOW_INSTALLING);
  /* a policy that turns checks off wins over the state for the status line */
  none.check_off = 1;
  SD_CHECK(ui_upd_status_of(&m, &none) == UI_UPD_SHOW_OFF_POLICY);
}
