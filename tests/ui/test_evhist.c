/* The agent's event history in the UI's event list (apps/shelldrive-ui/ui_evhist_model.c, 03 2.4 events.recent, 7.7):
   how a record is read, which records are taken when the UI also saw them live, and a second import from the same agent. */
#include <windows.h>
#include <string.h>

#include "sd_test.h"
#include "sd_base/sd_json.h"
#include "ui_evhist_model.h"

static sd_json *parse(const char *text)
{
  sd_json *j = NULL;
  if (sd_json_parse(text, strlen(text), 16, &j) != SD_OK)
    return NULL;
  return j;
}

SD_TEST(evhist_parse_reads_the_three_events)
{
  ui_evh_rec r;
  sd_json *j = parse("{\"seq\":7,\"time\":1790000000,\"event\":\"mount.state\",\"mount_id\":\"m-1\",\"state\":\"failed\","
                     "\"code\":\"auth_failed\"}");
  SD_REQUIRE(j != NULL);
  SD_CHECK_EQ_INT(ui_evh_parse(j, &r), 1);
  SD_CHECK_EQ_INT((int)r.seq, 7);
  SD_CHECK(r.time == 1790000000ll);
  SD_CHECK_STR(r.event, "mount.state");
  SD_CHECK_STR(r.mount_id, "m-1");
  SD_CHECK_STR(r.state, "failed");
  SD_CHECK_STR(r.code, "auth_failed");
  sd_json_free(j);

  j = parse("{\"seq\":8,\"time\":1,\"event\":\"warning\",\"mount_id\":\"m-1\",\"code\":\"hostkey_source_insecure\"}");
  SD_REQUIRE(j != NULL);
  SD_CHECK_EQ_INT(ui_evh_parse(j, &r), 1);
  SD_CHECK_STR(r.code, "hostkey_source_insecure");
  SD_CHECK_STR(r.state, "");
  sd_json_free(j);

  j = parse("{\"seq\":9,\"time\":1,\"event\":\"hostkeys.announced\",\"mount_id\":\"m-2\"}");
  SD_REQUIRE(j != NULL);
  SD_CHECK_EQ_INT(ui_evh_parse(j, &r), 1);
  sd_json_free(j);
}

SD_TEST(evhist_parse_refuses_what_it_cannot_show)
{
  ui_evh_rec r;
  sd_json *j = parse("{\"seq\":1,\"time\":1,\"event\":\"update.available\"}");       /* not an event this list shows */
  SD_REQUIRE(j != NULL);
  SD_CHECK_EQ_INT(ui_evh_parse(j, &r), 0);
  sd_json_free(j);
  j = parse("{\"time\":1,\"event\":\"warning\"}");                                       /* no sequence number */
  SD_REQUIRE(j != NULL);
  SD_CHECK_EQ_INT(ui_evh_parse(j, &r), 0);
  sd_json_free(j);
  j = parse("{\"seq\":0,\"time\":1,\"event\":\"warning\"}");
  SD_REQUIRE(j != NULL);
  SD_CHECK_EQ_INT(ui_evh_parse(j, &r), 0);
  sd_json_free(j);
  j = parse("[1,2]");
  SD_REQUIRE(j != NULL);
  SD_CHECK_EQ_INT(ui_evh_parse(j, &r), 0);
  sd_json_free(j);
  SD_CHECK_EQ_INT(ui_evh_parse(NULL, &r), 0);
  /* over-long text is cut, not overrun */
  j = parse("{\"seq\":2,\"time\":1,\"event\":\"warning\",\"mount_id\":\"0123456789012345678901234567890123456789\"}");
  SD_REQUIRE(j != NULL);
  SD_CHECK_EQ_INT(ui_evh_parse(j, &r), 1);
  SD_CHECK_EQ_INT((int)strlen(r.mount_id), (int)sizeof(r.mount_id) - 1);
  sd_json_free(j);
}

static ui_evh_rec rec(unsigned long long seq, long long t, const char *ev, const char *mount, const char *state,
                      const char *code)
{
  ui_evh_rec r;
  memset(&r, 0, sizeof(r));
  r.seq = seq;
  r.time = t;
  strcpy_s(r.event, sizeof(r.event), ev);
  strcpy_s(r.mount_id, sizeof(r.mount_id), mount);
  strcpy_s(r.state, sizeof(r.state), state);
  strcpy_s(r.code, sizeof(r.code), code);
  return r;
}

SD_TEST(evhist_first_import_takes_everything_it_has_not_seen_live)
{
  ui_evh_state s;
  ui_evh_rec a = rec(1, 1000, "mount.state", "m-1", "connecting", "");
  ui_evh_rec b = rec(2, 1001, "mount.state", "m-1", "mounted", "");
  ui_evh_rec w = rec(3, 1002, "warning", "m-1", "", "terrapin_exposed");
  ui_evh_init(&s);
  /* the UI saw the mounted event live (it subscribed before it asked for the history) */
  ui_evh_note_live(&s, "mount.state", "m-1", "mounted", 1001);
  ui_evh_begin(&s, 3);
  SD_CHECK_EQ_INT(ui_evh_wanted(&s, &a), 1);
  SD_CHECK_EQ_INT(ui_evh_wanted(&s, &b), 0);       /* said once, by the live event */
  SD_CHECK_EQ_INT(ui_evh_wanted(&s, &w), 1);       /* nothing live for this warning */
  ui_evh_end(&s, 3);
}

SD_TEST(evhist_live_match_is_by_kind_mount_state_and_time)
{
  ui_evh_state s;
  ui_evh_init(&s);
  ui_evh_note_live(&s, "mount.state", "m-1", "offline", 5000);
  ui_evh_begin(&s, 10);
  {
    ui_evh_rec other_mount = rec(1, 5000, "mount.state", "m-2", "offline", "");
    ui_evh_rec other_state = rec(2, 5000, "mount.state", "m-1", "mounted", "");
    ui_evh_rec other_event = rec(3, 5000, "warning", "m-1", "", "offline");
    ui_evh_rec too_old = rec(4, 5000 - UI_EVH_MATCH_SECONDS - 1, "mount.state", "m-1", "offline", "");
    ui_evh_rec same = rec(5, 5000 - UI_EVH_MATCH_SECONDS, "mount.state", "m-1", "offline", "");
    ui_evh_rec again = rec(6, 5000, "mount.state", "m-1", "offline", "");
    SD_CHECK_EQ_INT(ui_evh_wanted(&s, &other_mount), 1);
    SD_CHECK_EQ_INT(ui_evh_wanted(&s, &other_state), 1);
    SD_CHECK_EQ_INT(ui_evh_wanted(&s, &other_event), 1);
    SD_CHECK_EQ_INT(ui_evh_wanted(&s, &too_old), 1);       /* an earlier offline period of the same mount */
    SD_CHECK_EQ_INT(ui_evh_wanted(&s, &same), 0);
    SD_CHECK_EQ_INT(ui_evh_wanted(&s, &again), 1);         /* one live event covers one record */
  }
}

SD_TEST(evhist_second_import_takes_only_newer_records)
{
  ui_evh_state s;
  ui_evh_rec old1 = rec(4, 100, "mount.state", "m-1", "mounted", "");
  ui_evh_rec fresh = rec(6, 200, "mount.state", "m-1", "offline", "");
  ui_evh_rec restarted = rec(2, 300, "mount.state", "m-9", "mounted", "");
  ui_evh_init(&s);
  ui_evh_begin(&s, 5);
  SD_CHECK_EQ_INT(ui_evh_wanted(&s, &old1), 1);
  ui_evh_end(&s, 5);
  /* the same agent after a reconnect of the pipe: sequence numbers go on */
  ui_evh_begin(&s, 6);
  SD_CHECK_EQ_INT(ui_evh_wanted(&s, &old1), 0);
  SD_CHECK_EQ_INT(ui_evh_wanted(&s, &fresh), 1);
  ui_evh_end(&s, 6);
  /* a new agent process counts from 1 again: last_seq is below what was imported, so everything is new */
  ui_evh_begin(&s, 2);
  SD_CHECK_EQ_INT(ui_evh_wanted(&s, &restarted), 1);
  SD_CHECK_EQ_INT(ui_evh_wanted(&s, &old1), 1);
}

SD_TEST(evhist_live_notes_are_a_ring)
{
  ui_evh_state s;
  ui_evh_rec r = rec(1, 10, "mount.state", "m-first", "mounted", "");
  int i;
  ui_evh_init(&s);
  ui_evh_note_live(&s, "mount.state", "m-first", "mounted", 10);
  for (i = 0; i < UI_EVH_LIVE_SLOTS; i++)
    ui_evh_note_live(&s, "warning", "m-x", "pool_limited", 10);     /* the oldest note is replaced */
  ui_evh_note_live(&s, "other.event", "m-y", NULL, 10);             /* events the list does not show are not kept */
  ui_evh_begin(&s, 1);
  SD_CHECK_EQ_INT(ui_evh_wanted(&s, &r), 1);
}

SD_TEST(evhist_track_replays_the_state_of_each_mount)
{
  ui_evh_track t;
  char prev[24];
  ui_evh_track_init(&t);
  ui_evh_track_step(&t, "m-1", "connecting", prev);
  SD_CHECK_STR(prev, "");
  ui_evh_track_step(&t, "m-2", "mounted", prev);
  SD_CHECK_STR(prev, "");
  ui_evh_track_step(&t, "m-1", "mounted", prev);
  SD_CHECK_STR(prev, "connecting");
  ui_evh_track_step(&t, "m-1", "offline", prev);
  SD_CHECK_STR(prev, "mounted");
  ui_evh_track_step(&t, "m-2", "offline", prev);
  SD_CHECK_STR(prev, "mounted");
  ui_evh_track_step(&t, "", "mounted", prev);          /* a record without a mount tracks nothing */
  SD_CHECK_STR(prev, "");
  ui_evh_track_step(&t, NULL, "mounted", prev);
  SD_CHECK_STR(prev, "");
}
