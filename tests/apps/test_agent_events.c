/* The agent's event rules (apps/shelldrive-host/agent_events.c, 03 §2.4 mount.state reason, §5.1 hostkey_source_insecure):
 * pure functions, so no mount, IPC or fake backend is needed. */
#include <windows.h>
#include <string.h>

#include "sd_test.h"
#include "agent_events.h"

/* One offline period: the error that dropped the mount is the reason of every later connecting, authenticating and
   mounted event, until the mount is mounted again (the mounted event itself carries it). */
SD_TEST(agent_events_reason_of_reconnect)
{
  char drop[32] = "";
  char reason[32];
  SD_CHECK(agent_reason_on_state(drop, sizeof(drop), "mounted", NULL, reason, sizeof(reason)) == 0);
  SD_CHECK(agent_reason_on_state(drop, sizeof(drop), "offline", "network_error", reason, sizeof(reason)) == 0);
  SD_CHECK_STR(drop, "network_error");
  SD_CHECK(agent_reason_on_state(drop, sizeof(drop), "connecting", NULL, reason, sizeof(reason)) == 1);
  SD_CHECK_STR(reason, "network_error");
  SD_CHECK(agent_reason_on_state(drop, sizeof(drop), "authenticating", NULL, reason, sizeof(reason)) == 1);
  SD_CHECK_STR(reason, "network_error");
  SD_CHECK(agent_reason_on_state(drop, sizeof(drop), "mounted", NULL, reason, sizeof(reason)) == 1);
  SD_CHECK_STR(reason, "network_error");
  SD_CHECK_STR(drop, "");
  SD_CHECK(agent_reason_on_state(drop, sizeof(drop), "mounted", NULL, reason, sizeof(reason)) == 0);
}

/* A later offline period replaces the code; a failed or unmounted mount forgets it (no reason for a new mount). */
SD_TEST(agent_events_reason_replaced_and_ended)
{
  char drop[32] = "";
  char reason[32];
  SD_CHECK(agent_reason_on_state(drop, sizeof(drop), "offline", "timeout", reason, sizeof(reason)) == 0);
  SD_CHECK(agent_reason_on_state(drop, sizeof(drop), "connecting", NULL, reason, sizeof(reason)) == 1);
  SD_CHECK_STR(reason, "timeout");
  SD_CHECK(agent_reason_on_state(drop, sizeof(drop), "offline", "host_unreachable", reason, sizeof(reason)) == 0);
  SD_CHECK(agent_reason_on_state(drop, sizeof(drop), "connecting", NULL, reason, sizeof(reason)) == 1);
  SD_CHECK_STR(reason, "host_unreachable");
  SD_CHECK(agent_reason_on_state(drop, sizeof(drop), "unmounting", NULL, reason, sizeof(reason)) == 0);
  SD_CHECK_STR(drop, "");
  SD_CHECK(agent_reason_on_state(drop, sizeof(drop), "connecting", NULL, reason, sizeof(reason)) == 0);

  SD_CHECK(agent_reason_on_state(drop, sizeof(drop), "offline", "timeout", reason, sizeof(reason)) == 0);
  SD_CHECK(agent_reason_on_state(drop, sizeof(drop), "failed", "timeout", reason, sizeof(reason)) == 0);
  SD_CHECK_STR(drop, "");
  /* an offline event without a code keeps nothing */
  SD_CHECK(agent_reason_on_state(drop, sizeof(drop), "offline", NULL, reason, sizeof(reason)) == 0);
  SD_CHECK(agent_reason_on_state(drop, sizeof(drop), "connecting", NULL, reason, sizeof(reason)) == 0);
}

/* The reason is cut to the caller's buffer; a state that is not part of the reconnect has none. */
SD_TEST(agent_events_reason_truncates)
{
  char drop[32] = "";
  char reason[6];
  SD_CHECK(agent_reason_on_state(drop, sizeof(drop), "offline", "very_long_error_code", reason, sizeof(reason)) == 0);
  SD_CHECK(agent_reason_on_state(drop, sizeof(drop), "connecting", NULL, reason, sizeof(reason)) == 1);
  SD_CHECK_STR(reason, "very_");
  SD_CHECK(agent_reason_on_state(drop, sizeof(drop), "auth_required", NULL, reason, sizeof(reason)) == 0);
  SD_CHECK_STR(drop, "very_long_error_code");
}

/* hostkey_source_insecure: the first lookup of a source per run sets its bit and warns; the others do not. */
SD_TEST(agent_events_source_warned_once)
{
  uint32_t done = 0;
  SD_CHECK(agent_source_warn_take(&done, 1u << 0) == 1);
  SD_CHECK(agent_source_warn_take(&done, 1u << 0) == 0);
  SD_CHECK(agent_source_warn_take(&done, 1u << 1) == 1);
  SD_CHECK(agent_source_warn_take(&done, 1u << 1) == 0);
  SD_CHECK(done == 3u);
  SD_CHECK(agent_source_warn_take(&done, 0) == 0);
  SD_CHECK(agent_source_warn_take(NULL, 1u) == 0);
}
