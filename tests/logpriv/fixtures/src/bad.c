/* Fixture for logpriv.source_check_detects_fixture: every call below must be reported. */
#include "sd_platform/sd_log.h"

void logpriv_fixture(sd_ssh_conn *c, const char *host, const char *user)
{
  SD_LOGI("ssh", "connecting to %s", host);
  SD_LOGW("ssh", "user %s", c->user);
  SD_LOGE("ssh", "count %s %u", host);
  SD_LOGI("ssh", "fine %Hs %Us", host, user);
}
