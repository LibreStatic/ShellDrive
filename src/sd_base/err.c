#include "sd_base/sd_err.h"

#include <string.h>

#define SD_ERR_NAME_(sym, name) name,
static const char *const g_err_names[] = { SD_ERR_LIST(SD_ERR_NAME_) };
#undef SD_ERR_NAME_

SD_STATIC_ASSERT(SD_COUNTOF(g_err_names) == SD_ERR_COUNT, "error name table out of sync");

const char *sd_err_name(sd_err e)
{
  if ((unsigned)e >= (unsigned)SD_ERR_COUNT)
    return "unknown";
  return g_err_names[e];
}

sd_err sd_err_from_name(const char *name)
{
  size_t i;
  if (name == NULL)
    return SD_ERR_COUNT;
  for (i = 0; i < SD_COUNTOF(g_err_names); i++) {
    if (strcmp(g_err_names[i], name) == 0)
      return (sd_err)i;
  }
  return SD_ERR_COUNT;
}
