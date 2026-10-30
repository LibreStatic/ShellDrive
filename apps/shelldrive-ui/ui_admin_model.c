/* shelldrive-ui: the administrator side of the service prompts. See ui_admin_model.h. Pure. */
#include <windows.h>

#include "sd_base/sd_err.h"
#include "sd_base/sd_json.h"
#include "ui_admin_model.h"

sd_err ui_admin_parse_attention(const sd_json *data, int *count)
{
  int64_t v = 0;
  if (count != NULL)
    *count = 0;
  if (data == NULL || count == NULL || sd_json_type_of(data) != SD_JSON_OBJECT)
    return SD_E_INVALID_PARAM;
  if (!sd_json_get_int64(data, "count", &v))
    return SD_E_INVALID_PARAM;
  if (v < 0 || v > UI_ADMIN_COUNT_MAX)
    return SD_E_INVALID_PARAM;
  *count = (int)v;
  return SD_OK;
}

int ui_admin_attention_shown(int count, int user_is_admin)
{
  return user_is_admin && count > 0 ? 1 : 0;
}

int ui_admin_may_answer_service(int process_elevated, int user_is_admin)
{
  return process_elevated && user_is_admin ? 1 : 0;
}

ui_answer_route ui_admin_answer_route(int elevated_admin_mode)
{
  return elevated_admin_mode ? UI_ROUTE_SERVICE : UI_ROUTE_AGENT;
}

const wchar_t *ui_admin_launch_verb(int vista_or_later)
{
  return vista_or_later ? L"runas" : L"open";
}
