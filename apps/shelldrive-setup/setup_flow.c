/* shelldrive-setup: the page flow of the wizard (setup_flow.h). Pure: see the header for the rules. */
#include "setup_flow.h"

sd_flow_page sd_flow_first(const sd_flow_input *in)
{
  if (in->quiet)
    return SD_FLOW_NONE;
  if (in->uninstall)
    return in->passive ? SD_FLOW_PROGRESS : SD_FLOW_UNINSTALL;
  if (in->passive)
    return SD_FLOW_PROGRESS;
  return SD_FLOW_WELCOME;
}

/* The page that follows the mode decision: the destination for a portable copy without a folder, the Dokany
   page for the all-users choice, otherwise the progress page. */
static sd_flow_page after_mode(const sd_flow_input *in, sd_setup_mode mode)
{
  if (mode == SD_SETUP_MODE_PORTABLE && !in->dest_given)
    return SD_FLOW_DESTINATION;
  if (mode == SD_SETUP_MODE_MACHINE)
    return SD_FLOW_DOKANY;
  return SD_FLOW_PROGRESS;
}

sd_flow_page sd_flow_next(const sd_flow_input *in, const sd_flow_choice *c, sd_flow_page cur)
{
  sd_setup_mode mode = c != NULL ? c->mode : SD_SETUP_MODE_USER;

  switch (cur) {
  case SD_FLOW_UNINSTALL:
    return SD_FLOW_PROGRESS;
  case SD_FLOW_WELCOME:
    return SD_FLOW_LICENSE;
  case SD_FLOW_LICENSE:
    return in->mode_given ? after_mode(in, mode) : SD_FLOW_MODE;
  case SD_FLOW_MODE:
    return after_mode(in, mode);
  case SD_FLOW_DESTINATION:
    return mode == SD_SETUP_MODE_MACHINE ? SD_FLOW_DOKANY : SD_FLOW_PROGRESS;
  case SD_FLOW_DOKANY:
    return SD_FLOW_PROGRESS;
  case SD_FLOW_PROGRESS:
    /* The finish page follows an interactive install. A removal ends on its message box, a passive run has
       no page after the progress. */
    if (in->uninstall || in->passive || in->quiet)
      return SD_FLOW_NONE;
    return SD_FLOW_FINISH;
  case SD_FLOW_FINISH:
  case SD_FLOW_NONE:
  default:
    return SD_FLOW_NONE;
  }
}

void sd_flow_dokany_view_of(sd_setup_dokany_plan plan, sd_flow_dokany_view *v)
{
  v->enabled = 0;
  v->checked = 0;
  v->has_note = 0;
  v->note = 0;
  switch (plan) {
  case SD_SETUP_DOKANY_INSTALL_PLAN:
    /* Pre-checked (D36); the user may uncheck it. */
    v->enabled = 1;
    v->checked = 1;
    break;
  case SD_SETUP_DOKANY_UNAVAILABLE_PLAN:
    /* Shown disabled and unchecked, with the reason (04 §7.3). */
    v->has_note = 1;
    v->note = SD_MSG_INSTALLER_DOKANY_UNAVAILABLE;
    break;
  case SD_SETUP_DOKANY_SKIP_PLAN:
  default:
    /* Only /dokany=skip gets here for a machine install: the user may still check it. */
    v->enabled = 1;
    v->has_note = 1;
    v->note = SD_MSG_INSTALLER_DOKANY_SKIP_NOTE;
    break;
  }
}

int sd_flow_page_title(sd_flow_page p, sd_msg_id *id)
{
  sd_msg_id m;
  switch (p) {
  case SD_FLOW_WELCOME:     m = SD_MSG_INSTALLER_WELCOME_TITLE; break;
  case SD_FLOW_LICENSE:     m = SD_MSG_INSTALLER_LICENSE_TITLE; break;
  case SD_FLOW_MODE:        m = SD_MSG_INSTALLER_MODE_TITLE; break;
  case SD_FLOW_DESTINATION: m = SD_MSG_INSTALLER_DEST_TITLE; break;
  case SD_FLOW_DOKANY:      m = SD_MSG_INSTALLER_DOKANY_TITLE; break;
  case SD_FLOW_PROGRESS:    m = SD_MSG_INSTALLER_WINDOW_TITLE; break;
  case SD_FLOW_FINISH:      m = SD_MSG_INSTALLER_FINISH_TITLE; break;
  case SD_FLOW_UNINSTALL:   m = SD_MSG_INSTALLER_UNINSTALL_TITLE; break;
  case SD_FLOW_NONE:
  default:
    return 0;
  }
  *id = m;
  return 1;
}

const char *sd_flow_page_name(sd_flow_page p)
{
  switch (p) {
  case SD_FLOW_WELCOME:     return "welcome";
  case SD_FLOW_LICENSE:     return "license";
  case SD_FLOW_MODE:        return "mode";
  case SD_FLOW_DESTINATION: return "destination";
  case SD_FLOW_DOKANY:      return "dokany";
  case SD_FLOW_PROGRESS:    return "progress";
  case SD_FLOW_FINISH:      return "finish";
  case SD_FLOW_UNINSTALL:   return "uninstall";
  case SD_FLOW_NONE:
  default:
    return "none";
  }
}
