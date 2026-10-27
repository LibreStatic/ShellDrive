/* Pure tests of the setup wizard's page flow (apps/shelldrive-setup/setup_flow.c): which pages show for which
   command line, mode and Dokany availability. No window is created: the flow is a pure function. */
#include <windows.h>
#include <string.h>

#include "setup_core.h"
#include "setup_flow.h"
#include "sd_test.h"

#define FLOW_COUNTOF(a) (sizeof(a) / sizeof((a)[0]))

/* Runs the flow from the first page, answering with the given mode, and returns the pages in order (NONE ends it). */
static size_t run_flow(const sd_flow_input *in, sd_setup_mode answer, sd_flow_page *pages, size_t cap)
{
  sd_flow_choice c;
  sd_flow_page cur;
  size_t n = 0;

  c.mode = answer;
  cur = sd_flow_first(in);
  while (cur != SD_FLOW_NONE && n < cap) {
    pages[n++] = cur;
    cur = sd_flow_next(in, &c, cur);
  }
  return n;
}

static int same_pages(const sd_flow_page *a, size_t na, const sd_flow_page *b, size_t nb)
{
  size_t i;
  if (na != nb)
    return 0;
  for (i = 0; i < na; i++) {
    if (a[i] != b[i])
      return 0;
  }
  return 1;
}

#define SD_FLOW_CASE(name, input, mode, ...)                                              \
  do {                                                                                    \
    static const sd_flow_page expect_[] = { __VA_ARGS__ };                                \
    sd_flow_page got_[16];                                                                \
    size_t n_ = run_flow(&(input), (mode), got_, FLOW_COUNTOF(got_));                       \
    if (!same_pages(got_, n_, expect_, FLOW_COUNTOF(expect_)))                              \
      sd_test_fail(sd_t_, __FILE__, __LINE__, "page flow %s differs", name);              \
  } while (0)

SD_TEST(setup_flow_first_page)
{
  sd_flow_input in;

  memset(&in, 0, sizeof(in));
  SD_CHECK(sd_flow_first(&in) == SD_FLOW_WELCOME);

  in.quiet = 1;
  SD_CHECK(sd_flow_first(&in) == SD_FLOW_NONE);           /* /quiet shows nothing */

  memset(&in, 0, sizeof(in));
  in.passive = 1;
  SD_CHECK(sd_flow_first(&in) == SD_FLOW_PROGRESS);       /* /passive shows the progress only */

  memset(&in, 0, sizeof(in));
  in.uninstall = 1;
  SD_CHECK(sd_flow_first(&in) == SD_FLOW_UNINSTALL);      /* removal confirmation first */

  in.passive = 1;
  SD_CHECK(sd_flow_first(&in) == SD_FLOW_PROGRESS);       /* a passive removal asks nothing */

  in.passive = 0;
  in.quiet = 1;
  SD_CHECK(sd_flow_first(&in) == SD_FLOW_NONE);
}

SD_TEST(setup_flow_interactive_pages)
{
  sd_flow_input in;
  sd_flow_page pages[16];
  size_t n;

  /* No mode on the command line: the mode page is asked. */
  memset(&in, 0, sizeof(in));
  SD_FLOW_CASE("per-user, asked",
               in, SD_SETUP_MODE_USER,
               SD_FLOW_WELCOME, SD_FLOW_LICENSE, SD_FLOW_MODE, SD_FLOW_PROGRESS, SD_FLOW_FINISH);

  /* /peruser given: the mode page is skipped. */
  memset(&in, 0, sizeof(in));
  in.mode_given = 1;
  SD_FLOW_CASE("per-user, given",
               in, SD_SETUP_MODE_USER,
               SD_FLOW_WELCOME, SD_FLOW_LICENSE, SD_FLOW_PROGRESS, SD_FLOW_FINISH);

  /* Portable without a folder: the destination page follows the mode page. */
  memset(&in, 0, sizeof(in));
  SD_FLOW_CASE("portable, no folder",
               in, SD_SETUP_MODE_PORTABLE,
               SD_FLOW_WELCOME, SD_FLOW_LICENSE, SD_FLOW_MODE, SD_FLOW_DESTINATION, SD_FLOW_PROGRESS,
               SD_FLOW_FINISH);

  /* /portable=<folder> given: no destination page. */
  memset(&in, 0, sizeof(in));
  in.mode_given = 1;
  in.dest_given = 1;
  SD_FLOW_CASE("portable, folder given",
               in, SD_SETUP_MODE_PORTABLE,
               SD_FLOW_WELCOME, SD_FLOW_LICENSE, SD_FLOW_PROGRESS, SD_FLOW_FINISH);

  /* All users: the Dokany page sits between the mode and the progress. */
  memset(&in, 0, sizeof(in));
  in.mode_given = 1;
  SD_FLOW_CASE("all users, Dokany",
               in, SD_SETUP_MODE_MACHINE,
               SD_FLOW_WELCOME, SD_FLOW_LICENSE, SD_FLOW_DOKANY, SD_FLOW_PROGRESS, SD_FLOW_FINISH);

  /* The removal: confirmation, progress, and no finish page (its result is a message box). */
  memset(&in, 0, sizeof(in));
  in.uninstall = 1;
  SD_FLOW_CASE("removal", in, SD_SETUP_MODE_UNINSTALL, SD_FLOW_UNINSTALL, SD_FLOW_PROGRESS);

  /* Passive installs show the progress only, with no finish page. */
  memset(&in, 0, sizeof(in));
  in.passive = 1;
  in.mode_given = 1;
  n = run_flow(&in, SD_SETUP_MODE_USER, pages, FLOW_COUNTOF(pages));
  SD_CHECK_EQ_INT(n, 1);
  SD_CHECK(pages[0] == SD_FLOW_PROGRESS);
}

SD_TEST(setup_flow_terminates_for_every_input)
{
  /* Every combination of the command line and every answer: the flow ends, never repeats a page, and reaches
     the progress view unless the command line is /quiet. */
  unsigned bits;
  for (bits = 0; bits < 32; bits++) {
    sd_flow_input in;
    sd_setup_mode answers[4] = { SD_SETUP_MODE_USER, SD_SETUP_MODE_PORTABLE, SD_SETUP_MODE_MACHINE,
                                 SD_SETUP_MODE_USER };
    int a;
    memset(&in, 0, sizeof(in));
    in.quiet = (bits & 1) != 0;
    in.passive = (bits & 2) != 0;
    in.uninstall = (bits & 4) != 0;
    in.mode_given = (bits & 8) != 0;
    in.dest_given = (bits & 16) != 0;
    for (a = 0; a < 3; a++) {
      sd_flow_page pages[16];
      size_t n = run_flow(&in, answers[a], pages, FLOW_COUNTOF(pages));
      size_t i, j;
      int reached_progress = 0;
      SD_CHECK(n < FLOW_COUNTOF(pages));           /* the flow ended before the cap */
      for (i = 0; i < n; i++) {
        if (pages[i] == SD_FLOW_PROGRESS)
          reached_progress = 1;
        for (j = i + 1; j < n; j++)
          SD_CHECK(pages[i] != pages[j]);        /* no page twice */
      }
      if (!in.quiet)
        SD_CHECK(reached_progress);
      if (in.quiet)
        SD_CHECK(n == 0);
    }
  }
}

SD_TEST(setup_flow_dokany_view_states)
{
  sd_flow_dokany_view v;

  /* Pre-checked when the OS takes the driver (D36). */
  sd_flow_dokany_view_of(SD_SETUP_DOKANY_INSTALL_PLAN, &v);
  SD_CHECK(v.enabled && v.checked && !v.has_note);

  /* Unavailable: disabled, unchecked, with the reason. */
  sd_flow_dokany_view_of(SD_SETUP_DOKANY_UNAVAILABLE_PLAN, &v);
  SD_CHECK(!v.enabled && !v.checked);
  SD_CHECK(v.has_note && v.note == SD_MSG_INSTALLER_DOKANY_UNAVAILABLE);

  /* /dokany=skip: the user may still check it, and the note says WebDAV only. */
  sd_flow_dokany_view_of(SD_SETUP_DOKANY_SKIP_PLAN, &v);
  SD_CHECK(v.enabled && !v.checked);
  SD_CHECK(v.has_note && v.note == SD_MSG_INSTALLER_DOKANY_SKIP_NOTE);
}

SD_TEST(setup_flow_dokany_plan_by_mode)
{
  /* The plan the stub feeds the Dokany page: all users only, 7 SP1 (6.1) and later. */
  SD_CHECK(sd_setup_dokany_decide(SD_SETUP_MODE_USER, 0, SD_SETUP_DOKANY_AUTO, 10, 0) == SD_SETUP_DOKANY_SKIP_PLAN);
  SD_CHECK(sd_setup_dokany_decide(SD_SETUP_MODE_MACHINE, 0, SD_SETUP_DOKANY_AUTO, 6, 1) == SD_SETUP_DOKANY_INSTALL_PLAN);
  SD_CHECK(sd_setup_dokany_decide(SD_SETUP_MODE_MACHINE, 0, SD_SETUP_DOKANY_AUTO, 6, 0) == SD_SETUP_DOKANY_UNAVAILABLE_PLAN);
}

SD_TEST(setup_flow_names_and_titles)
{
  sd_flow_page p;
  sd_msg_id id = 0;
  for (p = SD_FLOW_WELCOME; p <= SD_FLOW_UNINSTALL; p = (sd_flow_page)(p + 1)) {
    SD_CHECK(sd_flow_page_title(p, &id) == 1);
    SD_CHECK(sd_flow_page_name(p) != NULL && sd_flow_page_name(p)[0] != '\0');
  }
  SD_CHECK(sd_flow_page_title(SD_FLOW_NONE, &id) == 0);
  SD_CHECK(sd_flow_page_title(SD_FLOW_PROGRESS, &id) == 1 && id == SD_MSG_INSTALLER_WINDOW_TITLE);
  SD_CHECK_STR(sd_flow_page_name(SD_FLOW_DOKANY), "dokany");
  /* The all-users choice is disabled in this build (04 §6.10): the test pins that state. */
  SD_CHECK_EQ_INT(SD_FLOW_MACHINE_AVAILABLE, 0);
}
