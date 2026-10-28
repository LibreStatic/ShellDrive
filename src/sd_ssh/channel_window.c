/* Adaptive receive window of one SSH channel (01 section 4.8, M7). See channel_window.h. */
#include "channel_window.h"

void ssh_win_init(ssh_win *w, int adaptive)
{
  w->allow = SSH_WIN_INITIAL;
  w->target = SSH_WIN_INITIAL;
  w->unacked = 0;
  w->epoch_start = 0;
  w->epoch_bytes = 0;
  w->epoch_valid = 0;
  w->streak = 0;
  w->adaptive = adaptive ? 1 : 0;
}

uint32_t ssh_win_on_data(ssh_win *w, uint32_t n, uint64_t now, uint32_t rtt_ms, uint64_t session_total)
{
  uint32_t grow, room;
  if (n > w->allow) return 0;   /* the caller rejects such data before this point */
  w->allow -= n;
  if (!w->adaptive) return 0;
  if (rtt_ms == 0) rtt_ms = 1;

  if (!w->epoch_valid || now < w->epoch_start || now - w->epoch_start >= rtt_ms) {
    /* The previous epoch is complete. Window-limited means the peer delivered at least half the target in it. */
    if (w->epoch_valid && w->epoch_bytes >= (uint64_t)(w->target / 2)) w->streak++;
    else w->streak = 0;
    w->epoch_valid = 1;
    w->epoch_start = now;
    w->epoch_bytes = 0;
  }
  w->epoch_bytes += n;

  if (w->streak < 2) return 0;
  w->streak = 0;

  /* Doubling, capped per channel and by the session budget. */
  if (w->target >= SSH_WIN_MAX) return 0;
  grow = w->target;
  if (grow > SSH_WIN_MAX - w->target) grow = SSH_WIN_MAX - w->target;
  room = session_total >= SSH_WIN_SESSION_CAP ? 0u : (uint32_t)(SSH_WIN_SESSION_CAP - session_total);
  if (grow > room) grow = room;
  if (grow == 0) return 0;
  w->target += grow;
  w->allow += grow;
  return grow;
}

uint32_t ssh_win_on_consumed(ssh_win *w, uint32_t n)
{
  uint32_t add;
  w->unacked += n;
  if (w->unacked < w->target / 2) return 0;
  add = w->unacked;
  w->unacked = 0;
  w->allow += add;
  return add;
}
