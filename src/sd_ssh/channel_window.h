/* Adaptive receive window of one SSH channel (01 section 4.8, M7). Pure state machine: no sockets, no
 * clock. The caller passes the current time in milliseconds, so tests drive it with a simulated clock.
 *
 * Rules (01 4.8):
 *   - initial allowance and floor: SSH_WIN_INITIAL (2 MiB); the target never shrinks;
 *   - WINDOW_ADJUST is sent once the consumer has freed at least half of the target;
 *   - growth: the target doubles, capped at SSH_WIN_MAX per channel and at SSH_WIN_SESSION_CAP summed over the
 *     channels of one connection. The extra allowance is granted at once.
 *
 * Growth trigger (interpretation, see docs/dev/m7-notes.md): 01 4.8 grows the window when the sender stalled
 * (allowance exhausted) twice within one RTT estimate. With the consumer freeing data at once, WINDOW_ADJUST
 * keeps the allowance above half the target, so an exhaustion never happens and the rule cannot fire. The
 * implemented signal is its bandwidth-delay equivalent: an "RTT epoch" is one RTT estimate long; an epoch in
 * which the peer delivered at least half the target means the window is the limit (throughput x RTT is close to
 * the window). Two such epochs in a row double the target.
 *
 * The allowance (`allow`) only grows through WINDOW_ADJUST grants and shrinks only with peer data. A fixed
 * window (adaptive = 0) keeps the initial 2 MiB forever. */
#ifndef SD_SSH_CHANNEL_WINDOW_H
#define SD_SSH_CHANNEL_WINDOW_H

#include <stddef.h>
#include <stdint.h>

#define SSH_WIN_INITIAL        (2u * 1024u * 1024u)   /* 01 4.8: initial window and floor */
#define SSH_WIN_MAX           (16u * 1024u * 1024u)   /* 01 4.8: cap per channel */
#define SSH_WIN_SESSION_CAP   (32u * 1024u * 1024u)   /* sum of the targets of one connection (m7-notes.md) */
#define SSH_WIN_RTT_DEFAULT_MS 500u                   /* used until the first RTT sample (01 4.6) */

typedef struct ssh_win {
  uint32_t allow;          /* bytes the peer may still send */
  uint32_t target;         /* window we keep open: SSH_WIN_INITIAL <= target <= SSH_WIN_MAX */
  uint32_t unacked;        /* consumed bytes not yet credited to the peer */
  uint64_t epoch_start;    /* start of the current RTT epoch (ms) */
  uint64_t epoch_bytes;    /* peer bytes received in the current epoch */
  int epoch_valid;
  uint32_t streak;         /* consecutive window-limited epochs */
  int adaptive;            /* 0: fixed window */
} ssh_win;

void ssh_win_init(ssh_win *w, int adaptive);

/* Peer data of n bytes was accepted (the caller checked n <= allow). rtt_ms is the current RTT estimate
 * (SSH_WIN_RTT_DEFAULT_MS without a sample). session_total is the sum of the targets of every channel on the
 * connection, including this one. Returns the growth to grant at once: the caller sends WINDOW_ADJUST with that
 * amount, and it is already added to allow. Returns 0 when there is no growth. */
uint32_t ssh_win_on_data(ssh_win *w, uint32_t n, uint64_t now, uint32_t rtt_ms, uint64_t session_total);

/* The consumer freed n bytes. Returns the amount to credit to the peer now (0 = send nothing); it is already
 * added to allow. */
uint32_t ssh_win_on_consumed(ssh_win *w, uint32_t n);

#endif /* SD_SSH_CHANNEL_WINDOW_H */
