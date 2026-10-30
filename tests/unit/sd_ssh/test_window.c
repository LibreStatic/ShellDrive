/* Adaptive channel windows (src/sd_ssh/channel_window.c, 01 section 4.8, M7). The receive window runs against a
 * simulated link: a virtual clock advances 1 ms per step, the peer sends no more than its advertised allowance,
 * data and WINDOW_ADJUST messages arrive after a fixed one-way delay (FIFO), and the consumer frees every byte
 * at once (as sd_sftp does). Every step checks the protocol invariants. No network, no wall clock. */
#include <string.h>

#include "channel_window.h"
#include "sd_test.h"

#define SIM_QN 1024u
#define MIB    (1024ull * 1024ull)

typedef struct sim_q {
  uint64_t at[SIM_QN];
  uint32_t n[SIM_QN];
  uint32_t head, count;
} sim_q;

typedef struct sim {
  uint32_t bw_low, bw_high;      /* bytes per ms the sender can push; alternate every 500 ms phase */
  uint32_t owd;                  /* one-way delay in ms (RTT = 2 x owd) */
  uint64_t total, left, sent, recv;
  uint64_t peer_allow;           /* sender's view: advertised minus sent */
  uint64_t granted;              /* initial allowance plus every WINDOW_ADJUST sent */
  uint64_t done_at;              /* 0 until every byte was received */
  uint32_t grows, adjusts, max_target, prev_target;
  ssh_win rx;
  sim_q data_q, adj_q;           /* in flight, toward the receiver and toward the sender */
} sim;

static int q_push(sim_q *q, uint64_t at, uint32_t n)
{
  uint32_t idx;
  if (q->count == SIM_QN) return 0;
  idx = (q->head + q->count) % SIM_QN;
  q->at[idx] = at;
  q->n[idx] = n;
  q->count++;
  return 1;
}

static void sim_init(sim *s, int adaptive, uint32_t bw_low, uint32_t bw_high, uint32_t owd, uint64_t total)
{
  memset(s, 0, sizeof(*s));
  ssh_win_init(&s->rx, adaptive);
  s->bw_low = bw_low;
  s->bw_high = bw_high;
  s->owd = owd;
  s->total = total;
  s->left = total;
  s->peer_allow = SSH_WIN_INITIAL;
  s->granted = SSH_WIN_INITIAL;
  s->max_target = SSH_WIN_INITIAL;
  s->prev_target = SSH_WIN_INITIAL;
}

static uint64_t sessions_total(const sim *v, size_t nv)
{
  uint64_t t = 0;
  size_t i;
  for (i = 0; i < nv; i++) t += v[i].rx.target;
  return t;
}

/* One millisecond of channel `s` (index `idx` in `v`). The session budget is the sum over all of `v`. */
static void sim_step(sd_test_ctx *sd_t_, sim *v, size_t nv, size_t idx, uint64_t t)
{
  sim *s = &v[idx];
  uint32_t rtt = 2u * s->owd;
  uint32_t bw = ((t / 500u) % 2u) ? s->bw_high : s->bw_low;

  /* WINDOW_ADJUST arrivals at the sender */
  while (s->adj_q.count && s->adj_q.at[s->adj_q.head] <= t) {
    s->peer_allow += s->adj_q.n[s->adj_q.head];
    s->adj_q.head = (s->adj_q.head + 1) % SIM_QN;
    s->adj_q.count--;
  }

  /* data arrivals at the receiver; the consumer frees them at once */
  while (s->data_q.count && s->data_q.at[s->data_q.head] <= t) {
    uint32_t n = s->data_q.n[s->data_q.head];
    uint32_t grow, add;
    s->data_q.head = (s->data_q.head + 1) % SIM_QN;
    s->data_q.count--;

    SD_CHECK(n <= s->rx.allow);                 /* the peer never exceeds the advertised window */
    s->recv += n;
    grow = ssh_win_on_data(&s->rx, n, t, rtt, sessions_total(v, nv));
    if (grow) {
      s->grows++;
      s->granted += grow;
      SD_CHECK(q_push(&s->adj_q, t + s->owd, grow));
    }
    add = ssh_win_on_consumed(&s->rx, n);
    if (add) {
      s->adjusts++;
      s->granted += add;
      SD_CHECK(q_push(&s->adj_q, t + s->owd, add));
    }
  }

  /* the receiver's allowance is exactly what was granted minus what arrived: never negative, never shrunk */
  SD_CHECK((uint64_t)s->rx.allow == s->granted - s->recv);
  SD_CHECK(s->rx.target >= s->prev_target);     /* the target never shrinks */
  SD_CHECK(s->rx.target >= SSH_WIN_INITIAL && s->rx.target <= SSH_WIN_MAX);
  s->prev_target = s->rx.target;
  if (s->rx.target > s->max_target) s->max_target = s->rx.target;

  /* the sender: at most one burst per ms, never more than its allowance */
  if (s->left) {
    uint64_t chunk = bw;
    if (chunk > s->peer_allow) chunk = s->peer_allow;
    if (chunk > s->left) chunk = s->left;
    if (chunk) {
      SD_CHECK(q_push(&s->data_q, t + s->owd, (uint32_t)chunk));
      s->peer_allow -= chunk;
      s->left -= chunk;
      s->sent += chunk;
    }
  }
  if (!s->done_at && s->recv == s->total) s->done_at = t;
}

/* Runs every channel of `v` together (one session) until all are done or max_ms passes. */
static void sim_run(sd_test_ctx *sd_t_, sim *v, size_t nv, uint64_t max_ms)
{
  uint64_t t;
  size_t i;
  for (t = 1; t <= max_ms; t++) {
    int all_done = 1;
    for (i = 0; i < nv; i++) sim_step(sd_t_, v, nv, i, t);
    SD_CHECK(sessions_total(v, nv) <= SSH_WIN_SESSION_CAP);   /* the memory budget of one connection */
    for (i = 0; i < nv; i++) if (!v[i].done_at) all_done = 0;
    if (all_done) break;
  }
  for (i = 0; i < nv; i++) {
    SD_CHECK(v[i].sent == v[i].total);
    SD_CHECK(v[i].recv == v[i].total);
    SD_CHECK(v[i].done_at != 0);
  }
}

/* ---- unit level ---- */

SD_TEST(window_consumed_credits_half_the_target)
{
  ssh_win w;
  ssh_win_init(&w, 1);
  SD_CHECK_EQ_U64(w.allow, SSH_WIN_INITIAL);
  SD_CHECK_EQ_U64(w.target, SSH_WIN_INITIAL);
  SD_CHECK_EQ_U64(ssh_win_on_consumed(&w, (uint32_t)(SSH_WIN_INITIAL / 2 - 1)), 0);
  SD_CHECK_EQ_U64(ssh_win_on_consumed(&w, 1), SSH_WIN_INITIAL / 2);
  SD_CHECK_EQ_U64(w.allow, SSH_WIN_INITIAL + SSH_WIN_INITIAL / 2);
  SD_CHECK_EQ_U64(w.unacked, 0);
}

SD_TEST(window_data_reduces_allowance_and_refuses_overrun)
{
  ssh_win w;
  ssh_win_init(&w, 1);
  SD_CHECK_EQ_U64(ssh_win_on_data(&w, 1000, 0, 100, SSH_WIN_INITIAL), 0);
  SD_CHECK_EQ_U64(w.allow, SSH_WIN_INITIAL - 1000);
  /* the caller rejects data beyond the allowance; the module does not wrap around either */
  SD_CHECK_EQ_U64(ssh_win_on_data(&w, SSH_WIN_INITIAL, 0, 100, SSH_WIN_INITIAL), 0);
  SD_CHECK_EQ_U64(w.allow, SSH_WIN_INITIAL - 1000);
}

SD_TEST(window_one_limited_epoch_is_not_enough)
{
  /* a full-enough epoch counts as one; a quiet epoch after it resets the streak and nothing grows */
  ssh_win w;
  ssh_win_init(&w, 1);
  SD_CHECK_EQ_U64(ssh_win_on_data(&w, (uint32_t)SSH_WIN_INITIAL / 2, 0, 100, SSH_WIN_INITIAL), 0);
  SD_CHECK_EQ_U64(ssh_win_on_data(&w, 0, 100, 100, SSH_WIN_INITIAL), 0);   /* closes epoch 1: streak 1 */
  SD_CHECK_EQ_U64(w.streak, 1);
  SD_CHECK_EQ_U64(ssh_win_on_data(&w, 0, 200, 100, SSH_WIN_INITIAL), 0);   /* closes epoch 2 (empty) */
  SD_CHECK_EQ_U64(w.streak, 0);
  SD_CHECK_EQ_U64(w.target, SSH_WIN_INITIAL);
}

SD_TEST(window_fixed_never_changes)
{
  ssh_win w;
  uint32_t i;
  ssh_win_init(&w, 0);
  for (i = 0; i < 1000; i++) {
    (void)ssh_win_on_data(&w, 1000, (uint64_t)i * 3, 1, SSH_WIN_INITIAL);
    (void)ssh_win_on_consumed(&w, 1000);
  }
  SD_CHECK_EQ_U64(w.target, SSH_WIN_INITIAL);
}

/* ---- simulated transport ---- */

SD_TEST(window_fixed_stays_at_initial_on_high_bdp)
{
  static sim v[1];
  sim_init(&v[0], 0, 10000u, 10000u, 100u, 64 * MIB);     /* 10 MB/s, RTT 200 ms: BDP 2 MB */
  sim_run(sd_t_, v, 1, 200000);
  SD_CHECK_EQ_U64(v[0].grows, 0);
  SD_CHECK_EQ_U64(v[0].max_target, SSH_WIN_INITIAL);
}

SD_TEST(window_grows_on_high_bdp_and_finishes_sooner)
{
  static sim fixed[1], adaptive[1];
  sim_init(&fixed[0], 0, 10000u, 10000u, 100u, 64 * MIB);
  sim_init(&adaptive[0], 1, 10000u, 10000u, 100u, 64 * MIB);
  sim_run(sd_t_, fixed, 1, 200000);
  sim_run(sd_t_, adaptive, 1, 200000);
  SD_CHECK(adaptive[0].grows >= 1);
  SD_CHECK(adaptive[0].max_target > SSH_WIN_INITIAL);
  SD_CHECK(adaptive[0].max_target <= SSH_WIN_MAX);
  /* simulated time, deterministic: the larger window is never slower on this link */
  SD_CHECK(adaptive[0].done_at <= fixed[0].done_at);
}

SD_TEST(window_bounded_by_per_channel_cap)
{
  static sim v[1];
  sim_init(&v[0], 1, 100000u, 100000u, 250u, 128 * MIB);   /* BDP 50 MB: the window is the limit all the time */
  sim_run(sd_t_, v, 1, 300000);
  SD_CHECK_EQ_U64(v[0].max_target, SSH_WIN_MAX);
  SD_CHECK_EQ_U64(v[0].rx.target, SSH_WIN_MAX);
}

SD_TEST(window_no_growth_on_low_rtt)
{
  static sim v[1];
  sim_init(&v[0], 1, 10000u, 10000u, 2u, 8 * MIB);        /* RTT 4 ms: at most 40 KB per epoch */
  sim_run(sd_t_, v, 1, 200000);
  SD_CHECK_EQ_U64(v[0].grows, 0);
  SD_CHECK_EQ_U64(v[0].max_target, SSH_WIN_INITIAL);
}

SD_TEST(window_session_budget_binds)
{
  /* three channels on one connection, each on a link that wants the cap: the sum never exceeds the session
   * budget (checked every millisecond by sim_run) and the first channel takes the room that is left */
  static sim v[3];
  sim_init(&v[0], 1, 100000u, 100000u, 250u, 128 * MIB);
  sim_init(&v[1], 1, 100000u, 100000u, 250u, 128 * MIB);
  sim_init(&v[2], 1, 100000u, 100000u, 250u, 128 * MIB);
  sim_run(sd_t_, v, 3, 300000);
  SD_CHECK(sessions_total(v, 3) <= SSH_WIN_SESSION_CAP);
  SD_CHECK_EQ_U64(v[0].max_target, SSH_WIN_MAX);
  SD_CHECK(v[1].max_target <= SSH_WIN_MAX && v[2].max_target <= SSH_WIN_MAX);
  SD_CHECK(v[1].max_target < SSH_WIN_MAX || v[2].max_target < SSH_WIN_MAX);
}

SD_TEST(window_protocol_holds_with_varying_throughput)
{
  /* throughput alternates between a trickle and a burst every 500 ms: the peer never exceeds its allowance,
   * the allowance equals grants minus arrivals, the target never shrinks (all checked in sim_step) */
  static sim v[1];
  sim_init(&v[0], 1, 1000u, 150000u, 100u, 128 * MIB);
  sim_run(sd_t_, v, 1, 300000);
  SD_CHECK(v[0].max_target <= SSH_WIN_MAX);
  SD_CHECK(v[0].adjusts >= 1);
}

static const sd_test_case k_tests[] = {
  SD_TEST_ENTRY(window_consumed_credits_half_the_target),
  SD_TEST_ENTRY(window_data_reduces_allowance_and_refuses_overrun),
  SD_TEST_ENTRY(window_one_limited_epoch_is_not_enough),
  SD_TEST_ENTRY(window_fixed_never_changes),
  SD_TEST_ENTRY(window_fixed_stays_at_initial_on_high_bdp),
  SD_TEST_ENTRY(window_grows_on_high_bdp_and_finishes_sooner),
  SD_TEST_ENTRY(window_bounded_by_per_channel_cap),
  SD_TEST_ENTRY(window_no_growth_on_low_rtt),
  SD_TEST_ENTRY(window_session_budget_binds),
  SD_TEST_ENTRY(window_protocol_holds_with_varying_throughput),
};

int main(int argc, char **argv)
{
  return sd_test_main(k_tests, SD_COUNTOF(k_tests), argc, argv);
}
