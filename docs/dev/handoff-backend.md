# Hand-off: all backend work, M1–M7

Date: 2026-10-25. Repo `github.com/LibreStatic/ShellDrive`. Backend work continues on branch `wip/m2-backend`
(this document lives there); `main` stays clean for the frontend track. This hand-off covers **every backend item
of every milestone** in `docs/design/00-integration-review.md` §6. Frontend (GUI) work is handed off separately to
the lead session, which validates and implements it.

## State update: 2026-10-27, M2 code complete; only the acceptance doc, the D38 package and the final -Clean remain

Read this first; it supersedes every section below. Branch `wip/m2-backend`, tree clean at `cbe6439`. The
striping worktree (`C:\Users\facum\ShellDrive-striping`, branch `wip/m2-striping`, clean at `dccb8c2`) is
fully merged - all later work went straight onto `wip/m2-backend`.

### What this session did (commits, oldest first)

- `cc0cd3a`: the CI repairs - `unit.crypto_pk` gets a 3600 s ctest TIMEOUT on the x86 flavours only (the
  suite passes by hand in ~25-30 min; x64 keeps 300 s), and the `reconnect_drop_during_pipelined_reads`
  race is fixed in `req_submit` (sftp_session.c): an operation carrying a handle submitted while the
  session is not READY returns `SD_E_STALE_HANDLE` per the M1 contract; path ops keep `SD_E_DISCONNECTED`.
  Verified 12x on x64-analysis.
- `c4934e9`..`dccb8c2` (11 commits): the striping branch rebased and landed. Increment 2 (stream idx 0-4,
  Q_STRIPE/PH_STRIPED, unit routing with quiescent recompute, lazy sub-handles, barriers, member-loss
  semantics), the real `s->live` accounting fix, 22 fake-transport unit tests, the per-member generation
  guard, the member-lost write-wires fix (`64409dc`: a dropped member's sibling wires stay answerable or
  the server hangs the session), interop coverage with a deterministic single-member drop
  (freeze - burst - kill - thaw), the independent review's fixes, and the contract docs (01 section 10.9,
  02 section 5.6 pointer, m2-notes).
- `2d26f5e`: pool increment 3 - 500 ms admission stagger (per-pool timer thread), backoff 500 ms then 2 s,
  abandonment after 3 transient refusals until the next generation via the new `SD_E_POOL_ABANDONED`
  (all consumers updated); identity mismatch still stops the generation instantly. 4 tests. Also fixed a
  pre-existing `InterlockedOr` gap on XP x86.
- `bdf8156`: system proxy opt-in (TM-R10) - pure decision function `ssh_sysproxy_decide()`, new
  `allow_system` field (policy `AllowSystemProxy`, default reject) on `sd_proxy_cfg`/`sd_mount_proxy`,
  fail-fast in `ssh_pxcfg_copy`, SSPI verdict `!discovered || AllowSystemProxySspi` in one place, WinHTTP
  for discovery only; documented in 01 section 5.2. Decision-matrix and boundary tests in `unit.ssh`.
- `5966ee3`: vfs striping policy (02 section 5.6) - `SD_SFTP_O_STRIPED` only when pool > 1 connection,
  sequential access, file >= 8 MiB (`stripe_min_file`) or >= 1 MiB sequential write latch; never APPEND or
  directories. 5 tests (`unit.vfs` 46/46). Bench `bench.vfs_pool` (label `bench`, gated behind
  `SD_IT_BENCH=1`): 1 GiB vs the wsl-sshd fixture - read 1.85x with 3 members (49.9 -> 92.2 MB/s), write
  does not scale (write-through saturates the primary bulk channel); numbers in m2-notes.
- `4871fcb` + `cabdd7f`: gate repairs - C28182 (`_Analysis_assume_(r->f != NULL)` in the REOPEN arm),
  ci-local excludes labels with the single expression `-LE 'matrix|bench'` (repeated -LE flags REPLACE,
  they do not accumulate), and the big striping test frames made `static` for the 16 KB analysis stack
  budget. After these, the full incremental `ci-local` run was GREEN on all five presets.
- `1fee8ee`: the M2 CLI - `profile import putty [<session>]|ssh-config [<file>] [--dry-run]`,
  `hostkey list [--announced]|import --from putty|openssh|remove|accept-announced <id> [--add-only]`
  (list/import/remove run sd_known_hosts in-process per 03 section 5/C19; accept-announced drives the
  existing IPC hostkey methods), `status`, `--jump` (repeatable, max 8), `--proxy`, `--connections`;
  console flows for password change, proxy password, legacy acknowledge, save-response, and TM-R03 jump
  lines. Agent conn JSON gains `pool`/`pool_wanted`; five new exit codes. The sd_mount mapping itself was
  already complete (`agent.c` build_chain/handle_mount_body). 56 new strings registered; parsing + smoke
  tests added.
- `cbe6439`: those 56 strings localized into es (rioplatense voseo), fr (vous), pt-BR, it, de (informal),
  CLDR plurals, prompt answer letters matched per locale; `sdl10n --check` and the `l10n.*` gates green.

### What remains of M2 (in order)

1. Acceptance: run `tests\interop\run-matrix.ps1` once with the matrix fixtures up (squid/dante down is
   the established green state) and write `docs/dev/m2-acceptance.md` following `m1-acceptance.md`'s
   conventions (scoped per 00 section 6 M2 row; striping numbers from m2-notes; exact reviewer commands;
   date 2026-10-27; no local user names or machine paths).
2. The D38 review pass 1 package (decisions.md D38): all of sd_crypto (pk+pq) and sd_ssh - sources
   reviewed, test evidence with commands and current results (unit suites, wycheproof, CNG-diff, the CT
   gate output, XP import floors), the TST mapping from 05-threat-model.md, open findings. It prepares
   the human pass 1; it does not replace it.
3. A fresh `tools\ci-local.ps1 -Clean` for the record (the incremental run is green at `cbe6439`; -Clean
   is the milestone gate).
4. Then M1 remainder, M3-M6 as listed below. M3's IPC surface is what the frontend track consumes - it
   is the next backend priority after M2 closes.

### Contract changes this session (frontend-relevant)

- `sd_err`: new code `SD_E_POOL_ABANDONED` (01 section 10.2 schema, IPC exit-code table, vfs mapping).
- CLI: the verbs and options above; exit codes `host_key_not_found`, `announcement_not_found`,
  `session_not_found`, `putty_not_found`, `file_not_found` (03 section 7).
- Agent connection JSON: `pool` and `pool_wanted` fields.
- `sd_ssh`: `allow_system` on `sd_proxy_cfg` (policy `AllowSystemProxy`, default 0); see 01 section 5.2.
- l10n: 56 new strings in the `l10n/cli` domain, complete in all six locales.
- ci-local now runs ctest with `-LE 'matrix|bench'`; benchmarks are opt-in via `SD_IT_BENCH=1`.

### Environment

- Fixtures up: all matrix instances except squid/dante (never run), wsl-sshd up. No CI running.
- Providers seen from the workflow subagents: TokenHarbor `deepseek-v4.1-flash:free$high` works but
  queues long; NIM rejects the harness reasoning parameters (`enable_thinking`/`reasoning`) with 400 on
  every model and level tried - unusable until that clears; `z-ai-individual-coding-plan` GLM-5.3-Flash
  `$high` did all of this session's subagent work reliably.

## State update: 2026-10-26, striping session: unit-tested, hardened, interop covered, contract documented; CI gate red

Read this first; on striping state it supersedes the two 2026-10-25 sections below.

**Where things stand.** `wip/m2-striping` (worktree `C:\Users\facum\ShellDrive-striping`) is clean at the tip,
ten commits on top of `5923090`. All six risks of the 2026-10-25 section are closed: 1 by the tests, 2/3/5 by
`8703f72`, 4 evaluated and dropped, 6 by the contract commit at the tip. The commits, oldest first:

1. `99d6042` "Implement pool striping over member streams (01 10.9, increment 2)" - the handed-off WIP,
   including this document's increment-2 section.
2. `818c000` "Fix the sub-open request accounting in pool striping" - **a real defect the new tests
   caught**: `start_sub_open()` (sftp_session.c:885) submitted its internal request without incrementing
   `s->live`, while `deliver()` (sftp_session.c:430) decrements it for every request, so after the first
   member sub-open `(uint32_t)s->live` wrapped to ~4e9 and every later submission returned `SD_E_BUSY`
   (measured: session READY, queued=0, inflight=0, fsync -> 23 "busy"). Fixed with the matching increment;
   `req_submit()`'s SD_E_BUSY rejection path (sftp_session.c:3013-3017) verified symmetric; barriers count
   `data_wires`/`SST_OPENING`, not `live`, so no double counting.
3. `93cc916` "Add fake-transport unit tests for pool striping" - `sftp_test_tp.{c,h}` now models streams
   0..4 (members 1..3 at idx 2..4, `SD_SFTP_TP_POOL`, `notify_ready` admitting through
   `sftp_session_pool_change()`, `member_stats` writing `out[idx-1]`, plus `fake_drop_member`,
   `fake_stream_packets`, `fake_set_session`); `tests/unit/sd_sftp/test_striping.c` (registered in
   CMakeLists.txt and main.c) covering unit routing, lazy sub-opens, barriers across every sub-handle
   with first-error-wins, member loss (in-flight READs re-issued on the primary with correct bytes,
   WRITEs completing SD_E_DISCONNECTED + maybe_executed + session_ready with the session still READY and a
   later striped open working), route recompute at the quiescent point, and regressions (plain handles /
   APPEND / CLASS_META / directories / no-member transports never touch a member stream).
4. `8703f72` "Guard pool member events with a per-member generation" - closes hand-off risks 2, 3 and 5:
   stale posted member events are ignored by generation (session-side guard at sftp_session.c:2495, the
   transport-side guard is sftp_ssh.c:422/436/787/865/933), a double drop emits exactly one EV_POOL and
   runs `member_lost` once (`striping_member_drop_reported_twice_acts_once`), `stripe_bytes` is clamped to
   the negotiated limits (`striping_stripe_unit_clamped_to_negotiated_limits`). One falsified unit test per
   risk (each fails with its guard disabled). Risk 4 evaluated and dropped: no real concurrency - all
   `f->sub` access is on the session I/O thread and `s->files` is walked under `s->lock`; the only
   caller-thread `file_unlink_free` path runs after the I/O thread is done (sftp_session.c:1418-1427).
5. `fbf8b17` "Keep a member-lost write's other wires answerable" - the wires of a failed write on the
   surviving channels stay in the wire table, so their late acknowledgements are discarded as stale replies
   instead of surfacing as "unknown id" `SD_E_PROTOCOL` (which had turned one lost member into a dead
   session).
6. `02075f2` "Add striping interop coverage with member loss" - `m2_striping_end_to_end` and
   `m2_striping_member_lost_mid_transfer` in `tests/unit/sd_sftp/test_ssh_interop.c`: a 32 MiB striped
   write + read-back over a 3-connection pool, SHA-256 verified against the server, payload on every
   member connection; then exactly one member killed mid-transfer through the fixture (`ctl.ps1` freeze /
   drop / thaw with bursts in flight, so the kill lands on wires the member really carried): burst reads
   recover byte-exact on the primary, burst writes on the lost member complete `SD_E_DISCONNECTED` with
   `maybe_executed = 1` and `session_ready = 1`, the pool reports 2 connections, the session never leaves
   READY and a follow-up striped transfer runs on the survivor.
7. `ea076d9` + `6b145cf` "Address review findings in the pool striping path" - three defects, tests grown
   to 22: (a) a refused member sub-open (server STATUS error or allocation failure) parked its units until
   the deadline instead of falling back - `stripe_unit_member()` now resolves the member per unit
   (`SST_FAILED` falls back at once, `SST_OPENING` waits, the next barrier recomputes the table without the
   member); (b) a write error on a member channel in the window between the member thread dropping the
   stream and the posted close killed the whole session - member channels now leave their bytes queued for
   the generation-guarded drop report, only channels 0/1 lose the session; (c) a striped write's statvfs
   refinement probe queued into `Q_STRIPE` parked forever (`pump_striped_req` keyed on the op alone) - probe
   phases now emit through `emit()` on the handle's own channel, so a full filesystem refines to
   `SD_E_NO_SPACE`. New pins: per-member WRITE placement, the three `emit_piece` parking limits with exact
   resume, a member dying with its barrier wire out, refused sub-open fallback, refined NO_SPACE vs
   unrefined FAILURE.
8. The tip commit documents the contract: 01 §10.9 rewritten as implemented (the transport view - stream
   indices 0 meta / 1 primary bulk / 2..4 members 1..3 behind `open_stream`/`write_stream`/`consumed_stream`,
   `member_stats` writing `out[idx-1]`; `Q_STRIPE`/`PH_STRIPED`; unit routing `route_map[k % route_n]` with
   the recompute points - the open FSTAT and completed barriers; barrier drain-then-fan-out, first error
   wins; the sub-open oflag mask `~(CREAT|TRUNC|EXCL|APPEND|STRIPED)`; the member-loss mechanics), the
   stale "[0] of out is unused" `member_stats` comment in `sd_sftp_transport.h` fixed (risk 6), and a
   striping section in `docs/dev/m2-notes.md` with every test name and the commands to run them.

Gates that ran green in the worktree (this session, `x64-modern` Debug): warning-free build;
`ctest -R ^unit\.sftp$` (64 tests, 0 failed, 15 s); the striping filters `sd-test-sftp --filter striping_`
(22/22) and `sd-test-sftp-ssh-interop --filter m2_striping` (2/2 against the wsl-sshd fixture, which was up
before and after). The x64-xp gate last ran green at `8703f72`; the four post-`8703f72` code commits and
this one have not been through it or through `ci-local` - the deciding gates re-run before the landing.
The transport-side generation guard in `sftp_ssh.c`, previously reachable only through a real SSH session,
is exercised by `m2_striping_member_lost_mid_transfer` (green above).

**The main-tree CI gate is RED, which blocks the landing.** `tools\ci-local.ps1 -Clean` finished on
`wip/m2-backend` at `5923090` (log: `build/ci-local-clean.log`) with three independent causes:

- x64-modern FAIL at minute 0: `Remove-Item` of `build\x64-modern` hit a file locked by a zombie process
  from the previous session's interrupted run. Environment only - a plain re-run clears it.
- x86-ia32-debug and x86-sse2-debug: `unit.crypto_pk` exceeds ctest's 300 s TIMEOUT. It is NOT broken:
  run by hand it completes `exit=0, 26 tests, 0 failed` in roughly 25-30 minutes (Debug + 32-bit limbs +
  CNG-diff comparisons + bench at 3.5 ops/s for dh group16). Fix: raise the ctest TIMEOUT for that test
  (config- or flavour-scoped) or trim/skip the bench in x86 Debug.
- x64-analysis: `reconnect_drop_during_pipelined_reads` got `SD_E_DISCONNECTED` (18) where the test
  requires `SD_E_STALE_HANDLE` (19) at `tests/unit/sd_sftp/test_reconnect.c:466` - a stale-marking race
  right after the drop, seen only in this preset. Decide which error is contractually first and make the
  marking (or the test's wait) deterministic.

**What is left** (increment 2 itself is code-complete, tested and documented):

1. Repair the three CI causes above on `wip/m2-backend`, then land `wip/m2-striping` (rebase or merge);
   a fresh full `ci-local -Clean` is the M2 gate afterwards - it also re-verifies the post-`8703f72`
   commits on every flavour, including x64-xp.
2. Increment 3: member reconnect/backoff - the 500 ms admission stagger, and a member refused 3x is
   abandoned for the generation (01 §10.9, "Admission rule" and the lead of "Per-connection reconnect").
3. The vfs striping policy (02 §5.6: >= 8 MiB or >= 1 MiB sequential write, never APPEND or directories)
   that decides which handles the VFS opens with `SD_SFTP_O_STRIPED`.
4. The 1 GiB pool speed-up measurement.
5. Then the rest of M2 in order: system proxy opt-in + TM-R10 tests, `sd_mount` mapping + CLI with l10n,
   `docs/dev/m2-acceptance.md` and the D38 review pass 1 package. After M2: M1 remainder (the non-blocked
   items), then M3-M6 backend per the milestone list below.

**Workflow resume (optional, only on the user's ask).** The dynamic-workflow run
`dwfrun-6119638b-437d-451c-874a-141e3c6b1b84` implements the phases above and was stopped by the user
mid-interop; everything through the x64-xp gate is cached under that id (ResumeWorkflowRun continues it;
its script is `.zcode/workflow-drafts/Striping-del-pool-M2-incremento-2.dwf.ts`). Provider notes from
this session: TokenHarbor `deepseek-v4.1-flash:free$high` works (it produced all the committed work
above) but queues long and rate-limits with backoff; the NIM provider rejected the harness reasoning
parameters (`enable_thinking`, `reasoning`) with 400s on every model and level tried (nemotron enabled
and disabled, glm-5.3-flash high), so it is unusable for workflow subagents until that clears;
NIM `deepseek-ai/deepseek-v4.1-flash$high` was switched to last and was stopped before proving itself.

Environment at hand-off: the matrix fixtures are down (start them with `ctl.ps1 start` / `fixture.sh start`
when a matrix row is needed; squid/dante still never run); the wsl-sshd fixture is up (verified before and
after the striping interop run above); a long CI run is in progress in the main tree - leave it alone; the
striping worktree is the only other checkout. Everything else in the milestone list below still applies.

## State update: 2026-10-25, pool striping (increment 2) - worktree `wip/m2-striping`

**Read this first.** Increment 2 (striping, 01 §10.9 / 02 §5.6) is implemented but **uncommitted** and **not
exercised by any test**. It lives in a separate worktree, `C:\Users\facum\ShellDrive-striping`, on branch
`wip/m2-striping` (created from `5923090`), because `tools\ci-local.ps1 -Clean` was still running in the main
tree. The main tree stays on `wip/m2-backend`; merge/cherry-pick when its gate is green. This whole section
exists only in the worktree: when the striping branch is merged, it lands with it.

Modified, not committed: `src/sd_sftp/sftp_internal.h`, `src/sd_sftp/sftp_session.c`,
`src/sd_sftp/sftp_ssh.c` (+829 / -29).

### Verified state

| Check | Result |
|---|---|
| `x64-modern` Debug configure + build (worktree) | Clean, zero warnings or errors |
| `ctest -R unit.sftp` (x64-modern Debug) | Passed, 5.72 s - existing tests only; **no striping test** |
| `ctest -R interop.sftp_ssh` | Skipped: the wsl-sshd fixture was not running |
| Main-tree gate `ci-local -Clean` (finished) | x64-xp **pass**. x64-modern failed at 0 min: `-Clean` could not delete a file under `build\x64-modern\tests\...` (a leftover test process held it; no ShellDrive process was running afterwards). x86-ia32 and x86-sse2: Release pass, Debug failed only on `unit.crypto_pk` **Timeout 300 s** (stops at `cng_diff_ecdh`; x64-analysis takes 136.88 s). x64-analysis: `unit.sftp reconnect_drop_during_pipelined_reads` failed with `SD_E_DISCONNECTED` (18) instead of `SD_E_STALE_HANDLE` (19) - that tree is `wip/m2-backend` at `5923090`, `dirty=0`, so it is pre-existing, not a striping change. Log: `C:\Users\facum\ShellDrive\build\ci-local-clean.log` |

The worktree build and `unit.sftp` run overlapped the x86 Debug presets of that gate, so CPU contention may
have contributed to the 300 s timeouts; re-run `x86-ia32-debug` and `x86-sse2-debug` alone before treating them
as product bugs. The `reconnect_drop_during_pipelined_reads` flake (a read submitted while the drop is being
processed completes with `DISCONNECTED` instead of `STALE_HANDLE`) passed in the other presets; it still needs
a decision: either the read path should map an in-flight drop to `STALE_HANDLE` or the test must accept both.

Build-tooling note: `cmake` and `ctest` are not on `PATH`. Use
`C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\{cmake,ctest}.exe`
(`ci-local.ps1` resolves them itself).

### What is implemented

**Session core (`sftp_session.c`, `sftp_internal.h`)**
- `NCH` grown to 5: 0 meta, 1 primary bulk, 2..4 members 1..3. New `Q_STRIPE` class queue (`qh/qt[3]`) and
  `PH_STRIPED` wire phase.
- `req_class` sends READ/WRITE/FSTAT/FSETSTAT/FSYNC/FSTATVFS/CLOSE of a striped handle to `Q_STRIPE`;
  `r->target_ch` binds an internal request to one member channel.
- `file_new` sets `striped` (`SD_SFTP_O_STRIPED`, never directories, meta handles or APPEND), `stripe_bytes`
  (default 1 MiB) and `route_n = 1`; `wire_take`/`detach_all` maintain `f->data_wires`.
- Routing: unit `k = off / stripe_bytes` goes to `route_map[k % route_n]`; the table is recomputed only at a
  quiescent point (`stripe_quiescent`, called from barrier replies and the open FSTAT), so a byte range always
  travels on the same connection in submission order.
- `emit_piece` splits each request at stripe-unit boundaries; `pump_striped_req` lazily opens one sub-handle per
  member (`start_sub_open`, `oflags & ~(CREAT|TRUNC|EXCL|APPEND|STRIPED)`) and stops at channel limits
  (inflight requests, obuf high water, inflight bytes).
- `emit_barrier`/`barrier_wire`: FSTAT/FSETSTAT/FSYNC/FSTATVFS/CLOSE wait for `f->data_wires == 0` and every
  `SST_OPENING` to settle, then run on the primary handle and on each open sub-handle; `striped_barrier_reply`
  completes when all wires settle (first error wins) and recomputes the route table.
- `member_lost` drops the member's wires, re-queues its in-flight READ ranges on the primary
  (`req_requeue_read`), fails its WRITEs with `SD_E_DISCONNECTED` plus `session_ready = 1`, releases the
  sub-handles and keeps the session READY.
- `sftp_session_pool_change` opens the member stream (`open_stream(1 + member)`) on admission and reports drops;
  `sink_on_open/closed/eof` handle member channels without killing the session; `go_ready` resets member
  channels and admission state; stats sum all `NCH`; reopen drops stale sub-handles; `sd_sftp_open` keeps
  `O_STRIPED` for `file_new` (the wire masks pflags with `& 0x3Fu`, so the bit never reaches the server).

**Pool transport (`sftp_ssh.c`)**
- Member channels are exposed as streams 2..4 through a two-queue proxy. RX: `member thread -> queue -> posted
  drain on the primary thread -> session sink`; the member channel is credited only when the session consumed
  the bytes, so the queues stay bounded by the SSH receive window. TX: `session -> bounded 1 MiB queue ->
  posted pump on the member thread`, with `on_writable` reported back to the session.
- `pool_open_stream` / `pool_write_stream` / `pool_consumed_stream` override the vtable for idx >= 2 and
  delegate idx 0..1 to the primary; `member_stats` writes `out[idx-1]` (members 1..3); `notify_ready` tears down
  and re-admits members per generation; `destroy` stops the member threads, frees the queues and destroys the
  per-member locks.

### Known risks (fix before trusting it)

1. Nothing exercises striping yet: no test opens a handle with `SD_SFTP_O_STRIPED`, so the whole emit and proxy
   path is unproven.
2. `member_stream_closed` is posted to the primary thread; a generation reset can run in between, so a stale
   event could call `on_closed` on a recycled `sftp_chan` and take down a freshly admitted member. Add a
   per-member generation/sequence and ignore stale posts.
3. A member drop can reach `sftp_session_pool_change(..., 0, ...)` twice (channel `on_closed` and
   `pool_decided`), producing duplicate `EV_POOL` events and a duplicate `member_lost`.
4. `member_lost` walks `s->files` releasing sub-handles; untested against a handle that is closing concurrently.
5. `stripe_bytes` is not clamped to `max_read`/`max_write` or validated as a multiple of the chunk size.
6. `sd_sftp_transport.h` still says "[0] of out is unused" for `member_stats`; the implementation uses
   `out[idx-1]`. Fix the comment in the contract commit.

### Next steps, in order

1. Commit the current state on `wip/m2-striping` (author and committer `FacuM`, no attribution), or keep it WIP
   but do not lose it.
2. Unit-test the striping path with the fake transport: `tests/unit/sd_sftp/sftp_test_tp.c` still exposes 2
   streams - extend it to N streams and route by idx, or drive `sftp_session_pool_change(s, 1..3, 1, SD_OK)`
   directly. Cover: units land on the routed streams, barriers wait for data wires, member loss re-issues reads
   and fails writes with `session_ready`, route recomputation at barriers.
3. Interop against the `modern` fixture with a file above the VFS threshold: verify SHA-256 on both sides,
   traffic in `stats.conn[1..3]`, and kill one member mid-transfer (reads recover, writes report
   `session_ready`).
4. Close risks 2 and 3 with a member generation field.
5. Re-run `unit.sftp`, then `x64-xp` Debug (the `NCH` change and the queues are flavour-independent, but XP has
   the strictest compiler and the oldest headers).
6. Document the contract in `01 §10.9` (stream idx 2..4, `PH_STRIPED`, barrier ordering, `member_stats`
   indexing) and in `docs/dev/m2-notes.md` in the same commit as the code. Record the VFS policy (02 §5.6:
   >= 8 MiB or >= 1 MiB sequential write, never APPEND or directories) when it is implemented.
7. Merge/cherry-pick onto `wip/m2-backend` once the main-tree gate is green, then continue with increment 3
   (member reconnect/backoff: 500 ms stagger, a member refused 3x is abandoned for the generation), the
   system-proxy TM-R10 tests, `sd_mount` mapping + CLI, `docs/dev/m2-acceptance.md` and the D38 package.

Before that merge, repair the gate itself: re-run `-Presets x64-modern` once the stale file lock is gone, then
`x86-ia32-debug` and `x86-sse2-debug` **alone** (no concurrent build or test on the machine) to tell a real
`unit.crypto_pk` slowdown from contention, and settle the `reconnect_drop_during_pipelined_reads` expectation.
Require the gate green on the merged tree, not only on either branch alone.

### Environment

- Worktree `C:\Users\facum\ShellDrive-striping` (`wip/m2-striping`); main tree on `wip/m2-backend` with the gate
  running.
- Matrix fixtures were up (all instances plus the HTTP/SOCKS proxies; squid/dante stopped). The **wsl-sshd**
  fixture was not: start it with `powershell -File tests\fixtures\wsl-sshd\start.ps1` before `interop.sftp_ssh`;
  fault injection is `powershell -File tests\fixtures\wsl-sshd\ctl.ps1 kill|restart|drop|freeze|reap|thaw|status`.
- Never run `wsl --shutdown` while fixtures run; tests use the fixtures' `direct_host`.

## State update: 2026-10-25, end of the M2 session (supersedes the per-area table below)

Branch `wip/m2-backend`, all work committed. Commits of this session, oldest first: "Fix the failing M2 unit
suites and add the RSA reference vectors", "Add matrix-driven transport interop tests for every fixture row",
"Add auth interop: every key format and user-certificate paths", "Implement pool members and admission in
sd_sftp (01 10.9, increment 1)", "Fix the XP/x86 flavours after the M2 WIP and pool work", "Make the
x64-analysis preset green again and scope the matrix tests", "Label the srv_* interop tests with 'matrix'".

### What is done (M2 order of the original hand-off)

1. Unit suites all green (17/17 on x64-modern Release and on x64-analysis Debug): the missing
   `refimpl/rsa_keys.txt` regenerated (seed 8017, `python -I tests/vectors/refimpl/pk_ref.py
   <rfc5903.txt> - - tests/vectors rsa`); the M1-era auth/conn tests updated to the implemented M2
   contract (cert-first offers, the RSA retry ladder, synchronous prompts -> `pump_prompts(f, n)` in
   the test harness); the fake pipe agent now always keeps a listening instance (the reconnect race
   was a test bug, not a product bug).
2. Transport interop done for every row: `tests/unit/sd_ssh/test_interop_m2.c`
   (`sd-test-ssh-interop-m2`), entries `interop.ssh_matrix_{connect,kex,pq,update,auth_keys,auth_certs}`
   with `srv_*` + `matrix` labels; `run-matrix.ps1` green on all rows with fixtures up, including
   `demo` (SOCKS5-auth -> OTP bastion -> target, PPK v3, ML-KEM), `jump2/jump3`, HTTP CONNECT
   (plain/Basic), SOCKS5 (plain/RFC 1929), `legacy`, `legacy3des`, `cert` (+ negative certificates),
   `rotate` (hostkeys-00 apply + reconnect). TOTP computed in-process from `SD_IT_OTP_SECRET`.
   Plain `ctest` excludes them via `-LE matrix` (they exit 77 without `SD_IT_*`); the runner fixed to
   not abort at the first failing row (PS 5.1 native-stderr quirk).
3. Connect, increment 1 of the pool (01 section 10.9): `sd_sftp_options.connections` (1..4) admits
   secondary members after READY only when authentication was non-interactive (2FA rule; prompts on a
   member are cancelled), each member = own `sd_ssh_conn` with `SD_SSH_CFG_POOL_MEMBER` + one bulk
   channel, admission exchange INIT/VERSION + REALPATH(".") length-framed, admit/drop decided on the
   primary I/O thread comparing host-key fingerprint and realpath; a mismatch drops the member and
   stops admissions for the generation. EV_POOL events, `info.connections`, `stats.conn[1..3]`.
   Tests: `m2_pool_admits_members`, `m2_pool_interactive_stays_at_one`
   (tests/unit/sd_sftp/test_ssh_interop.c, both green against `modern`).
4. All five presets build warning-free again (the XP import floors gained four documented XP APIs;
   `InterlockedAdd64` -> portable `sd_atomic_*`; Vista-only `GetTickCount64` -> `sd_tick_ms` in
   tests) and the x64-analysis preset is green (build + Debug unit suite) after analyzer fixes in
   `bn.c`, `profile_m2.c`, `secret.c` and several test files (details in m2-notes.md).

### What is NOT done (pick up here)

- **Pool increment 2 - striping (the next big rock).** Design is settled: grow `NCH` from 2 to 5
  (primary meta/bulk + 3 member bulk channels); the pool transport exposes member channels as
  streams with idx `1 + member` (2..4) through the existing `open_stream`/`write_stream` vtable
  (caps already carry `SD_SFTP_TP_POOL`); wires already key replies by `w->ch`, so routing is a new
  `member` decision in the emit path for `SD_SFTP_O_STRIPED` handles: unit `k = off / stripe_bytes`
  goes to member `k mod live_members`, sub-handles open lazily per member with
  `oflags & ~(CREAT|TRUNC|EXCL)`, `fstat/fsetstat/fsync/close` become barriers (wait for the
  handle's member wires to drain, then run on the primary), member loss reissues in-flight reads on
  the primary and completes writes with `SD_E_DISCONNECTED`/`maybe_executed = 1`/`session_ready = 1`.
  Then the vfs-side striping policy (02 section 5.6: >= 8 MiB or >= 1 MiB sequential write,
  never APPEND/directories) and the 1 GiB pool speed-up measurement.
- **Pool member reconnect/backoff** (member refused 3x is abandoned for the generation; 500 ms
  admission stagger) - increment 3.
- **System proxy opt-in + TM-R10 tests** (`SD_PROXY_SYSTEM`, `allow_discovered_sspi`,
  `AllowSystemProxySspi`): untested; needs either unit tests with a scripted WinHTTP environment or
  a fixture row.
- **sd_mount mapping + CLI** (original hand-off item 5): unchanged, half-done from before.
- **Verification gate:** a fresh `tools\ci-local.ps1 -Clean` was started and stopped midway at this
  session's end - run it as the first action; everything short of it is verified green (all presets
  build+test incrementally, matrix runner green, sftp/ssh interop green). Then
  `docs/dev/m2-acceptance.md` (does not exist yet) and the D38 review pass 1 package.

### Environment notes for the next session

- Fixtures were left running when the session ended: all matrix instances + proxies except
  `squid`/`dante` (never run; sudo step not done). `wsl.exe -e sh tests/fixtures/matrix/fixture.sh status`
  to check; restart with `ctl.ps1 start` / `fixture.sh start`. Never run `wsl --shutdown`.
- Encrypted PPK fixtures exist (puttygen installed): `SD_IT_KEY_ED25519_PPK3_ARGON2ID`,
  `SD_IT_KEY_RSA_PPK2_AES` - the PPK cross-check is covered by `interop.ssh_matrix_auth_keys`.
- `build/run-row.sh` (untracked dev helper) runs one matrix sub-test for one row by hand:
  `sh build/run-row.sh <row> <filter> [build-dir]`; `SD_IT_DBG=1` adds ssh log lines,
  row env comes from `tests/fixtures/matrix/state/endpoints.env` via `SD_IT_ENV_FILE`.
- The Windows->WSL localhost relay can wedge; rows/tests use `direct_host`. Killing sshd fixtures
  mid-copy is only safe via the fixture ctl scripts.

## Boundary between the two tracks

| Backend (this hand-off) | Frontend (other hand-off) |
|---|---|
| All libraries: `sd_base`, `sd_platform`, `sd_crypto`, `sd_ssh`, `sd_sftp`, `sd_vfs`, `sd_dokan`, `sd_webdav`, `sd_ipc`, `sd_config`, `sd_secret`, `sd_mount`, `sd_l10n` runtime | `shelldrive-ui.exe`: tray, main window, generated dialogs, prompt dialogs, host-key manager, logs viewer, first-run wizard, notifications |
| `shelldrive-host.exe` (agent and service modes), the CLI `shelldrive.exe` and its strings | `shelldrive-shellext.dll`: context menus, Explorer integration, Network locations, drive labels/icons, Windows 11 modern menu (`IExplorerCommand` + sparse MSIX contents) |
| IPC protocol, events and the shell-extension state snapshot **producer** | IPC/snapshot **consumers** in the UI and the shell extension |
| Setup stub engine, CAB payloads, MSI authoring, installer hooks, updater engine, ADMX/ADML generation, signing and release pipeline | Setup UI pages (incl. the D36 Dokany option page), updater consent UI, admin prompt UI |
| Build system, flavours, CI, local CI, lab, fuzzing, performance, crypto reviews | GUI string catalogs (their own l10n domain), accessibility, DPI, visual verification |

Contracts both tracks depend on are owned by backend and must be documented before frontend consumes them:
the IPC methods/events (03 §2), the snapshot layout (03 §8), the profile schema (03 §3.4.1) and policies (03 §3.5),
prompt kinds and their fields (01 §8, 03 §2.5), and error/exit codes (`sd_err`, 03 §7). Any change to these goes
into the owning design doc and `docs/dev/m*-notes.md` in the same commit.

## Rules (read first)

- `AGENTS.md`: English for code, comments, logs, docs and commits; user-facing strings in the six locales with the
  registers given there; full CLDR plurals.
- Commits: author **and** committer `FacuM <facumo.fm@gmail.com>`; never add `Co-Authored-By` or any AI/tool
  attribution (commit messages and PR bodies).
- `docs/design/decisions.md` is authoritative (D1–D46). Backend highlights: D1 zero third-party code, crypto
  included (specs only); D2 hashes are ours; D4 two x86 flavours; D6 service on by default per machine; D9
  write-through default; D11 global WebDAV spike; D15 ML-KEM in v1; D16 UpdateHostKeys; D17 no agents in the
  service; D18 pool only with non-interactive auth; D19 extra pool members bulk-only; D20 HTTP CONNECT + SOCKS5,
  no ProxyCommand; D28 x64-modern flavour; D31 ARM32 MSI; D32 Dokany packaging; D33 legacy enabled, warning only;
  D34 Terrapin cipher choice; D35 no implicit `service_access`; D36 Dokany install option; D37 `identities_only`;
  D38 review gate; D42 two signing sessions; D45 LibreStatic names; D46 public repo.
- Precedence: `decisions.md` → `00-integration-review.md` resolutions → owning design doc (01 SSH/SFTP/crypto,
  02 filesystem, 03 apps, 04 build) → `05-threat-model.md` TM-R as applied.
- Verification is local: `powershell -ExecutionPolicy Bypass -File tools\ci-local.ps1 [-Clean]` (x64-modern,
  x64-xp, x86-ia32, x86-sse2, x64-analysis; Release + Debug; fails on any warning or skipped interop test; x86
  `dokany.*` skips under WOW64 are expected). GitHub CI is free (public repo) but cannot run interop/WebDAV/Dokany.
- Per-area source lists in `src/sd_ssh/sources_{transport,auth,connect}.cmake` and
  `src/sd_crypto/sources_{pk,pq}.cmake` keep parallel work out of shared files.
- Never run `wsl --shutdown` while fixtures run. Tests use the fixtures' `direct_host` because the Windows→WSL
  `localhost:2222` relay can wedge after sshd kills.

## Environment on the dev machine

- VS 2022 Build Tools 17.14 (v143, v141 + v141_xp, ARM/ARM64 compilers, CMake), SDK 10.0.26100 and 7.1A.
  Not installed yet: SDK 10.0.22621 (needed for the ARM32 flavour, 04 §1.1), WiX 3.14.1, Windows ADK (oscdimg).
- Dokany 2.3.1 x64 installed; WebClient available (trigger-start); Hyper-V enabled; QEMU 11.1
  (`C:\Program Files\qemu`, `-cpu pentium3`); LibreOffice 26.8.1.
- WSL Ubuntu 24.04: `libpam-google-authenticator` + `/etc/pam.d/shelldrive-otp`, `squid`, `dante-server`,
  `putty-tools` (installed by the user).
- Fixtures (`docs/dev/m2-notes.md`): OpenSSH 10.6p1 (GPG-verified, user prefix); instances `modern` 2222, `ossh10`
  2230, `ossh10pq` 2239, `legacy` 2231, `legacy3des` 2238, `bastion1` 2232, `bastion2` 127.0.0.2:2233, `target`
  127.0.0.2:2234, `cert` 2235, `rotate` 2236, `otp` 2237; Python HTTP 2280/2281 and SOCKS5 2290/2291. Endpoints in
  `tests/fixtures/matrix/state/endpoints.env` (`SD_IT_*`; never log `SD_IT_OTP_SECRET`); TOTP via
  `sh tests/fixtures/matrix/fixture.sh otp-code` in WSL; matrix runner `tests/interop/run-matrix.ps1`.
  Squid/Dante rows are configured but never run. On `main`, fixture state dirs are excluded via `.git/info/exclude`.
- Lab (`tests/lab/`): Hyper-V and QEMU scripts, payload ISO builder, COM1 reader, in-guest smoke scripts. Waiting
  on licensed XP SP3 x86 and Windows 7 SP1 x86/x64 images from the user.

## Done so far (on `main`)

M0 complete (`docs/dev/m0-acceptance.md`). M1 code complete with Windows 11 acceptance (`docs/dev/m1-acceptance.md`):
reconnect, meta/bulk channels, caches and read-ahead, write-behind opt-in, `sd_webdav`, x86 flavours,
`sd-isacheck`, lab harness. GitHub CI green on five presets.

## Backend work by milestone

### M1 — remainder

- Lab acceptance (00 §6): XP SP3 x86 (`x86-ia32` on the QEMU Pentium III VM, `x86-sse2` elsewhere) and Windows 7
  SP1 x86/x64, WebDAV mount + file ops + Office/LibreOffice pattern, via `tests/lab/`.
- WebDAV with sshd killed mid-copy (not yet tested).
- TM-R19 token-only WebDAV mode + WinHTTP self-test, so non-redirector clients (LibreOffice opening files) work;
  policy `AllowWebDavTokenOnly` (03 §3.5).
- [done, r13 `wip/r13-davmove`] Replacing MOVE drops the destination lock (final UNLOCK gets 409): the destination
  URL keeps its lock across a replacing MOVE, decided in 02 §7.5; tests `webdav_server_office_save_sequence` and
  `webdav_server_replacing_move_drops_replaced_children_locks`. Lab re-check with Office is open (`m1-notes`).
- [done, r14 `wip/r14-offwait`] Negative cache while the link is down: a cached miss (and a name absent from a
  cached listing) reports `SD_VFS_E_DISCONNECTED`, so WebDAV answers 503 + `Retry-After` (tests
  `vfs_offline_negative_lookup_is_disconnected`, `webdav_server_cached_miss_is_503_while_link_down`). No
  `sd_mount` change was needed (`m1-notes`, r14).
- [done, r14] sd_vfs offline waits: `SD_SFTP_REQ_WAIT_READY` request instead of 50 ms polling; quiesce and
  unmount cancel the waiters (tests `vfs_offline_wait_completes_on_reconnect`, `vfs_offline_wait_cancel_returns_promptly`).
  Open: lookups still fail at once while offline, not after `offline_wait` (`m1-notes`, r14).
- TM-R17 watchers for long-running clients (crash filter and stop cleanup already done).

### M2 — all of it (in progress, uncommitted state committed on this branch)

Scope per 00 §6 M2 row, its demoable outcome and gate D38. State when the area agents were stopped (tree builds
warning-free on x64-modern; ctest 31/34):

| Area | Files | State |
|---|---|---|
| fixtures | `tests/fixtures/{matrix,openssh10,transport}/`, `tests/interop/`, `wsl-sshd/ctl.*` | Done (self-test 53/53, OTP live). |
| crypto `pq` | `src/sd_crypto/{sha3,mlkem,mlkem_hybrid,blake2b,argon2,des3}.c`, `pktcipher.c`, `sd_crypto_pq.h`, `tests/unit/sd_crypto_pq/` | Near done: tests pass; re-run full suite, x86-ia32 CT gate, throughput. |
| crypto `pk` | `src/sd_crypto/{bn,rsa,dh,dh_gex,ec_p,sha1}.c`, `pk_*`, `sd_crypto_pk.h`, `tests/unit/sd_crypto_pk/` | RSA private-key path fails (`rsa_reference_keys`, `cng_diff_rsa`); `bench_pk_throughput` fails. |
| ssh `transport` | `kex*.c`, `negotiate.c`, `packet.c`, `known_hosts*.c`, `hostkey_{verify,update}.c` | Interop tests not written; `unit.ssh` `ssh_conn_config_validation` fails (3 checks). |
| ssh `auth` | `auth*.c`, `keyfile*.c`, `agent*.c`, `sd_agent.h` | 7/19 `unit.ssh_auth` fail (mostly RSA; also password change, kbd-interactive rounds, fake agent pipe). |
| ssh `connect` | `conn.c`, `channel.c`, `jump_chain.c`, `proxy_*.c` | Jump chain and proxies written; pool + `SD_SFTP_O_STRIPED` in `src/sd_sftp/` not started. |
| apps backend | `src/sd_secret/`, `src/sd_config/{import.c,profile_m2.c}`, `src/sd_mount/*`, `apps/shelldrive-host/agent.c` | Secrets, importers, profile keys done; `sd_mount` mapping half done; CLI commands not done. |

Order: (1) fix RSA, then config validation; (2) transport interop over every KEX × host-key alg on `modern`,
`ossh10`, `ossh10pq`, `legacy`, `legacy3des`, `cert`, `rotate`; (3) auth: all key types/formats (encrypted PPK v3
cross-checked with `puttygen`), user certs on `cert`, OTP on `otp`, password change, Pageant/OpenSSH agent clients;
(4) connect: pool 1–4 with striping and barriers, vfs side (02 §5.6), the 2FA rule proved on `otp`, 2/3-hop jumps,
jump via SOCKS5 with auth, HTTP CONNECT with Basic, system proxy opt-in, TM-R10; pool speed-up on 1 GiB;
(5) `sd_mount` mapping + CLI (`profile import putty|ssh-config`, `hostkey list|import|remove|accept-announced`,
`--jump`, `--proxy`, `--connections`, kbd-interactive console prompts, password change, proxy credentials,
UpdateHostKeys review) with l10n; tag interop tests `srv_*` and drive acceptance with `run-matrix.ps1`;
(6) `ci-local -Clean` green, `docs/dev/m2-acceptance.md`; (7) D38 review pass 1 package (all of `sd_crypto` and
`sd_ssh`, test evidence, CT-gate output, TST mapping). **No public beta before pass 1 closes.**

### M3 — backend parts

- IPC surface the UI needs (03 §2): profile CRUD, mount/unmount/list/status, subscription to `mount.state`,
  `warning` (incl. `write_failed`), prompt events and `prompt.answer` from the UI, log query, settings read/write,
  host-key store operations incl. UpdateHostKeys review data. Version the protocol; document every method.
- Prompt broker in the agent: route to CLI → tray/UI → launch UI → queue (03 §2.5), with timeouts.
- State snapshot producer for the shell extension (03 §8): shared section layout, owner/integrity checks
  (TM-R26), update on every state change, versioned with one-version skew tolerance.
- Host-side data the shell integration needs: per-mount drive label/icon values written by the host per 03 §8
  (the frontend defines the visuals), stable targets for Network locations (02 §10.3).
- l10n tooling: `sdl10n` register lint, `qps` pseudo-locale generation, CLI catalog complete in six locales.

### M4 — backend parts

- Setup stub engine (04 §6): built from `x86-ia32`, CAB payload extraction via `cabinet.dll`, flavour selection by
  CPU and OS (`x86-ia32`/`x86-sse2`, `x64-xp`/`x64-modern`, ARM64; ARM32 own EXE), per-user/per-machine/portable,
  two-stage elevation and `%ProgramData%\LibreStatic` checks (TM-R33/R34), KnownDLLs-only imports.
- Six flavours in CI and local CI, incl. `x64-modern` (v143, CFG/CET) and `arm32` (needs SDK 10.0.22621).
- WiX 3.14 MSIs per flavour incl. ARM32 (D31), language transforms for every LCID (C43), service installed and on
  per machine (D6), `ENABLELINKEDCONNECTIONS` (D24), `DOKANY` property (D36), `REMOVESECRETS`, Dokany chaining after
  the `dokan2.dll` VC++ dependency check (C31, D32), repair-safe custom actions (TM-R35), `DEFAULTPROFILES`.
- Installer hooks run through `shelldrive-host.exe` (`webdav-tune`, `programdata-secure`, `user-cleanup`,
  `modern-menu` registration, `signal-shutdown`); upgrade with running processes (C3, C4).
- Updater engine (04 §9): signed manifest + keyset with offline root keys (TM-R37), per-channel anti-rollback,
  expiry, HTTPS then the static HTTP mirror (D30), staging, apply, `--selftest`, rollback. The consent UI is
  frontend; the engine exposes it over IPC.
- ADMX/ADML generated from the policy table (03 §3.5); sparse MSIX **build switch and packaging** (D27; its
  contents are frontend); reproducible-build check (`/Brepro`, double build); release pipeline with two offline
  signing sessions (D42), pinned Actions, maintainer rebuild (TM-R39).

### M5 — backend parts

- Global WebDAV spike first (D11, 02 §7.7): mechanisms `system`/`link` per OS, go/no-go recorded, `attach` fallback.
- `ShellDriveSvc`: Dokany global mounts, service-hosted WebDAV per the spike, `service_access`/`service_access_write`
  with no implicit default (D35), machine stores and secrets (SYSTEM DPAPI), no agents (D17), service pipe quotas
  (TM-R25), admin-only prompt routing (the admin UI is frontend), `hostkey add --from-server`, machine-store
  UpdateHostKeys only under policy, fast user switching/RDP, `--elevated-view`, `EnableLinkedConnections` diag/fix,
  threat-model review (05 §4).

### M6 — backend parts

- ARM64 native host and libraries, Dokany ARM64; ARM32 per D5; SHA-NI/AES-NI/ARMv8 fast paths (never in
  `x86-ia32`); 02 §11 performance targets with write mode stated, `shelldrive diag bench`; pool tuning; nightly
  fuzzing; external crypto review pass 2 with findings closed (TST-33); Authenticode via SignPath Foundation or
  Certum OSS (D29); `x64-modern` CFG/CET checks; admin/CLI documentation; lab smoke green on every VM (04 §11.4).
- The ARM64/x86/x64 shell DLLs and the modern menu are frontend.

### M7 — backend parts (post-1.0)

- `zlib@openssh.com`, adaptive channel windows, specialized NIST reductions, symlink reparse points only if an
  official signed Dokany gains an FSCTL callback (D12). The modern menu fallback is frontend.

## Handing results back

Per milestone: green `tools\ci-local.ps1 -Clean`, an acceptance doc in `docs/dev/` (no local user names or
profile paths), notes in `docs/dev/m*-notes.md`, and every contract change the frontend depends on listed under a
"Contract changes" heading there.
