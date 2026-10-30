# M7 notes: NIST fast reductions for P-256, P-384 and P-521

Scope: 01 section 2.8.2 (the M7 row of section 13 names "Solinas-specialized NIST reductions"). The scalar field
(group order n) stays on the Montgomery engine of bn.c.

## What exists

- `fe_mul_nist` (src/sd_crypto/ec_p.c): schoolbook `sd_mp_mul`, then a curve-specific reduction on 32-bit words
  (so 32-bit and 64-bit limb builds share the reduction code).
  - P-256: FIPS 186-4 D.2.3 vector sum s0 + 2 s1 + 2 s2 + s3 + s4 - s5 - s6 - s7 - s8, one pass, then a 5p offset and
    conditional subtractions of 8p, 4p, 2p, p.
  - P-384: 2^384 = 2^128 + 2^96 - 2^32 + 1 (mod p), two folds with signed column sums, then one subtraction of p.
  - P-521: 2^521 = 1 (mod p), one fold, one subtraction of p.
- `fe_mul_mont`: the previous path, CIOS `sd_mp_montmul` on Montgomery-form elements. Kept in every build.
- Per-curve selection, fixed at compile time in ec_p.c (`EC_NIST_P256`, `EC_NIST_P384`, `EC_NIST_P521`, one value per
  limb size). A curve uses one representation throughout: NIST curves hold normal-form elements; Montgomery curves
  hold Montgomery-form elements, converted at decode and at the affine output. The choice is a public table entry
  (`ec_curve.nist`), not secret data.

Selected (from the measurements below):

| Curve | 64-bit limbs (x64) | 32-bit limbs (x86) |
|---|---|---|
| P-256 | Montgomery (`EC_NIST_P256 0`) | Montgomery (`0`) |
| P-384 | Montgomery (`EC_NIST_P384 0`) | Montgomery (`0`) |
| P-521 | NIST fold (`EC_NIST_P521 1`) | NIST fold (`1`) |

## Constant-time rules

- No multiplication in the reductions: coefficients are +-1 and +-2 (shifts), so no 64-bit multiply appears on
  32-bit targets (TM-R02). Column sums are signed 64-bit additions; carries use constant shifts.
- Table lookups in P-256 index by public constants only.
- Conditional subtraction (`w32_csub`) computes both results and selects with a mask.
- Loops with secret data carry `SD_CT_NO_VECTOR`. No per-product wiping: the callers scrub the stack.
- The selection branch (`if (c->nist)`) tests a public table entry.

## Tests

`tests/unit/sd_crypto_pk/test_ec.c`, `ec_field_reduction_differential`, for each curve on the build's limb size:
- about 46 operands per curve (0, 1, 2, p-1, p, p+1 for P-256/P-384, all ones, one all-ones word, boundary words
  0/1/2^31/2^32-2/2^32-1, random words; P-521 operands stay below 2^521; P-256/P-384 span the full field length);
- every ordered pair: the NIST product (`sd_ec_test_fe_nist`) against the bit-serial reference (`sd_mp_mod` of the
  schoolbook product);
- for pairs below p: the Montgomery product (`sd_ec_test_fe_mont`) and the selected path as the point code uses it
  (`sd_ec_test_fe_sel`), against the same reference.

So both paths are checked for every curve on both limb sizes, whichever is selected. The RFC 5903, RFC 6979,
Wycheproof ECDSA/ECDH, reference-point and CNG tests pass with the selection.

Gate run (`tools/ci-local.ps1 -Presets x64-modern,x86-sse2 -ReleaseOnly -NoFixture -AllowSkip -Jobs 4 -TestRegex
'crypto|isacheck'`): x64-modern 15/15, x86-sse2 28/28, `isacheck.ct_sd_crypto` included and passing.

## Benchmark (bench_pk_throughput, ops/s)

Method: three alternating runs per binary, median per row. The binaries differ only in the selection (all-Montgomery
"before", all-NIST "after"). The development machine was loaded during the runs (the DH rows, which this change does
not touch, moved by about 1.5x between runs), so the absolute numbers are noisy. The ECDSA/ECDH rows below are the
ones that matter.

x64-modern Release (64-bit limbs):

| Case | Montgomery (before) | NIST (after) |
|---|---|---|
| p-256 ecdsa sign | 1700 | 1180 |
| p-256 ecdsa verify | 1040 | 570 |
| p-256 ecdh | 2190 | 1300 |
| p-384 ecdsa sign | 780 | 620 |
| p-384 ecdsa verify | 400 | 350 |
| p-384 ecdh | 815 | 700 |
| p-521 ecdsa sign | 320 | 380 |
| p-521 ecdsa verify | 150 | 160 |
| p-521 ecdh | 330 | 390 |

x86-sse2 Release (32-bit limbs):

| Case | Montgomery (before) | NIST (after) |
|---|---|---|
| p-256 ecdsa sign | 763 | 641 |
| p-256 ecdsa verify | 428 | 351 |
| p-256 ecdh | 839 | 710 |
| p-384 ecdsa sign | 307 | 301 |
| p-384 ecdsa verify | 159 | 152 |
| p-384 ecdh | 321 | 311 |
| p-521 ecdsa sign | 124 | 166 |
| p-521 ecdsa verify | 65 | 89 |
| p-521 ecdh | 132 | 166 |

The x64 "after" numbers for P-256 and P-384 come from the first full-NIST build; the x64 table was not re-measured
after the selection change (its P-256/P-384 entries use Montgomery in the final build, so they match the
"before" column). The x86 P-384 rows are within noise of each other.

## Open items

- The P-256 and P-384 NIST reductions do not beat Montgomery on either limb size here. A native 64-bit-word reduction
  for 64-bit limbs (fewer and wider conditional subtractions), or a tighter offset bound (fewer final subtraction
  stages), might change that. Revisit on a quiet machine before 1.0; the selection table is the only thing to change.
- Re-measure all rows on a quiet machine before 1.0.

# M7 notes: zlib@openssh.com (01 section 4.7, decisions D6)

## What exists

- `src/sd_ssh/ssh_zlib.c` (+ `ssh_zlib.h`): own RFC 1951 inflate/deflate and RFC 1950 framing. No third-party code.
  - Decoder: complete for all three block types, dynamic Huffman included. Code sets follow zlib's rules (no
    over-subscribed or incomplete codes except a single one-bit code, no distance codes 30/31, no length codes
    286/287, every distance inside the history). Resumable: a decision that lacks bits is undone and the unread
    bytes (at most 512, one dynamic header) are carried to the next packet together with the block state.
  - Encoder: greedy LZ77, hash chains (3-byte hash, 8 KiB heads, 32 KiB previous links, 32 chain steps), fixed
    Huffman codes. The history spans packets.
  - Stream shape, as OpenSSH's deflate()/inflate() use it: the zlib header once, then per packet a non-final block
    followed by an empty static block (partial flush). Up to 7 bits of that empty block may wait for the next
    packet; the decoder carries them.
- Transport (`packet.c`): `ssh_dir.comp` holds the codec of one direction. Compression starts with the packets after
  USERAUTH_SUCCESS (`ssh_dir_comp_start`, called from `auth.c`), in both directions. The payload is compressed
  before padding and encryption and inflated after the MAC check. The codec state survives re-keys; a re-key that
  negotiates `none` ends it.
- Negotiation (`negotiate.c`, `kex.c`): with `SD_SSH_CFG_COMPRESS` the compression list is
  `zlib@openssh.com,none`, otherwise `none`. Re-keys reuse the list built at the first KEXINIT.
- Profile key `connection.compression = yes|no`, default `no` (`sd_config`, `profile_m2.c`), copied by `sd_mount`
  into `SD_SSH_CFG_COMPRESS`. Also in 03's schema table (`connection.compression`).

## Limits

- Decompressed payload per packet: 256 KiB (`SSH_ZLIB_PACKET_MAX`, the zip-bomb guard of 01 section 4.7). A larger
  output, a bad stream, or any input after the end of a stream fails the connection with a protocol error.
- Compressed size and the whole-session expansion are not limited beyond the per-packet cap. The inbound packet
  limit (256 KiB, `SSH_MAX_PACKET_LEN`) still applies to the compressed bytes.
- Memory per compressing direction: about 450 KiB (the 288 KiB history, the hash tables). Per inflating direction:
  about 35 KiB and a 256 KiB output buffer.
- Speed: the decoder reads Huffman codes bit by bit; no table lookup yet.

## Decisions taken here

- Negotiation order: 01 section 4.3 listed `none, zlib@openssh.com`. The client list decides the choice (RFC 4253
  7.1), so with `none` first zlib could never be selected. The list therefore puts zlib first when the profile
  enables compression, which is what OpenSSH does with `Compression yes`. Otherwise `none` alone is offered.
- Profile key name: 01 and 03 did not name it. `connection.compression` (`yes|no`, default `no`) follows the
  existing `connection.*` keys.
- The packet-level API returns zero output for a call that ends inside a symbol; the SSH layer treats an empty
  payload as a protocol error, as it did before.

## Tests

- `unit.zlib` (`tests/unit/sd_ssh/test_zlib.c`): reference streams from zlib (hello world, Z_FIXED, stored, a
  95-byte dynamic-Huffman stream), a hand-built fixed block (valid, distance before the start, reserved BTYPE),
  truncation at every length, trailer and header bit flips, stored LEN/NLEN mismatch, a three-packet
  partial-flush stream from the reference zlib (decoded packet by packet), a dynamic stream fed one byte at a
  time, encoder round trips (40 packets, then the finish and an RFC 1950 one-shot decode), split feeding of an
  encoder stream in 1 to 9 byte pieces, the per-packet output limit (256 KiB of zeros refused at 64 KiB, accepted
  at 256 KiB), and size checks.
- `unit.ssh` (`ssh_packet_zlib_delayed` in `test_packet.c`): plain packets before the switch, compressed packets
  after it in both directions, sequence numbers, and the switch back to `none` on a re-key.
- `interop.zlib` (`interop_zlib_delayed` in `test_interop.c`, label `interop`, resource lock
  `wsl_sshd_fixture`, exit 77 without the fixture): negotiates `zlib@openssh.com` both ways against the WSL OpenSSH
  (default `Compression delayed`), runs an exec and a 300 KB output (several packets, both directions compressed).
- `fuzz.inflate` (`tests/fuzz/harness/fuzz_inflate.c`, corpus `tests/fuzz/corpus/inflate/`): whole streams through
  the one-shot path, and the same bytes through the packet decoder in pieces of 1 to 61 bytes.

## Open items

- The profile key is not mapped from OpenSSH `ssh_config` imports (`Compression yes`); import keeps the default.
- No `Compression` line in the fixture's `sshd_config`; the default `delayed` is relied on.
- Bit-by-bit Huffman decoding: measure against the 256 KiB output budget before any table-driven version.
- Zero-length (or flush-only) packets are not produced by the encoder and are refused by the decoder.

# M7 notes: adaptive channel windows (01 section 4.8)

## What exists

- `src/sd_ssh/channel_window.h` / `channel_window.c`: the receive window of one channel as a pure state machine.
  No socket and no clock: the caller passes the time in milliseconds, so tests run on a virtual clock.
  `ssh_win_on_data` accounts peer data and returns a growth grant; `ssh_win_on_consumed` returns the WINDOW_ADJUST
  amount once the consumer has freed half of the target.
- `src/sd_ssh/channel.c`: each channel carries an `ssh_win` (`ch->win`). CHANNEL_DATA and EXTENDED_DATA are checked
  against `win.allow`, a growth grant is sent as WINDOW_ADJUST while the channel is open and not closing, and
  `sd_ssh_channel_consumed` sends the half-window adjusts. The open message still advertises the 2 MiB initial window.
- `SSH_CH_ADAPTIVE` (`conn_internal.h`) is 1. Set it to 0 to get the fixed 2 MiB window back. The module keeps the
  same accounting in both modes.

## Algorithm and limits

- Initial allowance and floor: 2 MiB (`SSH_WIN_INITIAL`). The target never shrinks, and the allowance only grows through
  grants and consumption, so the peer is never told a smaller window than it may already use.
- Cap per channel: 16 MiB (`SSH_WIN_MAX`), doubling steps.
- Cap per connection: 32 MiB summed over the targets of the channels of one connection (`SSH_WIN_SESSION_CAP`). The
  value is ours: 01 4.8 gives no per-session figure. Growth is refused beyond it. The sum is computed from
  `c->ch[]` when a growth is decided, so no bookkeeping can drift.
- RTT: `srtt` from section 4.6 when a sample exists, otherwise `SSH_WIN_RTT_DEFAULT_MS` (500 ms). Ours, not in the doc.
- WINDOW_ADJUST threshold: half of the current target (it was half of the fixed 2 MiB).

## Growth trigger: deviation from 01 4.8 (read this before changing it)

01 4.8 says: double the window when the sender stalled (the allowance was exhausted) twice within one RTT estimate.
With `sd_sftp` consuming every byte at once, the receiver sends WINDOW_ADJUST as soon as half of the target is freed.
The allowance then never falls below half of the target, so it never reaches zero and the stated trigger can never
fire. Growth would never happen for SFTP.

The implementation uses the bandwidth-delay equivalent instead:

- An RTT epoch is one RTT estimate long. Peer bytes received in an epoch are summed.
- An epoch in which the peer delivered at least half the target was window-limited (throughput x RTT is close to the
  window). Two such epochs in a row double the target (`streak` in `ssh_win`).
- An epoch with less data resets the streak.

Recommended doc change (not made here, the task limits 01 edits to the status line): restate 4.8 with this trigger, or
keep the stall wording and have the consumer hold back credit to make a stall observable. The first is the honest
option.

## Tests

- `unit.ssh_window` (`tests/unit/sd_ssh/test_window.c`, sd-test-ssh_window.exe, no network). The link is simulated:
  a virtual clock advances 1 ms per step, the peer obeys its advertised allowance, data and WINDOW_ADJUST arrive after a
  fixed one-way delay, and the consumer frees everything at once. Every step checks the invariants: data never
  exceeds the allowance, `allow == granted - received`, the target never shrinks and stays within 2 MiB..16 MiB, and
  the session sum stays within 32 MiB.
  - unit level: half-target credit threshold, overrun refused, one window-limited epoch does not grow, the fixed mode
    never changes.
  - simulated transport: fixed window stays at 2 MiB on a high-BDP link (10 MB/s, RTT 200 ms); the adaptive window grows
    and finishes no later (simulated time) than the fixed one; a 250 ms link saturates at 16 MiB and not beyond; a
    low-RTT link (RTT 4 ms) never grows; three channels on one connection respect the 32 MiB budget; throughput that
    alternates between a trickle and a burst keeps the protocol invariants.
- Simulated times are model values, not wall-clock measurements. No timing is asserted against the real machine.
- Benchmarks: `bench.vfs_pool` and the sftp throughput tests were not run for this change. Before/after numbers are not
  recorded, since the real window effect needs a WAN-like link that the lab does not have.

## Open items

- Not wired to a profile key: the fixed window exists as the `SSH_CH_ADAPTIVE` switch only. Add a `connection.*` setting
  if a user-visible control is wanted.
- The 32 MiB session budget and the 500 ms default RTT are our values, to be confirmed in 01 4.8.
- The growth trigger deviates from the doc (see above). Decide the doc wording before 1.0.
- No WSL sshd interop test for growth yet: that needs a transfer large enough to fill a 2 MiB window on the fixture.
  The gate ran with `-NoFixture`.
