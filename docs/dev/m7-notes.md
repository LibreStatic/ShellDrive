# M7 notes: NIST fast reductions for P-256, P-384 and P-521

Scope: 01 section 2.8.2 (the M7 row of section 13 names "Solinas-specialized NIST reductions"). The scalar field
(group order n) stays on the Montgomery engine of bn.c.

## What changed

- Field elements of the three curves are normal-form limbs. `fe_mul` (src/sd_crypto/ec_p.c) is a schoolbook
  `sd_mp_mul` followed by a curve-specific reduction on 32-bit words, so the 32-bit and 64-bit limb builds run the
  same reduction code.
  - P-256: FIPS 186-4 D.2.3 vector sum s0 + 2 s1 + 2 s2 + s3 + s4 - s5 - s6 - s7 - s8, one pass, then 5p offset and
    conditional subtractions of 8p, 4p, 2p, p.
  - P-384: 2^384 = 2^128 + 2^96 - 2^32 + 1 (mod p), two folds with signed column sums, then one conditional
    subtraction of p.
  - P-521: 2^521 = 1 (mod p), one fold, one conditional subtraction of p.
- Constants: `gx`, `gy`, `b` in normal form (`k_<curve>_b|gx|gy` in pk_consts.inc, emitted by gen_pk_consts.py, which
  now writes them). The 32-bit word tables of p and its multiples are literal in ec_p.c.
- The Montgomery field path is kept as a test reference (`sd_ec_test_fe_mont`), next to a bit-serial reference
  (`sd_ec_test_fe_ref`, sd_mp_mod of the schoolbook product).

## Constant-time rules applied

- No multiplication in the reductions: coefficients are +-1 and +-2 (shifts), so no 64-bit multiply appears on
  32-bit targets (TM-R02). Column sums are signed 64-bit additions; carries use constant shifts.
- Table lookups in P-256 index by public constants only.
- Conditional subtraction (`w32_csub`) computes both results and selects with a mask.
- Loops with secret data carry `SD_CT_NO_VECTOR`. No per-product wiping: the callers already scrub the stack.
- The isacheck gate (`isacheck.ct_sd_crypto`) and the x86/x64 builds pass.

## Tests

`tests/unit/sd_crypto_pk/test_ec.c`, `ec_field_reduction_differential`: for each curve, every ordered pair of about
46 operands (0, 1, 2, p-1, p, p+1 for P-256/P-384, all ones, one all-ones word, boundary words 0/1/2^31/2^32-2/2^32-1,
random words; P-521 operands stay below 2^521) is checked against the bit-serial reference, and against the
Montgomery path where both operands are below p. P-256 and P-384 operands range over the full field length.
The existing RFC 5903, RFC 6979, Wycheproof ECDSA/ECDH, reference-point and CNG differential tests all pass unchanged.

Gate run (`tools/ci-local.ps1 -Presets x64-modern,x86-sse2 -ReleaseOnly -TestRegex 'crypto|isacheck'`): 15/15 and
28/28 passed.

## Benchmark (bench_pk_throughput, x64-modern Release, ops/s)

Three alternating runs per binary on a loaded development machine (the DH rows, which this change does not touch,
moved by about 1.5x between runs, so treat the absolute numbers as noisy). Medians:

| Case | Montgomery (before) | NIST reductions (after) |
|---|---|---|
| p-256 ecdh | ~2190 | ~1300 |
| p-256 ecdsa sign | ~1700 | ~1180 |
| p-256 ecdsa verify | ~1040 | ~570 |
| p-384 ecdh | ~815 | ~700 |
| p-384 ecdsa verify | ~390 | ~350 |
| p-521 ecdh | ~330 | ~390 |
| p-521 ecdsa verify | ~150 | ~175 |

Reading: on x64 the 4-limb CIOS multiplication is cheap, and the 32-bit word reductions (nine-word sums and up to four
masked subtractions of 9 words for P-256) cost more than the Montgomery steps they replace. P-521 gains from the
Mersenne-type fold. P-256 and P-384 are slower than before on this machine.

## Open items

- P-256 and P-384 regress on x64. Options: a reduction on native 64-bit words for 64-bit limbs (fewer and wider
  conditional subtractions), or fewer final subtraction stages (a tighter offset bound), or keep the Montgomery
  path for P-256/P-384 on x64 and use the NIST reductions only where they win. Decide with measurements on a quiet
  machine before 1.0.
- The x86 (32-bit limb) timings were not measured here.
