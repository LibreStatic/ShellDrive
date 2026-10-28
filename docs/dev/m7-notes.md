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
