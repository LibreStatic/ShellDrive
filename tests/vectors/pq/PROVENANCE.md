# Test vector provenance (sd_crypto M2 symmetric / post-quantum, area "pq")

Everything in this directory is test **data** or our own test scripts, never shipped code
(decisions.md D1, 01 §2.5). It is read at run time by `sd-test-crypto_pq` (`tests/unit/sd_crypto_pq`).
Downloaded on 2026-10-25. The `.txt` files are produced by our `convert.py` from the downloads listed
here (`python -I tests/vectors/pq/convert.py <download dir> tests/vectors/pq`); each starts with a
comment line naming its source and field order.

## NIST ACVP (ML-KEM, FIPS 203)

- Source: https://github.com/usnistgov/ACVP-Server, `gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json`
  and `gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json`, branch `master` at commit
  `975de31eb83d87039ec88934fdc47d8c312b892d`. Public domain (US Government work).
- Only the ML-KEM-768 groups are kept: `mlkem768_acvp_keygen.txt` (25), `mlkem768_acvp_encap.txt` (25),
  `mlkem768_acvp_decap.txt` (10, including modified ciphertexts = implicit rejection),
  `mlkem768_acvp_keycheck.txt` (10 encapsulation-key modulus checks, 10 decapsulation-key hash checks).

## Project Wycheproof (ML-KEM-768)

- Source: https://github.com/C2SP/wycheproof, `testvectors_v1/`, commit
  `d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9` (same commit as `../wycheproof/`). License: Apache-2.0.
- `mlkem_768_test.json` -> `wycheproof_mlkem768.txt` (strcmp, implicit rejection, malformed lengths),
  `mlkem_768_encaps_test.json` -> `wycheproof_mlkem768_encaps.txt` (modulus overflow / not reduced keys),
  `mlkem_768_keygen_seed_test.json` -> `wycheproof_mlkem768_keygen.txt`,
  `mlkem_768_semi_expanded_decaps_test.json` -> `wycheproof_mlkem768_decaps.txt` (corrupted dk hash / ek).
  Cases with a wrong seed, key or ciphertext *length* cannot be passed to the fixed-size API and are
  counted as rejected by the caller; the test checks Wycheproof marks them invalid.
- `aes_cbc_pkcs5_test.json` is not used: it tests PKCS#5 padding, which SSH CBC does not have.

## NIST CAVP (SHA-3, SHAKE, AES-CBC, TDES)

- Source: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/
  `sha3/sha-3bytetestvectors.zip`, `sha3/shakebytetestvectors.zip`, `aes/KAT_AES.zip`, `aes/aesmmt.zip`,
  `des/KAT_TDES.zip`, `des/tdesmmt.zip`. Public domain (US Government work).
- `sha3_256_short.txt`, `sha3_512_short.txt`: SHA3_256ShortMsg.rsp, SHA3_512ShortMsg.rsp (all cases).
- `sha3_256_monte.txt`, `sha3_512_monte.txt`: SHA3_*Monte.rsp (seed + 100 checkpoints); `convert.py`
  checks the Monte procedure against Python's `hashlib` before writing.
- `shake128.txt`, `shake256.txt`: SHAKE*ShortMsg.rsp (all) + every 5th case of SHAKE*VariableOut.rsp
  (to keep the data small). LongMsg files are not included; `sha3_random.txt` covers long inputs.
- `aes_cbc_cavp.txt`: CBCGFSbox, CBCKeySbox and CBCMMT for 128/192/256-bit keys.
- `tdes_cavp.txt`: TCBC invperm/permop/subtab/varkey/vartext KATs (single key used as K1 = K2 = K3) and
  TCBCMMT2/3, TECBMMT2/3 (keying options 2 and 1).

## BLAKE2b

- `blake2b_kat.txt` from https://github.com/BLAKE2/BLAKE2 `testvectors/blake2b-kat.txt` (branch `master`,
  2026-10-25; CC0 / public domain dedication of the BLAKE2 authors): 256 keyed cases, 64-byte key and output.
- RFC 7693 Appendix A (BLAKE2b-512("abc")) and RFC 9106 section 5 (Argon2d/i/id tags) are embedded in
  `tests/unit/sd_crypto_pq/test_kdf.c`.

## Our own references (independent cross-checks)

- `sha3_random.txt`: written by `sha3_random.py` with Python 3.14 `hashlib` (an independent Keccak
  implementation) for lengths around the rate boundaries.
  `python -I tests/vectors/pq/sha3_random.py tests/vectors/pq/sha3_random.txt`
- `ed25519_ppk3_argon2id.ppk`, `ed25519_ppk3_argon2i.ppk`, `ed25519_ppk3_argon2d.ppk`: PuTTY PPK v3
  files (aes256-cbc, passphrase `correct horse battery staple`, part of the fixture and not a secret).
  `puttygen` is not installed on the build machine (WSL Ubuntu 24.04 has no `putty-tools`), so they are
  written by `ppk_fixture.py`, our pure-Python reference of the PuTTY manual Appendix C, RFC 9106 Argon2
  (self-checked against the RFC 9106 tags) and FIPS 197 AES (self-checked against C.3), from an
  Ed25519 key generated with OpenSSH_for_Windows_9.5p2:
  `ssh-keygen -t ed25519 -N "" -C "sd_crypto ppk fixture" -f <tmp>/k`, then
  `python -I tests/vectors/pq/ppk_fixture.py <tmp>/k tests/vectors/pq`.
  The private blob is `mpint` of the 32-byte Ed25519 private key read as a little-endian integer, as we
  understand PuTTY's encoding; a puttygen-generated fixture should replace these when puttygen is
  available.
