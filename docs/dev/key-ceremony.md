# Key ceremony (first keyset)

How to run the first key ceremony and publish its results. The ceremony creates the two offline root keys
and the `release-beta` release key, and produces the signed `keyset.txt` (format version 1) that future
builds compile in. Background: `docs/design/04-build-install-update.md` §9.3 (key roles, keyset format,
rotation and revocation) and §12.3 (release process; the ceremony is step 11). Per D48, beta builds are
public GitHub pre-releases before crypto review pass 1 and before Authenticode signing, so the first
keyset needs only the beta release key; a `release-stable` key can be added later by a keyset rotation.

Tool: `tools/release/key-ceremony.ps1` (Windows PowerShell 5.1). It refuses to run on a networked machine,
on the system drive, over existing seeds or existing outputs, and it never prints or copies a seed.

## What it produces

Public (bring to the network machine, commit later):

| File | Content |
|---|---|
| `roots.txt` | comment header, then two `root <key-id> <pubkey-base64>` lines |
| `keyset.txt` | keyset version 1: the `release-beta` key (valid 1 year from the ceremony date) and both roots, with one `sig ed25519 ...` line per root (a keyset that sets root keys must be signed by both roots, §9.3) |
| `fingerprints.md` | the "Release keys" section for `README.md`: role, key id and full public key of each key |

Secret (stays on the removable media named by `-SecretDir`, never on a networked machine):
`root-a.seed`, `root-b.seed`, `release-beta.seed`. A seed file holds 32 bytes as 64 hex digits and is
written in clear text by the tool (`docs/dev/m4-notes.md`, "Signing tool") — that is why the machine and
the media must stay offline. The key id is the first 8 bytes of SHA-256 of the public key, printed by
`sd-updsign pubkey` as 16 hex digits.

## 1. Prepare the offline machine

1. Use a dedicated machine that never connects to any network. The script checks every network adapter and
   refuses while any reports *Up* (`Get-NetAdapter`; an `ipconfig` scan on Windows 7). Disable virtual
   switches too — Hyper-V/WSL adapters report *Up* even without a cable.
2. Build the tools on the networked machine (`build/<preset>/bin/<config>/`), record their SHA-256
   (`Get-FileHash -Algorithm SHA256 sd-updsign.exe, sd-release.exe`), and copy both EXEs to offline media.
3. On the offline machine, verify the copied EXE hashes match what the build machine recorded, and compare
   them again with what the script prints at start.

## 2. Run the script

Have ready: `-ToolsDir` (the two EXEs), `-SecretDir` (an **empty** folder on removable media),
`-PublicDir` (an empty output folder), and optionally `-Date` (UTC `YYYY-MM-DD`, default: today).

```text
powershell -NoProfile -ExecutionPolicy Bypass -File key-ceremony.ps1 ^
  -ToolsDir E:\tools -SecretDir E:\keys -PublicDir E:\public [-Date 2026-11-01]
```

(The `^` continues the line in cmd.exe; on a PowerShell prompt, put the command on one line.)

In order, it: checks the environment refusals; prints the tools' SHA-256; generates `root-a`, `root-b` and
`release-beta` (`sd-updsign keygen`), re-deriving each key id from SHA-256 and cross-checking both tools
(`sd-release pubkey`); writes the keyset body (version 1, product `com.librestatic.shelldrive`, the beta
key line and the two root lines); signs it with both roots (`sd-updsign sign-keyset --root ... --root ...`);
verifies both signatures (`sd-release verify --kind keyset`, once per root); writes `roots.txt` and
`fingerprints.md`; prints the SHA-256 of every public file.

If it aborts: fix the cause, **empty `-SecretDir`**, and start over. A half-generated set of keys must
never survive, and the script refuses to run over existing seeds to enforce that.

## 3. Secure the secret media

1. Copy the three `.seed` files to a second set of encrypted media. You now have two copies; store them in
   two separate locations (§9.3: the roots live on two separate encrypted media in two locations, offline
   only, never in CI, never on a networked machine).
2. Label the media with the three public key ids (public information, no secret on the label).
3. From now on the media is only ever mounted on the offline machine, and only for keyset ceremonies.

## 4. Publish

1. Bring **only** `-PublicDir` to the network machine (the seeds never leave the media).
2. Compare the SHA-256 of the three files against what the script printed.
3. Commit `installer/keys/roots.txt` and `installer/keys/keyset.txt`. The release build compiles the two
   root public keys and the current keyset into every binary and the setup stub (§9.3); until they exist
   every update verification fails closed (`docs/dev/m4-notes.md`).
4. Paste `fingerprints.md` into `README.md` as the **"Release keys"** section (TM-R38: key fingerprints in
   the README).

## 5. The release-beta seed and the later signing sessions

- Store `release-beta.seed` as the secret of the protected GitHub environment `beta-signing` (required
  reviewer: the maintainer). This is the seed's single transfer off the secret media; delete any working
  copy after the import and keep only the media copies. How the release workflow and
  `tools/release/package-beta.ps1` use that seed for a beta pre-release: `docs/dev/release-beta.md`.
- For beta pre-releases (D48) the release workflow performs the equivalent of the two offline signing
  sessions (§12.3 steps 5 and 7, D42) with that key behind the environment, and the maintainer approves the
  run: payload tables first (`sd-release sign --kind payload`), then `SHA256SUMS` + `SHA256SUMS.sig` and
  the signed manifest (`sd-release sign --kind sums`, `--kind manifest`) once the draft release exists.
  There is no manual offline session for beta; `sd-release verify` runs in the workflow against the
  release artifacts before anything is published.
- When stable releases start, rotate in a `release-stable` key (below). From then on, steps 5 and 7 for
  stable are the maintainer's manual offline sessions on this machine: `sd-release session` lists the
  hashes to compare (`SESSION.txt`, D42), `sd-release verify` checks the payloads/manifest against the
  rebuilt artifacts, and `sd-release sign --gates <release-gates.txt> --version <V> --commit <C>` signs
  (the gates record is mandatory there, which is why keysets are signed with `sd-updsign sign-keyset`
  instead — the ceremony is step 11, outside any release).

## 6. Rotation, revocation, expiry (§9.3)

- **Release key rotation:** sign a root keyset version `n+1` that adds the new release key; releases signed
  with it name `keyset n+1`; a later keyset drops the old key. Changing release keys needs a signature by
  **one** root ("either root"); the roots themselves are untouched.
- **Revocation of a release key** (e.g. a leaked beta key): a root-signed keyset with a
  `revoke <key-id> <reason-id>` line; clients refuse the key from then on and it cannot sign keysets back.
- **Root change:** a keyset with `root <key-id> <pubkey>` lines, signed by **both** current roots (the
  parser refuses anything less — `update_verify.c`, "rotation needs both current roots"). Loss of both
  roots cannot be recovered remotely: it needs a manual reinstall with new binaries.
- **Expiry:** the beta key from this ceremony is valid until the ceremony date + 1 year (the `key` line's
  second date). Rotate it before then with a new root-signed keyset.
- **Freshness re-signing** (TM-R36, every 14 days) uses release keys only; roots are touched only for
  keyset changes like these.
