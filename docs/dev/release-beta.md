# Publishing a beta pre-release

Beta builds are public GitHub pre-releases of this repository before crypto review pass 1 and before
Authenticode signing (decision D48): the gates `review-pass1` and `authenticode` may be waived in the release
gates record, every other gate of `docs/design/04-build-install-update.md` §12.3 still applies. Every beta
release carries `SHA256SUMS` + `SHA256SUMS.sig` (release-beta key), the "not yet externally reviewed" notice on
the setup's welcome page (`SD_SETUP_PRERELEASE_NOTICE`, on by default for the beta channel) and in the release
notes, and the key fingerprints in `README.md`. The tooling is `tools/release/package-beta.ps1`; the stable
channel keeps the two offline sessions (D42) and is not automated yet (`docs/dev/m4-notes.md`).

## One-time setup in GitHub

1. **Environment `beta-signing`** (Settings → Environments): required reviewer = the maintainer. It gates the two
   jobs that touch the seed or publish (`sign-beta`, `publish-beta`).
2. **Secret `RELEASE_BETA_SEED`** in that environment: the content of `release-beta.seed` (64 hex digits) from
   the key ceremony (`docs/dev/key-ceremony.md` §5 — the seed's single transfer off the secret media). Keep only
   the media copies afterwards.
3. **Commit `installer/keys/`** produced by the ceremony: `roots.txt`, `keyset.txt` (they compile into every
   binary; without them nothing verifies). Paste `fingerprints.md` into `README.md` as the "Release keys" section.
4. **Commit `installer/keys/release-gates.txt`** for the version in the release PR: channel `beta`, the version,
   the commit, every gate of the beta row of the §12.3 table (`ci-local` and `lab` pass; `review-pass1` and
   `authenticode` `waived` with a note), `approved` last. `sd-release gates check` refuses anything else.

## CI flow

Run the `release` workflow (`workflow_dispatch`), inputs `version` (must match `VERSION`) and `channel: beta`
(the default). The jobs run in this order; nothing is published unless all of them pass:

| Job | What it does |
|---|---|
| `verify-gates` | the input channel is `beta` or `stable`; `VERSION` matches the input |
| `build` | the six-preset matrix of §11.2 (tests, repro check), unsigned binaries |
| `package` | downloads each pinned Dokany file fresh from the lock's `url-upstream` (never a cache, TM-R39), then `package-beta.ps1` **without** `-Seed`: it verifies the files against `installer/dokany/dokany.lock` (`sd-release dokany verify`, TM-R23), builds fresh `-DSD_SETUP_CHANNEL=beta` trees, and produces the unsigned setup EXEs, the MSIs and `payload-tables.txt` |
| `check-gates` | `sd-release gates check` on the committed record (no secrets) |
| `sign-beta` | in `beta-signing`: writes `RELEASE_BETA_SEED` to a temp file, runs `package-beta.ps1 -Seed` (signs the payload tables, reattaches them as `PAYLOAD_SIG` with the `DOKANY_X64/X86` resources, builds `SHA256SUMS` + `SHA256SUMS.sig` and the signed beta manifest, verifies everything with `sd-release verify`), deletes the seed file |
| `publish-beta` | in `beta-signing`, the only job with `contents: write`: `gh release create v<version>-beta --prerelease --notes-file release-notes.md` with all files |

## Local flow (the maintainer, same tool)

```text
powershell -NoProfile -ExecutionPolicy Bypass -File tools\release\package-beta.ps1 ^
  -Version 0.1.0 -Commit <40-hex commit> -DokanyDir <folder with the upstream Dokany files> ^
  -Seed <release-beta.seed> [-Gates installer\keys\release-gates.txt] [-OutDir dist\beta-0.1.0]
```

Without `-Seed` the script stops after the unsigned artifacts and `payload-tables.txt` (the setups refuse to
run: no `PAYLOAD_SIG`, TM-R38), so the signing can happen on the offline machine:

```text
sd-release sign --kind payload --seed release-beta.seed --in <table> --out <sig> --sig-only ^
  --gates release-gates.txt --version 0.1.0 --commit <C>
```

Re-running with `-Seed` attaches those signatures and finishes the release. The script never downloads: point
`-DokanyDir` at the lock-verified upstream files. What a beta release ships today, and what is skipped with a
clear message (nothing is faked):

| Artifact | State |
|---|---|
| Setup EXEs | `x86-ia32` (carries `DOKANY_X64` + `DOKANY_X86`), `arm64`, `arm32` — the payload targets of those presets |
| Setup EXEs x64 / x86-sse2 | skipped: no payload target in those presets; the universal EXE assembly is release-pipeline work not in the repository yet |
| Per-machine MSIs | all six flavours, with WiX 3.14; without WiX every MSI is skipped |
| Dokany in the stub | embedded but not chained yet: nothing calls `sd_setup_dokany_run`, so a beta install uses Dokany when already installed and otherwise continues with WebDAV only |
| ARM64 Dokany | none: the lock pins no ARM64 installer upstream (§7.1); no ARM32 one exists |
