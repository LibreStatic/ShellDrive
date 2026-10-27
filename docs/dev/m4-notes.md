# M4 notes

## ADMX and reproducibility

Branch `wip/m4-admx`. Design references: 03 §3.5 (policy values), 04 §8.4 and §8.6 (ADMX/ADML, localization),
04 §12.2 (reproducible builds).

### Policy table and template

- `res/policy/policies.txt` is the single source of the 21 policy values (03 §3.5), with `@key
  Software\Policies\LibreStatic\ShellDrive`.
- `tools/sd-admxgen` (build-time C, no third-party code) generates into `generated/policy/`:
  `ShellDrive.admx`, `en-US`, `es-ES`, `fr-FR`, `pt-BR`, `it-IT`, `de-DE` `ShellDrive.adml`, `sd_policy_ids.h`
  and `sd_policy_table.h`. The output has no timestamps or absolute paths.
- Texts come from `l10n/policy/<lang>.po` (domain `policy`, six locales, English in msgid of `en.po`). `sdl10n --check
  --domain l10n/policy` (ctest `l10n.policy_catalogs_complete`) checks completeness, register and plurals. Keys are
  lower case (`policy.<name>.title`, `.explain`, `.label`, `.opt.<value>`), because sdl10n accepts `[a-z0-9_.-]`.
- Deviation: the ADML is produced by `sd-admxgen` and not by `sdl10n` (04 §8.6, C41 say `sdl10n`). `sdl10n` still
  owns the completeness rules for the domain. Owners of the ADML format should confirm this.
- The table has no decimal policy. The generator, the ADMX and the checks support `decimal` (min and max); unit tests
  cover it, and the first decimal policy needs only a table line and six translations.
- `supportedOn`: `SD_SUPPORTED_XP` (Windows XP SP3 or later) for 20 policies, `SD_SUPPORTED_WIN11` for
  `DisableModernContextMenu`.
- Enum types: `UpdateHostKeys`, `LegacyAlgorithms`, `LogPrivacy` are REG_DWORD; `UILanguage` (en, es, fr, pt-BR, it, de)
  and `UpdateChannel` (stable, beta) are REG_SZ, as the readers expect.

### Readers

- `src/sd_policy` (`sd_policy_get_dword`, `sd_policy_get_sz`) reads HKLM then HKCU with the generated names and
  types. A value of the wrong registry type reads as absent. Nothing writes the registry.
- `src/sd_l10n` (UILanguage) and `apps/shelldrive-host/explorer_data.c` (DisableNetworkLocations) use it. The
  `UILanguage` fallback changed slightly: an HKLM value of the right type is used even when it names an unknown language,
  so HKCU is no longer consulted in that case (the old code fell back to HKCU only when HKLM was absent or unparsable).
- `tests/policy/check-raw-reads.ps1` (ctest `policy.no_raw_reads`) fails when a source outside `src/sd_policy` contains
  the key path or a `L"<value name>"` literal.

### Checks

- `tests/policy/check-admx.ps1` (ctest `policy.admx_structure`): XML well-formedness, the target namespace, the policies
  against the table (name order, class, key, valueName, supportedOn, enum items and their value types, text maxLength,
  decimal range), every category, definition, presentation and `$(string.*)` reference, unique ids and names, the six
  culture folders and the strings and presentations of each ADML. It does not validate against the PolicyDefinitions
  schema, which is not available offline.
- `unit.admxgen` (`tools/sd-admxgen/test_admxgen.c`): XML and C escaping, table validation (every rejected form), PO
  parsing (continuation lines, escapes, fuzzy entries, plurals), enum and decimal and boolean emission, the headers,
  and a full run over the real table and catalogs (21 policies).
- `unit.policy` (`tests/unit/sd_policy`): the table is complete and its kinds match the readers; type mismatches
  read as absent.

### Reproducible builds

- Flags: `/Brepro` (compile and link), `/PDBALTPATH:<pdb name>`, `/Zi`, `/OPT:REF /OPT:ICF` (Release) were already in
  `cmake/SdOptions.cmake`, and nothing was added. No shipping source uses `__DATE__`, `__TIME__`, `__TIMESTAMP__` or
  `__FILE__`.
- `tools/check-repro.ps1 -Preset <preset> [-Config Release] [-KeepBuilds]` builds the preset twice (`build\repro-a`,
  `build\repro-b`) from one source tree mapped with `subst` to a free drive letter, and compares the PEs (`bin\*.exe`,
  `bin\*.dll`), the static libraries (`lib\*.lib`) and `generated\policy\**` byte for byte. PDBs are not compared.
- ctest `repro.x64-modern` and `repro.x86-ia32` (label `repro`). They are excluded from the default run in
  `tools/ci-local.ps1` (`-LE 'matrix|bench|repro'`) and from the commands in this file.

#### Results

RESULTS_PLACEHOLDER

### Build and test commands

```
cmake --preset x64-modern
cmake --build --preset x64-modern-debug
ctest --preset x64-modern-debug -LE "matrix|bench|interop|repro"
powershell -ExecutionPolicy Bypass -File tools\check-repro.ps1 -Preset x64-modern
powershell -ExecutionPolicy Bypass -File tools\check-repro.ps1 -Preset x86-ia32
```
