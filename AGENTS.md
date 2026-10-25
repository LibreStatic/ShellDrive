# Project rules

These rules apply to the whole repository. Component notes live next to the code (`<component>/AGENTS.md`).

## Language
- Commit messages, PR titles and descriptions, branch names, code identifiers, code comments, test names,
  log messages and machine-readable output (JSON diagnostics, protocol strings, event log payloads) are
  in English, whatever language the prompt uses.
- Documentation (`README.md`, `docs/`, `AGENTS.md` files, guides, checklists) is written in one language:
  English. Do not add translated copies of documents or prose in another language.
- User-facing text is written in English first and fully localized into English, Spanish, French,
  Portuguese, Italian and German. A string is not done until every locale has it. Keep one register per
  language across every component: Spanish with Rioplatense voseo ("Elegí"), Brazilian Portuguese, French
  with "vous", German and Italian with the informal imperative.
  - This covers the CLI (`--help`, user-facing errors, printed summaries), the tray app, the main window,
    Explorer integration, the installer (EXE and MSI) and the service's user-visible messages. Logs and
    JSON stay in English.
  - Use placeholders and plural-aware messages instead of string concatenation.
  - The resource format and loading mechanism for Win32 (XP-compatible) are defined in
    `docs/design/03-apps-platform.md` §9 "Localization" (§9.1 "Decision: our own message catalog compiled
    into each binary"): PO sources compiled into generated tables, with the `sdl10n` completeness check.
    Plural messages use the full CLDR plural categories (zero/one/two/few/many/other) for every locale.
- Adding a language means adding it to every component, the installer and the language list above.
