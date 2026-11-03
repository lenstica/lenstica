# Translating Lenstica

Everything the app says to you comes from one message file per language in
[`i18n/`](../i18n): the window, the menu bar menu, notifications, and the
messages the app shows in the window. English,
[`i18n/en.json`](../i18n/en.json), is the source, and the fallback for any
message a translation leaves out.

## Add a language

1. Copy `i18n/en.json` to `i18n/<code>.json`, named by the language's code:
   `uk.json`, `de.json`, `pt-BR.json`.
2. Set `language.name` to the language's own name (`"Українська"`); Settings
   → General → Language lists it under that name.
3. Translate the values. Keep the `{placeholders}` as they are. A message
   with a count is an object of plural forms, chosen by
   [CLDR plural rules](https://cldr.unicode.org/index/cldr-spec/plural-rules):
   give the forms your language needs (`zero`, `one`, `two`, `few`, `many`,
   `other`); `other` is required.
4. `cargo test` checks the file against English: no keys English does not
   have, the same shapes, and only English's placeholders. Then
   `cd ui && pnpm build` and build the app.

Nothing else needs listing: the window finds every file in `i18n/`, and the
app embeds them when it is built. A translation may be partial; what it
leaves out shows in English. Dates ("5 minutes ago") and numbers in the window
are formatted for the language by `Intl`.

The menu bar and notifications choose plural forms with the rules in
[`src/i18n.rs`](../src/i18n.rs) (`plural`), which cover English-like
languages, French and Portuguese, the East Slavic and other Slavic languages,
Polish, Czech and Slovak, Arabic, and languages without plurals (Japanese,
Chinese, Korean, Turkish…). A language with other rules needs a line there.

## Which language

The app speaks the first of the system's preferred languages it has a file
for, or the one chosen in Settings → General → Language (`window.language`),
else English.

## Not translated yet

Text a lens writes is still English: lens names and descriptions, findings,
summaries and remedies. So are error messages from the system and the CLI's
output ([#20](https://github.com/lenstica/lenstica/issues/20)).
