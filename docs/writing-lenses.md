# Writing lenses

There are three ways to add a lens, and all of them produce the same findings,
so a new lens shows up in the menu, the window, notifications, the CLI and the
MCP server with no UI changes.

- [An external tool](#an-external-tool)
- [Your own CLI](#your-own-cli)
- [A Rust crate](#a-rust-crate)

Installing lenses other people publish (`lenstica lens install`, a lens
registry, premium lenses) is planned: see
[SPEC.md](../SPEC.md#f-10-lens-installation) for the design.

## An external tool

Declare it in the [settings file](configuration.md). `format` is `gitleaks`,
`osv-scanner`, `trufflehog` (Lenstica translates their JSON and discards any
secret values in it) or `lenstica`, for tools that print Lenstica's report:

```toml
[[external]]
id = "gitleaks"
command = ["gitleaks", "dir", "{root}", "--report-format", "json", "--report-path", "-", "--no-banner", "--exit-code", "0"]
format = "gitleaks"
per_root = true          # once per search root and worktree, {root} replaced
interval_minutes = 240
```

Lenses run as `[[external]]` tools are separate programs with their own
licences.

## Your own CLI

With `format = "lenstica"`, print this on stdout (the exit code is ignored
when the output is valid):

```json
{
  "summary": "2 services missing a code owner",
  "passing": ["checked 14 services"],
  "findings": [
    {
      "key": "owners|billing",
      "severity": "medium",
      "category": "settings",
      "title": "billing has no CODEOWNERS entry",
      "detail": "…",
      "remedy": "Add an owner in .github/CODEOWNERS",
      "locations": [{ "label": "~/code/billing", "path": "/Users/me/code/billing" }],
      "links": []
    }
  ]
}
```

`key` must be stable for the same problem: each key is notified once.
Severities: `info`, `low`, `medium`, `high`, `critical`.

## A Rust crate

Depend on [`crates/lenstica-lens`](../crates/lenstica-lens), implement its
`Lens` trait (`run(&Context) -> Report`, optionally `fix`), and register it in
`src/lenses/mod.rs` behind a feature. The `Context` gives the search roots
(with worktrees), the PATH, a state directory, the lens's own
`[lenses.<id>]` settings and the shared package inventory. The secrets lens
([`crates/lenstica-secrets`](../crates/lenstica-secrets)) is built exactly
this way.

The lens API is `0.x` and may change until it is declared stable
([SPEC.md F-12](../SPEC.md#f-12-stable-lens-api)).

## Per-lens settings

Every lens, built-in or added, reads `[lenses.<id>]` from the settings file,
with `enabled`, `interval_minutes` and the lens's own keys.
