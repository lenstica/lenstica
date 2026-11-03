# Writing lenses

There are three ways to add a lens, and all of them produce the same findings,
so a new lens shows up in the menu, the window, notifications, the CLI and the
MCP server with no UI changes.

- [An external tool](#an-external-tool)
- [Your own CLI](#your-own-cli)
- [A Rust crate](#a-rust-crate)

Installing lenses other people publish (`lenstica lens install` and a lens
registry) is planned: see
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

Every lens appears under one or more [categories](lenses.md#categories):
`agents`, `packages`, `software`, `secrets`, `malware`, `network`, `privacy`.
gitleaks and trufflehog go under Secrets and osv-scanner under Packages and
Malware unless `categories = [...]` says otherwise.

Lenses run as `[[external]]` tools are separate programs with their own
licences.

## Your own CLI

With `format = "lenstica"`, say where the tool belongs:

```toml
[[external]]
id = "listening"
command = ["my-listening-check", "--json"]
format = "lenstica"
categories = ["network"]
```

and print this on stdout (the exit code is ignored when the output is valid):

```json
{
  "summary": "1 service listening on every interface",
  "passing": ["checked 6 listening ports"],
  "findings": [
    {
      "key": "listen|redis|6379",
      "severity": "medium",
      "category": "network",
      "title": "Redis listens on every interface (port 6379)",
      "detail": "…",
      "remedy": "Bind it to 127.0.0.1 in redis.conf",
      "locations": [{ "label": "/opt/homebrew/etc/redis.conf", "path": "/opt/homebrew/etc/redis.conf" }],
      "links": []
    }
  ]
}
```

`key` must be stable for the same problem: each key is notified once.
Severities: `info`, `low`, `medium`, `high`, `critical`. `category` is one of
the lens's categories; an optional `topic` puts the finding under one of the
category's filters in the window (`exposed`, `cooldown`, `prompt-injection`;
see [Lenses](lenses.md#categories)). A finding whose location is inside a
repository shows under that project in the window's project picker.

## A Rust crate

Depend on [`crates/lenstica-lens`](../crates/lenstica-lens), implement its
`Lens` trait (`categories()`, `run(&Context) -> Report`, optionally `fix`),
and register it in `src/lenses/mod.rs` behind a feature. `categories()` names
where the lens appears, at least one. A lens that sends data to a third
party, or runs or recommends a third party's tool, says so in
`third_party()`, and is then off until the user turns it on. The `Context` gives the search roots
(with worktrees), the PATH, a state directory, the lens's own
`[lenses.<id>]` settings and the shared package inventory. The secrets lens
([`crates/lenstica-secrets`](../crates/lenstica-secrets)) is built exactly
this way.

The lens API is `0.x` and may change until it is declared stable
([SPEC.md F-12](../SPEC.md#f-12-stable-lens-api)).

## Per-lens settings

Every lens, built-in or added, reads `[lenses.<id>]` from the settings file,
with `enabled`, `interval_minutes` and the lens's own keys.
