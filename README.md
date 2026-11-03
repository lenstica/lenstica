<p align="center">
  <img src="icons/128x128@2x.png" width="128" height="128" alt="Lenstica logo">
</p>

<h1 align="center">Lenstica</h1>

<p align="center">
  <strong>Every vulnerability, through the right lens.</strong><br>
  A local supply-chain security monitor for developer machines.
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License: Apache-2.0"></a>
  <img src="https://img.shields.io/badge/platforms-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey.svg" alt="Platforms: macOS, Linux, Windows">
  <img src="https://img.shields.io/badge/rust-2024%20edition-orange.svg" alt="Rust 2024 edition">
  <img src="https://img.shields.io/badge/status-early%20development-yellow.svg" alt="Status: early development">
</p>

<p align="center">
  <a href="https://lenstica.com">Website</a> ·
  <a href="#installation">Install</a> ·
  <a href="#documentation">Docs</a> ·
  <a href="SPEC.md">Roadmap</a> ·
  <a href="#contributing">Contributing</a>
</p>

---

Lenstica watches your machine through **lenses**: focused checks that each
look for one kind of risk. It finds package managers that install versions too
new to trust; vulnerable, malicious and deprecated packages; secrets a
compromised package would steal; poisoned AI-agent instructions; and installed
software that is too new. Every lens reports findings in the same format, so
they all show up in the menu bar, the window, desktop notifications, the CLI
and your AI coding agent.

Everything runs locally. Lenstica has no account and no telemetry
([what leaves your machine](#privacy)).

## Contents

- [Why](#why)
- [Features](#features)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Usage](#usage)
- [Lenses](#lenses)
- [Privacy](#privacy)
- [Documentation](#documentation)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)
- [Acknowledgements](#acknowledgements)

## Why

Lenstica started as one lens, the **cooldown**: keep every package manager
on the machine from installing versions published less than N days ago.

A release cooldown is the cheapest defence against the npm and PyPI
supply-chain attacks of the last two years. Malicious versions are usually
caught and pulled within hours to a few days: of ten prominent attacks in
2024-2025, eight were live for less than a week. So a package manager that
never installs anything younger than 7 days rarely sees one.

Every major package manager now supports a minimum release age, but each uses
a different setting name, unit and config file, and nothing tells you when
one goes missing. Lenstica writes the right value into each one, keeps it
there, and audits what is already installed, which the settings alone cannot
do. If you only want the settings, [docs/cooldown.md](docs/cooldown.md) shows
how to set each one by hand.

## Features

- **A cooldown everywhere.** Sets the minimum release age for npm, pnpm, Yarn,
  Bun, uv, pip, Poetry and Cargo, and restores it if a tool, a dotfile sync or
  a new machine resets it.
- **Dependency audit.** Reads every lockfile in your repositories and git
  worktrees, plus global installs. It reports versions that are too new,
  known vulnerabilities and malware (from [OSV.dev](https://osv.dev) and
  [Aikido Intel](https://intel.aikido.dev)), and deprecated or yanked releases.
- **Exposed secrets.** Finds credentials that malware running as you could
  steal, such as long-lived cloud keys, plain-text tokens, unencrypted SSH
  keys and `.env` files. It never stores or shows a secret value.
- **AI-agent instructions.** Scans CLAUDE.md, AGENTS.md, skills, plugins,
  hooks and MCP configs for hidden text, prompt injection, credential leaks
  and remote-code instructions.
- **Fix, not just report.** Every finding has a remedy. Where a fix is safe,
  Lenstica applies it in one click and keeps a backup of any file it edits.
- **Works with your AI agent.** Copy a prompt for any finding, install the
  agent skill, or connect the built-in MCP server.
- **Extensible.** Add your own lenses as a Rust crate, any CLI that prints
  JSON, or an existing scanner such as gitleaks, osv-scanner or trufflehog.
- **One binary.** The menu bar app, the window, the CLI and the MCP server
  ship as one native app for macOS, Windows and Linux, built on
  [Tauri](https://tauri.app).

## Installation

> [!NOTE]
> Lenstica is in early development (`0.x`). There are no prebuilt releases
> yet, so for now you build it from source. Once a version is tagged,
> packages for each platform will be attached to
> [GitHub Releases](https://github.com/lenstica/lenstica/releases).

### Requirements

- [Rust](https://rustup.rs) 1.90 or newer.
- On Linux, for the menu bar app and window: GTK 3, libayatana-appindicator
  and WebKitGTK development packages:

  ```sh
  sudo apt install libgtk-3-dev libayatana-appindicator3-dev libwebkit2gtk-4.1-dev
  ```

### With Cargo

This installs the CLI and the menu bar app, without an app bundle:

```sh
git clone https://github.com/lenstica/lenstica.git
cd lenstica
cargo install --path .          # puts `lenstica` in ~/.cargo/bin
```

On a headless Linux machine, leave out the app:

```sh
cargo install --path . --no-default-features --features secrets
```

### As a native app

To build the installable packages for the platform you are on:

```sh
cargo install tauri-cli --version "^2" --locked   # once
CI=true cargo tauri build                         # CI=true skips the Finder layout of the .dmg
```

| Platform | Packages in `target/release/bundle/` |
|----------|--------------------------------------|
| macOS | `macos/Lenstica.app`, `dmg/Lenstica_<version>_<arch>.dmg` (a menu bar app: no Dock icon until the window opens) |
| Windows | `msi/…msi`, `nsis/…-setup.exe` |
| Linux | `deb/…deb`, `rpm/…rpm`, `appimage/…AppImage` |

These builds are unsigned, so they open with a Gatekeeper or SmartScreen
warning. To use the CLI from the macOS app:

```sh
ln -s /Applications/Lenstica.app/Contents/MacOS/lenstica /usr/local/bin/lenstica
```

## Quick start

```sh
lenstica apply                  # write a 7-day cooldown into every package manager
lenstica status                 # run the lenses and show what needs attention
lenstica autostart install      # menu bar icon at every login, starting now
```

On a headless machine, `lenstica autostart install --headless` runs
`lenstica watch` as a systemd user service with desktop notifications.

To choose which folders are searched (the default is `~/Developer`), set
`scan.roots` in `~/.config/lenstica/lenstica.toml`, or use the window's
Settings page. To change the cooldown, run `lenstica set <days>`.

## Usage

### Menu bar app

The menu bar icon shows whether anything needs attention. The menu lists
every lens and each finding, with **Fix It**, **Open the file** and **Copy
Prompt for AI Agent**. The window has an overview, a searchable list of
findings, a switch for each lens, and every setting. See
[docs/app.md](docs/app.md).

### Command line

```text
lenstica                      status (the default)
lenstica status               every lens's summary and what needs attention; runs what is due
lenstica check [ids]          run lenses now; exit 1 at monitor.alert_severity or above
lenstica findings             findings with details and remedies
                              --severity high, --category secret, --lens vulnerabilities, --json
lenstica lenses               built-in, plugin and external lenses, schedules, last runs
lenstica fix <lens> <key>     fix one finding (the command is printed next to fixable ones)
lenstica audit                run the dependency lenses now
lenstica scan                 run the project-settings lens now
lenstica apply [ids] [-n]     write the cooldown into package managers
lenstica set <days>           change min_days and apply
lenstica window [page]        open the window (overview, findings, lenses, settings)
lenstica watch [--once]       foreground monitor with notifications, no icon
lenstica tray                 menu bar / tray app
lenstica config [path|show|edit]
lenstica managers             what Lenstica knows about each package manager
lenstica autostart install [--headless] | uninstall | status
lenstica prompt [lens [key]]  a brief for an AI agent: everything needing attention, or one finding
lenstica test-notification    show a test notification (and say whether it carries the app icon)
lenstica mcp [--setup]        MCP server on stdin/stdout for AI agents; --setup prints how to register it
lenstica skill [--install]    print the agent skill, or install it to ~/.claude/skills/lenstica
```

`lenstica check` exits with status 1 when a finding at or above
`monitor.alert_severity` remains, so you can use it in scripts and CI.

### With an AI agent

```sh
lenstica prompt                                     # a brief of everything needing attention
lenstica skill --install                            # teach Claude Code the lenstica CLI
claude mcp add --scope user lenstica -- lenstica mcp  # or connect the MCP server
```

See [docs/ai-agents.md](docs/ai-agents.md).

## Lenses

| id | What it finds |
|----|---------------|
| `package-managers` | A package manager without the cooldown, with a weaker one, or too old to have it. Re-applied automatically. |
| `project-settings` | Repository files that lower the cooldown (`.npmrc`, `pnpm-workspace.yaml`, …). Reported, never edited. |
| `package-age` | Locked or installed versions published less than N days ago. |
| `vulnerabilities` | Known vulnerabilities and malicious releases, from OSV.dev. |
| `aikido-malware` | npm and PyPI packages on Aikido Intel's malware, protestware and telemetry lists. |
| `deprecated` | Versions deprecated on npm or yanked on PyPI. |
| `software` | Installed software younger than N days: package managers, Homebrew formulae and casks, Rust toolchains, Node.js. |
| `homebrew-updates` | Homebrew fetching the newest formulae before every install. |
| `safe-chain` | Whether [Aikido Safe Chain](https://github.com/AikidoSec/safe-chain) is installed and loaded by your shells. |
| `install-scripts` | Package managers that run dependencies' install scripts. |
| `secrets` | Credentials that malware running as you could steal. |
| `agent-instructions` | AI-agent instruction files with hidden text, prompt injection, credential leaks or remote-code instructions. |

[docs/lenses.md](docs/lenses.md) covers each lens in detail, with severities
and what each one reads. To add your own, see
[docs/writing-lenses.md](docs/writing-lenses.md).

## Privacy

Lenstica runs entirely on your machine and sends nothing to Lenstica. What
does leave the machine:

- **Package names and versions** of public npm, PyPI and crates.io packages,
  sent to those registries and to [OSV.dev](https://osv.dev) to look up
  publish dates and advisories. Workspace, git, path, tarball and
  private-registry dependencies are skipped.
- **Aikido Intel's lists** are downloaded whole (about 11 MB, every 6 hours),
  so no package names are sent to Aikido.
- **Names and versions of installed software**, to date them: the package
  managers themselves (npm registry, PyPI, static.rust-lang.org), Homebrew
  formulae and casks (formulae.brew.sh, ghcr.io and each cask's download
  URL) and Node.js (nodejs.org).

Secret values are never stored, logged, shown or put in prompts. Findings name
the file, the variable and the kind of credential.

## Documentation

| Guide | What's in it |
|-------|--------------|
| [The cooldown](docs/cooldown.md) | What Lenstica writes into each package manager, and how to set it by hand |
| [Lenses](docs/lenses.md) | Every built-in lens in detail |
| [Configuration](docs/configuration.md) | The settings file, where files live, and things to know |
| [The app](docs/app.md) | The menu bar, the window, notifications and start at login |
| [AI agents](docs/ai-agents.md) | Prompts, the agent skill and the MCP server |
| [Writing lenses](docs/writing-lenses.md) | External tools, your own CLI, or a Rust crate |
| [SPEC.md](SPEC.md) | Architecture, roadmap, decisions and work log |

## Roadmap

Lenstica is free for individual developers: every lens, the menu bar app,
the CLI, the AI-agent integrations and your own lenses. Next up are signed
releases, installing lenses other people publish, and new lenses for
containers, CI workflows, and editor and browser extensions.

A team edition is planned for organisations that need the same rules on every
developer's machine: central policy, a dashboard, audit logs, SSO and managed
rollout. It will be the same binary unlocked by a licence key, and it will
never remove anything from the free edition. The full plan is in
[SPEC.md](SPEC.md#8-roadmap-and-backlog).

## Contributing

Bug reports, false positives, ideas for lenses and pull requests are all
welcome. Please [open an issue](https://github.com/lenstica/lenstica/issues)
to discuss a larger change before starting on it.

To build and test:

```sh
cargo test --workspace
cargo clippy --all-targets --workspace
LENSTICA_CROSS_CHECK=1 cargo check --target x86_64-pc-windows-msvc   # skips only the Windows resource step
cargo check --target x86_64-unknown-linux-gnu --no-default-features --features secrets
cargo tauri dev -- -- tray      # the app from a debug build (args after the second -- reach the binary)
```

To try changes without touching your real configs, run against a throwaway
home: `HOME=$(mktemp -d) cargo run -- apply`. Every path Lenstica reads or
writes is derived from `HOME`, `XDG_*` or `APPDATA`.

A few rules for changes, from [SPEC.md](SPEC.md#72-rules):

- Never print, log or store a secret value, including in tests and while
  debugging.
- Pin new dependencies to a release at least 7 days old, and prefer crates
  already in `Cargo.lock`.
- Keep the README, `docs/` and `SPEC.md` up to date with every user-visible
  change.

## Security

If you find a security vulnerability in Lenstica, please **do not open a
public issue**. Report it privately through
[GitHub's private vulnerability reporting](https://github.com/lenstica/lenstica/security/advisories/new).

## License

Lenstica is licensed under the [Apache License 2.0](LICENSE). That covers the
core, the `lenstica-lens` API crate and the built-in lenses, so anyone can use
Lenstica, including at work, and build lenses on it. See [NOTICE](NOTICE).

Lenses run as `[[external]]` tools are separate programs with their own
licences. The planned team edition will be a separate, proprietary add-on;
the open-source core does not depend on it and never will.

## Acknowledgements

- Icons from [Lucide](https://lucide.dev), ISC licence, kept in
  [`assets/lucide/`](assets/lucide) with their licence file.
- Vulnerability and malware data from [OSV.dev](https://osv.dev) and
  [Aikido Intel](https://intel.aikido.dev).
- Built with [Tauri](https://tauri.app).
