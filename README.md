<p align="center">
  <img src="icons/128x128@2x.png" width="128" height="128" alt="Lenstica logo">
</p>

<h1 align="center">Lenstica</h1>

<p align="center">
  A local security monitor for developer machines.
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License: Apache-2.0"></a>
  <img src="https://img.shields.io/badge/platforms-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey.svg" alt="Platforms: macOS, Linux, Windows">
</p>

Lenstica watches your machine through **lenses**, small checks that each look
for one kind of risk. Every finding shows up in the menu bar, the window, the
CLI and your AI agent, with a remedy and often a one-click fix.

## ✨ Features

- ⏳ **Cooldown everywhere**: npm, pnpm, Yarn, Bun, uv, pip, Poetry and Cargo
  never install versions younger than 7 days, and Lenstica restores the
  setting if something resets it
- 📦 **Dependency audit**: too-new, vulnerable, malicious and deprecated
  packages in every lockfile, worktree and global install
- 🔑 **Exposed secrets**: credentials that malware running as you could steal
  (values are never stored or shown)
- 🤖 **AI-agent instructions**: hidden text, prompt injection and risky
  settings in CLAUDE.md, AGENTS.md, skills, hooks and MCP configs
- 🧰 **Software ages**: package managers, Homebrew formulae and casks, Rust
  toolchains and Node.js that are too new
- 🛠️ **One-click fixes**, with a backup of every file Lenstica edits
- 🧩 **Your own lenses**: a Rust crate, any CLI that prints JSON, or gitleaks,
  osv-scanner and trufflehog
- 🔒 **Local first**: no account, no telemetry

## 💡 Why a cooldown?

- 🐛 Malicious package versions are usually caught and pulled within days
- 📊 8 of 10 prominent attacks in 2024-2025 were live for less than a week
- ⚙️ Every package manager supports a minimum release age, each with its own
  setting name, unit and file. Lenstica sets them all and keeps them set
- ✍️ Prefer doing it by hand? See [docs/cooldown.md](docs/cooldown.md)

## 📥 Installation

> [!NOTE]
> No prebuilt releases yet. Build from source with [Rust](https://rustup.rs)
> 1.90 or newer.

```sh
git clone https://github.com/lenstica/lenstica.git && cd lenstica
cargo install --path .
```

- 🐧 **Linux**: install `libgtk-3-dev libayatana-appindicator3-dev
  libwebkit2gtk-4.1-dev` first, or build headless with
  `--no-default-features --features secrets`
- 📦 **Native packages** (`.app`/`.dmg`, `.msi`, `.deb`/`.rpm`/`.AppImage`):
  `cargo install tauri-cli --version "^2" --locked && CI=true cargo tauri build`

## 🚀 Quick start

```sh
lenstica apply              # set a 7-day cooldown in every package manager
lenstica status             # run the lenses and show what needs attention
lenstica autostart install  # start the menu bar app at every login
```

- 📁 Lenstica searches `~/Developer` by default. Change `scan.roots` in
  `~/.config/lenstica/lenstica.toml` or in the window's Settings
- 🕐 Change the cooldown with `lenstica set <days>`
- 🚦 `lenstica check` exits 1 when something needs attention, so it works in CI
- 📖 Every command: `lenstica --help`

## 🔍 Lenses

| Lens | Finds |
|------|-------|
| `package-managers` | Missing or weaker cooldown settings |
| `project-settings` | Repository files that lower the cooldown |
| `package-age` | Locked or installed versions younger than N days |
| `vulnerabilities` | Known vulnerabilities and malware, from OSV.dev |
| `aikido-malware` | Packages on Aikido Intel's malware lists |
| `deprecated` | Deprecated (npm) or yanked (PyPI) versions |
| `software` | Installed software younger than N days |
| `homebrew-updates` | Homebrew auto-updating before every install |
| `safe-chain` | Whether Aikido Safe Chain is set up |
| `install-scripts` | Package managers that run install scripts |
| `secrets` | Credentials malware could steal |
| `agent-instructions` | Poisoned AI-agent instructions and risky agent settings |

## 🤖 AI agents

- 📋 **Copy Prompt for AI Agent** on any finding, or `lenstica prompt`
- 🎓 **Skill**: `lenstica skill --install` teaches Claude Code the CLI
- 🔌 **MCP server**: `claude mcp add --scope user lenstica -- lenstica mcp`

## 🛡️ Privacy

- 📤 Public package names and versions go to their registries and OSV.dev;
  installed software versions go to their release sites, to date them
- 📥 Aikido's malware lists are downloaded whole, so no names are sent
- 🚫 Private, git and local dependencies are skipped
- 🙈 Secret values are never stored, logged, shown or put in prompts

## 📚 Docs

- ⏳ [The cooldown](docs/cooldown.md): each package manager's setting
- 🔍 [Lenses](docs/lenses.md): every lens in detail
- ⚙️ [Configuration](docs/configuration.md): the settings file
- 🖥️ [The app](docs/app.md): menu bar, window, notifications
- 🤖 [AI agents](docs/ai-agents.md): prompts, skill, MCP server
- 🧩 [Writing lenses](docs/writing-lenses.md): add your own
- 🗺️ [SPEC.md](SPEC.md): architecture and roadmap

## 🤝 Contributing

Issues and pull requests are welcome. Please open an issue before a large
change.

```sh
cargo test --workspace
cargo clippy --all-targets --workspace
HOME=$(mktemp -d) cargo run -- apply   # try changes without touching your real configs
```

- 🙈 Never print, log or store a secret value, even in tests
- 📌 Pin new dependencies to a release at least 7 days old
- 📝 Keep the README, `docs/` and `SPEC.md` current

## 🔐 Security

Please don't report vulnerabilities in public issues. Use
[private vulnerability reporting](https://github.com/lenstica/lenstica/security/advisories/new)
instead.

## 📄 License

[Apache 2.0](LICENSE), see [NOTICE](NOTICE). Icons are from
[Lucide](https://lucide.dev) (ISC).
