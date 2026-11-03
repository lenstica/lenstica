<p align="center"><img src="icons/128x128@2x.png" width="128" height="128" alt="Lenstica"></p>

# Lenstica

**Every vulnerability, through the right lens.**

Lenstica is a local supply-chain security monitor for developer machines. It
looks at your machine through **lenses**, a library of focused checks that each
look for one kind of risk: package managers installing versions too new to
trust, vulnerable, malicious and deprecated packages, secrets a compromised
package would steal, poisoned AI-agent instructions, too-new software. Every
lens reports findings in one format, so they all show up in the menu bar, the
window, notifications, the CLI and your AI agent. You can add your own lenses,
and later install ones others publish.

Website: [lenstica.com](https://lenstica.com) · Source: [github.com/lenstica/lenstica](https://github.com/lenstica/lenstica) · Plan and roadmap: [SPEC.md](SPEC.md)

The first lens Lenstica grew from is the **cooldown**: keep every package
manager on the machine from installing versions published less than N days
ago, and keep watching what is already there. One settings file, a menu bar
icon, a window with every finding and how to fix it, and a CLI for scripts.

A release cooldown is the cheapest defence against the npm/PyPI supply-chain
attacks of the last two years: malicious versions are usually caught and
pulled within hours to a few days, so a tool that never installs anything
younger than a week rarely sees one. Every major package manager now supports
it, each with a different setting name, unit and config file. Lenstica
writes the right value into each one and keeps it there.

## Free and for teams

Lenstica is free for individual developers, and stays useful on its own:
every lens, the menu bar app, the CLI, the AI-agent integrations, and your own
lenses. A team edition, with the same app and binary unlocked by a licence key,
is planned for organisations that need the same rules on every developer's
machine: central policy, a team dashboard, audit logs and compliance reports,
SSO, managed rollout and premium lenses. See [SPEC.md](SPEC.md).

## Setting the minimum age by hand

You do not need Lenstica to get the protection: every package manager below
has the setting built in. Here is each one for **7 days**, Lenstica's default
and the figure most guidance settles on: of ten prominent open-source
supply-chain attacks in 2024-2025, eight were open for less than a week before
being caught, so a 7-day wait would have kept them out (14 days: all but one).
Shorter (3 days) still stops the many caught within hours; longer delays
urgent fixes more. pnpm 11 ships a 1-day default, so set it explicitly.
Set it once, user wide, and it applies to every project on the machine, unless a project's own
file overrides it (the second line of each entry), which Lenstica's
`project-settings` lens watches for.

**npm** 11.10+, value in days:

```sh
npm config set min-release-age=7 --location=user      # writes ~/.npmrc
```
Per project: `min-release-age=7` in the repository's `.npmrc`. One-off
exception: `npm install some-pkg --min-release-age=0`. Check: `npm config get min-release-age`.

**pnpm** 10.16+, value in minutes:

```sh
pnpm config set --global minimumReleaseAge 10080      # pnpm 11+: global config.yaml
```
pnpm 10.x keeps global settings in INI form instead: `minimum-release-age=10080`.
Per project: `minimumReleaseAge: 10080` in `pnpm-workspace.yaml`; exceptions
in `minimumReleaseAgeExclude: [some-pkg]`. Check: `pnpm config get minimumReleaseAge`.

**Yarn** 4.10+, value in minutes (4.11+ also takes `7d`), in `~/.yarnrc.yml`:

```yaml
npmMinimalAgeGate: 10080
```
Per project: the same line in the repository's `.yarnrc.yml`; exceptions in
`npmPreapprovedPackages`. Yarn Classic (1.x) has no such setting.

**Bun** 1.3+, value in seconds, in `~/.bunfig.toml` (or `$XDG_CONFIG_HOME/.bunfig.toml`):

```toml
[install]
minimumReleaseAge = 604800
```
Per project: the same table in the repository's `bunfig.toml`.

**uv** 0.9.17+, in `~/.config/uv/uv.toml` (`%APPDATA%\uv\uv.toml` on Windows):

```toml
exclude-newer = "7 days"
```
Per project: `exclude-newer = "7 days"` under `[tool.uv]` in `pyproject.toml`,
or in the project's `uv.toml`; per-package overrides with `exclude-newer-package`.

**pip** 26.1+, an ISO 8601 duration:

```sh
pip config --user set install.uploaded-prior-to P7D   # writes the user pip.conf / pip.ini
```
One-off: `pip install --uploaded-prior-to P7D …`, or the
`PIP_UPLOADED_PRIOR_TO` environment variable. Check: `pip config get install.uploaded-prior-to`.

**Poetry** 2.4+, value in days:

```sh
poetry config solver.min-release-age 7
```
Per project: `poetry config --local solver.min-release-age 7` (writes `poetry.toml`);
exceptions in `solver.min-release-age-exclude`.

**Cargo** 1.100+, in `~/.cargo/config.toml` (`$CARGO_HOME/config.toml`):

```toml
[registry]
global-min-publish-age = "7 days"
```
For one registry only: `min-publish-age = "7 days"` under `[registries.crates-io]`,
which overrides the global value for crates.io. Per project: the same in the
repository's `.cargo/config.toml`.

**Deno** 2.5+ has it per project only, in `deno.json`:

```json
{ "minimumDependencyAge": "P7D" }
```
One-off: `deno install --minimum-dependency-age=P7D`.

**Homebrew** has no minimum-age setting. The closest control: stop it fetching
the newest formulae before every `brew install` / `brew upgrade`, so new
versions arrive only when you run `brew update`:

```sh
mkdir -p ~/.homebrew && echo 'HOMEBREW_NO_AUTO_UPDATE=1' >> ~/.homebrew/brew.env
```
That file is read by `brew` however it is started; an `export` in `~/.zshrc`
only covers terminals. Lenstica does this with `homebrew.no_auto_update = true`.

**Update bots.** Renovate: `"minimumReleaseAge": "7 days"` in `renovate.json`.
Dependabot: under each update in `.github/dependabot.yml`,
`cooldown: { default-days: 7 }`.

What the settings cannot do, and Lenstica adds: notice when one is missing,
weaker or reset (by a tool, a dotfile sync or a new machine), when a project
overrides it, or when a package that is already locked is too new, vulnerable
or malicious; and they do nothing for lockfile installs (`npm ci`,
`--frozen-lockfile`), which take what is pinned.

## Install

Lenstica is a [Tauri](https://tauri.app) app: the menu bar icon and the window
are one native app on macOS, Windows and Linux, and the same binary is the CLI.
The window is an HTML page rendered by the system web view (WebKit, WebView2,
WebKitGTK), so it looks the same everywhere.

**As a native app.** Build the packages for the platform you are on:

```sh
cargo install tauri-cli --version "^2" --locked   # once
CI=true cargo tauri build                         # CI=true skips the Finder layout of the .dmg
```

| Platform | Packages in `target/release/bundle/` |
|----------|--------------------------------------|
| macOS | `macos/Lenstica.app`, `dmg/Lenstica_<version>_<arch>.dmg` (a menu bar app: no Dock icon until the window opens) |
| Windows | `msi/…msi`, `nsis/…-setup.exe` |
| Linux | `deb/…deb`, `rpm/…rpm`, `appimage/…AppImage` |

Packages for every platform are built natively by `.github/workflows/release.yml`
(push a `v*` tag, or run it by hand) and attached to a draft release.
Unsigned builds open with a Gatekeeper / SmartScreen warning; signing needs an
Apple Developer ID and a Windows code-signing certificate.

Open the app once to start it, then turn on **Start at login** in its menu.
To use the CLI from the app on macOS:
`ln -s /Applications/Lenstica.app/Contents/MacOS/lenstica /usr/local/bin/lenstica`.

**With cargo** (CLI plus the same app, unbundled):

```sh
cargo install --path .          # puts `lenstica` in ~/.cargo/bin
lenstica apply                  # write the cooldown into every package manager
lenstica autostart install      # menu bar icon at every login, starting now
```

Linux needs GTK 3, libayatana-appindicator and WebKitGTK development packages
for the app (`sudo apt install libgtk-3-dev libayatana-appindicator3-dev libwebkit2gtk-4.1-dev`).
Without them, build headless: `cargo install --path . --no-default-features --features secrets`
and use `lenstica autostart install --headless`, which runs `lenstica watch`
as a systemd user service with desktop notifications.

Launched with no arguments outside a terminal (Finder, Explorer, a login item)
the binary starts the menu bar app; in a terminal it prints `lenstica status`.
Opening the app again, or `lenstica window`, opens the window in the running
instance.

## Lenses

Everything Lenstica checks is a **lens** producing findings in one format
(severity, category, title, details, locations, remedy, links, and whether it
can fix it). The menu, the window, notifications and the CLI only know
findings, so a new lens shows up everywhere. `lenstica lenses` lists them.

| id | What it finds | Severity |
|----|---------------|----------|
| `package-managers` | A package manager without the cooldown, a weaker one, or too old to have it. Re-applied automatically (`monitor.auto_apply`); click to fix. | high / medium |
| `project-settings` | Repository files that lower the cooldown (`.npmrc`, `pnpm-workspace.yaml`, `.yarnrc.yml`, `bunfig.toml`, `uv.toml`, `pyproject.toml`, `poetry.toml`, `pip.conf`). Reported, never edited. | medium |
| `package-age` | Locked or installed versions published less than N days ago; and ones that were that young when their lockfile last changed. | medium / info |
| `vulnerabilities` | Known vulnerabilities and **malicious releases**, from [OSV.dev](https://osv.dev) (GitHub, PyPI and OpenSSF malicious-packages advisories). Malware is its own category, always critical, with a remedy that assumes compromise. | per advisory; malware critical |
| `aikido-malware` | Locked and installed npm and PyPI packages on [Aikido Intel](https://intel.aikido.dev)'s malware, protestware and telemetry lists, the lists [Safe Chain](https://github.com/AikidoSec/safe-chain) blocks downloads with. A second malware source beside OSV.dev. The lists are downloaded whole (about 11 MB, refreshed every 6 hours with an ETag), so no package names are sent. | malware critical, protestware high, telemetry low |
| `deprecated` | Versions deprecated on npm or yanked on PyPI. | info / low |
| `software` | Installed **software** published less than N days ago (below): the package managers themselves, Homebrew formulae and casks, Rust toolchains, Node.js. | medium |
| `homebrew-updates` | Homebrew fetching the newest formulae before every install. Click to set `HOMEBREW_NO_AUTO_UPDATE=1` in `~/.homebrew/brew.env`, or set `homebrew.no_auto_update = true`. | low |
| `safe-chain` | Whether Aikido Safe Chain is installed and loaded by your shells; recommends it when it is not. Click to run `safe-chain setup`. | info / low |
| `install-scripts` | Package managers that run dependencies' install scripts (how Shai-Hulud-style worms execute). Click to block, or set `install_scripts.block = true`. | low |
| `secrets` | Credentials malware running as you could steal (below). A plugin crate. | critical … info |
| `agent-instructions` | AI agent instruction files (CLAUDE.md, AGENTS.md, rules, skills, plugins, hooks, MCP configs) with hidden text, prompt injection, credential-leaking or remote-code instructions, and settings that let an injected instruction run without asking (below). Click to strip invisible characters. | critical … low |

Packages are read from every lockfile under `scan.roots` and **every git
worktree** of the repositories found there (`package-lock.json`,
`npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `uv.lock`,
`poetry.lock`, `Cargo.lock`), plus `npm -g`, `pnpm -g`, uv tools, `pip --user`
and `cargo install`. Crate publish times and yanked status come from the
crates.io sparse index; crate advisories (RustSec) from OSV.dev.

What leaves the machine: package **names and versions** of public npm, PyPI
and crates.io packages, to those registries and OSV.dev. Workspace, git, path, tarball
and private-registry entries are skipped. Publish times and advisories are
cached, so after the first run (a minute or two for a large monorepo) passes
take seconds. Each package is re-checked against OSV every 6 hours
(`[lenses.vulnerabilities] refresh_hours`), because advisories, malware
above all, are published for versions people already have.

### Software ages

The minimum-age settings cover dependencies, not the tools themselves:
`brew upgrade` installs a new sqlite or git the moment its bottle exists, and
`npm install -g npm` takes the newest npm. Nothing can hold those back, so the
`software` lens reports a version younger than `min_days` once it is
installed. What it looks at, each switchable under `[software]`:

| Software | Dated by |
|----------|----------|
| Package managers (npm, pnpm, Yarn, Bun, Deno, uv, pip, Poetry, Cargo) | npm registry or PyPI publish time; the Rust release manifest for Cargo |
| Homebrew formulae (homebrew/core) | when the version's bottle was published on ghcr.io (`org.opencontainers.image.created`) |
| Homebrew casks | the `Last-Modified` time of the download. Casks that update themselves (`auto_updates`: most browsers, editors, chat apps) are skipped: Homebrew's version is not what runs |
| Rust toolchains (rustup) | the toolchain's own release manifest, read locally. Nightly and beta are skipped |
| Node.js not from Homebrew | nodejs.org's release index |

A binary that comes from Homebrew is judged once, as a formula. Dates without
a time of day count from the end of that day, so nothing is reported older
than it is. Formulae from other taps and HEAD builds have no published bottle
and are listed as not checked. The Homebrew, Caskroom and rustup folders are
watched, so an install is checked within seconds. Remedies say what can be
done: `brew pin` to stop further upgrades, `rustup default 1.xx.y` to stay a
release behind.

### Aikido Safe Chain

lenstica and [Safe Chain](https://github.com/AikidoSec/safe-chain) cover
different moments. Safe Chain wraps npm, npx, Yarn, pnpm, Bun, pip, uv, Poetry
and pipx in your shell and checks each download against Aikido's malware lists
before it reaches the disk, and can also hold back very new versions.
lenstica sets each package manager's own minimum age (which applies however
the tool is started, also from an editor or a script) and audits what is
already installed, after the fact. Using both is sensible.

- `safe-chain` reports whether it is installed and which shells load it
  (`~/.zshrc`, `~/.bashrc`, fish, PowerShell, or its shims on PATH).
- `aikido-malware` checks your lockfiles and global installs against the same
  lists Safe Chain uses, so a package it would have blocked is found even if it
  got in another way. The lists are served by Aikido without an account; their
  terms of use are not published with them, so check Aikido's terms before
  using them commercially. Turn it off with `[lenses.aikido-malware] enabled = false`.

### Exposed secrets

A malicious install script runs as you, so file permissions do not stop it
reading your credentials. What helps is fewer, shorter-lived secrets in fewer
places; every finding says how. **No secret value is ever stored or shown**:
findings name the file, the setting or variable names and the kind of
credential.

- Cloud and registry credentials: long-lived AWS keys (`AKIA…`) in
  `~/.aws/credentials`, active AWS SSO sessions and cached role credentials,
  npm, PyPI and Cargo registry tokens, Docker registry passwords without a credential helper,
  static kubeconfig credentials, the GitHub CLI token in plain text,
  `.git-credentials`, `.netrc`, Terraform and Google Cloud credentials.
- SSH private keys without a passphrase.
- Secrets exported in shell startup files, and tokens in shell history
  (GitHub, npm, AWS, Anthropic, OpenAI, Slack, Stripe, Google, GitLab, private
  keys, URLs with passwords).
- `.env*` files, `appsettings*.json`, `secrets.json`, key and certificate
  files, Terraform state and service-account files under `scan.roots` and
  every worktree, **grouped across copies**: one finding for
  `.env.production` in 55 worktrees, listing all 55.

AWS SSO is far better than permanent keys, but its cache is still usable by
anything running as you until it expires (and renewable with its refresh
token), so it is listed below the alert line. Keep production behind a
separate, short-lived profile, and `aws sso logout` when done.

### AI agent instructions

Coding agents load some files as instructions from you: CLAUDE.md and
AGENTS.md, rules, skills, slash commands, subagents, auto memory, plugins,
hooks and MCP server definitions. A poisoned one (a plugin, a cloned
repository, a pull request that edits AGENTS.md) can make an agent leak
credentials or run code. `agent-instructions` reads them for:

- **Hidden text**: Unicode tag characters and variation-selector runs (text
  editors and GitHub do not show, but models read; the hidden text is decoded
  and checked too), bidirectional controls, zero-width characters. Click to
  strip them; the original is kept as `<name>.lenstica-backup`.
- **Prompt injection phrasing**: "ignore previous instructions", "you are now
  in developer mode", "do not tell the user about this", "keep this from the
  user", also inside HTML comments (invisible when rendered) and long base64
  blocks (decoded and checked).
- **Credential leaks**: a credential file or dump (`~/.ssh/`,
  `~/.aws/credentials`, `.npmrc`, `.netrc`, `gh auth token`, `printenv`) on
  the same line as a network command; instructions to send keys, tokens or
  the system prompt to a URL, issue, comment or chat; known exfiltration
  services (webhook.site, requestbin, ngrok, interactsh, Discord webhooks,
  paste sites).
- **Remote code**: `curl | sh`, `bash -c "$(curl …)"`, `base64 -d | sh`, and
  "follow the instructions at <url>". High in hooks and MCP definitions (they
  run on their own), low in prose (install instructions often look like this).
- **Weaker guard rails**: Claude Code `bypassPermissions` or `Bash(*)`,
  `enableAllProjectMcpServers`, Codex `approval_policy = "never"` with full
  access, MCP servers over plain `http://`, and MCP servers started with `npx`,
  `bunx`, `uvx` or `pnpm dlx` without a pinned version (the newest release runs
  at every start, skipping any lockfile).

Where it looks: your own files for Claude Code (`~/.claude/`: CLAUDE.md,
rules, skills, commands, agents, hooks, settings, project memory; MCP servers
in `~/.claude.json`), Codex (`~/.codex/`), Cursor, Gemini CLI, opencode,
Windsurf, Copilot CLI, Claude Desktop, VS Code's `mcp.json` and
`~/.agents/skills`; every **installed** Claude Code plugin (its skills,
commands, agents, hooks and the scripts they run, and its MCP servers); and
in each repository and worktree under `scan.roots`, CLAUDE.md, AGENTS.md,
GEMINI.md, `.cursorrules`, `.windsurfrules`, `.clinerules`, `.mcp.json` and
the `.claude`, `.cursor/rules`, `.github` (Copilot instructions and prompts),
`.windsurf`, `.roo`, `.kiro`, `.junie`, `.gemini`, `.codex`, `.agents` and
`.opencode` folders. Identical copies (one CLAUDE.md in 50 worktrees) are one
finding.

These are patterns, so a finding is a reason to read the lines it lists, not
proof. Phrases that are negated ("never pipe curl into sh") or quoted as an
example are skipped. Findings show the line and the few matched words, never
the surrounding text, and a copied prompt tells the agent the file is
untrusted. Accept reviewed files with `[lenses.agent-instructions] ignore`.

## Adding lenses

Three ways, all producing the same findings. Installing lenses other people
publish (`lenstica lens install`, a lens registry, premium lenses) is planned:
see [SPEC.md](SPEC.md#f-10-lens-installation) for the design.

**An external tool**, declared in the settings file. `format` is `gitleaks`,
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

**Your own CLI**, with `format = "lenstica"`: print this on stdout (exit code
is ignored when the output is valid):

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

**A Rust crate**: depend on `crates/lenstica-lens`, implement its `Lens`
trait (`run(&Context) -> Report`, optionally `fix`), and register it in
`src/lenses/mod.rs` behind a feature. The `Context` gives the search roots
(with worktrees), the PATH, a state directory, the lens's own
`[lenses.<id>]` settings and the shared package inventory. The secrets
lens (`crates/lenstica-secrets`) is built exactly this way.

Per-lens settings: `[lenses.<id>]` with `enabled`, `interval_minutes`
and the lens's own keys.

## The menu bar app and the window

A Lucide package icon in the menu bar (`package-check` when nothing needs
attention, an orange `package-x` with a count when something does,
`package-search` while the first checks run). The menu lists every lens
with a coloured dot: green when clear, the colour of its worst finding when
not, blue while running, hollow before its first run. Each finding needing
attention has a severity icon (filled red octagon critical, orange triangle
high, amber circle medium, blue `i` low, grey dot info) and a submenu: Fix It
when Lenstica can, Open the file, **Copy Prompt for AI Agent**, and Show in
Lenstica. Below them: Open Lenstica (⌘O), Settings (⌘,) and Quit (⌘Q).
Everything else (the minimum age, applying, checking now, the settings file,
start at login) lives in the window.

- **Overview**: counts by severity and category, a card per lens with its
  summary and a Run button.
- **Findings**: search and filter by severity, category and lens; details,
  remedy, every location (open or reveal), references, and actions: fix,
  copy a prompt for an AI agent, ignore a package or one version of it,
  ignore an advisory. One button copies a single prompt for everything shown.
- **Lenses**: turn each on or off, run it now, see what it checked.
- **Settings**: everything you would otherwise edit by hand, saved straight
  into the file with its comments kept: the cooldown and alerts; a switch per
  **check** and per **package manager** (one switched off is left exactly as
  it is); which folders to include and exclude; every **repository and
  worktree** found there, each with a switch (off adds it to `scan.exclude`);
  the installed-packages audit; which **installed software** to check;
  **notifications** (on or off, from which severity, per check, and whether
  automatic fixes are announced); and **AI agents** (install the skill, copy
  the MCP setup).

Lenses run on their own schedules, each on its own thread; one that watches
files (the package-manager configs, `.npmrc`) re-runs within seconds of an
edit, so a hand-weakened setting is reported and restored almost at once.
Every check also runs when the settings file changes. New findings at or
above `monitor.alert_severity` (default `medium`) are notified once each.

Login items: a launchd agent (`~/Library/LaunchAgents/com.lenstica.agent.plist`,
log in `~/Library/Logs/lenstica.log`), an XDG autostart entry or systemd user
unit on Linux, and the `HKCU\…\Run` key on Windows.

## AI agents

Three ways to hand Lenstica's findings to a coding agent such as Claude Code:

- **Copy a prompt.** Every finding, in the menu and the window, has Copy
  Prompt for AI Agent: a short brief with what was found, where, the
  suggested fix, and how to confirm it is gone (`lenstica check <lens>`).
  `lenstica prompt` prints the same for everything needing attention,
  `lenstica prompt <lens>` for one lens, `lenstica prompt <lens> '<key>'`
  for one finding. Findings hold secret names and paths, never values, and the
  prompt tells the agent not to print any.
- **The skill.** `lenstica skill --install` (or Settings → AI agents) writes
  [`skills/lenstica/SKILL.md`](skills/lenstica/SKILL.md) to
  `~/.claude/skills/lenstica/`, teaching the agent the CLI: `lenstica status
  --no-run --json`, `lenstica findings --json`, `lenstica fix`, `lenstica
  check`, and how to treat each lens's findings. `lenstica skill` prints it,
  for agents that load skills from elsewhere (`--install --dir DIR`).
- **The MCP server.** `lenstica mcp` speaks the Model Context Protocol on
  stdin/stdout. Register it with `claude mcp add --scope user lenstica --
  lenstica mcp`, or the `mcpServers` entry `lenstica mcp --setup` prints.
  Tools: `lenstica_status`, `lenstica_findings` (filter by severity, lens,
  category, text), `lenstica_finding` (one in full, with its brief),
  `lenstica_prompt`, `lenstica_run` (re-run lenses to confirm a fix) and
  `lenstica_fix` (Lenstica's own fixes). It reads the same stored results as
  the menu bar app.

## What it configures

| id | Setting it writes | Unit (7 days =) | Needs | User-level file |
|----|-------------------|-----------------|-------|-----------------|
| `npm` | `min-release-age` | days (`7`) | npm 11.10 | `~/.npmrc` (via `npm config set --location=user`) |
| `pnpm` | `minimumReleaseAge` | minutes (`10080`) | pnpm 10.16 | pnpm global config (via `pnpm config set --global`) |
| `yarn` | `npmMinimalAgeGate` | minutes (`10080`) | Yarn 4.10 | `~/.yarnrc.yml` |
| `bun` | `[install] minimumReleaseAge` | seconds (`604800`) | Bun 1.3 | `~/.bunfig.toml` (or `$XDG_CONFIG_HOME/.bunfig.toml`) |
| `uv` | `exclude-newer` | duration (`"7 days"`) | uv 0.9.17 | `~/.config/uv/uv.toml` (`%APPDATA%\uv\uv.toml`) |
| `pip` | `[install] uploaded-prior-to` | ISO 8601 (`P7D`) | pip 26.1 | pip user config (via `pip config --user set`) |
| `poetry` | `solver.min-release-age` | days (`7`) | Poetry 2.4 | Poetry config (via `poetry config`) |
| `cargo` | `[registry] global-min-publish-age` (and `[registries.crates-io] min-publish-age` if set) | duration (`"7 days"`) | Cargo 1.100 | `$CARGO_HOME/config.toml` (`~/.cargo/config.toml`) |

Homebrew, RubyGems, Go, Composer, Deno, conda, pixi, NuGet, Maven, Gradle
and CocoaPods are detected and listed as not covered: none has a
user-level minimum-age setting (Deno has one per project, in `deno.json`).

## Settings

One file, created with comments on first run:
`~/.config/lenstica/lenstica.toml` (`$XDG_CONFIG_HOME/lenstica/lenstica.toml`
when set; override with `--config FILE` or `LENSTICA_CONFIG`). Settings added
in newer versions are written into an existing file, with their comments, the
first time it is loaded; values already there are never changed.

```toml
min_days = 7

[monitor]
interval_minutes = 15
auto_apply = true          # re-fix missing/weaker settings, including newly installed managers
notify = true              # desktop notifications at all
alert_severity = "medium"  # lowest severity for the icon, counts and `lenstica check`
notify_severity = ""       # lowest severity notified; empty: alert_severity
notify_fixes = true        # also announce settings Lenstica restored by itself

[managers]
disabled = []              # e.g. ["poetry"]
extra_path = []            # more places to look for binaries, beyond PATH

[scan]
roots = ["~/Developer"]    # include: folders to search, or single repositories
exclude = []               # paths ("~/Developer/old") or folder names ("fixtures") to leave out
worktrees = true           # also every git worktree of the repositories found there
max_depth = 6

[audit]                    # the dependency lenses
enabled = true
interval_minutes = 30
global = true              # npm -g, pnpm -g, uv tools, pip --user
ignore = []                # "name" or "name@version" you have checked and accept
npm_registry = "https://registry.npmjs.org"
pypi_url = "https://pypi.org"

[install_scripts]
block = false

[homebrew]
no_auto_update = false     # true: keep HOMEBREW_NO_AUTO_UPDATE=1 in ~/.homebrew/brew.env

[software]                 # the software-age lens
package_managers = true
homebrew = true
casks = true
rust_toolchains = true
node = true
ignore = []                # "name" or "name@version"

[lenses.safe-chain]
enabled = true             # false: stop recommending Safe Chain

[lenses.agent-instructions]
ignore = []                # files or folders you have reviewed, e.g. ["~/.agents/skills/mine"]

[lenses.deprecated]
notify = false             # list a lens's findings without notifying them

[lenses.vulnerabilities]
refresh_hours = 6
ignore_advisories = []     # e.g. ["GHSA-xxxx-xxxx-xxxx"]
```

## Commands

```
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

## Things to know

- **To search only some repositories**, list them in `scan.roots` (include),
  or keep a broad root and leave folders out with `scan.exclude`. Excluding a
  repository excludes its worktrees too, wherever they live. Exclusions apply
  to every search: project settings, lockfiles and secrets. External tools are
  not run on an excluded root, but search everything inside the roots they get.
- **Project settings win.** A repository's own `pnpm-workspace.yaml` or
  `.npmrc` can lower the cooldown for that repository; `project-settings`
  reports those, it does not edit other people's repos.
- **Lockfiles are not re-checked by the package managers.** The cooldown
  applies when a version is resolved; `npm ci` and frozen-lockfile installs
  take what is pinned. That gap is what `package-age` covers.
- **An urgent fix younger than N days is blocked too.** Use the manager's own
  escape hatch for a one-off (`npm install --min-release-age=0 …`, pnpm
  `minimumReleaseAgeExclude`, uv `--exclude-newer-package`), or add the
  package to `audit.ignore` once checked.
- **"Locked while too new" is an upper bound.** Lockfiles do not record when a
  version was added; the file's last change (commit time when it matches git,
  else its mtime) is used, so a reported version really was too young, and
  one added well before the last change can be missed.
- **Yarn Classic** (1.x) has no age gate; Lenstica still writes
  `~/.yarnrc.yml`, which projects on Yarn 4.10+ read.
- Files Lenstica edits directly are backed up once as `<name>.lenstica-backup`.
- On macOS, notifications show Lenstica's name and icon when `Lenstica.app` is
  installed (in `/Applications` or `~/Applications`), from the menu bar app and
  the CLI alike, and are managed under System Settings → Notifications →
  Lenstica. A bare binary without the app falls back to `osascript`, which
  shows no icon. `lenstica test-notification` (or Settings → Notifications →
  Send a test) shows one and says which way it went. Apple's newer
  notification API needs a Developer ID signature; ad-hoc builds use the older
  one, which macOS still supports.
- `LENSTICA_DEBUG=1 lenstica tray` logs each action the window sends.

## Development

```sh
cargo test --workspace
cargo clippy --all-targets --workspace
LENSTICA_CROSS_CHECK=1 cargo check --target x86_64-pc-windows-msvc   # skips only the Windows resource step
cargo check --target x86_64-unknown-linux-gnu --no-default-features --features secrets
cargo tauri dev -- -- tray      # the app from a debug build (args after the second -- reach the binary)
```

To try changes without touching your real configs, run against a throwaway
home: `HOME=$(mktemp -d) cargo run -- apply`. Every path Lenstica reads or
writes is derived from `HOME` / `XDG_*` / `APPDATA`.

## License

The Lenstica core is free and open source under the [Apache License 2.0](LICENSE)
(`Apache-2.0`), including the `lenstica-lens` API crate and the built-in lenses:
anyone can use it, at work too, and build lenses on it. See [NOTICE](NOTICE).
Lenses run as `[[external]]` tools are separate programs with their own
licences. Team features (below and in [SPEC.md](SPEC.md)) will be a separate,
proprietary add-on unlocked by a licence key; the free core does not depend on
them and never will.

## Credits

Icons are from [Lucide](https://lucide.dev), ISC licence, kept in
`assets/lucide/` with their licence file.
