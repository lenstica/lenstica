# Lenses

Everything Lenstica checks is a **lens** producing findings in one format
(severity, category and topic, title, details, locations, remedy, links, and
whether it can fix it). The menu, the window, notifications and the CLI only
know findings, so a new lens shows up everywhere. `lenstica lenses` lists them.

- [Categories](#categories)
- [Third-party lenses are opt-in](#third-party-lenses-are-opt-in)
- [Built-in lenses](#built-in-lenses)
- [Dependencies: where packages are read from](#dependencies-where-packages-are-read-from)
- [Software ages](#software-ages)
- [Aikido Safe Chain](#aikido-safe-chain)
- [Exposed secrets](#exposed-secrets)
- [AI agent instructions](#ai-agent-instructions)
- [Listening ports](#listening-ports)

To add your own, see [Writing lenses](writing-lenses.md).

## Categories

Every lens registers with one or more categories, and every finding names one
and, usually, a topic within it. The window has a page per category and the
menu bar menu a submenu per category; a category no lens covers is not shown.

| Category (id) | Topics | Lenses |
|---------------|--------|--------|
| AI agents (`agents`) | Prompt injection, Hidden text, Elevated permissions, Rules violations, MCP servers | `agent-instructions` |
| Packages (`packages`) | Cooldown, Install scripts, Vulnerabilities, Deprecated | `package-managers`, `project-settings`, `package-age`, `install-scripts`, `deprecated`, `vulnerabilities` |
| Software (`software`) | Too new, Outdated, Auto updates | `software`, `homebrew-updates` |
| Secrets (`secrets`) | Exposed, Leaked | `secrets`; gitleaks and trufflehog as external tools |
| Malware (`malware`) | | `vulnerabilities` (malicious releases), `aikido-malware`, `safe-chain` |
| Network (`network`) | Open ports | `listening-ports` |
| Privacy (`privacy`) | Telemetry | `aikido-malware` (its telemetry list) |

Rules violations and Outdated are there for lenses to report; no built-in
lens does yet. `lenstica findings --category <id>` and the MCP server filter
by category.

## Third-party lenses are opt-in

A lens that relies on a third party, a service it sends data to or a tool it
runs or recommends, is off until you turn it on, in its category's page or
with `enabled = true` under `[lenses.<id>]`:

| Lens | Relies on |
|------|-----------|
| `vulnerabilities` | OSV.dev: the names and versions of your locked and installed packages are sent to it |
| `aikido-malware` | Aikido Security: its malware, protestware and telemetry lists are downloaded (whole, so no package names are sent) |
| `safe-chain` | Aikido Safe Chain: recommends installing it, and can run its `safe-chain setup` |

External tools under `[[external]]` are yours to add, so they run once declared.

## Built-in lenses

| id | What it finds | Severity |
|----|---------------|----------|
| `package-managers` | A package manager without the cooldown, a weaker one, or too old to have it. Re-applied automatically (`monitor.auto_apply`); click to fix. | high / medium |
| `project-settings` | Repository files that lower the cooldown (`.npmrc`, `pnpm-workspace.yaml`, `.yarnrc.yml`, `bunfig.toml`, `uv.toml`, `pyproject.toml`, `poetry.toml`, `pip.conf`). Reported, never edited. | medium |
| `package-age` | Locked or installed versions published less than N days ago; and ones that were that young when their lockfile last changed. | medium / info |
| `vulnerabilities` (opt-in) | Known vulnerabilities and **malicious releases**, from [OSV.dev](https://osv.dev) (GitHub, PyPI, RustSec and OpenSSF malicious-packages advisories; RustSec's unmaintained and unsound notices are informational). Malicious releases go under Malware, always critical, with a remedy that assumes compromise. | per advisory; malware critical |
| `aikido-malware` (opt-in) | Locked and installed npm and PyPI packages on [Aikido Intel](https://intel.aikido.dev)'s malware, protestware and telemetry lists, the lists [Safe Chain](https://github.com/AikidoSec/safe-chain) blocks downloads with. A second malware source beside OSV.dev. The lists are downloaded whole (about 11 MB, refreshed every 6 hours with an ETag), so no package names are sent. | malware critical, protestware high, telemetry low |
| `deprecated` | Versions deprecated on npm or yanked on PyPI or crates.io. | info / low |
| `software` | Installed **software** published less than N days ago ([below](#software-ages)): the package managers themselves, Homebrew formulae and casks, Rust toolchains, Node.js. | medium |
| `homebrew-updates` | Homebrew fetching the newest formulae before every install. Click to set `HOMEBREW_NO_AUTO_UPDATE=1` in `~/.homebrew/brew.env`, or set `homebrew.no_auto_update = true`. | low |
| `safe-chain` (opt-in) | Whether Aikido Safe Chain is installed and loaded by your shells; recommends it when it is not ([below](#aikido-safe-chain)). Click to run `safe-chain setup`. | info / low |
| `install-scripts` | Package managers that run dependencies' install scripts (how Shai-Hulud-style worms execute). Click to block, or set `install_scripts.block = true`. | low |
| `secrets` | Credentials malware running as you could steal ([below](#exposed-secrets)). A plugin crate. | critical … info |
| `listening-ports` | Programs that other devices on your network can connect to: debuggers, the Docker API, databases, container ports and development servers bound to every interface instead of localhost ([below](#listening-ports)). | critical … info |
| `agent-instructions` | AI agent instruction files (CLAUDE.md, AGENTS.md, rules, skills, plugins, hooks, MCP configs) with hidden text, prompt injection, credential-leaking or remote-code instructions, and settings that let an injected instruction run without asking ([below](#ai-agent-instructions)). Click to strip invisible characters. | critical … low |

Per-lens settings live under `[lenses.<id>]` in the settings file, with
`enabled`, `interval_minutes` and the lens's own keys. See
[Configuration](configuration.md).

## Dependencies: where packages are read from

Packages are read from every lockfile under `scan.roots` and **every git
worktree** of the repositories found there (`package-lock.json`,
`npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `uv.lock`,
`poetry.lock`, `Cargo.lock`), plus `npm -g`, `pnpm -g`, uv tools, `pip --user`
and `cargo install`. Crate publish times and yanked status come from the
crates.io sparse index; crate advisories (RustSec) from OSV.dev.

Package **names and versions** of public npm, PyPI and crates.io packages are
sent to those registries, and to OSV.dev when the `vulnerabilities` lens is on. Workspace, git, path, tarball and
private-registry entries are skipped where the lockfile records the registry
(npm, pnpm tarballs, Yarn 1, Bun, uv, Poetry, Cargo); Yarn 2+ lockfiles and
pnpm's scoped registries do not, so packages from an `npmScopes` or
`@scope:registry` registry are looked up on npm by name
([#30](https://github.com/lenstica/lenstica/issues/30)). Publish times and advisories are
cached, so after the first run (a minute or two for a large monorepo) passes
take seconds. Each package is re-checked against OSV every 6 hours
(`[lenses.vulnerabilities] refresh_hours`), because advisories, malware
above all, are published for versions people already have.

## Software ages

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

## Aikido Safe Chain

Lenstica and [Safe Chain](https://github.com/AikidoSec/safe-chain) cover
different moments. Safe Chain wraps npm, npx, Yarn, pnpm, Bun, pip, uv, Poetry
and pipx in your shell and checks each download against Aikido's malware lists
before it reaches the disk, and can also hold back very new versions.
Lenstica sets each package manager's own minimum age (which applies however
the tool is started, also from an editor or a script) and audits what is
already installed, after the fact. Using both is sensible.

- `safe-chain` reports whether it is installed and which shells load it
  (`~/.zshrc`, `~/.bashrc`, fish, PowerShell, or its shims on PATH).
- `aikido-malware` checks your lockfiles and global installs against the same
  lists Safe Chain uses, so a package it would have blocked is found even if it
  got in another way. The lists are served by Aikido without an account; their
  terms of use are not published with them, so check Aikido's terms before
  using them commercially. Turn it off with `[lenses.aikido-malware] enabled = false`.

## Exposed secrets

A malicious install script runs as you, so file permissions do not stop it
reading your credentials. What helps is fewer, shorter-lived secrets in fewer
places; every finding says how. **No secret value is ever stored or shown**:
findings name the file, the setting or variable names and the kind of
credential.

- Cloud and registry credentials: long-lived AWS keys (`AKIA…`) in
  `~/.aws/credentials`, active AWS SSO sessions and cached role credentials,
  npm, PyPI and Cargo registry tokens, Docker registry passwords without a
  credential helper, static kubeconfig credentials, the GitHub CLI token in
  plain text, `.git-credentials`, `.netrc`, Terraform and Google Cloud
  credentials.
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

## AI agent instructions

Coding agents load some files as instructions from you: CLAUDE.md and
AGENTS.md, rules, skills, slash commands, subagents, auto memory, plugins,
hooks and MCP server definitions. A poisoned one (a plugin, a cloned
repository, a pull request that edits AGENTS.md) can make an agent leak
credentials or run code. `agent-instructions` reads them for:

- **Hidden text**: Unicode tag characters and variation-selector runs (text
  editors and GitHub do not show them, but models read them; the hidden text
  is decoded and checked too), bidirectional controls, zero-width characters.
  Click to strip them; the original is kept as `<name>.lenstica-backup`.
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
  "follow the instructions at <url>". High in hook and MCP definitions (they
  run on their own), medium in the scripts hooks and skills run, low in prose
  (install instructions often look like this).
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

## Listening ports

A laptop joins office, home, café, hotel and conference networks, and every
device on them can connect to whatever listens on an address other than
loopback (`127.0.0.1`, `::1`). The `listening-ports` lens asks the operating
system which TCP ports are listening and which program owns each one, then
reports what other devices can reach:

| What | Examples | Severity | One finding per |
|------|----------|----------|-----------------|
| Debuggers and remote control | Node.js inspector (9229), Chrome remote debugging (9222), debugpy (5678), Java JDWP (5005), Docker Engine API without TLS (2375) | critical | port |
| Databases and brokers | PostgreSQL, MySQL, MongoDB, Redis, Memcached, Elasticsearch, ClickHouse, CouchDB, Cassandra, Neo4j, RabbitMQ, Kafka, SQL Server, etcd, CockroachDB, InfluxDB | high | port |
| Jupyter | 8888 | medium | port |
| Container ports | Published by Docker, OrbStack, Podman or Lima without an address, so on every interface | medium | program |
| Development servers | Node.js, Deno, Bun, Python, Ruby, PHP, Java, .NET, Erlang/Elixir | medium | program |
| Anything else | AirPlay Receiver, sync and sharing apps | info | program |

Known services are recognised by their default port, or by process name on
any port (`postgres`, `redis-server`, `mongod` …). Each finding names the
program, its process IDs and addresses, and a remedy for that service: bind
to `127.0.0.1`, or publish container ports as `127.0.0.1:5432:5432`
(Docker's `"ip": "127.0.0.1"` in daemon.json makes that the default).

What only this machine can reach is listed as checked. Everything appears on
the window's **Network** page and in `lenstica network`.

- **Only programs running as you are visible.** Without administrator rights
  the OS does not say which program owns another user's socket. Development
  servers, databases from Homebrew and container runtimes run as you; system
  services such as a root-owned `sshd` are left out.
- **TCP only.** UDP has no listening state, and the many sockets apps open
  for their own replies would drown out the few that matter.
- **Firewalls are not taken into account yet.** A program your firewall
  blocks is still reported.

To accept one, click **Ignore** on the finding, or list it in
`[lenses.listening-ports] ignore` as a port (`"5432"`), a program (`"Orca"`)
or both (`"node:3000"`).
