# Lenstica: product and engineering spec

**Every vulnerability, through the right lens.**

This file is where we track what Lenstica is, what has been built, how we
build it, and what comes next. Write a future feature down here first;
building it is a separate decision. Update the status of an item when its
work lands, and add a line to the [work log](#9-work-log) when something
ships.

| Status | Meaning |
|--------|---------|
| ✅ | Done and shipped in the current build |
| 🚧 | Being built |
| 📋 | Planned: agreed, designed here, not started |
| 💡 | Idea: worth recording, not yet agreed |

- Website: [lenstica.com](https://lenstica.com)
- Source (public, Apache 2.0): [github.com/lenstica/lenstica](https://github.com/lenstica/lenstica)
- Private code (team edition, premium lenses): a separate private repository, see [§3.4](#34-repositories)

---

## Contents

1. [Vision](#1-vision)
2. [Principles](#2-principles)
3. [Editions and business model](#3-editions-and-business-model)
4. [Architecture](#4-architecture)
5. [Lenses](#5-lenses)
6. [Requirements](#6-requirements)
7. [Development process](#7-development-process)
8. [Roadmap and backlog](#8-roadmap-and-backlog)
9. [Work log](#9-work-log)
10. [Decisions](#10-decisions)
11. [Open questions](#11-open-questions)
12. [Glossary](#12-glossary)

---

## 1. Vision

Developer machines are where supply-chain attacks land: a malicious package
version, a poisoned AI-agent instruction, a stolen token in a dotfile. Each
risk needs a different way of looking. **Lenstica is a library of security
lenses you look through**: every lens is a focused check for one kind of risk,
and every lens reports in the same format, so the menu bar, the window,
notifications, the CLI and AI agents show all of them without knowing which
lens found what.

- **For individual developers:** a free, local tool that is useful on its own
  from the first minute. It sets safe defaults (a 7-day cooldown on every
  package manager) and keeps watching.
- **For teams:** the same app, unlocked by a licence key, with one set of
  rules enforced on every developer's machine and visibility across all of
  them. This is the problem that only appears at scale, and it is what we
  sell.
- **For the community:** anyone can write a lens. Later, people can publish
  lenses and install other people's from a registry.

The free tool is the sales pitch. It should find enough real risk on a
developer's machine that their team wants central visibility.

## 2. Principles

1. **Local first.** Everything runs on the machine. What leaves it is listed in
   the README (package names and versions to public registries and OSV.dev, the
   Aikido lists downloaded whole). The free edition sends nothing to Lenstica.
2. **Never store or show a secret value.** Findings name the file, the setting
   or variable name and the kind of credential, never the contents. This
   applies to every lens, to logs, to prompts handed to AI agents, and to
   anything a future team edition uploads.
3. **One finding format.** A new lens appears everywhere (menu, window,
   notifications, CLI, MCP, prompts) without UI changes.
4. **Useful without setup.** Safe defaults; one settings file
   (`~/.config/lenstica/lenstica.toml`) with comments; everything also in the
   Settings window.
5. **Fix, don't just report.** Each finding has a remedy; where Lenstica can
   fix it safely it does it on a click, and keeps a `.lenstica-backup` of any
   file it edits.
6. **Practise what we preach.** Lenstica's own dependencies are held to the
   7-day cooldown (`cargo update --precise` to a version at least 7 days old).
7. **Free core, paid organisation features.** The free edition is never a
   trial and never time-limited. Paid features are gated by a licence key in
   the same binary, not by a fork.
8. **Patterns are hints, not verdicts.** Heuristic lenses (agent instructions)
   say "read these lines", show only the matched words, and are tuned against
   real machines for false positives before they ship.

## 3. Editions and business model

### 3.1 Free (Apache 2.0)

| Feature | Status |
|---------|--------|
| Local scanning and monitoring: every built-in lens ([§5](#5-lenses)) | ✅ |
| Menu bar app and window (macOS, Windows, Linux) | ✅ |
| CLI for scripts and CI (`lenstica check` exits 1 on findings) | ✅ |
| AI-agent integration: copy-a-prompt, the skill, the MCP server | ✅ |
| Your own lenses: Rust crate or any executable (`[[external]]`) | ✅ |
| Installing community lenses (`lenstica lens install`) | 📋 [F-10](#f-10-lens-installation) |
| IDE integration (VS Code / JetBrains extension showing findings for the open repository) | 💡 [F-14](#f-14-ide-integration) |
| Single developer, unlimited machines of their own | ✅ |

### 3.2 Team and Enterprise (proprietary, licence-key gated)

| Feature | Status |
|---------|--------|
| Central policy management: push rules to every developer ([T-1](#t-1-central-policy)) | 📋 |
| Team / enterprise dashboard ([T-2](#t-2-dashboard)) | 📋 |
| Compliance reporting and audit logs ([T-3](#t-3-compliance-and-audit-logs)) | 📋 |
| SSO and RBAC ([T-4](#t-4-sso-and-rbac)) | 📋 |
| Lens marketplace, premium lenses, private lens sharing ([T-5](#t-5-premium-lenses-and-private-lenses)) | 📋 |
| Managed rollout to N machines ([T-6](#t-6-managed-rollout)) | 📋 |
| SLA and priority support ([T-7](#t-7-support)) | 📋 |
| Licence keys and runtime feature flags ([T-0](#t-0-licence-keys)) | 📋 |

### 3.3 Pricing principles

- **Per seat, per month** (a seat is a developer, not a machine). Predictable
  and easy to budget; never per scan or per finding.
- **The free tier is a hard cap, not a trial.** Proposed: team features free
  for up to 3 developers (proposed limit; see [Q-1](#11-open-questions)),
  forever. No time-limited trials.
- **Same binary.** Upgrading from free to paid is entering a licence key or
  signing in, not reinstalling.
- **Let the free tier find the problem.** Free lenses surface real risk;
  the paid tier answers "is this happening on everyone's machine, and is it
  fixed?".

This is the open-core model Semgrep, Snyk and CodeQL use.

### 3.4 Repositories

| Repository | Visibility | Contents |
|------------|------------|----------|
| `lenstica/lenstica` | Public, Apache 2.0 | The app and CLI, the `lenstica-lens` API crate, built-in lenses, the free features, the hooks the team edition plugs into (policy loading, licence check, report upload) |
| `lenstica/lenses` | Public 💡 | The community lens registry index ([F-11](#f-11-lens-registry)) |
| `lenstica/lenstica-cloud` (name to confirm, [Q-2](#11-open-questions)) | Private | Control plane, dashboard, licence server, premium lenses, enterprise connectors |
| `lenstica/lenstica.com` | Private or public | The website and docs |

Rule: the public repository must build and work fully without the private
one. The team edition adds capabilities through the licence key and a
server; it never removes free ones.

## 4. Architecture

### 4.1 Components

```
lenstica (one binary: CLI + menu bar app + MCP server)
├── crates/lenstica-lens      public lens API: Finding, Report, Context, Lens trait
├── crates/lenstica-secrets   the secrets lens, a plugin crate built on that API
├── src/lenses/               built-in lenses, registry, runner, result store
├── src/managers/             package-manager adapters (npm, pnpm, Yarn, Bun, uv, pip, Poetry, Cargo)
├── src/audit/                lockfile and global-install inventory, registry publish times
├── src/gui/                  tray menu, window (Tauri), scheduler
├── src/mcp.rs, src/agent.rs, src/prompt.rs   AI-agent integrations
├── src/config.rs             the settings file (template, validation, migration of new keys)
├── src/migrate.rs            moving over from the pre-rename `cooldown` paths
└── assets/ui/                the window (plain HTML/JS, rendered by the system web view)
```

### 4.2 How a lens runs

1. The registry (`src/lenses/mod.rs`) lists every lens: built-in, plugin crate,
   or external executable from `[[external]]`.
2. The scheduler runs each enabled lens when it is due (per-lens interval, or
   at once when a file in its `watch` list changes).
3. The lens gets a `Context` (minimum age, search roots and exclusions, its
   `[lenses.<id>]` settings, a state directory, the shared package inventory)
   and returns a `Report` (findings, summary, passing checks, actions taken,
   files to watch).
4. The store (`~/.local/state/lenstica/findings.json`) keeps the latest result
   per lens and notifies each new finding once (by key).
5. Everything that shows results reads the store: menu, window, CLI, MCP.

### 4.3 Where things live

| What | Where |
|------|-------|
| Settings | `~/.config/lenstica/lenstica.toml` (`$XDG_CONFIG_HOME`, `LENSTICA_CONFIG`) |
| Results and caches | `~/.local/state/lenstica/` (`$XDG_STATE_HOME`) |
| macOS app | `Lenstica.app`, bundle id `com.lenstica.app` |
| macOS login item | `~/Library/LaunchAgents/com.lenstica.agent.plist`, log `~/Library/Logs/lenstica.log` |
| Linux login item | `~/.config/autostart/lenstica.desktop` or `systemd --user lenstica.service` |
| Windows login item | `HKCU\…\Run\Lenstica` |
| Agent skill | `~/.claude/skills/lenstica/SKILL.md` (only when the user installs it) |

### 4.4 Platforms

macOS (primary, tested on the author's machine), Windows and Linux (compile
checks in development; native bundles built by `.github/workflows/release.yml`).
Headless Linux runs `lenstica watch` as a systemd user service.

## 5. Lenses

A **lens** is one focused check. Kinds:

- **Built-in:** compiled into Lenstica (`src/lenses/`).
- **Plugin crate:** a Rust crate implementing `lenstica_lens::Lens`, compiled in
  behind a feature (`lenstica-secrets` is the example).
- **External:** any executable declared under `[[external]]`, printing
  Lenstica's JSON report (`format = "lenstica"`), or a known scanner whose
  output Lenstica translates (`gitleaks`, `osv-scanner`, `trufflehog`).
- **Installed (planned):** an external lens installed from a git repository or
  the registry ([F-10](#f-10-lens-installation)).

### 5.1 Current lenses

| Id | Looks for | Status |
|----|-----------|--------|
| `package-managers` | A package manager without the cooldown (minimum release age), a weaker one, or too old to have it; re-applies it automatically | ✅ |
| `project-settings` | Repository files that lower the cooldown (`.npmrc`, `pnpm-workspace.yaml`, `uv.toml`, …) | ✅ |
| `package-age` | Locked or installed versions younger than the cooldown, or that young when their lockfile changed | ✅ |
| `vulnerabilities` | Known vulnerabilities and malicious releases from OSV.dev | ✅ |
| `aikido-malware` | Packages on Aikido Intel's malware, protestware and telemetry lists | ✅ |
| `deprecated` | Deprecated (npm) or yanked (PyPI, crates.io) versions | ✅ |
| `software` | Installed software younger than the cooldown: package managers, Homebrew formulae and casks, Rust toolchains, Node.js | ✅ |
| `install-scripts` | Package managers that run dependencies' install scripts | ✅ |
| `homebrew-updates` | Homebrew updating itself before every install | ✅ |
| `safe-chain` | Whether Aikido Safe Chain is installed and loaded | ✅ |
| `secrets` | Credentials on disk: cloud keys, registry tokens, SSH keys without a passphrase, `.env` files, shell history (plugin crate) | ✅ |
| `agent-instructions` | CLAUDE.md, AGENTS.md, rules, skills, plugins, hooks and MCP configs with hidden text, prompt injection, credential-leak or remote-code instructions, weak agent settings | ✅ |

### 5.2 Planned and proposed lenses

| Id | Looks for | Status |
|----|-----------|--------|
| `agent-sessions` | [L-1](#l-1-agent-session-logs): secrets in AI-agent session logs; hidden instructions an agent received in tool results | 📋 |
| `containers` | [L-2](#l-2-containers): Dockerfiles, compose and devcontainer files with unpinned or `:latest` images, `curl \| sh`, unpinned features | 📋 |
| `container-images` | [L-3](#l-3-container-images): local images younger than the cooldown; image vulnerabilities through Trivy or Grype | 💡 |
| `ci-workflows` | [L-4](#l-4-ci-workflows): GitHub Actions pinned by tag instead of SHA, `pull_request_target` with checkout, secrets in logs | 💡 |
| `editor-extensions` | [L-5](#l-5-editor-extensions): VS Code / Cursor / JetBrains extensions younger than the cooldown or known malicious | 💡 |
| `browser-extensions` | [L-6](#l-6-browser-extensions): browser extensions with broad permissions installed recently | 💡 |
| `git-hooks` | [L-7](#l-7-git-hooks): repository hooks and `core.hooksPath` running downloaded code | 💡 |

## 6. Requirements

### 6.1 Functional

| Id | Requirement | Status |
|----|-------------|--------|
| R-1 | Set a minimum release age (default 7 days, 1–365) in every supported package manager's user-level config, and keep it there | ✅ |
| R-2 | Turn each package manager and each lens on or off in Settings | ✅ |
| R-3 | Limit searching to chosen folders (`scan.roots`) and exclude folders or names (`scan.exclude`); include git worktrees | ✅ |
| R-4 | Every finding: severity, category, title, details, locations, remedy, links, fixable; stable key; notified once | ✅ |
| R-5 | Menu bar: overall state, every lens with its findings, Fix It, Open file, Copy Prompt for AI Agent, Show in Lenstica; Open Lenstica ⌘O, Settings ⌘,, Quit ⌘Q | ✅ |
| R-6 | Window: overview, findings with filters and deep links, lenses, settings | ✅ |
| R-7 | Notifications: on/off, minimum severity, per lens, for automatic fixes; show the app's name and icon | ✅ |
| R-8 | AI agents: copy a prompt per finding or for all; a skill; an MCP server (status, findings, finding, prompt, run, fix) | ✅ |
| R-9 | Start at login on every platform | ✅ |
| R-10 | Accept a finding: `audit.ignore`, `software.ignore`, `[lenses.<id>] ignore`, advisory ignores | ✅ |
| R-11 | Install, update and remove third-party lenses safely | 📋 F-10 |
| R-12 | Organisation policy that a developer cannot weaken locally | 📋 T-1 |

### 6.2 Non-functional

| Id | Requirement | Status |
|----|-------------|--------|
| N-1 | No secret value is ever stored, logged, displayed, notified or put in a prompt | ✅ |
| N-2 | A lens run must not stall the app: per-tree file limits, size caps, caches with TTLs, incremental work where data is large | ✅ |
| N-3 | Works offline with cached data; network lenses report a failure instead of a false all-clear | ✅ |
| N-4 | Files Lenstica edits keep a one-time `.lenstica-backup` | ✅ |
| N-5 | Builds on macOS, Windows and Linux; headless build without GUI libraries | ✅ |
| N-6 | Dependencies at least 7 days old when added or updated | ✅ |
| N-7 | Prompts and findings about agent instructions carry no payload text beyond the matched phrase, and tell the agent the file is untrusted | ✅ |
| N-8 | Signed and notarised builds (Apple Developer ID, Windows code signing) | 📋 [F-20](#f-20-signing-and-notarisation) |

## 7. Development process

### 7.1 How a change is made

1. **Request**: the change is described (in chat, an issue, or this file).
   If it is a future feature, it goes in [§8](#8-roadmap-and-backlog) first.
2. **Decide what is the user's call.** Licence, naming, scope and anything
   outward-facing are asked about, with a recommendation, before building.
3. **Implement** in the existing patterns: a lens for a new kind of check, the
   finding format for output, the settings file plus the Settings window for
   options.
4. **Test on a sandbox first.** Run against a throwaway home
   (`HOME=$(mktemp -d)` or `XDG_STATE_HOME=/tmp/...`) so real configs and
   stored results are not touched; plant the bad case (a malicious skill, an
   old config) and check it is found.
5. **Tune against the real machine.** Run the lens on the author's machine,
   read what it flags, and remove false positives before shipping (the
   agent-instructions lens went from 200 findings to 7 this way).
6. **Verify**: `cargo test --workspace`, `cargo clippy --all-targets
   --workspace` clean, Windows and Linux compile checks, and the UI in a
   browser preview where it changed.
7. **Install and restart**: build the app bundle, sign it (ad hoc for now),
   install it, restart the login item, and check the running app.
8. **Report** what changed, what was verified, and what was not.
9. **Record**: update the status here and add a work-log line.

### 7.2 Rules

- **Commit and push only when asked.** No AI tool credits in commits or PRs.
- **Never print or store secret values**, also while developing: inspect
  config files by key names, never `cat` a credentials file.
- **Pin new dependencies** to a release at least 7 days old (`cargo add`, then
  `cargo update -p <crate> --precise <version>` if the newest is younger).
- **Prefer crates already in `Cargo.lock`** over new ones.
- **No unrequested side effects** on the user's machine (installing skills,
  registering MCP servers, changing settings); offer them instead.
- **Keep the README and this file current** with every user-visible change.

### 7.3 Commands

```sh
cargo test --workspace
cargo clippy --all-targets --workspace
LENSTICA_CROSS_CHECK=1 cargo check --target x86_64-pc-windows-msvc
cargo check --target x86_64-unknown-linux-gnu --no-default-features --features secrets
cargo tauri build --bundles app            # macOS app bundle
codesign -s - -f --deep target/release/bundle/macos/Lenstica.app
LENSTICA_DEBUG=1 lenstica tray             # log window actions and the menu tree
lenstica test-notification                 # check notifications and their icon
```

### 7.4 Releases

Tags `v*` run `.github/workflows/release.yml`, which builds native bundles on
each platform and attaches them to a draft release. Versioning: semantic,
`0.x` until the lens API is declared stable ([F-12](#f-12-stable-lens-api)).

## 8. Roadmap and backlog

### 8.1 Next up (free edition)

#### F-1 Publish the repository
🚧 Pushed to `github.com/lenstica/lenstica` (public, `main`, 2026-11-02). Still to do: CI (tests, clippy,
cross-checks on every PR), branch protection, issue templates, `CONTRIBUTING.md`
with the DCO ([D-9](#10-decisions)), `SECURITY.md` with a disclosure address
at lenstica.com.

#### F-2 Website
📋 lenstica.com: what it is, install, the lens catalogue, docs generated from
the README, pricing page for the team edition.

#### F-20 Signing and notarisation
📋 Apple Developer ID and notarisation, so the app opens without Gatekeeper
warnings and can use Apple's User Notifications API (ad-hoc builds are refused
permission; they use the older NSUserNotification path today). Windows code
signing. Homebrew cask and winget manifests once signed.

#### F-14 IDE integration
💡 A VS Code / Cursor extension and a JetBrains plugin that read the same
store (or the MCP server) and show the findings for the open repository
inline, with Fix and Copy Prompt.

### 8.2 Lenses to build

#### L-1 Agent session logs
📋 Session transcripts (Claude Code `~/.claude/projects/*/*.jsonl`, Codex
`~/.codex/sessions`, Gemini, Copilot, Cursor) keep everything an agent printed,
forever, in plain text.
- **Secrets in session logs**: reuse the secrets lens's token shapes (GitHub,
  npm, AWS, Anthropic, OpenAI, Slack, Stripe, private keys). Report counts and
  kinds per session file, never values. Remedy: delete or redact the session,
  rotate the credential.
- **Hidden instructions received**: invisible tag characters or known
  exfiltration endpoints inside tool results (web pages, MCP replies). No
  phrase matching here; ordinary sessions are full of quoted injection text.
- **Incremental**: remember size and offset per file; logs here are 4+ GB.

#### L-2 Containers
📋 In each repository: Dockerfiles, compose files, `devcontainer.json`.
Base images `:latest` or not pinned to a digest, `curl | sh` in `RUN`,
unpinned devcontainer features, `docker.sock` mounts, `--privileged`. No
daemon needed.

#### L-3 Container images
💡 Local images created less than the cooldown ago (Docker has no age gate).
Image vulnerabilities through Trivy, Grype or Docker Scout as external
formats.

#### L-4 CI workflows
💡 GitHub Actions referenced by tag instead of commit SHA, actions younger
than the cooldown, `pull_request_target` with a checkout of the PR,
`permissions: write-all`.

#### L-5 Editor extensions
💡 VS Code, Cursor, JetBrains extensions: version age, known-malicious lists,
auto-update settings.

#### L-6 Browser extensions
💡 Recently installed or updated extensions with access to all sites.

#### L-7 Git hooks
💡 `.git/hooks`, `core.hooksPath`, husky and lefthook configs that download
and run code.

### 8.3 The lens ecosystem

#### F-10 Lens installation
📋 Designed, not built ([D-6](#10-decisions)). Today any executable already
runs as a lens through `[[external]]`. Installation adds discovery, pinning
and trust.

- **Manifest** `lens.toml` at the root of a lens repository:
  ```toml
  id = "acme-terraform"            # unique; registry names are namespaced: publisher/id
  name = "Terraform state"
  version = "1.2.0"
  description = "Terraform state files with secrets in plain text"
  license = "Apache-2.0"
  command = ["bin/lens", "--root", "{root}"]   # or a script run by a declared interpreter
  format = "lenstica"              # or gitleaks / osv-scanner / trufflehog
  per_root = true
  interval_minutes = 240
  platforms = ["macos", "linux", "windows"]
  [permissions]
  network = ["api.example.com"]    # hosts it may contact; none by default
  read = ["{roots}", "~/.terraform.d"]
  write = []                       # lenses do not write by default
  ```
- **Commands**: `lenstica lens install <git-url>[@tag] | <registry-id>`,
  `lens list`, `lens update`, `lens remove`, `lens search`, `lens info`.
- **Pinning**: install resolves a tag to a commit SHA and records it with a
  content checksum in `~/.config/lenstica/lenses.lock`. Updates are explicit.
- **Cooldown for lenses**: a lens release younger than `min_days` is not
  installed or updated unless asked with `--allow-young`. Lenstica applies
  its own rule to its plugins.
- **Trust prompt**: before the first run, show publisher, licence, the
  command, and the permissions requested. In the window and the CLI.
- **Sandboxing**: run installed lenses with only the permissions they declare
  (macOS `sandbox-exec` profile, Linux Landlock and seccomp, Windows AppContainer
  where possible); no network unless declared; never the user's credential
  files unless declared and approved.
- **Output rules**: installed lenses' findings go through the same filter as
  external tools (secret values discarded; size limits).
- **Signing** (later): releases signed with Sigstore or minisign; verified
  publishers in the registry.

#### F-11 Lens registry
💡 A public index (`github.com/lenstica/lenses`, like the crates.io index):
one file per lens with publisher, repository, released versions with commit
SHAs, checksums and release dates, licence, permissions, platforms. Browsed on
lenstica.com and with `lenstica lens search`. Verified publishers, yanking,
malware reports. Premium lenses are listed but downloaded only with a licence
([T-5](#t-5-premium-lenses-and-private-lenses)).

#### F-12 Stable lens API
💡 Declare `lenstica-lens` 1.0: the `Lens` trait, `Finding`, `Report`,
`Context`, and the JSON report format, with a compatibility promise and a
schema file for non-Rust lens authors. A lens SDK and template repositories
for Rust, Go, Python and TypeScript.

#### F-13 Lens authoring docs
💡 "Write a lens" guide, the JSON schema, test harness (`lenstica lens test`
runs a lens against fixtures and validates its report).

### 8.4 Team and enterprise edition

All of these live in the private repository and the Lenstica server; the
public binary contains only the hooks (policy loading, licence verification,
report upload), each inactive without a licence.

#### T-0 Licence keys
📋 A licence is a signed token (Ed25519): organisation, seat count, features,
expiry. Verified offline by the binary (public key compiled in), refreshed
from the server when online, with a grace period. Features are checked at
runtime (`license::has(Feature::Policy)`). Same binary for free and paid.

#### T-1 Central policy
📋 An organisation pushes a signed policy bundle:
- minimum age, required lenses, required package-manager settings
  (install scripts blocked, Homebrew auto-update off), severity thresholds,
  notification rules;
- allowlists and accepted findings, shared across the team;
- MCP-server and agent-setting rules (no `bypassPermissions`, pinned MCP
  servers only).

The app shows enforced settings as locked ("Set by your organisation").
Delivery: pulled from the server with a device token, or installed by MDM as a
managed preferences file. A developer can be stricter locally, never weaker.

#### T-2 Dashboard
📋 Web dashboard: machines, developers, lens results per machine, trends,
what is unfixed and for how long, outliers. Data uploaded is the finding
metadata (lens, key, severity, category, title, location labels), never secret
values; path detail configurable per organisation for privacy.

#### T-3 Compliance and audit logs
📋 Audit log of policy changes, accepted findings and who accepted them;
reports mapping lenses to controls (SOC 2 CC7/CC8, ISO 27001 A.8, SLSA,
NIST SSDF); exports (CSV, PDF, SIEM webhook).

#### T-4 SSO and RBAC
📋 SAML and OIDC sign-in for the dashboard and device enrolment; roles
(owner, admin, security, viewer); SCIM provisioning.

#### T-5 Premium lenses and private lenses
📋 Premium lenses maintained by Lenstica (for example: deeper malware
intelligence, cloud-credential exposure checks, enterprise tool integrations),
downloaded with a licence. Organisations can publish private lenses to their
own members only (custom rule sharing).

#### T-6 Managed rollout
📋 Install and configure on N machines: signed `.pkg` and `.msi` with an
enrolment token, MDM profiles (Jamf, Kandji, Intune), status of every
enrolled machine, forced updates within a window.

#### T-7 Support
📋 SLA and priority support for paid plans.

### 8.5 Smaller items

| Id | Item | Status |
|----|------|--------|
| S-1 | "Accept" a finding from the window (writes the right ignore list) | 💡 |
| S-2 | Settings UI for `[lenses.agent-instructions] ignore` | 💡 |
| S-3 | Dedicated Settings page per lens, generated from a lens's declared options | 💡 |
| S-4 | `lenstica doctor`: explain why a package manager is not configured | 💡 |
| S-5 | Localisation of the window and notifications | 💡 |
| S-6 | Remove the migration from `cooldown` after a few releases | 📋 |

## 9. Work log

Newest last. Dates are when the work landed in the local build.

| Date | Work |
|------|------|
| 2026-10 | First version as `cooldown`: minimum release age written into npm, pnpm, Yarn, Bun, uv, pip, Poetry and Cargo; project settings that weaken it; menu bar app (Tauri) and CLI |
| 2026-10 | Dependency audit: package age, OSV.dev vulnerabilities and malware, deprecated and yanked versions; lockfile inventory incl. git worktrees |
| 2026-10 | Secrets lens as a plugin crate on the public API; external lenses (`[[external]]`, gitleaks, osv-scanner, trufflehog formats) |
| 2026-10 | Install-scripts lens; window with overview, findings, settings |
| 2026-11 | Aikido malware lists lens; Safe Chain lens; settings toggles per lens and per package manager; include/exclude folders |
| 2026-11 | Software ages lens (package managers, Homebrew formulae and casks, Rust toolchains, Node.js); Homebrew auto-update lens |
| 2026-11 | Menu redesign (coloured state icons, severity icons, submenus per finding, ⌘O/⌘,/⌘Q); copy-a-prompt for AI agents; MCP server; agent skill; notification settings |
| 2026-11 | 7-day default documented with sources; "Recommended" tag in Settings |
| 2026-11-02 | Agent-instructions lens (hidden text, injection phrasing, credential leaks, remote code, weak agent settings; fix strips invisible characters) |
| 2026-11-02 | Notifications carry the app icon (posted as the installed app); `lenstica test-notification` and Settings → Send a test |
| 2026-11-02 | Renamed to **Lenstica** (checkers are now lenses); new logo; licence changed to Apache 2.0; settings, results and login item migrate automatically; this spec |
| 2026-11-02 | Published to github.com/lenstica/lenstica (public, Apache 2.0) |

## 10. Decisions

| Id | Date | Decision | Why |
|----|------|----------|-----|
| D-1 | 2026-10 | Default minimum age 7 days | Most malicious releases are caught within a week; 8 of 10 prominent 2024–25 attacks would have been blocked (14 days: all but one) |
| D-2 | 2026-10 | One binary for CLI, menu bar app and MCP server | One install, one version, no IPC between components |
| D-3 | 2026-11-02 | Agent-instructions lens is pattern-based, no LLM | Local, fast, deterministic; findings carry only matched words; tuned for false positives |
| D-4 | 2026-11-02 | macOS notifications via NSUserNotification posted as the app | Apple's User Notifications API refuses ad-hoc-signed apps; revisit with F-20 |
| D-5 | 2026-11-02 | Rename `cooldown` → **Lenstica**; checks are **lenses**; "cooldown" stays the name of the minimum-age feature | A platform of many lenses, not one feature; lenstica.com and the GitHub org are owned |
| D-6 | 2026-11-02 | Lens installation designed in this spec, not built yet | Running third-party code needs the trust, pinning and sandboxing design first |
| D-7 | 2026-11-02 | Licence: Apache 2.0 (was AGPL v3) | Companies, the paying customers, often ban AGPL; open-core with a separate proprietary edition |
| D-8 | 2026-11-02 | Paid features gated by licence key in the same binary | Seamless upgrade; one codebase to test; no fork |
| D-9 | 2026-11-02 | Contributions under the DCO, not a CLA (proposed) | Apache 2.0 inbound = outbound is enough for a separate proprietary add-on; lower friction for contributors |
| D-10 | 2026-11-02 | Bundle id `com.lenstica.app`, login item `com.lenstica.agent` | Reverse-DNS of the owned domain |

## 11. Open questions

| Id | Question |
|----|----------|
| Q-1 | Free-tier cap for team features: up to 3 developers? 1 organisation? What counts as a seat (active in the last 30 days)? |
| Q-2 | Name of the private repository (`lenstica-cloud`, `lenstica-team`, …) and hosting for the server (region, data residency for EU customers) |
| Q-3 | Price per seat per month, and whether Enterprise (SSO, audit logs, SLA) is a separate tier |
| Q-4 | What the team edition uploads by default, and whether location paths are hashed |
| Q-5 | Trademark search and registration for "Lenstica" |
| Q-6 | Telemetry for the free edition: none (current), or opt-in anonymous usage counts |
| Q-7 | Does the registry host lens binaries, or only point at source repositories? |

## 12. Glossary

- **Lens**: one focused security check with an id (`package-age`), producing findings.
- **Finding**: one problem a lens found: severity, category, title, details,
  locations, remedy, links, whether it can be fixed, and a stable key.
- **Key**: a finding's identity within its lens; a finding is notified once per key.
- **Severity**: info, low, medium, high, critical. Low and above are problems.
- **Category**: grouping in the window: malware, vulnerability, secret, cooldown,
  deprecated, agent, settings.
- **Cooldown**: the minimum release age: package versions younger than N days
  are not installed.
- **Policy** (team edition): settings an organisation enforces on its developers' machines.
