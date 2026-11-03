# Configuration

Lenstica has one settings file, created with comments on first run:
`~/.config/lenstica/lenstica.toml` (`$XDG_CONFIG_HOME/lenstica/lenstica.toml`
when set; override with `--config FILE` or `LENSTICA_CONFIG`). Everything in
it can also be changed from the window's **Settings** page, which keeps the
file's comments.

Settings added in newer versions are written into an existing file, with
their comments, the first time it is loaded; values already there are never
changed.

- [The settings file](#the-settings-file)
- [Where things live](#where-things-live)
- [Things to know](#things-to-know)

## The settings file

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

Every lens also accepts `enabled` and `interval_minutes` under
`[lenses.<id>]`. External lenses are declared with `[[external]]`; see
[Writing lenses](writing-lenses.md).

## Where things live

| What | Where |
|------|-------|
| Settings | `~/.config/lenstica/lenstica.toml` (`$XDG_CONFIG_HOME`, `LENSTICA_CONFIG`) |
| Results and caches | `~/.local/state/lenstica/` (`$XDG_STATE_HOME`) |
| Backups of files Lenstica edits | `<name>.lenstica-backup`, next to the file, made once |
| Agent skill | `~/.claude/skills/lenstica/SKILL.md` (only when you install it) |
| Login item | see [Start at login](app.md#start-at-login) |

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
- `LENSTICA_DEBUG=1 lenstica tray` logs each action the window sends.
