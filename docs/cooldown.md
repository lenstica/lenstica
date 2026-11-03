# The cooldown: a minimum release age for every package manager

A release cooldown is the cheapest defence against the npm/PyPI supply-chain
attacks of the last two years. Malicious versions are usually caught and
pulled within hours to a few days, so a tool that never installs anything
younger than a week rarely sees one. Every major package manager now supports
it, each with a different setting name, unit and config file. Lenstica writes
the right value into each one and keeps it there.

- [What Lenstica configures](#what-lenstica-configures)
- [Setting the minimum age by hand](#setting-the-minimum-age-by-hand)
- [What the settings cannot do](#what-the-settings-cannot-do)

## What Lenstica configures

`lenstica apply` writes these settings, and the `package-managers` lens keeps
them in place (`monitor.auto_apply`).

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
and CocoaPods are detected and listed as not covered: none has a user-level
minimum-age setting (Deno has one per project, in `deno.json`).

## Setting the minimum age by hand

You do not need Lenstica to get the protection: every package manager below
has the setting built in. Here is each one for **7 days**, Lenstica's default
and the figure most guidance settles on: of ten prominent open-source
supply-chain attacks in 2024-2025, eight were open for less than a week before
being caught, so a 7-day wait would have kept them out (14 days: all but one).
Shorter (3 days) still stops the many caught within hours; longer delays
urgent fixes more. pnpm 11 ships a 1-day default, so set it explicitly.

Set it once, user wide, and it applies to every project on the machine, unless
a project's own file overrides it (the second line of each entry), which
Lenstica's `project-settings` lens watches for.

**npm** 11.10+, value in days:

```sh
npm config set min-release-age=7 --location=user      # writes ~/.npmrc
```

Per project: `min-release-age=7` in the repository's `.npmrc`. One-off
exception: `npm install some-pkg --min-release-age=0`. Check:
`npm config get min-release-age`.

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
`PIP_UPLOADED_PRIOR_TO` environment variable. Check:
`pip config get install.uploaded-prior-to`.

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

## What the settings cannot do

What the settings cannot do, and Lenstica adds: notice when one is missing,
weaker or reset (by a tool, a dotfile sync or a new machine), when a project
overrides it, or when a package that is already locked is too new, vulnerable
or malicious. They also do nothing for lockfile installs (`npm ci`,
`--frozen-lockfile`), which take what is pinned.
