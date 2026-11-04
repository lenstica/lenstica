# The menu bar app and the window

- [The menu](#the-menu)
- [The window](#the-window)
- [Schedules and notifications](#schedules-and-notifications)
- [Start at login](#start-at-login)

## The menu

The logo's three lenses in the menu bar, fading from the solid front lens to
the faint back one: in the bar's colour when nothing needs attention, in orange
when something does (the tooltip gives the count), and outlined while the first
checks run.

The menu has one submenu per [category](lenses.md#categories) (AI agents,
Packages, Software, Secrets, Malware, Network, and Privacy once a lens
covers it), each with a coloured dot: green when clear, the colour of its
worst finding when not, indigo while running, hollow before the first run.
Inside, each of the category's lenses has a line with its own dot and summary
(a lens that is off says so, and whether it is third party), then come the
findings needing attention. Each has a severity icon (filled red octagon
critical, orange triangle high, amber circle medium, blue `i` low, grey dot
info) and a submenu: Fix It when Lenstica can, Open the file, **Copy Prompt
for AI Agent**, and Show in Lenstica. The category ends with a prompt for all
of them and Open in Lenstica. Below the categories: Open Lenstica (⌘O),
Settings (⌘,) and Quit (⌘Q). The menu always covers every project; the
window's project picker does not change it.

## The window

The sidebar has the Overview, then **Assets** (a page per kind, with how many
there are), then one page per category, and at the bottom the project picker,
Settings, a link to the project on GitHub and the version.
Above the page, the top bar has Back and Forward (⌘[ and ⌘]) and where you
are. On macOS the window has no separate title bar: the window buttons sit in
the top bar, beside the logo, and dragging the bar moves the window
(double-click zooms it). Windows and Linux keep their usual title bar.

- **Overview**: how many findings need attention, by severity; a card per
  category with its state and topics; and the findings that need attention
  most. Check everything runs every lens that is on.
- **Assets**: what is on this machine, a page per kind: **Identities** (your
  git author, SSH keys, and the accounts signed in to the GitHub CLI, AWS,
  Google Cloud, Azure, Kubernetes, Docker registries, npm, PyPI, Cargo,
  `.netrc`, Claude Code and Codex: names only, never a key, tagged when a
  credential is kept in a plain file), **Repositories** (with remote, branch
  and worktrees), **Applications** (version, bundle id, where each came
  from: App Store, Homebrew, Apple, and what each is allowed to do: on macOS,
  the permissions System Settings spreads over Privacy & Security, such as
  Full Disk Access, Accessibility, Screen Recording, Input Monitoring,
  Automation, camera, microphone and folders, and its system extensions,
  each with a button to the pane that changes it; programs that hold one,
  such as Terminal or a Homebrew tool, are listed too; filter to the apps
  with elevated permissions. Reading them needs Full Disk Access; on macOS 27
  the permissions you give apps yourself (camera, microphone, folders,
  Automation…) are kept where no app can read them, which the page says. On Linux,
  each Flatpak's sandbox permissions with your overrides, and AppImages,
  which have no sandbox), **Containers** (running and stopped, in
  Docker Desktop, OrbStack, Colima, Rancher Desktop or Podman), **Virtual
  machines** (Lima, Colima, Podman, Multipass, Tart, Parallels, VirtualBox,
  VMware Fusion, UTM, Vagrant) and **Extensions** (VS Code, Cursor, Windsurf,
  VSCodium, Zed; Chrome, Brave, Edge, Arc, Vivaldi, Firefox; tagged when one
  can read every site). Each page groups by source, filters by source and
  text, and shows an asset's details, its file or folder (open or reveal),
  and the findings with a location in it; a repository also shows its
  project's findings in one click. Lenstica looks again each time a page
  opens, and on Look again; nothing is started, changed or sent. A tool that
  is installed but not running (Docker) is named, and so are folders macOS
  keeps from apps without Full Disk Access (browser profiles), with a button
  to that setting.
- **A category** (AI agents, Packages, …): what it covers and its state; its
  **lenses**, each with its state, summary and last run, a Run button and an
  on/off switch (third-party lenses say what they send or install, and are off
  until you turn them on); and its **findings**: filter by topic (Prompt
  injection, Cooldown, Exposed…), severity and text; the details, remedy,
  every location (open or reveal), references, and actions: fix, copy a
  prompt for an AI agent, ignore a package or one version of it, ignore an
  advisory, ignore a listening program or one of its ports. One button copies
  a single prompt for everything shown. A prompt is shown before it is copied.
- **Network** also lists every program **listening now** for TCP
  connections: first what other devices on your network can reach (riskiest
  first, with the severity of the `listening-ports` finding that covers it;
  click one for its finding), then, folded away, what only this machine can.
  It looks again every 10 seconds while open.
- **The project picker**: which project the window shows. **All projects**,
  **This Mac** (findings in no repository: package-manager settings,
  installed software, credentials in your home folder, global agent
  configuration), or one repository, which includes its worktrees. A finding
  belongs to every project one of its locations is in, and shows only those
  locations there. It changes only what is shown: every lens still checks
  everything.
- **Settings**: everything you would otherwise edit by hand, saved straight
  into the file with its comments kept, in sections listed beside it:
  - **General**: the cooldown, the lowest severity that needs attention, the
    appearance, the language (see [Translating](translating.md)), and start
    at login.
  - **Notifications**: on or off, from which severity, whether automatic
    fixes are announced, and per lens.
  - **Package managers**: a switch per package manager (one switched off is
    left exactly as it is), blocking install scripts, and Homebrew's
    auto-update.
  - **Projects**: which folders to include and exclude, and every
    **repository and worktree** found there, each with a switch (off adds it
    to `scan.exclude`).
  - **Checks**: what the installed-packages audit and the software lens look
    at, and what they never flag.
  - **AI agents**: install the skill, copy the MCP setup, and the
    **templates** prompts for agents are written with, with a live preview
    (see [AI agents](ai-agents.md#prompt-templates)).

`lenstica window <page>` opens it on `overview`, a category id (`packages`),
`settings`, or one section of it (`settings/projects`).

The window is a Svelte app (`ui/`, built into `assets/ui/`) rendered by the
system web view (WebKit, WebView2, WebKitGTK), so it looks the same on every
platform. Its design follows the logo: graphite and white glass in dark mode,
graphite on light grey in light mode, with the same status colours as the menu.
It is light or dark as the system is, unless Settings → App → Appearance
(`window.appearance`) picks one.

## Schedules and notifications

Lenses run on their own schedules, each on its own thread. One that watches
files (the package-manager configs, `.npmrc`) re-runs within seconds of an
edit, so a hand-weakened setting is reported and restored almost at once.
Every check also runs when the settings file changes. New findings at or
above `monitor.alert_severity` (default `medium`) are notified once each.

On macOS, notifications show Lenstica's name and icon when `Lenstica.app` is
installed (in `/Applications` or `~/Applications`), from the menu bar app and
the CLI alike, and are managed under System Settings → Notifications →
Lenstica. A bare binary without the app falls back to `osascript`, which shows
no icon. `lenstica test-notification` (or Settings → Notifications → Send a
test) shows one and says which way it went. Apple's newer notification API
needs a Developer ID signature; ad-hoc builds use the older one, which macOS
still supports.

## Start at login

Turn on **Start at login** in the window, or run `lenstica autostart install`.
It registers:

| Platform | Login item |
|----------|------------|
| macOS | a launchd agent, `~/Library/LaunchAgents/com.lenstica.agent.plist`, logging to `~/Library/Logs/lenstica.log` |
| Linux | an XDG autostart entry, or a systemd user unit with `--headless` |
| Windows | the `HKCU\…\Run` key |

Launched with no arguments outside a terminal (Finder, Explorer, a login item)
the binary starts the menu bar app; in a terminal it prints `lenstica status`.
Opening the app again, or `lenstica window`, opens the window in the running
instance.
