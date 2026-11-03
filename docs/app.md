# The menu bar app and the window

- [The menu](#the-menu)
- [The window](#the-window)
- [Schedules and notifications](#schedules-and-notifications)
- [Start at login](#start-at-login)

## The menu

A Lucide package icon in the menu bar: `package-check` when nothing needs
attention, an orange `package-x` with a count when something does, and
`package-search` while the first checks run.

The menu lists every lens with a coloured dot: green when clear, the colour of
its worst finding when not, blue while running, hollow before its first run.
Each finding needing attention has a severity icon (filled red octagon
critical, orange triangle high, amber circle medium, blue `i` low, grey dot
info) and a submenu: Fix It when Lenstica can, Open the file, **Copy Prompt
for AI Agent**, and Show in Lenstica. Below them: Open Lenstica (⌘O),
Settings (⌘,) and Quit (⌘Q). Everything else (the minimum age, applying,
checking now, the settings file, start at login) lives in the window.

## The window

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

The window is an HTML page rendered by the system web view (WebKit, WebView2,
WebKitGTK), so it looks the same on every platform.

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
