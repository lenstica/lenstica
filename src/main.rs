//! Lenstica — keep every package manager from installing versions newer than
//! N days, and watch what is already installed: too-new, vulnerable,
//! malicious and deprecated packages, and secrets a supply-chain attack
//! could steal. Each check is a pluggable lens (see `checks`).

mod agent;
mod assets;
mod audit;
mod autostart;
mod config;
mod duration;
mod exec;
mod files;
mod http;
mod i18n;
mod lenses;
mod managers;
mod mcp;
mod migrate;
mod network;
mod notify;
mod paths;
mod prompt;
mod report;
mod scan;
mod system;
mod version;

#[cfg(feature = "tray")]
mod gui;
#[cfg(feature = "tray")]
mod icon;

use std::collections::BTreeMap;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use lenstica_lens::{Finding, Severity};

use crate::config::Config;
use crate::duration::{DAY, HOUR, MINUTE};
use crate::lenses::store::RunResult;
use crate::managers::{Action, Ctx, Mode};
use crate::paths::tilde;

#[derive(Parser)]
#[command(
    name = "lenstica",
    version,
    about = "Keep package managers from installing versions newer than N days, and watch installed packages and secrets",
    after_help = "Settings live in ~/.config/lenstica/lenstica.toml (created on first run).\nWith no command, `lenstica` prints `status`."
)]
struct Cli {
    /// Use this settings file instead of ~/.config/lenstica/lenstica.toml (also: LENSTICA_CONFIG)
    #[arg(long, global = true, value_name = "FILE")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Overview of every lens; runs the ones whose results are out of date
    Status {
        #[arg(long)]
        json: bool,
        /// Only show stored results; run nothing
        #[arg(long)]
        no_run: bool,
    },
    /// Run lenses now and exit 1 if anything reaches monitor.alert_severity (for scripts and CI)
    Check {
        /// Only these lenses (see `lenstica lenses`)
        lenses: Vec<String>,
        #[arg(long)]
        json: bool,
        #[arg(long, short)]
        quiet: bool,
        /// Use cached data only; no network
        #[arg(long)]
        offline: bool,
        /// Also send desktop notifications for new findings
        #[arg(long)]
        notify: bool,
    },
    /// List findings with details and remedies; exits 1 when any needs attention
    Findings {
        /// Only this lens
        #[arg(long)]
        lens: Option<String>,
        /// Only this category: agents, packages, software, secrets, malware, network, privacy
        #[arg(long)]
        category: Option<lenstica_lens::Category>,
        /// Minimum severity: info, low, medium, high, critical (default: low)
        #[arg(long)]
        severity: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// List the lenses: built-in, plugin crates and external tools
    Lenses,
    /// Fix one finding through its lens (the key is in `lenstica findings`)
    Fix { lens: String, key: String },
    /// Write the cooldown into every detected package manager's user-level config
    Apply {
        /// Only these package managers (ids: npm, pnpm, yarn, bun, uv, pip, poetry, cargo)
        managers: Vec<String>,
        /// Show what would change without writing anything
        #[arg(long, short = 'n')]
        dry_run: bool,
        #[arg(long)]
        json: bool,
    },
    /// Change the minimum age in the settings file, then apply it everywhere
    Set {
        /// Minimum age in days (1-365); 7 is recommended
        days: u32,
        /// Only update the settings file
        #[arg(long)]
        no_apply: bool,
    },
    /// Run the dependency lenses now: package ages, vulnerabilities and malware, deprecations
    Audit {
        #[arg(long)]
        json: bool,
        #[arg(long)]
        offline: bool,
    },
    /// Find project-level configs that weaken the cooldown (never edits them)
    Scan {
        #[arg(long)]
        json: bool,
    },
    /// Print, show, or edit the settings file
    Config {
        #[command(subcommand)]
        action: Option<ConfigAction>,
    },
    /// List the package managers Lenstica configures and how
    Managers,
    /// List the programs accepting network connections, and whether other devices can reach them
    Network {
        #[arg(long)]
        json: bool,
    },
    /// List what is on this machine: identities (accounts, never their keys),
    /// repositories, applications, containers, virtual machines and extensions
    Assets {
        /// Only this kind: identities, repositories, applications, containers, virtual-machines, extensions
        kind: Option<assets::Kind>,
        #[arg(long)]
        json: bool,
    },
    /// Run the lenses continuously in the foreground with notifications, no icon
    Watch {
        /// Run one pass and exit
        #[arg(long)]
        once: bool,
    },
    /// Run the menu bar / system tray app
    Tray,
    /// Open the Lenstica window: every category's lenses and findings, and settings
    Window {
        /// Page to open on: overview, a category (agents, packages, software, secrets, malware, network, privacy), assets/<kind> (identities, repositories, applications, containers, virtual-machines, extensions) or settings; settings/<section> (general, notifications, managers, projects, checks, agents) opens one section
        page: Option<String>,
    },
    /// Start the monitor automatically at login
    Autostart {
        #[command(subcommand)]
        action: AutostartAction,
    },
    /// Print a short brief for an AI coding agent: everything that needs
    /// attention, one lens's findings, or one finding
    Prompt {
        /// Only this lens
        lens: Option<String>,
        /// Only this finding (the key is in `lenstica findings --json`)
        key: Option<String>,
    },
    /// Show a test notification, to check that notifications appear
    TestNotification,
    /// Run the MCP server on stdin/stdout, for AI agents (Claude Code, Cursor, ...)
    Mcp {
        /// Print how to register it with an agent instead
        #[arg(long)]
        setup: bool,
    },
    /// Print the agent skill (SKILL.md) that teaches the CLI, or install it
    Skill {
        /// Write it to ~/.claude/skills/lenstica/SKILL.md (or --dir)
        #[arg(long)]
        install: bool,
        /// Install into this directory instead
        #[arg(long, value_name = "DIR", requires = "install")]
        dir: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Print the settings file path
    Path,
    /// Print the settings file
    Show,
    /// Open the settings file in $VISUAL / $EDITOR (or the system default)
    Edit,
}

#[derive(Subcommand)]
enum AutostartAction {
    /// Install the login item and start it now
    Install {
        /// Run `lenstica watch` (notifications only) instead of the menu bar app
        #[arg(long)]
        headless: bool,
    },
    /// Remove the login item and stop it
    Uninstall,
    /// Show whether the login item is installed
    Status,
}

fn main() -> ExitCode {
    // Die quietly on a closed pipe (`lenstica findings | head`) like other CLI tools,
    // instead of panicking inside println!.
    #[cfg(unix)]
    // SAFETY: restoring the default disposition of one signal before any thread starts.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    let cli = Cli::parse();
    if let Some(path) = cli.config {
        config::set_path_override(path);
    } else {
        migrate::run();
    }
    // Launched with no arguments and no terminal (the app bundle from Finder, or a
    // login item), run the menu bar app; from a terminal, print the status.
    let launched_as_app = cli.command.is_none() && cfg!(feature = "tray") && !from_terminal();
    let command = match cli.command {
        Some(c) => c,
        None if launched_as_app => Command::Tray,
        None => Command::Status {
            json: false,
            no_run: false,
        },
    };
    match run(command) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("lenstica: {e:#}");
            ExitCode::from(2)
        }
    }
}

/// Whether a person ran this from a terminal (as opposed to Finder, Explorer
/// or a login item starting the app).
fn from_terminal() -> bool {
    #[cfg(windows)]
    {
        // Double-clicking a console program gives it a console of its own; only
        // a terminal leaves other processes (the shell) attached to it.
        unsafe extern "system" {
            fn GetConsoleProcessList(list: *mut u32, count: u32) -> u32;
        }
        let mut ids = [0u32; 2];
        // SAFETY: the buffer and its length match; the call only writes into it.
        let attached = unsafe { GetConsoleProcessList(ids.as_mut_ptr(), ids.len() as u32) };
        attached > 1
    }
    // Any terminal stream: `lenstica | less` and `$(lenstica)` still come from one.
    #[cfg(not(windows))]
    {
        std::io::stdin().is_terminal()
            || std::io::stdout().is_terminal()
            || std::io::stderr().is_terminal()
    }
}

fn exit(problems: bool) -> ExitCode {
    if problems {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn run_lenses(cfg: &Config, force: bool, only: &[String], offline: bool) -> Vec<RunResult> {
    let due = lenses::due(cfg, force, only);
    if std::io::stderr().is_terminal() && !due.is_empty() {
        eprintln!("Running lenses… (the first run looks up every package; later runs are quick)");
    }
    lenses::run_all(cfg, &due, offline)
}

/// The lens, which must exist and be turned on.
fn enabled_lens(cfg: &Config, id: &str) -> Result<lenses::Registered> {
    let r = lenses::find(cfg, id)?;
    if !lenses::enabled(cfg, &r) {
        bail!(
            "the {id} lens is turned off; turn it on with `[lenses.{id}] enabled = true` in {}",
            tilde(&config::path())
        );
    }
    Ok(r)
}

fn run(command: Command) -> Result<ExitCode> {
    match command {
        Command::Status { json, no_run } => {
            let cfg = Config::load()?;
            if !no_run {
                run_lenses(&cfg, false, &[], false);
            }
            lenses::store::prune(&cfg)?;
            let results = lenses::store::load();
            if json {
                print_json(&results)?;
            } else {
                print_overview(&cfg, &results);
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Check {
            lenses: ids,
            json,
            quiet,
            offline,
            notify,
        } => {
            let cfg = Config::load()?;
            for id in &ids {
                enabled_lens(&cfg, id)?;
            }
            let ran = run_lenses(&cfg, true, &ids, offline);
            if notify {
                for r in &ran {
                    lenses::store::notify_new(&cfg, r);
                }
            }
            let results = lenses::store::load();
            let shown: BTreeMap<String, RunResult> = results
                .into_iter()
                .filter(|(id, _)| ids.is_empty() || ids.contains(id))
                .collect();
            if json {
                print_json(&shown)?;
            } else if !quiet {
                print_overview(&cfg, &shown);
            }
            let problems = shown
                .values()
                .flat_map(|r| &r.findings)
                .any(|f| lenses::is_alert(&cfg, f));
            Ok(exit(problems))
        }
        Command::Findings {
            lens,
            category,
            severity,
            json,
        } => {
            let cfg = Config::load()?;
            let min = match &severity {
                Some(s) => {
                    lenses::parse_severity(s).with_context(|| format!("unknown severity `{s}`"))?
                }
                None => Severity::Low,
            };
            if let Some(id) = &lens {
                lenses::find(&cfg, id)?;
            }
            let results = lenses::store::load();
            let mut list: Vec<&Finding> = lenses::live_results(&cfg, &results)
                .filter(|r| lens.as_ref().is_none_or(|c| &r.id == c))
                .flat_map(|r| &r.findings)
                .filter(|f| category.is_none_or(|c| f.category == c))
                .filter(|f| f.severity >= min)
                .collect();
            list.sort_by(|a, b| lenses::by_severity(a, b));
            if json {
                print_json(&list)?;
            } else if list.is_empty() {
                println!(
                    "No findings at {} or above. `lenstica status` runs any lens that is due.",
                    min.label()
                );
            } else {
                print_findings_detail(&list);
            }
            Ok(exit(list.iter().any(|f| lenses::is_alert(&cfg, f))))
        }
        Command::Lenses => {
            let cfg = Config::load()?;
            print_lenses(&cfg);
            Ok(ExitCode::SUCCESS)
        }
        Command::Fix { lens, key } => {
            let cfg = Config::load()?;
            println!("{}", lenses::fix(&cfg, &lens, &key)?.0);
            Ok(ExitCode::SUCCESS)
        }
        Command::Apply {
            managers,
            dry_run,
            json,
        } => {
            let cfg = Config::load()?;
            for id in &managers {
                if managers::by_id(id).is_none() {
                    bail!(
                        "unknown package manager `{id}` (known: {})",
                        managers::ids().join(", ")
                    );
                }
            }
            let ctx = Ctx::new(&cfg);
            let outcomes = managers::apply_all(&cfg, &ctx, &managers, Mode::Exact, dry_run);
            if json {
                print_json(&outcomes)?;
            } else {
                print_outcomes(&outcomes, cfg.min_days, dry_run);
            }
            Ok(exit(
                outcomes
                    .iter()
                    .any(|o| matches!(o.action, Action::Failed { .. })),
            ))
        }
        Command::Set { days, no_apply } => {
            config::set_min_days(days)?;
            println!("min_days = {days} in {}", tilde(&config::path()));
            if no_apply {
                return Ok(ExitCode::SUCCESS);
            }
            run(Command::Apply {
                managers: Vec::new(),
                dry_run: false,
                json: false,
            })
        }
        Command::Audit { json, offline } => {
            let cfg = Config::load()?;
            let ids: Vec<String> = lenses::registry(&cfg)
                .iter()
                .filter(|r| r.group == lenses::Group::Dependencies && lenses::enabled(&cfg, r))
                .map(|r| r.id().to_string())
                .collect();
            run_and_show(&cfg, &ids, json, offline)
        }
        Command::Scan { json } => {
            let cfg = Config::load()?;
            let id = enabled_lens(&cfg, "project-settings")?.id().to_string();
            run_and_show(&cfg, &[id], json, false)
        }
        Command::Config { action } => {
            // Not loaded: a file with an invalid value must still open for repair.
            let path = config::ensure_exists()?;
            match action.unwrap_or(ConfigAction::Path) {
                ConfigAction::Path => println!("{}", path.display()),
                ConfigAction::Show => print!("{}", std::fs::read_to_string(&path)?),
                ConfigAction::Edit => edit(&path)?,
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Managers => {
            print_managers();
            Ok(ExitCode::SUCCESS)
        }
        Command::Network { json } => network_cmd(json),
        Command::Assets { kind, json } => assets_cmd(kind, json),
        Command::Watch { once } => watch(once),
        Command::Tray => tray(),
        Command::Window { page } => window(page),
        Command::Autostart { action } => autostart_cmd(action),
        Command::Prompt { lens, key } => {
            let cfg = Config::load()?;
            let results = lenses::store::load();
            if let Some(id) = &lens {
                lenses::find(&cfg, id)?;
            }
            let list = prompt::collect(&cfg, &results, &[(lens.as_deref(), key.as_deref())]);
            if key.is_some() && list.is_empty() {
                bail!("no current finding with that key; `lenstica findings --json` lists them");
            }
            print!("{}", prompt::for_findings(&cfg, &list));
            Ok(ExitCode::SUCCESS)
        }
        Command::Mcp { setup: true } => {
            println!("Claude Code:\n  {}\n", agent::mcp_command());
            println!(
                "Other MCP clients (Claude Desktop, Cursor, ...), in their mcpServers settings:\n{}",
                agent::mcp_json()
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::Mcp { setup: false } => {
            mcp::serve()?;
            Ok(ExitCode::SUCCESS)
        }
        Command::TestNotification => {
            notify::send(&i18n::t!("notify.title"), &i18n::t!("notify.test"))?;
            // The framework delivers asynchronously; give it a moment before exiting.
            std::thread::sleep(std::time::Duration::from_secs(2));
            let settings = if cfg!(target_os = "macos") {
                "System Settings → Notifications"
            } else if cfg!(windows) {
                "Settings → System → Notifications"
            } else {
                "your desktop's notification settings"
            };
            println!("Sent {}. Not seeing it? Check {settings}.", notify::route());
            Ok(ExitCode::SUCCESS)
        }
        Command::Skill { install: false, .. } => {
            print!("{}", agent::SKILL);
            Ok(ExitCode::SUCCESS)
        }
        Command::Skill { install: true, dir } => {
            let path = agent::install_skill(dir)?;
            println!("Installed the Lenstica skill at {}", tilde(&path));
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// Run some lenses now and print their findings in full.
fn run_and_show(cfg: &Config, ids: &[String], json: bool, offline: bool) -> Result<ExitCode> {
    if ids.is_empty() {
        bail!("those lenses are turned off in {}", tilde(&config::path()));
    }
    let ran = run_lenses(cfg, true, ids, offline);
    if json {
        print_json(&ran)?;
    } else {
        let s = Style::detect();
        for r in &ran {
            println!(
                "{} {}",
                s.bold(&r.title),
                s.dim(&format!("· {}", r.summary))
            );
            if let Some(e) = &r.error {
                println!("  {}", s.red(&format!("! {e}")));
            }
        }
        println!();
        let mut list: Vec<&Finding> = ran
            .iter()
            .flat_map(|r| &r.findings)
            .filter(|f| f.severity.is_problem())
            .collect();
        list.sort_by(|a, b| lenses::by_severity(a, b));
        print_findings_detail(&list);
        let info = ran
            .iter()
            .flat_map(|r| &r.findings)
            .filter(|f| !f.severity.is_problem())
            .count();
        if info > 0 {
            println!(
                "{}",
                s.dim(&format!(
                    "{info} informational findings: `lenstica findings --severity info`"
                ))
            );
        }
    }
    Ok(exit(
        ran.iter()
            .flat_map(|r| &r.findings)
            .any(|f| lenses::is_alert(cfg, f)),
    ))
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

#[cfg(feature = "tray")]
fn tray() -> Result<ExitCode> {
    gui::run(None)?;
    Ok(ExitCode::SUCCESS)
}

#[cfg(not(feature = "tray"))]
fn tray() -> Result<ExitCode> {
    bail!(
        "this build has no menu bar support (built without the `tray` feature); use `lenstica watch`"
    )
}

#[cfg(feature = "tray")]
fn window(page: Option<String>) -> Result<ExitCode> {
    let page = page.unwrap_or_else(|| "overview".to_string());
    // `settings/projects` opens one section of Settings.
    if !gui::pages().contains(&page.split_once('/').map_or(page.as_str(), |(p, _)| p)) {
        bail!("unknown page `{page}` (pages: {})", gui::pages().join(", "));
    }
    // A second launch hands over to the running app, which opens its window.
    gui::run(Some(page))?;
    Ok(ExitCode::SUCCESS)
}

#[cfg(not(feature = "tray"))]
fn window(_page: Option<String>) -> Result<ExitCode> {
    bail!("this build has no window (built without the `tray` feature); use `lenstica findings`")
}

fn watch(once: bool) -> Result<ExitCode> {
    let Some(_lock) = system::acquire_lock()? else {
        eprintln!("lenstica: the monitor is already running");
        return Ok(ExitCode::SUCCESS);
    };
    // A settings file broken by an edit keeps the monitor on its last good
    // settings rather than exiting (a login item would restart it in a loop).
    let mut last_good: Option<Config> = None;
    loop {
        let cfg = match Config::load() {
            Ok(cfg) => {
                last_good = Some(cfg.clone());
                cfg
            }
            Err(e) if once => return Err(e),
            Err(e) => {
                eprintln!("lenstica: {e:#}");
                match &last_good {
                    Some(cfg) => cfg.clone(),
                    None => {
                        thread::sleep(Duration::from_secs(30));
                        continue;
                    }
                }
            }
        };
        for result in lenses::run_due(&cfg, once, &[], false) {
            let stamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
            let alerts = result
                .findings
                .iter()
                .filter(|f| lenses::is_alert(&cfg, f))
                .count();
            println!(
                "[{stamp}] {}: {} ({alerts} to look at)",
                result.title, result.summary
            );
            if let Some(e) = &result.error {
                println!("  ! {e}");
            }
            for line in lenses::store::notify_new(&cfg, &result) {
                println!("  {line}");
            }
        }
        if once {
            return Ok(ExitCode::SUCCESS);
        }
        thread::sleep(Duration::from_secs(30));
    }
}

// ---- lens output -------------------------------------------------------------

fn ago(t: chrono::DateTime<chrono::Utc>) -> String {
    let secs = (chrono::Utc::now() - t).num_seconds().max(0);
    match secs {
        s if s < 60 => "just now".to_string(),
        s if s < HOUR => format!("{} min ago", s / MINUTE),
        s if s < DAY => format!("{} h ago", s / HOUR),
        s => format!("{} days ago", s / DAY),
    }
}

fn severity_tag(s: &Style, sev: Severity) -> String {
    match sev {
        Severity::Critical => s.paint("1;31", "CRITICAL"),
        Severity::High => s.red("HIGH    "),
        Severity::Medium => s.yellow("MEDIUM  "),
        Severity::Low => s.dim("LOW     "),
        Severity::Info => s.dim("INFO    "),
    }
}

fn where_label(f: &Finding) -> String {
    match f.locations.len() {
        0 => String::new(),
        1 => f.locations[0].label.clone(),
        n => format!("{} (+{} more)", f.locations[0].label, n - 1),
    }
}

fn print_overview(cfg: &Config, results: &BTreeMap<String, RunResult>) {
    let s = Style::detect();
    println!(
        "{} minimum release age {} days  {}",
        s.bold("Lenstica"),
        cfg.min_days,
        s.dim(&format!("({})", tilde(&config::path())))
    );
    println!();
    let registry = lenses::registry(cfg);
    let width = registry
        .iter()
        .map(|r| r.lens.title().chars().count())
        .max()
        .unwrap_or(0);
    for r in &registry {
        let title = pad(r.lens.title(), width);
        match results.get(r.id()) {
            _ if !lenses::enabled(cfg, r) => {
                println!("  {} {}  {}", s.dim("-"), s.dim(&title), s.dim("off"));
            }
            None => println!("  {} {}  {}", s.dim("…"), title, s.dim("not run yet")),
            Some(res) => {
                let alerts = res
                    .findings
                    .iter()
                    .filter(|f| lenses::is_alert(cfg, f))
                    .count();
                let mark = if res.error.is_some() {
                    s.red("!")
                } else if alerts > 0 {
                    s.red("✗")
                } else {
                    s.green("✓")
                };
                println!(
                    "  {mark} {title}  {}  {}",
                    res.status_text(),
                    s.dim(&ago(res.ran_at))
                );
            }
        }
    }
    println!();
    let mut alerts: Vec<&Finding> = results
        .values()
        .flat_map(|r| &r.findings)
        .filter(|f| lenses::is_alert(cfg, f))
        .collect();
    alerts.sort_by(|a, b| lenses::by_severity(a, b));
    if alerts.is_empty() {
        println!(
            "{}",
            s.green(&format!(
                "Nothing at {} or above needs attention.",
                lenses::threshold(cfg).label()
            ))
        );
        return;
    }
    for f in alerts.iter().take(15) {
        println!(
            "  {} {}  {}",
            severity_tag(&s, f.severity),
            f.title,
            s.dim(&where_label(f))
        );
    }
    if alerts.len() > 15 {
        println!("  {}", s.dim(&format!("… {} more", alerts.len() - 15)));
    }
    println!();
    println!(
        "{} need attention. Details and fixes: `lenstica findings` or `lenstica window`.",
        s.red(&format!("{}", alerts.len()))
    );
}

fn print_findings_detail(list: &[&Finding]) {
    let s = Style::detect();
    for f in list {
        println!("{} {}", severity_tag(&s, f.severity), s.bold(&f.title));
        for line in f.detail.lines().take(6) {
            println!("         {}", s.dim(line));
        }
        for loc in f.locations.iter().take(3) {
            println!("         at {}", loc.label);
        }
        if f.locations.len() > 3 {
            println!(
                "         {}",
                s.dim(&format!("… and {} more places", f.locations.len() - 3))
            );
        }
        if !f.remedy.is_empty() {
            println!("         {} {}", s.green("→"), f.remedy);
        }
        if let Some(link) = f.links.first() {
            println!("         {}", s.dim(link));
        }
        if let Some(fix) = prompt::fix_command(f) {
            println!("         {}", s.dim(&format!("fix: {fix}")));
        }
        println!();
    }
}

fn print_lenses(cfg: &Config) {
    let s = Style::detect();
    let results = lenses::store::load();
    for r in lenses::registry(cfg) {
        let on = lenses::enabled(cfg, &r);
        let state = if on { s.green("on ") } else { s.dim("off") };
        let categories: Vec<&str> = r.lens.categories().iter().map(|c| c.title()).collect();
        let every = lenses::interval(cfg, &r).as_secs() / 60;
        let last = results
            .get(r.id())
            .map_or_else(|| "never run".to_string(), |res| ago(res.ran_at));
        println!(
            "{state} {}  {}",
            s.bold(&format!("{:<18}", r.id())),
            s.dim(&format!(
                "{} · {} · every {every} min · {last}",
                categories.join(", "),
                r.origin.label()
            ))
        );
        println!("    {}", r.lens.description());
        if let Some(third) = r.lens.third_party() {
            println!("    {}", s.dim(&format!("Third party: {third}")));
        }
    }
    println!();
    println!(
        "{}",
        s.dim("Turn one on or off with `[lenses.<id>] enabled = true` or `false`; add tools under `[[external]]` (see the settings file).")
    );
}

fn edit(path: &std::path::Path) -> Result<()> {
    let editor = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .ok()
        .filter(|e| !e.trim().is_empty());
    let Some(editor) = editor else {
        return system::open(path);
    };
    let mut parts = editor.split_whitespace();
    let program = parts.next().context("empty $EDITOR")?;
    let status = std::process::Command::new(program)
        .args(parts)
        .arg(path)
        .status()
        .with_context(|| format!("cannot start {program}"))?;
    if !status.success() {
        bail!("{program} exited with {status}");
    }
    Ok(())
}

fn autostart_cmd(action: AutostartAction) -> Result<ExitCode> {
    match action {
        AutostartAction::Install { headless } => {
            let kind = if headless || !cfg!(feature = "tray") {
                autostart::Kind::Headless
            } else {
                autostart::Kind::Tray
            };
            let exe = autostart::executable()?;
            if autostart::is_build_artifact(&exe) {
                eprintln!(
                    "warning: {} is a cargo build output; `cargo clean` would break the login item.\n         Install it first with `cargo install --path .` and run this again from ~/.cargo/bin.",
                    exe.display()
                );
            }
            let path = autostart::install(kind, true)?;
            println!(
                "Installed {} ({}). It starts at login and is running now.",
                tilde(&path),
                exe.display()
            );
        }
        AutostartAction::Uninstall => {
            let removed = autostart::uninstall(true)?;
            if removed.is_empty() {
                println!("No login item was installed.");
            }
            for path in removed {
                println!("Removed {}", tilde(&path));
            }
        }
        AutostartAction::Status => match autostart::installed() {
            Some(path) => println!("Installed: {}", tilde(&path)),
            None => println!("Not installed. Run `lenstica autostart install`."),
        },
    }
    Ok(ExitCode::SUCCESS)
}

struct Style {
    enabled: bool,
}

impl Style {
    fn detect() -> Self {
        Self {
            enabled: std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none(),
        }
    }
    fn paint(&self, code: &str, text: &str) -> String {
        if self.enabled {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }
    fn green(&self, t: &str) -> String {
        self.paint("32", t)
    }
    fn red(&self, t: &str) -> String {
        self.paint("31", t)
    }
    fn yellow(&self, t: &str) -> String {
        self.paint("33", t)
    }
    fn dim(&self, t: &str) -> String {
        self.paint("2", t)
    }
    fn bold(&self, t: &str) -> String {
        self.paint("1", t)
    }
}

fn pad(text: &str, width: usize) -> String {
    let len = text.chars().count();
    format!("{text}{}", " ".repeat(width.saturating_sub(len)))
}

fn print_outcomes(outcomes: &[managers::Outcome], days: u32, dry_run: bool) {
    let s = Style::detect();
    if outcomes.is_empty() {
        println!("No supported package manager found on PATH.");
        return;
    }
    let name_w = outcomes.iter().map(|o| o.name.len()).max().unwrap_or(0);
    for o in outcomes {
        let (mark, text) = match &o.action {
            Action::Changed { from, to } => (
                s.green("✓"),
                format!("{} → {to}", from.as_deref().unwrap_or("not set")),
            ),
            Action::WouldChange { from, to } => (
                s.yellow("~"),
                format!("would set {} → {to}", from.as_deref().unwrap_or("not set")),
            ),
            Action::Unchanged => (s.dim("="), "already set".to_string()),
            Action::Skipped { reason } => (s.yellow("⚠"), format!("skipped: {reason}")),
            Action::Failed { error } => (s.red("✗"), format!("failed: {error}")),
        };
        println!(
            "  {mark} {}  {}  {}",
            pad(o.name, name_w),
            text,
            s.dim(&o.location)
        );
    }
    if !dry_run {
        println!();
        println!(
            "Every package manager above now refuses versions newer than {days} days, unless marked otherwise."
        );
    }
}

/// Everything listening, with the severity of the `listening-ports` finding
/// that covers it (the lens runs first, when it is on).
fn network_cmd(json: bool) -> Result<ExitCode> {
    let cfg = Config::load()?;
    let list = network::listening()?;
    let r = lenses::find(&cfg, lenses::ports::ID)?;
    let findings = if lenses::enabled(&cfg, &r) {
        lenses::run(&cfg, &r, false).findings
    } else {
        Vec::new()
    };
    let finding = |l: &network::Listening| {
        lenses::ports::finding_key(l).and_then(|k| findings.iter().find(|f| f.key == k))
    };
    if json {
        let out: Vec<serde_json::Value> = list
            .iter()
            .map(|l| {
                serde_json::json!({
                    "process": l.process,
                    "path": l.path,
                    "pids": l.pids,
                    "port": l.port,
                    "addresses": l.addresses,
                    "reach": l.reach(),
                    "severity": finding(l).map(|f| f.severity),
                    "finding": finding(l).map(|f| &f.key),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(ExitCode::SUCCESS);
    }
    let s = Style::detect();
    for (reach, heading) in [
        (network::Reach::Network, "Reachable from your network"),
        (network::Reach::Local, "This machine only"),
    ] {
        let group: Vec<_> = list.iter().filter(|l| l.reach() == reach).collect();
        println!(
            "{} {}",
            s.bold(heading),
            s.dim(&format!("({})", group.len()))
        );
        for l in group {
            let tag = match finding(l) {
                Some(f) => severity_tag(&s, f.severity),
                None => " ".repeat(8),
            };
            println!(
                "  {tag} {:<22} {:>5}  {}",
                l.process,
                l.port,
                s.dim(&l.sockets())
            );
        }
        println!();
    }
    println!(
        "{}",
        s.dim("Only programs running as you are visible. Details and remedies: `lenstica findings --lens listening-ports`.")
    );
    Ok(ExitCode::SUCCESS)
}

/// What is on this machine, by kind, grouped by where each asset comes from.
fn assets_cmd(kind: Option<assets::Kind>, json: bool) -> Result<ExitCode> {
    let cfg = Config::load()?;
    let kinds: Vec<assets::Kind> = kind.map_or_else(|| assets::Kind::ALL.to_vec(), |k| vec![k]);
    let found = assets::discover(&cfg, &kinds);
    if json {
        let out: Vec<serde_json::Value> = found.iter().map(assets::Discovery::brief).collect();
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(ExitCode::SUCCESS);
    }
    let s = Style::detect();
    for d in &found {
        println!(
            "{} {}",
            s.bold(d.kind.title()),
            s.dim(&format!("({})", d.assets.len()))
        );
        if !d.supported {
            println!("  {}", s.dim("Not listed on this system yet."));
        }
        let mut source: Option<&str> = None;
        for a in &d.assets {
            if source != Some(a.source.as_str()) {
                source = Some(&a.source);
                let heading = if a.source.is_empty() {
                    d.kind.unsourced()
                } else {
                    &a.source
                };
                println!("  {heading}");
            }
            let mut about: Vec<String> = a.status.iter().map(|st| st.label().to_string()).collect();
            about.extend(a.facts.iter().take(3).map(|f| f.value.clone()));
            let tags: Vec<&str> = a.tags.iter().map(|t| t.label).collect();
            let tags = if tags.is_empty() {
                String::new()
            } else {
                format!("  [{}]", tags.join(", "))
            };
            println!("    {:<32} {}{}", a.name, s.dim(&about.join(" · ")), tags);
        }
        for name in &d.not_running {
            println!(
                "  {}",
                s.dim(&format!(
                    "{name} is not running, so what it holds is not listed."
                ))
            );
        }
        for e in &d.errors {
            println!("  {}", s.dim(&format!("Could not read {e}")));
        }
        if !d.blocked.is_empty() {
            println!(
                "  {}",
                s.dim(&format!(
                    "macOS did not let Lenstica read {}: give it Full Disk Access to include them.",
                    d.blocked.join(", ")
                ))
            );
        }
        println!();
    }
    Ok(ExitCode::SUCCESS)
}

fn print_managers() {
    const EXAMPLE_DAYS: u32 = 7;
    let s = Style::detect();
    println!("{}", s.bold("Configured by Lenstica:"));
    for m in managers::all() {
        println!(
            "  {:<7} {:<26} {}  {}",
            m.id(),
            m.setting(),
            s.dim(&format!("needs ≥ {}", m.min_version())),
            s.dim(&format!("{EXAMPLE_DAYS} days = {}", m.target(EXAMPLE_DAYS)))
        );
    }
    println!();
    println!("{}", s.bold("Detected, but not configurable:"));
    for u in managers::UNSUPPORTED {
        println!("  {:<9} {}", u.id, s.dim(u.note));
    }
}
