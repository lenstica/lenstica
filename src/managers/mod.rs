//! One module per supported package manager. Each knows where its user-level
//! setting lives, how to read and write it, the unit it counts in, and the
//! first release that understands it.

mod bun;
mod cargo;
mod npm;
mod pip;
mod pnpm;
mod poetry;
mod uv;
mod yarn;

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::config::Config;
use crate::duration::{DAY, humanize, parse_age};
use crate::exec;
use crate::paths::tilde;
use crate::version::Version;

pub struct Ctx {
    pub days: u32,
    pub search: OsString,
    pub now: DateTime<Utc>,
}

impl Ctx {
    pub fn new(cfg: &Config) -> Self {
        Self {
            days: cfg.min_days,
            search: exec::search_path(&cfg.extra_path()),
            now: Utc::now(),
        }
    }

    /// The cooldown in seconds.
    pub fn target_secs(&self) -> i64 {
        i64::from(self.days) * DAY
    }
}

pub struct Tool {
    pub bin: PathBuf,
    pub version: Option<Version>,
    /// The version as the tool printed it (`25.0`, not `25.0.0`).
    pub version_text: Option<String>,
}

pub enum Gate {
    Supported,
    TooOld,
    /// Supported, with something the user should know.
    Note(String),
}

pub trait Manager: Send + Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn binaries(&self) -> &'static [&'static str];
    fn min_version(&self) -> Version;
    /// The setting's name as the package manager spells it.
    fn setting(&self) -> &'static str;
    /// Seconds per unit of a bare number in this manager's setting.
    fn bare_unit(&self) -> i64;
    /// The value that enforces `days`, in this manager's syntax: by default
    /// a bare number of [`Self::bare_unit`]s.
    fn target(&self, days: u32) -> String {
        (i64::from(days) * DAY / self.bare_unit()).to_string()
    }
    /// Whether the manager itself understands `raw`. By default only a bare
    /// whole number does; Lenstica's own parser reads far more, and a value
    /// it reads but the manager rejects must not look fine.
    fn accepts(&self, raw: &str) -> bool {
        crate::duration::unquote(raw).parse::<u64>().is_ok()
    }
    /// Where the user-level setting is stored, for display.
    fn location(&self, tool: &Tool) -> PathBuf;
    fn read(&self, tool: &Tool, ctx: &Ctx) -> Result<Option<String>>;
    fn write(&self, tool: &Tool, value: &str, ctx: &Ctx) -> Result<()>;

    fn gate(&self, version: Option<Version>) -> Gate {
        default_gate(self.min_version(), version)
    }
}

/// Supported from `min_version` on.
pub(crate) fn default_gate(min_version: Version, version: Option<Version>) -> Gate {
    match version {
        Some(v) if v < min_version => Gate::TooOld,
        Some(_) => Gate::Supported,
        None => Gate::Note("version could not be determined".to_string()),
    }
}

pub fn all() -> [&'static dyn Manager; 8] {
    [
        &npm::Npm,
        &pnpm::Pnpm,
        &yarn::Yarn,
        &bun::Bun,
        &uv::Uv,
        &pip::Pip,
        &poetry::Poetry,
        &cargo::Cargo,
    ]
}

pub fn ids() -> Vec<&'static str> {
    all().iter().map(|m| m.id()).collect()
}

pub fn by_id(id: &str) -> Option<&'static dyn Manager> {
    all().into_iter().find(|m| m.id() == id)
}

/// Package managers Lenstica can detect but not configure.
pub struct Unsupported {
    pub id: &'static str,
    pub name: &'static str,
    pub binaries: &'static [&'static str],
    pub note: &'static str,
}

pub const NO_SETTING: &str = "no user-level minimum-age setting that Lenstica can manage";

pub const UNSUPPORTED: &[Unsupported] = &[
    Unsupported {
        id: "brew",
        name: "Homebrew",
        binaries: &["brew"],
        note: NO_SETTING,
    },
    Unsupported {
        id: "gem",
        name: "RubyGems",
        binaries: &["gem"],
        note: NO_SETTING,
    },
    Unsupported {
        id: "go",
        name: "Go modules",
        binaries: &["go"],
        note: NO_SETTING,
    },
    Unsupported {
        id: "composer",
        name: "Composer",
        binaries: &["composer"],
        note: NO_SETTING,
    },
    Unsupported {
        id: "deno",
        name: "Deno",
        binaries: &["deno"],
        note: "per-project only: set minimumDependencyAge in each deno.json",
    },
    Unsupported {
        id: "conda",
        name: "conda",
        binaries: &["conda", "mamba", "micromamba"],
        note: NO_SETTING,
    },
    Unsupported {
        id: "pixi",
        name: "pixi",
        binaries: &["pixi"],
        note: NO_SETTING,
    },
    Unsupported {
        id: "dotnet",
        name: "NuGet (dotnet)",
        binaries: &["dotnet", "nuget"],
        note: NO_SETTING,
    },
    Unsupported {
        id: "maven",
        name: "Maven",
        binaries: &["mvn"],
        note: NO_SETTING,
    },
    Unsupported {
        id: "gradle",
        name: "Gradle",
        binaries: &["gradle"],
        note: NO_SETTING,
    },
    Unsupported {
        id: "cocoapods",
        name: "CocoaPods",
        binaries: &["pod"],
        note: NO_SETTING,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// Enforces exactly the configured age.
    Ok,
    /// Enforces more than the configured age.
    Stronger,
    /// No setting, or one that disables the cooldown.
    Missing,
    /// Enforces less than the configured age.
    Weaker,
    /// Installed release predates the setting.
    Outdated,
    /// The setting could not be read.
    Error,
}

impl State {
    pub fn is_problem(self) -> bool {
        matches!(
            self,
            State::Missing | State::Weaker | State::Outdated | State::Error
        )
    }

    /// Problems `apply` can fix by writing the setting.
    pub fn is_fixable(self) -> bool {
        matches!(self, State::Missing | State::Weaker | State::Error)
    }

    /// A stable name for finding keys, which must not change with a rename.
    pub fn key(self) -> &'static str {
        match self {
            State::Ok => "Ok",
            State::Stronger => "Stronger",
            State::Missing => "Missing",
            State::Weaker => "Weaker",
            State::Outdated => "Outdated",
            State::Error => "Error",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ManagerStatus {
    pub id: &'static str,
    pub name: &'static str,
    pub binary: String,
    pub version: Option<String>,
    pub min_version: String,
    pub setting: &'static str,
    pub location: String,
    /// The file behind `location`, watched by the menu bar app for hand edits.
    #[serde(skip)]
    pub path: PathBuf,
    pub current: Option<String>,
    pub current_age: Option<String>,
    pub target: String,
    pub state: State,
    pub detail: Option<String>,
    pub note: Option<String>,
}

pub fn locate(m: &dyn Manager, ctx: &Ctx) -> Option<Tool> {
    let bin = m
        .binaries()
        .iter()
        .find_map(|b| exec::find(b, &ctx.search))?;
    let (version, version_text) = exec::version_text_of(&bin, &ctx.search).unzip();
    Some(Tool {
        bin,
        version,
        version_text,
    })
}

pub fn inspect(m: &dyn Manager, tool: &Tool, ctx: &Ctx) -> ManagerStatus {
    let mut status = ManagerStatus {
        id: m.id(),
        name: m.name(),
        binary: tilde(&tool.bin),
        version: tool.version.map(|v| v.to_string()),
        min_version: m.min_version().to_string(),
        setting: m.setting(),
        location: String::new(),
        path: m.location(tool),
        current: None,
        current_age: None,
        target: m.target(ctx.days),
        state: State::Ok,
        detail: None,
        note: None,
    };
    status.location = tilde(&status.path);
    match m.gate(tool.version) {
        Gate::TooOld => {
            status.state = State::Outdated;
            status.detail = Some(format!("needs {} {} or newer", m.name(), m.min_version()));
            return status;
        }
        Gate::Note(note) => status.note = Some(note),
        Gate::Supported => {}
    }
    match m.read(tool, ctx) {
        Err(e) => {
            status.state = State::Error;
            status.detail = Some(format!("{e:#}"));
        }
        Ok(None) => status.state = State::Missing,
        Ok(Some(raw)) => {
            let secs = parse_age(&raw, m.bare_unit(), ctx.now);
            status.current_age = secs.map(humanize);
            status.current = Some(raw);
            status.state = match secs {
                None => {
                    status.detail = Some("value not recognised".to_string());
                    State::Error
                }
                Some(_) if !m.accepts(status.current.as_deref().unwrap_or_default()) => {
                    status.detail = Some(format!(
                        "{} does not understand this value; it expects {}",
                        m.name(),
                        m.target(ctx.days)
                    ));
                    State::Error
                }
                Some(0) => State::Missing,
                Some(s) if s < ctx.target_secs() => State::Weaker,
                Some(s) if s > ctx.target_secs() => State::Stronger,
                Some(_) => State::Ok,
            };
        }
    }
    status
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Make every manager enforce exactly the configured age.
    Exact,
    /// Only fix managers that enforce less than the configured age.
    ProblemsOnly,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Action {
    Changed { from: Option<String>, to: String },
    WouldChange { from: Option<String>, to: String },
    Unchanged,
    Skipped { reason: String },
    Failed { error: String },
}

#[derive(Debug, Clone, Serialize)]
pub struct Outcome {
    pub id: &'static str,
    pub name: &'static str,
    pub location: String,
    #[serde(flatten)]
    pub action: Action,
}

pub fn apply(m: &dyn Manager, ctx: &Ctx, mode: Mode, dry_run: bool) -> Option<Outcome> {
    let tool = locate(m, ctx)?;
    let before = inspect(m, &tool, ctx);
    let target = before.target.clone();
    let wanted = match before.state {
        State::Outdated => {
            let reason = before.detail.clone().unwrap_or_default();
            return Some(outcome(&before, Action::Skipped { reason }));
        }
        State::Ok => false,
        State::Stronger => mode == Mode::Exact,
        State::Missing | State::Weaker | State::Error => true,
    };
    let from = before.current.clone();
    let action = if !wanted {
        Action::Unchanged
    } else if dry_run {
        Action::WouldChange { from, to: target }
    } else {
        match m.write(&tool, &target, ctx) {
            Err(e) => Action::Failed {
                error: format!("{e:#}"),
            },
            Ok(()) => {
                let after = inspect(m, &tool, ctx);
                if after.state == State::Ok {
                    Action::Changed { from, to: target }
                } else {
                    Action::Failed {
                        error: format!(
                            "wrote {target}, but {} now reports {}",
                            m.name(),
                            after.current.as_deref().unwrap_or("nothing")
                        ),
                    }
                }
            }
        }
    };
    Some(outcome(&before, action))
}

fn outcome(status: &ManagerStatus, action: Action) -> Outcome {
    Outcome {
        id: status.id,
        name: status.name,
        location: status.location.clone(),
        action,
    }
}

/// Apply to every enabled manager (or the `only` subset) in parallel.
pub fn apply_all(
    cfg: &Config,
    ctx: &Ctx,
    only: &[String],
    mode: Mode,
    dry_run: bool,
) -> Vec<Outcome> {
    let selected: Vec<&'static dyn Manager> = all()
        .into_iter()
        .filter(|m| cfg.is_enabled(m.id()))
        .filter(|m| only.is_empty() || only.iter().any(|o| o == m.id()))
        .collect();
    std::thread::scope(|s| {
        let handles: Vec<_> = selected
            .iter()
            .map(|&m| (m, s.spawn(move || apply(m, ctx, mode, dry_run))))
            .collect();
        handles
            .into_iter()
            .filter_map(|(m, h)| {
                // A manager whose thread panicked is reported, not dropped.
                h.join().unwrap_or_else(|_| {
                    Some(Outcome {
                        id: m.id(),
                        name: m.name(),
                        location: String::new(),
                        action: Action::Failed {
                            error: "crashed while applying the setting".to_string(),
                        },
                    })
                })
            })
            .collect()
    })
}

/// `config get` answers that mean "not set".
pub(crate) fn unset_marker(value: &str) -> bool {
    matches!(value.trim(), "" | "null" | "undefined" | "None")
}

/// `N days` / `1 day`, the duration syntax uv and Cargo read.
pub(crate) fn days_text(days: u32) -> String {
    format!("{days} {}", if days == 1 { "day" } else { "days" })
}

fn program(tool: &Tool) -> String {
    tool.bin.file_stem().map_or_else(
        || tool.bin.display().to_string(),
        |s| s.to_string_lossy().into_owned(),
    )
}

/// A setting the tool prints with `args` (`npm config get x`): its last
/// line, `None` when unset. `missing` is the tool's error for an unset key,
/// for tools that fail instead of printing nothing.
pub(crate) fn cli_get(
    tool: &Tool,
    ctx: &Ctx,
    args: &[&str],
    missing: Option<&str>,
) -> Result<Option<String>> {
    let out = exec::run(&tool.bin, args, &ctx.search)?;
    if !out.success {
        if missing.is_some_and(|m| out.stderr.contains(m)) {
            return Ok(None);
        }
        bail!(
            "`{} {}` failed: {}",
            program(tool),
            args.join(" "),
            out.error_text()
        );
    }
    Ok(out
        .last_line()
        .filter(|v| !unset_marker(v))
        .map(str::to_string))
}

/// Set a setting with the tool itself (`npm config set x=1`).
pub(crate) fn cli_set(tool: &Tool, ctx: &Ctx, args: &[&str]) -> Result<()> {
    let out = exec::run(&tool.bin, args, &ctx.search)?;
    if !out.success {
        bail!(
            "`{} {}` failed: {}",
            program(tool),
            args.join(" "),
            out.error_text()
        );
    }
    Ok(())
}

/// Read `keys` from a TOML settings file; `None` when the file or key is missing.
pub(crate) fn toml_file_get(path: &Path, keys: &[&str]) -> Result<Option<String>> {
    use anyhow::Context as _;
    match crate::files::read_optional(path)? {
        Some(src) => crate::files::toml_get(&src, keys).with_context(|| path.display().to_string()),
        None => Ok(None),
    }
}

/// Set `keys` in a TOML settings file, creating it if needed.
pub(crate) fn toml_file_set(path: &Path, keys: &[&str], value: toml_edit::Value) -> Result<()> {
    use anyhow::Context as _;
    let src = crate::files::read_optional(path)?.unwrap_or_default();
    let updated =
        crate::files::toml_set(&src, keys, value).with_context(|| path.display().to_string())?;
    crate::files::write_atomic(path, &updated)
}
