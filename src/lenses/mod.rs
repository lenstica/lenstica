//! The lens registry and runner.
//!
//! Every check is a [`Lens`] from the `lenstica-lens` crate: built in
//! (this module), compiled in from a plugin crate (`lenstica-secrets`), or an
//! external tool declared under `[[external]]`. All of them produce the same
//! [`Finding`]s, which [`store`] keeps and notifies, and which the CLI, the
//! menu and the window display without knowing which lens made them.

mod age;
mod agents;
mod aikido;
mod cvss;
mod deprecated;
mod external;
mod homebrew;
mod managers;
mod osv;
mod projects;
mod safe_chain;
mod scripts;
pub mod shared;
mod software;
pub mod store;

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::panic::{self, AssertUnwindSafe};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context as _, Result, anyhow, bail};
use lenstica_lens::{Context, Finding, Lens, Severity};

use crate::config::Config;
use crate::managers::Ctx;
use crate::paths;
use store::RunResult;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    Builtin,
    /// Compiled in from a separate crate implementing the lens API.
    Plugin,
    External,
}

impl Origin {
    pub fn label(self) -> &'static str {
        match self {
            Origin::Builtin => "built-in",
            Origin::Plugin => "plugin crate",
            Origin::External => "external tool",
        }
    }
}

/// Which settings section supplies a lens's defaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Group {
    /// `[monitor]`: package-manager settings and project files.
    Settings,
    /// `[audit]`: everything that looks at locked and installed packages.
    Dependencies,
    Other,
}

#[derive(Clone)]
pub struct Registered {
    pub lens: Arc<dyn Lens>,
    pub origin: Origin,
    pub group: Group,
}

impl Registered {
    pub fn id(&self) -> &str {
        self.lens.id()
    }
}

fn builtin(lens: impl Lens + 'static, group: Group) -> Registered {
    Registered {
        lens: Arc::new(lens),
        origin: Origin::Builtin,
        group,
    }
}

/// Every lens, in display order.
pub fn registry(cfg: &Config) -> Vec<Registered> {
    let mut all = vec![
        builtin(managers::Managers, Group::Settings),
        builtin(projects::ProjectSettings, Group::Settings),
        builtin(age::PackageAge, Group::Dependencies),
        builtin(osv::Vulnerabilities, Group::Dependencies),
        builtin(aikido::AikidoMalware, Group::Dependencies),
        builtin(deprecated::Deprecated, Group::Dependencies),
        builtin(software::SoftwareAge, Group::Other),
        builtin(scripts::InstallScripts, Group::Settings),
        builtin(homebrew::HomebrewUpdates, Group::Settings),
        builtin(safe_chain::SafeChain, Group::Other),
        builtin(agents::AgentInstructions, Group::Other),
    ];
    // Plugin crates: each one is a dependency implementing `lenstica_lens::Lens`,
    // registered here behind its feature.
    #[cfg(feature = "secrets")]
    all.push(Registered {
        lens: Arc::new(lenstica_secrets::Secrets),
        origin: Origin::Plugin,
        group: Group::Other,
    });
    all.extend(external::from_config(cfg));
    all
}

pub fn find(cfg: &Config, id: &str) -> Result<Registered> {
    let all = registry(cfg);
    let known: Vec<String> = all.iter().map(|r| r.id().to_string()).collect();
    all.into_iter()
        .find(|r| r.id() == id)
        .with_context(|| format!("unknown lens `{id}` (known: {})", known.join(", ")))
}

fn own_settings<'a>(cfg: &'a Config, id: &str) -> Option<&'a toml::Table> {
    cfg.lenses.get(id)
}

pub fn enabled(cfg: &Config, r: &Registered) -> bool {
    if let Some(on) = own_settings(cfg, r.id())
        .and_then(|t| t.get("enabled"))
        .and_then(toml::Value::as_bool)
    {
        return on;
    }
    match r.group {
        Group::Dependencies => cfg.audit.enabled,
        _ => true,
    }
}

pub fn interval(cfg: &Config, r: &Registered) -> Duration {
    if let Some(m) = own_settings(cfg, r.id())
        .and_then(|t| t.get("interval_minutes"))
        .and_then(toml::Value::as_integer)
    {
        return Duration::from_secs(m.max(1) as u64 * 60);
    }
    match r.group {
        Group::Settings => cfg.interval(),
        Group::Dependencies => cfg.audit_interval(),
        Group::Other => r.lens.default_interval(),
    }
}

/// The lens's `[lenses.<id>]` table as JSON, for [`Context::settings`].
fn settings_json(cfg: &Config, id: &str) -> serde_json::Value {
    own_settings(cfg, id)
        .and_then(|t| serde_json::to_value(t).ok())
        .unwrap_or_else(|| serde_json::Value::Object(Default::default()))
}

pub fn parse_severity(s: &str) -> Option<Severity> {
    Some(match s.trim().to_ascii_lowercase().as_str() {
        "info" => Severity::Info,
        "low" => Severity::Low,
        "medium" | "moderate" => Severity::Medium,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        _ => return None,
    })
}

/// The lowest severity that counts as a problem.
pub fn threshold(cfg: &Config) -> Severity {
    parse_severity(&cfg.monitor.alert_severity).unwrap_or(Severity::Medium)
}

/// The lowest severity that is notified (`monitor.notify_severity`, else the alert threshold).
pub fn notify_threshold(cfg: &Config) -> Severity {
    parse_severity(&cfg.monitor.notify_severity).unwrap_or_else(|| threshold(cfg))
}

/// Whether this lens's findings are notified (`[lenses.<id>] notify`).
pub fn notifies(cfg: &Config, id: &str) -> bool {
    own_settings(cfg, id)
        .and_then(|t| t.get("notify"))
        .and_then(toml::Value::as_bool)
        .unwrap_or(true)
}

pub fn is_alert(cfg: &Config, f: &Finding) -> bool {
    f.severity >= threshold(cfg)
}

/// Every finding category the built-in lenses use, for filters and schemas.
pub const CATEGORIES: [&str; 8] = [
    "malware",
    "vulnerability",
    "secret",
    "cooldown",
    "deprecated",
    "settings",
    "agent",
    "telemetry",
];

/// Most severe first, then by title: the order every list of findings uses.
pub fn by_severity(a: &Finding, b: &Finding) -> Ordering {
    b.severity
        .cmp(&a.severity)
        .then_with(|| a.title.cmp(&b.title))
}

/// The ids of the lenses that exist and are turned on.
pub fn enabled_ids(cfg: &Config) -> BTreeSet<String> {
    registry(cfg)
        .iter()
        .filter(|r| enabled(cfg, r))
        .map(|r| r.id().to_string())
        .collect()
}

/// Stored results of the lenses that exist and are turned on: what the CLI,
/// the menu, the window and MCP all show.
pub fn live_results<'a>(
    cfg: &Config,
    results: &'a BTreeMap<String, RunResult>,
) -> impl Iterator<Item = &'a RunResult> {
    let enabled = enabled_ids(cfg);
    results.values().filter(move |r| enabled.contains(&r.id))
}

/// Build what a lens sees and hand it to `f`.
fn with_context<T>(cfg: &Config, id: &str, offline: bool, f: impl FnOnce(&Context) -> T) -> T {
    let ctx = Ctx::new(cfg);
    let roots = shared::roots(cfg, &ctx.search);
    let settings = settings_json(cfg, id);
    let exclude = cfg.exclude();
    let global = cfg.audit.global;
    let inventory =
        || shared::inventory(cfg, &ctx, &roots.paths, global).map(|inv| inv.api.clone());
    let cx = Context {
        now: SystemTime::now(),
        min_days: cfg.min_days,
        roots: &roots.paths,
        exclude: &exclude,
        search_path: &ctx.search,
        state_dir: paths::state_dir()
            .join("lenses")
            .join(lenstica_lens::key_part(id)),
        settings: &settings,
        offline,
        inventory: &inventory,
    };
    f(&cx)
}

/// Run one lens now and record the result.
pub fn run(cfg: &Config, r: &Registered, offline: bool) -> RunResult {
    let started = Instant::now();
    let outcome = with_context(cfg, r.id(), offline, |cx| {
        std::fs::create_dir_all(&cx.state_dir)
            .with_context(|| format!("cannot create {}", cx.state_dir.display()))?;
        // A panicking lens is reported as failed rather than vanishing.
        panic::catch_unwind(AssertUnwindSafe(|| r.lens.run(cx)))
            .unwrap_or_else(|_| Err(anyhow!("the lens crashed")))
    });
    let result = RunResult::new(r, outcome, started.elapsed());
    if let Err(e) = store::record(&result) {
        eprintln!("lenstica: {e:#}");
    }
    result
}

/// Whether a lens last run at `last` is due again, by the wall clock (time
/// asleep counts, so a laptop that slept past an interval runs it at once).
pub fn is_due(
    cfg: &Config,
    r: &Registered,
    last: Option<chrono::DateTime<chrono::Utc>>,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    last.is_none_or(|t| (now - t).to_std().unwrap_or_default() >= interval(cfg, r))
}

/// The enabled lenses (of `only`, when given) that are due, or all of them with `force`.
pub fn due(cfg: &Config, force: bool, only: &[String]) -> Vec<Registered> {
    let saved = store::load();
    let now = chrono::Utc::now();
    registry(cfg)
        .into_iter()
        .filter(|r| enabled(cfg, r))
        .filter(|r| only.is_empty() || only.iter().any(|o| o == r.id()))
        .filter(|r| force || is_due(cfg, r, saved.get(r.id()).map(|last| last.ran_at), now))
        .collect()
}

/// Run every enabled lens that is due (or all of them with `force`), in parallel.
pub fn run_due(cfg: &Config, force: bool, only: &[String], offline: bool) -> Vec<RunResult> {
    run_all(cfg, &due(cfg, force, only), offline)
}

/// Run these lenses now, in parallel.
pub fn run_all(cfg: &Config, lenses: &[Registered], offline: bool) -> Vec<RunResult> {
    std::thread::scope(|s| {
        let handles: Vec<_> = lenses
            .iter()
            .map(|r| s.spawn(move || run(cfg, r, offline)))
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap_or_else(|e| panic::resume_unwind(e)))
            .collect()
    })
}

/// Fix one finding through the lens that reported it, then re-run that lens.
/// Returns what was done and the new result.
pub fn fix(cfg: &Config, lens_id: &str, key: &str) -> Result<(String, RunResult)> {
    let r = find(cfg, lens_id)?;
    let finding = store::load()
        .get(lens_id)
        .and_then(|res| res.findings.iter().find(|f| f.key == key).cloned())
        .with_context(|| format!("no current finding `{key}` from {lens_id}"))?;
    if !finding.fixable {
        bail!(
            "`{}` cannot be fixed automatically: {}",
            finding.title,
            finding.remedy
        );
    }
    let done = with_context(cfg, lens_id, false, |cx| r.lens.fix(cx, &finding))?;
    Ok((done, run(cfg, &r, false)))
}
