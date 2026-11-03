//! The interface every Lenstica lens implements.
//!
//! Lenstica runs a set of independent lenses (package-manager settings,
//! too-new packages, known vulnerabilities, exposed secrets, ...). Each one
//! returns [`Finding`]s in this one format, and everything that shows results
//! (the menu bar app, the window, notifications, `lenstica findings`) works
//! from findings alone, so a new lens appears everywhere without UI changes.
//!
//! There are three ways to add one:
//!
//! - **A Rust crate**: depend on this crate, implement [`Lens`], and add the
//!   lens to Lenstica's registry (`src/lenses/mod.rs`) behind a feature.
//! - **Any executable**: declare it in `lenstica.toml` under `[[external]]` with
//!   `format = "lenstica"` and print a [`Report`] as JSON on stdout.
//! - **An existing scanner** (gitleaks, osv-scanner, trufflehog): declare it
//!   under `[[external]]` with its own `format`, and Lenstica translates.
//!
//! Every lens registers with one or more [`Category`]s, which organise the
//! window and the menu bar menu. Findings must never carry secret values: name
//! the file, the setting and the kind of credential, not its contents.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{MAIN_SEPARATOR, Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

pub use anyhow::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Worth knowing; not a problem.
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Low and above: counted as findings rather than information. Whether a
    /// problem also turns the menu bar icon orange and fails `lenstica check`
    /// is up to the user's `monitor.alert_severity`.
    pub fn is_problem(self) -> bool {
        self >= Severity::Low
    }

    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// What a lens looks at. The window's sidebar and the menu bar menu are
/// organised by category; every lens registers with one or more
/// ([`Lens::categories`]), and every finding names one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    // The aliases are the names findings used before there were categories.
    #[serde(alias = "agent")]
    Agents,
    #[serde(
        alias = "cooldown",
        alias = "vulnerability",
        alias = "deprecated",
        alias = "settings"
    )]
    Packages,
    Software,
    #[serde(alias = "secret")]
    Secrets,
    Malware,
    Network,
    #[serde(alias = "telemetry")]
    Privacy,
}

/// Well-known topics: the kinds of problem within a category, offered as
/// filters in the window ([`Category::topics`]). A lens may use others.
pub mod topic {
    pub const PROMPT_INJECTION: &str = "prompt-injection";
    pub const HIDDEN_TEXT: &str = "hidden-text";
    pub const PERMISSIONS: &str = "permissions";
    /// Agent instructions or settings that break rules you set (no lens reports it yet).
    pub const RULES_VIOLATIONS: &str = "rules-violations";
    pub const MCP: &str = "mcp";
    pub const COOLDOWN: &str = "cooldown";
    pub const INSTALL_SCRIPTS: &str = "install-scripts";
    pub const VULNERABILITIES: &str = "vulnerabilities";
    pub const DEPRECATED: &str = "deprecated";
    pub const TOO_NEW: &str = "too-new";
    /// Installed software far behind its current release (no lens reports it yet).
    pub const OUTDATED: &str = "outdated";
    pub const AUTO_UPDATES: &str = "auto-updates";
    pub const EXPOSED: &str = "exposed";
    pub const LEAKED: &str = "leaked";
    pub const TELEMETRY: &str = "telemetry";
    pub const OPEN_PORTS: &str = "open-ports";
}

impl Category {
    /// Every category, in display order.
    pub const ALL: [Category; 7] = [
        Category::Agents,
        Category::Packages,
        Category::Software,
        Category::Secrets,
        Category::Malware,
        Category::Network,
        Category::Privacy,
    ];

    /// The id used in settings, reports and `--category`: `agents`.
    pub fn id(self) -> &'static str {
        match self {
            Category::Agents => "agents",
            Category::Packages => "packages",
            Category::Software => "software",
            Category::Secrets => "secrets",
            Category::Malware => "malware",
            Category::Network => "network",
            Category::Privacy => "privacy",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Category::Agents => "AI agents",
            Category::Packages => "Packages",
            Category::Software => "Software",
            Category::Secrets => "Secrets",
            Category::Malware => "Malware",
            Category::Network => "Network",
            Category::Privacy => "Privacy",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Category::Agents => {
                "The instructions, skills, hooks and MCP servers your coding agents load, and the permissions they run with."
            }
            Category::Packages => {
                "Your dependencies and the package managers that install them: the cooldown, install scripts, known vulnerabilities and deprecations."
            }
            Category::Software => {
                "Software installed on this machine and how it updates: tools and apps newer than the cooldown, and automatic updates."
            }
            Category::Secrets => {
                "Credentials a malicious package running as you could read on disk, and credentials leaked into code."
            }
            Category::Malware => {
                "Known malicious packages and releases, and protection against installing them."
            }
            Category::Network => {
                "Connections and services on this machine that others could reach or listen to."
            }
            Category::Privacy => "Packages and tools that report on you: telemetry and tracking.",
        }
    }

    /// The well-known topics within this category, as (id, title), in order.
    pub fn topics(self) -> &'static [(&'static str, &'static str)] {
        use topic::*;
        match self {
            Category::Agents => &[
                (PROMPT_INJECTION, "Prompt injection"),
                (HIDDEN_TEXT, "Hidden text"),
                (PERMISSIONS, "Elevated permissions"),
                (RULES_VIOLATIONS, "Rules violations"),
                (MCP, "MCP servers"),
            ],
            Category::Packages => &[
                (COOLDOWN, "Cooldown"),
                (INSTALL_SCRIPTS, "Install scripts"),
                (VULNERABILITIES, "Vulnerabilities"),
                (DEPRECATED, "Deprecated"),
            ],
            Category::Software => &[
                (TOO_NEW, "Too new"),
                (OUTDATED, "Outdated"),
                (AUTO_UPDATES, "Auto updates"),
            ],
            Category::Secrets => &[(EXPOSED, "Exposed"), (LEAKED, "Leaked")],
            Category::Privacy => &[(TELEMETRY, "Telemetry")],
            Category::Network => &[(OPEN_PORTS, "Open ports")],
            Category::Malware => &[],
        }
    }
}

/// An id or an older name: `agents`, `secret`.
impl FromStr for Category {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        serde_json::from_value(serde_json::Value::String(s.trim().to_ascii_lowercase())).map_err(
            |_| {
                let ids: Vec<&str> = Category::ALL.iter().map(|c| c.id()).collect();
                format!("unknown category `{s}` (one of {})", ids.join(", "))
            },
        )
    }
}

/// Where a finding is. `label` is for display (`~/code/app/.env`, `npm -g`);
/// `path`, when set, is a file the UI can open.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
}

impl Location {
    pub fn label(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            path: None,
            line: None,
        }
    }

    pub fn file(label: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self {
            label: label.into(),
            path: Some(path.into()),
            line: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Finding {
    /// Stable identity within its lens. A finding is notified once per key,
    /// so include whatever makes it a *different* problem (a package version,
    /// a value that changed) and nothing that changes on its own (an age).
    pub key: String,
    pub severity: Severity,
    pub category: Category,
    /// The kind of problem within the category: one of [`Category::topics`]
    /// when one fits (`cooldown`, `prompt-injection`), or empty.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub topic: String,
    pub title: String,
    #[serde(default)]
    pub detail: String,
    #[serde(default)]
    pub locations: Vec<Location>,
    /// What to do about it.
    #[serde(default)]
    pub remedy: String,
    #[serde(default)]
    pub links: Vec<String>,
    /// [`Lens::fix`] can resolve it.
    #[serde(default)]
    pub fixable: bool,
    /// Filled in by Lenstica: the id of the lens that produced it.
    /// (`checker` in reports from before lenses were called lenses.)
    #[serde(default, alias = "checker")]
    pub lens: String,
}

impl Finding {
    pub fn new(
        key: impl Into<String>,
        severity: Severity,
        category: Category,
        title: impl Into<String>,
    ) -> Self {
        Self {
            key: key.into(),
            severity,
            category,
            topic: String::new(),
            title: title.into(),
            detail: String::new(),
            locations: Vec::new(),
            remedy: String::new(),
            links: Vec::new(),
            fixable: false,
            lens: String::new(),
        }
    }

    pub fn topic(mut self, topic: impl Into<String>) -> Self {
        self.topic = topic.into();
        self
    }

    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }

    pub fn remedy(mut self, remedy: impl Into<String>) -> Self {
        self.remedy = remedy.into();
        self
    }

    pub fn at(mut self, location: Location) -> Self {
        self.locations.push(location);
        self
    }

    pub fn link(mut self, url: impl Into<String>) -> Self {
        self.links.push(url.into());
        self
    }

    pub fn fixable(mut self) -> Self {
        self.fixable = true;
        self
    }
}

/// What one run of a lens produced. Also the JSON an external lens
/// prints with `format = "lenstica"`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Report {
    #[serde(default)]
    pub findings: Vec<Finding>,
    /// One line for the UI: "6 package managers hold back versions newer than 7 days".
    #[serde(default)]
    pub summary: String,
    /// Things that were checked and are fine, for the window's details pane.
    #[serde(default)]
    pub passing: Vec<String>,
    /// Things the lens changed during this run ("Reset npm min-release-age to 7").
    /// Each is notified.
    #[serde(default)]
    pub actions: Vec<String>,
    /// Files whose change should re-run this lens straight away (the menu
    /// bar app polls them every few seconds), e.g. the configs it enforces.
    #[serde(default)]
    pub watch: Vec<PathBuf>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Npm,
    Pypi,
    /// Rust crates from crates.io.
    Crates,
}

impl Ecosystem {
    pub fn label(self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::Pypi => "pypi",
            Ecosystem::Crates => "crates",
        }
    }

    /// The ecosystem name OSV and most advisory databases use.
    pub fn osv_name(self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::Pypi => "PyPI",
            Ecosystem::Crates => "crates.io",
        }
    }
}

/// A package from a lockfile or a global install, collected once per pass and
/// shared by every lens that looks at dependencies.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Package {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
}

/// A lockfile or a global install.
#[derive(Clone, Debug)]
pub struct Source {
    /// `~/code/app/pnpm-lock.yaml`, or `npm -g`.
    pub label: String,
    pub path: Option<PathBuf>,
    /// Upper bound on when the lockfile last changed (commit time or mtime).
    pub locked_at: Option<SystemTime>,
    pub packages: Vec<Package>,
}

impl Source {
    pub fn location(&self) -> Location {
        Location {
            label: self.label.clone(),
            path: self.path.clone(),
            line: None,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Inventory {
    pub sources: Vec<Source>,
    /// Lockfiles that could not be read, as "path: error".
    pub errors: Vec<String>,
}

impl Inventory {
    /// Every distinct package, with the sources that contain it.
    pub fn by_package(&self) -> BTreeMap<&Package, Vec<&Source>> {
        let mut map: BTreeMap<&Package, Vec<&Source>> = BTreeMap::new();
        for source in &self.sources {
            for package in &source.packages {
                let list = map.entry(package).or_default();
                // Sources are visited in order, so a repeat can only be the last one.
                if !list.last().is_some_and(|s| std::ptr::eq(*s, source)) {
                    list.push(source);
                }
            }
        }
        map
    }
}

/// What Lenstica provides to a lens on each run.
pub struct Context<'a> {
    pub now: SystemTime,
    /// The configured minimum release age.
    pub min_days: u32,
    /// Directories to search (`scan.roots` plus their git worktrees).
    pub roots: &'a [PathBuf],
    /// Folders inside the roots that must not be searched (`scan.exclude`).
    /// A lens walking `roots` itself should skip whatever this matches.
    pub exclude: &'a Exclude,
    /// PATH to find tools with; login agents start with a minimal one.
    pub search_path: &'a OsStr,
    /// A directory of the lens's own for caches and state.
    pub state_dir: PathBuf,
    /// The lens's `[lenses.<id>]` table from lenstica.toml, as JSON.
    pub settings: &'a serde_json::Value,
    /// Make no network requests; use caches only.
    pub offline: bool,
    /// Packages from every lockfile under `roots` and global installs,
    /// collected on first use and shared by all lenses in the pass.
    pub inventory: &'a dyn Fn() -> Result<std::sync::Arc<Inventory>>,
}

/// Folders left out of every search: by path (the folder and everything below
/// it), or by bare name (any folder called that, at any depth).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Exclude {
    pub paths: Vec<PathBuf>,
    pub names: Vec<String>,
}

impl Exclude {
    /// `~/code/old` and `/abs/path` are paths; `fixtures` is a name. `~` must
    /// already be expanded by the caller (Lenstica does it from the settings).
    /// A relative path such as `apps/legacy` matches that folder under any root.
    pub fn new(entries: impl IntoIterator<Item = PathBuf>) -> Self {
        let mut out = Self::default();
        for entry in entries {
            let text = entry.to_string_lossy();
            let text = text.trim_end_matches(['/', '\\']);
            if text.is_empty() {
                continue;
            }
            if text.contains(['/', '\\']) {
                out.paths.push(PathBuf::from(text));
            } else {
                out.names.push(text.to_string());
            }
        }
        out
    }

    pub fn is_empty(&self) -> bool {
        self.paths.is_empty() && self.names.is_empty()
    }

    /// Whether `path` is an excluded folder or inside one.
    pub fn skips(&self, path: &Path) -> bool {
        self.paths.iter().any(|p| {
            if p.is_absolute() {
                path.starts_with(p)
            } else {
                path.ancestors().any(|a| a.ends_with(p))
            }
        }) || (!self.names.is_empty()
            && path.components().any(|c| {
                let c = c.as_os_str().to_string_lossy();
                self.names.iter().any(|n| *n == c)
            }))
    }
}

pub trait Lens: Send + Sync {
    /// Stable, lowercase, used in settings and as the finding namespace: `secrets`.
    fn id(&self) -> &str;
    fn title(&self) -> &str;
    fn description(&self) -> &str;
    /// The categories this lens appears under, the main one first; at least one.
    fn categories(&self) -> &[Category];
    /// What the lens relies on outside Lenstica, in one sentence for the user:
    /// a service it sends data to, or a tool it runs or recommends ("Sends the
    /// names and versions of your packages to OSV.dev."). A lens with one is
    /// off until the user turns it on.
    fn third_party(&self) -> Option<&str> {
        None
    }
    fn default_interval(&self) -> Duration {
        Duration::from_secs(30 * 60)
    }
    fn run(&self, cx: &Context) -> Result<Report>;
    /// Resolve a finding this lens marked `fixable`; returns what was done.
    fn fix(&self, _cx: &Context, finding: &Finding) -> Result<String> {
        anyhow::bail!("{} cannot fix `{}` automatically", self.id(), finding.key)
    }
}

fn env_dir(var: &str) -> Option<PathBuf> {
    std::env::var_os(var)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

/// The user's home directory (`HOME`, or `USERPROFILE` on Windows), the way
/// Lenstica resolves it, so lenses read the same files it does.
pub fn home_dir() -> PathBuf {
    let primary = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    env_dir(primary)
        .or_else(|| env_dir("HOME"))
        .unwrap_or_else(|| PathBuf::from("."))
}

/// A path with the home directory abbreviated to `~`, for labels.
pub fn tilde(path: &Path) -> String {
    match path.strip_prefix(home_dir()) {
        Ok(rest) if rest.as_os_str().is_empty() => "~".to_string(),
        Ok(rest) => format!("~{MAIN_SEPARATOR}{}", rest.display()),
        Err(_) => path.display().to_string(),
    }
}

/// Characters that make a reasonable stable key out of free text.
pub fn key_part(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "@/._-:".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exclude_matches_paths_and_names() {
        let ex = Exclude::new([
            PathBuf::from("/home/me/code/old/"),
            PathBuf::from("fixtures"),
        ]);
        assert!(ex.skips(std::path::Path::new("/home/me/code/old")));
        assert!(ex.skips(std::path::Path::new("/home/me/code/old/app/.env")));
        assert!(!ex.skips(std::path::Path::new("/home/me/code/older")));
        assert!(ex.skips(std::path::Path::new("/home/me/code/app/fixtures/.env")));
        assert!(!ex.skips(std::path::Path::new("/home/me/code/app/fixtures2")));
    }

    #[test]
    fn external_report_json_round_trips() {
        let json = r#"{"summary":"1 issue","findings":[{"key":"k","severity":"high","category":"secret","title":"t",
            "locations":[{"label":"~/x/.env","path":"/home/u/x/.env"}]}]}"#;
        let report: Report = serde_json::from_str(json).unwrap();
        assert_eq!(report.findings[0].severity, Severity::High);
        assert!(report.findings[0].severity.is_problem());
        assert!(!Severity::Info.is_problem());
        assert_eq!(
            report.findings[0].locations[0].path.as_deref(),
            Some(std::path::Path::new("/home/u/x/.env"))
        );
        assert!(report.passing.is_empty() && report.actions.is_empty());
        assert_eq!(report.findings[0].category, Category::Secrets);
    }

    #[test]
    fn categories_read_ids_and_older_names() {
        for c in Category::ALL {
            assert_eq!(c.id().parse::<Category>(), Ok(c));
            assert_eq!(serde_json::to_value(c).unwrap(), c.id());
        }
        assert_eq!("vulnerability".parse(), Ok(Category::Packages));
        assert_eq!("Agent".parse(), Ok(Category::Agents));
        assert!(
            "weather"
                .parse::<Category>()
                .unwrap_err()
                .contains("agents, packages")
        );
    }
}
