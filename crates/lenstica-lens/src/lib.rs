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
//! Findings must never carry secret values: name the file, the setting and the
//! kind of credential, not its contents.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{MAIN_SEPARATOR, Path, PathBuf};
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
    /// Grouping in the UI: `malware`, `vulnerability`, `secret`, `lenstica`,
    /// `deprecated`, `settings`, or anything a lens needs.
    pub category: String,
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
        category: impl Into<String>,
        title: impl Into<String>,
    ) -> Self {
        Self {
            key: key.into(),
            severity,
            category: category.into(),
            title: title.into(),
            detail: String::new(),
            locations: Vec::new(),
            remedy: String::new(),
            links: Vec::new(),
            fixable: false,
            lens: String::new(),
        }
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
    }
}
