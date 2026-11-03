//! The latest result of every lens, kept in `~/.local/state/lenstica/findings.json`,
//! and the notifications for findings not seen before.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use lenstica_lens::{Category, Finding, Report, Severity};
use serde::{Deserialize, Serialize};

use super::Registered;
use crate::config::Config;
use crate::files;
use crate::i18n::t;
use crate::notify;
use crate::paths;

/// The shape of results this version saves. Results saved by an older
/// version are re-run at start (1: findings carry a category and topic).
pub const FORMAT: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunResult {
    pub id: String,
    /// [`FORMAT`] when saved; 0 before there was one.
    #[serde(default)]
    pub format: u32,
    pub title: String,
    pub description: String,
    pub origin: String,
    pub ran_at: DateTime<Utc>,
    pub seconds: f64,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub passing: Vec<String>,
    #[serde(default)]
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub watch: Vec<PathBuf>,
    #[serde(default)]
    pub error: Option<String>,
    /// What the lens changed in this run; notified, not stored.
    #[serde(skip)]
    pub actions: Vec<String>,
}

impl RunResult {
    pub fn new(r: &Registered, outcome: Result<Report>, took: Duration) -> Self {
        let mut result = Self {
            id: r.id().to_string(),
            format: FORMAT,
            title: r.lens.title().to_string(),
            description: r.lens.description().to_string(),
            origin: r.origin.label().to_string(),
            ran_at: Utc::now(),
            seconds: took.as_secs_f64(),
            summary: String::new(),
            passing: Vec::new(),
            findings: Vec::new(),
            watch: Vec::new(),
            error: None,
            actions: Vec::new(),
        };
        match outcome {
            Ok(report) => {
                result.summary = report.summary;
                result.passing = report.passing;
                result.watch = report.watch;
                result.actions = report.actions;
                result.findings = report.findings;
                for f in &mut result.findings {
                    f.lens.clone_from(&result.id);
                }
                place(&mut result.findings, r.lens.categories());
                result.findings.sort_by(super::by_severity);
            }
            Err(e) => result.error = Some(format!("{e:#}")),
        }
        result
    }

    /// The summary, or why the run failed.
    pub fn status_text(&self) -> String {
        self.error
            .as_ref()
            .map_or_else(|| self.summary.clone(), |e| format!("Failed: {e}"))
    }
}

fn path() -> PathBuf {
    paths::state_dir().join("findings.json")
}

pub fn load() -> BTreeMap<String, RunResult> {
    let mut all: BTreeMap<String, RunResult> = files::read_json(&path()).unwrap_or_default();
    // Results saved before there were categories name an older one.
    for r in super::registry(&Config::default()) {
        if let Some(result) = all.get_mut(r.id()) {
            place(&mut result.findings, r.lens.categories());
        }
    }
    all
}

/// A finding goes under a category its lens registered with; one that names
/// another (an older name such as `settings`, or a tool's mistake) goes under
/// the lens's main category.
fn place(findings: &mut [Finding], categories: &[Category]) {
    let Some(main) = categories.first() else {
        return;
    };
    for f in findings {
        if !categories.contains(&f.category) {
            f.category = *main;
        }
    }
}

fn save(all: &BTreeMap<String, RunResult>) -> Result<()> {
    files::write_state(&path(), &serde_json::to_string_pretty(all)?).context("cannot save findings")
}

/// Replace one lens's entry, re-reading the file first.
pub fn record(result: &RunResult) -> Result<()> {
    files::with_state_lock(|| {
        let mut all = load();
        // A failed run keeps the previous findings visible next to the error.
        let mut entry = result.clone();
        if entry.error.is_some()
            && let Some(previous) = all.get(&entry.id)
        {
            entry.findings.clone_from(&previous.findings);
            entry.passing.clone_from(&previous.passing);
            entry.watch.clone_from(&previous.watch);
        }
        all.insert(entry.id.clone(), entry);
        save(&all)
    })
}

/// Drop results of lenses that no longer exist or are turned off.
pub fn prune(cfg: &Config) -> Result<()> {
    let live: BTreeSet<String> = super::registry(cfg)
        .iter()
        .filter(|r| super::enabled(cfg, r))
        .map(|r| r.id().to_string())
        .collect();
    files::with_state_lock(|| {
        let mut all = load();
        let before = all.len();
        all.retain(|id, _| live.contains(id));
        if all.len() == before {
            return Ok(());
        }
        save(&all)
    })
}

fn notified_path() -> PathBuf {
    paths::state_dir().join("notified.json")
}

/// Record which problems of this run are notified, and return the ones not
/// notified before.
fn unseen<'a>(result: &RunResult, problems: &[&'a Finding]) -> Result<Vec<&'a Finding>> {
    files::with_state_lock(|| {
        let mut seen: BTreeMap<String, BTreeSet<String>> =
            files::read_json(&notified_path()).unwrap_or_default();
        let previous = seen.remove(&result.id).unwrap_or_default();
        let fresh = problems
            .iter()
            .copied()
            .filter(|f| !previous.contains(&f.key))
            .collect();
        // A failed run says nothing about whether old problems are gone.
        let current = if result.error.is_none() {
            problems.iter().map(|f| f.key.clone()).collect()
        } else {
            previous
        };
        seen.insert(result.id.clone(), current);
        files::write_state(&notified_path(), &serde_json::to_string(&seen)?)?;
        Ok(fresh)
    })
}

/// Notify what this run changed, and problems not notified before. Returns
/// the lines sent. A problem that goes away and comes back is notified again.
pub fn notify_new(cfg: &Config, result: &RunResult) -> Vec<String> {
    crate::i18n::choose(&cfg.window.language);
    let wanted = super::notifies(cfg, &result.id);
    let threshold = super::notify_threshold(cfg);
    let problems: Vec<&Finding> = if wanted {
        result
            .findings
            .iter()
            .filter(|f| f.severity >= threshold)
            .collect()
    } else {
        Vec::new()
    };
    let fresh = unseen(result, &problems).unwrap_or_else(|e| {
        eprintln!("lenstica: cannot record notifications: {e:#}");
        Vec::new()
    });

    let mut lines = if cfg.monitor.notify_fixes && wanted {
        result.actions.clone()
    } else {
        Vec::new()
    };
    if !fresh.is_empty() {
        let worst = fresh
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(Severity::Info);
        lines.push(t!(
            "notify.newFindings",
            lens = result.title,
            count = fresh.len(),
            severity = t!(&format!("severity.{}", worst.label()))
        ));
        lines.extend(fresh.iter().take(3).map(|f| format!("• {}", f.title)));
    }
    if cfg.monitor.notify && !lines.is_empty() {
        let critical = fresh.iter().any(|f| f.severity == Severity::Critical);
        let title = if critical {
            t!("notify.critical")
        } else {
            t!("notify.title")
        };
        if let Err(e) = notify::send(&title, &lines.join("\n")) {
            eprintln!("lenstica: notification failed: {e:#}");
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn findings_go_under_a_category_their_lens_registered_with() {
        // The Homebrew lens's findings were `settings` before categories, which now reads as Packages.
        let old = r#"{"key":"k","severity":"low","category":"settings","title":"t"}"#;
        let mut findings = vec![serde_json::from_str::<Finding>(old).unwrap()];
        place(&mut findings, &[Category::Software]);
        assert_eq!(findings[0].category, Category::Software);
        let mut malware = vec![Finding::new("m", Severity::High, Category::Malware, "t")];
        place(&mut malware, &[Category::Packages, Category::Malware]);
        assert_eq!(malware[0].category, Category::Malware);
    }
}
