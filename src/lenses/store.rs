//! The latest result of every lens, kept in `~/.local/state/lenstica/findings.json`,
//! and the notifications for findings not seen before.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use lenstica_lens::{Finding, Report, Severity};
use serde::{Deserialize, Serialize};

use super::Registered;
use crate::config::Config;
use crate::files;
use crate::notify;
use crate::paths;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunResult {
    pub id: String,
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
    files::read_json(&path()).unwrap_or_default()
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
        lines.push(format!(
            "{}: {} new {} ({} worst)",
            result.title,
            fresh.len(),
            if fresh.len() == 1 {
                "finding"
            } else {
                "findings"
            },
            worst.label()
        ));
        lines.extend(fresh.iter().take(3).map(|f| format!("• {}", f.title)));
    }
    if cfg.monitor.notify && !lines.is_empty() {
        let critical = fresh.iter().any(|f| f.severity == Severity::Critical);
        let title = if critical {
            "Lenstica: CRITICAL"
        } else {
            "Lenstica"
        };
        if let Err(e) = notify::send(title, &lines.join("\n")) {
            eprintln!("lenstica: notification failed: {e:#}");
        }
    }
    lines
}
