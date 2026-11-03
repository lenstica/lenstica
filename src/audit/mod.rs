//! Collect locked and installed packages, and judge their age.
//!
//! [`collect`] reads every lockfile under the search roots and the global
//! installs (no network). [`classify`] sorts packages by age, two ways:
//!
//! - **Too new**: a version locked or installed right now that was published
//!   less than `min_days` ago. Nobody has had the cooldown's worth of time to
//!   notice if it is malicious.
//! - **Locked while too new**: old enough today, but it was younger than
//!   `min_days` when its lockfile last changed, so it got in around the
//!   cooldown. The lockfile's change time is an upper bound on when the version
//!   was added (git commit time when the file is clean, else its mtime), so
//!   this never reports a version that was in fact old enough; it can miss one
//!   that was added earlier than the file's last change.

pub mod global;
pub mod lockfiles;
pub mod registry;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::duration::humanize;
use crate::exec;
use crate::files;
use crate::managers::Ctx;
use crate::paths::{self, tilde};
use crate::scan;
use lockfiles::{Ecosystem, Locked, Pkg};
use registry::Cache;

/// Where a set of packages came from: a lockfile, or a global install.
pub struct Source {
    pub label: String,
    pub path: Option<PathBuf>,
    pub locked_at: Option<DateTime<Utc>>,
    pub entries: Vec<Locked>,
}

impl Source {
    pub fn location(&self) -> lenstica_lens::Location {
        lenstica_lens::Location {
            label: self.label.clone(),
            path: self.path.clone(),
            line: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    TooNew,
    LockedWhileTooNew,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub kind: Kind,
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
    pub published: DateTime<Utc>,
    /// Age now (too new) or age when the lockfile last changed (locked while too new).
    pub age: String,
    /// Indexes into the sources passed to [`classify`].
    pub sources: Vec<usize>,
}

/// Every package source under the roots, plus global installs.
pub struct Collected {
    pub sources: Vec<Source>,
    pub errors: Vec<String>,
}

pub struct Classified {
    pub findings: Vec<Finding>,
    pub packages: usize,
    /// Packages no public registry could date (private, unpublished, or offline).
    pub unknown: usize,
}

// ---- lockfile change times ---------------------------------------------------

#[derive(Default, Serialize, Deserialize)]
struct LockTimes {
    /// path -> (mtime in ns, lock time in unix seconds), recomputed when the mtime moves.
    files: BTreeMap<String, (i128, i64)>,
}

impl LockTimes {
    fn path() -> PathBuf {
        // v2: v1 trusted git for ignored lockfiles.
        paths::state_dir().join("lockfile-times-v2.json")
    }

    fn load() -> Self {
        files::read_optional(&Self::path())
            .ok()
            .flatten()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    fn save(&self) -> Result<()> {
        files::write_state(&Self::path(), &serde_json::to_string(self)?)
            .context("cannot save lockfile times")
    }

    fn get(&mut self, path: &Path, ctx: &Ctx, git: Option<&Path>) -> Option<DateTime<Utc>> {
        let modified = std::fs::metadata(path).and_then(|m| m.modified()).ok()?;
        let mtime_ns = modified.duration_since(UNIX_EPOCH).ok()?.as_nanos() as i128;
        let key = path.to_string_lossy().into_owned();
        if let Some(&(ns, at)) = self.files.get(&key)
            && ns == mtime_ns
        {
            return DateTime::from_timestamp(at, 0);
        }
        let mtime = DateTime::<Utc>::from(modified);
        let at = git
            .and_then(|g| committed_at(g, path, ctx))
            .map_or(mtime, |c| c.min(mtime));
        self.files.insert(key, (mtime_ns, at.timestamp()));
        Some(at)
    }
}

/// Commit time of the file's last change, only when the working copy matches it.
fn committed_at(git: &Path, path: &Path, ctx: &Ctx) -> Option<DateTime<Utc>> {
    let dir = path.parent()?.to_string_lossy().into_owned();
    let name = path.file_name()?.to_string_lossy().into_owned();
    let status = exec::run(
        git,
        &[
            "-C",
            &dir,
            "status",
            "--porcelain",
            "--ignored",
            "--untracked-files=all",
            "--",
            &name,
        ],
        &ctx.search,
    )
    .ok()?;
    // Empty output only for a tracked, unmodified file. Ignored (`!!`), untracked (`??`)
    // and modified files have a working copy newer than any commit; an ignored file's
    // `git log` would even name an old commit that deleted it.
    if !status.success || !status.stdout.trim().is_empty() {
        return None;
    }
    let log = exec::run(
        git,
        &["-C", &dir, "log", "-1", "--format=%ct", "--", &name],
        &ctx.search,
    )
    .ok()?;
    DateTime::from_timestamp(log.last_line()?.parse().ok()?, 0)
}

// ---- the audit ----------------------------------------------------------------

/// Whether an ignore rule (`name`, or `name@version`; a scoped `@s/pkg`
/// keeps its leading `@`) covers this package.
pub fn ignore_matches<'a>(
    rules: impl IntoIterator<Item = &'a String>,
    name: &str,
    version: &str,
) -> bool {
    rules.into_iter().any(
        |r| match r.rsplit_once('@').filter(|(n, _)| !n.is_empty()) {
            Some((n, v)) => n == name && v == version,
            None => r == name,
        },
    )
}

pub fn ignored(rules: &[String], pkg: &Pkg) -> bool {
    ignore_matches(rules, &pkg.name, &pkg.version)
}

pub fn collect(cfg: &Config, ctx: &Ctx, roots: &[PathBuf], global: bool) -> Result<Collected> {
    let mut errors = Vec::new();
    let git = exec::find("git", &ctx.search);
    let mut times = LockTimes::load();
    let mut sources = Vec::new();
    for path in scan::find_files(roots, &cfg.exclude(), cfg.scan.max_depth, lockfiles::NAMES) {
        let parsed = files::read_optional(&path).and_then(|src| {
            lockfiles::parse(&path, &src.unwrap_or_default(), &cfg.audit.npm_registry)
        });
        match parsed {
            Ok(entries) if !entries.is_empty() => sources.push(Source {
                label: tilde(&path),
                locked_at: times.get(&path, ctx, git.as_deref()),
                path: Some(path),
                entries,
            }),
            Ok(_) => {}
            Err(e) => errors.push(format!("{}: {e:#}", tilde(&path))),
        }
    }
    if let Err(e) = times.save() {
        errors.push(format!("{e:#}"));
    }
    if global {
        sources.extend(global::collect(ctx, &mut errors));
    }
    Ok(Collected { sources, errors })
}

/// Every distinct package that still needs a publish time from a registry.
pub fn undated(sources: &[Source], cfg: &Config) -> BTreeSet<Pkg> {
    sources
        .iter()
        .flat_map(|s| s.entries.iter())
        .filter(|e| e.published.is_none() && !ignored(&cfg.audit.ignore, &e.pkg))
        .map(|e| e.pkg.clone())
        .collect()
}

struct Group {
    published: DateTime<Utc>,
    age_secs: i64,
    sources: Vec<usize>,
}

pub fn classify(sources: &[Source], cache: &Cache, cfg: &Config, ctx: &Ctx) -> Classified {
    let mut groups: BTreeMap<(Kind, Pkg), Group> = BTreeMap::new();
    let mut packages = BTreeSet::new();
    let mut unknown = BTreeSet::new();
    for (index, source) in sources.iter().enumerate() {
        let locked_at = plausible_lock_time(source, cache);
        for entry in &source.entries {
            if ignored(&cfg.audit.ignore, &entry.pkg) {
                continue;
            }
            packages.insert(&entry.pkg);
            let Some(published) = entry.published.or_else(|| cache.lookup(&entry.pkg)) else {
                unknown.insert(&entry.pkg);
                continue;
            };
            let age_now = (ctx.now - published).num_seconds();
            let (kind, age_secs) = if age_now < ctx.target_secs() {
                (Kind::TooNew, age_now.max(0))
            } else if let Some(at) = locked_at {
                let age_then = (at - published).num_seconds();
                if age_then >= ctx.target_secs() {
                    continue;
                }
                (Kind::LockedWhileTooNew, age_then.max(0))
            } else {
                continue;
            };
            let group = groups
                .entry((kind, entry.pkg.clone()))
                .or_insert_with(|| Group {
                    published,
                    age_secs,
                    sources: Vec::new(),
                });
            group.age_secs = group.age_secs.min(age_secs);
            if !group.sources.contains(&index) {
                group.sources.push(index);
            }
        }
    }
    let mut findings: Vec<(i64, Finding)> = groups
        .into_iter()
        .map(|((kind, pkg), g)| {
            let finding = Finding {
                kind,
                ecosystem: pkg.eco,
                name: pkg.name,
                version: pkg.version,
                published: g.published,
                age: if g.age_secs < 60 {
                    "under a minute".to_string()
                } else {
                    humanize(round_age(g.age_secs))
                },
                sources: g.sources,
            };
            (g.age_secs, finding)
        })
        .collect();
    findings.sort_by(|a, b| (a.1.kind, a.0, &a.1.name).cmp(&(b.1.kind, b.0, &b.1.name)));
    Classified {
        findings: findings.into_iter().map(|(_, f)| f).collect(),
        packages: packages.len(),
        unknown: unknown.len(),
    }
}

/// A lockfile cannot have changed before a version it contains was published.
/// When one appears to have (history rewritten with old dates, a copied file,
/// a skewed clock), its change time says nothing, so it is not used.
fn plausible_lock_time(source: &Source, cache: &Cache) -> Option<DateTime<Utc>> {
    let at = source.locked_at?;
    let newest = source
        .entries
        .iter()
        .filter_map(|e| e.published.or_else(|| cache.lookup(&e.pkg)))
        .max();
    newest.is_none_or(|n| n <= at).then_some(at)
}

/// Ages read better rounded: to the hour above a day, to the minute below.
fn round_age(secs: i64) -> i64 {
    use crate::duration::{DAY, HOUR, MINUTE};
    let unit = if secs >= DAY { HOUR } else { MINUTE };
    (secs / unit) * unit
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(now: DateTime<Utc>) -> Ctx {
        Ctx {
            days: 7,
            search: Default::default(),
            now,
        }
    }

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn entry(name: &str, published: &str) -> Locked {
        Locked {
            pkg: Pkg {
                eco: Ecosystem::Npm,
                name: name.into(),
                version: "1.0.0".into(),
            },
            published: Some(at(published)),
            public: true,
        }
    }

    #[test]
    fn classifies_by_age_now_and_at_lock_time() {
        let now = at("2026-11-02T12:00:00Z");
        let sources = vec![
            Source {
                label: "a/pnpm-lock.yaml".into(),
                path: None,
                locked_at: Some(at("2026-10-01T00:00:00Z")),
                entries: vec![
                    entry("snuck-in", "2026-09-29T00:00:00Z"), // 2 days old at lock time
                    entry("fine", "2026-08-01T00:00:00Z"),     // 2 months old at lock time
                ],
            },
            Source {
                label: "b/uv.lock".into(),
                path: None,
                locked_at: Some(at("2026-11-02T00:00:00Z")),
                entries: vec![entry("fresh", "2026-11-01T12:00:00Z")], // 1 day old now
            },
            Source {
                label: "npm -g".into(),
                path: None,
                locked_at: None,
                entries: vec![
                    entry("fresh", "2026-11-01T12:00:00Z"),
                    entry("old-global", "2026-01-01T00:00:00Z"),
                ],
            },
        ];
        let mut cfg = Config::default();
        let report = classify(&sources, &Cache::default(), &cfg, &ctx(now));
        let got: Vec<(Kind, &str, &str, usize)> = report
            .findings
            .iter()
            .map(|f| (f.kind, f.name.as_str(), f.age.as_str(), f.sources.len()))
            .collect();
        assert_eq!(
            got,
            vec![
                (Kind::TooNew, "fresh", "1 day", 2),
                (Kind::LockedWhileTooNew, "snuck-in", "2 days", 1)
            ]
        );
        assert_eq!(report.packages, 4);

        // A lock time older than a package it contains is impossible, so it is not used.
        let impossible = vec![Source {
            label: "copied/package-lock.json".into(),
            path: None,
            locked_at: Some(at("2020-01-01T00:00:00Z")),
            entries: vec![entry("from-2023", "2023-06-01T00:00:00Z")],
        }];
        assert!(
            classify(&impossible, &Cache::default(), &cfg, &ctx(now))
                .findings
                .is_empty()
        );

        cfg.audit.ignore = vec!["fresh".into(), "snuck-in@1.0.0".into()];
        assert!(
            classify(&sources, &Cache::default(), &cfg, &ctx(now))
                .findings
                .is_empty()
        );
    }
}
