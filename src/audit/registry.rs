//! Publish times and status (deprecated / yanked) from the public registries.
//!
//! A version's publish time never changes, so it is fetched once and cached
//! for good. Status can change (a maintainer deprecates an old release), so it
//! is re-checked weekly, and only when a lens asks for it.
//!
//! npm only exposes per-version times in the full package document, so one
//! fetch per package name answers every version of it. PyPI has a small
//! per-version endpoint.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::lockfiles::{Ecosystem, Pkg};
use crate::config::Audit;
use crate::duration::{DAY, WEEK};
use crate::files;
use crate::http;
use crate::paths;

/// Don't re-ask a registry about a version it could not date for this long
/// (private and unpublished packages would otherwise be re-requested every pass).
/// How long a failed lookup waits before it is tried again.
pub const RETRY_AFTER_SECS: i64 = DAY;
/// How old a deprecated/yanked answer may be before it is refreshed.
const STATUS_TTL_SECS: i64 = WEEK;
const BATCH: usize = 64;

#[derive(Default, Serialize, Deserialize)]
pub struct Cache {
    /// `npm:react@19.0.0` -> RFC 3339 publish time.
    published: BTreeMap<String, String>,
    /// `npm:react@19.0.0` -> unix time of the last lookup that could not date it.
    /// Tracked per version: one npm document answers every version of a name,
    /// but only the versions wanted at the time are kept.
    fetched: BTreeMap<String, i64>,
    /// `npm:inflight@1.0.6` -> "" (fine), "deprecated: <message>" or "yanked: <reason>".
    #[serde(default)]
    status: BTreeMap<String, String>,
    /// Same keys -> unix time the status was read.
    #[serde(default)]
    status_checked: BTreeMap<String, i64>,
}

/// What a registry says about one version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status<'a> {
    Fine,
    /// npm: the maintainers' deprecation message.
    Deprecated(&'a str),
    /// PyPI or crates.io: the reason given.
    Yanked(&'a str),
}

impl<'a> Status<'a> {
    /// The cache keeps `""`, `"deprecated: <message>"` or `"yanked: <reason>"`.
    fn parse(stored: &'a str) -> Self {
        match stored.split_once(": ") {
            Some(("deprecated", msg)) => Self::Deprecated(msg),
            Some(("yanked", msg)) => Self::Yanked(msg),
            _ => Self::Fine,
        }
    }
}

fn version_key(pkg: &Pkg) -> String {
    format!("{}:{}@{}", pkg.eco.label(), pkg.name, pkg.version)
}

pub struct Progress<'a> {
    pub report: &'a dyn Fn(usize, usize),
}

impl Cache {
    fn path() -> PathBuf {
        paths::state_dir().join("publish-times.json")
    }

    pub fn load() -> Self {
        files::read_json(&Self::path()).unwrap_or_default()
    }

    /// Merge into what is on disk first: several lenses, the menu bar app
    /// and a CLI run may fill the cache at once, and none may drop another's work.
    pub fn save(&self) -> Result<()> {
        files::with_state_lock(|| self.merge_into_disk())
    }

    fn merge_into_disk(&self) -> Result<()> {
        let mut merged = Self::load();
        merged
            .published
            .extend(self.published.iter().map(|(k, v)| (k.clone(), v.clone())));
        merged
            .fetched
            .extend(self.fetched.iter().map(|(k, v)| (k.clone(), *v)));
        merged
            .status
            .extend(self.status.iter().map(|(k, v)| (k.clone(), v.clone())));
        for (k, v) in &self.status_checked {
            let entry = merged.status_checked.entry(k.clone()).or_insert(*v);
            *entry = (*entry).max(*v);
        }
        let published = &merged.published;
        merged.fetched.retain(|k, _| !published.contains_key(k));
        files::write_state(&Self::path(), &serde_json::to_string(&merged)?)
            .context("cannot save the publish-time cache")
    }

    pub fn lookup(&self, pkg: &Pkg) -> Option<DateTime<Utc>> {
        let raw = self.published.get(&version_key(pkg))?;
        DateTime::parse_from_rfc3339(raw)
            .ok()
            .map(|t| t.with_timezone(&Utc))
    }

    /// `None` when never checked.
    pub fn status(&self, pkg: &Pkg) -> Option<Status<'_>> {
        self.status.get(&version_key(pkg)).map(|s| Status::parse(s))
    }

    fn needs_fetch(&self, pkg: &Pkg, now: i64, want_status: bool) -> bool {
        let key = version_key(pkg);
        // A name or version the registry did not know waits a day either way.
        let backing_off = self
            .fetched
            .get(&key)
            .is_some_and(|t| now - t < RETRY_AFTER_SECS);
        let undated = self.lookup(pkg).is_none() && !backing_off;
        let stale_status = want_status
            && !backing_off
            && self
                .status_checked
                .get(&key)
                .is_none_or(|t| now - t >= STATUS_TTL_SECS);
        undated || stale_status
    }

    /// Fetch what the cache cannot answer: publish times, and with
    /// `want_status` also deprecated/yanked status older than a week.
    pub fn fill(
        &mut self,
        wanted: &BTreeSet<Pkg>,
        cfg: &Audit,
        search: &std::ffi::OsStr,
        now: DateTime<Utc>,
        progress: Option<&Progress>,
        want_status: bool,
    ) -> Result<()> {
        let now_ts = now.timestamp();
        // npm and crates.io answer every version of a name in one document.
        let mut by_name: BTreeMap<(Ecosystem, String), Vec<Pkg>> = BTreeMap::new();
        let mut jobs: Vec<Job> = Vec::new();
        for pkg in wanted
            .iter()
            .filter(|p| self.needs_fetch(p, now_ts, want_status))
        {
            match pkg.eco {
                Ecosystem::Npm | Ecosystem::Crates => by_name
                    .entry((pkg.eco, pkg.name.clone()))
                    .or_default()
                    .push(pkg.clone()),
                Ecosystem::Pypi => jobs.push(Job {
                    url: format!(
                        "{}/pypi/{}/{}/json",
                        cfg.pypi_url.trim_end_matches('/'),
                        pkg.name,
                        pkg.version
                    ),
                    pkgs: vec![pkg.clone()],
                }),
            }
        }
        // Every wanted version of a name rides on the one document fetched for it.
        for ((eco, name), pkgs) in &mut by_name {
            pkgs.extend(
                wanted
                    .iter()
                    .filter(|p| p.eco == *eco && &p.name == name)
                    .cloned(),
            );
            pkgs.sort();
            pkgs.dedup();
        }
        jobs.extend(by_name.into_iter().map(|((eco, name), pkgs)| Job {
            url: match eco {
                Ecosystem::Crates => format!(
                    "{}/{}",
                    cfg.crates_index.trim_end_matches('/'),
                    crate_index_path(&name)
                ),
                _ => format!(
                    "{}/{}",
                    cfg.npm_registry.trim_end_matches('/'),
                    name.replacen('/', "%2F", 1)
                ),
            },
            pkgs,
        }));
        if jobs.is_empty() {
            return Ok(());
        }
        let scratch = http::Scratch::new(&paths::state_dir(), "fetch")?;
        let total = jobs.len();
        let mut done = 0;
        for chunk in jobs.chunks(BATCH) {
            let urls: Vec<String> = chunk.iter().map(|j| j.url.clone()).collect();
            http::get_batch(&urls, &scratch.0, search)?;
            for (i, job) in chunk.iter().enumerate() {
                let file = scratch.0.join(i.to_string());
                self.absorb(job, &file, now_ts);
                let _ = fs::remove_file(&file);
                for p in &job.pkgs {
                    let key = version_key(p);
                    if self.lookup(p).is_none() {
                        self.fetched.insert(key, now_ts);
                    } else {
                        self.fetched.remove(&key);
                    }
                }
            }
            done += chunk.len();
            if let Some(p) = progress {
                (p.report)(done, total);
            }
            self.save()?;
        }
        Ok(())
    }

    /// Record what one response says; a missing or unusable response records nothing.
    fn absorb(&mut self, job: &Job, file: &Path, now: i64) {
        let Ok(body) = fs::read_to_string(file) else {
            return;
        };
        match job.pkgs[0].eco {
            Ecosystem::Crates => {
                // One JSON object per line, one line per published version.
                let mut versions: HashMap<String, IndexLine> = HashMap::new();
                for line in body.lines() {
                    if let Ok(entry) = serde_json::from_str::<IndexLine>(line) {
                        versions.insert(entry.vers.clone(), entry);
                    }
                }
                for p in &job.pkgs {
                    let Some(entry) = versions.get(&p.version) else {
                        continue;
                    };
                    let key = version_key(p);
                    if let Some(t) = &entry.pubtime {
                        self.published.insert(key.clone(), t.clone());
                    }
                    let status = if entry.yanked {
                        "yanked: yanked on crates.io".to_string()
                    } else {
                        String::new()
                    };
                    self.status.insert(key.clone(), status);
                    self.status_checked.insert(key, now);
                }
            }
            Ecosystem::Npm => {
                let Ok(doc) = serde_json::from_str::<Packument>(&body) else {
                    return;
                };
                for p in &job.pkgs {
                    let key = version_key(p);
                    if let Some(t) = doc.time.get(&p.version) {
                        self.published.insert(key.clone(), t.clone());
                    }
                    if let Some(v) = doc.versions.get(&p.version) {
                        let status = match &v.deprecated {
                            Some(serde_json::Value::String(msg)) if !msg.trim().is_empty() => {
                                format!("deprecated: {}", msg.trim())
                            }
                            _ => String::new(),
                        };
                        self.status.insert(key.clone(), status);
                        self.status_checked.insert(key, now);
                    }
                }
            }
            Ecosystem::Pypi => {
                let Ok(doc) = serde_json::from_str::<PypiRelease>(&body) else {
                    return;
                };
                let key = version_key(&job.pkgs[0]);
                let earliest = doc
                    .urls
                    .iter()
                    .filter_map(|u| DateTime::parse_from_rfc3339(&u.upload_time_iso_8601).ok())
                    .min();
                if let Some(t) = earliest {
                    self.published
                        .insert(key.clone(), t.with_timezone(&Utc).to_rfc3339());
                }
                let status = if doc.info.yanked {
                    let reason = doc.info.yanked_reason.unwrap_or_default();
                    format!(
                        "yanked: {}",
                        if reason.trim().is_empty() {
                            "no reason given"
                        } else {
                            reason.trim()
                        }
                    )
                } else {
                    String::new()
                };
                self.status.insert(key.clone(), status);
                self.status_checked.insert(key, now);
            }
        }
    }
}

struct Job {
    url: String,
    pkgs: Vec<Pkg>,
}

/// Where the sparse index keeps a crate: `se/rd/serde`, `3/s/syn`, `2/cc`, `1/a`.
/// Crate names are ASCII, so the slicing is on character boundaries.
fn crate_index_path(name: &str) -> String {
    let n = name.to_lowercase();
    match n.len() {
        1 => format!("1/{n}"),
        2 => format!("2/{n}"),
        3 => format!("3/{}/{n}", &n[..1]),
        _ => format!("{}/{}/{n}", &n[..2], &n[2..4]),
    }
}

/// One version in a crates.io sparse-index file.
#[derive(Deserialize)]
struct IndexLine {
    vers: String,
    #[serde(default)]
    yanked: bool,
    /// Publish time; recorded for versions published since the index began carrying it.
    #[serde(default)]
    pubtime: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::crate_index_path;

    #[test]
    fn sparse_index_paths() {
        assert_eq!(crate_index_path("a"), "1/a");
        assert_eq!(crate_index_path("cc"), "2/cc");
        assert_eq!(crate_index_path("syn"), "3/s/syn");
        assert_eq!(crate_index_path("Serde"), "se/rd/serde");
        assert_eq!(crate_index_path("tokio-util"), "to/ki/tokio-util");
    }
}

#[derive(Deserialize)]
struct Packument {
    #[serde(default)]
    time: HashMap<String, String>,
    #[serde(default)]
    versions: HashMap<String, VersionDoc>,
}

#[derive(Deserialize)]
struct VersionDoc {
    /// A message string when deprecated (npm has also stored `false`).
    #[serde(default)]
    deprecated: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct PypiRelease {
    #[serde(default)]
    urls: Vec<PypiFile>,
    #[serde(default)]
    info: PypiInfo,
}

#[derive(Deserialize, Default)]
struct PypiInfo {
    #[serde(default)]
    yanked: bool,
    #[serde(default)]
    yanked_reason: Option<String>,
}

#[derive(Deserialize)]
struct PypiFile {
    upload_time_iso_8601: String,
}
