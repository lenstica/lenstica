//! Locked and installed packages on Aikido Intel's malware lists, the lists
//! Aikido Safe Chain blocks downloads with. A second opinion beside OSV.dev's
//! malicious-packages advisories: Aikido often lists a package first.
//!
//! The lists are downloaded whole (no package names leave the machine) and
//! refreshed every `refresh_hours` with an ETag, so an unchanged list costs
//! one small request.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context as _, Result};
use lenstica_lens::{Context, Ecosystem, Finding, Lens, Location, Package, Report, Severity};
use serde::Deserialize;
use serde_json::Value;

use crate::http;

pub struct AikidoMalware;

const BASE: &str = "https://malware-list.aikido.dev";

#[derive(Deserialize)]
struct Entry {
    package_name: String,
    version: String,
    reason: String,
}

/// Name -> (version or `*`, reason), for one ecosystem.
type List = HashMap<String, Vec<(String, String)>>;

fn list_file(eco: Ecosystem) -> &'static str {
    match eco {
        Ecosystem::Npm => "malware_predictions.json",
        _ => "malware_pypi.json",
    }
}

/// PyPI names compare case-insensitively, with `-`, `_` and `.` alike.
fn normalise(eco: Ecosystem, name: &str) -> String {
    match eco {
        Ecosystem::Pypi => name.to_lowercase().replace(['_', '.'], "-"),
        _ => name.to_string(),
    }
}

/// Download a list again when it is older than `max_age` (unchanged lists
/// answer 304 and keep the copy on disk).
fn refresh(dir: &Path, file: &str, max_age: Duration, cx: &Context) -> Result<()> {
    let path = dir.join(file);
    let fresh = fs::metadata(&path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .is_some_and(|age| age < max_age);
    if fresh {
        return Ok(());
    }
    let scratch = http::Scratch::new(dir, "download")?;
    let etag = dir.join(format!("{file}.etag"));
    let etag_arg = etag.to_string_lossy().into_owned();
    let mut extra = vec!["--etag-save", etag_arg.as_str()];
    if path.exists() && etag.exists() {
        extra.extend(["--etag-compare", etag_arg.as_str()]);
    }
    http::get_batch_with(
        &[format!("{BASE}/{file}")],
        &scratch.0,
        cx.search_path,
        &extra,
    )?;
    let got = scratch.0.join("0");
    let body = fs::read(&got).unwrap_or_default();
    if body.is_empty() {
        // 304 Not Modified: keep the list, and wait `max_age` before asking again.
        if path.exists() {
            let _ = fs::File::options()
                .append(true)
                .open(&path)
                .and_then(|f| f.set_modified(SystemTime::now()));
            return Ok(());
        }
        anyhow::bail!("{BASE}/{file} returned nothing");
    }
    serde_json::from_slice::<Vec<Value>>(&body)
        .with_context(|| format!("{BASE}/{file} is not a malware list"))?;
    fs::rename(&got, &path).with_context(|| format!("cannot save {}", path.display()))
}

fn load(dir: &Path, eco: Ecosystem) -> Result<List> {
    let path: PathBuf = dir.join(list_file(eco));
    let body = fs::read(&path).with_context(|| format!("no copy of {} yet", list_file(eco)))?;
    let entries: Vec<Entry> = serde_json::from_slice(&body)
        .with_context(|| format!("{} is not a malware list", path.display()))?;
    let mut list = List::new();
    for e in entries {
        list.entry(normalise(eco, &e.package_name))
            .or_default()
            .push((e.version, e.reason));
    }
    Ok(list)
}

/// What a reason means: severity, category and a phrase for the title.
fn judge(reason: &str) -> (Severity, &'static str, &'static str) {
    match reason.to_ascii_uppercase().as_str() {
        "PROTESTWARE" => (Severity::High, "malware", "Protestware"),
        "TELEMETRY" => (Severity::Low, "vulnerability", "Telemetry"),
        _ => (Severity::Critical, "malware", "Malicious package"),
    }
}

fn ignored(ignore: &[String], p: &Package) -> bool {
    ignore.iter().any(
        |r| match r.rsplit_once('@').filter(|(n, _)| !n.is_empty()) {
            Some((name, version)) => name == p.name && version == p.version,
            None => *r == p.name,
        },
    )
}

fn finding(pkg: &Package, reason: &str, sources: &[&lenstica_lens::Source]) -> Finding {
    let (severity, category, what) = judge(reason);
    let kind = if category == "malware" {
        "malware"
    } else {
        "telemetry"
    };
    let remedy = match what {
        "Telemetry" => {
            "It reports usage back to its author. Remove it, or turn its telemetry off if it offers a setting."
        }
        _ => {
            "Remove it, then treat this machine as compromised: from another machine, revoke and rotate every credential \
              this one can reach (npm and GitHub tokens, cloud sign-ins, SSH keys, .env secrets)."
        }
    };
    let mut f = Finding::new(
        format!(
            "{kind}|{}|{}|{}",
            pkg.ecosystem.label(),
            pkg.name,
            pkg.version
        ),
        severity,
        category,
        format!(
            "{what}: {} {} ({})",
            pkg.name,
            pkg.version,
            pkg.ecosystem.label()
        ),
    )
    .detail(format!(
        "Listed as {reason} by Aikido Intel ({BASE}/{}).",
        list_file(pkg.ecosystem)
    ))
    .remedy(remedy);
    for s in sources {
        f = f.at(Location {
            label: s.label.clone(),
            path: s.path.clone(),
            line: None,
        });
    }
    f
}

impl Lens for AikidoMalware {
    fn id(&self) -> &str {
        "aikido-malware"
    }
    fn title(&self) -> &str {
        "Aikido malware lists"
    }
    fn description(&self) -> &str {
        "Locked and installed npm and PyPI packages on Aikido Intel's malware, protestware and telemetry lists, the lists Aikido Safe Chain blocks downloads with. The lists are downloaded whole, so no package names are sent."
    }

    fn run(&self, cx: &Context) -> Result<Report> {
        let cfg = crate::config::Config::load()?;
        let hours = cx
            .settings
            .get("refresh_hours")
            .and_then(Value::as_u64)
            .unwrap_or(6)
            .max(1);
        let mut passing = Vec::new();
        let mut lists: HashMap<Ecosystem, List> = HashMap::new();
        for eco in [Ecosystem::Npm, Ecosystem::Pypi] {
            if !cx.offline
                && let Err(e) = refresh(
                    &cx.state_dir,
                    list_file(eco),
                    Duration::from_secs(hours * 3600),
                    cx,
                )
            {
                passing.push(format!(
                    "skipped refreshing the {} list: {e:#}",
                    eco.label()
                ));
            }
            match load(&cx.state_dir, eco) {
                Ok(list) => {
                    lists.insert(eco, list);
                }
                Err(e) => passing.push(format!("{} packages not checked: {e:#}", eco.label())),
            }
        }

        let inventory = (cx.inventory)()?;
        let mut findings = Vec::new();
        let mut checked = 0;
        for (pkg, sources) in inventory.by_package() {
            let Some(list) = lists.get(&pkg.ecosystem) else {
                continue;
            };
            if ignored(&cfg.audit.ignore, pkg) {
                continue;
            }
            checked += 1;
            let Some(entries) = list.get(&normalise(pkg.ecosystem, &pkg.name)) else {
                continue;
            };
            // The most serious listing of this exact version, or of every version.
            let hit = entries
                .iter()
                .filter(|(v, _)| v == "*" || *v == pkg.version)
                .max_by_key(|(_, reason)| judge(reason).0);
            if let Some((_, reason)) = hit {
                findings.push(finding(pkg, reason, &sources));
            }
        }
        let listed: usize = lists.values().map(HashMap::len).sum();
        passing.insert(
            0,
            format!("{checked} npm and PyPI packages compared with {listed} listed package names"),
        );
        let bad = findings.iter().filter(|f| f.category == "malware").count();
        Ok(Report {
            summary: format!(
                "{bad} malicious or protestware packages, {} with telemetry, among {checked} checked",
                findings.len() - bad
            ),
            findings,
            passing,
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_like_pypi_and_ranks_reasons() {
        assert_eq!(normalise(Ecosystem::Pypi, "Log_Utils.SDK"), "log-utils-sdk");
        assert_eq!(normalise(Ecosystem::Npm, "@Scope/Pkg"), "@Scope/Pkg");
        assert!(judge("MALWARE").0 > judge("PROTESTWARE").0);
        assert!(judge("PROTESTWARE").0 > judge("TELEMETRY").0);
    }
}
