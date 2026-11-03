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
use lenstica_lens::{
    Category, Context, Ecosystem, Finding, Lens, Package, Report, Severity, Source, topic,
};
use serde::Deserialize;

use super::shared::{self, MALWARE_REMEDY, normalise_name};
use crate::audit;
use crate::http::{self, Fetched};

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

fn parse_list(body: &[u8]) -> serde_json::Result<Vec<Entry>> {
    serde_json::from_slice(body)
}

/// Download a list again when it is older than `max_age` (unchanged lists
/// answer 304 and keep the copy on disk). A new list replaces the old one,
/// and its ETag is kept, only once the whole list has been read.
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
    // Without a list on disk, a 304 would leave nothing to read.
    if !path.exists() {
        let _ = fs::remove_file(&etag);
    }
    let got = scratch.0.join("list");
    let new_etag = scratch.0.join("etag");
    let url = format!("{BASE}/{file}");
    match http::get_conditional(&url, &got, &etag, &new_etag, cx.search_path)? {
        Fetched::NotModified => {
            // Wait `max_age` before asking again.
            fs::File::options()
                .append(true)
                .open(&path)
                .and_then(|f| f.set_modified(SystemTime::now()))
                .with_context(|| format!("cannot touch {}", path.display()))
        }
        Fetched::Modified => {
            let body = fs::read(&got).with_context(|| format!("{url} returned nothing"))?;
            parse_list(&body).with_context(|| format!("{url} is not a malware list"))?;
            fs::rename(&got, &path).with_context(|| format!("cannot save {}", path.display()))?;
            if new_etag.exists() {
                fs::rename(&new_etag, &etag)
                    .with_context(|| format!("cannot save {}", etag.display()))?;
            }
            Ok(())
        }
    }
}

fn load(dir: &Path, eco: Ecosystem) -> Result<List> {
    let path: PathBuf = dir.join(list_file(eco));
    let body = fs::read(&path).with_context(|| format!("no copy of {} yet", list_file(eco)))?;
    let entries =
        parse_list(&body).with_context(|| format!("{} is not a malware list", path.display()))?;
    let mut list = List::new();
    for e in entries {
        list.entry(normalise_name(eco, &e.package_name))
            .or_default()
            .push((e.version, e.reason));
    }
    Ok(list)
}

/// What a listing says about a package.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Listing {
    Telemetry,
    Protestware,
    Malware,
}

impl Listing {
    fn from_reason(reason: &str) -> Self {
        match reason.to_ascii_uppercase().as_str() {
            "PROTESTWARE" => Self::Protestware,
            "TELEMETRY" => Self::Telemetry,
            _ => Self::Malware,
        }
    }

    fn severity(self) -> Severity {
        match self {
            Self::Malware => Severity::Critical,
            Self::Protestware => Severity::High,
            Self::Telemetry => Severity::Low,
        }
    }

    /// Where the finding goes: its category and topic.
    fn placement(self) -> (Category, &'static str) {
        match self {
            Self::Malware | Self::Protestware => (Category::Malware, ""),
            Self::Telemetry => (Category::Privacy, topic::TELEMETRY),
        }
    }

    /// The key namespace.
    fn namespace(self) -> &'static str {
        match self {
            Self::Malware | Self::Protestware => "malware",
            Self::Telemetry => "telemetry",
        }
    }

    fn title(self) -> &'static str {
        match self {
            Self::Malware => "Malicious package",
            Self::Protestware => "Protestware",
            Self::Telemetry => "Telemetry",
        }
    }

    fn remedy(self) -> &'static str {
        match self {
            Self::Telemetry => {
                "It reports usage back to its author. Remove it, or turn its telemetry off if it offers a setting."
            }
            Self::Malware | Self::Protestware => MALWARE_REMEDY,
        }
    }
}

fn finding(pkg: &Package, reason: &str, sources: &[&Source]) -> Finding {
    let listing = Listing::from_reason(reason);
    let mut f = Finding::new(
        format!(
            "{}|{}|{}|{}",
            listing.namespace(),
            pkg.ecosystem.label(),
            pkg.name,
            pkg.version
        ),
        listing.severity(),
        listing.placement().0,
        format!(
            "{}: {} {} ({})",
            listing.title(),
            pkg.name,
            pkg.version,
            pkg.ecosystem.label()
        ),
    )
    .topic(listing.placement().1)
    .detail(format!(
        "Listed as {reason} by Aikido Intel ({BASE}/{}).",
        list_file(pkg.ecosystem)
    ))
    .remedy(listing.remedy());
    for s in sources {
        f = f.at(s.location());
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
    fn categories(&self) -> &[Category] {
        &[Category::Malware, Category::Privacy]
    }
    fn third_party(&self) -> Option<&str> {
        Some("Downloads Aikido Security's malware, protestware and telemetry lists.")
    }

    fn run(&self, cx: &Context) -> Result<Report> {
        let cfg = crate::config::Config::load()?;
        let hours = shared::refresh_hours(cx.settings);
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
            if audit::ignore_matches(&cfg.audit.ignore, &pkg.name, &pkg.version) {
                continue;
            }
            checked += 1;
            let Some(entries) = list.get(&normalise_name(pkg.ecosystem, &pkg.name)) else {
                continue;
            };
            // The most serious listing of this exact version, or of every version.
            let hit = entries
                .iter()
                .filter(|(v, _)| v == "*" || *v == pkg.version)
                .max_by_key(|(_, reason)| Listing::from_reason(reason));
            if let Some((_, reason)) = hit {
                findings.push(finding(pkg, reason, &sources));
            }
        }
        let listed: usize = lists.values().map(HashMap::len).sum();
        passing.insert(
            0,
            format!("{checked} npm and PyPI packages compared with {listed} listed package names"),
        );
        let bad = findings
            .iter()
            .filter(|f| f.category == Category::Malware)
            .count();
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
        assert_eq!(
            normalise_name(Ecosystem::Pypi, "Log_Utils.SDK"),
            "log-utils-sdk"
        );
        assert_eq!(normalise_name(Ecosystem::Pypi, "a__b"), "a-b");
        assert_eq!(normalise_name(Ecosystem::Npm, "@Scope/Pkg"), "@Scope/Pkg");
        let rank = |r| Listing::from_reason(r).severity();
        assert!(rank("MALWARE") > rank("PROTESTWARE"));
        assert!(rank("PROTESTWARE") > rank("TELEMETRY"));
        // A list with an entry the lens cannot read must not replace a good one.
        assert!(
            parse_list(br#"[{"package_name":"x","version":null,"reason":"MALWARE"}]"#).is_err()
        );
    }
}
