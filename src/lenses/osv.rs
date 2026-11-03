//! Known vulnerabilities and malicious packages, from OSV.dev.
//!
//! OSV aggregates GitHub advisories, PyPI's advisory database, RustSec and the
//! OpenSSF malicious-packages dataset. Malware is reported separately and at
//! critical severity: an `MAL-` id, or an advisory tagged CWE-506 (embedded
//! malicious code), which is how GitHub files some worm releases. RustSec's
//! informational notices (unmaintained, unsound) are shown as information.
//! Severity comes from the advisory's label, else its CVSS v3 vector (v4-only
//! advisories fall back to medium).
//!
//! Each package version is asked about once per `refresh_hours` (default 6):
//! advisories, malware above all, are published for versions that are already
//! installed. Advisory details are cached by their `modified` time.
//! Only the names and versions of public packages are sent.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context as _, Result};
use lenstica_lens::{Category, Context, Finding, Lens, Package, Report, Severity, Source, topic};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::cvss;
use super::shared::{self, MALWARE_REMEDY, normalise_name};
use crate::audit;
use crate::config::Config;
use crate::files;
use crate::http;
use crate::version::PackageVersion;

const API: &str = "https://api.osv.dev";
const QUERY_BATCH: usize = 1000;
const DETAIL_BATCH: usize = 64;
/// Pages of further advisories fetched for one package, at most.
const MAX_PAGES: usize = 10;
/// Bumped when [`parse_advisory`] changes, so cached advisories are re-read.
const CACHE_VERSION: u32 = 2;

pub struct Vulnerabilities;

#[derive(Default, Serialize, Deserialize)]
struct Cache {
    #[serde(default)]
    version: u32,
    /// `npm:lodash@4.17.15` -> (checked at, [(advisory id, modified)]).
    packages: BTreeMap<String, (i64, Vec<(String, String)>)>,
    advisories: BTreeMap<String, Advisory>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Advisory {
    id: String,
    modified: String,
    summary: String,
    severity: Severity,
    malicious: bool,
    aliases: Vec<String>,
    /// (ecosystem, lowercase package name, first fixed version) per affected range.
    fixed: Vec<(String, String, String)>,
    url: String,
}

fn package_key(p: &Package) -> String {
    format!("{}:{}@{}", p.ecosystem.label(), p.name, p.version)
}

impl Cache {
    fn load(dir: &Path) -> Self {
        let mut cache: Self = files::read_json(&dir.join("osv.json")).unwrap_or_default();
        if cache.version != CACHE_VERSION {
            cache.advisories.clear();
            cache.version = CACHE_VERSION;
        }
        cache
    }

    fn save(&self, dir: &Path) -> Result<()> {
        files::write_state(&dir.join("osv.json"), &serde_json::to_string(self)?)
            .context("cannot save the OSV cache")
    }
}

fn str_at<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

/// The strings in a JSON array; empty for anything else.
fn str_array(v: Option<&Value>) -> impl Iterator<Item = String> + '_ {
    v.and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(String::from)
}

fn array<'a>(v: &'a Value, key: &str) -> impl Iterator<Item = &'a Value> {
    v.get(key).and_then(Value::as_array).into_iter().flatten()
}

fn parse_advisory(doc: &Value) -> Option<Advisory> {
    let id = doc.get("id")?.as_str()?.to_string();
    let aliases: Vec<String> = str_array(doc.get("aliases")).collect();
    let db = doc.get("database_specific");
    let cwe_506 = db
        .and_then(|d| d.get("cwe_ids"))
        .and_then(Value::as_array)
        .is_some_and(|ids| ids.iter().any(|c| c.as_str() == Some("CWE-506")));
    let malicious =
        id.starts_with("MAL-") || aliases.iter().any(|a| a.starts_with("MAL-")) || cwe_506;
    let labelled = db
        .and_then(|d| d.get("severity"))
        .and_then(Value::as_str)
        .and_then(super::parse_severity);
    let scored = array(doc, "severity")
        .filter_map(|s| cvss::base_score(str_at(s, "score")))
        .fold(None, |best: Option<f64>, s| {
            Some(best.map_or(s, |b| b.max(s)))
        })
        .map(cvss::severity);
    // RustSec notices (unmaintained, unsound) are not vulnerabilities.
    let informational = array(doc, "affected").any(|a| {
        a.pointer("/database_specific/informational")
            .is_some_and(|v| !v.is_null())
    });
    let severity = if malicious {
        Severity::Critical
    } else if informational {
        Severity::Info
    } else {
        labelled.or(scored).unwrap_or(Severity::Medium)
    };
    let mut fixed = Vec::new();
    for affected in array(doc, "affected") {
        let pkg = affected.get("package");
        let eco = pkg.map_or("", |p| str_at(p, "ecosystem")).to_string();
        let name = pkg.map_or("", |p| str_at(p, "name")).to_lowercase();
        for event in array(affected, "ranges").flat_map(|r| array(r, "events")) {
            if let Some(v) = event.get("fixed").and_then(Value::as_str) {
                fixed.push((eco.clone(), name.clone(), v.to_string()));
            }
        }
    }
    let refs = doc
        .get("references")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    let url = refs
        .iter()
        .find(|r| str_at(r, "type") == "ADVISORY")
        .or_else(|| refs.first())
        .map(|r| str_at(r, "url").to_string())
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| format!("https://osv.dev/vulnerability/{id}"));
    let summary = match str_at(doc, "summary") {
        "" => str_at(doc, "details")
            .lines()
            .next()
            .unwrap_or("")
            .chars()
            .take(160)
            .collect(),
        s => s.to_string(),
    };
    Some(Advisory {
        modified: str_at(doc, "modified").to_string(),
        summary,
        severity,
        malicious,
        aliases,
        fixed,
        url,
        id,
    })
}

fn query_of(p: &Package, page_token: Option<&str>) -> Value {
    let mut q = serde_json::json!({
        "package": { "name": p.name, "ecosystem": p.ecosystem.osv_name() },
        "version": p.version,
    });
    if let Some(token) = page_token {
        q["page_token"] = token.into();
    }
    q
}

/// One `querybatch` call: a result per query, in order.
fn query_batch(queries: Vec<Value>, cx: &Context) -> Result<Vec<Value>> {
    let body = serde_json::json!({ "queries": queries }).to_string();
    let response = http::post_json(
        &format!("{API}/v1/querybatch"),
        &body,
        &cx.state_dir,
        cx.search_path,
    )?;
    let mut parsed: Value =
        serde_json::from_str(&response).context("unexpected reply from OSV.dev")?;
    match parsed.get_mut("results").map(Value::take) {
        Some(Value::Array(results)) => Ok(results),
        _ => anyhow::bail!("OSV.dev reply has no results"),
    }
}

/// The (id, modified) pairs in one query result, and the token for its next page.
fn vulns_of(result: &Value) -> (Vec<(String, String)>, Option<String>) {
    let vulns = array(result, "vulns")
        .map(|x| {
            (
                str_at(x, "id").to_string(),
                str_at(x, "modified").to_string(),
            )
        })
        .collect();
    let next = result
        .get("next_page_token")
        .and_then(Value::as_str)
        .filter(|t| !t.is_empty())
        .map(String::from);
    (vulns, next)
}

/// Ask OSV about every package not checked within `refresh_secs`, following
/// result pages for packages with many advisories.
fn refresh_packages(
    cache: &mut Cache,
    packages: &[&Package],
    refresh_secs: i64,
    now: i64,
    cx: &Context,
) -> Result<()> {
    let stale: Vec<&Package> = packages
        .iter()
        .copied()
        .filter(|p| {
            cache
                .packages
                .get(&package_key(p))
                .is_none_or(|(t, _)| now - t >= refresh_secs)
        })
        .collect();
    for chunk in stale.chunks(QUERY_BATCH) {
        let results = query_batch(chunk.iter().map(|p| query_of(p, None)).collect(), cx)?;
        let mut found: Vec<Vec<(String, String)>> = Vec::with_capacity(chunk.len());
        let mut pages: Vec<(usize, String)> = Vec::new();
        for (i, result) in results.iter().enumerate().take(chunk.len()) {
            let (vulns, next) = vulns_of(result);
            found.push(vulns);
            pages.extend(next.map(|t| (i, t)));
        }
        for _ in 0..MAX_PAGES {
            if pages.is_empty() {
                break;
            }
            let queries = pages
                .iter()
                .map(|(i, token)| query_of(chunk[*i], Some(token)))
                .collect();
            let results = query_batch(queries, cx)?;
            let mut next_pages = Vec::new();
            for ((i, _), result) in pages.iter().zip(&results) {
                let (vulns, next) = vulns_of(result);
                found[*i].extend(vulns);
                next_pages.extend(next.map(|t| (*i, t)));
            }
            pages = next_pages;
        }
        for (p, vulns) in chunk.iter().zip(found) {
            cache.packages.insert(package_key(p), (now, vulns));
        }
        cache.save(&cx.state_dir)?;
    }
    Ok(())
}

/// Fetch details for advisories not cached, or changed since.
fn refresh_advisories(
    cache: &mut Cache,
    wanted: &BTreeMap<String, String>,
    cx: &Context,
) -> Result<()> {
    let missing: Vec<&String> = wanted
        .iter()
        .filter(|(id, modified)| {
            cache
                .advisories
                .get(*id)
                .is_none_or(|a| &a.modified != *modified)
        })
        .map(|(id, _)| id)
        .collect();
    let scratch = http::Scratch::new(&cx.state_dir, "advisories")?;
    for chunk in missing.chunks(DETAIL_BATCH) {
        let urls: Vec<String> = chunk
            .iter()
            .map(|id| format!("{API}/v1/vulns/{id}"))
            .collect();
        http::get_batch(&urls, &scratch.0, cx.search_path)?;
        for i in 0..chunk.len() {
            let file = scratch.0.join(i.to_string());
            if let Some(adv) = files::read_json::<Value>(&file)
                .as_ref()
                .and_then(parse_advisory)
            {
                cache.advisories.insert(adv.id.clone(), adv);
            }
            let _ = std::fs::remove_file(&file);
        }
        cache.save(&cx.state_dir)?;
    }
    Ok(())
}

/// Keep one id per advisory: OSV lists the same issue under GHSA, PYSEC, CVE
/// and MAL ids. Malware ids first, then GitHub's, then the rest.
fn dedupe(advisories: Vec<&Advisory>) -> Vec<&Advisory> {
    let rank = |a: &Advisory| match a.id.as_str() {
        id if id.starts_with("MAL-") => 0,
        id if id.starts_with("GHSA-") => 1,
        _ => 2,
    };
    let mut sorted = advisories;
    sorted.sort_by(|a, b| (rank(a), &a.id).cmp(&(rank(b), &b.id)));
    let mut covered: BTreeSet<&str> = BTreeSet::new();
    let mut kept = Vec::new();
    for a in sorted {
        if covered.contains(a.id.as_str()) || a.aliases.iter().any(|x| covered.contains(x.as_str()))
        {
            continue;
        }
        covered.insert(&a.id);
        covered.extend(a.aliases.iter().map(String::as_str));
        kept.push(a);
    }
    kept
}

/// The version that fixes every advisory listing a fix: per advisory the
/// lowest fixed version above `current`, then the highest of those. Also
/// how many advisories list no fix above `current`.
fn fixed_in(advisories: &[&Advisory], pkg: &Package) -> (Option<String>, usize) {
    let Some(current) = PackageVersion::parse(&pkg.version) else {
        return (None, advisories.len());
    };
    let name = normalise_name(pkg.ecosystem, &pkg.name).to_lowercase();
    let same_package = |eco: &str, n: &str| {
        eco == pkg.ecosystem.osv_name() && normalise_name(pkg.ecosystem, n).to_lowercase() == name
    };
    let mut unfixed = 0;
    let mut needed: Option<(PackageVersion, &String)> = None;
    for a in advisories {
        let lowest = a
            .fixed
            .iter()
            .filter(|(eco, n, _)| same_package(eco, n))
            .filter_map(|(_, _, v)| {
                PackageVersion::parse(v)
                    .filter(|p| *p > current)
                    .map(|p| (p, v))
            })
            .min();
        match lowest {
            Some(fix) => {
                if needed.as_ref().is_none_or(|n| fix.0 > n.0) {
                    needed = Some(fix);
                }
            }
            None => unfixed += 1,
        }
    }
    (needed.map(|(_, v)| v.clone()), unfixed)
}

fn finding(
    pkg: &Package,
    advisories: &[&Advisory],
    sources: &[&Source],
    (fix, unfixed): (Option<String>, usize),
) -> Finding {
    let worst = advisories
        .iter()
        .map(|a| a.severity)
        .max()
        .unwrap_or(Severity::Medium);
    let malicious = advisories.iter().any(|a| a.malicious);
    let ids: Vec<&str> = advisories.iter().map(|a| a.id.as_str()).collect();
    let mut f = if malicious {
        Finding::new(
            format!(
                "malware|{}|{}|{}",
                pkg.ecosystem.label(),
                pkg.name,
                pkg.version
            ),
            Severity::Critical,
            Category::Malware,
            format!(
                "Malicious package: {} {} ({})",
                pkg.name,
                pkg.version,
                pkg.ecosystem.label()
            ),
        )
        .remedy(MALWARE_REMEDY)
    } else {
        let remedy = match (&fix, unfixed) {
            (Some(v), 0) => format!("Upgrade {} to {v} or later.", pkg.name),
            (Some(v), n) => format!(
                "Upgrade {} to {v} or later. {n} of the advisories list no fixed version yet: check whether \
                 their code path is used.",
                pkg.name
            ),
            (None, _) => "No fixed version is listed. Check whether the vulnerable code path is used, or replace the package.".to_string(),
        };
        Finding::new(
            format!(
                "vuln|{}|{}|{}|{}",
                pkg.ecosystem.label(),
                pkg.name,
                pkg.version,
                ids.join(",")
            ),
            worst,
            Category::Packages,
            format!(
                "{} {}: {} known {} ({} worst)",
                pkg.name,
                pkg.version,
                advisories.len(),
                if advisories.len() == 1 {
                    "vulnerability"
                } else {
                    "vulnerabilities"
                },
                worst.label()
            ),
        )
        .topic(topic::VULNERABILITIES)
        .remedy(remedy)
    };
    f.detail = advisories
        .iter()
        .map(|a| format!("{} ({}): {}", a.id, a.severity.label(), a.summary))
        .collect::<Vec<_>>()
        .join("\n");
    for a in advisories.iter().take(5) {
        f = f.link(a.url.clone());
    }
    for s in sources {
        f = f.at(s.location());
    }
    f
}

impl Lens for Vulnerabilities {
    fn id(&self) -> &str {
        "vulnerabilities"
    }
    fn title(&self) -> &str {
        "Vulnerabilities and malware"
    }
    fn description(&self) -> &str {
        "Locked and installed packages with known vulnerabilities or known malicious releases, from OSV.dev (GitHub, PyPI, RustSec and OpenSSF malicious-packages advisories)."
    }
    fn categories(&self) -> &[Category] {
        &[Category::Packages, Category::Malware]
    }
    fn third_party(&self) -> Option<&str> {
        Some(
            "Sends the names and versions of your locked and installed packages to OSV.dev, the open vulnerability database run by Google.",
        )
    }

    fn run(&self, cx: &Context) -> Result<Report> {
        let cfg = Config::load()?;
        let inventory = (cx.inventory)()?;
        let by_package = inventory.by_package();
        let packages: Vec<&Package> = by_package
            .keys()
            .copied()
            .filter(|p| !audit::ignore_matches(&cfg.audit.ignore, &p.name, &p.version))
            .collect();
        let refresh_hours = shared::refresh_hours(cx.settings);
        let ignore_advisories: BTreeSet<String> =
            str_array(cx.settings.get("ignore_advisories")).collect();

        let mut cache = Cache::load(&cx.state_dir);
        let now = chrono::Utc::now().timestamp();
        let mut problems = Vec::new();
        if !cx.offline {
            let refresh_secs = i64::try_from(refresh_hours * 3600).unwrap_or(i64::MAX);
            if let Err(e) = refresh_packages(&mut cache, &packages, refresh_secs, now, cx) {
                problems.push(format!("OSV.dev: {e:#}"));
            }
            let wanted: BTreeMap<String, String> = packages
                .iter()
                .filter_map(|p| cache.packages.get(&package_key(p)))
                .flat_map(|(_, v)| v.iter().cloned())
                .collect();
            if let Err(e) = refresh_advisories(&mut cache, &wanted, cx) {
                problems.push(format!("OSV.dev advisories: {e:#}"));
            }
        }

        let mut findings = Vec::new();
        let mut checked = 0;
        for pkg in &packages {
            let Some((_, ids)) = cache.packages.get(&package_key(pkg)) else {
                continue;
            };
            checked += 1;
            let advisories: Vec<&Advisory> = ids
                .iter()
                .filter(|(id, _)| !ignore_advisories.contains(id))
                .filter_map(|(id, _)| cache.advisories.get(id))
                .filter(|a| !a.aliases.iter().any(|x| ignore_advisories.contains(x)))
                .collect();
            let advisories = dedupe(advisories);
            if advisories.is_empty() {
                continue;
            }
            let fix = fixed_in(&advisories, pkg);
            findings.push(finding(pkg, &advisories, &by_package[pkg], fix));
        }
        let malware = findings
            .iter()
            .filter(|f| f.category == Category::Malware)
            .count();
        let count = |s: Severity| {
            findings
                .iter()
                .filter(|f| f.category == Category::Packages && f.severity == s)
                .count()
        };
        let summary = format!(
            "{} malicious, {} vulnerable ({} critical, {} high) of {} packages checked",
            malware,
            findings.len() - malware,
            count(Severity::Critical),
            count(Severity::High),
            checked
        );
        let mut passing = vec![format!(
            "{checked} of {} packages checked against OSV.dev (each re-checked every {refresh_hours} h)",
            packages.len()
        )];
        if malware == 0 {
            passing.push("No installed or locked package is known to be malicious".to_string());
        }
        passing.extend(problems);
        Ok(Report {
            findings,
            summary,
            passing,
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lenstica_lens::Ecosystem;

    #[test]
    fn reads_advisories_and_prefers_github_ids() {
        let ghsa: Value = serde_json::from_str(r#"{"id":"GHSA-aaaa","modified":"m","summary":"Prototype pollution",
            "aliases":["CVE-1","PYSEC-1"],"database_specific":{"severity":"HIGH"},
            "affected":[{"package":{"ecosystem":"npm","name":"lodash"},"ranges":[{"events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}],
            "references":[{"type":"WEB","url":"https://x"},{"type":"ADVISORY","url":"https://github.com/advisories/GHSA-aaaa"}]}"#).unwrap();
        let pysec: Value = serde_json::from_str(r#"{"id":"PYSEC-1","modified":"m","details":"Same issue\nmore",
            "aliases":["GHSA-aaaa"],"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}"#).unwrap();
        let mal: Value = serde_json::from_str(
            r#"{"id":"MAL-2025-1","modified":"m","summary":"Malicious code in x"}"#,
        )
        .unwrap();
        let (g, p, m) = (
            parse_advisory(&ghsa).unwrap(),
            parse_advisory(&pysec).unwrap(),
            parse_advisory(&mal).unwrap(),
        );
        assert_eq!(
            (g.severity, g.url.as_str()),
            (Severity::High, "https://github.com/advisories/GHSA-aaaa")
        );
        assert_eq!(
            (p.severity, p.summary.as_str()),
            (Severity::Critical, "Same issue")
        );
        assert!(m.malicious && m.severity == Severity::Critical && !g.malicious);
        let kept: Vec<&str> = dedupe(vec![&p, &g, &m])
            .iter()
            .map(|a| a.id.as_str())
            .collect();
        assert_eq!(kept, vec!["MAL-2025-1", "GHSA-aaaa"]);
        let pkg = Package {
            ecosystem: Ecosystem::Npm,
            name: "lodash".into(),
            version: "4.17.15".into(),
        };
        assert_eq!(fixed_in(&[&g], &pkg), (Some("4.17.21".to_string()), 0));
        // Two advisories fixed in different releases: only the later fixes both.
        let mut older = g.clone();
        older.fixed = vec![("npm".into(), "lodash".into(), "4.17.16".into())];
        assert_eq!(
            fixed_in(&[&older, &g], &pkg),
            (Some("4.17.21".to_string()), 0)
        );
        let mut unfixed = g.clone();
        unfixed.fixed.clear();
        assert_eq!(
            fixed_in(&[&unfixed, &g], &pkg),
            (Some("4.17.21".to_string()), 1)
        );
        // PyPI names match however they are spelled.
        let mut py = g.clone();
        py.fixed = vec![("PyPI".into(), "typing-extensions".into(), "4.5.0".into())];
        let pkg = Package {
            ecosystem: Ecosystem::Pypi,
            name: "typing_extensions".into(),
            version: "4.4.0".into(),
        };
        assert_eq!(fixed_in(&[&py], &pkg).0.as_deref(), Some("4.5.0"));
        let notice: Value = serde_json::from_str(r#"{"id":"RUSTSEC-1","modified":"m","summary":"unmaintained",
            "affected":[{"package":{"ecosystem":"crates.io","name":"atty"},"database_specific":{"informational":"unmaintained"}}]}"#).unwrap();
        assert_eq!(parse_advisory(&notice).unwrap().severity, Severity::Info);
    }
}
