//! Known vulnerabilities and malicious packages, from OSV.dev.
//!
//! OSV aggregates GitHub advisories, PyPI's advisory database and the OpenSSF
//! malicious-packages dataset. Malware is reported separately and at critical
//! severity: an `MAL-` id, or an advisory tagged CWE-506 (embedded malicious
//! code), which is how GitHub files some worm releases.
//!
//! Each package version is asked about once per `refresh_hours` (default 6):
//! advisories, malware above all, are published for versions that are already
//! installed. Advisory details are cached by their `modified` time.
//! Only the names and versions of public packages are sent.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context as _, Result};
use lenstica_lens::{Context, Finding, Lens, Location, Package, Report, Severity};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::cvss;
use crate::config::Config;
use crate::files;
use crate::http;
use crate::version::Version;

const API: &str = "https://api.osv.dev";
const QUERY_BATCH: usize = 1000;
const DETAIL_BATCH: usize = 64;

pub struct Vulnerabilities;

#[derive(Default, Serialize, Deserialize)]
struct Cache {
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
        files::read_optional(&dir.join("osv.json"))
            .ok()
            .flatten()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    fn save(&self, dir: &Path) -> Result<()> {
        files::write_state(&dir.join("osv.json"), &serde_json::to_string(self)?)
            .context("cannot save the OSV cache")
    }
}

fn str_at<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

fn parse_advisory(doc: &Value) -> Option<Advisory> {
    let id = doc.get("id")?.as_str()?.to_string();
    let aliases: Vec<String> = doc
        .get("aliases")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
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
    let scored = doc
        .get("severity")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|s| cvss::base_score(str_at(s, "score")))
        .fold(None, |best: Option<f64>, s| {
            Some(best.map_or(s, |b| b.max(s)))
        })
        .map(cvss::severity);
    let severity = if malicious {
        Severity::Critical
    } else {
        labelled.or(scored).unwrap_or(Severity::Medium)
    };
    let mut fixed = Vec::new();
    for affected in doc
        .get("affected")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let pkg = affected.get("package");
        let eco = pkg
            .map(|p| str_at(p, "ecosystem"))
            .unwrap_or("")
            .to_string();
        let name = pkg.map(|p| str_at(p, "name")).unwrap_or("").to_lowercase();
        for range in affected
            .get("ranges")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            for event in range
                .get("events")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let Some(v) = event.get("fixed").and_then(Value::as_str) {
                    fixed.push((eco.clone(), name.clone(), v.to_string()));
                }
            }
        }
    }
    let refs: Vec<&Value> = doc
        .get("references")
        .and_then(Value::as_array)
        .map(|r| r.iter().collect())
        .unwrap_or_default();
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

/// Ask OSV about every package not checked within `refresh_secs`.
fn refresh_packages(
    cache: &mut Cache,
    packages: &[&Package],
    refresh_secs: i64,
    now: i64,
    cx: &Context,
) -> Result<()> {
    let stale: Vec<&&Package> = packages
        .iter()
        .filter(|p| {
            cache
                .packages
                .get(&package_key(p))
                .is_none_or(|(t, _)| now - t >= refresh_secs)
        })
        .collect();
    for chunk in stale.chunks(QUERY_BATCH) {
        let queries: Vec<Value> = chunk
            .iter()
            .map(|p| {
                serde_json::json!({
                    "package": { "name": p.name, "ecosystem": p.ecosystem.osv_name() },
                    "version": p.version,
                })
            })
            .collect();
        let body = serde_json::json!({ "queries": queries }).to_string();
        let response = http::post_json(
            &format!("{API}/v1/querybatch"),
            &body,
            &cx.state_dir,
            cx.search_path,
        )?;
        let parsed: Value =
            serde_json::from_str(&response).context("unexpected reply from OSV.dev")?;
        let results = parsed
            .get("results")
            .and_then(Value::as_array)
            .context("OSV.dev reply has no results")?;
        for (p, result) in chunk.iter().zip(results) {
            let vulns = result
                .get("vulns")
                .and_then(Value::as_array)
                .map(|v| {
                    v.iter()
                        .map(|x| {
                            (
                                str_at(x, "id").to_string(),
                                str_at(x, "modified").to_string(),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();
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
            if let Some(adv) = files::read_optional(&file)
                .ok()
                .flatten()
                .and_then(|s| serde_json::from_str::<Value>(&s).ok())
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
    sorted.sort_by_key(|a| (rank(a), a.id.clone()));
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

/// The lowest fixed version above `current` for this package, if any.
fn fixed_in(advisories: &[&Advisory], pkg: &Package) -> Option<String> {
    let name = pkg.name.to_lowercase();
    let current = Version::parse(&pkg.version)?;
    advisories
        .iter()
        .flat_map(|a| a.fixed.iter())
        .filter(|(eco, n, _)| eco == pkg.ecosystem.osv_name() && *n == name)
        .filter_map(|(_, _, v)| {
            Version::parse(v)
                .filter(|parsed| *parsed > current)
                .map(|parsed| (parsed, v.clone()))
        })
        .min()
        .map(|(_, v)| v)
}

fn ignored_package(cfg: &Config, p: &Package) -> bool {
    cfg.audit.ignore.iter().any(
        |r| match r.rsplit_once('@').filter(|(n, _)| !n.is_empty()) {
            Some((name, version)) => name == p.name && version == p.version,
            None => r == &p.name,
        },
    )
}

fn finding(
    pkg: &Package,
    advisories: &[&Advisory],
    sources: &[&lenstica_lens::Source],
    fix: Option<String>,
) -> Finding {
    let worst = advisories
        .iter()
        .map(|a| a.severity)
        .max()
        .unwrap_or(Severity::Medium);
    let malicious: Vec<&&Advisory> = advisories.iter().filter(|a| a.malicious).collect();
    let ids: Vec<&str> = advisories.iter().map(|a| a.id.as_str()).collect();
    let mut f = if !malicious.is_empty() {
        Finding::new(
            format!("malware|{}|{}|{}", pkg.ecosystem.label(), pkg.name, pkg.version),
            Severity::Critical,
            "malware",
            format!("Malicious package: {} {} ({})", pkg.name, pkg.version, pkg.ecosystem.label()),
        )
        .remedy(
            "Remove it, then treat this machine as compromised: from another machine, revoke and rotate every credential \
             this one can reach (npm and GitHub tokens, cloud sign-ins, SSH keys, .env secrets), and check the advisory \
             for anything it installs to persist.",
        )
    } else {
        let remedy = match &fix {
            Some(v) => format!("Upgrade {} to {v} or later.", pkg.name),
            None => "No fixed version is listed. Check whether the vulnerable code path is used, or replace the package.".to_string(),
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
            "vulnerability",
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
        f = f.at(Location {
            label: s.label.clone(),
            path: s.path.clone(),
            line: None,
        });
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
        "Locked and installed packages with known vulnerabilities or known malicious releases, from OSV.dev (GitHub, PyPI and OpenSSF malicious-packages advisories)."
    }

    fn run(&self, cx: &Context) -> Result<Report> {
        let cfg = Config::load()?;
        let inventory = (cx.inventory)()?;
        let by_package = inventory.by_package();
        let packages: Vec<&Package> = by_package
            .keys()
            .copied()
            .filter(|p| !ignored_package(&cfg, p))
            .collect();
        let refresh_hours = cx
            .settings
            .get("refresh_hours")
            .and_then(Value::as_i64)
            .unwrap_or(6)
            .max(1);
        let ignore_advisories: BTreeSet<String> = cx
            .settings
            .get("ignore_advisories")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let mut cache = Cache::load(&cx.state_dir);
        let now = chrono::Utc::now().timestamp();
        let mut problems = Vec::new();
        if !cx.offline {
            if let Err(e) = refresh_packages(&mut cache, &packages, refresh_hours * 3600, now, cx) {
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
        let malware = findings.iter().filter(|f| f.category == "malware").count();
        let count = |s: Severity| {
            findings
                .iter()
                .filter(|f| f.category == "vulnerability" && f.severity == s)
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
        assert_eq!(fixed_in(&[&g], &pkg).as_deref(), Some("4.17.21"));
    }
}
