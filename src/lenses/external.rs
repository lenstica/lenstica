//! Other tools run as lenses (`[[external]]` in lenstica.toml).
//!
//! `format = "lenstica"` (or the older `"cooldown"`) reads Lenstica's own JSON report (see the
//! `lenstica-lens` crate: `Report`), which is how internal tools plug in.
//! The other formats translate existing scanners. Secret values in their
//! output (gitleaks `Secret`/`Match`, trufflehog `Raw`) are never read into a
//! finding.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use lenstica_lens::{Category, Context, Finding, Lens, Location, Report, Severity, topic};
use serde_json::Value;

use super::{Group, Origin, Registered};
use crate::config::{Config, External, ExternalFormat};
use crate::exec;
use crate::paths::tilde;

pub fn from_config(cfg: &Config) -> Vec<Registered> {
    cfg.external
        .iter()
        .filter(|e| e.enabled)
        .map(|e| Registered {
            lens: Arc::new(Tool {
                title: e.title.clone().unwrap_or_else(|| e.id.clone()),
                description: format!("External tool: {}", e.command.join(" ")),
                categories: if e.categories.is_empty() {
                    e.format.default_categories().to_vec()
                } else {
                    e.categories.clone()
                },
                spec: e.clone(),
            }),
            origin: Origin::External,
            group: Group::Other,
        })
        .collect()
}

struct Tool {
    spec: External,
    title: String,
    description: String,
    categories: Vec<Category>,
}

impl Tool {
    fn invoke(&self, cx: &Context, root: Option<&Path>) -> Result<String> {
        let replace = |arg: &str| match root {
            Some(r) => arg.replace("{root}", &r.to_string_lossy()),
            None => arg.to_string(),
        };
        let program = &self.spec.command[0];
        let resolved =
            exec::find(program, cx.search_path).unwrap_or_else(|| PathBuf::from(program));
        let args: Vec<String> = self.spec.command[1..].iter().map(|a| replace(a)).collect();
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let out = exec::run_timeout(
            &resolved,
            &arg_refs,
            cx.search_path,
            Duration::from_secs(self.spec.timeout_seconds),
        )?;
        // Scanners exit non-zero when they find something; only empty output is a failure.
        if out.stdout.trim().is_empty() && !out.success {
            bail!("{} failed: {}", program, out.error_text());
        }
        Ok(out.stdout)
    }
}

impl Lens for Tool {
    fn id(&self) -> &str {
        &self.spec.id
    }
    fn title(&self) -> &str {
        &self.title
    }
    fn description(&self) -> &str {
        &self.description
    }
    fn categories(&self) -> &[Category] {
        &self.categories
    }
    fn default_interval(&self) -> Duration {
        Duration::from_secs(self.spec.interval_minutes.unwrap_or(120).saturating_mul(60))
    }

    fn run(&self, cx: &Context) -> Result<Report> {
        let mut outputs = Vec::new();
        if self.spec.per_root {
            for root in cx.roots {
                outputs.push((Some(root.as_path()), self.invoke(cx, Some(root))?));
            }
        } else {
            outputs.push((None, self.invoke(cx, None)?));
        }
        let mut report = Report::default();
        for (root, out) in &outputs {
            let part = parse(self.spec.format, out, *root).with_context(|| {
                format!(
                    "cannot read {} output as `{}`",
                    self.spec.id,
                    self.spec.format.as_str()
                )
            })?;
            report.findings.extend(part.findings);
            report.passing.extend(part.passing);
            report.actions.extend(part.actions);
            if report.summary.is_empty() {
                report.summary = part.summary;
            }
        }
        if self.spec.per_root || report.summary.is_empty() {
            report.summary = format!("{} findings from {}", report.findings.len(), self.title);
        }
        report.findings = merge_duplicates(std::mem::take(&mut report.findings));
        Ok(report)
    }
}

/// One finding per key, with the locations of every duplicate: several roots
/// can report the same file (nested worktrees), and osv-scanner reports a
/// package once per lockfile.
fn merge_duplicates(findings: Vec<Finding>) -> Vec<Finding> {
    let mut merged: Vec<Finding> = Vec::with_capacity(findings.len());
    let mut index: HashMap<String, usize> = HashMap::new();
    for f in findings {
        match index.get(&f.key) {
            Some(&i) => {
                for l in f.locations {
                    if !merged[i].locations.contains(&l) {
                        merged[i].locations.push(l);
                    }
                }
            }
            None => {
                index.insert(f.key.clone(), merged.len());
                merged.push(f);
            }
        }
    }
    merged
}

pub fn parse(format: ExternalFormat, out: &str, root: Option<&Path>) -> Result<Report> {
    match format {
        ExternalFormat::Lenstica => Ok(serde_json::from_str(out)?),
        ExternalFormat::Gitleaks => gitleaks(out, root),
        ExternalFormat::OsvScanner => osv_scanner(out, root),
        ExternalFormat::Trufflehog => trufflehog(out, root),
    }
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

fn file_location(file: &str, root: Option<&Path>, line: Option<u32>) -> Location {
    let path = match root {
        Some(r) if !Path::new(file).is_absolute() => r.join(file),
        _ => PathBuf::from(file),
    };
    Location {
        label: tilde(&path),
        path: Some(path),
        line,
    }
}

fn gitleaks(out: &str, root: Option<&Path>) -> Result<Report> {
    let items: Vec<Value> =
        serde_json::from_str(out.trim()).context("gitleaks report is not a JSON array")?;
    let findings = items
        .iter()
        .map(|i| {
            let line = i.get("StartLine").and_then(Value::as_u64).map(|n| n as u32);
            let loc = file_location(s(i, "File"), root, line);
            Finding::new(
                format!("{}|{}|{}", s(i, "RuleID"), loc.label, line.unwrap_or(0)),
                Severity::High,
                Category::Secrets,
                format!("{} in {}{}", s(i, "Description"), loc.label, line.map(|l| format!(":{l}")).unwrap_or_default()),
            ).topic(topic::LEAKED)
            .remedy("Rotate the credential, then remove it from the file (and from git history if it was committed).")
            .at(loc)
        })
        .collect();
    Ok(Report {
        findings,
        ..Default::default()
    })
}

fn osv_scanner(out: &str, root: Option<&Path>) -> Result<Report> {
    let doc: Value = serde_json::from_str(out).context("osv-scanner report is not JSON")?;
    let mut findings = Vec::new();
    for result in doc
        .get("results")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let source = result.get("source").map_or("", |x| s(x, "path"));
        for p in result
            .get("packages")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let pkg = p.get("package").unwrap_or(&Value::Null);
            let vulns = p
                .get("vulnerabilities")
                .and_then(Value::as_array)
                .map_or(&[][..], Vec::as_slice);
            if vulns.is_empty() {
                continue;
            }
            let malicious = vulns.iter().any(|v| s(v, "id").starts_with("MAL-"));
            let worst = vulns
                .iter()
                .filter_map(|v| {
                    v.get("database_specific")
                        .map(|d| s(d, "severity"))
                        .and_then(super::parse_severity)
                })
                .max()
                .unwrap_or(Severity::Medium);
            let (name, version, eco) = (s(pkg, "name"), s(pkg, "version"), s(pkg, "ecosystem"));
            findings.push(
                Finding::new(
                    format!(
                        "{}|{eco}|{name}|{version}",
                        if malicious { "malware" } else { "vuln" }
                    ),
                    if malicious { Severity::Critical } else { worst },
                    if malicious {
                        Category::Malware
                    } else {
                        Category::Packages
                    },
                    format!("{name} {version}: {} advisories", vulns.len()),
                )
                .topic(if malicious {
                    ""
                } else {
                    topic::VULNERABILITIES
                })
                .detail(
                    vulns
                        .iter()
                        .map(|v| format!("{}: {}", s(v, "id"), s(v, "summary")))
                        .collect::<Vec<_>>()
                        .join("\n"),
                )
                .at(file_location(source, root, None)),
            );
        }
    }
    Ok(Report {
        findings,
        ..Default::default()
    })
}

fn trufflehog(out: &str, root: Option<&Path>) -> Result<Report> {
    let mut findings = Vec::new();
    for line in out.lines().filter(|l| l.trim_start().starts_with('{')) {
        let v: Value = serde_json::from_str(line).context("trufflehog line is not JSON")?;
        let fs = v.pointer("/SourceMetadata/Data/Filesystem");
        let file = fs.map_or("", |f| s(f, "file"));
        let line_no = fs
            .and_then(|f| f.get("line"))
            .and_then(Value::as_u64)
            .map(|n| n as u32);
        let verified = v.get("Verified").and_then(Value::as_bool).unwrap_or(false);
        let detector = s(&v, "DetectorName");
        let loc = file_location(file, root, line_no);
        findings.push(
            Finding::new(
                format!("{detector}|{}|{}", loc.label, line_no.unwrap_or(0)),
                if verified {
                    Severity::Critical
                } else {
                    Severity::High
                },
                Category::Secrets,
                format!(
                    "{}{detector} credential in {}",
                    if verified { "Live " } else { "" },
                    loc.label
                ),
            )
            .topic(topic::LEAKED)
            .detail(if verified {
                "trufflehog confirmed it still works."
            } else {
                "Not verified against its service."
            })
            .remedy("Rotate the credential, then remove it from the file.")
            .at(loc),
        );
    }
    Ok(Report {
        findings,
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapters_drop_secret_values() {
        let gl = r#"[{"Description":"AWS Access Key","File":"app/.env","StartLine":3,"RuleID":"aws-access-token",
            "Secret":"AKIAABCDEFGHIJKLMNOP","Match":"KEY=AKIAABCDEFGHIJKLMNOP"}]"#;
        let r = parse(ExternalFormat::Gitleaks, gl, Some(Path::new("/repo"))).unwrap();
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("AKIAABCDEFGHIJKLMNOP"), "{json}");
        assert_eq!(
            r.findings[0].locations[0].path.as_deref(),
            Some(Path::new("/repo/app/.env"))
        );

        let th = r#"{"SourceMetadata":{"Data":{"Filesystem":{"file":"/x/.env","line":2}}},"DetectorName":"Github","Verified":true,"Raw":"ghp_secretvalue"}"#;
        let r = parse(ExternalFormat::Trufflehog, th, None).unwrap();
        assert_eq!(r.findings[0].severity, Severity::Critical);
        assert!(
            !serde_json::to_string(&r)
                .unwrap()
                .contains("ghp_secretvalue")
        );

        let osv = r#"{"results":[{"source":{"path":"/x/package-lock.json"},"packages":[{"package":{"name":"evil","version":"1.0.0","ecosystem":"npm"},
            "vulnerabilities":[{"id":"MAL-2025-9","summary":"Malicious code"}]}]}]}"#;
        let r = parse(ExternalFormat::OsvScanner, osv, None).unwrap();
        assert_eq!(
            (r.findings[0].category, r.findings[0].severity),
            (Category::Malware, Severity::Critical)
        );

        // An older report names a category from before there were categories.
        let own = r#"{"summary":"ok","findings":[{"key":"k","severity":"low","category":"settings","title":"t"}]}"#;
        let f = &parse(ExternalFormat::Lenstica, own, None).unwrap().findings[0];
        assert_eq!(
            (f.severity, f.category),
            (Severity::Low, Category::Packages)
        );
    }
}
