//! Locked and installed packages younger than the cooldown.

use super::shared::plural;
use anyhow::Result;
use lenstica_lens::{Category, Context, Finding, Lens, Report, Severity, topic};

use super::shared;
use crate::audit::{self, Kind, registry::Cache};
use crate::config::Config;
use crate::managers::Ctx;

pub struct PackageAge;

impl Lens for PackageAge {
    fn id(&self) -> &str {
        "package-age"
    }
    fn title(&self) -> &str {
        "Package ages"
    }
    fn description(&self) -> &str {
        "Packages in your lockfiles and global installs that were published less than the cooldown ago, or were that young when their lockfile last changed."
    }
    fn categories(&self) -> &[Category] {
        &[Category::Packages]
    }

    fn run(&self, cx: &Context) -> Result<Report> {
        let cfg = Config::load()?;
        let ctx = Ctx::new(&cfg);
        let inventory = shared::inventory(&cfg, &ctx, cx.roots, cfg.audit.global)?;
        let sources = &inventory.collected.sources;
        let mut cache = Cache::load();
        let mut errors = inventory.collected.errors.clone();
        if !cx.offline {
            let wanted = audit::undated(sources, &cfg);
            if let Err(e) = cache.fill(&wanted, &cfg.audit, &ctx.search, ctx.now, None, false) {
                errors.push(format!("{e:#}"));
            }
        }
        let classified = audit::classify(sources, &cache, &cfg, &ctx);
        let findings: Vec<Finding> = classified
            .findings
            .iter()
            .map(|f| {
                let (key, severity, title, remedy) = match f.kind {
                    Kind::TooNew => (
                        "too-new",
                        Severity::Medium,
                        format!("{} {} was published {} ago", f.name, f.version, f.age),
                        format!(
                            "It has not had the {}-day cooldown's worth of scrutiny. Pin an older version, or add \"{}@{}\" to audit.ignore once you have checked it.",
                            cfg.min_days, f.name, f.version
                        ),
                    ),
                    Kind::LockedWhileTooNew => (
                        "locked-young",
                        Severity::Info,
                        format!("{} {} was {} old when locked", f.name, f.version, f.age),
                        "It is old enough now; nothing to undo. It shows where the cooldown was bypassed.".to_string(),
                    ),
                };
                let mut finding = Finding::new(
                    format!("{key}|{}|{}|{}", f.ecosystem.label(), f.name, f.version),
                    severity,
                    Category::Packages,
                    title,
                ).topic(topic::COOLDOWN)
                .detail(format!(
                    "{} package published {} UTC. Found in {}.",
                    f.ecosystem.label(),
                    f.published.format("%Y-%m-%d %H:%M"),
                    plural(f.sources.len(), "place", "places")
                ))
                .remedy(remedy);
                for &i in &f.sources {
                    finding = finding.at(sources[i].location());
                }
                finding
            })
            .collect();
        let too_new = classified
            .findings
            .iter()
            .filter(|f| f.kind == Kind::TooNew)
            .count();
        let locked = classified.findings.len() - too_new;
        let summary = format!(
            "{} of {} published less than {} days ago; {} locked while too new",
            too_new, classified.packages, cfg.min_days, locked
        );
        let mut passing = vec![format!(
            "{} from {} ({} not in a public registry)",
            plural(classified.packages, "package", "packages"),
            plural(
                sources.len(),
                "lockfile or global install",
                "lockfiles and global installs"
            ),
            classified.unknown
        )];
        passing.extend(errors.into_iter().take(10).map(|e| format!("skipped: {e}")));
        Ok(Report {
            findings,
            summary,
            passing,
            ..Default::default()
        })
    }
}
