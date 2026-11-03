//! Locked and installed versions their maintainers deprecated (npm) or
//! yanked (PyPI, crates.io). Read from the same registry documents as publish
//! times; re-checked weekly.

use anyhow::Result;
use lenstica_lens::{Category, Context, Finding, Lens, Report, Severity, topic};

use super::shared;
use crate::audit::{
    self,
    registry::{Cache, Status},
};
use crate::config::Config;
use crate::managers::Ctx;

pub struct Deprecated;

impl Lens for Deprecated {
    fn id(&self) -> &str {
        "deprecated"
    }
    fn title(&self) -> &str {
        "Deprecated and yanked"
    }
    fn description(&self) -> &str {
        "Locked and installed versions marked deprecated on npm or yanked on PyPI or crates.io, usually because they are broken, unmaintained or replaced."
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
        let wanted: std::collections::BTreeSet<_> = sources
            .iter()
            .flat_map(|s| s.entries.iter())
            .filter(|e| e.public && !audit::ignored(&cfg.audit.ignore, &e.pkg))
            .map(|e| e.pkg.clone())
            .collect();
        let mut passing = Vec::new();
        if !cx.offline
            && let Err(e) = cache.fill(&wanted, &cfg.audit, &ctx.search, ctx.now, None, true)
        {
            passing.push(format!("registry lookups: {e:#}"));
        }
        let mut findings = Vec::new();
        let mut checked = 0;
        for pkg in &wanted {
            let Some(status) = cache.status(pkg) else {
                continue;
            };
            checked += 1;
            let (severity, kind, message) = match status {
                Status::Deprecated(msg) => (Severity::Info, "deprecated", msg),
                Status::Yanked(msg) => (Severity::Low, "yanked", msg),
                Status::Fine => continue,
            };
            let mut f = Finding::new(
                format!("{kind}|{}|{}|{}", pkg.eco.label(), pkg.name, pkg.version),
                severity,
                Category::Packages,
                format!("{} {} is {kind}", pkg.name, pkg.version),
            )
            .topic(topic::DEPRECATED)
            .detail(message.to_string())
            .remedy(if kind == "yanked" {
                "Its maintainers pulled this release; move to another version."
            } else {
                "Upgrade it, or the package that depends on it, to a maintained version."
            });
            for s in sources
                .iter()
                .filter(|s| s.entries.iter().any(|e| &e.pkg == pkg))
            {
                f = f.at(s.location());
            }
            findings.push(f);
        }
        let yanked = findings
            .iter()
            .filter(|f| f.severity == Severity::Low)
            .count();
        let summary = format!(
            "{} deprecated, {yanked} yanked, of {checked} packages checked",
            findings.len() - yanked
        );
        passing.insert(
            0,
            format!(
                "{checked} of {} packages have a known status (re-checked weekly)",
                wanted.len()
            ),
        );
        Ok(Report {
            findings,
            summary,
            passing,
            ..Default::default()
        })
    }
}
