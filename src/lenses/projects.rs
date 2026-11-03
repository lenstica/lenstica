//! Project files that override the cooldown with a weaker one.

use anyhow::Result;
use lenstica_lens::{Context, Finding, Lens, Location, Report, Severity};

use super::shared;
use crate::config::Config;
use crate::scan;

pub struct ProjectSettings;

impl Lens for ProjectSettings {
    fn id(&self) -> &str {
        "project-settings"
    }
    fn title(&self) -> &str {
        "Project settings"
    }
    fn description(&self) -> &str {
        "Repository config files (.npmrc, pnpm-workspace.yaml, uv.toml, ...) that lower or disable the cooldown for that repository. Reported, never edited."
    }

    fn run(&self, cx: &Context) -> Result<Report> {
        let cfg = Config::load()?;
        let target = i64::from(cfg.min_days) * crate::duration::DAY;
        let now = chrono::DateTime::<chrono::Utc>::from(cx.now);
        let found = scan::scan(cx.roots, cx.exclude, cfg.scan.max_depth, target, now);
        let scope = shared::roots(&cfg, cx.search_path).label.clone();
        let findings = found
            .iter()
            .map(|f| {
                Finding::new(
                    format!("{}|{}|{}", f.full_path.display(), f.setting, f.value),
                    Severity::Medium,
                    "cooldown",
                    format!("{} lowers the {} cooldown to {}", f.path, f.manager, f.age),
                )
                .detail(format!("{} = {} overrides your {}-day setting for this repository.", f.setting, f.value, cfg.min_days))
                .remedy("Raise or remove the setting in that file (Lenstica never edits project files).")
                .at(Location::file(f.path.clone(), f.full_path.clone()))
            })
            .collect::<Vec<_>>();
        let summary = if findings.is_empty() {
            format!("No project setting weakens the cooldown under {scope}")
        } else {
            format!(
                "{} project files weaken the cooldown under {scope}",
                findings.len()
            )
        };
        Ok(Report {
            findings,
            summary,
            passing: vec![format!("Searched {scope}")],
            ..Default::default()
        })
    }
}
