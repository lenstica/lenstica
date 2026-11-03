//! Each package manager's own minimum-release-age setting, re-applied when
//! `monitor.auto_apply` is on.

use std::collections::BTreeSet;

use anyhow::{Context as _, Result, bail};
use lenstica_lens::{Category, Context, Finding, Lens, Location, Report, Severity, topic};

use crate::config::Config;
use crate::files;
use crate::managers::{self, Action, Ctx, ManagerStatus, Mode, State};
use crate::report::{self, describe};

pub struct Managers;

fn title(m: &ManagerStatus, days: u32) -> String {
    match m.state {
        State::Missing => format!("{} has no minimum release age", m.name),
        State::Weaker => format!(
            "{} allows versions {} old (the cooldown is {days} days)",
            m.name,
            m.current_age.as_deref().unwrap_or("too")
        ),
        State::Outdated => match m.version.as_deref() {
            Some(v) => format!("{} {v} is too old to enforce a cooldown", m.name),
            None => format!("{} is too old to enforce a cooldown", m.name),
        },
        State::Error => format!("Cannot read {}'s minimum release age", m.name),
        State::Ok | State::Stronger => format!("{} is fine", m.name),
    }
}

fn finding(m: &ManagerStatus, days: u32) -> Finding {
    let severity = match m.state {
        State::Missing | State::Weaker => Severity::High,
        _ => Severity::Medium,
    };
    let remedy = match m.state {
        State::Outdated => format!("Upgrade {} to {} or newer.", m.name, m.min_version),
        _ => format!(
            "Set {} to {} (`lenstica apply {}`), or click to fix.",
            m.setting, m.target, m.id
        ),
    };
    let mut f = Finding::new(
        format!(
            "{}|{}|{}",
            m.id,
            m.state.key(),
            m.current.as_deref().unwrap_or("")
        ),
        severity,
        Category::Packages,
        title(m, days),
    )
    .topic(topic::COOLDOWN)
    .detail(format!("{} in {}: {}", m.setting, m.location, describe(m)))
    .remedy(remedy)
    .at(Location::file(m.location.clone(), m.path.clone()));
    if m.state.is_fixable() {
        f = f.fixable();
    }
    f
}

/// "npm: min-release-age was 1 (1 day), below the 7-day cooldown. Reset to 7."
fn describe_fix(
    before: Option<&ManagerStatus>,
    name: &str,
    from: Option<&str>,
    to: &str,
    days: u32,
) -> String {
    let was = match (from, before.and_then(|m| m.current_age.as_deref())) {
        (None, _) => "was not set".to_string(),
        (Some(raw), Some(age)) if raw != age => format!("was {raw} ({age})"),
        (Some(raw), _) => format!("was {raw}"),
    };
    let setting = before.map_or("its setting", |m| m.setting);
    format!("{name}: {setting} {was}, below the {days}-day cooldown. Reset to {to}.")
}

/// Announce package managers that appeared since the last run.
fn new_arrivals(cx: &Context, present: &[(String, String)]) -> Vec<String> {
    let path = cx.state_dir.join("seen.json");
    let seen: Option<BTreeSet<String>> = files::read_json(&path);
    let now: BTreeSet<String> = present.iter().map(|(id, _)| id.clone()).collect();
    if let Ok(json) = serde_json::to_string(&now) {
        let _ = files::write_state(&path, &json);
    }
    let Some(seen) = seen else { return Vec::new() };
    present
        .iter()
        .filter(|(id, _)| !seen.contains(id))
        .map(|(_, name)| format!("New package manager detected: {name}."))
        .collect()
}

impl Lens for Managers {
    fn id(&self) -> &str {
        "package-managers"
    }
    fn title(&self) -> &str {
        "Package managers"
    }
    fn description(&self) -> &str {
        "Each package manager's own minimum-release-age setting, re-applied automatically when it is missing or weaker."
    }
    fn categories(&self) -> &[Category] {
        &[Category::Packages]
    }

    fn run(&self, cx: &Context) -> Result<Report> {
        let cfg = Config::load()?;
        let ctx = Ctx::new(&cfg);
        let (mut found, not_installed) = report::inspect_managers(&cfg, &ctx);
        let mut actions = Vec::new();
        if cfg.monitor.auto_apply && found.iter().any(|m| m.state.is_fixable()) {
            let applied = managers::apply_all(&cfg, &ctx, &[], Mode::ProblemsOnly, false);
            for o in &applied {
                if let Action::Changed { from, to } = &o.action {
                    actions.push(describe_fix(
                        found.iter().find(|m| m.id == o.id),
                        o.name,
                        from.as_deref(),
                        to,
                        cfg.min_days,
                    ));
                }
            }
            if !actions.is_empty() {
                found = report::inspect_managers(&cfg, &ctx).0;
            }
        }
        let unsupported = report::detect_unsupported(&ctx);
        let present: Vec<(String, String)> = found
            .iter()
            .map(|m| (m.id.to_string(), m.name.to_string()))
            .chain(
                unsupported
                    .iter()
                    .map(|u| (u.id.to_string(), format!("{} ({})", u.name, u.note))),
            )
            .collect();
        actions.extend(new_arrivals(cx, &present));

        let mut findings: Vec<Finding> = found
            .iter()
            .filter(|m| m.state.is_problem())
            .map(|m| finding(m, cfg.min_days))
            .collect();
        if !unsupported.is_empty() {
            let names: Vec<&str> = unsupported.iter().map(|u| u.name).collect();
            let mut f = Finding::new(
                format!("unsupported|{}", names.join(",")),
                Severity::Info,
                Category::Packages,
                format!("Not covered: {}", names.join(", ")),
            )
            .topic(topic::COOLDOWN)
            .detail(
                unsupported
                    .iter()
                    .map(|u| format!("{} ({}): {}", u.name, u.binary, u.note))
                    .collect::<Vec<_>>()
                    .join("\n"),
            )
            .remedy("Nothing Lenstica can set. Review new versions from these by hand.");
            for u in &unsupported {
                f = f.at(Location::label(format!("{}: {}", u.name, u.binary)));
            }
            findings.push(f);
        }
        let ok = found.iter().filter(|m| !m.state.is_problem()).count();
        let passing = found
            .iter()
            .filter(|m| !m.state.is_problem())
            .map(|m| {
                format!(
                    "{} {}: {} = {} in {}",
                    m.name,
                    m.version.as_deref().unwrap_or("?"),
                    m.setting,
                    describe(m),
                    m.location
                )
            })
            .chain(
                (!not_installed.is_empty())
                    .then(|| format!("Not installed: {}", not_installed.join(", "))),
            )
            .collect();
        let summary = if found.is_empty() {
            "No package manager found".to_string()
        } else if ok == found.len() {
            format!(
                "All {} package managers hold back versions newer than {} days",
                found.len(),
                cfg.min_days
            )
        } else {
            format!(
                "{} of {} package managers below the {}-day cooldown",
                found.len() - ok,
                found.len(),
                cfg.min_days
            )
        };
        Ok(Report {
            findings,
            summary,
            passing,
            actions,
            // The PATH directories too: installing a package manager adds a file to
            // one, which re-runs this lens and configures it within seconds.
            watch: found
                .iter()
                .map(|m| m.path.clone())
                .chain(std::env::split_paths(cx.search_path).filter(|d| d.is_dir()))
                .collect(),
        })
    }

    fn fix(&self, _cx: &Context, finding: &Finding) -> Result<String> {
        let id = finding
            .key
            .split('|')
            .next()
            .unwrap_or_default()
            .to_string();
        let cfg = Config::load()?;
        let ctx = Ctx::new(&cfg);
        let outcome =
            managers::apply_all(&cfg, &ctx, std::slice::from_ref(&id), Mode::Exact, false)
                .into_iter()
                .next()
                .with_context(|| format!("{id} is not installed"))?;
        match outcome.action {
            Action::Changed { to, .. } => Ok(format!("Set {} to {to}", outcome.name)),
            Action::Unchanged => Ok(format!("{} was already set", outcome.name)),
            Action::Skipped { reason } => bail!("{}: {reason}", outcome.name),
            Action::Failed { error } => bail!("{}: {error}", outcome.name),
            Action::WouldChange { .. } => unreachable!("not a dry run"),
        }
    }
}
