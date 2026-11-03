//! Package-manager inspection shared by the lenses and `lenstica apply`.

use serde::Serialize;

use crate::config::Config;
use crate::exec;
use crate::managers::{self, Ctx, ManagerStatus, State};
use crate::paths::tilde;

#[derive(Debug, Clone, Serialize)]
pub struct Detected {
    pub id: &'static str,
    pub name: &'static str,
    pub binary: String,
    pub note: &'static str,
}

pub fn inspect_managers(cfg: &Config, ctx: &Ctx) -> (Vec<ManagerStatus>, Vec<&'static str>) {
    let enabled: Vec<_> = managers::all()
        .into_iter()
        .filter(|m| cfg.is_enabled(m.id()))
        .collect();
    let results: Vec<(&'static str, Option<ManagerStatus>)> = std::thread::scope(|s| {
        let handles: Vec<_> = enabled
            .iter()
            .map(|m| {
                s.spawn(move || {
                    let status =
                        managers::locate(*m, ctx).map(|tool| managers::inspect(*m, &tool, ctx));
                    (m.name(), status)
                })
            })
            .collect();
        handles.into_iter().filter_map(|h| h.join().ok()).collect()
    });
    let mut found = Vec::new();
    let mut missing = Vec::new();
    for (name, status) in results {
        match status {
            Some(s) => found.push(s),
            None => missing.push(name),
        }
    }
    (found, missing)
}

pub fn detect_unsupported(ctx: &Ctx) -> Vec<Detected> {
    managers::UNSUPPORTED
        .iter()
        .filter_map(|u| {
            let bin = u.binaries.iter().find_map(|b| exec::find(b, &ctx.search))?;
            Some(Detected {
                id: u.id,
                name: u.name,
                binary: tilde(&bin),
                note: u.note,
            })
        })
        .collect()
}

/// One-line description of a manager's state, shared by the CLI and the menu.
pub fn describe(m: &ManagerStatus) -> String {
    let current = || match (&m.current, &m.current_age) {
        (Some(raw), Some(age)) if raw == age => raw.clone(),
        (Some(raw), Some(age)) => format!("{raw} ({age})"),
        (Some(raw), None) => raw.clone(),
        (None, _) => String::new(),
    };
    match m.state {
        State::Ok => current(),
        State::Stronger => format!("{} — stronger than required", current()),
        State::Missing if m.current.is_some() => {
            format!("{} (disabled)", m.current.as_deref().unwrap_or(""))
        }
        State::Missing => "not set".to_string(),
        State::Weaker => format!("{} — weaker than required", current()),
        State::Outdated | State::Error => m.detail.clone().unwrap_or_default(),
    }
}
