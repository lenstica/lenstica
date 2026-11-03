//! Whether Homebrew updates itself before every install.
//!
//! Homebrew has no minimum-age setting. By default `brew install`, `brew
//! upgrade` and `brew tap` first fetch the newest formula definitions, so a
//! version published minutes ago can arrive with an unrelated install.
//! `HOMEBREW_NO_AUTO_UPDATE=1` makes new versions arrive only when you run
//! `brew update` yourself. It is not an age gate; the software-age lens
//! still reports what is younger than the cooldown.
//!
//! Lenstica writes it to Homebrew's own per-user environment file
//! (`~/.homebrew/brew.env`, or `$XDG_CONFIG_HOME/homebrew/brew.env`), which
//! `brew` reads however it is started, unlike a line in a shell startup file.

use std::path::PathBuf;

use anyhow::{Result, bail};
use lenstica_lens::{Context, Finding, Lens, Location, Report, Severity};

use crate::config::Config;
use crate::exec;
use crate::files;
use crate::paths;

pub struct HomebrewUpdates;

const VAR: &str = "HOMEBREW_NO_AUTO_UPDATE";
const KEY: &str = "homebrew|auto-update";

/// Homebrew's per-user environment file, as `brew` itself locates it.
fn user_env_file() -> PathBuf {
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .or_else(|| std::env::var_os("HOMEBREW_XDG_CONFIG_HOME").filter(|v| !v.is_empty()));
    match config {
        Some(dir) => PathBuf::from(dir).join("homebrew").join("brew.env"),
        None => paths::home().join(".homebrew").join("brew.env"),
    }
}

/// Every environment file `brew` reads, system-wide first.
fn env_files(cx: &Context) -> Vec<PathBuf> {
    let mut out = vec![PathBuf::from("/etc/homebrew/brew.env")];
    if let Some(brew) = exec::find("brew", cx.search_path)
        && let Some(prefix) = brew.parent().and_then(|bin| bin.parent())
    {
        out.push(prefix.join("etc").join("homebrew").join("brew.env"));
    }
    out.push(user_env_file());
    out
}

/// `brew` treats the variable as set when it has any value, `0` included.
fn sets_var(src: &str) -> bool {
    src.lines().any(|l| {
        let l = l.trim();
        let l = l.strip_prefix("export ").unwrap_or(l).trim();
        l.strip_prefix(VAR)
            .and_then(|rest| rest.trim_start().strip_prefix('='))
            .is_some_and(|v| !v.trim().trim_matches(['"', '\'']).is_empty())
    })
}

/// Shell startup files that export it: these only cover terminals.
fn shell_files() -> Vec<PathBuf> {
    let home = paths::home();
    [
        ".zshrc",
        ".zprofile",
        ".zshenv",
        ".bashrc",
        ".bash_profile",
        ".profile",
    ]
    .iter()
    .map(|f| home.join(f))
    .chain([home.join(".config/fish/config.fish")])
    .collect()
}

fn write_env_file() -> Result<String> {
    let path = user_env_file();
    let src = files::read_optional(&path)?.unwrap_or_default();
    if sets_var(&src) {
        return Ok(format!("{VAR} is already set in {}", paths::tilde(&path)));
    }
    let mut text = src;
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(&format!("{VAR}=1\n"));
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    files::write_atomic(&path, &text)?;
    Ok(format!(
        "Homebrew: set {VAR}=1 in {}; new versions now arrive only with `brew update`",
        paths::tilde(&path)
    ))
}

impl Lens for HomebrewUpdates {
    fn id(&self) -> &str {
        "homebrew-updates"
    }
    fn title(&self) -> &str {
        "Homebrew auto-update"
    }
    fn description(&self) -> &str {
        "Whether Homebrew fetches the newest formulae before every install. Homebrew has no minimum-age setting; turning auto-update off means new versions arrive only when you run brew update."
    }

    fn run(&self, cx: &Context) -> Result<Report> {
        let cfg = Config::load()?;
        let mut watch: Vec<PathBuf> = env_files(cx);
        if exec::find("brew", cx.search_path).is_none() {
            return Ok(Report {
                summary: "Homebrew is not installed".to_string(),
                watch,
                ..Default::default()
            });
        }
        let in_env_file = env_files(cx).into_iter().find(|f| {
            files::read_optional(f)
                .ok()
                .flatten()
                .is_some_and(|s| sets_var(&s))
        });
        let mut actions = Vec::new();
        let in_env_file = match in_env_file {
            None if cfg.homebrew.no_auto_update => match write_env_file() {
                Ok(done) => {
                    actions.push(done);
                    Some(user_env_file())
                }
                Err(e) => {
                    actions.push(format!(
                        "Homebrew: cannot write {}: {e:#}",
                        paths::tilde(&user_env_file())
                    ));
                    None
                }
            },
            other => other,
        };
        if let Some(file) = in_env_file {
            return Ok(Report {
                summary: "Homebrew updates only when you run brew update".to_string(),
                passing: vec![format!("{VAR} set in {}", paths::tilde(&file))],
                actions,
                watch,
                ..Default::default()
            });
        }
        let in_shell: Vec<PathBuf> = shell_files()
            .into_iter()
            .filter(|f| {
                files::read_optional(f)
                    .ok()
                    .flatten()
                    .is_some_and(|s| sets_var(&s))
            })
            .collect();
        watch.extend(shell_files());
        let detail = if in_shell.is_empty() {
            "`brew install`, `brew upgrade` and `brew tap` first fetch the newest formula definitions, so a version \
             published minutes ago can come in with an unrelated install. Homebrew has no minimum-age setting; with \
             auto-update off, new versions arrive only when you run `brew update`."
                .to_string()
        } else {
            format!(
                "{} sets it, but only for terminals that read that file: brew started by an editor, a script or a \
                 GUI still updates itself first. Homebrew's own environment file applies everywhere.",
                in_shell
                    .iter()
                    .map(|p| paths::tilde(p))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        let path = user_env_file();
        let finding = Finding::new(
            KEY,
            Severity::Low,
            "settings",
            if in_shell.is_empty() {
                "Homebrew updates itself before every install"
            } else {
                "Homebrew auto-update is off only in your shell"
            },
        )
        .detail(detail)
        .remedy(format!(
            "Click to set {VAR}=1 in {}, or switch on homebrew.no_auto_update in Settings to keep it set. \
             Then run `brew update && brew upgrade` when you choose to.",
            paths::tilde(&path)
        ))
        .at(Location::file(paths::tilde(&path), path.clone()))
        .fixable();
        Ok(Report {
            summary: finding.title.clone(),
            findings: vec![finding],
            actions,
            watch,
            ..Default::default()
        })
    }

    fn fix(&self, _cx: &Context, finding: &Finding) -> Result<String> {
        if finding.key != KEY {
            bail!("nothing to apply for {}", finding.key);
        }
        write_env_file()
    }
}

#[cfg(test)]
mod tests {
    use super::sets_var;

    #[test]
    fn reads_env_and_shell_lines() {
        assert!(sets_var("HOMEBREW_NO_AUTO_UPDATE=1\n"));
        assert!(sets_var("# x\nexport HOMEBREW_NO_AUTO_UPDATE=1\n"));
        assert!(sets_var("HOMEBREW_NO_AUTO_UPDATE = \"1\""));
        assert!(!sets_var("# HOMEBREW_NO_AUTO_UPDATE=1\n"));
        assert!(!sets_var("HOMEBREW_NO_AUTO_UPDATE=\n"));
        assert!(!sets_var("HOMEBREW_NO_AUTO_UPDATE_SECS=60\n"));
    }
}
