//! Whether Aikido Safe Chain is installed and wired into the shell.
//!
//! Safe Chain and Lenstica cover different moments: Safe Chain checks each
//! download against Aikido's malware lists before it reaches the disk, while
//! Lenstica sets the package managers' own minimum age and audits what is
//! already installed. Safe Chain works through shell functions, so it only
//! protects commands typed in a shell whose startup file loads it.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use lenstica_lens::{Context, Finding, Lens, Location, Report, Severity};

use crate::exec;
use crate::files;
use crate::paths::{self, tilde};

pub struct SafeChain;

const REPO: &str = "https://github.com/AikidoSec/safe-chain";
const NOT_INSTALLED: &str = "safe-chain|not-installed";
const NOT_SET_UP: &str = "safe-chain|not-set-up";

fn safe_chain_dir() -> PathBuf {
    paths::home().join(".safe-chain")
}

fn binary(cx: &Context) -> Option<PathBuf> {
    exec::find("safe-chain", cx.search_path).or_else(|| {
        let bin = safe_chain_dir().join("bin").join(if cfg!(windows) {
            "safe-chain.exe"
        } else {
            "safe-chain"
        });
        bin.is_file().then_some(bin)
    })
}

/// Each shell's startup file, for the shells installed here.
fn startup_files(cx: &Context) -> Vec<(&'static str, PathBuf)> {
    let home = paths::home();
    let zdotdir = std::env::var_os("ZDOTDIR")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.clone());
    let candidates = [
        ("zsh", "zsh", zdotdir.join(".zshrc")),
        ("bash", "bash", home.join(".bashrc")),
        ("fish", "fish", home.join(".config/fish/config.fish")),
        (
            "PowerShell",
            "pwsh",
            if cfg!(windows) {
                home.join("Documents/PowerShell/Microsoft.PowerShell_profile.ps1")
            } else {
                home.join(".config/powershell/Microsoft.PowerShell_profile.ps1")
            },
        ),
    ];
    candidates
        .into_iter()
        .filter(|(_, bin, file)| file.exists() || exec::find(bin, cx.search_path).is_some())
        .map(|(name, _, file)| (name, file))
        .collect()
}

/// The line `safe-chain setup` adds: `source ~/.safe-chain/scripts/init-posix.sh # Safe-chain ...`.
fn loads_safe_chain(src: &str) -> bool {
    src.lines().any(|l| {
        let l = l.trim();
        !l.starts_with('#') && l.contains(".safe-chain") && l.contains("init-")
    })
}

/// `safe-chain setup-ci` puts shims on PATH instead of shell functions.
fn shims_on_path(cx: &Context) -> bool {
    std::env::split_paths(cx.search_path).any(|p| p.ends_with(Path::new(".safe-chain/shims")))
}

impl Lens for SafeChain {
    fn id(&self) -> &str {
        "safe-chain"
    }
    fn title(&self) -> &str {
        "Aikido Safe Chain"
    }
    fn description(&self) -> &str {
        "Whether Aikido Safe Chain is installed and loaded by your shells. It checks every npm, Yarn, pnpm, Bun, pip, uv and Poetry download against Aikido's malware lists and blocks a malicious package before it is installed, which Lenstica can only report afterwards."
    }
    fn default_interval(&self) -> std::time::Duration {
        std::time::Duration::from_secs(6 * 3600)
    }

    fn run(&self, cx: &Context) -> Result<Report> {
        let shells = startup_files(cx);
        let watch: Vec<PathBuf> = shells.iter().map(|(_, f)| f.clone()).collect();
        let Some(bin) = binary(cx) else {
            let finding = Finding::new(
                NOT_INSTALLED,
                Severity::Info,
                "settings",
                "Aikido Safe Chain is not installed",
            )
            .detail(
                "Lenstica finds malware once it is in a lockfile or installed, possibly after its install script \
                 has already run. Safe Chain stops it at download time instead, for npm, npx, Yarn, pnpm, Bun, pip, \
                 uv, Poetry and pipx typed in a terminal. It is free and needs no account; the two work together.",
            )
            .remedy(format!(
                "Install it as its README describes ({REPO}#installation), then open a new terminal and run \
                 `npm safe-chain-verify`. Turn this check off on the Lenses page if you do not want it."
            ))
            .link(REPO);
            return Ok(Report {
                summary: "Safe Chain is not installed".to_string(),
                findings: vec![finding],
                watch,
                ..Default::default()
            });
        };

        let mut loaded = Vec::new();
        let mut missing = Vec::new();
        for (shell, file) in &shells {
            let src = files::read_optional(file)
                .ok()
                .flatten()
                .unwrap_or_default();
            if loads_safe_chain(&src) {
                loaded.push(*shell);
            } else {
                missing.push((*shell, file.clone()));
            }
        }
        let shims = shims_on_path(cx);
        let mut passing = vec![format!("Safe Chain installed at {}", tilde(&bin))];
        if !loaded.is_empty() {
            passing.push(format!("loaded by {}", loaded.join(", ")));
        }
        if shims {
            passing.push("its shims are on PATH".to_string());
        }
        passing.push(
            "Applies to commands typed in a terminal; installs started by an editor, a GUI or a script that \
             calls a package manager by full path bypass it"
                .to_string(),
        );
        let mut findings = Vec::new();
        if loaded.is_empty() && !shims {
            let mut f = Finding::new(
                NOT_SET_UP,
                Severity::Low,
                "settings",
                "Safe Chain is installed but no shell loads it",
            )
            .detail(
                "Without its shell integration, npm, pip and the others run unprotected: Safe Chain only checks \
                 downloads when the commands go through its wrappers.",
            )
            .remedy("Run `safe-chain setup` (Lenstica can do it), then open a new terminal.")
            .link(format!("{REPO}/blob/main/docs/shell-integration.md"))
            .fixable();
            for (shell, file) in &missing {
                f = f.at(Location::file(
                    format!("{shell}: {}", tilde(file)),
                    file.clone(),
                ));
            }
            findings.push(f);
        } else if !missing.is_empty() && !shims {
            let names: Vec<&str> = missing.iter().map(|(s, _)| *s).collect();
            let mut f = Finding::new(
                format!("safe-chain|partial|{}", names.join(",")),
                Severity::Info,
                "settings",
                format!("Safe Chain is not loaded in {}", names.join(", ")),
            )
            .remedy("Run `safe-chain setup` to add it to every shell, then open a new terminal.")
            .fixable();
            for (shell, file) in &missing {
                f = f.at(Location::file(
                    format!("{shell}: {}", tilde(file)),
                    file.clone(),
                ));
            }
            findings.push(f);
        }
        let summary = match (findings.is_empty(), loaded.is_empty()) {
            (true, false) => format!("Installed and loaded by {}", loaded.join(", ")),
            (true, true) => "Installed, through shims on PATH".to_string(),
            (false, _) => findings[0].title.clone(),
        };
        Ok(Report {
            findings,
            summary,
            passing,
            watch,
            ..Default::default()
        })
    }

    fn fix(&self, cx: &Context, finding: &Finding) -> Result<String> {
        if !finding.key.starts_with("safe-chain|") || finding.key == NOT_INSTALLED {
            bail!("only Safe Chain's shell setup can be done automatically");
        }
        let Some(bin) = binary(cx) else {
            bail!("Safe Chain is not installed");
        };
        let out = exec::run(&bin, &["setup"], cx.search_path)?;
        if !out.success {
            bail!("`safe-chain setup` failed: {}", out.error_text());
        }
        Ok("Ran `safe-chain setup`; open a new terminal for it to take effect".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::loads_safe_chain;

    #[test]
    fn recognises_the_setup_line() {
        assert!(loads_safe_chain(
            "export X=1\nsource /Users/me/.safe-chain/scripts/init-posix.sh # Safe-chain Zsh initialization script\n"
        ));
        assert!(loads_safe_chain(
            "source ~/.safe-chain/scripts/init-fish.fish # Safe-chain Fish initialization script"
        ));
        assert!(!loads_safe_chain(
            "# source ~/.safe-chain/scripts/init-posix.sh\n"
        ));
        assert!(!loads_safe_chain("alias npm=pnpm\n"));
    }
}
