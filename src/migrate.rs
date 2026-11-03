//! Moving over from before the project was renamed from cooldown to Lenstica:
//! the settings file, the stored results and the login item. Runs at start-up
//! and does nothing once there is nothing left to move.

use std::path::{Path, PathBuf};

use crate::autostart;
use crate::config;
use crate::paths;

/// Rename-era names: the settings file and folders were called `cooldown`.
const OLD: &str = "cooldown";

pub fn run() {
    if let Err(e) = settings() {
        eprintln!("lenstica: cannot move the old cooldown settings: {e:#}");
    }
    if let Err(e) = state() {
        eprintln!("lenstica: cannot move the old cooldown results: {e:#}");
    }
    if let Err(e) = login_item() {
        eprintln!("lenstica: cannot replace the old cooldown login item: {e:#}");
    }
}

/// `[checkers.<id>]` became `[lenses.<id>]`, and the external report format
/// `cooldown` became `lenstica` (both old spellings are still read).
pub fn rewrite_settings(src: &str) -> String {
    src.lines()
        .map(|l| {
            let t = l.trim_start();
            if t.starts_with("[checkers") || t.starts_with("# [checkers") {
                l.replacen("[checkers", "[lenses", 1)
            } else if t.starts_with("format") && l.contains("\"cooldown\"") {
                l.replacen("\"cooldown\"", "\"lenstica\"", 1)
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + if src.ends_with('\n') { "\n" } else { "" }
}

fn settings() -> anyhow::Result<()> {
    let new = config::path();
    let old = paths::config_root().join(OLD).join(format!("{OLD}.toml"));
    if new.exists() || !old.is_file() || std::env::var_os("LENSTICA_CONFIG").is_some() {
        return Ok(());
    }
    let src = std::fs::read_to_string(&old)?;
    if let Some(dir) = new.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&new, rewrite_settings(&src))?;
    // Kept, renamed, so nothing reads it by mistake and nothing is lost.
    std::fs::rename(&old, old.with_extension("toml.moved-to-lenstica"))?;
    eprintln!(
        "lenstica: moved your settings from {} to {}",
        paths::tilde(&old),
        paths::tilde(&new)
    );
    Ok(())
}

fn state() -> anyhow::Result<()> {
    let new = paths::state_dir();
    let Some(old) = new.parent().map(|p| p.join(OLD)) else {
        return Ok(());
    };
    if new.exists() || !old.is_dir() {
        return Ok(());
    }
    std::fs::rename(&old, &new)?;
    Ok(())
}

/// The old login item started the `cooldown` binary. Replace it with one for
/// this executable, unless this is a development build that `cargo clean`
/// would delete.
fn login_item() -> anyhow::Result<()> {
    let Some((old, kind)) = old_login_item() else {
        return Ok(());
    };
    let exe = autostart::executable()?;
    if autostart::is_build_artifact(&exe) {
        return Ok(());
    }
    remove_old_login_item(&old);
    let installed = autostart::install(kind, true)?;
    eprintln!(
        "lenstica: replaced the cooldown login item with {}",
        paths::tilde(&installed)
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn old_login_item() -> Option<(PathBuf, autostart::Kind)> {
    let path = paths::home()
        .join("Library/LaunchAgents")
        .join("dev.cooldown.agent.plist");
    let src = std::fs::read_to_string(&path).ok()?;
    Some((path, kind_of(&src)))
}

#[cfg(target_os = "macos")]
fn remove_old_login_item(path: &Path) {
    if let Ok(out) = std::process::Command::new("id").arg("-u").output() {
        let uid = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let _ = std::process::Command::new("launchctl")
            .args(["bootout", &format!("gui/{uid}/dev.cooldown.agent")])
            .output();
    }
    let _ = std::fs::remove_file(path);
}

#[cfg(all(unix, not(target_os = "macos")))]
fn old_login_item() -> Option<(PathBuf, autostart::Kind)> {
    let config = paths::config_root();
    let desktop = config.join("autostart").join(format!("{OLD}.desktop"));
    let unit = config.join("systemd/user").join(format!("{OLD}.service"));
    [desktop, unit].into_iter().find(|p| p.is_file()).map(|p| {
        let src = std::fs::read_to_string(&p).unwrap_or_default();
        (p, kind_of(&src))
    })
}

#[cfg(all(unix, not(target_os = "macos")))]
fn remove_old_login_item(path: &Path) {
    if path.extension().is_some_and(|e| e == "service") {
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "disable", "--now", &format!("{OLD}.service")])
            .output();
    }
    let _ = std::fs::remove_file(path);
}

#[cfg(windows)]
const RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";

#[cfg(windows)]
fn old_login_item() -> Option<(PathBuf, autostart::Kind)> {
    let out = std::process::Command::new("reg")
        .args(["query", RUN_KEY, "/v", OLD])
        .output()
        .ok()?;
    out.status.success().then(|| {
        (
            PathBuf::from(format!(r"{RUN_KEY}\{OLD}")),
            kind_of(&String::from_utf8_lossy(&out.stdout)),
        )
    })
}

#[cfg(windows)]
fn remove_old_login_item(_path: &Path) {
    let _ = std::process::Command::new("reg")
        .args(["delete", RUN_KEY, "/v", OLD, "/f"])
        .output();
}

fn kind_of(src: &str) -> autostart::Kind {
    if src.contains(" watch") || src.contains(">watch<") {
        autostart::Kind::Headless
    } else {
        autostart::Kind::Tray
    }
}

#[cfg(test)]
mod tests {
    use super::rewrite_settings;

    #[test]
    fn renames_lens_sections_only() {
        let src = "min_days = 7\n[checkers]\n[checkers.secrets]\nenabled = true\n# [checkers.safe-chain]\n\n[[external]]\nformat = \"cooldown\"\n# the cooldown is 7 days\n";
        assert_eq!(
            rewrite_settings(src),
            "min_days = 7\n[lenses]\n[lenses.secrets]\nenabled = true\n# [lenses.safe-chain]\n\n[[external]]\nformat = \"lenstica\"\n# the cooldown is 7 days\n"
        );
    }
}
