//! Platform directory resolution. Everything is derived from environment
//! variables (`HOME`, `XDG_*`, `APPDATA`, ...) so a sandboxed `HOME` redirects
//! every read and write, which is how the end-to-end tests run.

use std::env;
use std::path::{MAIN_SEPARATOR, Path, PathBuf};

fn env_dir(var: &str) -> Option<PathBuf> {
    env::var_os(var)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

pub fn home() -> PathBuf {
    let primary = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    env_dir(primary)
        .or_else(|| env_dir("HOME"))
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn xdg_config_home() -> Option<PathBuf> {
    env_dir("XDG_CONFIG_HOME")
}

/// `$XDG_CONFIG_HOME`, or `~/.config` on every OS.
pub fn config_root() -> PathBuf {
    xdg_config_home().unwrap_or_else(|| home().join(".config"))
}

pub fn state_dir() -> PathBuf {
    env_dir("XDG_STATE_HOME")
        .unwrap_or_else(|| home().join(".local").join("state"))
        .join("lenstica")
}

pub fn appdata() -> PathBuf {
    env_dir("APPDATA").unwrap_or_else(|| home().join("AppData").join("Roaming"))
}

pub fn local_appdata() -> PathBuf {
    env_dir("LOCALAPPDATA").unwrap_or_else(|| home().join("AppData").join("Local"))
}

/// Render a path with the home directory abbreviated to `~`.
pub fn tilde(path: &Path) -> String {
    match path.strip_prefix(home()) {
        Ok(rest) if rest.as_os_str().is_empty() => "~".to_string(),
        Ok(rest) => format!("~{MAIN_SEPARATOR}{}", rest.display()),
        Err(_) => path.display().to_string(),
    }
}

/// Expand a leading `~` to the home directory.
pub fn expand(raw: &str) -> PathBuf {
    if raw == "~" {
        return home();
    }
    match raw.strip_prefix("~/").or_else(|| raw.strip_prefix("~\\")) {
        Some(rest) => home().join(rest),
        None => PathBuf::from(raw),
    }
}
