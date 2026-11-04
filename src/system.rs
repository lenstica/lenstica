//! Small OS integrations: opening files, the single-instance lock.

use std::fs::{self, File, TryLockError};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result};

use crate::paths;

fn spawn(mut cmd: Command, what: &str) -> Result<()> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("cannot open {what}"))?;
    std::thread::spawn(move || child.wait());
    Ok(())
}

/// The platform's "open with the default handler". On Windows this is
/// ShellExecute through `rundll32`, never `cmd /C start`: cmd would treat `&`,
/// `|` and `^` in a link as commands.
fn opener() -> Command {
    if cfg!(target_os = "macos") {
        Command::new("open")
    } else if cfg!(windows) {
        let mut c = Command::new("rundll32");
        c.arg("url.dll,FileProtocolHandler");
        c
    } else {
        Command::new("xdg-open")
    }
}

#[cfg_attr(not(feature = "tray"), allow(dead_code))]
/// Open a folder in the file manager, or a file with its default handler.
pub fn open_any(path: &Path) -> Result<()> {
    if path.is_dir() {
        let mut cmd = opener();
        cmd.arg(path);
        return spawn(cmd, &path.display().to_string());
    }
    open(path)
}

#[cfg_attr(not(feature = "tray"), allow(dead_code))]
/// Show a file selected in the file manager.
pub fn reveal(path: &Path) -> Result<()> {
    let mut cmd = if cfg!(target_os = "macos") {
        let mut c = Command::new("open");
        c.arg("-R").arg(path);
        c
    } else if cfg!(windows) {
        let mut c = Command::new("explorer");
        select_arg(&mut c, path);
        c
    } else {
        let mut c = Command::new("xdg-open");
        c.arg(path.parent().unwrap_or(path));
        c
    };
    cmd.stdin(Stdio::null());
    spawn(cmd, &path.display().to_string())
}

#[cfg_attr(not(feature = "tray"), allow(dead_code))]
/// Open an http(s) link in the browser. Other schemes are refused.
pub fn open_url(url: &str) -> Result<()> {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        anyhow::bail!("refusing to open a non-web link: {url}");
    }
    let mut cmd = opener();
    cmd.arg(url);
    spawn(cmd, url)
}

/// A pane of System Settings (macOS): one of Privacy & Security's
/// (`Privacy_AllFiles`, `Privacy_Camera`…), or `LoginItems` for Login Items
/// & Extensions. Only names from the assets' permission table come here.
#[cfg_attr(not(feature = "tray"), allow(dead_code))]
pub fn open_settings_pane(pane: &str) -> Result<()> {
    if !cfg!(target_os = "macos") {
        anyhow::bail!("System Settings is on macOS");
    }
    if !pane.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        anyhow::bail!("not a settings pane: {pane}");
    }
    let url = if pane == "LoginItems" {
        "x-apple.systempreferences:com.apple.LoginItems-Settings.extension".to_string()
    } else {
        format!("x-apple.systempreferences:com.apple.preference.security?{pane}")
    };
    let mut cmd = Command::new("open");
    cmd.arg(&url);
    spawn(cmd, "System Settings")
}

/// Open a file with the platform's default handler (a text editor on macOS).
pub fn open(path: &Path) -> Result<()> {
    let mut cmd = if cfg!(target_os = "macos") {
        let mut c = Command::new("open");
        c.arg("-t");
        c
    } else {
        opener()
    };
    cmd.arg(path);
    spawn(cmd, &path.display().to_string())
}

/// `/select,"<path>"`, quoted the way Explorer parses it (not the way Rust
/// quotes a whole argument).
#[cfg(windows)]
fn select_arg(cmd: &mut Command, path: &Path) {
    use std::os::windows::process::CommandExt;
    cmd.raw_arg(format!("/select,\"{}\"", path.display()));
}

#[cfg(not(windows))]
fn select_arg(cmd: &mut Command, path: &Path) {
    cmd.arg(format!("/select,{}", path.display()));
}

/// Held for the life of the process so only one monitor runs at a time.
pub struct InstanceLock {
    _file: File,
}

/// `Ok(None)` when another monitor already holds the lock.
pub fn acquire_lock() -> Result<Option<InstanceLock>> {
    acquire_named_lock("monitor")
}

fn lock_file(name: &str) -> Result<(File, PathBuf)> {
    let dir = paths::state_dir();
    fs::create_dir_all(&dir).with_context(|| format!("cannot create {}", dir.display()))?;
    let path = dir.join(format!("{name}.lock"));
    let file = File::create(&path).with_context(|| format!("cannot open {}", path.display()))?;
    Ok((file, path))
}

/// Wait for the `name` lock and hold it until the returned guard drops.
pub fn wait_named_lock(name: &str) -> Result<InstanceLock> {
    let (file, path) = lock_file(name)?;
    file.lock()
        .with_context(|| format!("cannot lock {}", path.display()))?;
    Ok(InstanceLock { _file: file })
}

/// `Ok(None)` when another process already holds the `name` lock.
pub fn acquire_named_lock(name: &str) -> Result<Option<InstanceLock>> {
    let (file, path) = lock_file(name)?;
    match file.try_lock() {
        Ok(()) => Ok(Some(InstanceLock { _file: file })),
        Err(TryLockError::WouldBlock) => Ok(None),
        Err(TryLockError::Error(e)) => {
            Err(e).with_context(|| format!("cannot lock {}", path.display()))
        }
    }
}
