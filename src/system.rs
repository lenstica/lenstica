//! Small OS integrations: opening files, the single-instance lock.

use std::fs::{self, File, TryLockError};
use std::path::Path;
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

fn opener() -> Command {
    if cfg!(target_os = "macos") {
        Command::new("open")
    } else if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.args(["/C", "start", ""]);
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
        c.arg(format!("/select,{}", path.display()));
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

/// Held for the life of the process so only one monitor runs at a time.
pub struct InstanceLock {
    _file: File,
}

/// `Ok(None)` when another monitor already holds the lock.
pub fn acquire_lock() -> Result<Option<InstanceLock>> {
    acquire_named_lock("monitor")
}

/// `Ok(None)` when another process already holds the `name` lock.
pub fn acquire_named_lock(name: &str) -> Result<Option<InstanceLock>> {
    let dir = paths::state_dir();
    fs::create_dir_all(&dir).with_context(|| format!("cannot create {}", dir.display()))?;
    let path = dir.join(format!("{name}.lock"));
    let file = File::create(&path).with_context(|| format!("cannot open {}", path.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(Some(InstanceLock { _file: file })),
        Err(TryLockError::WouldBlock) => Ok(None),
        Err(TryLockError::Error(e)) => {
            Err(e).with_context(|| format!("cannot lock {}", path.display()))
        }
    }
}
