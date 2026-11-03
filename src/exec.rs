//! Locating and running package-manager binaries.
//!
//! A login agent (launchd, systemd, the Windows Run key) starts with a minimal
//! PATH, so the search path is the configured extra directories, then the
//! inherited PATH, then the usual install locations of each package manager.

use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use wait_timeout::ChildExt;

use crate::paths::{self, home};
use crate::version::Version;

const TIMEOUT: Duration = Duration::from_secs(30);

pub struct Output {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    /// The most useful single line to show when the command failed.
    pub fn error_text(&self) -> String {
        let line = self
            .stderr
            .lines()
            .chain(self.stdout.lines())
            .map(str::trim)
            .find(|l| !l.is_empty())
            .unwrap_or("command failed without output");
        line.chars().take(240).collect()
    }

    /// The last non-empty stdout line, which is where `config get` answers.
    pub fn last_line(&self) -> Option<&str> {
        self.stdout.lines().map(str::trim).rfind(|l| !l.is_empty())
    }
}

pub fn search_path(extra: &[PathBuf]) -> OsString {
    let mut dirs: Vec<PathBuf> = extra.to_vec();
    if let Some(path) = std::env::var_os("PATH") {
        dirs.extend(std::env::split_paths(&path));
    }
    dirs.extend(default_dirs());
    let mut seen = HashSet::new();
    dirs.retain(|d| {
        !d.as_os_str().is_empty() && std::env::join_paths([d]).is_ok() && seen.insert(d.clone())
    });
    std::env::join_paths(dirs).unwrap_or_default()
}

fn default_dirs() -> Vec<PathBuf> {
    let h = home();
    let mut dirs = Vec::new();
    if cfg!(windows) {
        dirs.push(paths::appdata().join("npm"));
        dirs.push(paths::local_appdata().join("pnpm"));
        dirs.push(paths::local_appdata().join("Microsoft").join("WindowsApps"));
        for rel in [
            ".bun/bin",
            ".cargo/bin",
            ".local/bin",
            ".deno/bin",
            "scoop/shims",
        ] {
            dirs.push(h.join(rel));
        }
    } else {
        for abs in [
            "/opt/homebrew/bin",
            "/usr/local/bin",
            "/home/linuxbrew/.linuxbrew/bin",
            "/snap/bin",
            "/usr/local/go/bin",
            "/usr/bin",
            "/bin",
        ] {
            dirs.push(PathBuf::from(abs));
        }
        for rel in [
            ".local/bin",
            ".cargo/bin",
            ".bun/bin",
            ".deno/bin",
            ".volta/bin",
            "Library/pnpm",
            ".local/share/pnpm",
            ".local/share/mise/shims",
            ".asdf/shims",
            ".pyenv/shims",
            ".pixi/bin",
            ".local/share/fnm/aliases/default/bin",
            "go/bin",
        ] {
            dirs.push(h.join(rel));
        }
        dirs.extend(nvm_bins(&h));
    }
    dirs
}

/// nvm installs each Node version under its own prefix; newest first.
fn nvm_bins(home: &Path) -> Vec<PathBuf> {
    let root = std::env::var_os("NVM_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".nvm"))
        .join("versions")
        .join("node");
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let mut versions: Vec<(Version, PathBuf)> = entries
        .flatten()
        .filter_map(|e| {
            let version = Version::parse(&e.file_name().to_string_lossy())?;
            Some((version, e.path().join("bin")))
        })
        .collect();
    versions.sort_by(|a, b| b.0.cmp(&a.0));
    versions.into_iter().map(|(_, bin)| bin).collect()
}

pub fn find(binary: &str, search: &OsStr) -> Option<PathBuf> {
    which::which_in(binary, Some(search), home()).ok()
}

/// Run `program args...` from the home directory, so no project-level config
/// leaks into what should be a user-level answer.
pub fn run(program: &Path, args: &[&str], search: &OsStr) -> Result<Output> {
    run_timeout(program, args, search, TIMEOUT)
}

pub fn run_timeout(
    program: &Path,
    args: &[&str],
    search: &OsStr,
    timeout: Duration,
) -> Result<Output> {
    let mut dirs: Vec<PathBuf> = program
        .parent()
        .map(Path::to_path_buf)
        .into_iter()
        .collect();
    dirs.extend(std::env::split_paths(search));
    let path = std::env::join_paths(dirs).unwrap_or_else(|_| search.to_os_string());

    let mut child = Command::new(program)
        .args(args)
        .current_dir(home())
        .env("PATH", path)
        .env("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0")
        .env("NO_UPDATE_NOTIFIER", "1")
        .env("npm_config_update_notifier", "false")
        .env("PIP_DISABLE_PIP_VERSION_CHECK", "1")
        .env("PIP_REQUIRE_VIRTUALENV", "0")
        .env("POETRY_NO_INTERACTION", "1")
        .env("NO_COLOR", "1")
        .env("FORCE_COLOR", "0")
        // Read-only git queries must not take index.lock in the user's repositories.
        .env("GIT_OPTIONAL_LOCKS", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to start {}", program.display()))?;

    let stdout = child.stdout.take().map(drain);
    let stderr = child.stderr.take().map(drain);
    let Some(status) = child.wait_timeout(timeout)? else {
        // Kill and leave the reader threads behind: a grandchild may still hold the pipes.
        let _ = child.kill();
        let _ = child.wait();
        bail!(
            "`{} {}` did not finish within {}s",
            program.display(),
            args.join(" "),
            timeout.as_secs()
        );
    };
    let collect = |h: Option<thread::JoinHandle<Vec<u8>>>| {
        h.and_then(|h| h.join().ok())
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_default()
    };
    Ok(Output {
        success: status.success(),
        stdout: collect(stdout),
        stderr: collect(stderr),
    })
}

fn drain<R: Read + Send + 'static>(mut pipe: R) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut buf = Vec::new();
        // A read error only truncates diagnostic output; the exit status still decides.
        let _ = pipe.read_to_end(&mut buf);
        buf
    })
}

pub fn version_of(program: &Path, search: &OsStr) -> Option<Version> {
    let out = run(program, &["--version"], search).ok()?;
    Version::parse(&out.stdout).or_else(|| Version::parse(&out.stderr))
}
