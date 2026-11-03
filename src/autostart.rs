//! Start the monitor at login: a launchd agent on macOS, an XDG autostart
//! entry (menu bar) or systemd user unit (headless) on Linux, and the Run key
//! on Windows.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

#[cfg(not(windows))]
use crate::files;
#[cfg(not(windows))]
use crate::paths;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// The menu bar / tray app.
    Tray,
    /// `lenstica watch`, notifications only.
    Headless,
}

impl Kind {
    fn subcommand(self) -> &'static str {
        match self {
            Kind::Tray => "tray",
            Kind::Headless => "watch",
        }
    }
}

pub fn executable() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("cannot find the Lenstica executable")?;
    Ok(exe.canonicalize().unwrap_or(exe))
}

/// True when the executable lives in a cargo build directory that a
/// `cargo clean` would delete out from under the login item.
pub fn is_build_artifact(exe: &Path) -> bool {
    let s = exe.to_string_lossy();
    [
        "/target/debug/",
        "/target/release/",
        "\\target\\debug\\",
        "\\target\\release\\",
    ]
    .iter()
    .any(|p| s.contains(p))
}

fn run_checked(cmd: &mut Command) -> Result<()> {
    let out = cmd
        .output()
        .with_context(|| format!("cannot run {cmd:?}"))?;
    if !out.status.success() {
        bail!(
            "{:?} failed: {}",
            cmd,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

// ---- macOS ------------------------------------------------------------------

#[cfg(target_os = "macos")]
const LABEL: &str = "com.lenstica.agent";

#[cfg(target_os = "macos")]
fn plist_path() -> PathBuf {
    paths::home()
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{LABEL}.plist"))
}

#[cfg(target_os = "macos")]
fn gui_domain() -> Result<String> {
    let out = Command::new("id")
        .arg("-u")
        .output()
        .context("cannot run id -u")?;
    Ok(format!(
        "gui/{}",
        String::from_utf8_lossy(&out.stdout).trim()
    ))
}

#[cfg(target_os = "macos")]
fn xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(target_os = "macos")]
pub fn install(kind: Kind, start_now: bool) -> Result<PathBuf> {
    let exe = executable()?;
    let log = paths::home()
        .join("Library")
        .join("Logs")
        .join("lenstica.log");
    let path_env = std::env::var("PATH").unwrap_or_default();
    let session = if kind == Kind::Tray {
        "\n  <key>LimitLoadToSessionType</key>\n  <string>Aqua</string>"
    } else {
        ""
    };
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{exe}</string>
    <string>{sub}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
  <key>ProcessType</key>
  <string>Interactive</string>{session}
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key>
    <string>{path}</string>
  </dict>
  <key>StandardOutPath</key>
  <string>{log}</string>
  <key>StandardErrorPath</key>
  <string>{log}</string>
</dict>
</plist>
"#,
        label = LABEL,
        exe = xml(&exe.to_string_lossy()),
        sub = kind.subcommand(),
        path = xml(&path_env),
        log = xml(&log.to_string_lossy()),
    );
    let path = plist_path();
    files::write_state(&path, &plist)?;
    if start_now {
        let domain = gui_domain()?;
        // Not loaded yet is the normal case for a first install.
        let _ = Command::new("launchctl")
            .args(["bootout", &format!("{domain}/{LABEL}")])
            .output();
        run_checked(
            Command::new("launchctl")
                .args(["bootstrap", &domain])
                .arg(&path),
        )?;
    }
    Ok(path)
}

#[cfg(target_os = "macos")]
pub fn uninstall() -> Result<Vec<PathBuf>> {
    let path = plist_path();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let domain = gui_domain()?;
    // bootout also stops the running agent; it fails harmlessly when it is not loaded.
    let _ = Command::new("launchctl")
        .args(["bootout", &format!("{domain}/{LABEL}")])
        .output();
    std::fs::remove_file(&path).with_context(|| format!("cannot remove {}", path.display()))?;
    Ok(vec![path])
}

#[cfg(target_os = "macos")]
pub fn installed() -> Option<PathBuf> {
    Some(plist_path()).filter(|p| p.exists())
}

// ---- Linux and other Unix ---------------------------------------------------

#[cfg(all(unix, not(target_os = "macos")))]
fn desktop_path() -> PathBuf {
    paths::config_root()
        .join("autostart")
        .join("lenstica.desktop")
}

#[cfg(all(unix, not(target_os = "macos")))]
fn unit_path() -> PathBuf {
    paths::config_root()
        .join("systemd")
        .join("user")
        .join("lenstica.service")
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn install(kind: Kind, start_now: bool) -> Result<PathBuf> {
    let exe = executable()?;
    let exe_str = exe.to_string_lossy();
    match kind {
        Kind::Tray => {
            let path = desktop_path();
            let entry = format!(
                "[Desktop Entry]\nType=Application\nName=Lenstica\nComment=Lenstica security monitor\nExec=\"{exe_str}\" {sub}\nNoDisplay=true\nX-GNOME-Autostart-enabled=true\n",
                sub = kind.subcommand()
            );
            files::write_state(&path, &entry)?;
            if start_now {
                Command::new(&exe)
                    .arg("tray")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .context("cannot start lenstica tray")?;
            }
            Ok(path)
        }
        Kind::Headless => {
            let path = unit_path();
            let path_env = std::env::var("PATH").unwrap_or_default();
            let unit = format!(
                "[Unit]\nDescription=Lenstica security monitor\n\n[Service]\nExecStart=\"{exe_str}\" {sub}\nEnvironment=\"PATH={path_env}\"\nRestart=on-failure\n\n[Install]\nWantedBy=default.target\n",
                sub = kind.subcommand()
            );
            files::write_state(&path, &unit)?;
            run_checked(Command::new("systemctl").args(["--user", "daemon-reload"]))?;
            let mut enable = Command::new("systemctl");
            enable.args(["--user", "enable"]);
            if start_now {
                enable.arg("--now");
            }
            run_checked(enable.arg("lenstica.service"))?;
            Ok(path)
        }
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn uninstall() -> Result<Vec<PathBuf>> {
    let mut removed = Vec::new();
    let unit = unit_path();
    if unit.exists() {
        let _ = Command::new("systemctl")
            .args(["--user", "disable", "--now", "lenstica.service"])
            .output();
        std::fs::remove_file(&unit).with_context(|| format!("cannot remove {}", unit.display()))?;
        let _ = Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .output();
        removed.push(unit);
    }
    let desktop = desktop_path();
    if desktop.exists() {
        std::fs::remove_file(&desktop)
            .with_context(|| format!("cannot remove {}", desktop.display()))?;
        removed.push(desktop);
    }
    Ok(removed)
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn installed() -> Option<PathBuf> {
    [unit_path(), desktop_path()]
        .into_iter()
        .find(|p| p.exists())
}

// ---- Windows ----------------------------------------------------------------

#[cfg(windows)]
const RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";

#[cfg(windows)]
pub fn install(kind: Kind, start_now: bool) -> Result<PathBuf> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let exe = executable()?;
    let command = format!("\"{}\" {}", exe.display(), kind.subcommand());
    run_checked(Command::new("reg").args([
        "add", RUN_KEY, "/v", "Lenstica", "/t", "REG_SZ", "/d", &command, "/f",
    ]))?;
    if start_now {
        Command::new(&exe)
            .arg(kind.subcommand())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .context("cannot start Lenstica")?;
    }
    Ok(PathBuf::from(format!(r"{RUN_KEY}\Lenstica")))
}

#[cfg(windows)]
pub fn uninstall() -> Result<Vec<PathBuf>> {
    if installed().is_none() {
        return Ok(Vec::new());
    }
    run_checked(Command::new("reg").args(["delete", RUN_KEY, "/v", "Lenstica", "/f"]))?;
    Ok(vec![PathBuf::from(format!(r"{RUN_KEY}\Lenstica"))])
}

#[cfg(windows)]
pub fn installed() -> Option<PathBuf> {
    let ok = Command::new("reg")
        .args(["query", RUN_KEY, "/v", "Lenstica"])
        .output()
        .is_ok_and(|o| o.status.success());
    ok.then(|| PathBuf::from(format!(r"{RUN_KEY}\Lenstica")))
}
