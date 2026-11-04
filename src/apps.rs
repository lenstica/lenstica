//! The apps Lenstica opens things with: a text editor for a file, a file
//! manager to show it, a terminal in its folder. Each is `system` (the
//! platform's own) or one picked in Settings → General and kept in `[apps]`;
//! the window lists the ones installed. Only names are looked up and run.
// Without the window, only the editor is used (`lenstica config edit`).
#![cfg_attr(not(feature = "tray"), allow(dead_code))]

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Result;
use serde::Serialize;

use crate::config::Config;
use crate::system;

/// What a button does with a path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Open a file in the text editor (a folder too, when one is picked).
    Editor,
    /// Show it in the file manager, selected where the manager can.
    Files,
    /// Open a terminal in its folder.
    Terminal,
}

impl Role {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "editor" => Some(Role::Editor),
            "files" => Some(Role::Files),
            "terminal" => Some(Role::Terminal),
            _ => None,
        }
    }
}

/// Editors, terminals and file managers Lenstica knows how to open, as named
/// on this platform: app names on macOS, commands elsewhere.
#[cfg(target_os = "macos")]
mod known {
    pub const EDITORS: &[&str] = &[
        "Visual Studio Code",
        "Cursor",
        "Windsurf",
        "VSCodium",
        "Zed",
        "Sublime Text",
        "Nova",
        "BBEdit",
        "CotEditor",
        "TextMate",
        "Xcode",
        "IntelliJ IDEA",
        "IntelliJ IDEA CE",
        "WebStorm",
        "PyCharm",
        "PyCharm CE",
        "RustRover",
        "GoLand",
        "TextEdit",
    ];
    pub const TERMINALS: &[&str] = &[
        "Terminal",
        "iTerm",
        "Ghostty",
        "Warp",
        "WezTerm",
        "Alacritty",
        "kitty",
        "Hyper",
        "Tabby",
    ];
    pub const FILES: &[&str] = &[
        "Finder",
        "Path Finder",
        "ForkLift",
        "Commander One",
        "Marta",
        "Nimble Commander",
        "QSpace Pro",
    ];
}

#[cfg(all(unix, not(target_os = "macos")))]
mod known {
    pub const EDITORS: &[&str] = &[
        "code",
        "cursor",
        "windsurf",
        "codium",
        "zed",
        "zeditor",
        "subl",
        "gnome-text-editor",
        "gedit",
        "kate",
        "mousepad",
        "xed",
    ];
    pub const TERMINALS: &[&str] = &[
        "gnome-terminal",
        "konsole",
        "kitty",
        "alacritty",
        "wezterm",
        "foot",
        "ghostty",
        "xfce4-terminal",
        "tilix",
        "terminator",
        "xterm",
    ];
    pub const FILES: &[&str] = &["nautilus", "dolphin", "thunar", "nemo", "pcmanfm", "caja"];
}

#[cfg(windows)]
mod known {
    pub const EDITORS: &[&str] = &[];
    pub const TERMINALS: &[&str] = &["wt"];
    pub const FILES: &[&str] = &[];
}

/// The ones installed here, for Settings to offer.
#[derive(Debug, Serialize)]
pub struct Installed {
    pub editors: Vec<&'static str>,
    pub terminals: Vec<&'static str>,
    pub files: Vec<&'static str>,
}

pub fn installed() -> Installed {
    let found = |names: &[&'static str]| {
        names
            .iter()
            .copied()
            .filter(|n| locate(n).is_some())
            .collect()
    };
    Installed {
        editors: found(known::EDITORS),
        terminals: found(known::TERMINALS),
        files: found(known::FILES),
    }
}

/// Where an app is: its bundle on macOS, its program on the `PATH` elsewhere.
fn locate(name: &str) -> Option<PathBuf> {
    if cfg!(target_os = "macos") {
        let home = crate::paths::home();
        [
            PathBuf::from("/Applications"),
            home.join("Applications"),
            PathBuf::from("/Applications/Utilities"),
            PathBuf::from("/System/Applications"),
            PathBuf::from("/System/Applications/Utilities"),
            PathBuf::from("/System/Library/CoreServices"),
        ]
        .into_iter()
        .map(|dir| dir.join(format!("{name}.app")))
        .find(|p| p.is_dir())
    } else {
        let exe = if cfg!(windows) {
            format!("{name}.exe")
        } else {
            name.to_string()
        };
        std::env::split_paths(&std::env::var_os("PATH")?)
            .map(|dir| dir.join(&exe))
            .find(|p| p.is_file())
    }
}

/// The folder a path is in, or the path when it is a folder.
fn folder_of(path: &Path) -> PathBuf {
    if path.is_dir() {
        path.to_path_buf()
    } else {
        path.parent().unwrap_or(path).to_path_buf()
    }
}

/// Open `path` the way `role` says, with the app picked for it.
pub fn open(role: Role, path: &Path) -> Result<()> {
    // A settings file that does not read leaves the system's own.
    let apps = Config::load().map(|c| c.apps).unwrap_or_default();
    let picked = |s: &str| {
        let s = s.trim();
        (!s.is_empty() && s != "system").then(|| s.to_string())
    };
    let what = path.display().to_string();
    match role {
        Role::Editor => editor(path, picked(&apps.editor).as_deref(), &what),
        Role::Files => files(path, picked(&apps.files).as_deref(), &what),
        Role::Terminal => terminal(&folder_of(path), picked(&apps.terminal).as_deref(), &what),
    }
}

fn editor(path: &Path, app: Option<&str>, what: &str) -> Result<()> {
    match app {
        // The system's text editor can't open a folder: show that instead.
        None => system::open_any(path),
        Some(app) => {
            let mut cmd = if cfg!(target_os = "macos") {
                let mut c = Command::new("open");
                c.arg("-a").arg(app);
                c
            } else {
                Command::new(app)
            };
            cmd.arg(path);
            system::spawn(cmd, what)
        }
    }
}

fn files(path: &Path, app: Option<&str>, what: &str) -> Result<()> {
    match app {
        None | Some("Finder") | Some("explorer") => system::reveal(path),
        Some(app) if cfg!(target_os = "macos") => {
            let mut cmd = Command::new("open");
            cmd.arg("-a").arg(app).arg(folder_of(path));
            system::spawn(cmd, what)
        }
        Some(app) => {
            let mut cmd = Command::new(app);
            // These select the file in its folder; the rest open the folder.
            if path.is_file() && ["nautilus", "dolphin", "nemo"].contains(&app) {
                cmd.arg("--select").arg(path);
            } else {
                cmd.arg(folder_of(path));
            }
            system::spawn(cmd, what)
        }
    }
}

fn terminal(dir: &Path, app: Option<&str>, what: &str) -> Result<()> {
    if cfg!(target_os = "macos") {
        let app = app.unwrap_or("Terminal");
        let mut cmd = Command::new("open");
        // Most open a folder given to them in a new window there; these take a flag.
        match app {
            "WezTerm" => cmd.args(["-na", app, "--args", "start", "--cwd"]).arg(dir),
            "Alacritty" => cmd
                .args(["-na", app, "--args", "--working-directory"])
                .arg(dir),
            "kitty" => cmd.args(["-na", app, "--args", "--directory"]).arg(dir),
            _ => cmd.arg("-a").arg(app).arg(dir),
        };
        return system::spawn(cmd, what);
    }
    if cfg!(windows) {
        return windows_terminal(dir, app, what);
    }
    let app = match app {
        Some(app) => app.to_string(),
        None => std::env::var("TERMINAL")
            .ok()
            .filter(|t| !t.trim().is_empty())
            .or_else(|| {
                std::iter::once("x-terminal-emulator")
                    .chain(known::TERMINALS.iter().copied())
                    .find(|t| locate(t).is_some())
                    .map(String::from)
            })
            .ok_or_else(|| anyhow::anyhow!("no terminal found: pick one in Settings → General"))?,
    };
    let mut cmd = Command::new(&app);
    cmd.current_dir(dir);
    let flag = |f: &str| format!("{f}={}", dir.display());
    match app.as_str() {
        "gnome-terminal" | "xfce4-terminal" | "tilix" | "terminator" | "foot" | "ghostty" => {
            cmd.arg(flag("--working-directory"));
        }
        "konsole" => {
            cmd.arg("--workdir").arg(dir);
        }
        "kitty" => {
            cmd.arg("--directory").arg(dir);
        }
        "alacritty" => {
            cmd.arg("--working-directory").arg(dir);
        }
        "wezterm" => {
            cmd.args(["start", "--cwd"]).arg(dir);
        }
        // xterm and the rest start where they are run.
        _ => {}
    }
    system::spawn(cmd, what)
}

/// Windows Terminal in the folder, or a new console window there. The folder
/// is the working directory, never part of a command line a shell parses.
#[cfg(windows)]
fn windows_terminal(dir: &Path, app: Option<&str>, what: &str) -> Result<()> {
    use std::os::windows::process::CommandExt;
    const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
    let wt = app.map_or_else(|| locate("wt").is_some(), |a| a == "wt");
    let mut cmd = if wt {
        let mut c = Command::new("wt");
        c.arg("-d").arg(dir);
        c
    } else {
        let mut c = Command::new(app.unwrap_or("cmd.exe"));
        c.creation_flags(CREATE_NEW_CONSOLE);
        c
    };
    cmd.current_dir(dir);
    system::spawn(cmd, what)
}

#[cfg(not(windows))]
fn windows_terminal(_: &Path, _: Option<&str>, _: &str) -> Result<()> {
    unreachable!("only called on Windows")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_are_named_as_the_window_sends_them() {
        assert_eq!(Role::parse("editor"), Some(Role::Editor));
        assert_eq!(Role::parse("files"), Some(Role::Files));
        assert_eq!(Role::parse("terminal"), Some(Role::Terminal));
        assert_eq!(Role::parse("shell"), None);
    }

    #[test]
    fn a_file_opens_a_terminal_in_its_folder() {
        let dir = std::env::temp_dir();
        assert_eq!(folder_of(&dir), dir);
        let file = dir.join("lenstica-apps-test-missing.toml");
        assert_eq!(folder_of(&file), dir);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn finder_and_terminal_are_always_there_on_macos() {
        let found = installed();
        assert!(found.files.contains(&"Finder"));
        assert!(found.terminals.contains(&"Terminal"));
    }
}
