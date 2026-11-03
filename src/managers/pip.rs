use std::path::PathBuf;

use anyhow::Result;

use super::{Ctx, Manager, Tool, cli_get, cli_set};
use crate::duration::DAY;
use crate::paths;
use crate::version::Version;

/// pip >= 26.1: `[install] uploaded-prior-to = P7D` (26.0 took absolute
/// timestamps only). Goes through `pip config --user`, which picks the right
/// file for the platform; every Python's pip shares that user file.
pub struct Pip;

const KEY: &str = "install.uploaded-prior-to";

impl Manager for Pip {
    fn id(&self) -> &'static str {
        "pip"
    }
    fn name(&self) -> &'static str {
        "pip"
    }
    fn binaries(&self) -> &'static [&'static str] {
        &["pip3", "pip"]
    }
    fn min_version(&self) -> Version {
        Version::new(26, 1, 0)
    }
    fn setting(&self) -> &'static str {
        KEY
    }
    fn bare_unit(&self) -> i64 {
        DAY
    }
    fn target(&self, days: u32) -> String {
        format!("P{days}D")
    }
    /// `P<n>D` or an absolute date and time, nothing else.
    fn accepts(&self, raw: &str) -> bool {
        let v = crate::duration::unquote(raw);
        v.strip_prefix('P')
            .and_then(|d| d.strip_suffix('D'))
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
            || crate::duration::is_timestamp(v)
    }
    /// pip's user config: `%APPDATA%\pip\pip.ini`; on macOS
    /// `~/Library/Application Support/pip/pip.conf` when that folder exists,
    /// else `~/.config/pip/pip.conf` (pip ignores `XDG_CONFIG_HOME` there).
    fn location(&self, _tool: &Tool) -> PathBuf {
        if cfg!(windows) {
            paths::appdata().join("pip").join("pip.ini")
        } else if cfg!(target_os = "macos") {
            let library = paths::home()
                .join("Library")
                .join("Application Support")
                .join("pip");
            if library.is_dir() {
                library.join("pip.conf")
            } else {
                paths::home().join(".config").join("pip").join("pip.conf")
            }
        } else {
            paths::config_root().join("pip").join("pip.conf")
        }
    }
    fn read(&self, tool: &Tool, ctx: &Ctx) -> Result<Option<String>> {
        cli_get(tool, ctx, &["config", "get", KEY], Some("No such key"))
    }
    fn write(&self, tool: &Tool, value: &str, ctx: &Ctx) -> Result<()> {
        cli_set(tool, ctx, &["config", "--user", "set", KEY, value])
    }
}
