use std::path::PathBuf;

use anyhow::{Result, bail};

use super::{Ctx, Manager, Tool, unset_marker};
use crate::duration::DAY;
use crate::exec;
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
    fn location(&self, _tool: &Tool) -> PathBuf {
        if cfg!(windows) {
            paths::appdata().join("pip").join("pip.ini")
        } else {
            paths::config_root().join("pip").join("pip.conf")
        }
    }
    fn read(&self, tool: &Tool, ctx: &Ctx) -> Result<Option<String>> {
        let out = exec::run(&tool.bin, &["config", "get", KEY], &ctx.search)?;
        if !out.success {
            if out.stderr.contains("No such key") {
                return Ok(None);
            }
            bail!("pip config get failed: {}", out.error_text());
        }
        Ok(out
            .last_line()
            .filter(|v| !unset_marker(v))
            .map(str::to_string))
    }
    fn write(&self, tool: &Tool, value: &str, ctx: &Ctx) -> Result<()> {
        let out = exec::run(
            &tool.bin,
            &["config", "--user", "set", KEY, value],
            &ctx.search,
        )?;
        if !out.success {
            bail!("pip config set failed: {}", out.error_text());
        }
        Ok(())
    }
}
