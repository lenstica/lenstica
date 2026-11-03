use std::path::PathBuf;

use anyhow::{Result, bail};

use super::{Ctx, Manager, Tool, unset_marker};
use crate::duration::DAY;
use crate::exec;
use crate::paths;
use crate::version::Version;

/// Poetry >= 2.4: `solver.min-release-age` in days (0, the default, disables it).
pub struct Poetry;

const KEY: &str = "solver.min-release-age";

impl Manager for Poetry {
    fn id(&self) -> &'static str {
        "poetry"
    }
    fn name(&self) -> &'static str {
        "Poetry"
    }
    fn binaries(&self) -> &'static [&'static str] {
        &["poetry"]
    }
    fn min_version(&self) -> Version {
        Version::new(2, 4, 0)
    }
    fn setting(&self) -> &'static str {
        KEY
    }
    fn bare_unit(&self) -> i64 {
        DAY
    }
    fn target(&self, days: u32) -> String {
        days.to_string()
    }
    fn location(&self, _tool: &Tool) -> PathBuf {
        if let Some(dir) = std::env::var_os("POETRY_CONFIG_DIR").filter(|d| !d.is_empty()) {
            return PathBuf::from(dir).join("config.toml");
        }
        let dir = if let Some(xdg) = paths::xdg_config_home() {
            xdg.join("pypoetry")
        } else if cfg!(target_os = "macos") {
            paths::home()
                .join("Library")
                .join("Application Support")
                .join("pypoetry")
        } else if cfg!(windows) {
            paths::appdata().join("pypoetry")
        } else {
            paths::home().join(".config").join("pypoetry")
        };
        dir.join("config.toml")
    }
    fn read(&self, tool: &Tool, ctx: &Ctx) -> Result<Option<String>> {
        let out = exec::run(&tool.bin, &["config", KEY], &ctx.search)?;
        if !out.success {
            bail!("poetry config failed: {}", out.error_text());
        }
        Ok(out
            .last_line()
            .filter(|v| !unset_marker(v))
            .map(str::to_string))
    }
    fn write(&self, tool: &Tool, value: &str, ctx: &Ctx) -> Result<()> {
        let out = exec::run(&tool.bin, &["config", KEY, value], &ctx.search)?;
        if !out.success {
            bail!("poetry config failed: {}", out.error_text());
        }
        Ok(())
    }
}
