use std::path::PathBuf;

use anyhow::{Result, bail};

use super::{Ctx, Manager, Tool, unset_marker};
use crate::duration::DAY;
use crate::exec;
use crate::paths;
use crate::version::Version;

/// npm >= 11.10: `min-release-age` in days, in the user `.npmrc`.
pub struct Npm;

const KEY: &str = "min-release-age";

impl Manager for Npm {
    fn id(&self) -> &'static str {
        "npm"
    }
    fn name(&self) -> &'static str {
        "npm"
    }
    fn binaries(&self) -> &'static [&'static str] {
        &["npm"]
    }
    fn min_version(&self) -> Version {
        Version::new(11, 10, 0)
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
        ["NPM_CONFIG_USERCONFIG", "npm_config_userconfig"]
            .iter()
            .find_map(|v| std::env::var_os(v).filter(|p| !p.is_empty()))
            .map(PathBuf::from)
            .unwrap_or_else(|| paths::home().join(".npmrc"))
    }
    fn read(&self, tool: &Tool, ctx: &Ctx) -> Result<Option<String>> {
        let out = exec::run(&tool.bin, &["config", "get", KEY], &ctx.search)?;
        if !out.success {
            bail!("npm config get failed: {}", out.error_text());
        }
        Ok(out
            .last_line()
            .filter(|v| !unset_marker(v))
            .map(str::to_string))
    }
    fn write(&self, tool: &Tool, value: &str, ctx: &Ctx) -> Result<()> {
        let assignment = format!("{KEY}={value}");
        let out = exec::run(
            &tool.bin,
            &["config", "set", &assignment, "--location=user"],
            &ctx.search,
        )?;
        if !out.success {
            bail!("npm config set failed: {}", out.error_text());
        }
        Ok(())
    }
}
