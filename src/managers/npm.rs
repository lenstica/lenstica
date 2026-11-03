use std::path::PathBuf;

use anyhow::Result;

use super::{Ctx, Manager, Tool, cli_get, cli_set};
use crate::duration::DAY;
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
    fn location(&self, _tool: &Tool) -> PathBuf {
        ["NPM_CONFIG_USERCONFIG", "npm_config_userconfig"]
            .iter()
            .find_map(|v| std::env::var_os(v).filter(|p| !p.is_empty()))
            .map_or_else(|| paths::home().join(".npmrc"), PathBuf::from)
    }
    fn read(&self, tool: &Tool, ctx: &Ctx) -> Result<Option<String>> {
        cli_get(tool, ctx, &["config", "get", KEY], None)
    }
    fn write(&self, tool: &Tool, value: &str, ctx: &Ctx) -> Result<()> {
        let assignment = format!("{KEY}={value}");
        cli_set(
            tool,
            ctx,
            &["config", "set", &assignment, "--location=user"],
        )
    }
}
