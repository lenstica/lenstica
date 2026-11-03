use std::path::PathBuf;

use anyhow::{Context, Result};
use toml_edit::Value;

use super::{Ctx, Manager, Tool, toml_file_get, toml_file_set};
use crate::paths;
use crate::version::Version;

/// Bun >= 1.3: `[install] minimumReleaseAge` in seconds, in the global
/// bunfig. Bun reads exactly one: `$XDG_CONFIG_HOME/.bunfig.toml` when that
/// variable is set, else `~/.bunfig.toml`.
pub struct Bun;

pub(crate) const KEYS: [&str; 2] = ["install", "minimumReleaseAge"];

fn global_bunfig() -> PathBuf {
    paths::xdg_config_home()
        .unwrap_or_else(paths::home)
        .join(".bunfig.toml")
}

impl Manager for Bun {
    fn id(&self) -> &'static str {
        "bun"
    }
    fn name(&self) -> &'static str {
        "Bun"
    }
    fn binaries(&self) -> &'static [&'static str] {
        &["bun"]
    }
    fn min_version(&self) -> Version {
        Version::new(1, 3, 0)
    }
    fn setting(&self) -> &'static str {
        "install.minimumReleaseAge"
    }
    fn bare_unit(&self) -> i64 {
        1
    }
    fn location(&self, _tool: &Tool) -> PathBuf {
        global_bunfig()
    }
    fn read(&self, _tool: &Tool, _ctx: &Ctx) -> Result<Option<String>> {
        toml_file_get(&global_bunfig(), &KEYS)
    }
    fn write(&self, _tool: &Tool, value: &str, _ctx: &Ctx) -> Result<()> {
        let seconds: i64 = value
            .parse()
            .context("bun cooldown must be whole seconds")?;
        toml_file_set(&global_bunfig(), &KEYS, Value::from(seconds))
    }
}
