use std::path::PathBuf;

use anyhow::Result;

use super::{Ctx, Manager, Tool, cli_get, cli_set};
use crate::duration::MINUTE;
use crate::paths;
use crate::version::Version;

/// pnpm >= 10.16: `minimumReleaseAge` in minutes. pnpm 11 moved global
/// settings from the INI `rc` file to `config.yaml` (camelCase keys), so the
/// key and file follow the installed version. Writes go through `pnpm config`.
pub struct Pnpm;

fn uses_yaml(tool: &Tool) -> bool {
    tool.version.is_none_or(|v| v >= Version::new(11, 0, 0))
}

fn key(tool: &Tool) -> &'static str {
    if uses_yaml(tool) {
        "minimumReleaseAge"
    } else {
        "minimum-release-age"
    }
}

fn config_dir() -> PathBuf {
    if let Some(xdg) = paths::xdg_config_home() {
        return xdg.join("pnpm");
    }
    if cfg!(target_os = "macos") {
        paths::home()
            .join("Library")
            .join("Preferences")
            .join("pnpm")
    } else if cfg!(windows) {
        paths::local_appdata().join("pnpm").join("config")
    } else {
        paths::home().join(".config").join("pnpm")
    }
}

impl Manager for Pnpm {
    fn id(&self) -> &'static str {
        "pnpm"
    }
    fn name(&self) -> &'static str {
        "pnpm"
    }
    fn binaries(&self) -> &'static [&'static str] {
        &["pnpm"]
    }
    fn min_version(&self) -> Version {
        Version::new(10, 16, 0)
    }
    fn setting(&self) -> &'static str {
        "minimumReleaseAge"
    }
    fn bare_unit(&self) -> i64 {
        MINUTE
    }
    fn location(&self, tool: &Tool) -> PathBuf {
        config_dir().join(if uses_yaml(tool) { "config.yaml" } else { "rc" })
    }
    fn read(&self, tool: &Tool, ctx: &Ctx) -> Result<Option<String>> {
        cli_get(tool, ctx, &["config", "get", key(tool)], None)
    }
    fn write(&self, tool: &Tool, value: &str, ctx: &Ctx) -> Result<()> {
        cli_set(tool, ctx, &["config", "set", "--global", key(tool), value])
    }
}
