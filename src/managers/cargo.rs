use std::path::PathBuf;

use anyhow::{Context, Result};
use toml_edit::Value;

use super::{Ctx, Manager, Tool};
use crate::duration::DAY;
use crate::files;
use crate::paths;
use crate::version::Version;

/// Cargo >= 1.100: `[registry] global-min-publish-age = "7 days"` in
/// `$CARGO_HOME/config.toml`. A `[registries.crates-io] min-publish-age`
/// overrides it for crates.io, so that one is read first and kept in step.
pub struct Cargo;

const GLOBAL: [&str; 2] = ["registry", "global-min-publish-age"];
const CRATES_IO: [&str; 3] = ["registries", "crates-io", "min-publish-age"];

fn cargo_home() -> PathBuf {
    std::env::var_os("CARGO_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| paths::home().join(".cargo"))
}

/// `config.toml`, or the extension-less `config` older setups still use.
fn config_file() -> PathBuf {
    let home = cargo_home();
    let legacy = home.join("config");
    let current = home.join("config.toml");
    if !current.exists() && legacy.is_file() {
        legacy
    } else {
        current
    }
}

impl Manager for Cargo {
    fn id(&self) -> &'static str {
        "cargo"
    }
    fn name(&self) -> &'static str {
        "Cargo"
    }
    fn binaries(&self) -> &'static [&'static str] {
        &["cargo"]
    }
    fn min_version(&self) -> Version {
        Version::new(1, 100, 0)
    }
    fn setting(&self) -> &'static str {
        "registry.global-min-publish-age"
    }
    fn bare_unit(&self) -> i64 {
        DAY
    }
    fn target(&self, days: u32) -> String {
        format!("{days} {}", if days == 1 { "day" } else { "days" })
    }
    fn location(&self, _tool: &Tool) -> PathBuf {
        config_file()
    }
    fn read(&self, _tool: &Tool, _ctx: &Ctx) -> Result<Option<String>> {
        let path = config_file();
        let Some(src) = files::read_optional(&path)? else {
            return Ok(None);
        };
        let at =
            |keys: &[&str]| files::toml_get(&src, keys).with_context(|| path.display().to_string());
        Ok(match at(&CRATES_IO)? {
            Some(v) => Some(v),
            None => at(&GLOBAL)?,
        })
    }
    fn write(&self, _tool: &Tool, value: &str, _ctx: &Ctx) -> Result<()> {
        let path = config_file();
        let src = files::read_optional(&path)?.unwrap_or_default();
        let mut updated = files::toml_set(&src, &GLOBAL, Value::from(value))
            .with_context(|| path.display().to_string())?;
        if files::toml_get(&updated, &CRATES_IO)?.is_some() {
            updated = files::toml_set(&updated, &CRATES_IO, Value::from(value))?;
        }
        files::write_atomic(&path, &updated)
    }
}
