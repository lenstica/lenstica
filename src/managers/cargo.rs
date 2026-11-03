use std::path::PathBuf;

use anyhow::{Context, Result};
use toml_edit::Value;

use super::{Ctx, Manager, Tool, days_text, toml_file_get};
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
        .map_or_else(|| paths::home().join(".cargo"), PathBuf::from)
}

/// `config.toml`, or the extension-less `config` older setups still use:
/// when both exist, Cargo reads `config`, so that is the one to change.
fn config_file() -> PathBuf {
    let home = cargo_home();
    let legacy = home.join("config");
    if legacy.is_file() {
        legacy
    } else {
        home.join("config.toml")
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
        days_text(days)
    }
    /// A duration such as `7 days`.
    fn accepts(&self, _raw: &str) -> bool {
        true
    }
    fn location(&self, _tool: &Tool) -> PathBuf {
        config_file()
    }
    fn read(&self, _tool: &Tool, _ctx: &Ctx) -> Result<Option<String>> {
        let path = config_file();
        if let Some(v) = toml_file_get(&path, &CRATES_IO)? {
            return Ok(Some(v));
        }
        toml_file_get(&path, &GLOBAL)
    }
    fn write(&self, _tool: &Tool, value: &str, _ctx: &Ctx) -> Result<()> {
        let path = config_file();
        let src = files::read_optional(&path)?.unwrap_or_default();
        let context = || path.display().to_string();
        let mut updated =
            files::toml_set(&src, &GLOBAL, Value::from(value)).with_context(context)?;
        if files::toml_get(&updated, &CRATES_IO)
            .with_context(context)?
            .is_some()
        {
            updated =
                files::toml_set(&updated, &CRATES_IO, Value::from(value)).with_context(context)?;
        }
        files::write_atomic(&path, &updated)
    }
}
