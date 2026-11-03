use std::path::PathBuf;

use anyhow::Result;
use toml_edit::Value;

use super::{Ctx, Manager, Tool, days_text, toml_file_get, toml_file_set};
use crate::duration::DAY;
use crate::paths;
use crate::version::Version;

/// uv >= 0.9.17: `exclude-newer = "7 days"` in the user `uv.toml`.
pub struct Uv;

const KEYS: [&str; 1] = ["exclude-newer"];

fn user_config() -> PathBuf {
    if cfg!(windows) {
        paths::appdata().join("uv").join("uv.toml")
    } else {
        paths::config_root().join("uv").join("uv.toml")
    }
}

impl Manager for Uv {
    fn id(&self) -> &'static str {
        "uv"
    }
    fn name(&self) -> &'static str {
        "uv"
    }
    fn binaries(&self) -> &'static [&'static str] {
        &["uv"]
    }
    fn min_version(&self) -> Version {
        Version::new(0, 9, 17)
    }
    fn setting(&self) -> &'static str {
        "exclude-newer"
    }
    fn bare_unit(&self) -> i64 {
        DAY
    }
    fn target(&self, days: u32) -> String {
        days_text(days)
    }
    /// A duration (`7 days`, `P7D`) or a date.
    fn accepts(&self, _raw: &str) -> bool {
        true
    }
    fn location(&self, _tool: &Tool) -> PathBuf {
        user_config()
    }
    fn read(&self, _tool: &Tool, _ctx: &Ctx) -> Result<Option<String>> {
        toml_file_get(&user_config(), &KEYS)
    }
    fn write(&self, _tool: &Tool, value: &str, _ctx: &Ctx) -> Result<()> {
        toml_file_set(&user_config(), &KEYS, Value::from(value))
    }
}
