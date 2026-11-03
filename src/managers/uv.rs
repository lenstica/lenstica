use std::path::PathBuf;

use anyhow::{Context, Result};
use toml_edit::Value;

use super::{Ctx, Manager, Tool};
use crate::duration::DAY;
use crate::files;
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
        format!("{days} {}", if days == 1 { "day" } else { "days" })
    }
    fn location(&self, _tool: &Tool) -> PathBuf {
        user_config()
    }
    fn read(&self, _tool: &Tool, _ctx: &Ctx) -> Result<Option<String>> {
        let path = user_config();
        match files::read_optional(&path)? {
            Some(src) => files::toml_get(&src, &KEYS).with_context(|| path.display().to_string()),
            None => Ok(None),
        }
    }
    fn write(&self, _tool: &Tool, value: &str, _ctx: &Ctx) -> Result<()> {
        let path = user_config();
        let src = files::read_optional(&path)?.unwrap_or_default();
        let updated = files::toml_set(&src, &KEYS, Value::from(value))
            .with_context(|| path.display().to_string())?;
        files::write_atomic(&path, &updated)
    }
}
