use std::path::PathBuf;

use anyhow::{Context, Result};
use toml_edit::Value;

use super::{Ctx, Manager, Tool};
use crate::files;
use crate::paths;
use crate::version::Version;

/// Bun >= 1.3: `[install] minimumReleaseAge` in seconds, in the global
/// bunfig (`$XDG_CONFIG_HOME/.bunfig.toml`, else `~/.bunfig.toml`).
pub struct Bun;

const KEYS: [&str; 2] = ["install", "minimumReleaseAge"];

fn candidates() -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Some(xdg) = paths::xdg_config_home() {
        files.push(xdg.join(".bunfig.toml"));
    }
    files.push(paths::home().join(".bunfig.toml"));
    files
}

/// The file that already sets the key, else the first that exists, else the preferred one.
fn target_file() -> Result<PathBuf> {
    let candidates = candidates();
    for path in &candidates {
        if let Some(src) = files::read_optional(path)?
            && files::toml_get(&src, &KEYS)
                .with_context(|| path.display().to_string())?
                .is_some()
        {
            return Ok(path.clone());
        }
    }
    Ok(candidates
        .iter()
        .find(|p| p.exists())
        .unwrap_or(&candidates[0])
        .clone())
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
    fn target(&self, days: u32) -> String {
        (u64::from(days) * 86_400).to_string()
    }
    fn location(&self, _tool: &Tool) -> PathBuf {
        target_file().unwrap_or_else(|_| candidates()[0].clone())
    }
    fn read(&self, _tool: &Tool, _ctx: &Ctx) -> Result<Option<String>> {
        for path in candidates() {
            if let Some(src) = files::read_optional(&path)?
                && let Some(v) =
                    files::toml_get(&src, &KEYS).with_context(|| path.display().to_string())?
            {
                return Ok(Some(v));
            }
        }
        Ok(None)
    }
    fn write(&self, _tool: &Tool, value: &str, _ctx: &Ctx) -> Result<()> {
        let path = target_file()?;
        let seconds: i64 = value
            .parse()
            .context("bun cooldown must be whole seconds")?;
        let src = files::read_optional(&path)?.unwrap_or_default();
        let updated = files::toml_set(&src, &KEYS, Value::from(seconds))
            .with_context(|| path.display().to_string())?;
        files::write_atomic(&path, &updated)
    }
}
