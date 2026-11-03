use std::path::PathBuf;

use anyhow::Result;

use super::{Ctx, Gate, Manager, Tool};
use crate::duration::MINUTE;
use crate::files;
use crate::paths;
use crate::version::Version;

/// Yarn >= 4.10: `npmMinimalAgeGate` in `~/.yarnrc.yml`. A bare number is
/// minutes, which 4.10 requires (duration strings arrived in 4.11).
///
/// Written straight to the file rather than through `yarn config set -H`: the
/// global `yarn` is often Yarn Classic or a Corepack shim, while each project
/// runs its own Yarn release, and every Yarn >= 2 reads `~/.yarnrc.yml`.
pub struct Yarn;

const KEY: &str = "npmMinimalAgeGate";

fn rc_path() -> PathBuf {
    paths::home().join(".yarnrc.yml")
}

impl Manager for Yarn {
    fn id(&self) -> &'static str {
        "yarn"
    }
    fn name(&self) -> &'static str {
        "Yarn"
    }
    fn binaries(&self) -> &'static [&'static str] {
        &["yarn"]
    }
    fn min_version(&self) -> Version {
        Version::new(4, 10, 0)
    }
    fn setting(&self) -> &'static str {
        KEY
    }
    fn bare_unit(&self) -> i64 {
        MINUTE
    }
    fn target(&self, days: u32) -> String {
        (u64::from(days) * 24 * 60).to_string()
    }
    fn location(&self, _tool: &Tool) -> PathBuf {
        rc_path()
    }
    fn gate(&self, version: Option<Version>) -> Gate {
        match version {
            Some(v) if v.major < 2 => Gate::Note(
                "global yarn is Yarn Classic, which has no age gate; projects on Yarn 4.10+ still read this".to_string(),
            ),
            Some(v) if v < self.min_version() => Gate::TooOld,
            Some(_) => Gate::Supported,
            None => Gate::Note("version could not be determined".to_string()),
        }
    }
    fn read(&self, _tool: &Tool, _ctx: &Ctx) -> Result<Option<String>> {
        Ok(files::read_optional(&rc_path())?.and_then(|src| files::yaml_get_top(&src, KEY)))
    }
    fn write(&self, _tool: &Tool, value: &str, _ctx: &Ctx) -> Result<()> {
        let path = rc_path();
        let src = files::read_optional(&path)?.unwrap_or_default();
        files::write_atomic(&path, &files::yaml_set_top(&src, KEY, value))
    }
}
