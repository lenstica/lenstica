//! Work several lenses need, done once and shared for a short while: the
//! search roots (with git worktrees) and the package inventory (every lockfile
//! and global install). Dependency lenses run in parallel; the first to ask
//! collects, the others wait for that result instead of collecting again.
//!
//! Also the few helpers the package lenses have in common.

use std::ffi::OsStr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::audit::{self, Collected};
use crate::config::Config;
use crate::managers::Ctx;
use crate::scan::{self, Roots};

const ROOTS_TTL: Duration = Duration::from_secs(60);
const INVENTORY_TTL: Duration = Duration::from_secs(120);

type Slot<K, V> = Mutex<Option<(Instant, K, Arc<V>)>>;

static ROOTS: Slot<(Vec<PathBuf>, Vec<String>, bool, usize), Roots> = Mutex::new(None);
/// Everything `audit::collect` reads: roots, exclusions, global installs,
/// scan depth and the npm registry.
type InventoryKey = (Vec<PathBuf>, Vec<String>, bool, usize, String);
static INVENTORY: Slot<InventoryKey, Inventory> = Mutex::new(None);

pub struct Inventory {
    /// Lenstica's own view, with publish times recorded in lockfiles.
    pub collected: Collected,
    /// The same packages through the public lens API.
    pub api: Arc<lenstica_lens::Inventory>,
}

fn cached<K: PartialEq + Clone, V>(
    slot: &Slot<K, V>,
    key: K,
    ttl: Duration,
    make: impl FnOnce() -> Result<V>,
) -> Result<Arc<V>> {
    // Held while computing, so concurrent callers wait for one result.
    let mut guard = slot.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some((at, k, v)) = guard.as_ref()
        && *k == key
        && at.elapsed() < ttl
    {
        return Ok(v.clone());
    }
    let value = Arc::new(make()?);
    *guard = Some((Instant::now(), key, value.clone()));
    Ok(value)
}

pub fn roots(cfg: &Config, search: &OsStr) -> Arc<Roots> {
    let key = (
        cfg.scan_roots(),
        cfg.scan.exclude.clone(),
        cfg.scan.worktrees,
        cfg.scan.max_depth,
    );
    cached(&ROOTS, key, ROOTS_TTL, || {
        Ok(scan::roots(cfg, cfg.scan_roots(), search))
    })
    .expect("computing roots cannot fail")
}

pub fn inventory(
    cfg: &Config,
    ctx: &Ctx,
    roots: &[PathBuf],
    global: bool,
) -> Result<Arc<Inventory>> {
    let key = (
        roots.to_vec(),
        cfg.scan.exclude.clone(),
        global,
        cfg.scan.max_depth,
        cfg.audit.npm_registry.clone(),
    );
    cached(&INVENTORY, key, INVENTORY_TTL, || {
        let collected = audit::collect(cfg, ctx, roots, global)?;
        let api = Arc::new(to_api(&collected));
        Ok(Inventory { collected, api })
    })
}

fn to_api(collected: &Collected) -> lenstica_lens::Inventory {
    use lenstica_lens::{Ecosystem, Package, Source};
    let sources = collected
        .sources
        .iter()
        .map(|s| Source {
            label: s.label.clone(),
            path: s.path.clone(),
            locked_at: s.locked_at.map(Into::into),
            // Only public packages reach the lens API: lenses send names to registries.
            packages: s
                .entries
                .iter()
                .filter(|e| e.public)
                .map(|e| Package {
                    ecosystem: match e.pkg.eco {
                        audit::lockfiles::Ecosystem::Npm => Ecosystem::Npm,
                        audit::lockfiles::Ecosystem::Pypi => Ecosystem::Pypi,
                        audit::lockfiles::Ecosystem::Crates => Ecosystem::Crates,
                    },
                    name: e.pkg.name.clone(),
                    version: e.pkg.version.clone(),
                })
                .collect(),
        })
        .collect();
    lenstica_lens::Inventory {
        sources,
        errors: collected.errors.clone(),
    }
}

// ---- helpers for the package lenses -------------------------------------------

/// What to do about a malicious package, whichever lens found it.
pub const MALWARE_REMEDY: &str = "Remove it, then treat this machine as compromised: from another machine, revoke and rotate \
     every credential this one can reach (npm and GitHub tokens, cloud sign-ins, SSH keys, .env secrets), and check \
     the advisory for anything it installs to persist.";

/// A lens's `refresh_hours` setting: at least 1, default 6.
pub fn refresh_hours(settings: &serde_json::Value) -> u64 {
    settings
        .get("refresh_hours")
        .and_then(serde_json::Value::as_i64)
        .map_or(6, |h| h.max(1).unsigned_abs())
}

/// A package name as its registry compares it: PyPI ignores case and treats
/// runs of `-`, `_` and `.` alike (PEP 503); the others compare as written.
pub fn normalise_name(eco: lenstica_lens::Ecosystem, name: &str) -> String {
    match eco {
        lenstica_lens::Ecosystem::Pypi => {
            let mut out = String::with_capacity(name.len());
            for c in name.chars() {
                if matches!(c, '-' | '_' | '.') {
                    if !out.ends_with('-') {
                        out.push('-');
                    }
                } else {
                    out.push(c.to_ascii_lowercase());
                }
            }
            out
        }
        _ => name.to_string(),
    }
}

/// `1 package`, `3 packages`.
pub fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}
