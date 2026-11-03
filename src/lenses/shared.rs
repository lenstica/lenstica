//! Work several lenses need, done once and shared for a short while: the
//! search roots (with git worktrees) and the package inventory (every lockfile
//! and global install). Dependency lenses run in parallel; the first to ask
//! collects, the others wait for that result instead of collecting again.

use std::ffi::OsStr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
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
static INVENTORY: Slot<(Vec<PathBuf>, Vec<String>, bool), Inventory> = Mutex::new(None);

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
    let mut guard = slot.lock().unwrap_or_else(|p| p.into_inner());
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
    let key = (roots.to_vec(), cfg.scan.exclude.clone(), global);
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
            packages: s
                .entries
                .iter()
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
