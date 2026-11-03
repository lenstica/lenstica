//! How recently the installed software itself was published: the package
//! managers, Homebrew formulae and casks, Rust toolchains and Node.js.
//!
//! None of these can hold back a new release the way a package manager's
//! minimum-age setting holds back a dependency, so this reports after the
//! fact: a version installed while it is younger than `min_days`.
//!
//! Where each publish time comes from:
//!
//! - Homebrew formulae: the bottle's `org.opencontainers.image.created` on
//!   ghcr.io, the moment the version became installable with `brew`.
//! - Homebrew casks: the download's `Last-Modified` header. Casks carry no
//!   date, and the file is what the vendor published.
//! - npm, pnpm, Yarn, Bun and Deno: the npm registry; uv, pip and Poetry: PyPI
//!   (the same cache the package audit uses).
//! - Cargo and rustup toolchains: the Rust release manifest's `date`.
//! - Node.js: nodejs.org's release index.
//!
//! Dates without a time of day count from the end of that day, so a release
//! is never reported as older than it is. Publish times never change and are
//! cached for good.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use chrono::{DateTime, NaiveDate, Utc};
use lenstica_lens::{Category, Context, Finding, Lens, Location, Report, Severity, topic};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::shared::plural;
use crate::audit;
use crate::audit::lockfiles::{Ecosystem, Pkg};
use crate::audit::registry::{Cache as RegistryCache, RETRY_AFTER_SECS};
use crate::config::Config;
use crate::duration::humanize;
use crate::exec;
use crate::files;
use crate::http;
use crate::managers::{self, Ctx};
use crate::paths::{self, tilde};
use crate::version::Version;

pub struct SoftwareAge;

/// Don't re-ask about something that could not be dated for this long.
const GHCR_ACCEPT: &str = "Accept: application/vnd.oci.image.index.v1+json";
/// ghcr.io's anonymous token for public images, as `brew` itself sends it.
const GHCR_AUTH: &str = "Authorization: Bearer QQ==";

/// Where a publish time is looked up.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Lookup {
    /// The npm registry or PyPI.
    Registry(Pkg),
    /// A Homebrew bottle: `ghcr.io/v2/homebrew/core/<repo>/manifests/<tag>`.
    Bottle { repo: String, tag: String },
    /// A Homebrew cask's download.
    Cask,
    /// `static.rust-lang.org/dist/channel-rust-<version>.toml`.
    Rust,
    /// nodejs.org's release index.
    Node,
    /// Already known from a local file.
    Known(DateTime<Utc>),
}

/// One installed program and version.
#[derive(Debug, Clone)]
struct Item {
    /// Finding-key namespace: `brew`, `cask`, `npm`, `pypi`, `rust`, `node`.
    kind: &'static str,
    /// What it is, for titles: "Homebrew formula", "package manager", ...
    what: &'static str,
    name: String,
    version: String,
    lookup: Lookup,
    /// Where it is installed.
    path: PathBuf,
    /// Shown under the title: where the date comes from.
    source: &'static str,
}

impl Item {
    fn cache_key(&self) -> String {
        format!("{}:{}@{}", self.kind, self.name, self.version)
    }
}

/// Publish times of things the package registries do not cover.
#[derive(Default, Serialize, Deserialize)]
struct Cache {
    published: BTreeMap<String, String>,
    failed: BTreeMap<String, i64>,
    /// Casks whose app updates itself, so the installed cask version is not
    /// what runs: their age cannot be judged from Homebrew.
    #[serde(default)]
    self_updating: BTreeSet<String>,
}

impl Cache {
    fn path(dir: &Path) -> PathBuf {
        dir.join("publish-times.json")
    }

    fn load(dir: &Path) -> Self {
        files::read_json(&Self::path(dir)).unwrap_or_default()
    }

    fn save(&self, dir: &Path) -> Result<()> {
        files::write_state(&Self::path(dir), &serde_json::to_string(self)?)
            .context("cannot save the software publish-time cache")
    }

    fn get(&self, key: &str) -> Option<DateTime<Utc>> {
        parse_time(self.published.get(key)?)
    }

    fn wants(&self, key: &str, now: i64) -> bool {
        !self.published.contains_key(key)
            && !key
                .strip_prefix("cask:")
                .and_then(|k| k.rsplit_once('@'))
                .is_some_and(|(token, _)| self.self_updating.contains(token))
            && self
                .failed
                .get(key)
                .is_none_or(|t| now - t >= RETRY_AFTER_SECS)
    }

    fn record(&mut self, key: String, time: Option<DateTime<Utc>>, now: i64) {
        match time {
            Some(t) => {
                self.failed.remove(&key);
                self.published.insert(key, t.to_rfc3339());
            }
            None => {
                self.failed.insert(key, now);
            }
        }
    }
}

fn parse_time(raw: &str) -> Option<DateTime<Utc>> {
    if let Ok(t) = DateTime::parse_from_rfc3339(raw.trim()) {
        return Some(t.with_timezone(&Utc));
    }
    if let Ok(t) = DateTime::parse_from_rfc2822(raw.trim()) {
        return Some(t.with_timezone(&Utc));
    }
    end_of_day(raw)
}

/// `2026-02-12` -> the last moment of that day, UTC.
fn end_of_day(raw: &str) -> Option<DateTime<Utc>> {
    let day = NaiveDate::parse_from_str(raw.trim().trim_matches('"'), "%Y-%m-%d").ok()?;
    Some(day.and_hms_opt(23, 59, 59)?.and_utc())
}

// ---- what is installed ---------------------------------------------------------

/// Homebrew prefixes with a Cellar: Apple Silicon, Intel and Linux installs.
fn brew_prefixes() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let candidates = std::env::var_os("HOMEBREW_PREFIX")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .into_iter()
        .chain([
            PathBuf::from("/opt/homebrew"),
            PathBuf::from("/usr/local"),
            PathBuf::from("/home/linuxbrew/.linuxbrew"),
            paths::home().join(".linuxbrew"),
        ]);
    for prefix in candidates {
        if (prefix.join("Cellar").is_dir() || prefix.join("Caskroom").is_dir())
            && !out.contains(&prefix)
        {
            out.push(prefix);
        }
    }
    out
}

fn is_from_homebrew(bin: &Path) -> bool {
    fs::canonicalize(bin)
        .unwrap_or_else(|_| bin.to_path_buf())
        .components()
        .any(|c| c.as_os_str() == "Cellar")
}

fn subdirs(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = entries
        .flatten()
        .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
        // A cask renamed with an alias leaves a symlink to its new name.
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| e.path())
        .collect();
    out.sort();
    out
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// The ghcr.io repository for a formula: `python@3.13` -> `python/3.13`,
/// `libsigc++` -> `libsigcxx`, as `brew` names them.
fn ghcr_repo(formula: &str) -> String {
    formula.replace('@', "/").replace('+', "x")
}

/// Every installed keg from homebrew/core. Kegs from other taps, and HEAD
/// builds, have no bottle to date; they are counted in `skipped`.
fn formulae(prefix: &Path, skipped: &mut usize) -> Vec<Item> {
    let mut out = Vec::new();
    for formula in subdirs(&prefix.join("Cellar")) {
        let name = file_name(&formula);
        for keg in subdirs(&formula) {
            let tag = file_name(&keg);
            let receipt: Option<Value> = files::read_json(&keg.join("INSTALL_RECEIPT.json"));
            let tap = receipt
                .as_ref()
                .and_then(|r| r.pointer("/source/tap"))
                .and_then(Value::as_str)
                .unwrap_or("homebrew/core");
            if tap != "homebrew/core" || tag.starts_with("HEAD") {
                *skipped += 1;
                continue;
            }
            // `1.2.3_1` is revision 1 of version 1.2.3; the bottle tag keeps it.
            let version = tag
                .rsplit_once('_')
                .filter(|(_, revision)| revision.parse::<u32>().is_ok())
                .map_or(tag.as_str(), |(v, _)| v)
                .to_string();
            out.push(Item {
                kind: "brew",
                what: "Homebrew formula",
                name: name.clone(),
                version,
                lookup: Lookup::Bottle {
                    repo: ghcr_repo(&name),
                    tag: tag.clone(),
                },
                path: keg,
                source: "Dated by when its bottle was published on ghcr.io.",
            });
        }
    }
    out
}

/// Installed casks from homebrew/cask; `version :latest` ones and those from
/// other taps are counted in `skipped`.
fn casks(prefix: &Path, skipped: &mut usize) -> Vec<Item> {
    let mut out = Vec::new();
    for cask in subdirs(&prefix.join("Caskroom")) {
        let token = file_name(&cask);
        let tap = files::read_json::<Value>(&cask.join(".metadata/INSTALL_RECEIPT.json"))
            .and_then(|r| Some(r.pointer("/source/tap")?.as_str()?.to_string()));
        if tap.as_deref().is_some_and(|t| t != "homebrew/cask") {
            *skipped += 1;
            continue;
        }
        for dir in subdirs(&cask) {
            let version = file_name(&dir);
            if version == "latest" {
                *skipped += 1;
                continue;
            }
            out.push(Item {
                kind: "cask",
                what: "Homebrew cask",
                name: token.clone(),
                version,
                lookup: Lookup::Cask,
                path: dir,
                source: "Dated by the Last-Modified time of its download.",
            });
        }
    }
    out
}

fn rustup_home() -> PathBuf {
    std::env::var_os("RUSTUP_HOME")
        .filter(|v| !v.is_empty())
        .map_or_else(|| paths::home().join(".rustup"), PathBuf::from)
}

/// Stable toolchains installed with rustup, dated by their local release
/// manifest (no network). Nightly and beta toolchains are new by design and
/// are counted in `skipped`.
fn rust_toolchains(skipped: &mut usize) -> Vec<Item> {
    let mut out = Vec::new();
    for dir in subdirs(&rustup_home().join("toolchains")) {
        let manifest = dir.join("lib/rustlib/multirust-channel-manifest.toml");
        let Some(src) = files::read_optional(&manifest).ok().flatten() else {
            continue;
        };
        let (Some(date), Some(version)) = (
            files::ini_get(&src, None, "date").and_then(|d| end_of_day(&d)),
            files::ini_get(&src, Some("pkg.rust"), "version"),
        ) else {
            continue;
        };
        let version = version.split_whitespace().next().unwrap_or("").to_string();
        if version.contains('-') || version.is_empty() {
            *skipped += 1;
            continue;
        }
        out.push(Item {
            kind: "rust",
            what: "Rust toolchain",
            name: "rust".to_string(),
            version,
            lookup: Lookup::Known(date),
            path: dir,
            source: "Dated by its Rust release manifest.",
        });
    }
    out
}

/// The npm or PyPI package a package manager is published as.
fn registry_package(id: &str, version: Version) -> Option<(Ecosystem, &'static str)> {
    Some(match id {
        "npm" => (Ecosystem::Npm, "npm"),
        "pnpm" => (Ecosystem::Npm, "pnpm"),
        // Yarn 2+ is published as @yarnpkg/cli-dist; `yarn` on npm is Yarn 1.
        "yarn" if version.major >= 2 => (Ecosystem::Npm, "@yarnpkg/cli-dist"),
        "yarn" => (Ecosystem::Npm, "yarn"),
        "bun" => (Ecosystem::Npm, "bun"),
        "deno" => (Ecosystem::Npm, "deno"),
        "uv" => (Ecosystem::Pypi, "uv"),
        "pip" => (Ecosystem::Pypi, "pip"),
        "poetry" => (Ecosystem::Pypi, "poetry"),
        _ => return None,
    })
}

/// The package managers themselves, and Node.js. A binary from Homebrew is
/// left to the Homebrew check, and rustup's `cargo` to the toolchain check.
fn tools(cfg: &Config, ctx: &Ctx, by_brew: bool, by_rustup: bool) -> Vec<Item> {
    // (id, name, binary, version, the version as the tool wrote it)
    let mut found: Vec<(&'static str, &'static str, PathBuf, Version, String)> = Vec::new();
    if cfg.software.package_managers {
        for m in managers::all()
            .into_iter()
            .filter(|m| cfg.is_enabled(m.id()))
        {
            if let Some(tool) = managers::locate(m, ctx)
                && let (Some(v), Some(text)) = (tool.version, tool.version_text)
            {
                found.push((m.id(), m.name(), tool.bin, v, text));
            }
        }
        if let Some(bin) = exec::find("deno", &ctx.search)
            && let Some((v, text)) = exec::version_text_of(&bin, &ctx.search)
        {
            found.push(("deno", "Deno", bin, v, text));
        }
    }
    if cfg.software.node
        && let Some(bin) = exec::find("node", &ctx.search)
        && let Some((v, text)) = exec::version_text_of(&bin, &ctx.search)
    {
        found.push(("node", "Node.js", bin, v, text));
    }
    let mut out = Vec::new();
    for (id, name, bin, version, text) in found {
        if by_brew && is_from_homebrew(&bin) {
            continue;
        }
        let item = |kind, lookup, source| Item {
            kind,
            what: if id == "node" {
                "runtime"
            } else {
                "package manager"
            },
            name: name.to_string(),
            version: text.clone(),
            lookup,
            path: bin.clone(),
            source,
        };
        match id {
            "cargo" => {
                // rustup's proxies are hard links (or symlinks) next to rustup itself.
                let rustup = format!("rustup{}", std::env::consts::EXE_SUFFIX);
                let proxy = bin.parent().is_some_and(|d| d.join(&rustup).exists())
                    || fs::canonicalize(&bin)
                        .ok()
                        .is_some_and(|p| file_name(&p).starts_with("rustup"));
                if !(by_rustup && proxy) {
                    out.push(item(
                        "rust",
                        Lookup::Rust,
                        "Dated by its Rust release manifest.",
                    ));
                }
            }
            "node" => out.push(item(
                "node",
                Lookup::Node,
                "Dated by nodejs.org's release index.",
            )),
            _ => {
                let Some((eco, package)) = registry_package(id, version) else {
                    continue;
                };
                let (kind, source) = match eco {
                    Ecosystem::Pypi => ("pypi", "Dated by its upload to PyPI."),
                    _ => ("npm", "Dated by its publish time on the npm registry."),
                };
                out.push(item(
                    kind,
                    Lookup::Registry(Pkg {
                        eco,
                        name: package.to_string(),
                        version: text.clone(),
                    }),
                    source,
                ));
            }
        }
    }
    out
}

// ---- dating ---------------------------------------------------------------------

/// GET each URL; the body of each response, `None` where it failed.
fn fetch(urls: &[String], extra: &[&str], ctx: &Ctx, dir: &Path) -> Result<Vec<Option<String>>> {
    if urls.is_empty() {
        return Ok(Vec::new());
    }
    let scratch = http::Scratch::new(dir, "fetch")?;
    http::get_batch_with(urls, &scratch.0, &ctx.search, extra)?;
    Ok((0..urls.len())
        .map(|i| fs::read_to_string(scratch.0.join(i.to_string())).ok())
        .collect())
}

/// Look up `items` with one batch of requests: `url` names each request, and
/// `read` turns its response into a publish time.
fn date_each(
    items: &[&Item],
    url: impl Fn(&Item) -> String,
    extra: &[&str],
    read: impl Fn(&str) -> Option<DateTime<Utc>>,
    (ctx, dir, cache): (&Ctx, &Path, &mut Cache),
    problems: &mut Vec<String>,
) {
    let urls: Vec<String> = items.iter().map(|&i| url(i)).collect();
    match fetch(&urls, extra, ctx, dir) {
        Ok(bodies) => {
            for (item, body) in items.iter().zip(bodies) {
                let time = body.as_deref().and_then(&read);
                cache.record(item.cache_key(), time, ctx.now.timestamp());
            }
        }
        Err(e) => problems.push(format!("{e:#}")),
    }
}

/// Fetch every publish time the caches cannot answer; returns problems.
fn fill(
    cfg: &Config,
    ctx: &Ctx,
    items: &[Item],
    (cache, registry): (&mut Cache, &mut RegistryCache),
    dir: &Path,
) -> Vec<String> {
    let now = ctx.now.timestamp();
    let mut problems = Vec::new();

    // npm and PyPI: through the package audit's cache.
    let packages: BTreeSet<Pkg> = items
        .iter()
        .filter_map(|i| match &i.lookup {
            Lookup::Registry(p) => Some(p.clone()),
            _ => None,
        })
        .collect();
    if !packages.is_empty()
        && let Err(e) = registry.fill(&packages, &cfg.audit, &ctx.search, ctx.now, None, false)
    {
        problems.push(format!("package registries: {e:#}"));
    }

    let pending = |cache: &Cache, want: fn(&Lookup) -> bool| -> Vec<&Item> {
        items
            .iter()
            .filter(|i| want(&i.lookup) && cache.wants(&i.cache_key(), now))
            .collect()
    };

    let bottles = pending(cache, |l| matches!(l, Lookup::Bottle { .. }));
    date_each(
        &bottles,
        |i| match &i.lookup {
            Lookup::Bottle { repo, tag } => {
                format!("https://ghcr.io/v2/homebrew/core/{repo}/manifests/{tag}")
            }
            _ => unreachable!("only bottles are pending here"),
        },
        &["--header", GHCR_ACCEPT, "--header", GHCR_AUTH],
        bottle_created,
        (ctx, dir, cache),
        &mut problems,
    );

    // A rebuilt bottle replaces the version's tag with `<tag>-<n>`: find it
    // for the bottles the first pass could not date. (They were just recorded
    // as failed, so `pending` would no longer list them.)
    let rebuilt: Vec<&Item> = bottles
        .iter()
        .copied()
        .filter(|i| cache.get(&i.cache_key()).is_none())
        .collect();
    let lists: Vec<String> = rebuilt
        .iter()
        .filter_map(|i| match &i.lookup {
            Lookup::Bottle { repo, .. } => {
                Some(format!("https://ghcr.io/v2/homebrew/core/{repo}/tags/list"))
            }
            _ => None,
        })
        .collect();
    if let Ok(bodies) = fetch(&lists, &["--header", GHCR_AUTH], ctx, dir) {
        let mut found: Vec<(&Item, String)> = Vec::new();
        for (item, body) in rebuilt.iter().zip(bodies) {
            let Lookup::Bottle { repo, tag } = &item.lookup else {
                continue;
            };
            let tags: Vec<String> = body
                .and_then(|b| serde_json::from_str::<Value>(&b).ok())
                .and_then(|d| serde_json::from_value(d.get("tags")?.clone()).ok())
                .unwrap_or_default();
            if let Some(t) = first_rebuild(&tags, tag) {
                found.push((
                    item,
                    format!("https://ghcr.io/v2/homebrew/core/{repo}/manifests/{t}"),
                ));
            }
        }
        let urls: BTreeMap<String, String> = found
            .iter()
            .map(|(i, u)| (i.cache_key(), u.clone()))
            .collect();
        let items: Vec<&Item> = found.iter().map(|(i, _)| *i).collect();
        date_each(
            &items,
            |i| urls[&i.cache_key()].clone(),
            &["--header", GHCR_ACCEPT, "--header", GHCR_AUTH],
            bottle_created,
            (ctx, dir, cache),
            &mut problems,
        );
    }

    // A cargo that rustup does not manage: the Rust release it came with.
    let rust = pending(cache, |l| *l == Lookup::Rust);
    date_each(
        &rust,
        |i| {
            format!(
                "https://static.rust-lang.org/dist/channel-rust-{}.toml",
                i.version
            )
        },
        &["--range", "0-511"],
        |body| end_of_day(&files::ini_get(body, None, "date")?),
        (ctx, dir, cache),
        &mut problems,
    );

    // Node.js: one index answers every version.
    let node = pending(cache, |l| *l == Lookup::Node);
    if !node.is_empty() {
        match fetch(
            &["https://nodejs.org/dist/index.json".to_string()],
            &[],
            ctx,
            dir,
        ) {
            Ok(bodies) => {
                let releases: Vec<Value> = bodies
                    .into_iter()
                    .flatten()
                    .next()
                    .and_then(|b| serde_json::from_str(&b).ok())
                    .unwrap_or_default();
                for item in node {
                    let tag = format!("v{}", item.version);
                    let date = releases
                        .iter()
                        .find(|r| r.get("version").and_then(Value::as_str) == Some(tag.as_str()))
                        .and_then(|r| end_of_day(r.get("date")?.as_str()?));
                    cache.record(item.cache_key(), date, now);
                }
            }
            Err(e) => problems.push(format!("nodejs.org: {e:#}")),
        }
    }

    // Casks: the installed version's download URL, then its Last-Modified.
    let casks = pending(cache, |l| *l == Lookup::Cask);
    let api: Vec<String> = casks
        .iter()
        .map(|i| format!("https://formulae.brew.sh/api/cask/{}.json", i.name))
        .collect();
    match fetch(&api, &[], ctx, dir) {
        Ok(docs) => {
            let mut downloads: Vec<(&Item, String)> = Vec::new();
            for (item, doc) in casks.iter().zip(docs) {
                let doc: Option<Value> = doc.and_then(|b| serde_json::from_str(&b).ok());
                let updates_itself = doc
                    .as_ref()
                    .and_then(|d| d.get("auto_updates"))
                    .and_then(Value::as_bool)
                    == Some(true);
                if updates_itself {
                    cache.self_updating.insert(item.name.clone());
                } else if doc.is_some() {
                    cache.self_updating.remove(&item.name);
                }
                match doc.as_ref().and_then(|d| cask_download(d, &item.version)) {
                    Some(url) => downloads.push((item, url)),
                    None => cache.record(item.cache_key(), None, now),
                }
            }
            let urls: BTreeMap<String, String> = downloads
                .iter()
                .map(|(i, u)| (i.cache_key(), u.clone()))
                .collect();
            let items: Vec<&Item> = downloads.iter().map(|(i, _)| *i).collect();
            date_each(
                &items,
                |i| urls[&i.cache_key()].clone(),
                &["--head"],
                last_modified,
                (ctx, dir, cache),
                &mut problems,
            );
        }
        Err(e) => problems.push(format!("formulae.brew.sh: {e:#}")),
    }

    if let Err(e) = cache.save(dir) {
        problems.push(format!("{e:#}"));
    }
    problems
}

fn bottle_created(body: &str) -> Option<DateTime<Utc>> {
    let doc: Value = serde_json::from_str(body).ok()?;
    parse_time(
        doc.pointer("/annotations/org.opencontainers.image.created")?
            .as_str()?,
    )
}

/// The earliest rebuild of `tag` among a bottle's tags: `0.1.3-1` for `0.1.3`.
fn first_rebuild<'a>(tags: &'a [String], tag: &str) -> Option<&'a str> {
    tags.iter()
        .filter_map(|t| {
            let n: u32 = t.strip_prefix(tag)?.strip_prefix('-')?.parse().ok()?;
            Some((n, t.as_str()))
        })
        .min()
        .map(|(_, t)| t)
}

/// The last `Last-Modified` in a header dump: after redirects, the file's own.
fn last_modified(headers: &str) -> Option<DateTime<Utc>> {
    headers
        .lines()
        .rev()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim()
                .eq_ignore_ascii_case("last-modified")
                .then(|| v.trim().to_string())
        })
        .and_then(|v| parse_time(&v))
}

/// The download URL of `version` of a cask, from its formulae.brew.sh entry.
/// The API describes the newest version only; an older installed one is
/// found by putting its version into that URL. A cask that updates itself,
/// or whose URL does not contain its version, cannot be dated.
fn cask_download(doc: &Value, installed: &str) -> Option<String> {
    if doc.get("auto_updates").and_then(Value::as_bool) == Some(true) {
        return None;
    }
    let url = doc.get("url")?.as_str()?;
    let current = doc.get("version")?.as_str()?;
    if current == installed {
        return Some(url.to_string());
    }
    // `1.2.3,abcd` versions: Homebrew puts the parts into the URL separately.
    let parts: Vec<(&str, &str)> = current.split(',').zip(installed.split(',')).collect();
    if parts.is_empty() || !parts.iter().all(|(c, _)| !c.is_empty() && url.contains(c)) {
        return None;
    }
    let mut out = url.to_string();
    for (c, i) in parts {
        out = out.replace(c, i);
    }
    Some(out)
}

fn published(item: &Item, cache: &Cache, registry: &RegistryCache) -> Option<DateTime<Utc>> {
    match &item.lookup {
        Lookup::Known(t) => Some(*t),
        Lookup::Registry(p) => registry.lookup(p),
        _ => cache.get(&item.cache_key()),
    }
}

fn ignored(cfg: &Config, item: &Item) -> bool {
    audit::ignore_matches(
        cfg.software.ignore.iter().chain(&cfg.audit.ignore),
        &item.name,
        &item.version,
    )
}

fn remedy(item: &Item, days: u32) -> String {
    let after = format!(
        "Once you have checked it, add \"{}@{}\" to software.ignore.",
        item.name, item.version
    );
    let what = match item.kind {
        "brew" => format!(
            "Homebrew has no minimum-age setting, so `brew upgrade` installs a release as soon as its bottle exists. \
             Check the release notes, and run `brew pin {}` to keep it from upgrading again until you have.",
            item.name
        ),
        "cask" => "Homebrew has no minimum-age setting for casks. Check the vendor's release notes before you open it, \
                   and upgrade casks with `brew upgrade --cask` only when you mean to."
            .to_string(),
        "rust" => "`rustup update` installs a new stable release the day it ships. To stay a release behind, \
                   pin one with `rustup default 1.xx.y` or a rust-toolchain.toml."
            .to_string(),
        "node" => "Install an older release with your Node.js version manager, or wait.".to_string(),
        _ => format!(
            "A package manager's minimum-age setting does not cover updates of the package manager itself. \
             Go back to a release older than {days} days, or wait until this one is."
        ),
    };
    format!("{what} {after}")
}

impl Lens for SoftwareAge {
    fn id(&self) -> &str {
        "software"
    }
    fn title(&self) -> &str {
        "Software ages"
    }
    fn description(&self) -> &str {
        "Installed software published less than the cooldown ago: the package managers themselves, Homebrew formulae and casks, Rust toolchains and Node.js. None of them can hold back new releases, so this reports them after installation."
    }
    fn categories(&self) -> &[Category] {
        &[Category::Software]
    }
    fn default_interval(&self) -> std::time::Duration {
        std::time::Duration::from_secs(60 * 60)
    }

    fn run(&self, cx: &Context) -> Result<Report> {
        let cfg = Config::load()?;
        let ctx = Ctx::new(&cfg);
        let sw = &cfg.software;
        let mut items: Vec<Item> = Vec::new();
        let mut watch = Vec::new();
        let (mut other_taps, mut latest, mut prerelease) = (0, 0, 0);
        let prefixes = brew_prefixes();
        for prefix in &prefixes {
            if sw.homebrew {
                items.extend(formulae(prefix, &mut other_taps));
                watch.push(prefix.join("Cellar"));
            }
            if sw.casks {
                items.extend(casks(prefix, &mut latest));
                watch.push(prefix.join("Caskroom"));
            }
        }
        if sw.rust_toolchains {
            items.extend(rust_toolchains(&mut prerelease));
            watch.push(rustup_home().join("toolchains"));
        }
        items.extend(tools(
            &cfg,
            &ctx,
            sw.homebrew && !prefixes.is_empty(),
            sw.rust_toolchains,
        ));
        watch.retain(|p| p.is_dir());

        let mut cache = Cache::load(&cx.state_dir);
        let mut registry = RegistryCache::load();
        let mut problems = Vec::new();
        if !cx.offline {
            problems = fill(
                &cfg,
                &ctx,
                &items,
                (&mut cache, &mut registry),
                &cx.state_dir,
            );
        }

        let target = cfg.target_secs();
        let mut findings = Vec::new();
        let mut counts: BTreeMap<&'static str, (usize, usize)> = BTreeMap::new();
        let mut self_updating = 0;
        for item in &items {
            if item.lookup == Lookup::Cask && cache.self_updating.contains(&item.name) {
                self_updating += 1;
                continue;
            }
            let entry = counts.entry(item.what).or_default();
            entry.0 += 1;
            let Some(published) = published(item, &cache, &registry) else {
                continue;
            };
            entry.1 += 1;
            let age = (ctx.now - published).num_seconds().max(0);
            if age >= target || ignored(&cfg, item) {
                continue;
            }
            findings.push(
                Finding::new(
                    format!("too-new|{}|{}|{}", item.kind, item.name, item.version),
                    Severity::Medium,
                    Category::Software,
                    format!(
                        "{} {} was published {} ago",
                        item.name,
                        item.version,
                        humanize(age.max(60))
                    ),
                )
                .topic(topic::TOO_NEW)
                .detail(format!(
                    "{} {}, published {} UTC. {}",
                    capitalise(item.what),
                    item.name,
                    published.format("%Y-%m-%d %H:%M"),
                    item.source
                ))
                .remedy(remedy(item, cfg.min_days))
                .at(Location::file(tilde(&item.path), item.path.clone())),
            );
        }
        let mut passing: Vec<String> = counts
            .iter()
            .map(|(what, (all, dated))| {
                let label = plural_what(what, *all);
                if all == dated {
                    format!("{all} {label}")
                } else {
                    format!("{all} {label} ({} could not be dated)", all - dated)
                }
            })
            .collect();
        if other_taps > 0 {
            passing.push(format!(
                "{} from other taps, or HEAD builds, not checked",
                plural(other_taps, "Homebrew install", "Homebrew installs")
            ));
        }
        if self_updating > 0 {
            passing.push(format!(
                "{} update themselves inside the app, so Homebrew's version says nothing about what runs; not checked",
                plural(self_updating, "cask", "casks")
            ));
        }
        if latest > 0 {
            passing.push(format!(
                "{} with version :latest not checked",
                plural(latest, "cask", "casks")
            ));
        }
        if prerelease > 0 {
            passing.push(format!(
                "{} not checked",
                plural(
                    prerelease,
                    "nightly or beta Rust toolchain",
                    "nightly or beta Rust toolchains"
                )
            ));
        }
        passing.extend(
            problems
                .into_iter()
                .take(5)
                .map(|p| format!("skipped: {p}")),
        );
        let summary = format!(
            "{} of {} installed programs published less than {} days ago",
            findings.len(),
            items.len() - self_updating,
            cfg.min_days
        );
        Ok(Report {
            findings,
            summary,
            passing,
            watch,
            ..Default::default()
        })
    }
}

fn capitalise(s: &str) -> String {
    let mut c = s.chars();
    c.next()
        .map(|f| f.to_uppercase().collect::<String>() + c.as_str())
        .unwrap_or_default()
}

fn plural_what(what: &str, n: usize) -> String {
    if n == 1 {
        return what.to_string();
    }
    match what {
        "Homebrew formula" => "Homebrew formulae".to_string(),
        other => format!("{other}s"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_bottles_like_brew() {
        assert_eq!(ghcr_repo("python@3.13"), "python/3.13");
        assert_eq!(ghcr_repo("libsigc++"), "libsigcxx");
        assert_eq!(ghcr_repo("sqlite"), "sqlite");
    }

    #[test]
    fn reads_rust_manifests_and_dates_whole_days_late() {
        let src = "manifest-version = \"2\"\ndate = \"2026-02-12\"\n\n[pkg.cargo]\nversion = \"0.94.0\"\n[pkg.rust]\nversion = \"1.93.1 (01f6ddf75 2026-02-11)\"\n";
        assert_eq!(
            files::ini_get(src, None, "date").as_deref(),
            Some("2026-02-12")
        );
        assert_eq!(
            files::ini_get(src, Some("pkg.rust"), "version").as_deref(),
            Some("1.93.1 (01f6ddf75 2026-02-11)")
        );
        assert_eq!(
            end_of_day("2026-02-12").unwrap().to_rfc3339(),
            "2026-02-12T23:59:59+00:00"
        );
        assert!(parse_time("Tue, 27 Oct 2026 01:19:34 GMT").is_some());
    }

    #[test]
    fn finds_rebuilt_bottles() {
        let tags: Vec<String> = ["0.1.3-2", "0.1.3-1", "0.1.30", "0.1.3_1-1"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(first_rebuild(&tags, "0.1.3"), Some("0.1.3-1"));
        assert_eq!(first_rebuild(&tags, "0.1.3_1"), Some("0.1.3_1-1"));
        assert_eq!(first_rebuild(&tags, "0.2"), None);
    }

    #[test]
    fn finds_an_older_casks_download() {
        let doc: Value = serde_json::from_str(
            r#"{"version":"159.0","url":"https://cdn/firefox/releases/159.0/mac/Firefox%20159.0.dmg"}"#,
        )
        .unwrap();
        assert_eq!(
            cask_download(&doc, "158.0.1").as_deref(),
            Some("https://cdn/firefox/releases/158.0.1/mac/Firefox%20158.0.1.dmg")
        );
        let updates: Value =
            serde_json::from_str(r#"{"version":"1","url":"https://x/1","auto_updates":true}"#)
                .unwrap();
        assert_eq!(cask_download(&updates, "1"), None);
        let opaque: Value =
            serde_json::from_str(r#"{"version":"2.0","url":"https://x/latest.dmg"}"#).unwrap();
        assert_eq!(cask_download(&opaque, "1.0"), None);
    }

    #[test]
    fn maps_package_managers_to_their_packages() {
        assert_eq!(
            registry_package("yarn", Version::new(4, 10, 0)),
            Some((Ecosystem::Npm, "@yarnpkg/cli-dist"))
        );
        assert_eq!(
            registry_package("yarn", Version::new(1, 22, 22)),
            Some((Ecosystem::Npm, "yarn"))
        );
        assert_eq!(
            registry_package("uv", Version::new(0, 9, 0)),
            Some((Ecosystem::Pypi, "uv"))
        );
        assert_eq!(registry_package("cargo", Version::new(1, 93, 1)), None);
    }
}
