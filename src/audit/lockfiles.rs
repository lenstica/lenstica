//! Parse the package/version pairs out of every lockfile format Lenstica
//! knows. Only packages from the public registries are kept: workspace,
//! git, tarball, path and private-registry entries have no public publish
//! time to compare against (and their names should not be sent anywhere).

use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::duration::unquote;
use crate::files;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Npm,
    Pypi,
    Crates,
}

impl Ecosystem {
    pub fn label(self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::Pypi => "pypi",
            Ecosystem::Crates => "crates",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Pkg {
    pub eco: Ecosystem,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone)]
pub struct Locked {
    pub pkg: Pkg,
    /// Publish time recorded in the lockfile itself (uv records upload times).
    pub published: Option<DateTime<Utc>>,
    /// From a public registry, so its name may be looked up there. uv keeps
    /// private-index packages whose lockfile records an upload time; they
    /// count for the age check but are never sent anywhere.
    pub public: bool,
}

pub const NAMES: &[&str] = &[
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lock",
    "uv.lock",
    "poetry.lock",
    "Cargo.lock",
];

pub fn parse(path: &Path, src: &str, npm_registry: &str) -> Result<Vec<Locked>> {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    match name {
        "package-lock.json" | "npm-shrinkwrap.json" => npm_lock(src, npm_registry),
        "pnpm-lock.yaml" => Ok(pnpm_lock(src)),
        "yarn.lock" => Ok(yarn_lock(src, npm_registry)),
        "bun.lock" => bun_lock(src, npm_registry),
        "uv.lock" => uv_lock(src),
        "poetry.lock" => poetry_lock(src),
        "Cargo.lock" => cargo_lock(src),
        _ => Ok(Vec::new()),
    }
}

/// A plain registry release (`1.2.3`, `2.0.0-rc.1`), not a URL, path or protocol.
fn is_release(version: &str) -> bool {
    version.starts_with(|c: char| c.is_ascii_digit()) && !version.contains([':', '/'])
}

/// `name@version`, where a scoped name starts with its own `@`.
fn split_spec(spec: &str) -> Option<(&str, &str)> {
    let at = spec.get(1..)?.rfind('@')? + 1;
    Some((&spec[..at], &spec[at + 1..]))
}

fn npm(name: &str, version: &str) -> Option<Locked> {
    // An alias (`"x": "npm:real@1.0.0"`) names the real package.
    let (name, version) = version
        .strip_prefix("npm:")
        .and_then(split_spec)
        .unwrap_or((name, version));
    (!name.is_empty() && is_release(version)).then(|| Locked {
        pkg: Pkg {
            eco: Ecosystem::Npm,
            name: name.to_string(),
            version: version.to_string(),
        },
        published: None,
        public: true,
    })
}

fn pypi(name: &str, version: &str, published: Option<DateTime<Utc>>, public: bool) -> Locked {
    Locked {
        pkg: Pkg {
            eco: Ecosystem::Pypi,
            name: name.to_string(),
            version: version.to_string(),
        },
        published,
        public,
    }
}

/// The public npm registries, then the configured one, each ending in `/`.
fn npm_registries(npm_registry: &str) -> [String; 3] {
    [
        "https://registry.npmjs.org/".to_string(),
        "https://registry.yarnpkg.com/".to_string(),
        format!("{}/", npm_registry.trim_end_matches('/')),
    ]
}

fn is_public_npm(url: &str, npm_registry: &str) -> bool {
    npm_registries(npm_registry)
        .iter()
        .any(|r| url.starts_with(r.as_str()))
}

/// The host of an `https://host[:port]/...` URL.
fn url_host(url: &str) -> Option<&str> {
    let rest = url.split_once("://")?.1;
    rest.split(['/', ':', '?', '#']).next()
}

/// pypi.org itself, not a mirror or test.pypi.org.
fn is_public_pypi(url: &str) -> bool {
    matches!(url_host(url), Some("pypi.org" | "files.pythonhosted.org"))
}

// ---- npm --------------------------------------------------------------------

fn npm_lock(src: &str, npm_registry: &str) -> Result<Vec<Locked>> {
    let doc: Value = serde_json::from_str(src).context("invalid JSON")?;
    let mut out = Vec::new();
    if let Some(packages) = doc.get("packages").and_then(Value::as_object) {
        for (key, entry) in packages {
            // "" is the root project and "packages/x" a workspace; only installed deps live under node_modules/.
            let Some(idx) = key.rfind("node_modules/") else {
                continue;
            };
            if entry.get("link").and_then(Value::as_bool) == Some(true) {
                continue;
            }
            if entry
                .get("resolved")
                .and_then(Value::as_str)
                .is_some_and(|r| !is_public_npm(r, npm_registry))
            {
                continue;
            }
            // `name` is only present when the install is an alias (`"x": "npm:y@1"`).
            let name = entry
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or(&key[idx + "node_modules/".len()..]);
            if let Some(version) = entry.get("version").and_then(Value::as_str) {
                out.extend(npm(name, version));
            }
        }
    } else if let Some(deps) = doc.get("dependencies") {
        npm_lock_v1(deps, npm_registry, &mut out);
    }
    Ok(out)
}

fn npm_lock_v1(deps: &Value, npm_registry: &str, out: &mut Vec<Locked>) {
    let Some(deps) = deps.as_object() else { return };
    for (name, entry) in deps {
        let public = entry
            .get("resolved")
            .and_then(Value::as_str)
            .is_none_or(|r| is_public_npm(r, npm_registry));
        if let (true, Some(version)) = (public, entry.get("version").and_then(Value::as_str)) {
            out.extend(npm(name, version));
        }
        if let Some(nested) = entry.get("dependencies") {
            npm_lock_v1(nested, npm_registry, out);
        }
    }
}

// ---- pnpm -------------------------------------------------------------------

fn pnpm_lock(src: &str) -> Vec<Locked> {
    let lines: Vec<&str> = src.lines().collect();
    let mut out = Vec::new();
    let mut in_packages = false;
    for (i, line) in lines.iter().enumerate() {
        if !line.starts_with(' ') && !line.trim().is_empty() {
            in_packages = line.trim_end() == "packages:";
            continue;
        }
        let Some(rest) = line.strip_prefix("  ") else {
            continue;
        };
        if !in_packages || rest.starts_with(' ') || !rest.trim_end().ends_with(':') {
            continue;
        }
        // Registry packages resolve by integrity only; tarball, git and directory sources say so.
        let resolution = lines[i + 1..]
            .iter()
            .take_while(|l| l.starts_with("    "))
            .find(|l| l.trim_start().starts_with("resolution:"));
        if resolution.is_some_and(|r| {
            r.contains("tarball:") || r.contains("repo:") || r.contains("directory:")
        }) {
            continue;
        }
        let key = unquote(rest.trim_end().trim_end_matches(':'));
        if let Some((name, version)) = pnpm_key(key) {
            out.extend(npm(name, version));
        }
    }
    out
}

/// v9 `name@1.0.0`, v6 `/name@1.0.0(peer@2)`, v5 `/name/1.0.0_peer@2`.
fn pnpm_key(key: &str) -> Option<(&str, &str)> {
    let key = key.strip_prefix('/').unwrap_or(key);
    let key = key.split('(').next()?;
    // v5 first: its peer suffix (`_react@17.0.2`) contains an `@` of its own.
    if let Some(slash) = key.rfind('/') {
        let version = key[slash + 1..].split('_').next()?;
        if is_release(version) && !version.contains('@') {
            return Some((&key[..slash], version));
        }
    }
    split_spec(key)
}

// ---- Yarn -------------------------------------------------------------------

fn yarn_lock(src: &str, npm_registry: &str) -> Vec<Locked> {
    let berry = src
        .lines()
        .any(|l| l.trim_start_matches('"').starts_with("__metadata"));
    let mut out = Vec::new();
    let mut version: Option<String> = None;
    for line in src.lines() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        if !line.starts_with(' ') {
            version = None;
            continue;
        }
        let t = line.trim();
        if berry {
            // `resolution: "name@npm:1.2.3"`; patch:, workspace:, git and file entries are skipped.
            if let Some(res) = t.strip_prefix("resolution:")
                && let Some((name, rest)) = split_spec(unquote(res))
                && let Some(v) = rest.strip_prefix("npm:")
            {
                out.extend(npm(name, v));
            }
        } else if let Some(v) = t.strip_prefix("version ") {
            version = Some(unquote(v).to_string());
        } else if let Some(url) = t.strip_prefix("resolved ") {
            // The tarball URL carries the real name, which an alias header does not.
            let url = unquote(url);
            if let (Some(v), Some(name)) = (&version, yarn_classic_name(url, npm_registry)) {
                out.extend(npm(&name, v));
            }
        }
    }
    out
}

fn yarn_classic_name(url: &str, npm_registry: &str) -> Option<String> {
    // The name follows the registry's own path (`https://nexus/repository/npm/`).
    let path = npm_registries(npm_registry)
        .iter()
        .find_map(|r| url.strip_prefix(r.as_str()))?;
    let name = path.split("/-/").next()?;
    Some(name.replace("%2f", "/").replace("%2F", "/"))
}

// ---- Bun --------------------------------------------------------------------

/// bun.lock: JSON with trailing commas. A registry package is
/// `[spec, registry, info, integrity]`, where an empty registry is the default.
fn bun_lock(src: &str, npm_registry: &str) -> Result<Vec<Locked>> {
    let doc: Value =
        serde_json::from_str(&files::jsonc_to_json(src)).context("invalid bun.lock")?;
    let mut out = Vec::new();
    if let Some(packages) = doc.get("packages").and_then(Value::as_object) {
        for entry in packages.values() {
            let public = entry
                .get(1)
                .and_then(Value::as_str)
                .is_none_or(|r| r.is_empty() || is_public_npm(r, npm_registry));
            if public
                && let Some((name, version)) =
                    entry.get(0).and_then(Value::as_str).and_then(split_spec)
            {
                out.extend(npm(name, version));
            }
        }
    }
    Ok(out)
}

// ---- uv ---------------------------------------------------------------------

#[derive(Deserialize)]
struct UvLock {
    #[serde(default)]
    package: Vec<UvPackage>,
}

#[derive(Deserialize)]
struct UvPackage {
    name: String,
    version: Option<String>,
    source: Option<toml::Table>,
    sdist: Option<UvFile>,
    #[serde(default)]
    wheels: Vec<UvFile>,
}

#[derive(Deserialize)]
struct UvFile {
    #[serde(rename = "upload-time")]
    upload_time: Option<String>,
}

fn uv_lock(src: &str) -> Result<Vec<Locked>> {
    let lock: UvLock = toml::from_str(src).context("invalid uv.lock")?;
    let mut out = Vec::new();
    for p in lock.package {
        let (Some(version), Some(source)) = (p.version, p.source) else {
            continue;
        };
        let Some(registry) = source.get("registry").and_then(toml::Value::as_str) else {
            continue;
        };
        // The earliest file upload is when the release became installable.
        let published = p
            .sdist
            .iter()
            .chain(p.wheels.iter())
            .filter_map(|f| f.upload_time.as_deref())
            .filter_map(|t| DateTime::parse_from_rfc3339(t).ok())
            .map(|t| t.with_timezone(&Utc))
            .min();
        let public = is_public_pypi(registry);
        if published.is_some() || public {
            out.push(pypi(&p.name, &version, published, public));
        }
    }
    Ok(out)
}

// ---- Poetry -----------------------------------------------------------------

#[derive(Deserialize)]
struct PoetryLock {
    #[serde(default)]
    package: Vec<PoetryPackage>,
}

#[derive(Deserialize)]
struct PoetryPackage {
    name: String,
    version: String,
    source: Option<PoetrySource>,
}

#[derive(Deserialize)]
struct PoetrySource {
    url: Option<String>,
}

fn poetry_lock(src: &str) -> Result<Vec<Locked>> {
    let lock: PoetryLock = toml::from_str(src).context("invalid poetry.lock")?;
    Ok(lock
        .package
        .into_iter()
        // No [package.source] means PyPI; anything else is a private index, git or a path.
        .filter(|p| {
            p.source
                .as_ref()
                .is_none_or(|s| s.url.as_deref().is_some_and(is_public_pypi))
        })
        .map(|p| pypi(&p.name, &p.version, None, true))
        .collect())
}

// ---- Cargo ------------------------------------------------------------------

#[derive(Deserialize)]
struct CargoLock {
    #[serde(default)]
    package: Vec<CargoPackage>,
}

#[derive(Deserialize)]
struct CargoPackage {
    name: String,
    version: String,
    source: Option<String>,
}

/// crates.io, by either of its index addresses.
fn is_crates_io(source: &str) -> bool {
    source == "registry+https://github.com/rust-lang/crates.io-index"
        || source == "sparse+https://index.crates.io/"
}

fn cargo_lock(src: &str) -> Result<Vec<Locked>> {
    let lock: CargoLock = toml::from_str(src).context("invalid Cargo.lock")?;
    Ok(lock
        .package
        .into_iter()
        // No source: a workspace member. git+, path and other registries have no public publish time.
        .filter(|p| p.source.as_deref().is_some_and(is_crates_io))
        .map(|p| Locked {
            pkg: Pkg {
                eco: Ecosystem::Crates,
                name: p.name,
                version: p.version,
            },
            published: None,
            public: true,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(locked: &[Locked]) -> Vec<String> {
        let mut v: Vec<String> = locked
            .iter()
            .map(|l| format!("{}@{}", l.pkg.name, l.pkg.version))
            .collect();
        v.sort();
        v
    }

    #[test]
    fn package_lock_v3() {
        let src = r#"{"lockfileVersion":3,"packages":{
            "":{"name":"root"},
            "packages/app":{"name":"app","version":"1.0.0"},
            "node_modules/app":{"resolved":"packages/app","link":true},
            "node_modules/react":{"version":"19.0.0","resolved":"https://registry.npmjs.org/react/-/react-19.0.0.tgz"},
            "node_modules/a/node_modules/@scope/b":{"version":"2.1.0"},
            "node_modules/alias":{"name":"real","version":"3.0.0"},
            "node_modules/gitdep":{"version":"1.0.0","resolved":"git+ssh://git@github.com/x/y.git#abc"},
            "node_modules/private":{"version":"1.0.0","resolved":"https://npm.example.com/private/-/private-1.0.0.tgz"}
        }}"#;
        let got = npm_lock(src, "https://registry.npmjs.org").unwrap();
        assert_eq!(
            pairs(&got),
            vec!["@scope/b@2.1.0", "react@19.0.0", "real@3.0.0"]
        );
    }

    #[test]
    fn pnpm_lock_all_versions() {
        let v9 = "lockfileVersion: '9.0'\n\nimporters:\n  .:\n    dependencies:\n      react:\n        specifier: ^19\n        version: 19.0.0\n\npackages:\n\n  '@babel/core@7.24.0':\n    resolution: {integrity: sha512-x}\n\n  react@19.0.0:\n    resolution: {integrity: sha512-y}\n\n  tar@https://codeload.github.com/x/tar/tar.gz/abc:\n    resolution: {tarball: https://codeload.github.com/x}\n\n  local@file:../local:\n    resolution: {directory: ../local, type: directory}\n\nsnapshots:\n\n  react@19.0.0: {}\n";
        assert_eq!(
            pairs(&pnpm_lock(v9)),
            vec!["@babel/core@7.24.0", "react@19.0.0"]
        );
        let v6 = "lockfileVersion: '6.0'\npackages:\n  /@types/node@20.1.0:\n    resolution: {integrity: x}\n  /react-dom@18.2.0(react@18.2.0):\n    resolution: {integrity: y}\n";
        assert_eq!(
            pairs(&pnpm_lock(v6)),
            vec!["@types/node@20.1.0", "react-dom@18.2.0"]
        );
        let v5 = "lockfileVersion: 5.4\npackages:\n  /@scope/pkg/1.2.3_react@17.0.2:\n    resolution: {integrity: x}\n";
        assert_eq!(pairs(&pnpm_lock(v5)), vec!["@scope/pkg@1.2.3"]);
    }

    #[test]
    fn yarn_classic_and_berry() {
        let classic = "# yarn lockfile v1\n\n\"@babel/core@^7.0.0\", \"@babel/core@^7.1.0\":\n  version \"7.24.0\"\n  resolved \"https://registry.yarnpkg.com/@babel/core/-/core-7.24.0.tgz#abc\"\n\nalias@npm:real@^1:\n  version \"1.0.0\"\n  resolved \"https://registry.yarnpkg.com/real/-/real-1.0.0.tgz\"\n\nlocal@file:../x:\n  version \"0.0.1\"\n";
        assert_eq!(
            pairs(&yarn_lock(classic, "https://registry.npmjs.org")),
            vec!["@babel/core@7.24.0", "real@1.0.0"]
        );
        let berry = "__metadata:\n  version: 8\n\n\"@scope/a@npm:^1.0.0\":\n  version: 1.2.0\n  resolution: \"@scope/a@npm:1.2.0\"\n\n\"app@workspace:.\":\n  version: 0.0.0-use.local\n  resolution: \"app@workspace:.\"\n\n\"p@patch:p@npm%3A1.0.0#~/.yarn/patches/p.patch\":\n  version: 1.0.0\n  resolution: \"p@patch:p@npm%3A1.0.0#~/.yarn/patches/p.patch::version=1.0.0\"\n";
        assert_eq!(
            pairs(&yarn_lock(berry, "https://registry.npmjs.org")),
            vec!["@scope/a@1.2.0"]
        );
    }

    #[test]
    fn bun_lock_with_trailing_commas() {
        let src = "{\n  \"lockfileVersion\": 1,\n  \"workspaces\": { \"\": { \"name\": \"app\", }, },\n  \"packages\": {\n    \"react\": [\"react@19.0.0\", \"\", {}, \"sha512-x\"],\n    \"@s/b\": [\"@s/b@1.0.0\", \"\", {}, \"sha512-y\",],\n    \"gh\": [\"gh@github:x/y#abc\", {}, \"x-y-abc\"],\n  },\n}\n";
        assert_eq!(
            pairs(&bun_lock(src, "https://registry.npmjs.org").unwrap()),
            vec!["@s/b@1.0.0", "react@19.0.0"]
        );
    }

    #[test]
    fn uv_lock_reads_upload_times() {
        let src = r#"
version = 1
[[package]]
name = "app"
version = "0.1.0"
source = { virtual = "." }

[[package]]
name = "boto3"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://x/boto3.tar.gz", upload-time = "2026-10-30T10:00:00Z" }
wheels = [{ url = "https://x/boto3.whl", upload-time = "2026-10-30T09:00:00Z" }]

[[package]]
name = "old"
version = "2.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "internal"
version = "1.0"
source = { registry = "https://pypi.internal.example/simple" }
"#;
        let got = uv_lock(src).unwrap();
        assert_eq!(pairs(&got), vec!["boto3@1.0.0", "old@2.0"]);
        let boto = got.iter().find(|l| l.pkg.name == "boto3").unwrap();
        assert_eq!(
            boto.published.unwrap().to_rfc3339(),
            "2026-10-30T09:00:00+00:00"
        );
    }

    #[test]
    fn cargo_lock_keeps_crates_io_only() {
        let src = r#"
version = 4

[[package]]
name = "app"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.229"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc"

[[package]]
name = "anyhow"
version = "1.0.104"
source = "sparse+https://index.crates.io/"

[[package]]
name = "forked"
version = "0.3.0"
source = "git+https://github.com/x/forked#abc"

[[package]]
name = "internal"
version = "2.0.0"
source = "sparse+https://crates.example.com/index/"
"#;
        assert_eq!(
            pairs(&cargo_lock(src).unwrap()),
            vec!["anyhow@1.0.104", "serde@1.0.229"]
        );
    }

    #[test]
    fn poetry_lock_skips_private_sources() {
        let src = "[[package]]\nname = \"requests\"\nversion = \"2.32.0\"\n\n[[package]]\nname = \"corp\"\nversion = \"1.0\"\n[package.source]\ntype = \"legacy\"\nurl = \"https://pypi.corp.example/simple\"\nreference = \"corp\"\n";
        assert_eq!(pairs(&poetry_lock(src).unwrap()), vec!["requests@2.32.0"]);
    }
}
