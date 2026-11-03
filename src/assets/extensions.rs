//! Editor and browser extensions: what runs inside the tools that see your
//! code and your accounts. VS Code and the editors built on it (Cursor,
//! Windsurf, VSCodium), Zed, Chromium browsers (Chrome, Brave, Edge, Arc,
//! Vivaldi, Chromium) per profile, and Firefox. A browser extension that can
//! read every site is tagged.

use std::path::{Path, PathBuf};

use serde_json::Value;

use super::{Asset, Ctx, Found, day_from_epoch, file_name, modified_day, subdirs};
use crate::paths::{self, home};
use crate::version::Version;

pub(super) fn discover(_ctx: &Ctx, found: &mut Found) {
    let h = home();
    for (dir, editor) in [
        (h.join(".vscode/extensions"), "VS Code"),
        (h.join(".vscode-insiders/extensions"), "VS Code Insiders"),
        (h.join(".cursor/extensions"), "Cursor"),
        (h.join(".windsurf/extensions"), "Windsurf"),
        (h.join(".vscode-oss/extensions"), "VSCodium"),
    ] {
        for a in vscode(&dir, editor) {
            found.add(a);
        }
    }
    zed(found);
    for (root, browser) in chromium_roots() {
        if found.readable(&root, browser) {
            for a in chromium(&root, browser) {
                found.add(a);
            }
        }
    }
    let firefox_root = firefox_root();
    if !found.readable(&firefox_root, "Firefox") {
        return;
    }
    for profile in subdirs(&firefox_root) {
        if let Ok(text) = std::fs::read_to_string(profile.join("extensions.json")) {
            for a in firefox(&text, &profile) {
                found.add(a);
            }
        }
    }
}

// ---- VS Code and its forks -------------------------------------------------------------

/// Each extension folder (`publisher.name-1.2.3`), newest version of each,
/// skipping those the editor has marked for removal in `.obsolete`.
fn vscode(dir: &Path, editor: &str) -> Vec<Asset> {
    let obsolete: Vec<String> =
        crate::files::read_json::<serde_json::Map<String, Value>>(&dir.join(".obsolete"))
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default();
    let installed: Vec<Value> =
        crate::files::read_json(&dir.join("extensions.json")).unwrap_or_default();
    let mut best: Vec<(String, Option<Version>, Asset)> = Vec::new();
    for ext in subdirs(dir) {
        if obsolete.contains(&file_name(&ext)) {
            continue;
        }
        let Some(pkg) = crate::files::read_json::<Value>(&ext.join("package.json")) else {
            continue;
        };
        let get = |k: &str| {
            pkg.get(k)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let (publisher, name, version) = (get("publisher"), get("name"), get("version"));
        if publisher.is_empty() || name.is_empty() {
            continue;
        }
        let id = format!("{publisher}.{name}").to_lowercase();
        let shown = localized(&get("displayName"), &ext.join("package.nls.json"))
            .unwrap_or_else(|| name.clone());
        let installed_on = installed
            .iter()
            .find(|e| {
                e.pointer("/identifier/id")
                    .and_then(Value::as_str)
                    .is_some_and(|i| i.eq_ignore_ascii_case(&id))
            })
            .and_then(|e| {
                e.pointer("/metadata/installedTimestamp")
                    .and_then(Value::as_i64)
            })
            .and_then(day_from_epoch);
        let asset = Asset::new(format!("{editor}:{id}"), shown, editor)
            .path(&ext)
            .fact("id", &id)
            .fact("version", &version)
            .fact("publisher", publisher)
            .fact_opt("installed", installed_on)
            .fact_opt("updated", modified_day(&ext));
        let v = Version::parse(&version);
        match best.iter_mut().find(|(i, _, _)| *i == id) {
            Some(slot) if v > slot.1 => *slot = (id, v, asset),
            Some(_) => {}
            None => best.push((id, v, asset)),
        }
    }
    best.into_iter().map(|(_, _, a)| a).collect()
}

/// `%displayName%` from `package.nls.json`; a plain name as it is.
fn localized(name: &str, nls: &Path) -> Option<String> {
    if name.is_empty() {
        return None;
    }
    match name.strip_prefix('%').and_then(|n| n.strip_suffix('%')) {
        Some(key) => crate::files::read_json::<Value>(nls)?
            .get(key)
            .and_then(|v| {
                v.as_str()
                    .or_else(|| v.get("message").and_then(Value::as_str))
            })
            .map(str::to_string),
        None => Some(name.to_string()),
    }
}

// ---- Zed -----------------------------------------------------------------------------

fn zed(found: &mut Found) {
    let dir = if cfg!(target_os = "macos") {
        home().join("Library/Application Support/Zed/extensions/installed")
    } else {
        home().join(".local/share/zed/extensions/installed")
    };
    for ext in subdirs(&dir) {
        let Ok(text) = std::fs::read_to_string(ext.join("extension.toml")) else {
            continue;
        };
        let Ok(doc) = text.parse::<toml::Table>() else {
            continue;
        };
        let get = |k: &str| doc.get(k).and_then(toml::Value::as_str).map(str::to_string);
        let id = get("id").unwrap_or_else(|| file_name(&ext));
        found.add(
            Asset::new(
                format!("Zed:{id}"),
                get("name").unwrap_or_else(|| id.clone()),
                "Zed",
            )
            .path(&ext)
            .fact("id", &id)
            .fact_opt("version", get("version"))
            .fact_opt("updated", modified_day(&ext)),
        );
    }
}

// ---- Chromium browsers ---------------------------------------------------------------

fn chromium_roots() -> Vec<(PathBuf, &'static str)> {
    let list: Vec<(&str, &'static str)> = if cfg!(target_os = "macos") {
        vec![
            ("Google/Chrome", "Chrome"),
            ("Google/Chrome Beta", "Chrome Beta"),
            ("Chromium", "Chromium"),
            ("BraveSoftware/Brave-Browser", "Brave"),
            ("Microsoft Edge", "Edge"),
            ("Vivaldi", "Vivaldi"),
            ("Arc/User Data", "Arc"),
        ]
    } else if cfg!(windows) {
        vec![
            ("Google/Chrome/User Data", "Chrome"),
            ("Chromium/User Data", "Chromium"),
            ("BraveSoftware/Brave-Browser/User Data", "Brave"),
            ("Microsoft/Edge/User Data", "Edge"),
            ("Vivaldi/User Data", "Vivaldi"),
        ]
    } else {
        vec![
            ("google-chrome", "Chrome"),
            ("chromium", "Chromium"),
            ("BraveSoftware/Brave-Browser", "Brave"),
            ("microsoft-edge", "Edge"),
            ("vivaldi", "Vivaldi"),
        ]
    };
    let base = if cfg!(target_os = "macos") {
        home().join("Library/Application Support")
    } else if cfg!(windows) {
        paths::local_appdata()
    } else {
        paths::config_root()
    };
    list.into_iter()
        .map(|(rel, name)| (base.join(rel), name))
        .collect()
}

/// Every profile's extensions: `<profile>/Extensions/<id>/<version>/manifest.json`.
fn chromium(root: &Path, browser: &str) -> Vec<Asset> {
    let state: Value = crate::files::read_json(&root.join("Local State")).unwrap_or_default();
    let mut out = Vec::new();
    for profile in subdirs(root) {
        let extensions = profile.join("Extensions");
        if !extensions.is_dir() {
            continue;
        }
        let dir = file_name(&profile);
        let profile_name = state
            .pointer(&format!(
                "/profile/info_cache/{}",
                dir.replace('~', "~0").replace('/', "~1")
            ))
            .and_then(|p| p.get("name"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| dir.clone());
        for ext in subdirs(&extensions) {
            let id = file_name(&ext);
            if id == "Temp" {
                continue;
            }
            // Version folders are `1.2.3_0`; the newest is the one in use.
            let Some(version_dir) = subdirs(&ext)
                .into_iter()
                .max_by_key(|v| Version::parse(&file_name(v)))
            else {
                continue;
            };
            let Some(manifest) =
                crate::files::read_json::<Value>(&version_dir.join("manifest.json"))
            else {
                continue;
            };
            // Themes change colours only.
            if manifest.get("theme").is_some() {
                continue;
            }
            let name = manifest_name(&manifest, &version_dir).unwrap_or_else(|| id.clone());
            out.push(
                Asset::new(format!("{browser}:{dir}:{id}"), name, browser)
                    .path(&version_dir)
                    .fact("id", &id)
                    .fact_opt("version", manifest.get("version").and_then(Value::as_str))
                    .fact("profile", &profile_name)
                    .fact_opt("updated", modified_day(&version_dir))
                    .tag_if(reads_every_site(&manifest), "allSites"),
            );
        }
    }
    out
}

/// The manifest's name, looked up in `_locales` when it is `__MSG_key__`.
fn manifest_name(manifest: &Value, dir: &Path) -> Option<String> {
    let name = manifest.get("name").and_then(Value::as_str)?;
    let Some(key) = name
        .strip_prefix("__MSG_")
        .and_then(|n| n.strip_suffix("__"))
    else {
        return Some(name.to_string());
    };
    let locale = manifest
        .get("default_locale")
        .and_then(Value::as_str)
        .unwrap_or("en");
    let messages: Value =
        crate::files::read_json(&dir.join("_locales").join(locale).join("messages.json"))?;
    messages
        .as_object()?
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .and_then(|(_, v)| v.get("message").and_then(Value::as_str))
        .map(str::to_string)
}

/// Host access to every site: `<all_urls>` or a `*` host, in permissions,
/// host permissions or content scripts.
fn reads_every_site(manifest: &Value) -> bool {
    let patterns = [
        "permissions",
        "host_permissions",
        "optional_host_permissions",
    ]
    .iter()
    .filter_map(|k| manifest.get(*k).and_then(Value::as_array))
    .flatten()
    .chain(
        manifest
            .get("content_scripts")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|c| c.get("matches").and_then(Value::as_array))
            .flatten(),
    )
    .filter_map(Value::as_str);
    patterns.into_iter().any(all_sites)
}

fn all_sites(pattern: &str) -> bool {
    if pattern == "<all_urls>" {
        return true;
    }
    pattern
        .split_once("://")
        .is_some_and(|(_, rest)| rest.split('/').next() == Some("*"))
}

// ---- Firefox -----------------------------------------------------------------------

fn firefox_root() -> PathBuf {
    if cfg!(target_os = "macos") {
        home().join("Library/Application Support/Firefox/Profiles")
    } else if cfg!(windows) {
        paths::appdata().join("Mozilla/Firefox/Profiles")
    } else {
        home().join(".mozilla/firefox")
    }
}

/// `extensions.json`: extensions the user installed (`app-profile`), not
/// Firefox's own.
fn firefox(text: &str, profile: &Path) -> Vec<Asset> {
    let Ok(doc) = serde_json::from_str::<Value>(text) else {
        return Vec::new();
    };
    let dir = file_name(profile);
    let profile_name = dir
        .split_once('.')
        .map_or(dir.as_str(), |(_, n)| n)
        .to_string();
    doc.get("addons")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|a| a.get("type").and_then(Value::as_str) == Some("extension"))
        .filter(|a| a.get("location").and_then(Value::as_str) == Some("app-profile"))
        .filter_map(|a| {
            let id = a.get("id").and_then(Value::as_str)?.to_string();
            let name = a
                .pointer("/defaultLocale/name")
                .and_then(Value::as_str)
                .unwrap_or(&id)
                .to_string();
            let origins = a
                .pointer("/userPermissions/origins")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .any(all_sites);
            let active = a.get("active").and_then(Value::as_bool).unwrap_or(true);
            let mut asset = Asset::new(format!("Firefox:{dir}:{id}"), name, "Firefox")
                .fact("id", &id)
                .fact_opt("version", a.get("version").and_then(Value::as_str))
                .fact("profile", &profile_name)
                .fact_opt(
                    "installed",
                    a.get("installDate")
                        .and_then(Value::as_i64)
                        .and_then(day_from_epoch),
                )
                .tag_if(origins, "allSites")
                .tag_if(!active, "disabled");
            if let Some(path) = a.get("path").and_then(Value::as_str) {
                asset = asset.path(path);
            }
            Some(asset)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_site_patterns() {
        assert!(all_sites("<all_urls>"));
        assert!(all_sites("*://*/*"));
        assert!(all_sites("https://*/"));
        assert!(!all_sites("https://*.google.com/*"));
        assert!(!all_sites("https://docs.google.com/*"));
        assert!(!all_sites("storage"));
        let m: Value = serde_json::from_str(
            r#"{"permissions":["tabs"],"content_scripts":[{"matches":["<all_urls>"]}]}"#,
        )
        .unwrap();
        assert!(reads_every_site(&m));
    }

    #[test]
    fn firefox_user_extensions_only() {
        let text = r#"{"addons":[
            {"id":"formautofill@mozilla.org","type":"extension","location":"app-builtin-addons","defaultLocale":{"name":"Form Autofill"}},
            {"id":"ublock0@raymondhill.net","type":"extension","location":"app-profile","version":"1.60.0","active":true,"installDate":1792610529000,"defaultLocale":{"name":"uBlock Origin"},"userPermissions":{"origins":["<all_urls>"]}},
            {"id":"t@x","type":"theme","location":"app-profile"}
        ]}"#;
        let list = firefox(text, Path::new("/p/abcd.default-release"));
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "uBlock Origin");
        assert_eq!(list[0].get("profile"), Some("default-release"));
        assert_eq!(list[0].get("installed"), Some("2026-10-21"));
        assert_eq!(list[0].tags[0].key, "allSites");
    }

    #[test]
    fn localized_names() {
        let dir = std::env::temp_dir().join(format!("lenstica-ext-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("_locales/en_US")).unwrap();
        std::fs::write(
            dir.join("_locales/en_US/messages.json"),
            r#"{"extName":{"message":"Google Docs Offline"}}"#,
        )
        .unwrap();
        std::fs::write(dir.join("package.nls.json"), r#"{"displayName":"Python"}"#).unwrap();
        let m: Value =
            serde_json::from_str(r#"{"name":"__MSG_EXTNAME__","default_locale":"en_US"}"#).unwrap();
        assert_eq!(
            manifest_name(&m, &dir).as_deref(),
            Some("Google Docs Offline")
        );
        assert_eq!(
            localized("%displayName%", &dir.join("package.nls.json")).as_deref(),
            Some("Python")
        );
        assert_eq!(
            localized("Plain", &dir.join("none.json")).as_deref(),
            Some("Plain")
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
