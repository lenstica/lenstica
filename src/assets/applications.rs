//! Installed applications. On macOS, every app in `/Applications` and
//! `~/Applications` (and the folders inside them), with its version, bundle
//! identifier, and where it came from: the App Store, Homebrew, or Apple.
//! On Linux, the desktop entries of installed programs, Flatpaks and Snaps.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::{Asset, Ctx, Found, file_name, modified_day, subdirs};
use crate::paths::home;

#[cfg(target_os = "macos")]
pub(super) fn discover(_ctx: &Ctx, found: &mut Found) {
    let casks = cask_apps();
    for root in [PathBuf::from("/Applications"), home().join("Applications")] {
        for app in apps_in(&root) {
            if let Some(a) = mac_app(&app, &casks) {
                found.add(a);
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub(super) fn discover(_ctx: &Ctx, found: &mut Found) {
    let h = home();
    let dirs = [
        (PathBuf::from("/usr/share/applications"), ""),
        (PathBuf::from("/usr/local/share/applications"), ""),
        (h.join(".local/share/applications"), ""),
        (
            PathBuf::from("/var/lib/flatpak/exports/share/applications"),
            "Flatpak",
        ),
        (
            h.join(".local/share/flatpak/exports/share/applications"),
            "Flatpak",
        ),
        (PathBuf::from("/var/lib/snapd/desktop/applications"), "Snap"),
    ];
    for (dir, source) in dirs {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for path in entries.flatten().map(|e| e.path()) {
            if path.extension().is_some_and(|e| e == "desktop")
                && let Ok(text) = std::fs::read_to_string(&path)
                && let Some(a) = desktop_entry(&text, &path, source)
            {
                found.add(a);
            }
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(super) fn discover(_ctx: &Ctx, _found: &mut Found) {}

/// The `.app` bundles in a folder, and in the folders inside it that are not
/// apps themselves (`/Applications/Utilities`, a vendor's folder).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn apps_in(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in subdirs(root) {
        if entry.extension().is_some_and(|e| e == "app") {
            out.push(entry);
        } else {
            out.extend(
                subdirs(&entry)
                    .into_iter()
                    .filter(|p| p.extension().is_some_and(|e| e == "app")),
            );
        }
    }
    out
}

/// App bundle names Homebrew casks installed (`Firefox.app` -> `firefox`),
/// from each cask's install receipt.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn cask_apps() -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for prefix in crate::lenses::software::brew_prefixes() {
        for cask in subdirs(&prefix.join("Caskroom")) {
            let receipt = cask.join(".metadata/INSTALL_RECEIPT.json");
            let Some(doc) = crate::files::read_json::<serde_json::Value>(&receipt) else {
                continue;
            };
            for name in receipt_apps(&doc) {
                out.insert(name, file_name(&cask));
            }
        }
    }
    out
}

fn receipt_apps(doc: &serde_json::Value) -> Vec<String> {
    doc.get("uninstall_artifacts")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|a| a.get("app").and_then(serde_json::Value::as_array))
        .flatten()
        .filter_map(|v| v.as_str())
        // `{ target: … }` forms rename the app; the plain name is enough here.
        .map(|s| s.rsplit('/').next().unwrap_or(s).to_string())
        .collect()
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn mac_app(app: &Path, casks: &BTreeMap<String, String>) -> Option<Asset> {
    // Safari and other system apps are links into the sealed system volume.
    if std::fs::symlink_metadata(app).is_ok_and(|m| m.file_type().is_symlink()) {
        return None;
    }
    let info = plist::Value::from_file(app.join("Contents/Info.plist")).ok();
    let get = |key: &str| {
        info.as_ref()
            .and_then(|v| v.as_dictionary())
            .and_then(|d| d.get(key))
            .and_then(|v| v.as_string())
            .map(str::to_string)
    };
    let bundle = file_name(app);
    let name = bundle.trim_end_matches(".app").to_string();
    let id = get("CFBundleIdentifier");
    let source = if app.join("Contents/_MASReceipt/receipt").is_file() {
        "App Store"
    } else if casks.contains_key(&bundle) {
        "Homebrew"
    } else if id.as_deref().is_some_and(|i| i.starts_with("com.apple.")) {
        "Apple"
    } else {
        ""
    };
    Some(
        Asset::new(app.to_string_lossy(), name, source)
            .path(app)
            .fact_opt(
                "version",
                get("CFBundleShortVersionString").or_else(|| get("CFBundleVersion")),
            )
            .fact_opt("bundleId", id)
            .fact_opt("updated", modified_day(app)),
    )
}

/// A `.desktop` file that shows in the menu: its name and version.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn desktop_entry(text: &str, path: &Path, source: &str) -> Option<Asset> {
    let mut in_entry = false;
    let mut get = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_entry = line == "[Desktop Entry]";
            continue;
        }
        if in_entry && let Some((k, v)) = line.split_once('=') {
            get.entry(k.trim().to_string())
                .or_insert_with(|| v.trim().to_string());
        }
    }
    let hidden = |k: &str| get.get(k).is_some_and(|v| v == "true");
    if get.get("Type").is_some_and(|t| t != "Application")
        || hidden("NoDisplay")
        || hidden("Hidden")
    {
        return None;
    }
    let name = get.get("Name")?.clone();
    let id = file_name(path).trim_end_matches(".desktop").to_string();
    Some(
        Asset::new(path.to_string_lossy(), name, source)
            .path(path)
            .fact("bundleId", id)
            .fact_opt("updated", modified_day(path)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apps_named_in_a_cask_receipt() {
        let doc: serde_json::Value =
            serde_json::from_str(r#"{"uninstall_artifacts":[{"uninstall":[{"quit":"x"}]},{"app":["Visual Studio Code.app"]}]}"#).unwrap();
        assert_eq!(receipt_apps(&doc), ["Visual Studio Code.app"]);
    }

    #[test]
    fn desktop_entries_that_show() {
        let text = "[Desktop Entry]\nType=Application\nName=Firefox\nName[uk]=Firefox UA\nExec=firefox %u\n[Desktop Action new]\nName=New window\n";
        let a = desktop_entry(
            text,
            Path::new("/usr/share/applications/firefox.desktop"),
            "",
        )
        .unwrap();
        assert_eq!(a.name, "Firefox");
        assert_eq!(a.get("bundleId"), Some("firefox"));
        assert!(
            desktop_entry(
                "[Desktop Entry]\nType=Application\nName=X\nNoDisplay=true\n",
                Path::new("/x.desktop"),
                ""
            )
            .is_none()
        );
    }
}
