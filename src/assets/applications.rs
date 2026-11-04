//! Installed applications and what each is allowed to do.
//!
//! On macOS, every app in `/Applications` and `~/Applications` (and the
//! folders inside them), with its version, bundle identifier, and where it
//! came from: the App Store, Homebrew, or Apple. Each carries the permissions
//! System Settings scatters over Privacy & Security and Login Items &
//! Extensions; an app or program elsewhere that holds one (Terminal, a
//! Homebrew binary, a vendor's helper) is listed too, so every grant shows.
//!
//! On Linux, the desktop entries of installed programs and Snaps, every
//! Flatpak with what its sandbox lets through, and AppImages, which have no
//! sandbox.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[cfg(any(target_os = "macos", target_os = "linux"))]
use super::permissions;
use super::permissions::{Extension, Grant};
use super::{Asset, Ctx, Found, file_name, modified_day, subdirs};
#[cfg(any(target_os = "macos", target_os = "linux"))]
use crate::paths::home;

#[cfg(target_os = "macos")]
pub(super) fn discover(ctx: &Ctx, found: &mut Found) {
    let casks = cask_apps();
    let mut apps: Vec<Asset> = Vec::new();
    for root in [PathBuf::from("/Applications"), home().join("Applications")] {
        apps.extend(apps_in(&root).iter().filter_map(|app| mac_app(app, &casks)));
    }
    let grants = permissions::tcc(ctx, found);
    let extensions = permissions::system_extensions(ctx);
    let missing: BTreeSet<String> = grants
        .iter()
        .filter(|g| !g.by_path && by_bundle(&apps, &g.client).is_none())
        .map(|g| g.client.clone())
        .collect();
    for app in spotlight(ctx, &missing) {
        if let Some(a) = mac_app(&app, &casks)
            && !apps.iter().any(|x| {
                x.id == a.id
                    || (x.get("bundleId").is_some() && x.get("bundleId") == a.get("bundleId"))
            })
        {
            apps.push(a);
        }
    }
    attach(&mut apps, grants, extensions);
    for a in apps {
        found.add(a);
    }
}

#[cfg(target_os = "linux")]
pub(super) fn discover(ctx: &Ctx, found: &mut Found) {
    let h = home();
    let dirs = [
        (PathBuf::from("/usr/share/applications"), ""),
        (PathBuf::from("/usr/local/share/applications"), ""),
        (h.join(".local/share/applications"), ""),
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
    flatpaks(ctx, found);
    appimages(found);
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(super) fn discover(_ctx: &Ctx, _found: &mut Found) {}

// ---- macOS ---------------------------------------------------------------------------

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
    // Safari and other system apps in /Applications are links into the sealed system volume.
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
    } else if id.as_deref().is_some_and(|i| i.starts_with("com.apple."))
        || app.starts_with("/System")
    {
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

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn by_bundle(apps: &[Asset], id: &str) -> Option<usize> {
    apps.iter().position(|a| a.get("bundleId") == Some(id))
}

/// Apps outside the Applications folders that hold a grant (Terminal, a
/// vendor's helper), found by bundle identifier with one Spotlight query.
/// The copy in a system or Applications folder wins over backups and builds.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn spotlight(ctx: &Ctx, ids: &BTreeSet<String>) -> Vec<PathBuf> {
    let mdfind = Path::new("/usr/bin/mdfind");
    if ids.is_empty() || !mdfind.exists() {
        return Vec::new();
    }
    let query = ids
        .iter()
        .map(|id| {
            format!(
                "kMDItemCFBundleIdentifier == \"{}\"",
                id.replace(['"', '\\'], "")
            )
        })
        .collect::<Vec<_>>()
        .join(" || ");
    let Ok(out) = ctx.run(mdfind, &[&query]) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = out
        .stdout
        .lines()
        .map(PathBuf::from)
        .filter(|p| p.extension().is_some_and(|e| e == "app"))
        .filter(|p| {
            !p.components()
                .any(|c| c.as_os_str() == "DerivedData" || c.as_os_str() == "Backups.backupdb")
        })
        .collect();
    let rank = |p: &Path| {
        let preferred = ["/System/", "/Applications/", "/Library/"]
            .iter()
            .any(|r| p.starts_with(r));
        (!preferred, p.as_os_str().len())
    };
    paths.sort_by_key(|p| rank(p));
    paths
}

/// Give each app its grants and system extensions. A grant held by a
/// program, or by an app found nowhere, becomes an entry of its own.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn attach(apps: &mut Vec<Asset>, grants: Vec<Grant>, extensions: Vec<Extension>) {
    let names: BTreeMap<String, String> = apps
        .iter()
        .filter_map(|a| Some((a.get("bundleId")?.to_string(), a.name.clone())))
        .collect();
    for g in grants {
        let mut p = g.permission;
        // Automation names the app it controls.
        if let Some(name) = names.get(&p.detail) {
            p.detail = name.clone();
        }
        let at = if g.by_path {
            apps.iter().position(|a| {
                a.path
                    .as_ref()
                    .is_some_and(|dir| Path::new(&g.client).starts_with(dir))
            })
        } else {
            by_bundle(apps, &g.client)
        };
        let i = match at {
            Some(i) => i,
            // A permission turned off, held by nothing else listed, is no news.
            None if !p.allowed => continue,
            None => {
                apps.push(holder(&g.client, g.by_path));
                apps.len() - 1
            }
        };
        apps[i].permit(p);
    }
    for e in extensions {
        // The app whose bundle identifier the extension's starts with, the longest.
        let owner = apps
            .iter()
            .enumerate()
            .filter_map(|(i, a)| {
                let id = a.get("bundleId")?;
                e.id.starts_with(&format!("{id}.")).then_some((id.len(), i))
            })
            .max()
            .map(|(_, i)| i);
        let i = owner.unwrap_or_else(|| {
            apps.push(
                Asset::new(format!("sysext:{}", e.id), e.permission.detail.clone(), "")
                    .fact("bundleId", &e.id),
            );
            apps.len() - 1
        });
        apps[i].permit(e.permission);
    }
}

/// An entry for whatever holds a grant but is no app in the list: a program
/// (by path; inside an app bundle, that app), or an app Spotlight could not
/// find (by bundle identifier): often one removed with its grant left behind.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn holder(client: &str, by_path: bool) -> Asset {
    if !by_path {
        let source = if client.starts_with("com.apple.") {
            "Apple"
        } else {
            ""
        };
        return Asset::new(format!("bundle:{client}"), client, source)
            .fact("bundleId", client)
            .tag_if(true, "notFound");
    }
    let path = Path::new(client);
    let source = if path
        .components()
        .any(|c| c.as_os_str() == "Cellar" || c.as_os_str() == "Caskroom")
    {
        "Homebrew"
    } else if ["/System/", "/usr/", "/bin/", "/sbin/"]
        .iter()
        .any(|p| client.starts_with(p))
    {
        "Apple"
    } else {
        ""
    };
    // The app bundle a program sits in names it best.
    let bundle = path
        .ancestors()
        .find(|a| a.extension().is_some_and(|e| e == "app"));
    let name = match bundle {
        Some(app) => file_name(app).trim_end_matches(".app").to_string(),
        // `~/.local/share/claude/versions/2.1.227`: a version, named by what it is a version of.
        None if file_name(path).starts_with(|c: char| c.is_ascii_digit()) => {
            let of = path
                .parent()
                .and_then(Path::parent)
                .map(file_name)
                .unwrap_or_default();
            format!("{of} {}", file_name(path)).trim().to_string()
        }
        None => file_name(path),
    };
    let mut a = Asset::new(client, name, source).path(bundle.unwrap_or(path));
    if !path.exists() {
        a = a.tag_if(true, "notFound");
    }
    a
}

// ---- Linux ---------------------------------------------------------------------------

/// A `.desktop` file that shows in the menu: its name. AppImages' entries
/// are left to [`appimages`], which finds the files themselves.
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
    let appimage = get.keys().any(|k| k.starts_with("X-AppImage"))
        || get
            .get("Exec")
            .is_some_and(|e| e.to_ascii_lowercase().contains(".appimage"));
    if get.get("Type").is_some_and(|t| t != "Application")
        || hidden("NoDisplay")
        || hidden("Hidden")
        || appimage
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

/// Every installed Flatpak app, system-wide and yours, with its permissions.
#[cfg(target_os = "linux")]
fn flatpaks(ctx: &Ctx, found: &mut Found) {
    let h = home();
    let system = PathBuf::from("/var/lib/flatpak");
    let user = h.join(".local/share/flatpak");
    // Names and versions, when the flatpak tool is there to say.
    let listed: BTreeMap<String, (String, String)> = ctx
        .find("flatpak")
        .and_then(|f| {
            ctx.run(&f, &["list", "--app", "--columns=application,name,version"])
                .ok()
        })
        .map(|o| {
            o.stdout
                .lines()
                .filter_map(|l| {
                    let mut cols = l.split('\t');
                    let id = cols.next()?.trim().to_string();
                    Some((
                        id,
                        (
                            cols.next().unwrap_or_default().trim().to_string(),
                            cols.next().unwrap_or_default().trim().to_string(),
                        ),
                    ))
                })
                .collect()
        })
        .unwrap_or_default();
    for root in [&system, &user] {
        for app in subdirs(&root.join("app")) {
            let id = file_name(&app);
            let active = app.join("current/active");
            let Ok(metadata) = std::fs::read_to_string(active.join("metadata")) else {
                continue;
            };
            let overrides: Vec<String> = [
                system.join("overrides/global"),
                system.join(format!("overrides/{id}")),
                user.join("overrides/global"),
                user.join(format!("overrides/{id}")),
            ]
            .iter()
            .filter_map(|p| std::fs::read_to_string(p).ok())
            .collect();
            let (name, version) = listed.get(&id).cloned().unwrap_or_default();
            let name = if name.is_empty() {
                std::fs::read_to_string(
                    active.join(format!("export/share/applications/{id}.desktop")),
                )
                .ok()
                .and_then(|t| desktop_entry(&t, Path::new("x.desktop"), "").map(|a| a.name))
                .unwrap_or_else(|| id.clone())
            } else {
                name
            };
            let mut a = Asset::new(format!("flatpak:{id}"), name, "Flatpak")
                .path(&app)
                .fact("version", version)
                .fact("bundleId", &id)
                .fact_opt("updated", modified_day(&active));
            for p in permissions::flatpak(&metadata, &overrides) {
                a.permit(p);
            }
            found.add(a);
        }
    }
}

/// AppImages in the folders people keep them in: they run with everything
/// your user can do.
#[cfg(target_os = "linux")]
fn appimages(found: &mut Found) {
    let h = home();
    let mut dirs = vec![
        h.join("Applications"),
        h.join("AppImages"),
        h.join(".local/bin"),
        h.join("Downloads"),
        h.join("Desktop"),
        PathBuf::from("/opt"),
    ];
    for d in [h.join("Applications"), PathBuf::from("/opt")] {
        dirs.extend(subdirs(&d));
    }
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for path in entries.flatten().map(|e| e.path()) {
            let file = file_name(&path);
            if !path.is_file() || !file.to_ascii_lowercase().ends_with(".appimage") {
                continue;
            }
            let (name, version) = permissions::appimage_name(&file);
            let mut a = Asset::new(path.to_string_lossy(), name, "AppImage")
                .path(&path)
                .fact_opt("version", version)
                .fact_opt("updated", modified_day(&path));
            a.permit(super::Permission::new("unsandboxed", true));
            found.add(a);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assets::Permission;

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
        assert!(
            desktop_entry(
                "[Desktop Entry]\nType=Application\nName=X\nExec=/home/a/Applications/X.AppImage\n",
                Path::new("/x.desktop"),
                ""
            )
            .is_none()
        );
    }

    #[test]
    fn grants_go_to_their_apps_or_their_own_entries() {
        let mut apps = vec![
            Asset::new("/Applications/Discord.app", "Discord", "")
                .path("/Applications/Discord.app")
                .fact("bundleId", "com.hnc.Discord"),
            Asset::new("/Applications/Tailscale.app", "Tailscale", "")
                .path("/Applications/Tailscale.app")
                .fact("bundleId", "io.tailscale.ipn.macsys"),
            Asset::new("bundle:com.apple.systemevents", "System Events", "Apple")
                .fact("bundleId", "com.apple.systemevents"),
        ];
        let grant = |client: &str, by_path: bool, p: Permission| Grant {
            client: client.into(),
            by_path,
            permission: p,
        };
        let grants = vec![
            grant(
                "com.hnc.Discord",
                false,
                Permission::new("screenRecording", true),
            ),
            grant("com.hnc.Discord", false, Permission::new("camera", false)),
            grant(
                "com.hnc.Discord",
                false,
                Permission::new("automation", true).detail("com.apple.systemevents"),
            ),
            grant(
                "/opt/homebrew/Cellar/yabai/7.1.25/bin/yabai",
                true,
                Permission::new("accessibility", true),
            ),
            grant(
                "/opt/homebrew/Cellar/yabai/7.1.25/bin/yabai",
                true,
                Permission::new("screenRecording", true),
            ),
            grant(
                "com.example.helper",
                false,
                Permission::new("fullDiskAccess", true),
            ),
            grant("com.example.gone", false, Permission::new("camera", false)),
        ];
        let extensions = vec![Extension {
            id: "io.tailscale.ipn.macsys.network-extension".into(),
            permission: Permission::new("networkExtension", true)
                .detail("Tailscale Network Extension"),
        }];
        attach(&mut apps, grants, extensions);
        assert_eq!(apps.len(), 5, "a camera grant turned off adds no entry");
        let discord = &apps[0];
        let keys: Vec<(&str, bool)> = discord
            .permissions
            .iter()
            .map(|p| (p.key, p.allowed))
            .collect();
        assert_eq!(
            keys,
            [
                ("screenRecording", true),
                ("automation", true),
                ("camera", false)
            ]
        );
        assert_eq!(discord.permissions[1].detail, "System Events");
        assert!(discord.tags.iter().any(|t| t.key == "elevated"));
        assert_eq!(apps[1].permissions[0].key, "networkExtension");
        let yabai = &apps[3];
        assert_eq!(
            (yabai.name.as_str(), yabai.source.as_str()),
            ("yabai", "Homebrew")
        );
        assert_eq!(yabai.permissions.len(), 2);
        assert_eq!(apps[4].name, "com.example.helper");
        assert!(apps[4].tags.iter().any(|t| t.key == "notFound"));
        assert_eq!(
            holder("/Users/a/.local/share/claude/versions/2.1.227", true).name,
            "claude 2.1.227"
        );
        let inside = holder(
            "/Applications/Arturia/Mini V4.app/Contents/MacOS/Mini V4",
            true,
        );
        assert_eq!(inside.name, "Mini V4");
        assert_eq!(
            inside.path.as_deref(),
            Some(Path::new("/Applications/Arturia/Mini V4.app"))
        );
    }
}
