//! What apps are allowed to do beyond their own files.
//!
//! On macOS, the grants System Settings → Privacy & Security shows, spread
//! over a dozen panes: read from the two TCC databases (the system's, for Full
//! Disk Access, Accessibility, Screen Recording, Input Monitoring and the
//! like; yours, for the camera, microphone, folders, Automation…). macOS lets
//! only apps with Full Disk Access read them. And the system extensions an
//! app installed (network, endpoint security, driver, camera), which
//! `systemextensionsctl` lists to anyone.
//!
//! On Linux, what a Flatpak's sandbox lets through (its manifest's
//! `[Context]` and bus policy, with the system's and your overrides), and
//! AppImages, which run with no sandbox at all.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::{Ctx, Found, Permission, SetBy};
use crate::paths::home;

/// One grant in a TCC database: who holds it, and what.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Grant {
    /// A bundle identifier, or a program's path.
    pub client: String,
    pub by_path: bool,
    pub permission: Permission,
}

/// TCC's service names, and the permission each is.
const SERVICES: &[(&str, &str)] = &[
    ("kTCCServiceSystemPolicyAllFiles", "fullDiskAccess"),
    ("kTCCServiceAccessibility", "accessibility"),
    // Sending keystrokes and clicks is granted under Accessibility.
    ("kTCCServicePostEvent", "accessibility"),
    ("kTCCServiceScreenCapture", "screenRecording"),
    ("kTCCServiceAudioCapture", "screenRecording"),
    ("kTCCServiceListenEvent", "inputMonitoring"),
    ("kTCCServiceAppleEvents", "automation"),
    ("kTCCServiceDeveloperTool", "developerTools"),
    ("kTCCServiceSystemPolicyAppBundles", "appManagement"),
    ("kTCCServiceSystemPolicyAppData", "appData"),
    ("kTCCServiceEndpointSecurityClient", "endpointSecurity"),
    ("kTCCServiceRemoteDesktop", "remoteDesktop"),
    ("kTCCServiceCamera", "camera"),
    ("kTCCServiceMicrophone", "microphone"),
    ("kTCCServiceAddressBook", "contacts"),
    ("kTCCServiceCalendar", "calendars"),
    ("kTCCServiceReminders", "reminders"),
    ("kTCCServicePhotos", "photos"),
    ("kTCCServicePhotosAdd", "photos"),
    ("kTCCServiceSystemPolicyDesktopFolder", "desktopFolder"),
    ("kTCCServiceSystemPolicyDocumentsFolder", "documentsFolder"),
    ("kTCCServiceSystemPolicyDownloadsFolder", "downloadsFolder"),
    ("kTCCServiceSystemPolicyNetworkVolumes", "networkVolumes"),
    (
        "kTCCServiceSystemPolicyRemovableVolumes",
        "removableVolumes",
    ),
    ("kTCCServiceMediaLibrary", "mediaLibrary"),
    ("kTCCServiceSpeechRecognition", "speechRecognition"),
    ("kTCCServiceBluetoothAlways", "bluetooth"),
    ("kTCCServiceMotion", "motion"),
    ("kTCCServiceFocusStatus", "focus"),
    ("kTCCServiceWillow", "home"),
    ("kTCCServiceWebBrowserPublicKeyCredential", "passkeys"),
];

const TCC_QUERY: &str = "SELECT service, client, client_type, auth_value, auth_reason, indirect_object_identifier FROM access";

/// The name blocked sources go by when macOS keeps them from Lenstica.
pub(super) const PRIVACY: &str = "Privacy & Security permissions";

/// Every grant in both TCC databases. One macOS will not let this app read
/// without Full Disk Access is noted as blocked.
///
/// macOS 27 moved the per-user database out of `~/Library` into a protected
/// system container no other app may open, even with Full Disk Access; when
/// it is not where earlier versions keep it, that is noted instead, so the
/// window does not ask for access that would not help.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(super) fn tcc(ctx: &Ctx, found: &mut Found) -> Vec<Grant> {
    let sqlite = Path::new("/usr/bin/sqlite3");
    if !sqlite.exists() {
        return Vec::new();
    }
    let user = home().join("Library/Application Support/com.apple.TCC/TCC.db");
    let mut dbs = vec![PathBuf::from(
        "/Library/Application Support/com.apple.TCC/TCC.db",
    )];
    match std::fs::metadata(&user) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            found.notes.push("userPermissionsHidden")
        }
        // There, or there but protected: sqlite3 says which.
        _ => dbs.push(user),
    }
    let mut out = Vec::new();
    for db in dbs {
        let db_arg = db.to_string_lossy();
        match ctx.run(sqlite, &["-readonly", "-json", &db_arg, TCC_QUERY]) {
            Ok(o) if o.success => out.extend(parse_tcc(&o.stdout)),
            Ok(o) => {
                let said = o.stderr.to_ascii_lowercase();
                if said.contains("authorization denied") || said.contains("unable to open") {
                    if !found.blocked.iter().any(|b| b == PRIVACY) {
                        found.blocked.push(PRIVACY.to_string());
                    }
                } else {
                    found.error("TCC", o.error_text());
                }
            }
            Err(e) => found.error("TCC", format!("{e:#}")),
        }
    }
    out
}

/// `sqlite3 -json` rows of the `access` table.
pub(super) fn parse_tcc(json: &str) -> Vec<Grant> {
    let rows: Vec<Value> = serde_json::from_str(json.trim()).unwrap_or_default();
    rows.iter()
        .filter_map(|r| {
            let service = r.get("service")?.as_str()?;
            let key = SERVICES.iter().find(|(s, _)| *s == service)?.1;
            let client = r.get("client")?.as_str()?.to_string();
            let auth = r.get("auth_value").and_then(Value::as_i64).unwrap_or(0);
            // 2 allowed, 3 limited (some photos); 0 denied, 1 not decided.
            let allowed = auth == 2 || auth == 3;
            // 2 allowed at a prompt, 3 set by a tool, 4 switched in System
            // Settings: you. 6 and 7 a management profile. 5, 11 and 12 the
            // system's own policy or the app's entitlement.
            let by = match r.get("auth_reason").and_then(Value::as_i64) {
                Some(2..=4) => Some(SetBy::User),
                Some(6 | 7) => Some(SetBy::Organization),
                Some(5 | 11 | 12) => Some(SetBy::System),
                _ => None,
            };
            let target = r
                .get("indirect_object_identifier")
                .and_then(Value::as_str)
                .filter(|t| key == "automation" && !t.is_empty() && *t != "UNUSED")
                .unwrap_or_default();
            Some(Grant {
                client,
                by_path: r.get("client_type").and_then(Value::as_i64) == Some(1),
                permission: Permission::new(key, allowed).by(by).detail(target),
            })
        })
        .collect()
}

/// One system extension: its bundle identifier and what it is allowed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Extension {
    pub id: String,
    pub permission: Permission,
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(super) fn system_extensions(ctx: &Ctx) -> Vec<Extension> {
    let tool = Path::new("/usr/bin/systemextensionsctl");
    if !tool.exists() {
        return Vec::new();
    }
    ctx.run(tool, &["list"])
        .map(|o| parse_system_extensions(&o.stdout))
        .unwrap_or_default()
}

/// `systemextensionsctl list`: a `--- com.apple.system_extension.<kind>`
/// line per kind, then tab-separated rows: enabled, active, team, `id
/// (version)`, name, `[state]`. Ones on their way out are left out.
pub(super) fn parse_system_extensions(text: &str) -> Vec<Extension> {
    let mut kind = "";
    let mut out = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("--- com.apple.system_extension.") {
            kind = match rest.split_whitespace().next().unwrap_or_default() {
                "network_extension" => "networkExtension",
                "endpoint_security" => "endpointSecurity",
                "driver_extension" => "driverExtension",
                "cmio" => "cameraExtension",
                _ => "",
            };
            continue;
        }
        let cols: Vec<&str> = line.split('\t').collect();
        if kind.is_empty() || cols.len() < 6 || cols[3] == "bundleID (version)" {
            continue;
        }
        let state = cols[5];
        if state.contains("uninstall") || state.contains("terminated") {
            continue;
        }
        let id = cols[3].split(" (").next().unwrap_or_default().to_string();
        let allowed = cols[0].trim() == "*" && state.contains("activated enabled");
        out.push(Extension {
            id,
            permission: Permission::new(kind, allowed).detail(cols[4].trim()),
        });
    }
    out
}

// ---- Linux: Flatpak and AppImage ----------------------------------------------------------

/// A Flatpak's permissions: its manifest's `metadata`, then the system's
/// overrides, then yours (each may add, or take away with `!`).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(super) fn flatpak(metadata: &str, overrides: &[String]) -> Vec<Permission> {
    let mut lists: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut buses: BTreeMap<(String, String), String> = BTreeMap::new();
    for text in std::iter::once(metadata).chain(overrides.iter().map(String::as_str)) {
        let mut section = String::new();
        for line in text.lines() {
            let line = line.trim();
            if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                section = name.to_string();
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            let (k, v) = (k.trim(), v.trim());
            if section == "Context" {
                let list = lists.entry(k.to_string()).or_default();
                for item in v.split(';').map(str::trim).filter(|i| !i.is_empty()) {
                    match item.strip_prefix('!') {
                        Some(gone) => list.retain(|x| x != gone),
                        None if !list.iter().any(|x| x == item) => list.push(item.to_string()),
                        None => {}
                    }
                }
            } else if section == "Session Bus Policy" || section == "System Bus Policy" {
                buses.insert((section.clone(), k.to_string()), v.to_string());
            }
        }
    }
    let get = |k: &str| lists.get(k).cloned().unwrap_or_default();
    let mut out = Vec::new();
    let filesystems = get("filesystems");
    let base = |f: &str| f.split(':').next().unwrap_or(f).to_string();
    if filesystems.iter().any(|f| base(f) == "host") {
        out.push(Permission::new("allFiles", true));
    }
    if filesystems
        .iter()
        .any(|f| base(f) == "home" || base(f) == "~")
    {
        out.push(Permission::new("homeFolder", true));
    }
    let system: Vec<String> = filesystems
        .iter()
        .filter(|f| ["host-os", "host-etc", "host-root"].contains(&base(f).as_str()))
        .cloned()
        .collect();
    if !system.is_empty() {
        out.push(Permission::new("systemFolders", true).detail(system.join(", ")));
    }
    let folders: Vec<String> = filesystems
        .iter()
        .filter(|f| {
            !["host", "home", "~", "host-os", "host-etc", "host-root"].contains(&base(f).as_str())
        })
        .cloned()
        .collect();
    if !folders.is_empty() {
        out.push(Permission::new("folders", true).detail(folders.join(", ")));
    }
    let talks = |section: &str, name: &str| {
        buses
            .get(&(section.to_string(), name.to_string()))
            .is_some_and(|v| v == "talk" || v == "own")
    };
    if talks("Session Bus Policy", "org.freedesktop.Flatpak") {
        out.push(Permission::new("sandboxEscape", true));
    }
    if talks("Session Bus Policy", "org.freedesktop.secrets") {
        out.push(Permission::new("keyring", true));
    }
    let sockets = get("sockets");
    for (socket, key) in [
        ("session-bus", "sessionBus"),
        ("system-bus", "systemBus"),
        ("ssh-auth", "sshAgent"),
        ("gpg-agent", "gpgAgent"),
        ("x11", "x11"),
        ("pulseaudio", "audio"),
        ("pcsc", "smartCards"),
        ("cups", "printing"),
    ] {
        if sockets.iter().any(|s| s == socket) {
            out.push(Permission::new(key, true));
        }
    }
    let devices = get("devices");
    for (device, key) in [
        ("all", "allDevices"),
        ("input", "inputDevices"),
        ("usb", "usb"),
    ] {
        if devices.iter().any(|d| d == device) {
            out.push(Permission::new(key, true));
        }
    }
    if get("features").iter().any(|f| f == "devel") {
        out.push(Permission::new("debugging", true));
    }
    if get("shared").iter().any(|s| s == "network") {
        out.push(Permission::new("network", true));
    }
    out
}

/// `Obsidian-1.6.7.AppImage` -> (`Obsidian`, `1.6.7`).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(super) fn appimage_name(file: &str) -> (String, Option<String>) {
    let stem = file
        .strip_suffix(".AppImage")
        .or_else(|| file.strip_suffix(".appimage"))
        .unwrap_or(file);
    let stem = [
        "-x86_64", "_x86_64", ".x86_64", "-aarch64", "_aarch64", "-arm64", "-amd64",
    ]
    .iter()
    .find_map(|arch| stem.strip_suffix(arch))
    .unwrap_or(stem);
    let split = stem.char_indices().find(|(i, c)| {
        (*c == '-' || *c == '_') && stem[i + 1..].starts_with(|d: char| d.is_ascii_digit())
    });
    match split {
        Some((i, _)) => (stem[..i].to_string(), Some(stem[i + 1..].to_string())),
        None => (stem.to_string(), None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(list: &[Permission]) -> Vec<&str> {
        list.iter().map(|p| p.key).collect()
    }

    #[test]
    fn tcc_rows() {
        let json = r#"[
            {"service":"kTCCServiceSystemPolicyAllFiles","client":"com.apple.Terminal","client_type":0,"auth_value":2,"auth_reason":4,"indirect_object_identifier":"UNUSED"},
            {"service":"kTCCServiceAccessibility","client":"/opt/homebrew/Cellar/yabai/7.1.25/bin/yabai","client_type":1,"auth_value":2,"auth_reason":3,"indirect_object_identifier":"UNUSED"},
            {"service":"kTCCServiceAppleEvents","client":"com.googlecode.iterm2","client_type":0,"auth_value":2,"auth_reason":2,"indirect_object_identifier":"com.apple.systemevents"},
            {"service":"kTCCServiceCamera","client":"us.zoom.xos","client_type":0,"auth_value":0,"auth_reason":2,"indirect_object_identifier":"UNUSED"},
            {"service":"kTCCServiceUbiquity","client":"x","client_type":0,"auth_value":2}
        ]"#;
        let g = parse_tcc(json);
        assert_eq!(g.len(), 4);
        assert_eq!(g[0].permission.key, "fullDiskAccess");
        assert_eq!(
            g[0].permission.by,
            Some(SetBy::User),
            "switched on in System Settings"
        );
        assert!(g[1].by_path && g[1].permission.elevated);
        assert_eq!(g[2].permission.detail, "com.apple.systemevents");
        assert!(!g[3].permission.allowed);
        assert!(parse_tcc("").is_empty());
    }

    #[test]
    fn system_extension_rows() {
        let text = "4 extension(s)\n--- com.apple.system_extension.network_extension (Go to 'System Settings > General > Login Items & Extensions > Network Extensions' to modify these system extension(s))\nenabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n*\t*\tW5364U7YZB\tio.tailscale.ipn.macsys.network-extension (1.104.4/101.104.4)\tTailscale Network Extension\t[activated enabled]\n\t\tW5364U7YZB\tio.tailscale.ipn.macsys.network-extension (1.104.2/101.104.2)\tTailscale Network Extension\t[terminated waiting to uninstall on reboot]\n--- com.apple.system_extension.cmio (Go to …)\nenabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n\t*\t2MMRE5MTB8\tcom.obsproject.obs-studio.mac-camera-extension (32.2.2/31845296735)\tOBS Virtual Camera\t[activated waiting for user]\n";
        let list = parse_system_extensions(text);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].id, "io.tailscale.ipn.macsys.network-extension");
        assert_eq!(list[0].permission.key, "networkExtension");
        assert!(list[0].permission.allowed);
        assert_eq!(list[0].permission.detail, "Tailscale Network Extension");
        assert_eq!(list[1].permission.key, "cameraExtension");
        assert!(!list[1].permission.allowed);
    }

    #[test]
    fn flatpak_manifest_and_overrides() {
        let metadata = "[Application]\nname=org.example.App\n\n[Context]\nshared=network;ipc;\nsockets=x11;wayland;pulseaudio;ssh-auth;\ndevices=dri;all;\nfilesystems=home;xdg-download:ro;/mnt/data;\n\n[Session Bus Policy]\norg.freedesktop.Flatpak=talk\norg.freedesktop.Notifications=talk\n";
        let list = flatpak(metadata, &[]);
        assert_eq!(
            keys(&list),
            [
                "homeFolder",
                "folders",
                "sandboxEscape",
                "sshAgent",
                "x11",
                "audio",
                "allDevices",
                "network"
            ]
        );
        assert_eq!(list[1].detail, "xdg-download:ro, /mnt/data");
        // An override takes the home folder and SSH keys away, and adds every file.
        let user = "[Context]\nfilesystems=!home;host;\nsockets=!ssh-auth;\n".to_string();
        let list = flatpak(metadata, &[user]);
        assert!(keys(&list).contains(&"allFiles"));
        assert!(!keys(&list).contains(&"homeFolder"));
        assert!(!keys(&list).contains(&"sshAgent"));
    }

    #[test]
    fn appimage_names() {
        assert_eq!(
            appimage_name("Obsidian-1.6.7.AppImage"),
            ("Obsidian".into(), Some("1.6.7".into()))
        );
        assert_eq!(
            appimage_name("cursor-0.42.3-x86_64.AppImage"),
            ("cursor".into(), Some("0.42.3".into()))
        );
        assert_eq!(appimage_name("Krita.appimage"), ("Krita".into(), None));
    }
}
