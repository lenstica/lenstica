//! What is on this machine: the accounts it can act as, its repositories,
//! applications, containers, virtual machines and extensions.
//!
//! An inventory, not a check. Lenses judge what is risky; assets say what
//! there is, so the window, the CLI and AI agents can show it, and the window
//! can link each asset to the findings about it. Everything is read locally
//! and nothing is sent anywhere. Credentials are never read for their value:
//! an identity is an account's name and where its key is kept, never the key.

mod applications;
mod containers;
mod extensions;
mod identities;
mod machines;
mod permissions;
mod repositories;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::Result;
use serde::Serialize;

use crate::config::Config;
use crate::exec::{self, Output};
use crate::paths::home;

/// A kind of asset: one page in the window's sidebar.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    Identities,
    Repositories,
    Applications,
    Containers,
    VirtualMachines,
    Extensions,
}

impl Kind {
    pub const ALL: [Kind; 6] = [
        Kind::Identities,
        Kind::Repositories,
        Kind::Applications,
        Kind::Containers,
        Kind::VirtualMachines,
        Kind::Extensions,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Kind::Identities => "identities",
            Kind::Repositories => "repositories",
            Kind::Applications => "applications",
            Kind::Containers => "containers",
            Kind::VirtualMachines => "virtual-machines",
            Kind::Extensions => "extensions",
        }
    }

    /// The English name; the window shows its own translation.
    pub fn title(self) -> &'static str {
        match self {
            Kind::Identities => "Identities",
            Kind::Repositories => "Repositories",
            Kind::Applications => "Applications",
            Kind::Containers => "Containers",
            Kind::VirtualMachines => "Virtual machines",
            Kind::Extensions => "Extensions",
        }
    }

    /// `virtual-machines` -> [`Kind::VirtualMachines`].
    pub fn from_id(id: &str) -> Option<Kind> {
        Kind::ALL.into_iter().find(|k| k.id() == id)
    }

    /// The heading for assets with no source: a repository without a remote,
    /// an app installed by hand.
    pub fn unsourced(self) -> &'static str {
        match self {
            Kind::Repositories => "No remote",
            _ => "Other",
        }
    }

    /// Whether this system has a way to list it yet.
    pub fn supported(self) -> bool {
        match self {
            // Windows keeps installed programs in the registry: not read yet.
            Kind::Applications => cfg!(any(target_os = "macos", target_os = "linux")),
            _ => true,
        }
    }

    fn discover(self, ctx: &Ctx, found: &mut Found) {
        match self {
            Kind::Identities => identities::discover(ctx, found),
            Kind::Repositories => repositories::discover(ctx, found),
            Kind::Applications => applications::discover(ctx, found),
            Kind::Containers => containers::discover(ctx, found),
            Kind::VirtualMachines => machines::discover(ctx, found),
            Kind::Extensions => extensions::discover(ctx, found),
        }
    }
}

/// Running or not, for what can be either.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Running,
    Paused,
    Stopped,
}

impl Status {
    /// From the words container and VM tools use: `running`, `Up 3 hours`, `exited`.
    fn parse(text: &str) -> Option<Status> {
        let t = text.trim().to_ascii_lowercase();
        if t.is_empty() {
            return None;
        }
        Some(
            if t.starts_with("running") || t.starts_with("up") || t.starts_with("restarting") {
                Status::Running
            } else if t.starts_with("paused")
                || t.starts_with("suspended")
                || t.starts_with("saved")
            {
                Status::Paused
            } else {
                Status::Stopped
            },
        )
    }

    pub fn label(self) -> &'static str {
        match self {
            Status::Running => "running",
            Status::Paused => "paused",
            Status::Stopped => "stopped",
        }
    }
}

/// Every fact an asset can state, with its English name; the window
/// translates them under `assets.facts`.
pub const FACTS: &[(&str, &str)] = &[
    ("account", "Account"),
    ("user", "User"),
    ("email", "Email"),
    ("host", "Host"),
    ("signIn", "Sign-in"),
    ("region", "Region"),
    ("role", "Role"),
    ("project", "Project"),
    ("cluster", "Cluster"),
    ("namespace", "Namespace"),
    ("keyType", "Key type"),
    ("comment", "Comment"),
    ("signing", "Commit signing"),
    ("organization", "Organization"),
    ("subscriptions", "Subscriptions"),
    ("keptIn", "Key kept in"),
    ("remote", "Remote"),
    ("branch", "Branch"),
    ("worktrees", "Worktrees"),
    ("version", "Version"),
    ("bundleId", "Bundle ID"),
    ("image", "Image"),
    ("state", "State"),
    ("ports", "Ports"),
    ("created", "Created"),
    ("id", "ID"),
    ("arch", "Architecture"),
    ("cpus", "CPUs"),
    ("memory", "Memory"),
    ("disk", "Disk"),
    ("type", "Type"),
    ("system", "System"),
    ("address", "Address"),
    ("folder", "Folder"),
    ("publisher", "Publisher"),
    ("profile", "Profile"),
    ("updated", "Updated"),
    ("installed", "Installed"),
];

/// Every tag an asset can carry, with its English name (`assets.tags`).
pub const TAGS: &[(&str, &str)] = &[
    ("current", "In use"),
    ("credentialsInFile", "Credentials in a file"),
    ("allSites", "All sites"),
    ("disabled", "Turned off"),
    ("excluded", "Left out of checks"),
    ("elevated", "Elevated permissions"),
    ("notFound", "Not found"),
];

/// Every permission an app can hold: its key, its English name (as System
/// Settings or Flatpak names it; the window translates it under
/// `assets.permissions` with a line on what it allows), whether it reaches
/// beyond the app itself (other apps, every file, the screen, the keyboard,
/// the system), and on macOS the System Settings pane that changes it.
pub const PERMISSIONS: &[(&str, &str, bool, Option<&str>)] = &[
    // macOS: Privacy & Security.
    (
        "fullDiskAccess",
        "Full Disk Access",
        true,
        Some("Privacy_AllFiles"),
    ),
    (
        "accessibility",
        "Accessibility",
        true,
        Some("Privacy_Accessibility"),
    ),
    (
        "screenRecording",
        "Screen & System Audio Recording",
        true,
        Some("Privacy_ScreenCapture"),
    ),
    (
        "inputMonitoring",
        "Input Monitoring",
        true,
        Some("Privacy_ListenEvent"),
    ),
    ("automation", "Automation", true, Some("Privacy_Automation")),
    (
        "developerTools",
        "Developer Tools",
        true,
        Some("Privacy_DevTools"),
    ),
    (
        "appManagement",
        "App Management",
        true,
        Some("Privacy_AppBundles"),
    ),
    ("appData", "Other apps' data", true, Some("Privacy_AppData")),
    (
        "remoteDesktop",
        "Remote Desktop",
        true,
        Some("Privacy_RemoteDesktop"),
    ),
    ("camera", "Camera", false, Some("Privacy_Camera")),
    (
        "microphone",
        "Microphone",
        false,
        Some("Privacy_Microphone"),
    ),
    ("contacts", "Contacts", false, Some("Privacy_Contacts")),
    ("calendars", "Calendars", false, Some("Privacy_Calendars")),
    ("reminders", "Reminders", false, Some("Privacy_Reminders")),
    ("photos", "Photos", false, Some("Privacy_Photos")),
    (
        "desktopFolder",
        "Desktop folder",
        false,
        Some("Privacy_FilesAndFolders"),
    ),
    (
        "documentsFolder",
        "Documents folder",
        false,
        Some("Privacy_FilesAndFolders"),
    ),
    (
        "downloadsFolder",
        "Downloads folder",
        false,
        Some("Privacy_FilesAndFolders"),
    ),
    (
        "networkVolumes",
        "Network volumes",
        false,
        Some("Privacy_FilesAndFolders"),
    ),
    (
        "removableVolumes",
        "Removable volumes",
        false,
        Some("Privacy_FilesAndFolders"),
    ),
    (
        "mediaLibrary",
        "Media & Apple Music",
        false,
        Some("Privacy_Media"),
    ),
    (
        "speechRecognition",
        "Speech Recognition",
        false,
        Some("Privacy_SpeechRecognition"),
    ),
    ("bluetooth", "Bluetooth", false, Some("Privacy_Bluetooth")),
    ("motion", "Motion & Fitness", false, Some("Privacy_Motion")),
    ("focus", "Focus", false, Some("Privacy_Focus")),
    ("home", "Home", false, Some("Privacy_HomeKit")),
    (
        "passkeys",
        "Passkeys Access for Web Browsers",
        false,
        Some("Privacy_PasskeyAccess"),
    ),
    // macOS: Login Items & Extensions.
    (
        "networkExtension",
        "Network extension",
        true,
        Some("LoginItems"),
    ),
    (
        "endpointSecurity",
        "Endpoint security extension",
        true,
        Some("LoginItems"),
    ),
    (
        "driverExtension",
        "Driver extension",
        true,
        Some("LoginItems"),
    ),
    (
        "cameraExtension",
        "Camera extension",
        false,
        Some("LoginItems"),
    ),
    // Linux: what a Flatpak's sandbox lets through, and AppImages, which have none.
    ("unsandboxed", "Not sandboxed", true, None),
    ("allFiles", "All files", true, None),
    ("homeFolder", "Home folder", true, None),
    ("systemFolders", "System folders", true, None),
    ("folders", "Folders", false, None),
    (
        "sandboxEscape",
        "Run commands outside the sandbox",
        true,
        None,
    ),
    ("sessionBus", "Every app on the session bus", true, None),
    ("systemBus", "The system bus", true, None),
    ("keyring", "Passwords in the keyring", true, None),
    ("sshAgent", "Your SSH keys", true, None),
    ("gpgAgent", "Your GPG keys", true, None),
    ("x11", "X11 display", true, None),
    ("allDevices", "All devices", true, None),
    ("inputDevices", "Input devices", true, None),
    ("debugging", "Debugging other processes", true, None),
    ("network", "Network", false, None),
    ("audio", "Sound and microphone", false, None),
    ("usb", "USB devices", false, None),
    ("smartCards", "Smart cards", false, None),
    ("printing", "Printing", false, None),
];

/// Who set a permission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SetBy {
    User,
    /// A management profile from an organisation.
    Organization,
    System,
}

/// One permission an app holds, or was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Permission {
    pub key: &'static str,
    pub label: &'static str,
    pub elevated: bool,
    pub allowed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub by: Option<SetBy>,
    /// What it applies to: the app an Automation grant controls, a
    /// Flatpak's folders, a system extension's name.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub detail: String,
    /// Whether System Settings has a pane for it ([`settings_pane`]).
    pub settings: bool,
}

impl Permission {
    pub fn new(key: &'static str, allowed: bool) -> Self {
        let found = PERMISSIONS.iter().find(|p| p.0 == key);
        debug_assert!(found.is_some(), "unknown permission `{key}`");
        Self {
            key,
            label: found.map_or("", |p| p.1),
            elevated: found.is_some_and(|p| p.2),
            allowed,
            by: None,
            detail: String::new(),
            settings: found.is_some_and(|p| p.3.is_some()),
        }
    }

    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }

    pub fn by(mut self, by: Option<SetBy>) -> Self {
        self.by = by;
        self
    }
}

/// The System Settings pane for a permission (macOS), from the table only.
#[cfg_attr(not(feature = "tray"), allow(dead_code))]
pub fn settings_pane(key: &str) -> Option<&'static str> {
    PERMISSIONS.iter().find(|p| p.0 == key).and_then(|p| p.3)
}

fn label(table: &[(&'static str, &'static str)], key: &str) -> &'static str {
    let found = table.iter().find(|(k, _)| *k == key).map(|(_, l)| *l);
    debug_assert!(found.is_some(), "unknown asset fact or tag `{key}`");
    found.unwrap_or("")
}

/// One thing a fact says: `Region: eu-west-1`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Fact {
    pub key: &'static str,
    pub label: &'static str,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Tag {
    pub key: &'static str,
    pub label: &'static str,
}

/// One asset.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Asset {
    /// Unique within its kind: a path, `aws:prod`, a container's id.
    pub id: String,
    pub name: String,
    /// What it comes from or runs on (`AWS`, `Docker Desktop`, `Lima`, `Chrome`);
    /// empty when there is nothing to say (an app installed by hand).
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
    /// Its file or folder, to open or reveal, and to match findings against.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    pub facts: Vec<Fact>,
    pub tags: Vec<Tag>,
    /// What an app may do beyond its own files (Applications only), allowed first.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub permissions: Vec<Permission>,
}

impl Asset {
    pub fn new(id: impl Into<String>, name: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            source: source.into(),
            status: None,
            path: None,
            facts: Vec::new(),
            tags: Vec::new(),
            permissions: Vec::new(),
        }
    }

    pub fn path(mut self, path: impl Into<PathBuf>) -> Self {
        self.path = Some(path.into());
        self
    }

    pub fn status(mut self, status: Option<Status>) -> Self {
        self.status = status;
        self
    }

    /// A fact; an empty value is left out.
    pub fn fact(mut self, key: &'static str, value: impl Into<String>) -> Self {
        let value = value.into();
        let value = value.trim();
        if !value.is_empty() {
            self.facts.push(Fact {
                key,
                label: label(FACTS, key),
                value: value.to_string(),
            });
        }
        self
    }

    pub fn fact_opt(self, key: &'static str, value: Option<impl Into<String>>) -> Self {
        match value {
            Some(v) => self.fact(key, v),
            None => self,
        }
    }

    pub fn tag_if(mut self, on: bool, key: &'static str) -> Self {
        if on && !self.tags.iter().any(|t| t.key == key) {
            self.tags.push(Tag {
                key,
                label: label(TAGS, key),
            });
        }
        self
    }

    /// Add a permission (one already there for the same thing is replaced),
    /// tagging the app when an elevated one is allowed.
    pub fn permit(&mut self, p: Permission) {
        self.permissions
            .retain(|q| !(q.key == p.key && q.detail == p.detail));
        if p.allowed && p.elevated && !self.tags.iter().any(|t| t.key == "elevated") {
            self.tags.push(Tag {
                key: "elevated",
                label: label(TAGS, "elevated"),
            });
        }
        self.permissions.push(p);
        // Allowed first, elevated first, then as System Settings lists them.
        let order = |p: &Permission| {
            PERMISSIONS
                .iter()
                .position(|q| q.0 == p.key)
                .unwrap_or(usize::MAX)
        };
        self.permissions
            .sort_by_key(|p| (!p.allowed, !p.elevated, order(p), p.detail.clone()));
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.facts
            .iter()
            .find(|f| f.key == key)
            .map(|f| f.value.as_str())
    }
}

/// What one look for a kind of asset found.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Discovery {
    pub kind: Kind,
    pub supported: bool,
    /// Sorted by source (those without one last), then name.
    pub assets: Vec<Asset>,
    /// Tools that are installed but did not answer because they are not
    /// running (Docker without its engine started), so what they hold is missing.
    pub not_running: Vec<String>,
    /// Sources that could not be read: `limactl: …`.
    pub errors: Vec<String>,
    /// Sources macOS keeps from apps without Full Disk Access (browser
    /// profiles, other apps' data), so what they hold is missing.
    pub blocked: Vec<String>,
    pub seconds: f64,
}

impl Discovery {
    /// The compact form the CLI's `--json` and the MCP server give: facts as
    /// `{key: value}`, tags by key.
    pub fn brief(&self) -> serde_json::Value {
        serde_json::json!({
            "kind": self.kind,
            "supported": self.supported,
            "assets": self.assets.iter().map(|a| serde_json::json!({
                "id": a.id,
                "name": a.name,
                "source": a.source,
                "status": a.status,
                "path": a.path,
                "facts": a.facts.iter().map(|f| (f.key.to_string(), serde_json::Value::from(f.value.clone()))).collect::<serde_json::Map<_, _>>(),
                "tags": a.tags.iter().map(|t| t.key).collect::<Vec<_>>(),
                "permissions": a.permissions.iter().map(|p| serde_json::json!({
                    "key": p.key,
                    "allowed": p.allowed,
                    "elevated": p.elevated,
                    "by": p.by,
                    "detail": p.detail,
                })).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
            "notRunning": self.not_running,
            "errors": self.errors,
            "blocked": self.blocked,
        })
    }
}

/// What a kind's discovery collects as it goes.
#[derive(Default)]
struct Found {
    assets: Vec<Asset>,
    not_running: Vec<String>,
    errors: Vec<String>,
    blocked: Vec<String>,
}

impl Found {
    fn add(&mut self, asset: Asset) {
        self.assets.push(asset);
    }

    fn error(&mut self, source: &str, e: impl std::fmt::Display) {
        self.errors.push(format!("{source}: {e}"));
    }

    /// Whether a folder can be listed. One the system refuses (macOS keeps
    /// browser profiles from apps without Full Disk Access, without asking)
    /// is noted as blocked; one that is missing is simply not there.
    fn readable(&mut self, dir: &Path, source: &str) -> bool {
        match std::fs::read_dir(dir) {
            Ok(_) => true,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                if !self.blocked.iter().any(|b| b == source) {
                    self.blocked.push(source.to_string());
                }
                false
            }
            Err(_) => false,
        }
    }
}

/// Whether this app may read what macOS protects. Checked on a folder only
/// Full Disk Access opens, which fails quietly without it; other apps'
/// sandboxes are only read with it, since reading them otherwise makes macOS
/// ask the user.
fn full_disk_access() -> bool {
    !cfg!(target_os = "macos")
        || std::fs::read_dir(home().join("Library/Application Support/com.apple.TCC")).is_ok()
}

/// How a discovery runs tools: the search path a login agent needs, and a
/// short time limit, since a tool that hangs must not hold up the window.
struct Ctx<'a> {
    cfg: &'a Config,
    search: OsString,
}

const TOOL_TIMEOUT: Duration = Duration::from_secs(10);

impl<'a> Ctx<'a> {
    fn new(cfg: &'a Config) -> Self {
        let mut extra = cfg.extra_path();
        // Where container and VM apps keep their command-line tools.
        let h = home();
        extra.extend([
            h.join(".docker/bin"),
            h.join(".orbstack/bin"),
            h.join(".rd/bin"),
            PathBuf::from("/Applications/Docker.app/Contents/Resources/bin"),
            PathBuf::from("/opt/podman/bin"),
            PathBuf::from("/Applications/VirtualBox.app/Contents/MacOS"),
            PathBuf::from("/Applications/VMware Fusion.app/Contents/Library"),
            PathBuf::from("/Applications/Parallels Desktop.app/Contents/MacOS"),
        ]);
        Self {
            cfg,
            search: exec::search_path(&extra),
        }
    }

    fn find(&self, binary: &str) -> Option<PathBuf> {
        exec::find(binary, &self.search)
    }

    fn run(&self, program: &Path, args: &[&str]) -> Result<Output> {
        exec::run_timeout(program, args, &self.search, TOOL_TIMEOUT)
    }
}

/// Look for each kind, all at once.
pub fn discover(cfg: &Config, kinds: &[Kind]) -> Vec<Discovery> {
    let ctx = Ctx::new(cfg);
    std::thread::scope(|s| {
        let handles: Vec<_> = kinds
            .iter()
            .map(|&kind| {
                let ctx = &ctx;
                (kind, s.spawn(move || discover_one(ctx, kind)))
            })
            .collect();
        handles
            .into_iter()
            .map(|(kind, h)| {
                h.join().unwrap_or_else(|_| Discovery {
                    kind,
                    supported: kind.supported(),
                    assets: Vec::new(),
                    not_running: Vec::new(),
                    errors: vec!["the search stopped unexpectedly".to_string()],
                    blocked: Vec::new(),
                    seconds: 0.0,
                })
            })
            .collect()
    })
}

fn discover_one(ctx: &Ctx, kind: Kind) -> Discovery {
    let started = std::time::Instant::now();
    let mut found = Found::default();
    if kind.supported() {
        kind.discover(ctx, &mut found);
    }
    let Found {
        mut assets,
        not_running,
        errors,
        blocked,
    } = found;
    // Those without a source ("Other", "No remote") last.
    assets.sort_by(|a, b| {
        (a.source.is_empty(), a.source.to_lowercase())
            .cmp(&(b.source.is_empty(), b.source.to_lowercase()))
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
            .then_with(|| a.id.cmp(&b.id))
    });
    assets.dedup_by(|a, b| a.id == b.id);
    Discovery {
        kind,
        supported: kind.supported(),
        assets,
        not_running,
        errors,
        blocked,
        seconds: started.elapsed().as_secs_f64(),
    }
}

// ---- helpers shared by the kinds ------------------------------------------------

/// `2026-10-01`, the day a file or folder last changed. Archives often keep
/// a placeholder time (1980, 1970): that says nothing, so it is left out.
fn modified_day(path: &Path) -> Option<String> {
    let time = std::fs::metadata(path).and_then(|m| m.modified()).ok()?;
    let since_2001 = time.duration_since(SystemTime::UNIX_EPOCH).ok()?.as_secs() > 978_307_200;
    since_2001.then(|| day(time))
}

fn day(time: SystemTime) -> String {
    chrono::DateTime::<chrono::Utc>::from(time)
        .format("%Y-%m-%d")
        .to_string()
}

/// `2026-10-01` from milliseconds or seconds since 1970.
fn day_from_epoch(n: i64) -> Option<String> {
    let secs = if n > 100_000_000_000 { n / 1000 } else { n };
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0)
        .map(|t| t.format("%Y-%m-%d").to_string())
}

/// `4 GB`, `512 MB`.
fn bytes(n: u64) -> String {
    const GB: u64 = 1 << 30;
    const MB: u64 = 1 << 20;
    if n >= GB {
        let g = n as f64 / GB as f64;
        if (g - g.round()).abs() < 0.05 {
            format!("{} GB", g.round() as u64)
        } else {
            format!("{g:.1} GB")
        }
    } else {
        format!("{} MB", n / MB)
    }
}

/// The folders directly inside `dir`, sorted; hidden ones left out.
fn subdirs(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = entries
        .flatten()
        .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
        .filter(|e| e.path().is_dir())
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

/// The sections of an INI file (`~/.aws/config`, `.pypirc`, gcloud
/// configurations), in order, each with its `key = value` pairs. Keys outside
/// any section go in a section named "".
fn ini_sections(src: &str) -> Vec<(String, Vec<(String, String)>)> {
    let mut out: Vec<(String, Vec<(String, String)>)> = vec![(String::new(), Vec::new())];
    for raw in src.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            out.push((name.trim().to_string(), Vec::new()));
            continue;
        }
        if let Some((k, v)) = line.split_once(['=', ':']) {
            let v = v.trim().trim_matches(|c| c == '"' || c == '\'');
            out.last_mut()
                .expect("starts with one section")
                .1
                .push((k.trim().to_string(), v.to_string()));
        }
    }
    out.retain(|(name, pairs)| !name.is_empty() || !pairs.is_empty());
    out
}

fn ini_value<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs
        .iter()
        .rev()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.as_str())
        .filter(|v| !v.is_empty())
}

/// A URL without a user name or password in it: `https://tok@host/x` -> `https://host/x`.
fn without_credentials(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    let end = rest.find('/').unwrap_or(rest.len());
    match rest[..end].rfind('@') {
        Some(at) => format!("{scheme}://{}", &rest[at + 1..]),
        None => url.to_string(),
    }
}

/// Run a tool that lists something; `None` (with the reason noted) when it
/// failed. A failure that says the tool's engine is not running is noted as
/// such, not as an error.
fn list_with(
    ctx: &Ctx,
    found: &mut Found,
    source: &str,
    program: &Path,
    args: &[&str],
) -> Option<String> {
    match ctx.run(program, args) {
        Ok(out) if out.success => Some(out.stdout),
        Ok(out) => {
            if not_running(&out.stderr) || not_running(&out.stdout) {
                found.not_running.push(source.to_string());
            } else {
                found.error(source, out.error_text());
            }
            None
        }
        Err(e) => {
            found.error(source, format!("{e:#}"));
            None
        }
    }
}

fn not_running(text: &str) -> bool {
    let t = text.to_ascii_lowercase();
    [
        "cannot connect",
        "is the docker daemon running",
        "connection refused",
        "no such file or directory",
        "not running",
        "failed to connect",
        "unable to connect",
    ]
    .iter()
    .any(|s| t.contains(s))
}

/// Each line of output that is a JSON object (`docker ps --format '{{json .}}'`,
/// `limactl list --format json`), or the items of one JSON array.
fn json_items(text: &str) -> Vec<serde_json::Value> {
    let trimmed = text.trim();
    if trimmed.starts_with('[') {
        return serde_json::from_str::<Vec<serde_json::Value>>(trimmed).unwrap_or_default();
    }
    trimmed
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l.trim()).ok())
        .filter(serde_json::Value::is_object)
        .collect()
}

/// A JSON value as text: strings as they are, numbers written out.
fn text(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) if !s.is_empty() => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// The first of several keys a tool may use for the same thing (`Name`, `name`).
fn field(v: &serde_json::Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|k| v.get(*k).and_then(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_from_tool_words() {
        assert_eq!(Status::parse("Up 5 weeks"), Some(Status::Running));
        assert_eq!(Status::parse("Running"), Some(Status::Running));
        assert_eq!(Status::parse("exited"), Some(Status::Stopped));
        assert_eq!(
            Status::parse("Exited (0) 2 days ago"),
            Some(Status::Stopped)
        );
        assert_eq!(Status::parse("paused"), Some(Status::Paused));
        assert_eq!(Status::parse(""), None);
    }

    #[test]
    fn credentials_never_stay_in_a_url() {
        assert_eq!(
            without_credentials("https://x-access-token:ghp_abc@github.com/o/r.git"),
            "https://github.com/o/r.git"
        );
        assert_eq!(
            without_credentials("git@github.com:o/r.git"),
            "git@github.com:o/r.git"
        );
        assert_eq!(
            without_credentials("https://github.com/o/r@v1"),
            "https://github.com/o/r@v1"
        );
    }

    #[test]
    fn ini_sections_in_order() {
        let s = ini_sections(
            "top = 1\n[default]\nregion = eu-west-1\n# c\n[profile prod]\nsso_account_id = \"123\"\n",
        );
        assert_eq!(s[0].0, "");
        assert_eq!(s[1].0, "default");
        assert_eq!(ini_value(&s[2].1, "sso_account_id"), Some("123"));
    }

    #[test]
    fn sizes_and_days() {
        assert_eq!(bytes(4 * (1 << 30)), "4 GB");
        assert_eq!(bytes(3 * (1 << 29)), "1.5 GB");
        assert_eq!(bytes(512 * (1 << 20)), "512 MB");
        assert_eq!(day_from_epoch(1_792_610_529).as_deref(), Some("2026-10-21"));
        assert_eq!(
            day_from_epoch(1_792_610_529_000).as_deref(),
            Some("2026-10-21")
        );
    }

    #[test]
    fn json_lines_or_array() {
        assert_eq!(json_items("{\"a\":1}\n{\"a\":2}\nnot json\n").len(), 2);
        assert_eq!(json_items("[{\"a\":1},{\"a\":2}]").len(), 2);
        assert!(json_items("").is_empty());
    }

    /// The window names every kind, fact, tag and status in English, so a
    /// translation has something to translate.
    #[test]
    fn the_window_names_every_kind_fact_and_tag() {
        let en: serde_json::Value =
            serde_json::from_str(include_str!("../../i18n/en.json")).unwrap();
        let has = |path: &str| {
            en.pointer(path)
                .and_then(serde_json::Value::as_str)
                .is_some()
        };
        for k in Kind::ALL {
            assert!(
                has(&format!("/assets/kinds/{}/title", k.id())),
                "{}",
                k.id()
            );
            assert!(
                has(&format!("/assets/kinds/{}/description", k.id())),
                "{}",
                k.id()
            );
            assert_eq!(Kind::from_id(k.id()), Some(k));
        }
        for (key, english) in FACTS {
            assert_eq!(
                en.pointer(&format!("/assets/facts/{key}"))
                    .and_then(|v| v.as_str()),
                Some(*english)
            );
        }
        for (key, english) in TAGS {
            assert_eq!(
                en.pointer(&format!("/assets/tags/{key}"))
                    .and_then(|v| v.as_str()),
                Some(*english)
            );
        }
        for s in [Status::Running, Status::Paused, Status::Stopped] {
            assert!(has(&format!("/assets/status/{}", s.label())));
        }
        assert!(has("/assets/kinds/repositories/noSource") && has("/assets/noSource"));
        for (key, english, _, _) in PERMISSIONS {
            assert_eq!(
                en.pointer(&format!("/assets/permissions/{key}/title"))
                    .and_then(|v| v.as_str()),
                Some(*english)
            );
            assert!(has(&format!("/assets/permissions/{key}/about")), "{key}");
        }
    }

    #[test]
    fn every_fact_and_tag_has_a_name() {
        for (key, label) in FACTS.iter().chain(TAGS) {
            assert!(!key.is_empty() && !label.is_empty());
        }
        let a = Asset::new("x", "x", "")
            .fact("region", " ")
            .fact("region", "eu")
            .tag_if(true, "current")
            .tag_if(true, "current");
        assert_eq!(a.facts.len(), 1);
        assert_eq!(a.tags.len(), 1);
    }
}
