//! The desktop app, built on Tauri: the menu bar / tray icon and the window
//! in one process, packaged as a native app (`cargo tauri build`: .app/.dmg,
//! .msi/.exe, .deb/.rpm/.AppImage). The window is `assets/ui`, rendered by the
//! system web view, so it looks the same on every platform.
//!
//! - [`schedule`] decides which lenses are due and runs them on threads.
//! - [`menu`] builds the tray menu and icon from the latest results.
//! - [`commands`] answers what the window asks for.
//!
//! A second launch (`lenstica window`, or opening the app again) hands over to
//! the running instance, which opens the window.

mod commands;
mod menu;
mod schedule;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::mpsc::{self, Sender};
use std::sync::{Mutex, MutexGuard, PoisonError};

use anyhow::Result;
use serde_json::{Value, json};
use tauri::{AppHandle, Emitter, Manager, RunEvent, WebviewUrl, WebviewWindowBuilder, WindowEvent};

use crate::autostart;
use crate::config::{self, Config};
use crate::lenses::{self, store::RunResult};
use crate::paths;
use crate::system::{self, InstanceLock};

/// What the scheduler is asked to do.
pub enum Request {
    /// Run every enabled lens now.
    CheckAll,
    /// Run these lenses now; `true` = use caches only (after an ignore).
    Run(Vec<String>, bool),
    ApplyAll,
    Fix {
        lens: String,
        key: String,
    },
}

#[derive(Default)]
pub struct Shared {
    pub results: BTreeMap<String, RunResult>,
    pub running: BTreeSet<String>,
    /// Tray menu item id -> what clicking it does; rebuilt with the menu.
    pub clicks: HashMap<String, menu::Click>,
}

pub struct AppState {
    shared: Mutex<Shared>,
    requests: Mutex<Sender<Request>>,
    /// Held while this process is the monitor, so `lenstica watch` cannot run alongside.
    monitor_lock: Mutex<Option<InstanceLock>>,
}

/// `LENSTICA_DEBUG=1` logs what the window asks for and the menu as text.
pub fn debug() -> bool {
    std::env::var_os("LENSTICA_DEBUG").is_some_and(|v| v != "0")
}

impl AppState {
    /// The shared state. A thread that panicked while holding it left it
    /// usable: every update is a whole-field assignment.
    pub fn lock(&self) -> MutexGuard<'_, Shared> {
        self.shared.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn send(&self, request: Request) {
        if let Ok(tx) = self.requests.lock() {
            let _ = tx.send(request);
        }
    }
}

// `generate_context!` embeds `assets/ui`, but the compiler does not see those
// files as inputs, so an edit to the page alone would ship the old one.
// Including them makes any change rebuild the crate and re-embed the page.
const _: &[u8] = include_bytes!("../../assets/ui/index.html");
const _: &[u8] = include_bytes!("../../assets/ui/app.js");

/// The window's pages, as `lenstica window <page>` and the page's `#hash` name them.
pub const PAGES: [&str; 4] = ["overview", "findings", "lenses", "settings"];

/// What a second launch asked for: its arguments after the program name.
fn hand_over(app: &AppHandle, args: &[String]) {
    let args: Vec<&str> = args
        .iter()
        .map(String::as_str)
        .filter(|a| !a.starts_with("-psn"))
        .collect();
    match args.as_slice() {
        // Opening the app again (Finder, Spotlight, Explorer) shows the window.
        [] | ["window"] => show_window(app),
        ["window", page] if PAGES.contains(&page.split_once('/').map_or(*page, |(p, _)| p)) => {
            show_page(app, page);
        }
        _ => {}
    }
}

/// `None`: the menu bar app only; `Some(page)`: also open the window on that page.
pub fn run(open_window: Option<String>) -> Result<()> {
    #[cfg(windows)]
    detach_console();
    let (requests, inbox) = mpsc::channel();
    let mut inbox = Some(inbox);
    let app = tauri::Builder::default()
        // First, so a second launch forwards to this one and exits before doing anything.
        .plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
            hand_over(app, argv.get(1..).unwrap_or_default());
        }))
        .plugin(tauri_plugin_clipboard_manager::init())
        .manage(AppState {
            shared: Mutex::new(Shared {
                results: lenses::store::load(),
                ..Default::default()
            }),
            requests: Mutex::new(requests),
            monitor_lock: Mutex::new(None),
        })
        .invoke_handler(tauri::generate_handler![
            commands::action,
            commands::get_state,
            commands::list_repos
        ])
        .setup(move |app| {
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);
            menu::create(app.handle())?;
            match system::acquire_lock()? {
                Some(lock) => {
                    *app.state::<AppState>()
                        .monitor_lock
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner) = Some(lock);
                    if let Some(inbox) = inbox.take() {
                        schedule::start(app.handle().clone(), inbox);
                    }
                }
                // `lenstica watch` is monitoring; this instance only shows results.
                None => eprintln!("lenstica: another monitor is running; showing its results only"),
            }
            if let Some(page) = &open_window {
                show_page(app.handle(), page);
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::Destroyed = event {
                // Back to a menu bar app: no Dock icon without a window.
                #[cfg(target_os = "macos")]
                let _ = window
                    .app_handle()
                    .set_activation_policy(tauri::ActivationPolicy::Accessory);
                let _ = window;
            }
        })
        .build(tauri::generate_context!())?;
    app.run(|app, event| match event {
        // Closing the window must not quit the menu bar app; only Quit (an explicit exit code) does.
        RunEvent::ExitRequested { api, code, .. } if code.is_none() => api.prevent_exit(),
        // macOS: opening the app again (Finder, Spotlight, `open`) reuses this process.
        #[cfg(target_os = "macos")]
        RunEvent::Reopen { .. } => show_window(app),
        _ => {
            let _ = app;
        }
    });
    Ok(())
}

/// Open the window, or bring it to the front.
pub fn show_window(app: &AppHandle) {
    open_at(app, None);
}

/// Open the window on one page (`overview`, `findings`, `lenses`, `settings`).
pub fn show_page(app: &AppHandle, page: &str) {
    open_at(app, Some(page));
}

fn open_at(app: &AppHandle, page: Option<&str>) {
    #[cfg(target_os = "macos")]
    let _ = app.set_activation_policy(tauri::ActivationPolicy::Regular);
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
        if let Some(page) = page {
            let _ = window.emit("navigate", page);
        }
        return;
    }
    // A new window reads its first page from the address, so nothing depends on
    // an event arriving before the page is listening.
    let url = match page {
        Some(page) => format!("index.html#{page}"),
        None => "index.html".to_string(),
    };
    let built = WebviewWindowBuilder::new(app, "main", WebviewUrl::App(url.into()))
        .title("Lenstica")
        .inner_size(1180.0, 780.0)
        .min_inner_size(880.0, 560.0)
        .build();
    match built {
        Ok(window) => {
            let _ = window.set_focus();
        }
        Err(e) => notify_error(&format!("cannot open the window: {e}")),
    }
}

/// Open the window on the findings page with one finding selected.
pub fn show_finding(app: &AppHandle, lens: &str, key: &str) {
    open_at(
        app,
        Some(&format!(
            "findings/{}",
            url_encode(&format!("{lens}|{key}"))
        )),
    );
}

/// Percent-encode everything but unreserved characters, for an address fragment.
fn url_encode(text: &str) -> String {
    text.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Put a prompt for an AI agent on the clipboard. Each item is a lens and
/// either one finding's key or `None` for all of that lens's alerts.
pub fn copy_prompt(app: &AppHandle, items: &[(String, Option<String>)]) -> Result<()> {
    use tauri_plugin_clipboard_manager::ClipboardExt;
    let cfg = Config::load()?;
    let results = {
        let shared = app.state::<AppState>();
        let shared = shared.lock();
        shared.results.clone()
    };
    let items: Vec<(Option<&str>, Option<&str>)> = items
        .iter()
        .map(|(lens, key)| (Some(lens.as_str()), key.as_deref()))
        .collect();
    let pairs = crate::prompt::collect(&cfg, &results, &items);
    if pairs.is_empty() {
        anyhow::bail!("those findings are no longer reported");
    }
    app.clipboard()
        .write_text(crate::prompt::for_findings(&pairs))
        .map_err(|e| anyhow::anyhow!("cannot copy to the clipboard: {e}"))?;
    toast(
        app,
        if pairs.len() == 1 {
            "Copied a prompt for your AI agent".to_string()
        } else {
            format!("Copied a prompt covering {} findings", pairs.len())
        },
        true,
    );
    Ok(())
}

pub fn notify_error(text: &str) {
    eprintln!("lenstica: {text}");
    if Config::load().map(|c| c.monitor.notify).unwrap_or(true) {
        let _ = crate::notify::send("Lenstica", text);
    }
}

pub fn toast(app: &AppHandle, text: impl Into<String>, ok: bool) {
    let _ = app.emit("toast", json!({ "text": text.into(), "ok": ok }));
}

/// Everything the window shows, sent as the `state` event.
fn state(app: &AppHandle) -> Value {
    let loaded = Config::load();
    let config_error = loaded.as_ref().err().map(|e| format!("{e:#}"));
    let cfg = loaded.unwrap_or_default();
    let (results, running) = {
        let shared = app.state::<AppState>();
        let shared = shared.lock();
        (shared.results.clone(), shared.running.clone())
    };
    let lenses: Vec<Value> = lenses::registry(&cfg)
        .iter()
        .map(|r| {
            json!({
                "id": r.id(),
                "title": r.lens.title(),
                "description": r.lens.description(),
                "origin": r.origin.label(),
                "enabled": lenses::enabled(&cfg, r),
                "notify": lenses::notifies(&cfg, r.id()),
                "intervalMinutes": lenses::interval(&cfg, r).as_secs() / 60,
                "running": running.contains(r.id()),
                "result": results.get(r.id()),
            })
        })
        .collect();
    let managers: Vec<Value> = crate::managers::all()
        .iter()
        .map(|m| json!({ "id": m.id(), "name": m.name(), "enabled": cfg.is_enabled(m.id()) }))
        .collect();
    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "managers": managers,
        "agent": {
            "skillInstalled": crate::agent::skill_installed(),
            "skillPath": paths::tilde(&crate::agent::default_skill_dir().join("SKILL.md")),
            "mcpCommand": crate::agent::mcp_command(),
            "mcpJson": crate::agent::mcp_json(),
        },
        "configPath": paths::tilde(&config::path()),
        "configError": config_error,
        "alertSeverity": lenses::threshold(&cfg).label(),
        "settings": cfg,
        "lenses": lenses,
        "autostart": autostart::installed().is_some(),
        "now": chrono::Utc::now(),
    })
}

/// Rebuild the tray and, if the window is open, send it fresh state.
pub fn refresh(app: &AppHandle) {
    menu::refresh(app);
    if app.get_webview_window("main").is_some() {
        let _ = app.emit("state", state(app));
    }
}

#[cfg(windows)]
fn detach_console() {
    unsafe extern "system" {
        fn FreeConsole() -> i32;
    }
    // SAFETY: FreeConsole takes no arguments and only detaches this process from its console.
    unsafe {
        FreeConsole();
    }
}
