//! The tray icon and its menu, built from findings alone, so any lens
//! (built-in, plugin crate or external tool) shows up without changes here.

use std::path::PathBuf;

use anyhow::Result;
use lenstica_lens::{Finding, Severity};
use tauri::image::Image;
use tauri::menu::{
    IconMenuItem, IsMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu,
};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Manager, Wry};

use super::{AppState, Request, Shared};
use crate::config::Config;
use crate::icon::{self, Glyph, MenuIcon};
use crate::lenses;
use crate::system;

const TRAY_ID: &str = "lenstica";
/// Findings listed per lens submenu; the window shows them all.
const MENU_LIMIT: usize = 25;

#[derive(Clone)]
pub enum Click {
    Fix {
        lens: String,
        key: String,
    },
    /// Copy a prompt for an AI agent: one finding, or every alert of a lens.
    CopyPrompt {
        lens: String,
        key: Option<String>,
    },
    ShowFinding {
        lens: String,
        key: String,
    },
    OpenWindow,
    OpenSettings,
    OpenFile(PathBuf),
    Quit,
}

fn image(glyph: Glyph) -> Image<'static> {
    Image::new_owned(icon::rgba(glyph), icon::SIZE, icon::SIZE)
}

fn menu_image(icon: MenuIcon) -> Image<'static> {
    Image::new_owned(icon::menu_rgba(icon), icon::MENU_SIZE, icon::MENU_SIZE)
}

pub fn create(app: &AppHandle) -> Result<()> {
    let menu = Menu::new(app)?;
    TrayIconBuilder::with_id(TRAY_ID)
        .icon(image(Glyph::Checking))
        .icon_as_template(Glyph::Checking.is_template())
        .tooltip("Lenstica")
        .menu(&menu)
        .show_menu_on_left_click(true)
        .on_menu_event(on_click)
        .build(app)?;
    refresh(app);
    Ok(())
}

fn on_click(app: &AppHandle, event: MenuEvent) {
    let click = {
        let state = app.state::<AppState>();
        let shared = state.shared.lock().unwrap_or_else(|p| p.into_inner());
        shared.clicks.get(&event.id.0).cloned()
    };
    let state = app.state::<AppState>();
    let outcome = match click {
        Some(Click::Fix { lens, key }) => {
            state.send(Request::Fix { lens, key });
            Ok(())
        }
        Some(Click::CopyPrompt { lens, key }) => super::copy_prompt(app, &[(lens, key)]),
        Some(Click::ShowFinding { lens, key }) => {
            super::show_finding(app, &lens, &key);
            Ok(())
        }
        Some(Click::OpenWindow) => {
            super::show_window(app);
            Ok(())
        }
        Some(Click::OpenSettings) => {
            super::show_page(app, "settings");
            Ok(())
        }
        Some(Click::OpenFile(path)) => system::open(&path),
        Some(Click::Quit) => {
            app.exit(0);
            Ok(())
        }
        None => Ok(()),
    };
    if let Err(e) = outcome {
        super::notify_error(&format!("{e:#}"));
    }
}

/// How deep an item sits, from its id: `lens:summary` 1, `lens:f0:fix` 2.
fn depth(id: &str) -> usize {
    match id.matches(':').count() {
        0 => 0,
        1 => 1,
        _ => 2,
    }
}

fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        text.to_string()
    } else {
        format!("{}…", text.chars().take(max - 1).collect::<String>())
    }
}

fn capitalised(s: Severity) -> String {
    let label = s.label();
    label[..1].to_uppercase() + &label[1..]
}

/// The file a finding points at, if it is one that can be opened.
fn file_of(f: &Finding) -> Option<PathBuf> {
    f.locations
        .iter()
        .find_map(|l| l.path.clone())
        .filter(|p| p.is_file())
}

/// Builds menu items while recording what each one does.
struct Builder<'a> {
    app: &'a AppHandle,
    shared: &'a mut Shared,
    /// With `LENSTICA_DEBUG`, the menu as text (indent = depth), logged on rebuild.
    trace: Option<Vec<String>>,
}

impl Builder<'_> {
    fn trace(
        &mut self,
        depth: usize,
        text: &str,
        icon: Option<MenuIcon>,
        accelerator: Option<&str>,
    ) {
        if let Some(t) = &mut self.trace {
            let icon = icon.map(|i| format!("[{i:?}] ")).unwrap_or_default();
            let keys = accelerator.map(|a| format!("  ({a})")).unwrap_or_default();
            t.push(format!("{}{icon}{text}{keys}", "  ".repeat(depth)));
        }
    }

    fn record(&mut self, id: &str, click: Option<Click>) {
        if let Some(click) = click {
            self.shared.clicks.insert(id.to_string(), click);
        }
    }

    fn item(
        &mut self,
        id: String,
        text: &str,
        enabled: bool,
        click: Option<Click>,
    ) -> Result<MenuItem<Wry>> {
        self.trace(depth(&id), text, None, None);
        self.record(&id, click);
        Ok(MenuItem::with_id(
            self.app,
            id,
            text,
            enabled,
            None::<&str>,
        )?)
    }

    fn icon_item(
        &mut self,
        id: String,
        text: &str,
        icon: MenuIcon,
        enabled: bool,
        click: Option<Click>,
    ) -> Result<IconMenuItem<Wry>> {
        self.trace(depth(&id), text, Some(icon), None);
        self.record(&id, click);
        Ok(IconMenuItem::with_id(
            self.app,
            id,
            text,
            enabled,
            Some(menu_image(icon)),
            None::<&str>,
        )?)
    }

    fn shortcut(
        &mut self,
        id: &str,
        text: &str,
        accelerator: &str,
        click: Click,
    ) -> Result<MenuItem<Wry>> {
        self.trace(0, text, None, Some(accelerator));
        self.record(id, Some(click));
        Ok(MenuItem::with_id(
            self.app,
            id,
            text,
            true,
            Some(accelerator),
        )?)
    }

    /// One finding: a submenu with what can be done about it.
    fn finding(&mut self, id: &str, f: &Finding, lens_title: &str) -> Result<Submenu<Wry>> {
        self.trace(
            1,
            &truncate(&f.title, 80),
            Some(MenuIcon::Severity(f.severity)),
            None,
        );
        let sub = Submenu::with_id_and_icon(
            self.app,
            format!("{id}:menu"),
            truncate(&f.title, 80),
            true,
            Some(menu_image(MenuIcon::Severity(f.severity))),
        )?;
        sub.append(&self.item(
            format!("{id}:about"),
            &format!("{} · {lens_title}", capitalised(f.severity)),
            false,
            None,
        )?)?;
        sub.append(&PredefinedMenuItem::separator(self.app)?)?;
        if f.fixable {
            let fix = Click::Fix {
                lens: f.lens.clone(),
                key: f.key.clone(),
            };
            sub.append(&self.item(format!("{id}:fix"), "Fix It", true, Some(fix))?)?;
        }
        if let Some(path) = file_of(f) {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            sub.append(&self.item(
                format!("{id}:file"),
                &format!("Open {}", truncate(&name, 40)),
                true,
                Some(Click::OpenFile(path)),
            )?)?;
        }
        sub.append(&self.icon_item(
            format!("{id}:prompt"),
            "Copy Prompt for AI Agent",
            MenuIcon::Copy,
            true,
            Some(Click::CopyPrompt {
                lens: f.lens.clone(),
                key: Some(f.key.clone()),
            }),
        )?)?;
        sub.append(&self.item(
            format!("{id}:show"),
            "Show in Lenstica",
            true,
            Some(Click::ShowFinding {
                lens: f.lens.clone(),
                key: f.key.clone(),
            }),
        )?)?;
        Ok(sub)
    }

    fn lens(&mut self, cfg: &Config, r: &lenses::Registered) -> Result<Submenu<Wry>> {
        let id = r.id().to_string();
        let title = r.lens.title().to_string();
        let result = self.shared.results.get(&id).cloned();
        let alerts: Vec<Finding> = result
            .as_ref()
            .map(|res| {
                let mut list: Vec<Finding> = res
                    .findings
                    .iter()
                    .filter(|f| lenses::is_alert(cfg, f))
                    .cloned()
                    .collect();
                list.sort_by(|a, b| {
                    b.severity
                        .cmp(&a.severity)
                        .then_with(|| a.title.cmp(&b.title))
                });
                list
            })
            .unwrap_or_default();
        let state = match &result {
            _ if self.shared.running.contains(&id) => MenuIcon::Running,
            None => MenuIcon::NotRun,
            Some(res) if res.error.is_some() => MenuIcon::Failed,
            Some(_) => match alerts.first() {
                None => MenuIcon::Ok,
                Some(worst) => MenuIcon::Problem(worst.severity),
            },
        };
        let label = if alerts.is_empty() {
            title.clone()
        } else {
            format!("{title} ({})", alerts.len())
        };
        let summary = match &result {
            None => "Not run yet".to_string(),
            Some(res) => res
                .error
                .as_ref()
                .map_or(res.summary.clone(), |e| format!("Failed: {e}")),
        };
        self.trace(0, &label, Some(state), None);
        let sub = Submenu::with_id_and_icon(
            self.app,
            format!("{id}:menu"),
            label,
            true,
            Some(menu_image(state)),
        )?;
        sub.append(&self.item(
            format!("{id}:summary"),
            &truncate(&summary, 90),
            false,
            None,
        )?)?;
        if !alerts.is_empty() {
            sub.append(&PredefinedMenuItem::separator(self.app)?)?;
        }
        for (i, f) in alerts.iter().take(MENU_LIMIT).enumerate() {
            sub.append(&self.finding(&format!("{id}:f{i}"), f, &title)?)?;
        }
        sub.append(&PredefinedMenuItem::separator(self.app)?)?;
        if alerts.len() > 1 {
            sub.append(&self.icon_item(
                format!("{id}:prompt"),
                &format!("Copy Prompt for All {}", alerts.len()),
                MenuIcon::Copy,
                true,
                Some(Click::CopyPrompt {
                    lens: id.clone(),
                    key: None,
                }),
            )?)?;
        }
        let more = if alerts.len() > MENU_LIMIT {
            format!("Show All {} in Lenstica", alerts.len())
        } else {
            "Show in Lenstica".to_string()
        };
        sub.append(&self.item(format!("{id}:open"), &more, true, Some(Click::OpenWindow))?)?;
        Ok(sub)
    }

    fn menu(&mut self, cfg: &Config, alerts: &[Severity]) -> Result<Menu<Wry>> {
        self.shared.clicks.clear();
        let app = self.app;
        let mut items: Vec<Box<dyn IsMenuItem<Wry>>> = Vec::new();
        let (headline, state) = match alerts.iter().max() {
            _ if self.shared.results.is_empty() => ("Checking…".to_string(), MenuIcon::Running),
            None => (
                format!("Nothing needs attention · {}-day cooldown", cfg.min_days),
                MenuIcon::Ok,
            ),
            Some(worst) => (
                format!(
                    "{} need attention · {}-day cooldown",
                    alerts.len(),
                    cfg.min_days
                ),
                MenuIcon::Problem(*worst),
            ),
        };
        items.push(Box::new(self.icon_item(
            "headline".into(),
            &headline,
            state,
            false,
            None,
        )?));
        items.push(Box::new(PredefinedMenuItem::separator(app)?));
        for r in lenses::registry(cfg)
            .iter()
            .filter(|r| lenses::enabled(cfg, r))
        {
            items.push(Box::new(self.lens(cfg, r)?));
        }
        items.push(Box::new(PredefinedMenuItem::separator(app)?));
        items.push(Box::new(self.shortcut(
            "window",
            "Open Lenstica",
            "CmdOrCtrl+O",
            Click::OpenWindow,
        )?));
        items.push(Box::new(self.shortcut(
            "settings",
            "Settings",
            "CmdOrCtrl+,",
            Click::OpenSettings,
        )?));
        items.push(Box::new(PredefinedMenuItem::separator(app)?));
        items.push(Box::new(self.shortcut(
            "quit",
            "Quit",
            "CmdOrCtrl+Q",
            Click::Quit,
        )?));
        let menu = Menu::new(app)?;
        for item in &items {
            menu.append(item.as_ref())?;
        }
        Ok(menu)
    }
}

/// Rebuild the menu, icon, count and tooltip from the latest results.
pub fn refresh(app: &AppHandle) {
    if let Err(e) = try_refresh(app) {
        eprintln!("lenstica: cannot update the menu: {e:#}");
    }
}

fn try_refresh(app: &AppHandle) -> Result<()> {
    let Some(tray) = app.tray_by_id(TRAY_ID) else {
        return Ok(());
    };
    let cfg = Config::load().unwrap_or_default();
    let state = app.state::<AppState>();
    let mut shared = state.shared.lock().unwrap_or_else(|p| p.into_inner());
    let alerts: Vec<Severity> = shared
        .results
        .values()
        .flat_map(|r| &r.findings)
        .filter(|f| lenses::is_alert(&cfg, f))
        .map(|f| f.severity)
        .collect();
    let empty = shared.results.is_empty();
    let debug = std::env::var_os("LENSTICA_DEBUG").is_some_and(|v| v != "0");
    let mut builder = Builder {
        app,
        shared: &mut shared,
        trace: debug.then(Vec::new),
    };
    let menu = builder.menu(&cfg, &alerts)?;
    if let Some(lines) = builder.trace.take() {
        eprintln!("lenstica menu:\n{}", lines.join("\n"));
    }
    drop(shared);
    let glyph = match (alerts.len(), empty) {
        (0, true) => Glyph::Checking,
        (0, false) => Glyph::Protected,
        _ => Glyph::Problem,
    };
    let critical = alerts.contains(&Severity::Critical);
    let tooltip = match alerts.len() {
        0 if empty => "Lenstica: checking…".to_string(),
        0 => "Lenstica: nothing needs attention".to_string(),
        n => format!(
            "Lenstica: {n} need attention{}",
            if critical { " (critical)" } else { "" }
        ),
    };
    tray.set_menu(Some(menu))?;
    tray.set_icon_with_as_template(Some(image(glyph)), glyph.is_template())?;
    tray.set_title((!alerts.is_empty()).then(|| alerts.len().to_string()))?;
    tray.set_tooltip(Some(tooltip))?;
    Ok(())
}
