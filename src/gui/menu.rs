//! The tray icon and its menu: one submenu per category, built from the
//! lenses' categories and their findings alone, so any lens (built-in, plugin
//! crate or external tool) shows up without changes here.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;

use anyhow::Result;
use lenstica_lens::{Category, Finding, Severity};
use tauri::image::Image;
use tauri::menu::{
    IconMenuItem, IsMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu,
};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Manager, Wry};

use super::{AppState, Request};
use crate::config::Config;
use crate::i18n::{self, t};
use crate::icon::{self, Glyph, MenuIcon};
use crate::lenses::{self, store::RunResult};

const TRAY_ID: &str = "lenstica";
/// Findings listed per category submenu; the window shows them all.
const MENU_LIMIT: usize = 25;

#[derive(Clone)]
pub enum Click {
    Fix {
        lens: String,
        key: String,
    },
    /// Copy a prompt for an AI agent covering these (lens, finding key) pairs.
    CopyPrompt(Vec<(String, Option<String>)>),
    ShowFinding {
        category: Category,
        lens: String,
        key: String,
    },
    ShowCategory(Category),
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
        .tooltip(t!("notify.title"))
        .menu(&menu)
        .show_menu_on_left_click(true)
        .on_menu_event(on_click)
        .build(app)?;
    refresh(app);
    Ok(())
}

fn on_click(app: &AppHandle, event: MenuEvent) {
    let state = app.state::<AppState>();
    let click = state.lock().clicks.get(&event.id.0).cloned();
    let outcome = match click {
        Some(Click::Fix { lens, key }) => {
            state.send(Request::Fix { lens, key });
            Ok(())
        }
        Some(Click::CopyPrompt(items)) => super::copy_prompt(app, &items),
        Some(Click::ShowFinding {
            category,
            lens,
            key,
        }) => {
            super::show_finding(app, category, &lens, &key);
            Ok(())
        }
        Some(Click::ShowCategory(category)) => {
            super::show_page(app, category.id());
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
        Some(Click::OpenFile(path)) => crate::apps::open(crate::apps::Role::Editor, &path),
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

/// How deep an item sits, from its id: `packages:l0` 1, `packages:f0:fix` 2.
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

/// A severity's name in the app's language: "Medium".
fn severity_name(s: Severity) -> String {
    t!(&format!("severity.{}", s.label()))
}

/// A category's name in the app's language.
fn category_name(c: Category) -> String {
    i18n::message_or(&format!("categories.{}.title", c.id()), c.title(), &[])
}

/// The file a finding points at, if it is one that can be opened.
fn file_of(f: &Finding) -> Option<PathBuf> {
    f.locations
        .iter()
        .find_map(|l| l.path.clone())
        .filter(|p| p.is_file())
}

/// Builds menu items while recording what each one does. Works from a
/// snapshot: every menu call waits for the main thread, which may itself be
/// waiting for the shared state, so the state is never locked while building.
struct Builder<'a> {
    app: &'a AppHandle,
    results: &'a BTreeMap<String, RunResult>,
    running: &'a BTreeSet<String>,
    clicks: HashMap<String, Click>,
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
            self.clicks.insert(id.to_string(), click);
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
            &t!(
                "menu.findingAbout",
                severity = severity_name(f.severity),
                lens = lens_title
            ),
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
                &t!("menu.openFile", file = truncate(&name, 40)),
                true,
                Some(Click::OpenFile(path)),
            )?)?;
        }
        sub.append(&self.icon_item(
            format!("{id}:prompt"),
            &t!("menu.copyPrompt"),
            MenuIcon::Copy,
            true,
            Some(Click::CopyPrompt(vec![(
                f.lens.clone(),
                Some(f.key.clone()),
            )])),
        )?)?;
        sub.append(&self.item(
            format!("{id}:show"),
            &t!("menu.show"),
            true,
            Some(Click::ShowFinding {
                category: f.category,
                lens: f.lens.clone(),
                key: f.key.clone(),
            }),
        )?)?;
        Ok(sub)
    }

    /// A lens's state: running, never run, failed, or the worst of its alerts.
    fn lens_state(&self, cfg: &Config, id: &str) -> MenuIcon {
        let result = self.results.get(id);
        if self.running.contains(id) {
            return MenuIcon::Running;
        }
        match result {
            None => MenuIcon::NotRun,
            Some(res) if res.error.is_some() => MenuIcon::Failed,
            Some(res) => res
                .findings
                .iter()
                .filter(|f| lenses::is_alert(cfg, f))
                .map(|f| f.severity)
                .max()
                .map_or(MenuIcon::Ok, MenuIcon::Problem),
        }
    }

    /// One category: its lenses' state, then its findings that need attention.
    fn category(
        &mut self,
        cfg: &Config,
        category: Category,
        members: &[&lenses::Registered],
    ) -> Result<Submenu<Wry>> {
        let id = category.id();
        let on: Vec<&lenses::Registered> = members
            .iter()
            .copied()
            .filter(|r| lenses::enabled(cfg, r))
            .collect();
        let mut alerts: Vec<(&Finding, &str)> = on
            .iter()
            .filter_map(|r| self.results.get(r.id()))
            .flat_map(|res| res.findings.iter().map(move |f| (f, res.title.as_str())))
            .filter(|(f, _)| f.category == category && lenses::is_alert(cfg, f))
            .collect();
        alerts.sort_by(|a, b| lenses::by_severity(a.0, b.0));
        let states: Vec<MenuIcon> = on.iter().map(|r| self.lens_state(cfg, r.id())).collect();
        let state = if states.contains(&MenuIcon::Running) {
            MenuIcon::Running
        } else if let Some((worst, _)) = alerts.first() {
            MenuIcon::Problem(worst.severity)
        } else if states.contains(&MenuIcon::Failed) {
            MenuIcon::Failed
        } else if states.is_empty() || states.contains(&MenuIcon::NotRun) {
            MenuIcon::NotRun
        } else {
            MenuIcon::Ok
        };
        let name = category_name(category);
        let label = match alerts.len() {
            0 => name.clone(),
            n => format!("{name} ({n})"),
        };
        self.trace(0, &label, Some(state), None);
        let sub = Submenu::with_id_and_icon(
            self.app,
            format!("{id}:menu"),
            label,
            true,
            Some(menu_image(state)),
        )?;
        let open = Click::ShowCategory(category);
        for (i, r) in members.iter().enumerate() {
            let (icon, status) = if lenses::enabled(cfg, r) {
                let status = self.results.get(r.id()).map_or_else(
                    || t!("menu.notRun"),
                    |res| {
                        res.error
                            .as_ref()
                            .map_or_else(|| res.summary.clone(), |e| t!("lens.failed", error = e))
                    },
                );
                (self.lens_state(cfg, r.id()), status)
            } else if r.lens.third_party().is_some() {
                (MenuIcon::NotRun, t!("menu.offThirdParty"))
            } else {
                (MenuIcon::NotRun, t!("menu.off"))
            };
            let text = truncate(
                &t!("menu.lensLine", lens = r.lens.title(), status = status),
                90,
            );
            sub.append(&self.icon_item(
                format!("{id}:l{i}"),
                &text,
                icon,
                true,
                Some(open.clone()),
            )?)?;
        }
        if !alerts.is_empty() {
            sub.append(&PredefinedMenuItem::separator(self.app)?)?;
        }
        for (i, (f, title)) in alerts.iter().take(MENU_LIMIT).enumerate() {
            sub.append(&self.finding(&format!("{id}:f{i}"), f, title)?)?;
        }
        sub.append(&PredefinedMenuItem::separator(self.app)?)?;
        if alerts.len() > 1 {
            let items = alerts
                .iter()
                .map(|(f, _)| (f.lens.clone(), Some(f.key.clone())))
                .collect();
            sub.append(&self.icon_item(
                format!("{id}:prompt"),
                &t!("menu.copyAll", count = alerts.len()),
                MenuIcon::Copy,
                true,
                Some(Click::CopyPrompt(items)),
            )?)?;
        }
        let more = if alerts.len() > MENU_LIMIT {
            t!("menu.showAll", count = alerts.len())
        } else {
            t!("menu.openCategory", category = name)
        };
        sub.append(&self.item(format!("{id}:open"), &more, true, Some(open))?)?;
        Ok(sub)
    }

    fn menu(&mut self, cfg: &Config, alerts: &[Severity]) -> Result<Menu<Wry>> {
        let app = self.app;
        let mut items: Vec<Box<dyn IsMenuItem<Wry>>> = Vec::new();
        let (headline, state) = match alerts.iter().max() {
            _ if self.results.is_empty() => (t!("menu.checking"), MenuIcon::Running),
            None => (t!("menu.clear", days = cfg.min_days), MenuIcon::Ok),
            Some(worst) => (
                t!("menu.need", count = alerts.len(), days = cfg.min_days),
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
        let registry = lenses::registry(cfg);
        for category in Category::ALL {
            let members = lenses::in_category(&registry, category);
            // A category no lens covers (yet) is left out.
            if !members.is_empty() {
                items.push(Box::new(self.category(cfg, category, &members)?));
            }
        }
        items.push(Box::new(PredefinedMenuItem::separator(app)?));
        items.push(Box::new(self.shortcut(
            "window",
            &t!("menu.openLenstica"),
            "CmdOrCtrl+O",
            Click::OpenWindow,
        )?));
        items.push(Box::new(self.shortcut(
            "settings",
            &t!("menu.settings"),
            "CmdOrCtrl+,",
            Click::OpenSettings,
        )?));
        items.push(Box::new(PredefinedMenuItem::separator(app)?));
        items.push(Box::new(self.shortcut(
            "quit",
            &t!("menu.quit"),
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
    let (results, running) = {
        let shared = state.lock();
        (shared.results.clone(), shared.running.clone())
    };
    // Lenses turned off since their last run are not counted, as in their menus.
    let enabled = lenses::enabled_ids(&cfg);
    let alerts: Vec<Severity> = results
        .iter()
        .filter(|(id, _)| enabled.contains(*id))
        .flat_map(|(_, r)| &r.findings)
        .filter(|f| lenses::is_alert(&cfg, f))
        .map(|f| f.severity)
        .collect();
    let empty = results.is_empty();
    let mut builder = Builder {
        app,
        results: &results,
        running: &running,
        clicks: HashMap::new(),
        trace: super::debug().then(Vec::new),
    };
    let menu = builder.menu(&cfg, &alerts)?;
    if let Some(lines) = builder.trace.take() {
        eprintln!("lenstica menu:\n{}", lines.join("\n"));
    }
    state.lock().clicks = builder.clicks;
    let glyph = match (alerts.len(), empty) {
        (0, true) => Glyph::Checking,
        (0, false) => Glyph::Protected,
        _ => Glyph::Problem,
    };
    let critical = alerts.contains(&Severity::Critical);
    let tooltip = match alerts.len() {
        0 if empty => t!("menu.tooltipChecking"),
        0 => t!("menu.tooltipClear"),
        n if critical => t!("menu.tooltipCritical", count = n),
        n => t!("menu.tooltipNeed", count = n),
    };
    tray.set_menu(Some(menu))?;
    tray.set_icon_with_as_template(Some(image(glyph)), glyph.is_template())?;
    tray.set_tooltip(Some(tooltip))?;
    Ok(())
}
