//! What the window can ask for, through one `action` command. Slow work goes
//! to the scheduler or a thread; results come back as `state` and `toast` events.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use serde_json::Value;
use tauri::{AppHandle, Emitter, Manager};

use super::{AppState, Request};
use crate::autostart::{self, Kind};
use crate::config::{self, Config};
use crate::i18n::t;
use crate::system;

/// The window's state, returned directly so the first paint never depends on an event.
#[tauri::command]
pub fn get_state(app: AppHandle) -> Value {
    super::state(&app)
}

/// Every repository and worktree under the search roots, with whether
/// `scan.exclude` leaves it out. Async: walking the roots takes a moment, and
/// must not block the window.
#[tauri::command]
pub async fn list_repos() -> Result<Value, String> {
    let cfg = Config::load().map_err(|e| format!("{e:#}"))?;
    let search = crate::exec::search_path(&cfg.extra_path());
    let exclude = cfg.exclude();
    let repos = crate::scan::repositories(&cfg.scan_roots(), cfg.scan.max_depth, &search);
    Ok(Value::Array(
        repos
            .into_iter()
            .map(|r| {
                let excluded = exclude.skips(&r.path)
                    || r.worktree_of.as_deref().is_some_and(|m| exclude.skips(m));
                serde_json::json!({
                    "path": r.path,
                    "label": crate::paths::tilde(&r.path),
                    "worktreeOf": r.worktree_of.as_deref().map(crate::paths::tilde),
                    // The main checkout's path, so findings in a worktree count for its project.
                    "mainPath": r.worktree_of.as_deref().unwrap_or(&r.path),
                    "excluded": excluded,
                    // Excluded through a parent folder or the main checkout, not by itself.
                    "inherited": excluded && !exclude.paths.contains(&r.path),
                })
            })
            .collect(),
    ))
}

/// What prompt templates being edited in Settings would write: for one
/// finding and for several, from the current alerts (samples when there are
/// fewer than two). An empty template means Lenstica's own.
#[tauri::command]
pub fn preview_prompt(
    app: AppHandle,
    finding: String,
    findings: String,
    item: String,
) -> Result<Value, String> {
    use crate::prompt::{self, Templates};
    let or = |custom: &str, default: &'static str| {
        if custom.trim().is_empty() {
            default.to_string()
        } else {
            custom.to_string()
        }
    };
    let (finding, findings, item) = (
        or(&finding, prompt::DEFAULT_FINDING),
        or(&findings, prompt::DEFAULT_FINDINGS),
        or(&item, prompt::DEFAULT_ITEM),
    );
    let t = Templates {
        finding: &finding,
        findings: &findings,
        item: &item,
    };
    t.check().map_err(|e| format!("{e:#}"))?;
    let cfg = Config::load().unwrap_or_default();
    let results = app.state::<AppState>().lock().results.clone();
    let alerts = prompt::collect(&cfg, &results, &[]);
    let samples = prompt::samples();
    let list: Vec<(&lenstica_lens::Finding, &str)> = if alerts.len() >= 2 {
        alerts.into_iter().take(3).collect()
    } else {
        samples.iter().map(|(f, title)| (f, *title)).collect()
    };
    Ok(serde_json::json!({
        "one": prompt::write_one(&t, list[0].0, list[0].1),
        "many": prompt::write_many(&t, &list),
        "real": list[0].0.key != samples[0].0.key,
    }))
}

/// A finding to write a prompt for; no `key` means all of the lens's alerts.
#[derive(serde::Deserialize)]
pub struct PromptItem {
    lens: String,
    key: Option<String>,
}

/// The prompt Copy Prompt for AI Agent would copy, to show before copying.
#[tauri::command]
pub fn prompt_text(app: AppHandle, items: Vec<PromptItem>) -> Result<Value, String> {
    let items: Vec<(String, Option<String>)> = items.into_iter().map(|i| (i.lens, i.key)).collect();
    let (text, count) = super::prompt_text(&app, &items).map_err(|e| format!("{e:#}"))?;
    Ok(serde_json::json!({ "text": text, "count": count }))
}

#[tauri::command]
pub fn action(app: AppHandle, msg: Value) -> Result<(), String> {
    if super::debug() {
        eprintln!("lenstica window: {msg}");
    }
    handle(&app, &msg).map_err(|e| format!("{e:#}"))
}

fn str_field<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v.get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("missing `{key}`"))
}

fn toml_value(v: &Value) -> Result<toml_edit::Value> {
    Ok(match v {
        Value::Bool(b) => (*b).into(),
        Value::Number(n) => n
            .as_i64()
            .context("settings take whole numbers only")?
            .into(),
        Value::String(s) => s.as_str().into(),
        Value::Array(items) => {
            let mut array = toml_edit::Array::new();
            for item in items {
                array.push(item.as_str().context("lists hold text only")?);
            }
            toml_edit::Value::Array(array)
        }
        other => bail!("unsupported setting value {other}"),
    })
}

fn handle(app: &AppHandle, msg: &Value) -> Result<()> {
    let state = app.state::<AppState>();
    match str_field(msg, "type")? {
        "rendered" => {}
        "ready" | "refresh" => {
            let _ = app.emit("state", super::state(app));
        }
        // One lens, several (a category's), or every enabled lens.
        "run" => {
            let ids: Vec<String> = match (msg.get("lens"), msg.get("lenses")) {
                (Some(id), _) => vec![id.as_str().context("`lens` is text")?.to_string()],
                (None, Some(list)) => list
                    .as_array()
                    .context("`lenses` is a list")?
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect(),
                (None, None) => Vec::new(),
            };
            if ids.is_empty() {
                state.send(Request::CheckAll);
            } else {
                state.send(Request::Run(ids, false));
            }
        }
        "fix" => state.send(Request::Fix {
            lens: str_field(msg, "lens")?.to_string(),
            key: str_field(msg, "key")?.to_string(),
        }),
        "open" => {
            let path = PathBuf::from(str_field(msg, "path")?);
            if msg.get("reveal").and_then(Value::as_bool) == Some(true) {
                system::reveal(&path)?;
            } else {
                system::open_any(&path)?;
            }
        }
        "openUrl" => system::open_url(str_field(msg, "url")?)?,
        "openConfig" => system::open(&config::ensure_exists()?)?,
        "ignorePackage" => {
            let entry = str_field(msg, "entry")?;
            config::add_to_list(&["audit", "ignore"], entry)?;
            super::toast(app, t!("toast.ignoredPackage", entry = entry), true);
            state.send(Request::Run(
                vec![str_field(msg, "lens")?.to_string()],
                true,
            ));
        }
        "ignoreAdvisory" => {
            let id = str_field(msg, "id")?;
            config::add_to_list(&["lenses", "vulnerabilities", "ignore_advisories"], id)?;
            super::toast(app, t!("toast.ignoredAdvisory", id = id), true);
            state.send(Request::Run(vec!["vulnerabilities".to_string()], true));
        }
        "setting" => {
            let path: Vec<String> = msg
                .get("path")
                .and_then(Value::as_array)
                .context("missing `path`")?
                .iter()
                .map(|p| {
                    p.as_str()
                        .map(String::from)
                        .context("`path` holds text only")
                })
                .collect::<Result<_>>()?;
            let keys: Vec<&str> = path.iter().map(String::as_str).collect();
            config::set_value(
                &keys,
                toml_value(msg.get("value").context("missing `value`")?)?,
            )?;
            super::toast(app, t!("toast.saved", setting = path.join(".")), true);
            super::refresh(app);
        }
        "toggleLens" => {
            let on = msg
                .get("enabled")
                .and_then(Value::as_bool)
                .context("missing `enabled`")?;
            config::set_value(&["lenses", str_field(msg, "id")?, "enabled"], on.into())?;
            super::refresh(app);
        }
        "toggleManager" => {
            let id = str_field(msg, "id")?;
            if crate::managers::by_id(id).is_none() {
                bail!("unknown package manager `{id}`");
            }
            let on = msg.get("enabled").and_then(Value::as_bool) == Some(true);
            if on {
                config::remove_from_list(&["managers", "disabled"], id)?;
            } else {
                config::add_to_list(&["managers", "disabled"], id)?;
            }
            super::toast(
                app,
                if on {
                    t!("toast.manage", name = id)
                } else {
                    t!("toast.leaveAlone", name = id)
                },
                true,
            );
            super::refresh(app);
        }
        "toggleExclude" => {
            let path = PathBuf::from(str_field(msg, "path")?);
            let shown = crate::paths::tilde(&path);
            let raw = path.to_string_lossy().into_owned();
            if msg.get("excluded").and_then(Value::as_bool) == Some(true) {
                config::add_to_list(&["scan", "exclude"], &shown)?;
                super::toast(app, t!("toast.leavingOut", path = shown), true);
            } else {
                // The entry may be written either way; remove both spellings.
                let a = config::remove_from_list(&["scan", "exclude"], &shown)?;
                let b = config::remove_from_list(&["scan", "exclude"], &raw)?;
                if !(a || b) {
                    bail!(
                        "{shown} is left out through a parent folder or a name in scan.exclude; edit that entry instead"
                    );
                }
                super::toast(app, t!("toast.searchingAgain", path = shown), true);
            }
            super::refresh(app);
        }
        "autostart" => {
            if msg.get("enabled").and_then(Value::as_bool) == Some(true) {
                autostart::install(Kind::Tray, false)?;
            } else {
                // Not stopped: the running app is the one whose switch was turned off.
                autostart::uninstall(false)?;
            }
            super::refresh(app);
        }
        "apply" => state.send(Request::ApplyAll),
        "copyPrompt" => {
            let items: Vec<(String, Option<String>)> = msg
                .get("items")
                .and_then(Value::as_array)
                .context("missing `items`")?
                .iter()
                .filter_map(|i| {
                    Some((
                        i.get("lens")?.as_str()?.to_string(),
                        i.get("key").and_then(Value::as_str).map(String::from),
                    ))
                })
                .collect();
            super::copy_prompt(app, &items)?;
        }
        "testNotification" => {
            crate::notify::send(&t!("notify.title"), &t!("notify.test"))?;
        }
        "installSkill" => {
            let path = crate::agent::install_skill(None)?;
            super::toast(
                app,
                t!("toast.installedSkill", path = crate::paths::tilde(&path)),
                true,
            );
        }
        "copyText" => {
            use tauri_plugin_clipboard_manager::ClipboardExt;
            app.clipboard()
                .write_text(str_field(msg, "text")?.to_string())
                .map_err(|e| anyhow::anyhow!("cannot copy: {e}"))?;
            let said = msg
                .get("toast")
                .and_then(Value::as_str)
                .map_or_else(|| t!("toast.copied"), String::from);
            super::toast(app, said, true);
        }
        other => bail!("unknown action `{other}`"),
    }
    Ok(())
}
