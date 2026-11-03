//! What the window can ask for, through one `action` command. Slow work goes
//! to the scheduler or a thread; results come back as `state` and `toast` events.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use serde_json::Value;
use tauri::{AppHandle, Emitter, Manager};

use super::{AppState, Request};
use crate::autostart::{self, Kind};
use crate::config::{self, Config};
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
                    "excluded": excluded,
                    // Excluded through a parent folder or the main checkout, not by itself.
                    "inherited": excluded && !exclude.paths.contains(&r.path),
                })
            })
            .collect(),
    ))
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
        "run" => match msg.get("lens").and_then(Value::as_str) {
            Some(id) => state.send(Request::Run(vec![id.to_string()], false)),
            None => state.send(Request::CheckAll),
        },
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
            super::toast(app, format!("Added {entry} to audit.ignore"), true);
            state.send(Request::Run(
                vec![str_field(msg, "lens")?.to_string()],
                true,
            ));
        }
        "ignoreAdvisory" => {
            let id = str_field(msg, "id")?;
            config::add_to_list(&["lenses", "vulnerabilities", "ignore_advisories"], id)?;
            super::toast(app, format!("Ignoring advisory {id}"), true);
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
            super::toast(app, format!("Saved {}", path.join(".")), true);
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
                format!(
                    "Lenstica will {} {id}",
                    if on { "manage" } else { "leave alone" }
                ),
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
                super::toast(app, format!("Leaving out {shown}"), true);
            } else {
                // The entry may be written either way; remove both spellings.
                let a = config::remove_from_list(&["scan", "exclude"], &shown)?;
                let b = config::remove_from_list(&["scan", "exclude"], &raw)?;
                if !(a || b) {
                    bail!(
                        "{shown} is left out through a parent folder or a name in scan.exclude; edit that entry instead"
                    );
                }
                super::toast(app, format!("Searching {shown} again"), true);
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
            crate::notify::send(
                "Lenstica",
                "Test notification. New findings will appear like this.",
            )?;
        }
        "installSkill" => {
            let path = crate::agent::install_skill(None)?;
            super::toast(
                app,
                format!("Installed the skill at {}", crate::paths::tilde(&path)),
                true,
            );
        }
        "copyText" => {
            use tauri_plugin_clipboard_manager::ClipboardExt;
            app.clipboard()
                .write_text(str_field(msg, "text")?.to_string())
                .map_err(|e| anyhow::anyhow!("cannot copy: {e}"))?;
            super::toast(app, "Copied", true);
        }
        other => bail!("unknown action `{other}`"),
    }
    Ok(())
}
