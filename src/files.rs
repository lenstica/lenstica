//! Minimal, format-preserving edits of the config files Lenstica writes
//! directly (TOML via `toml_edit`, top-level YAML scalars), plus readers for
//! the formats it only scans (INI-style `.npmrc` / `pip.conf`).

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use toml_edit::{DocumentMut, InlineTable, Item, Table, TableLike, Value};

use crate::duration::unquote;

pub fn read_optional(path: &Path) -> Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("cannot read {}", path.display())),
    }
}

/// A suffix no other thread or process uses at the same time, for temp names.
pub fn unique_suffix() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    format!(
        "{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

/// Run a read-modify-write of Lenstica's state files with no other writer
/// active: lenses record from parallel threads, and the menu bar app and a
/// CLI run may write at the same moment.
pub fn with_state_lock<T>(f: impl FnOnce() -> Result<T>) -> Result<T> {
    static THREADS: Mutex<()> = Mutex::new(());
    let _thread = THREADS.lock().unwrap_or_else(PoisonError::into_inner);
    let _process = crate::system::wait_named_lock("state")?;
    f()
}

/// Parse a JSON file; `None` when it is missing, unreadable or malformed.
pub fn read_json<T: DeserializeOwned>(path: &Path) -> Option<T> {
    let text = read_optional(path).ok().flatten()?;
    serde_json::from_str(&text).ok()
}

fn backup_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".lenstica-backup");
    path.with_file_name(name)
}

/// Write via a temp file and rename. The first time Lenstica touches a file,
/// the original is kept next to it as `<name>.lenstica-backup` (empty when
/// there was no file, so a later write never backs up Lenstica's own text).
/// A symlinked file (dotfile managers) is written through the link, and the
/// file keeps its permissions: some of these files hold registry tokens.
pub fn write_atomic(path: &Path, contents: &str) -> Result<()> {
    let is_link = fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink());
    let target = if is_link {
        fs::canonicalize(path).with_context(|| format!("cannot follow {}", path.display()))?
    } else {
        path.to_path_buf()
    };
    let path = target.as_path();
    let backup = backup_path(path);
    // Before the rename to Lenstica, backups were `<name>.cooldown-backup`;
    // one of those already holds the original.
    let mut old = path.file_name().unwrap_or_default().to_os_string();
    old.push(".cooldown-backup");
    let backed_up = backup.exists() || path.with_file_name(old).exists();
    if !backed_up {
        if path.exists() {
            fs::copy(path, &backup)
                .with_context(|| format!("cannot back up {}", path.display()))?;
        } else {
            write_state(&backup, "")?;
        }
    }
    let permissions = fs::metadata(path).ok().map(|m| m.permissions());
    write_with(path, contents, permissions)
}

/// Write via a temp file and rename, without a backup: for Lenstica's own state.
pub fn write_state(path: &Path, contents: &str) -> Result<()> {
    write_with(path, contents, None)
}

fn write_with(path: &Path, contents: &str, permissions: Option<fs::Permissions>) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    }
    // Unique per writer, so two threads or processes writing the same file
    // never truncate each other's temp file mid-rename.
    let mut tmp_name = path.file_name().unwrap_or_default().to_os_string();
    tmp_name.push(format!(".{}.lenstica-tmp", unique_suffix()));
    let tmp = path.with_file_name(tmp_name);
    fs::write(&tmp, contents).with_context(|| format!("cannot write {}", tmp.display()))?;
    if let Some(p) = permissions {
        fs::set_permissions(&tmp, p)
            .with_context(|| format!("cannot set permissions on {}", tmp.display()))?;
    }
    fs::rename(&tmp, path).with_context(|| format!("cannot replace {}", path.display()))
}

// ---- JSON with comments ------------------------------------------------------

/// JSON with comments and trailing commas (`bun.lock`, VS Code and opencode
/// settings) as plain JSON.
pub fn jsonc_to_json(src: &str) -> String {
    strip_trailing_commas(&strip_json_comments(src))
}

fn strip_json_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut chars = src.chars().peekable();
    let (mut in_string, mut escaped) = (false, false);
    while let Some(c) = chars.next() {
        if in_string {
            out.push(c);
            match c {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match (c, chars.peek()) {
            ('/', Some('/')) => while chars.next_if(|&n| n != '\n').is_some() {},
            ('/', Some('*')) => {
                chars.next();
                let mut prev = '\0';
                for n in chars.by_ref() {
                    if prev == '*' && n == '/' {
                        break;
                    }
                    prev = n;
                }
                out.push(' ');
            }
            _ => {
                in_string = c == '"';
                out.push(c);
            }
        }
    }
    out
}

fn strip_trailing_commas(src: &str) -> String {
    let chars: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let (mut in_string, mut escaped) = (false, false);
    for (i, &c) in chars.iter().enumerate() {
        if in_string {
            out.push(c);
            match c {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }
        if c == '"' {
            in_string = true;
        } else if c == ',' {
            let next = chars[i + 1..].iter().find(|n| !n.is_whitespace());
            if matches!(next, Some('}' | ']')) {
                continue;
            }
        }
        out.push(c);
    }
    out
}

// ---- TOML -------------------------------------------------------------------

pub fn toml_get(src: &str, keys: &[&str]) -> Result<Option<String>> {
    let doc: DocumentMut = src.parse().context("invalid TOML")?;
    let mut item: &Item = doc.as_item();
    for key in keys {
        match item.get(key) {
            Some(next) => item = next,
            None => return Ok(None),
        }
    }
    Ok(match item.as_value() {
        Some(Value::String(s)) => Some(s.value().clone()),
        Some(other) => {
            // Without its decor: `604800 # 7 days` is the number alone.
            let mut bare = other.clone();
            bare.decor_mut().clear();
            Some(bare.to_string())
        }
        None => None,
    })
}

/// Set `keys` to `value`, creating tables as needed. A comment on a replaced
/// value described the old value and goes with it, as in [`yaml_set_top`].
pub fn toml_set(src: &str, keys: &[&str], value: Value) -> Result<String> {
    let (last, tables) = keys.split_last().expect("at least one key");
    let mut doc: DocumentMut = src.parse().context("invalid TOML")?;
    toml_table_at(doc.as_item_mut(), tables)?.insert(last, Item::Value(value));
    Ok(doc.to_string())
}

/// The table at `keys` under `item`, created where missing: a `[table]`, or
/// an inline table inside an inline one (`install = { ... }`).
pub fn toml_table_at<'a>(mut item: &'a mut Item, keys: &[&str]) -> Result<&'a mut dyn TableLike> {
    for key in keys {
        let inline = item.as_inline_table().is_some();
        let table = item
            .as_table_like_mut()
            .with_context(|| format!("`{key}`'s parent is not a table; edit it by hand"))?;
        if !table.contains_key(key) {
            let new = if inline {
                Item::Value(Value::InlineTable(InlineTable::new()))
            } else {
                Item::Table(Table::new())
            };
            table.insert(key, new);
        }
        item = table.get_mut(key).expect("just inserted");
    }
    item.as_table_like_mut().with_context(|| {
        format!(
            "`{}` exists but is not a table; edit it by hand",
            keys.join(".")
        )
    })
}

// ---- YAML (top-level scalar keys only) --------------------------------------

fn yaml_key_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(key).or_else(|| {
        ['"', '\''].into_iter().find_map(|q| {
            line.strip_prefix(q)
                .and_then(|l| l.strip_prefix(key))
                .and_then(|l| l.strip_prefix(q))
        })
    })?;
    rest.trim_start().strip_prefix(':')
}

fn strip_yaml_comment(value: &str) -> &str {
    let v = value.trim();
    if v.starts_with('"') || v.starts_with('\'') {
        let quote = v.as_bytes()[0] as char;
        return match v[1..].find(quote) {
            Some(end) => &v[..end + 2],
            None => v,
        };
    }
    match v.find(" #") {
        Some(i) => v[..i].trim_end(),
        None if v.starts_with('#') => "",
        None => v,
    }
}

pub fn yaml_get_top(src: &str, key: &str) -> Option<String> {
    src.lines()
        .filter_map(|line| yaml_key_value(line, key))
        .map(|v| unquote(strip_yaml_comment(v)).to_string())
        .next_back()
        .filter(|v| !v.is_empty() && v != "null" && v != "~")
}

/// Replace (or append) `key: value` at the top level, dropping any indented
/// block that belonged to a previous value of the key. A comment on the
/// replaced line described the old value and goes with it; the file's line
/// endings stay.
pub fn yaml_set_top(src: &str, key: &str, value: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut replaced = false;
    let mut skipping_block = false;
    for line in src.lines() {
        if skipping_block {
            if line.starts_with(' ') || line.starts_with('\t') {
                continue;
            }
            skipping_block = false;
        }
        if yaml_key_value(line, key).is_some() {
            if !replaced {
                out.push(format!("{key}: {value}"));
                replaced = true;
            }
            skipping_block = true;
            continue;
        }
        out.push(line.to_string());
    }
    if !replaced {
        while out.last().is_some_and(|l| l.trim().is_empty()) {
            out.pop();
        }
        out.push(format!("{key}: {value}"));
    }
    let newline = if src.contains("\r\n") { "\r\n" } else { "\n" };
    let mut text = out.join(newline);
    text.push_str(newline);
    text
}

// ---- INI (`.npmrc`, `pip.conf`) ---------------------------------------------

/// Last value of `key` in `section` (`None` = keys outside any section).
pub fn ini_get(src: &str, section: Option<&str>, key: &str) -> Option<String> {
    let mut current: Option<String> = None;
    let mut found = None;
    for raw in src.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            current = Some(name.trim().to_ascii_lowercase());
            continue;
        }
        if current.as_deref() != section {
            continue;
        }
        let Some((k, v)) = line.split_once(['=', ':']) else {
            continue;
        };
        if k.trim() == key {
            found = Some(unquote(v).to_string());
        }
    }
    found.filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edits_keep_comments_inline_tables_and_line_endings() {
        let src = "[install]\nminimumReleaseAge = 604800 # 7 days\n";
        assert_eq!(
            toml_get(src, &["install", "minimumReleaseAge"]).unwrap(),
            Some("604800".to_string())
        );
        let out = toml_set(
            src,
            &["install", "minimumReleaseAge"],
            Value::from(1_209_600),
        )
        .unwrap();
        assert_eq!(out, "[install]\nminimumReleaseAge = 1209600\n");
        let inline = "install = { registry = \"x\" }\n";
        let out = toml_set(inline, &["install", "minimumReleaseAge"], Value::from(1)).unwrap();
        assert_eq!(
            toml_get(&out, &["install", "minimumReleaseAge"]).unwrap(),
            Some("1".to_string())
        );
        assert_eq!(
            yaml_set_top(
                "a: 1\r\n'enableScripts': true\r\n",
                "enableScripts",
                "false"
            ),
            "a: 1\r\nenableScripts: false\r\n"
        );
    }

    #[test]
    fn jsonc_becomes_json() {
        assert_eq!(jsonc_to_json("{\"a\": \"x,}\",}"), "{\"a\": \"x,}\"}");
        let src = "{\n  // servers\n  \"url\": \"http://x//y\", /* old */\n  \"b\": [1,],\n}";
        let v: serde_json::Value = serde_json::from_str(&jsonc_to_json(src)).unwrap();
        assert_eq!(v["url"], "http://x//y");
        assert_eq!(v["b"], serde_json::json!([1]));
    }

    #[test]
    fn toml_round_trip_keeps_comments() {
        let src = "# mine\n[install]\n# keep\nregistry = \"x\"\n";
        let out = toml_set(src, &["install", "minimumReleaseAge"], Value::from(604800)).unwrap();
        assert!(out.contains("# mine") && out.contains("# keep"));
        assert_eq!(
            toml_get(&out, &["install", "minimumReleaseAge"])
                .unwrap()
                .as_deref(),
            Some("604800")
        );
        let top = toml_set("", &["exclude-newer"], Value::from("7 days")).unwrap();
        assert_eq!(top.trim(), "exclude-newer = \"7 days\"");
        assert_eq!(
            toml_get(&top, &["exclude-newer"]).unwrap().as_deref(),
            Some("7 days")
        );
        assert!(toml_set("install = 3\n", &["install", "x"], Value::from(1)).is_err());
    }

    #[test]
    fn yaml_top_level_scalars() {
        let src = "nodeLinker: node-modules\nnpmMinimalAgeGate: 1440 # one day\nplugins:\n  - a\n";
        assert_eq!(
            yaml_get_top(src, "npmMinimalAgeGate").as_deref(),
            Some("1440")
        );
        let out = yaml_set_top(src, "npmMinimalAgeGate", "10080");
        assert_eq!(
            out,
            "nodeLinker: node-modules\nnpmMinimalAgeGate: 10080\nplugins:\n  - a\n"
        );
        let appended = yaml_set_top("a: 1\n\n", "npmMinimalAgeGate", "10080");
        assert_eq!(appended, "a: 1\nnpmMinimalAgeGate: 10080\n");
        // An indented key belongs to another mapping and is not ours.
        assert_eq!(
            yaml_get_top("x:\n  npmMinimalAgeGate: 1\n", "npmMinimalAgeGate"),
            None
        );
        assert_eq!(
            yaml_get_top("minimumReleaseAge: \"7d\"\n", "minimumReleaseAge").as_deref(),
            Some("7d")
        );
    }

    #[test]
    fn ini_sections() {
        let npmrc = "registry=https://x\nmin-release-age = 3\n";
        assert_eq!(
            ini_get(npmrc, None, "min-release-age").as_deref(),
            Some("3")
        );
        let pip = "[global]\ntimeout = 5\n[install]\nuploaded-prior-to = P2D\n";
        assert_eq!(
            ini_get(pip, Some("install"), "uploaded-prior-to").as_deref(),
            Some("P2D")
        );
        assert_eq!(ini_get(pip, Some("global"), "uploaded-prior-to"), None);
    }
}
