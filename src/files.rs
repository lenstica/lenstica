//! Minimal, format-preserving edits of the config files Lenstica writes
//! directly (TOML via `toml_edit`, top-level YAML scalars), plus readers for
//! the formats it only scans (INI-style `.npmrc` / `pip.conf`).

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use toml_edit::{DocumentMut, Item, Value};

use crate::duration::unquote;

pub fn read_optional(path: &Path) -> Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("cannot read {}", path.display())),
    }
}

fn backup_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".lenstica-backup");
    path.with_file_name(name)
}

/// Write via a temp file and rename. The first time Lenstica touches an
/// existing file, the original is kept next to it as `<name>.lenstica-backup`.
pub fn write_atomic(path: &Path, contents: &str) -> Result<()> {
    let backup = backup_path(path);
    // Before the rename to Lenstica, backups were `<name>.cooldown-backup`;
    // one of those already holds the original.
    let mut old = path.file_name().unwrap_or_default().to_os_string();
    old.push(".cooldown-backup");
    let backed_up = backup.exists() || path.with_file_name(old).exists();
    if path.exists() && !backed_up {
        fs::copy(path, &backup).with_context(|| format!("cannot back up {}", path.display()))?;
    }
    write_state(path, contents)
}

/// Write via a temp file and rename, without a backup: for Lenstica's own state.
pub fn write_state(path: &Path, contents: &str) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    }
    let mut tmp_name = path.file_name().unwrap_or_default().to_os_string();
    tmp_name.push(".lenstica-tmp");
    let tmp = path.with_file_name(tmp_name);
    fs::write(&tmp, contents).with_context(|| format!("cannot write {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| format!("cannot replace {}", path.display()))
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
        Some(other) => Some(other.to_string().trim().to_string()),
        None => None,
    })
}

pub fn toml_set(src: &str, keys: &[&str], value: Value) -> Result<String> {
    let (last, tables) = keys.split_last().expect("at least one key");
    let mut doc: DocumentMut = src.parse().context("invalid TOML")?;
    let mut table = doc.as_table_mut();
    for key in tables {
        if !table.contains_key(key) {
            table.insert(key, Item::Table(toml_edit::Table::new()));
        }
        table = match table.get_mut(key).and_then(Item::as_table_mut) {
            Some(t) => t,
            None => bail!("`{key}` exists but is not a [table]; edit it by hand"),
        };
    }
    table.insert(last, Item::Value(value));
    Ok(doc.to_string())
}

// ---- YAML (top-level scalar keys only) --------------------------------------

fn yaml_key_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(key).or_else(|| {
        line.strip_prefix('"')
            .and_then(|l| l.strip_prefix(key))
            .and_then(|l| l.strip_prefix('"'))
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
/// block that belonged to a previous value of the key.
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
    let mut text = out.join("\n");
    text.push('\n');
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
        if line.starts_with('[') && line.ends_with(']') {
            current = Some(line[1..line.len() - 1].trim().to_ascii_lowercase());
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
