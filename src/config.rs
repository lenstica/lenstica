//! The one settings file: `~/.config/lenstica/lenstica.toml`
//! (`$XDG_CONFIG_HOME/lenstica/lenstica.toml` when that is set).

use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use toml_edit::DocumentMut;

use crate::duration::DAY;
use crate::files;
use crate::paths;

pub const MAX_DAYS: u32 = 365;

static PATH_OVERRIDE: OnceLock<PathBuf> = OnceLock::new();

pub fn set_path_override(path: PathBuf) {
    let _ = PATH_OVERRIDE.set(path);
}

#[cfg(test)]
fn set_path_override_for_test(path: &std::path::Path) {
    // Tests in this module share the process; only this one sets it.
    let _ = PATH_OVERRIDE.set(path.to_path_buf());
}

pub fn path() -> PathBuf {
    if let Some(p) = PATH_OVERRIDE.get() {
        return p.clone();
    }
    if let Some(p) = std::env::var_os("LENSTICA_CONFIG").filter(|p| !p.is_empty()) {
        return PathBuf::from(p);
    }
    paths::config_root().join("lenstica").join("lenstica.toml")
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
    pub min_days: u32,
    pub monitor: Monitor,
    pub managers: Managers,
    pub scan: Scan,
    pub audit: Audit,
    pub install_scripts: InstallScripts,
    pub homebrew: Homebrew,
    pub software: Software,
    /// `[lenses.<id>]`: `enabled`, `interval_minutes`, and lens-specific keys.
    #[serde(alias = "checkers")]
    pub lenses: std::collections::BTreeMap<String, toml::Table>,
    /// `[[external]]`: other tools run as lenses.
    pub external: Vec<External>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct InstallScripts {
    /// Write the settings that stop dependencies' install scripts from running.
    pub block: bool,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Homebrew {
    /// Keep `HOMEBREW_NO_AUTO_UPDATE=1` in Homebrew's environment file.
    pub no_auto_update: bool,
}

/// `[software]`: which installed software the software-age lens looks at.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct Software {
    /// npm, pnpm, Yarn, Bun, Deno, uv, pip, Poetry and Cargo themselves.
    pub package_managers: bool,
    /// Homebrew formulae, dated by when their bottle was published.
    pub homebrew: bool,
    /// Homebrew casks (apps), dated by their download's Last-Modified time.
    pub casks: bool,
    /// Rust toolchains installed with rustup.
    pub rust_toolchains: bool,
    /// Node.js, when it is not from Homebrew.
    pub node: bool,
    /// Software never to flag, as "name" or "name@version".
    pub ignore: Vec<String>,
}

impl Default for Software {
    fn default() -> Self {
        Self {
            package_managers: true,
            homebrew: true,
            casks: true,
            rust_toolchains: true,
            node: true,
            ignore: Vec::new(),
        }
    }
}

/// Another tool run as a lens; see `[[external]]` in the template.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct External {
    pub id: String,
    #[serde(default)]
    pub title: Option<String>,
    /// Program and arguments; `{root}` is replaced by each search root when `per_root`.
    pub command: Vec<String>,
    /// `lenstica`, `gitleaks`, `osv-scanner` or `trufflehog`.
    #[serde(default = "default_format")]
    pub format: String,
    #[serde(default)]
    pub per_root: bool,
    #[serde(default)]
    pub interval_minutes: Option<u64>,
    #[serde(default = "default_external_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_format() -> String {
    "lenstica".to_string()
}

fn default_external_timeout() -> u64 {
    600
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct Monitor {
    pub interval_minutes: u64,
    pub auto_apply: bool,
    pub notify: bool,
    /// Lowest severity that counts as a problem: turns the icon orange, is
    /// notified, and fails `lenstica check`. `low`, `medium`, `high`, `critical`.
    pub alert_severity: String,
    /// Lowest severity worth a notification; empty means `alert_severity`.
    pub notify_severity: String,
    /// Also notify when Lenstica restores a setting by itself.
    pub notify_fixes: bool,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Managers {
    pub disabled: Vec<String>,
    pub extra_path: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct Scan {
    pub roots: Vec<String>,
    /// Folders under the roots to leave out: paths, or bare folder names.
    pub exclude: Vec<String>,
    pub worktrees: bool,
    pub max_depth: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            min_days: 7,
            monitor: Monitor::default(),
            managers: Managers::default(),
            scan: Scan::default(),
            audit: Audit::default(),
            install_scripts: InstallScripts::default(),
            homebrew: Homebrew::default(),
            software: Software::default(),
            lenses: Default::default(),
            external: Vec::new(),
        }
    }
}

impl Default for Monitor {
    fn default() -> Self {
        Self {
            interval_minutes: 15,
            auto_apply: true,
            notify: true,
            alert_severity: "medium".to_string(),
            notify_severity: String::new(),
            notify_fixes: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct Audit {
    pub enabled: bool,
    pub interval_minutes: u64,
    pub global: bool,
    pub ignore: Vec<String>,
    pub npm_registry: String,
    pub pypi_url: String,
    pub crates_index: String,
}

impl Default for Audit {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_minutes: 30,
            global: true,
            ignore: Vec::new(),
            npm_registry: "https://registry.npmjs.org".to_string(),
            pypi_url: "https://pypi.org".to_string(),
            crates_index: "https://index.crates.io".to_string(),
        }
    }
}

impl Default for Scan {
    fn default() -> Self {
        Self {
            roots: Vec::new(),
            exclude: Vec::new(),
            worktrees: true,
            max_depth: 6,
        }
    }
}

const TEMPLATE: &str = r#"# Lenstica — the single place that decides how old a package version must be
# before any package manager on this machine may install it.
#
# `lenstica apply` writes this into every detected package manager's own
# user-level config; the menu bar app and `lenstica watch` keep it that way.

# Minimum age, in days, of a newly published version before it can be installed (1-365).
# Recommended: 7. Most malicious releases are caught and pulled within a week.
min_days = 7

[monitor]
# How often the menu bar app and `lenstica watch` re-check, in minutes.
interval_minutes = 15
# Re-apply automatically when a package manager is missing the setting or has a
# weaker one, including a package manager installed after Lenstica was set up.
auto_apply = true
# Show a desktop notification when something needs attention. Turn off one
# lens's notifications with `notify = false` under [lenses.<id>].
notify = true
# Lowest severity that counts as a problem (icon, notifications, `lenstica check`):
# low, medium, high or critical. Lower findings are still listed.
alert_severity = "medium"
# Lowest severity worth a notification, if different: e.g. "high" to be told
# only about high and critical findings. Empty means alert_severity.
notify_severity = ""
# Also notify when Lenstica restores a package manager's setting by itself.
notify_fixes = true

[managers]
# Package managers to leave alone, by id: npm, pnpm, yarn, bun, uv, pip, poetry, cargo.
disabled = []
# Extra directories to search for package-manager binaries, besides PATH.
extra_path = []

[scan]
# Directories searched for project-level configs that weaken the cooldown, such
# as a pnpm-workspace.yaml with a lower minimumReleaseAge. Project files are
# reported, never edited. An empty list turns the scan off.
roots = [__ROOTS__]
# Folders under the roots to leave out of every search (project settings,
# lockfiles, secrets, worktrees). A path ("~/Developer/old-stuff") skips that
# folder and everything below it; a bare name ("fixtures") skips every folder
# with that name. To search only some repositories, list them in `roots` instead.
exclude = []
# Also search every git worktree of each repository found under the roots,
# wherever it lives (worktree tools often keep them outside the repo, or in a
# hidden directory the search would otherwise skip).
worktrees = true
# How many directory levels below each root to search.
max_depth = 6

[audit]
# Also check what is already installed: every lockfile under scan.roots
# (package-lock, pnpm, Yarn, Bun, uv, Poetry, Cargo) and, with `global`, npm -g,
# pnpm -g, uv tools, pip --user and cargo install. Flags versions published less than
# min_days ago, and versions that were that young when their lockfile changed.
enabled = true
# How often the menu bar app and `lenstica watch` re-audit, in minutes.
# Publish times are cached for good, so only new versions cost a lookup.
interval_minutes = 30
global = true
# Packages never to flag, as "name" or "name@version".
ignore = []
# Where publish times are looked up. Lockfile entries from any other registry are skipped.
npm_registry = "https://registry.npmjs.org"
pypi_url = "https://pypi.org"
crates_index = "https://index.crates.io"

[install_scripts]
# Stop dependencies' install scripts from running, the way Shai-Hulud-style
# worms execute: npm ignore-scripts, Yarn enableScripts: false. (pnpm 10+ and
# Bun already skip them unless a package is allowed by name.) Off by default
# because native builds then need their packages allowed explicitly.
block = false

[homebrew]
# Homebrew has no minimum-age setting, and `brew install` / `brew upgrade`
# fetch the newest formulae first. With this on, Lenstica keeps
# HOMEBREW_NO_AUTO_UPDATE=1 in ~/.homebrew/brew.env, so new versions arrive
# only when you run `brew update`. Off by default: `brew install` then uses
# formulae as of your last `brew update`.
no_auto_update = false

[software]
# Also check how recently the software itself was published, not only the
# packages in your projects. None of these can hold back new versions the way
# the package-manager setting does, so a version younger than min_days is
# reported after it was installed.
# npm, pnpm, Yarn, Bun, Deno, uv, pip, Poetry and Cargo themselves.
package_managers = true
# Homebrew formulae, dated by when their bottle was published on ghcr.io.
homebrew = true
# Homebrew casks (apps), dated by their download's Last-Modified time.
casks = true
# Rust toolchains installed with rustup, dated by the Rust release manifest.
rust_toolchains = true
# Node.js when it is not from Homebrew, dated by nodejs.org.
node = true
# Software never to flag, as "name" or "name@version" (audit.ignore applies too).
ignore = []

# Other tools can run as lenses. Their findings appear in the menu, the
# window and notifications like the built-in ones. `format` is `lenstica`
# (the tool prints Lenstica's JSON report), `gitleaks`, `osv-scanner` or
# `trufflehog`. With `per_root`, the command runs once per search root and
# worktree, with `{root}` replaced. Secret values in tool output are discarded.
#
# [[external]]
# id = "gitleaks"
# command = ["gitleaks", "dir", "{root}", "--report-format", "json", "--report-path", "-", "--no-banner", "--exit-code", "0"]
# format = "gitleaks"
# per_root = true
# interval_minutes = 240

# Per-lens settings: `enabled`, `interval_minutes`, and the lens's own
# keys. `lenstica lenses` lists the ids.
[lenses]
# [lenses.vulnerabilities]
# refresh_hours = 6        # how often OSV.dev is asked again about each package
# ignore_advisories = []   # e.g. ["GHSA-xxxx-xxxx-xxxx"] once you have assessed it
# [lenses.secrets]
# enabled = true
# [lenses.aikido-malware]
# refresh_hours = 6        # how often the Aikido malware lists are downloaded again
# [lenses.safe-chain]
# enabled = false          # stop recommending Aikido Safe Chain
# [lenses.agent-instructions]
# ignore = []              # files or folders whose agent instructions you have reviewed, e.g. ["~/.agents/skills/mine"]
# max_depth = 6            # how deep to look for CLAUDE.md, AGENTS.md, .claude/, .cursor/ ... in your repositories
"#;

fn default_roots() -> Vec<String> {
    [
        "Developer",
        "Projects",
        "src",
        "code",
        "dev",
        "repos",
        "workspace",
    ]
    .iter()
    .filter(|d| paths::home().join(d).is_dir())
    .map(|d| format!("~/{d}"))
    .collect()
}

fn render_template() -> String {
    let roots = default_roots()
        .iter()
        .map(|r| format!("\"{r}\""))
        .collect::<Vec<_>>()
        .join(", ");
    TEMPLATE.replace("__ROOTS__", &roots)
}

impl Config {
    /// Load the settings file, creating it from the documented template on first use.
    pub fn load() -> Result<Self> {
        let path = path();
        let src = match files::read_optional(&path)? {
            Some(src) => match add_missing_settings(&src)? {
                Some(upgraded) => {
                    files::write_atomic(&path, &upgraded)?;
                    upgraded
                }
                None => src,
            },
            None => {
                let src = render_template();
                files::write_atomic(&path, &src)?;
                src
            }
        };
        let cfg: Config = toml::from_str(&src)
            .with_context(|| format!("invalid settings in {}", path.display()))?;
        cfg.validate()
            .with_context(|| format!("invalid settings in {}", path.display()))?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if !(1..=MAX_DAYS).contains(&self.min_days) {
            bail!(
                "min_days must be between 1 and {MAX_DAYS}, got {}",
                self.min_days
            );
        }
        if crate::lenses::parse_severity(&self.monitor.alert_severity).is_none() {
            bail!(
                "monitor.alert_severity must be low, medium, high or critical, got `{}`",
                self.monitor.alert_severity
            );
        }
        if !self.monitor.notify_severity.trim().is_empty()
            && crate::lenses::parse_severity(&self.monitor.notify_severity).is_none()
        {
            bail!(
                "monitor.notify_severity must be empty, low, medium, high or critical, got `{}`",
                self.monitor.notify_severity
            );
        }
        for e in &self.external {
            if e.command.is_empty() {
                bail!("external lens `{}` has an empty command", e.id);
            }
            if !matches!(
                e.format.as_str(),
                "lenstica" | "cooldown" | "gitleaks" | "osv-scanner" | "trufflehog"
            ) {
                bail!("external lens `{}`: unknown format `{}`", e.id, e.format);
            }
        }
        if self.audit.interval_minutes == 0 {
            bail!("audit.interval_minutes must be at least 1");
        }
        if self.monitor.interval_minutes == 0 {
            bail!("monitor.interval_minutes must be at least 1");
        }
        let known = crate::managers::ids();
        for id in &self.managers.disabled {
            if !known.contains(&id.as_str()) {
                bail!(
                    "managers.disabled: unknown package manager `{id}` (known: {})",
                    known.join(", ")
                );
            }
        }
        Ok(())
    }

    pub fn target_secs(&self) -> i64 {
        i64::from(self.min_days) * DAY
    }

    pub fn interval(&self) -> Duration {
        Duration::from_secs(self.monitor.interval_minutes.saturating_mul(60))
    }

    pub fn audit_interval(&self) -> Duration {
        Duration::from_secs(self.audit.interval_minutes.saturating_mul(60))
    }

    pub fn is_enabled(&self, id: &str) -> bool {
        !self.managers.disabled.iter().any(|d| d == id)
    }

    pub fn extra_path(&self) -> Vec<PathBuf> {
        self.managers
            .extra_path
            .iter()
            .map(|p| paths::expand(p))
            .collect()
    }

    pub fn scan_roots(&self) -> Vec<PathBuf> {
        self.scan.roots.iter().map(|p| paths::expand(p)).collect()
    }

    pub fn exclude(&self) -> lenstica_lens::Exclude {
        lenstica_lens::Exclude::new(self.scan.exclude.iter().map(|p| paths::expand(p.trim())))
    }
}

/// Settings added to Lenstica after the file was written, taken from the
/// template with their comments, so every option stays documented in the
/// user's own file. Existing values are never touched. `None` if nothing is missing.
fn add_missing_settings(src: &str) -> Result<Option<String>> {
    let template: DocumentMut = render_template()
        .parse()
        .expect("the template is valid TOML");
    let mut doc: DocumentMut = src
        .parse()
        .with_context(|| format!("invalid TOML in {}", path().display()))?;
    let mut changed = false;
    for (name, item) in template.as_table().iter() {
        let (key, _) = template
            .as_table()
            .get_key_value(name)
            .expect("iterating its own keys");
        let Some(existing) = doc.as_table_mut().get_mut(name) else {
            let mut item = item.clone();
            if let Some(table) = item.as_table_mut() {
                // Append after the user's own tables rather than at the template's position.
                table.set_position(None);
            }
            doc.as_table_mut().insert_formatted(key, item);
            changed = true;
            continue;
        };
        let (Some(wanted), Some(have)) = (item.as_table(), existing.as_table_mut()) else {
            continue;
        };
        for (sub, value) in wanted.iter() {
            if !have.contains_key(sub) {
                let (sub_key, _) = wanted.get_key_value(sub).expect("iterating its own keys");
                have.insert_formatted(sub_key, value.clone());
                changed = true;
            }
        }
    }
    Ok(changed.then(|| doc.to_string()))
}

/// Edit the settings file in place (comments and layout kept), refusing any
/// edit that would leave it invalid.
pub fn update(edit: impl FnOnce(&mut DocumentMut) -> Result<()>) -> Result<()> {
    Config::load()?;
    let path = path();
    let src = files::read_optional(&path)?.unwrap_or_default();
    let mut doc: DocumentMut = src
        .parse()
        .with_context(|| format!("invalid TOML in {}", path.display()))?;
    edit(&mut doc)?;
    let text = doc.to_string();
    let cfg: Config =
        toml::from_str(&text).context("the change would make the settings invalid")?;
    cfg.validate()?;
    files::write_atomic(&path, &text)
}

/// The table at `keys`, created (as a normal `[table]`) where missing.
fn table_at<'a>(doc: &'a mut DocumentMut, keys: &[&str]) -> Result<&'a mut toml_edit::Table> {
    let mut table = doc.as_table_mut();
    for key in keys {
        if !table.contains_key(key) {
            table.insert(key, toml_edit::Item::Table(toml_edit::Table::new()));
        }
        table = table
            .get_mut(key)
            .and_then(toml_edit::Item::as_table_mut)
            .with_context(|| format!("`{key}` in the settings file is not a table"))?;
    }
    Ok(table)
}

/// Set one value: `set_value(&["monitor", "notify"], false.into())`.
pub fn set_value(keys: &[&str], value: toml_edit::Value) -> Result<()> {
    let (last, tables) = keys.split_last().context("empty settings path")?;
    update(|doc| {
        let table = table_at(doc, tables)?;
        match table.get_mut(last).and_then(toml_edit::Item::as_value_mut) {
            // Replace the value but keep its spacing and trailing comment; the key
            // (and the comment lines above it) stays untouched.
            Some(existing) => {
                let decor = existing.decor().clone();
                *existing = value;
                *existing.decor_mut() = decor;
            }
            None => {
                table.insert(last, toml_edit::Item::Value(value));
            }
        }
        Ok(())
    })
}

#[cfg_attr(not(feature = "tray"), allow(dead_code))]
/// Add a string to a list setting unless it is already there; true if added.
pub fn add_to_list(keys: &[&str], item: &str) -> Result<bool> {
    let (last, tables) = keys.split_last().context("empty settings path")?;
    let mut added = false;
    update(|doc| {
        let table = table_at(doc, tables)?;
        if !table.contains_key(last) {
            table.insert(last, toml_edit::value(toml_edit::Array::new()));
        }
        let array = table
            .get_mut(last)
            .and_then(toml_edit::Item::as_array_mut)
            .with_context(|| format!("`{}` is not a list", keys.join(".")))?;
        if !array.iter().any(|v| v.as_str() == Some(item)) {
            array.push(item);
            added = true;
        }
        Ok(())
    })?;
    Ok(added)
}

#[cfg_attr(not(feature = "tray"), allow(dead_code))]
/// Remove every copy of a string from a list setting; true if any was there.
pub fn remove_from_list(keys: &[&str], item: &str) -> Result<bool> {
    let (last, tables) = keys.split_last().context("empty settings path")?;
    let mut removed = false;
    update(|doc| {
        let table = table_at(doc, tables)?;
        if let Some(array) = table.get_mut(last).and_then(toml_edit::Item::as_array_mut) {
            let before = array.len();
            array.retain(|v| v.as_str() != Some(item));
            removed = array.len() != before;
        }
        Ok(())
    })?;
    Ok(removed)
}

/// Change `min_days` in place, keeping the file's comments and layout.
pub fn set_min_days(days: u32) -> Result<()> {
    if !(1..=MAX_DAYS).contains(&days) {
        bail!("days must be between 1 and {MAX_DAYS}");
    }
    set_value(&["min_days"], i64::from(days).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_parses_to_the_defaults() {
        let cfg: Config =
            toml::from_str(&TEMPLATE.replace("__ROOTS__", "\"~/Developer\"")).unwrap();
        assert_eq!(cfg.min_days, 7);
        assert_eq!(cfg.monitor.interval_minutes, 15);
        assert!(cfg.monitor.auto_apply && cfg.monitor.notify);
        assert_eq!(cfg.scan.roots, vec!["~/Developer"]);
        cfg.validate().unwrap();
    }

    #[test]
    fn adds_missing_settings_without_touching_existing_ones() {
        let old = "# mine\nmin_days = 3\n\n[scan]\nroots = [\"~/code\"]\nmax_depth = 2\n";
        let new = add_missing_settings(old)
            .unwrap()
            .expect("[audit] and scan.worktrees are missing");
        assert!(new.starts_with("# mine\nmin_days = 3\n"), "{new}");
        let cfg: Config = toml::from_str(&new).unwrap();
        assert_eq!((cfg.min_days, cfg.scan.max_depth), (3, 2));
        assert_eq!(cfg.scan.roots, vec!["~/code"]);
        assert!(
            new.contains("# Also search every git worktree") && new.contains("worktrees = true")
        );
        assert!(new.contains("[audit]") && new.contains("[monitor]"));
        assert_eq!(
            add_missing_settings(&new).unwrap(),
            None,
            "second pass adds nothing"
        );
    }

    #[test]
    fn edits_keep_comments_and_refuse_invalid_values() {
        let dir = std::env::temp_dir().join(format!("lenstica-cfg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let file = dir.join("lenstica.toml");
        set_path_override_for_test(&file);
        Config::load().unwrap();
        set_value(&["monitor", "alert_severity"], "high".into()).unwrap();
        assert!(
            add_to_list(
                &["lenses", "vulnerabilities", "ignore_advisories"],
                "GHSA-x"
            )
            .unwrap()
        );
        assert!(
            !add_to_list(
                &["lenses", "vulnerabilities", "ignore_advisories"],
                "GHSA-x"
            )
            .unwrap()
        );
        assert!(add_to_list(&["managers", "disabled"], "poetry").unwrap());
        assert!(remove_from_list(&["managers", "disabled"], "poetry").unwrap());
        assert!(!remove_from_list(&["managers", "disabled"], "poetry").unwrap());
        assert!(
            add_to_list(&["managers", "disabled"], "nmp").is_err(),
            "an unknown package manager must be refused"
        );
        assert!(
            set_value(&["min_days"], 0.into()).is_err(),
            "min_days 0 must be refused"
        );
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(text.contains("# Lowest severity that counts as a problem"));
        let cfg = Config::load().unwrap();
        assert_eq!(
            (cfg.monitor.alert_severity.as_str(), cfg.min_days),
            ("high", 7)
        );
        assert_eq!(
            cfg.lenses["vulnerabilities"]["ignore_advisories"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rejects_bad_values() {
        let cfg: Config = toml::from_str("min_days = 0").unwrap();
        assert!(cfg.validate().is_err());
        let cfg: Config = toml::from_str("[managers]\ndisabled = [\"nmp\"]").unwrap();
        assert!(cfg.validate().is_err());
    }
}
