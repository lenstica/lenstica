//! Whether package managers run dependencies' install scripts, which is how
//! Shai-Hulud-style worms execute. Recommended, applied only with
//! `install_scripts.block = true` (or a click on the finding).

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use lenstica_lens::{Category, Context, Finding, Lens, Location, Report, Severity, topic};

use crate::config::Config;
use crate::exec;
use crate::files;
use crate::paths;
use crate::version::Version;

pub struct InstallScripts;

fn yarnrc() -> PathBuf {
    paths::home().join(".yarnrc.yml")
}

fn npmrc() -> PathBuf {
    std::env::var_os("NPM_CONFIG_USERCONFIG")
        .map_or_else(|| paths::home().join(".npmrc"), PathBuf::from)
}

/// A manager that runs dependency install scripts, and how to stop it.
struct Open {
    id: &'static str,
    name: &'static str,
    setting: &'static str,
    path: PathBuf,
    /// Why blocking failed, when `install_scripts.block` tried.
    error: Option<String>,
}

fn npm_runs_scripts(npm: &Path, search: &OsStr) -> Result<bool> {
    let out = exec::run(npm, &["config", "get", "ignore-scripts"], search)?;
    if !out.success {
        bail!("npm config get failed: {}", out.error_text());
    }
    Ok(out.last_line() != Some("true"))
}

fn yarn_runs_scripts() -> Result<bool> {
    let src = files::read_optional(&yarnrc())?.unwrap_or_default();
    Ok(files::yaml_get_top(&src, "enableScripts").as_deref() != Some("false"))
}

fn block(id: &str, search: &OsStr) -> Result<String> {
    match id {
        "npm" => {
            let npm = exec::find("npm", search).context("npm is not installed")?;
            let out = exec::run(
                &npm,
                &["config", "set", "ignore-scripts=true", "--location=user"],
                search,
            )?;
            if !out.success {
                bail!("npm config set failed: {}", out.error_text());
            }
            Ok("npm: set ignore-scripts=true".to_string())
        }
        "yarn" => {
            let path = yarnrc();
            let src = files::read_optional(&path)?.unwrap_or_default();
            files::write_atomic(&path, &files::yaml_set_top(&src, "enableScripts", "false"))?;
            Ok("Yarn: set enableScripts: false".to_string())
        }
        other => bail!("Lenstica does not manage install scripts for {other}"),
    }
}

impl Lens for InstallScripts {
    fn id(&self) -> &str {
        "install-scripts"
    }
    fn title(&self) -> &str {
        "Install scripts"
    }
    fn description(&self) -> &str {
        "Whether installing a dependency can run its code (preinstall/postinstall scripts), the way supply-chain worms steal developer credentials."
    }
    fn categories(&self) -> &[Category] {
        &[Category::Packages]
    }

    fn run(&self, cx: &Context) -> Result<Report> {
        let cfg = Config::load()?;
        let search = cx.search_path;
        let mut open = Vec::new();
        let mut passing = Vec::new();
        if let Some(npm) = exec::find("npm", search) {
            if npm_runs_scripts(&npm, search)? {
                open.push(Open {
                    id: "npm",
                    name: "npm",
                    setting: "ignore-scripts=true",
                    path: npmrc(),
                    error: None,
                });
            } else {
                passing.push("npm: ignore-scripts=true".to_string());
            }
        }
        if let Some(yarn) = exec::find("yarn", search) {
            let modern = exec::version_of(&yarn, search).is_none_or(|v| v >= Version::new(2, 0, 0));
            if modern && yarn_runs_scripts()? {
                open.push(Open {
                    id: "yarn",
                    name: "Yarn",
                    setting: "enableScripts: false",
                    path: yarnrc(),
                    error: None,
                });
            } else if modern {
                passing.push("Yarn: enableScripts: false".to_string());
            }
        }
        let mut old_pnpm = None;
        if let Some(pnpm) = exec::find("pnpm", search) {
            match exec::version_of(&pnpm, search) {
                Some(v) if v >= Version::new(10, 0, 0) => passing.push(
                    "pnpm 10+: dependency scripts run only for packages allowed by name"
                        .to_string(),
                ),
                Some(v) => old_pnpm = Some(v),
                None => {}
            }
        }
        if exec::find("bun", search).is_some() {
            passing.push("Bun: dependency scripts run only for trustedDependencies".to_string());
        }

        let mut actions = Vec::new();
        if cfg.install_scripts.block {
            open.retain_mut(|o| match block(o.id, search) {
                Ok(done) => {
                    actions.push(format!("Blocked install scripts. {done}."));
                    false
                }
                Err(e) => {
                    o.error = Some(format!("{e:#}"));
                    true
                }
            });
        }

        let mut findings: Vec<Finding> = open
            .iter()
            .map(|o| {
                Finding::new(format!("open|{}", o.id), Severity::Low, Category::Packages, format!("{} runs dependencies' install scripts", o.name)).topic(topic::INSTALL_SCRIPTS)
                    .detail(format!(
                        "Installing a package lets it run code as you, before you ever import it. That is how the \
                         Shai-Hulud worm stole npm, GitHub and cloud credentials. Setting {} in {} stops it.{}",
                        o.setting,
                        paths::tilde(&o.path),
                        o.error.as_ref().map_or_else(String::new, |e| format!(" Lenstica could not set it: {e}"))
                    ))
                    .remedy(format!(
                        "Click to set {} now, or set install_scripts.block = true. Packages that need a build step \
                         then need `npm rebuild <pkg>` or an explicit allow.",
                        o.setting
                    ))
                    .at(Location::file(paths::tilde(&o.path), o.path.clone()))
                    .fixable()
            })
            .collect();
        if let Some(v) = old_pnpm {
            findings.push(
                Finding::new("old-pnpm", Severity::Low, Category::Packages, format!("pnpm {v} runs dependencies' install scripts")).topic(topic::INSTALL_SCRIPTS)
                    .detail("pnpm before 10 runs every dependency's install scripts; pnpm 10 runs them only for packages allowed by name.")
                    .remedy("Upgrade pnpm to 10 or later."),
            );
        }
        if exec::find("uv", search).is_some() || exec::find("pip3", search).is_some() {
            findings.push(
                Finding::new("sdist-builds", Severity::Info, Category::Packages, "pip and uv run build code for source-only packages").topic(topic::INSTALL_SCRIPTS)
                    .detail("Installing a package that ships only a source distribution runs its build backend (setup.py) as you.")
                    .remedy("For projects that should never build from source: uv `no-build = true`, pip `--only-binary :all:`."),
            );
        }
        let summary = match open.as_slice() {
            [] => "No package manager runs dependency install scripts".to_string(),
            [one] => format!("{} runs dependency install scripts", one.name),
            many => format!(
                "{} run dependency install scripts",
                many.iter()
                    .map(|o| o.name)
                    .collect::<Vec<_>>()
                    .join(" and ")
            ),
        };
        Ok(Report {
            findings,
            summary,
            passing,
            actions,
            watch: vec![npmrc(), yarnrc()],
        })
    }

    fn fix(&self, cx: &Context, finding: &Finding) -> Result<String> {
        match finding.key.strip_prefix("open|") {
            Some(id) => block(id, cx.search_path),
            None => bail!("nothing to apply for {}", finding.key),
        }
    }
}
