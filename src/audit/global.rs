//! Globally installed packages: `npm -g`, `pnpm -g`, uv tools, `pip --user`.

use serde_json::Value;

use super::Source;
use super::lockfiles::{Ecosystem, Locked, Pkg};
use crate::exec;
use crate::managers::Ctx;

fn locked(eco: Ecosystem, name: &str, version: &str) -> Option<Locked> {
    let version = version.trim().trim_start_matches('v');
    (!name.is_empty() && version.starts_with(|c: char| c.is_ascii_digit())).then(|| Locked {
        pkg: Pkg {
            eco,
            name: name.to_string(),
            version: version.to_string(),
        },
        published: None,
    })
}

fn deps(value: &Value) -> Vec<Locked> {
    value
        .get("dependencies")
        .and_then(Value::as_object)
        .map(|deps| {
            deps.iter()
                .filter_map(|(name, d)| locked(Ecosystem::Npm, name, d.get("version")?.as_str()?))
                .collect()
        })
        .unwrap_or_default()
}

fn run_json(bin: &str, args: &[&str], ctx: &Ctx, errors: &mut Vec<String>) -> Option<Value> {
    let path = exec::find(bin, &ctx.search)?;
    match exec::run(&path, args, &ctx.search) {
        // `npm ls` exits 1 for extraneous or invalid trees but still prints the full JSON.
        Ok(out) => match serde_json::from_str(&out.stdout) {
            Ok(v) => Some(v),
            Err(_) => {
                errors.push(format!("`{bin} {}`: {}", args.join(" "), out.error_text()));
                None
            }
        },
        Err(e) => {
            errors.push(format!("{e:#}"));
            None
        }
    }
}

pub fn collect(ctx: &Ctx, errors: &mut Vec<String>) -> Vec<Source> {
    let mut sources = Vec::new();
    let mut add = |label: &str, entries: Vec<Locked>| {
        if !entries.is_empty() {
            sources.push(Source {
                label: label.to_string(),
                path: None,
                locked_at: None,
                entries,
            });
        }
    };

    if let Some(v) = run_json("npm", &["ls", "-g", "--depth=0", "--json"], ctx, errors) {
        add("npm -g", deps(&v));
    }
    if let Some(v) = run_json("pnpm", &["ls", "-g", "--depth=0", "--json"], ctx, errors) {
        let entries = match &v {
            Value::Array(items) => items.iter().flat_map(deps).collect(),
            other => deps(other),
        };
        add("pnpm -g", entries);
    }
    if let Some(uv) = exec::find("uv", &ctx.search) {
        match exec::run(&uv, &["tool", "list"], &ctx.search) {
            // "ruff v0.6.0" per tool, then "- ruff" per executable.
            Ok(out) if out.success => add(
                "uv tools",
                out.stdout
                    .lines()
                    .filter(|l| !l.starts_with('-'))
                    .filter_map(|l| {
                        let mut parts = l.split_whitespace();
                        locked(Ecosystem::Pypi, parts.next()?, parts.next()?)
                    })
                    .collect(),
            ),
            Ok(out) => errors.push(format!("`uv tool list`: {}", out.error_text())),
            Err(e) => errors.push(format!("{e:#}")),
        }
    }
    let pip = if exec::find("pip3", &ctx.search).is_some() {
        "pip3"
    } else {
        "pip"
    };
    if let Some(Value::Array(items)) =
        run_json(pip, &["list", "--user", "--format=json"], ctx, errors)
    {
        add(
            "pip --user",
            items
                .iter()
                .filter_map(|i| {
                    locked(
                        Ecosystem::Pypi,
                        i.get("name")?.as_str()?,
                        i.get("version")?.as_str()?,
                    )
                })
                .collect(),
        );
    }
    if let Some(cargo) = exec::find("cargo", &ctx.search) {
        match exec::run(&cargo, &["install", "--list"], &ctx.search) {
            // "ripgrep v14.1.0:" per crate, then indented binary names. Path and git
            // installs carry a third part, "(…)", and have no crates.io publish time.
            Ok(out) if out.success => add(
                "cargo install",
                out.stdout
                    .lines()
                    .filter(|l| !l.starts_with(char::is_whitespace))
                    .filter_map(|l| {
                        let mut parts = l.trim_end_matches(':').split_whitespace();
                        let (name, version) = (parts.next()?, parts.next()?);
                        if parts.next().is_some() {
                            return None;
                        }
                        locked(Ecosystem::Crates, name, version)
                    })
                    .collect(),
            ),
            Ok(out) => errors.push(format!("`cargo install --list`: {}", out.error_text())),
            Err(e) => errors.push(format!("{e:#}")),
        }
    }
    sources
}
