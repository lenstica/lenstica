//! Find project-level configs that override the user-level cooldown with a
//! weaker one. A project setting beats the user setting for every package
//! manager here, so one `minimumReleaseAge: 0` in a repo silently opts that
//! repo out. These files are reported, never edited.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::Serialize;
use walkdir::WalkDir;

use crate::config::Config;
use crate::duration::{DAY, MINUTE, humanize, parse_age};
use crate::exec;
use crate::files;
use crate::paths::tilde;
use lenstica_lens::Exclude;

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub path: String,
    #[serde(skip)]
    #[cfg_attr(not(feature = "tray"), allow(dead_code))]
    pub full_path: PathBuf,
    pub manager: &'static str,
    pub setting: &'static str,
    pub value: String,
    pub age: String,
}

enum Format {
    Ini(Option<&'static str>),
    Yaml,
    Toml(&'static [&'static str]),
}

struct Rule {
    /// File name, or a path suffix such as `.cargo/config.toml`.
    file: &'static str,
    manager: &'static str,
    setting: &'static str,
    format: Format,
    bare_unit: i64,
}

const CARGO_GLOBAL: &[&str] = &["registry", "global-min-publish-age"];
const CARGO_CRATES_IO: &[&str] = &["registries", "crates-io", "min-publish-age"];

const RULES: &[Rule] = &[
    Rule {
        file: ".cargo/config.toml",
        manager: "cargo",
        setting: "registry.global-min-publish-age",
        format: Format::Toml(CARGO_GLOBAL),
        bare_unit: DAY,
    },
    Rule {
        file: ".cargo/config.toml",
        manager: "cargo",
        setting: "registries.crates-io.min-publish-age",
        format: Format::Toml(CARGO_CRATES_IO),
        bare_unit: DAY,
    },
    Rule {
        file: ".cargo/config",
        manager: "cargo",
        setting: "registry.global-min-publish-age",
        format: Format::Toml(CARGO_GLOBAL),
        bare_unit: DAY,
    },
    Rule {
        file: ".cargo/config",
        manager: "cargo",
        setting: "registries.crates-io.min-publish-age",
        format: Format::Toml(CARGO_CRATES_IO),
        bare_unit: DAY,
    },
    Rule {
        file: ".npmrc",
        manager: "npm",
        setting: "min-release-age",
        format: Format::Ini(None),
        bare_unit: DAY,
    },
    Rule {
        file: ".npmrc",
        manager: "pnpm",
        setting: "minimum-release-age",
        format: Format::Ini(None),
        bare_unit: MINUTE,
    },
    Rule {
        file: "pnpm-workspace.yaml",
        manager: "pnpm",
        setting: "minimumReleaseAge",
        format: Format::Yaml,
        bare_unit: MINUTE,
    },
    Rule {
        file: ".yarnrc.yml",
        manager: "yarn",
        setting: "npmMinimalAgeGate",
        format: Format::Yaml,
        bare_unit: MINUTE,
    },
    Rule {
        file: "bunfig.toml",
        manager: "bun",
        setting: "minimumReleaseAge",
        format: Format::Toml(&["install", "minimumReleaseAge"]),
        bare_unit: 1,
    },
    Rule {
        file: "uv.toml",
        manager: "uv",
        setting: "exclude-newer",
        format: Format::Toml(&["exclude-newer"]),
        bare_unit: DAY,
    },
    Rule {
        file: "pyproject.toml",
        manager: "uv",
        setting: "tool.uv.exclude-newer",
        format: Format::Toml(&["tool", "uv", "exclude-newer"]),
        bare_unit: DAY,
    },
    Rule {
        file: "poetry.toml",
        manager: "poetry",
        setting: "solver.min-release-age",
        format: Format::Toml(&["solver", "min-release-age"]),
        bare_unit: DAY,
    },
    Rule {
        file: "pip.conf",
        manager: "pip",
        setting: "uploaded-prior-to",
        format: Format::Ini(Some("install")),
        bare_unit: DAY,
    },
    Rule {
        file: "pip.ini",
        manager: "pip",
        setting: "uploaded-prior-to",
        format: Format::Ini(Some("install")),
        bare_unit: DAY,
    },
];

/// Directories never worth descending into: dependency trees, build output,
/// caches, and every hidden directory (`.git`, `.venv`, `.next`, ...).
const SKIP_DIRS: &[&str] = &[
    "node_modules",
    "target",
    "dist",
    "build",
    "out",
    "coverage",
    "vendor",
    "venv",
    "env",
    "__pycache__",
    "site-packages",
    "bower_components",
    "Pods",
    "DerivedData",
    "Library",
];

fn skip_dir(name: &OsStr) -> bool {
    let name = name.to_string_lossy();
    // `.cargo` holds a repository's Cargo config; every other hidden directory is skipped.
    (name.starts_with('.') && name != ".cargo") || SKIP_DIRS.contains(&name.as_ref())
}

/// Never descend below a `.cargo` directory: a `CARGO_HOME` keeps the whole
/// registry cache there, and only its config files matter.
fn inside_cargo_dir(path: &Path) -> bool {
    path.parent()
        .and_then(Path::file_name)
        .is_some_and(|p| p == ".cargo")
}

fn rule_file_name(rule: &Rule) -> &'static str {
    rule.file.rsplit('/').next().unwrap_or(rule.file)
}

fn extract(rule: &Rule, src: &str) -> Option<String> {
    match &rule.format {
        Format::Ini(section) => files::ini_get(src, *section, rule.setting),
        Format::Yaml => files::yaml_get_top(src, rule.setting),
        // A file that does not parse is the package manager's error to report, not ours.
        Format::Toml(keys) => files::toml_get(src, keys).ok().flatten(),
    }
}

pub fn scan(
    roots: &[PathBuf],
    exclude: &Exclude,
    max_depth: usize,
    target_secs: i64,
    now: DateTime<Utc>,
) -> Vec<Finding> {
    let mut names: Vec<&str> = RULES.iter().map(rule_file_name).collect();
    names.dedup();
    let mut findings = Vec::new();
    for path in find_files(roots, exclude, max_depth, &names) {
        let matching: Vec<&Rule> = RULES.iter().filter(|r| path.ends_with(r.file)).collect();
        if matching.is_empty() {
            continue;
        }
        let Ok(Some(src)) = files::read_optional(&path) else {
            continue;
        };
        for rule in matching {
            if let Some(finding) = check(rule, &path, &src, target_secs, now) {
                findings.push(finding);
            }
        }
    }
    findings.sort_by(|a, b| a.path.cmp(&b.path));
    findings
}

/// Every file under `roots` whose name is in `names`, skipping dependency,
/// build and hidden directories, and whatever `scan.exclude` names.
pub fn find_files(
    roots: &[PathBuf],
    exclude: &Exclude,
    max_depth: usize,
    names: &[&str],
) -> Vec<PathBuf> {
    // A set: a worktree nested inside another root must not be counted twice.
    let mut found = BTreeSet::new();
    for root in roots.iter().filter(|r| r.is_dir() && !exclude.skips(r)) {
        let walker = WalkDir::new(root)
            .max_depth(max_depth)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                e.depth() == 0
                    || !(e.file_type().is_dir()
                        && (skip_dir(e.file_name())
                            || inside_cargo_dir(e.path())
                            || exclude.skips(e.path())))
            });
        found.extend(
            walker
                .flatten()
                .filter(|e| e.file_type().is_file())
                .filter(|e| names.iter().any(|n| e.file_name() == *n))
                .map(walkdir::DirEntry::into_path),
        );
    }
    found.into_iter().collect()
}

/// The directories to search: the configured roots, plus (with
/// `scan.worktrees`) every git worktree of every repository under them.
/// Worktrees often live elsewhere (`~/orca/workspaces/...`) or in hidden
/// directories the walk skips (`.claude/worktrees/...`).
pub struct Roots {
    pub paths: Vec<PathBuf>,
    pub label: String,
}

pub fn roots(cfg: &Config, base: Vec<PathBuf>, search: &OsStr) -> Roots {
    let exclude = cfg.exclude();
    let mut paths: Vec<PathBuf> = base.into_iter().filter(|p| !exclude.skips(p)).collect();
    let configured = paths
        .iter()
        .map(|p| tilde(p))
        .collect::<Vec<_>>()
        .join(", ");
    let mut worktrees = 0;
    if cfg.scan.worktrees {
        for repo in repositories(&paths, cfg.scan.max_depth, search) {
            let Some(main) = &repo.worktree_of else {
                continue;
            };
            // Leaving a repository out leaves out its worktrees too.
            if exclude.skips(main) || exclude.skips(&repo.path) || covered(&repo.path, &paths) {
                continue;
            }
            paths.push(repo.path);
            worktrees += 1;
        }
    }
    let excluded = match exclude.paths.len() + exclude.names.len() {
        0 => String::new(),
        1 => ", 1 folder excluded".to_string(),
        n => format!(", {n} folders excluded"),
    };
    let label = match worktrees {
        0 => format!("{configured}{excluded}"),
        1 => format!("{configured} + 1 git worktree{excluded}"),
        n => format!("{configured} + {n} git worktrees{excluded}"),
    };
    Roots { paths, label }
}

/// A repository found under the roots, or a git worktree of one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repo {
    pub path: PathBuf,
    /// For a linked worktree: the repository it belongs to.
    pub worktree_of: Option<PathBuf>,
}

/// Every repository under `roots` and every worktree of each, ignoring
/// `scan.exclude` (so settings can list what is left out, too).
pub fn repositories(roots: &[PathBuf], max_depth: usize, search: &OsStr) -> Vec<Repo> {
    let repos = find_repos(roots, max_depth);
    let mut out: Vec<Repo> = repos
        .iter()
        .map(|p| Repo {
            path: p.clone(),
            worktree_of: None,
        })
        .collect();
    let mut seen: BTreeSet<PathBuf> = repos.iter().cloned().collect();
    for (main, wt) in worktrees_of(&repos, search) {
        if seen.insert(wt.clone()) {
            out.push(Repo {
                path: wt,
                worktree_of: Some(main),
            });
        } else if let Some(r) = out.iter_mut().find(|r| r.path == wt) {
            // A linked worktree that is also under a root: still a worktree of `main`.
            r.worktree_of = Some(main);
        }
    }
    out
}

/// Already reached by walking one of `roots`: below it, and not inside a
/// directory the walk skips.
fn covered(path: &Path, roots: &[PathBuf]) -> bool {
    roots.iter().any(|root| {
        path.strip_prefix(root)
            .is_ok_and(|rest| rest.components().all(|c| !skip_dir(c.as_os_str())))
    })
}

/// Repository roots under `roots`, not descending into a repository once found.
fn find_repos(roots: &[PathBuf], max_depth: usize) -> Vec<PathBuf> {
    let mut repos = Vec::new();
    for root in roots.iter().filter(|r| r.is_dir()) {
        let mut walker = WalkDir::new(root)
            .max_depth(max_depth)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                e.file_type().is_dir() && (e.depth() == 0 || !skip_dir(e.file_name()))
            });
        while let Some(entry) = walker.next() {
            let Ok(entry) = entry else { continue };
            // `.git` is a directory in a main checkout and a file in a linked worktree.
            if entry.path().join(".git").exists() {
                repos.push(entry.into_path());
                walker.skip_current_dir();
            }
        }
    }
    repos
}

/// (main checkout, worktree) for every linked worktree of `repos`.
fn worktrees_of(repos: &[PathBuf], search: &OsStr) -> Vec<(PathBuf, PathBuf)> {
    let Some(git) = exec::find("git", search) else {
        return Vec::new();
    };
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    let mut found = Vec::new();
    for repo in repos {
        // A worktree of a repository already listed lists the same set again.
        if seen.contains(repo) {
            continue;
        }
        let dir = repo.to_string_lossy().into_owned();
        let Ok(out) = exec::run(
            &git,
            &["-C", &dir, "worktree", "list", "--porcelain"],
            search,
        ) else {
            continue;
        };
        if !out.success {
            continue;
        }
        // The first entry is always the main checkout.
        let mut main: Option<PathBuf> = None;
        for line in out.stdout.lines() {
            let Some(path) = line.strip_prefix("worktree ") else {
                continue;
            };
            let path = PathBuf::from(path);
            let main = main.get_or_insert_with(|| path.clone()).clone();
            if seen.insert(path.clone()) && path != main && path.is_dir() {
                found.push((main, path));
            }
        }
    }
    found
}

fn check(
    rule: &Rule,
    path: &Path,
    src: &str,
    target_secs: i64,
    now: DateTime<Utc>,
) -> Option<Finding> {
    let value = extract(rule, src)?;
    let secs = parse_age(&value, rule.bare_unit, now)?;
    (secs < target_secs).then(|| Finding {
        path: tilde(path),
        full_path: path.to_path_buf(),
        manager: rule.manager,
        setting: rule.setting,
        age: if secs == 0 {
            "disabled".to_string()
        } else {
            humanize(secs)
        },
        value,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn reports_only_weaker_overrides() {
        let root = std::env::temp_dir().join(format!("lenstica-scan-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let write = |rel: &str, body: &str| {
            let p = root.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, body).unwrap();
        };
        write(
            "weak/pnpm-workspace.yaml",
            "packages:\n  - a\nminimumReleaseAge: 1440\n",
        );
        write("strong/pnpm-workspace.yaml", "minimumReleaseAge: 20160\n");
        write("off/.npmrc", "min-release-age=0\n");
        write(
            "py/pyproject.toml",
            "[tool.uv]\nexclude-newer = \"2 days\"\n",
        );
        write("pinned/uv.toml", "exclude-newer = \"2020-01-01\"\n");
        write(
            "rust/.cargo/config.toml",
            "[registry]\nglobal-min-publish-age = \"1 day\"\n",
        );
        write(
            "rust/config.toml",
            "[registry]\nglobal-min-publish-age = \"1 day\"\n",
        );
        write("app/node_modules/x/.yarnrc.yml", "npmMinimalAgeGate: 0\n");
        write(".hidden/.yarnrc.yml", "npmMinimalAgeGate: 0\n");

        let found = scan(
            std::slice::from_ref(&root),
            &Exclude::default(),
            6,
            7 * DAY,
            Utc::now(),
        );
        let got: Vec<(String, &str)> = found
            .iter()
            .map(|f| {
                (
                    f.full_path
                        .strip_prefix(&root)
                        .unwrap()
                        .display()
                        .to_string(),
                    f.age.as_str(),
                )
            })
            .collect();
        assert_eq!(
            got,
            vec![
                ("off/.npmrc".to_string(), "disabled"),
                ("py/pyproject.toml".to_string(), "2 days"),
                ("rust/.cargo/config.toml".to_string(), "1 day"),
                ("weak/pnpm-workspace.yaml".to_string(), "1 day"),
            ]
        );
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn finds_worktrees_outside_and_hidden_inside_the_roots() {
        let base = std::env::temp_dir().join(format!("lenstica-wt-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let repo = base.join("code").join("app");
        fs::create_dir_all(&repo).unwrap();
        let git = |dir: &Path, args: &[&str]| {
            let ok = std::process::Command::new("git")
                .arg("-C")
                .arg(dir)
                .args(["-c", "user.name=t", "-c", "user.email=t@example.com"])
                .args(args)
                .output()
                .expect("git is installed")
                .status
                .success();
            assert!(ok, "git {args:?}");
        };
        git(&repo, &["init", "-q"]);
        git(&repo, &["commit", "-q", "--allow-empty", "-m", "init"]);
        let outside = base.join("elsewhere").join("feature");
        git(
            &repo,
            &[
                "worktree",
                "add",
                "-q",
                "--detach",
                outside.to_str().unwrap(),
            ],
        );
        git(
            &repo,
            &[
                "worktree",
                "add",
                "-q",
                "--detach",
                ".claude/worktrees/review",
            ],
        );
        fs::write(
            outside.join("pnpm-workspace.yaml"),
            "minimumReleaseAge: 60\n",
        )
        .unwrap();
        fs::write(
            repo.join(".claude/worktrees/review/.npmrc"),
            "min-release-age=1\n",
        )
        .unwrap();

        // Canonical paths: git reports /private/var/... for macOS temp directories.
        let code = base.join("code").canonicalize().unwrap();
        let search = exec::search_path(&[]);
        let mut cfg = Config::default();
        let found = roots(&cfg, vec![code.clone()], &search);
        assert_eq!(found.paths.len(), 3, "{:?}", found.paths);
        assert!(
            found.label.ends_with("+ 2 git worktrees"),
            "{}",
            found.label
        );
        let hits = scan(&found.paths, &Exclude::default(), 6, 7 * DAY, Utc::now());
        let mut names: Vec<&str> = hits.iter().map(|f| f.setting).collect();
        names.sort_unstable();
        // One weak setting in each worktree: outside the root, and under a hidden directory.
        assert_eq!(names, vec!["min-release-age", "minimumReleaseAge"]);
        assert_eq!(hits.len(), 2, "{hits:?}");

        // Leaving out the main checkout leaves out its worktrees, wherever they are.
        cfg.scan.exclude = vec![code.join("app").to_string_lossy().into_owned()];
        let left = roots(&cfg, vec![code.clone()], &search);
        assert_eq!(left.paths, vec![code.clone()], "{:?}", left.paths);
        assert!(scan(&left.paths, &cfg.exclude(), 6, 7 * DAY, Utc::now()).is_empty());
        let listed = repositories(std::slice::from_ref(&code), 6, &search);
        assert_eq!(listed.len(), 3, "{listed:?}");
        assert_eq!(listed.iter().filter(|r| r.worktree_of.is_some()).count(), 2);
        cfg.scan.exclude.clear();

        cfg.scan.worktrees = false;
        let plain = roots(&cfg, vec![code], &search);
        assert_eq!(plain.paths.len(), 1);
        assert!(scan(&plain.paths, &Exclude::default(), 6, 7 * DAY, Utc::now()).is_empty());
        fs::remove_dir_all(&base).unwrap();
    }
}
