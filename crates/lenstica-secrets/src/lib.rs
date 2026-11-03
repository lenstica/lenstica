//! Credentials on disk that malware running as you could read and use.
//!
//! File permissions do not help against that: a malicious install script runs
//! as you and reads whatever you can. What helps is having fewer, shorter-lived
//! secrets in fewer places, so every finding says how to shrink the exposure.
//!
//! **No secret value ever leaves this module.** Findings name the file, the
//! setting or variable names and the kind of credential, never the contents.
//! Values are only compared in memory against known token shapes.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use chrono::{DateTime, NaiveDateTime, Utc};
use lenstica_lens::{
    Context, Exclude, Finding, Lens, Location, Report, Result, Severity, home_dir, tilde,
};
use regex::Regex;
use serde_json::Value;
use walkdir::WalkDir;

pub struct Secrets;

impl Lens for Secrets {
    fn id(&self) -> &str {
        "secrets"
    }
    fn title(&self) -> &str {
        "Exposed secrets"
    }
    fn description(&self) -> &str {
        "Credentials stored in files a malicious package running as you could read: cloud keys and sign-in caches, \
         registry and GitHub tokens, SSH keys without a passphrase, secrets in shell startup files and history, and \
         .env and settings files in your projects and every worktree."
    }
    fn default_interval(&self) -> Duration {
        Duration::from_secs(60 * 60)
    }

    fn run(&self, cx: &Context) -> Result<Report> {
        let home = home_dir();
        let now = DateTime::<Utc>::from(cx.now);
        let mut out = Out::default();
        aws(&home, &mut out);
        aws_sign_in(&home, now, &mut out);
        npmrc(&home, &mut out);
        cargo_credentials(&env_path("CARGO_HOME", home.join(".cargo")), &mut out);
        simple_token_files(&home, &mut out);
        docker(&home, &mut out);
        kube(&home, &mut out);
        ssh(&home, &mut out);
        gcloud(&home, &mut out);
        shell_startup(&home, &mut out);
        shell_history(&home, &mut out);
        let depth = cx
            .settings
            .get("max_depth")
            .and_then(Value::as_u64)
            .unwrap_or(6) as usize;
        project_files(cx.roots, cx.exclude, depth, &mut out);

        let count = |s: Severity| out.findings.iter().filter(|f| f.severity == s).count();
        let problems = out
            .findings
            .iter()
            .filter(|f| f.severity.is_problem())
            .count();
        let summary = if problems == 0 {
            "No exposed long-lived secrets found".to_string()
        } else {
            let breakdown: Vec<String> = [
                Severity::Critical,
                Severity::High,
                Severity::Medium,
                Severity::Low,
            ]
            .into_iter()
            .map(|s| (s, count(s)))
            .filter(|(_, n)| *n > 0)
            .map(|(s, n)| format!("{n} {}", s.label()))
            .collect();
            format!(
                "{problems} {} ({})",
                if problems == 1 {
                    "exposure"
                } else {
                    "exposures"
                },
                breakdown.join(", ")
            )
        };
        Ok(Report {
            findings: out.findings,
            summary,
            passing: out.passing,
            ..Default::default()
        })
    }
}

#[derive(Default)]
struct Out {
    findings: Vec<Finding>,
    passing: Vec<String>,
}

fn read(path: &Path) -> Option<String> {
    std::fs::read(path)
        .ok()
        .map(|b| String::from_utf8_lossy(&b).into_owned())
}

fn at(path: &Path) -> Location {
    Location::file(tilde(path), path)
}

fn env_path(var: &str, default: PathBuf) -> PathBuf {
    std::env::var_os(var)
        .filter(|v| !v.is_empty())
        .map_or(default, PathBuf::from)
}

// ---- value classification (in memory only) -------------------------------------

fn token_patterns() -> &'static [(&'static str, Regex)] {
    static PATTERNS: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        [
            (
                "GitHub token",
                r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}",
            ),
            ("GitHub token", r"\bgithub_pat_[A-Za-z0-9_]{60,}"),
            ("npm token", r"\bnpm_[A-Za-z0-9]{36}\b"),
            ("AWS access key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
            ("Anthropic API key", r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
            // Project, service-account and admin keys, or legacy alphanumeric
            // ones; `sk-ant-` (Anthropic) fits neither.
            (
                "OpenAI API key",
                r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|\bsk-[A-Za-z0-9]{32,}",
            ),
            ("Slack token", r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),
            ("Stripe live key", r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}"),
            ("Google API key", r"\bAIza[0-9A-Za-z_-]{35}"),
            ("GitLab token", r"\bglpat-[A-Za-z0-9_-]{20,}"),
            ("private key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
            (
                "URL with a password",
                r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:[^\s@/]{3,}@[^\s/]+",
            ),
        ]
        .into_iter()
        .map(|(name, re)| (name, Regex::new(re).expect("valid pattern")))
        .collect()
    })
}

/// The words of an identifier: `CONDUCTOR_JWT_SecretKey` -> conductor, jwt,
/// secret, key; `DBPassword` -> db, password.
fn words(name: &str) -> Vec<String> {
    let chars: Vec<char> = name.chars().collect();
    let mut out = Vec::new();
    let mut word = String::new();
    for (i, &c) in chars.iter().enumerate() {
        if !c.is_ascii_alphanumeric() {
            if !word.is_empty() {
                out.push(std::mem::take(&mut word));
            }
            continue;
        }
        let prev = i.checked_sub(1).map(|j| chars[j]);
        let next = chars.get(i + 1);
        // camelCase (`jwtSecret`), and the end of an acronym (`JWTSecret`).
        let boundary = c.is_ascii_uppercase()
            && (prev.is_some_and(|p| p.is_ascii_lowercase() || p.is_ascii_digit())
                || (prev.is_some_and(|p| p.is_ascii_uppercase())
                    && next.is_some_and(char::is_ascii_lowercase)));
        if boundary && !word.is_empty() {
            out.push(std::mem::take(&mut word));
        }
        word.push(c.to_ascii_lowercase());
    }
    if !word.is_empty() {
        out.push(word);
    }
    out
}

/// A name that says it holds a secret, by whole words: `DB_PASSWORD`,
/// `ClientSecret`, `API_KEY`, but not `Authority`, `TOKENIZER_PATH` or
/// `AUTH_URL` (a name ending in a word for where or how, not what).
fn secret_name(name: &str) -> bool {
    const WORDS: &[&str] = &[
        "secret",
        "secrets",
        "token",
        "password",
        "passwd",
        "pwd",
        "credential",
        "credentials",
        "dsn",
        "apikey",
        "privatekey",
        "accesskey",
        "secretkey",
        "auth",
        "authtoken",
    ];
    const PAIRS: &[(&str, &str)] = &[
        ("api", "key"),
        ("access", "key"),
        ("private", "key"),
        ("client", "key"),
        ("connection", "string"),
        ("signing", "key"),
    ];
    const NOT_SECRET_LAST: &[&str] = &[
        "url", "uri", "endpoint", "domain", "host", "path", "file", "enabled", "lifetime",
        "expiry", "ttl", "type", "header",
    ];
    let w = words(name);
    if w.last()
        .is_some_and(|l| NOT_SECRET_LAST.contains(&l.as_str()))
    {
        return false;
    }
    w.iter().any(|x| WORDS.contains(&x.as_str()))
        || w.windows(2)
            .any(|p| PAIRS.contains(&(p[0].as_str(), p[1].as_str())))
}

/// A real-looking secret rather than an empty value, a placeholder or a reference
/// to a secret manager (`op://…`, `${VAR}`).
fn literal(value: &str) -> bool {
    let v = value.trim().trim_matches(['"', '\'']);
    let lower = v.to_ascii_lowercase();
    v.len() >= 8
        && !v.starts_with(['$', '`', '<'])
        && !lower.starts_with("op://")
        && !lower.starts_with("your")
        && ![
            "changeme",
            "change_me",
            "xxxxxxxx",
            "password",
            "placeholder",
            "true",
            "false",
        ]
        .contains(&lower.as_str())
        && !v.chars().all(|c| c == 'x' || c == '*' || c == '.')
}

/// The kind of the first known token shape in `text`.
fn token_kind(text: &str) -> Option<&'static str> {
    token_patterns()
        .iter()
        .find(|(_, re)| re.is_match(text))
        .map(|(name, _)| *name)
}

/// Is this `name = value` pair a secret? By the shape of the value, or a
/// secret-sounding name with a literal value.
fn is_secret(name: &str, value: &str) -> bool {
    token_kind(value).is_some() || (secret_name(name) && literal(value))
}

fn list(names: &BTreeSet<String>, max: usize) -> String {
    let shown: Vec<&str> = names.iter().take(max).map(String::as_str).collect();
    match names.len().saturating_sub(max) {
        0 => shown.join(", "),
        more => format!("{}, and {more} more", shown.join(", ")),
    }
}

// ---- credential stores in the home directory ------------------------------------

fn ini_sections(src: &str) -> Vec<(String, Vec<(String, String)>)> {
    let mut sections: Vec<(String, Vec<(String, String)>)> = vec![(String::new(), Vec::new())];
    for line in src.lines().map(str::trim) {
        if line.starts_with('#') || line.starts_with(';') || line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            sections.push((name.trim().to_string(), Vec::new()));
        } else if let Some((k, v)) = line.split_once('=') {
            sections
                .last_mut()
                .expect("never empty")
                .1
                .push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    sections
}

fn aws(home: &Path, out: &mut Out) {
    let path = env_path(
        "AWS_SHARED_CREDENTIALS_FILE",
        home.join(".aws").join("credentials"),
    );
    let Some(src) = read(&path) else {
        out.passing.push(format!("AWS: no {} file", tilde(&path)));
        return;
    };
    let (mut long_lived, mut temporary) = (BTreeSet::new(), BTreeSet::new());
    for (profile, keys) in ini_sections(&src) {
        for (k, v) in keys {
            if k == "aws_access_key_id" {
                if v.starts_with("AKIA") {
                    long_lived.insert(profile.clone());
                } else if v.starts_with("ASIA") {
                    temporary.insert(profile.clone());
                }
            }
        }
    }
    if !long_lived.is_empty() {
        out.findings.push(
            Finding::new(format!("aws-keys|{}", list(&long_lived, 50)), Severity::High, "secret", "Long-lived AWS access keys on disk")
                .detail(format!(
                    "Profiles with permanent access keys (AKIA…) in {}: {}. They work from anywhere until someone rotates them.",
                    tilde(&path),
                    list(&long_lived, 10)
                ))
                .remedy("Delete them and deactivate them in IAM; sign in with IAM Identity Center (`aws sso login`) or aws-vault, which keep only short-lived credentials.")
                .at(at(&path)),
        );
    }
    if !temporary.is_empty() {
        out.findings.push(
            Finding::new("aws-temporary", Severity::Low, "secret", format!("Temporary AWS credentials stored in {}", tilde(&path)))
                .detail(format!("Profiles: {}. They expire, but anything running as you can use them until then.", list(&temporary, 10)))
                .remedy("Prefer `aws sso login` profiles or aws-vault over writing session keys into the credentials file.")
                .at(at(&path)),
        );
    }
    if long_lived.is_empty() && temporary.is_empty() {
        out.passing
            .push(format!("AWS: no access keys in {}", tilde(&path)));
    }
}

fn parse_expiry(raw: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw)
        .map(|t| t.with_timezone(&Utc))
        .ok()
        .or_else(|| {
            NaiveDateTime::parse_from_str(raw.trim_end_matches("UTC"), "%Y-%m-%dT%H:%M:%S")
                .ok()
                .map(|n| n.and_utc())
        })
}

fn json_files(dir: &Path) -> Vec<(PathBuf, Value)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .filter_map(|p| Some((p.clone(), serde_json::from_str(&read(&p)?).ok()?)))
        .collect()
}

/// SSO is far better than permanent keys, but its cache is still usable by
/// anything running as you until it expires, so it is listed (below the alert line).
fn aws_sign_in(home: &Path, now: DateTime<Utc>, out: &mut Out) {
    let sso_dir = home.join(".aws").join("sso").join("cache");
    let mut sessions = Vec::new();
    for (_, v) in json_files(&sso_dir) {
        let Some(expires) = v
            .get("expiresAt")
            .and_then(Value::as_str)
            .and_then(parse_expiry)
        else {
            continue;
        };
        if expires > now && v.get("accessToken").is_some() {
            sessions.push((expires, v.get("refreshToken").is_some()));
        }
    }
    let cli_dir = home.join(".aws").join("cli").join("cache");
    let roles = json_files(&cli_dir)
        .iter()
        .filter(|(_, v)| {
            v.pointer("/Credentials/Expiration")
                .and_then(Value::as_str)
                .and_then(parse_expiry)
                .is_some_and(|e| e > now)
        })
        .count();
    if sessions.is_empty() && roles == 0 {
        out.passing
            .push("AWS: no active SSO session or cached role credentials".to_string());
        return;
    }
    if sessions.is_empty() {
        out.findings.push(
            Finding::new(
                "aws-sign-in",
                Severity::Info,
                "secret",
                "Cached AWS role credentials on disk",
            )
            .detail(format!(
                "{roles} cached role {}. Anything running as you can use them until they expire.",
                if roles == 1 {
                    "credential"
                } else {
                    "credentials"
                }
            ))
            .remedy("They expire on their own; delete ~/.aws/cli/cache to end them sooner.")
            .at(at(&cli_dir)),
        );
        return;
    }
    let renewable = sessions.iter().any(|(_, refresh)| *refresh);
    let latest = sessions.iter().map(|(e, _)| *e).max();
    let hours = latest.map(|e| (e - now).num_minutes() as f64 / 60.0);
    out.findings.push(
        Finding::new("aws-sign-in", if renewable { Severity::Low } else { Severity::Info }, "secret", "Active AWS sign-in cached on disk")
            .detail(format!(
                "{} active SSO {}{}{}, and {roles} cached role credentials. Anything running as you can mint credentials \
                 for every account and role this sign-in reaches until it expires{}.",
                sessions.len(),
                if sessions.len() == 1 { "session" } else { "sessions" },
                hours.map(|h| format!(" (expires in {h:.1} h)")).unwrap_or_default(),
                if renewable { ", with a refresh token" } else { "" },
                if renewable { ", and renew it with the refresh token" } else { "" }
            ))
            .remedy(
                "Keep production behind a separate profile with a short session that needs a fresh MFA sign-in; \
                 run `aws sso logout` when you are done; shorten the session duration in IAM Identity Center. \
                 Ending the session there revokes everything derived from it.",
            )
            .at(at(&sso_dir)),
    );
}

/// `cargo login` without a credential provider stores the token in plain text.
/// `dir` is `$CARGO_HOME` (default `~/.cargo`).
fn cargo_credentials(dir: &Path, out: &mut Out) {
    for name in ["credentials.toml", "credentials"] {
        let path = dir.join(name);
        let Some(src) = read(&path) else { continue };
        let registries: BTreeSet<String> = ini_sections(&src)
            .into_iter()
            .filter(|(_, keys)| keys.iter().any(|(k, v)| k == "token" && literal(v)))
            .map(|(section, _)| {
                section
                    .strip_prefix("registries.")
                    .unwrap_or("crates.io")
                    .to_string()
            })
            .collect();
        if registries.is_empty() {
            continue;
        }
        out.findings.push(
            Finding::new(
                format!("cargo-token|{name}|{}", list(&registries, 20)),
                Severity::High,
                "secret",
                format!("Cargo registry token stored in plain text in {}", tilde(&path)),
            )
            .detail(format!(
                "Registries: {}. Anyone with it can publish new versions of your crates, which is how a supply-chain worm spreads.",
                list(&registries, 5)
            ))
            .remedy(
                "Keep it in the system keychain instead: set `[registry] global-credential-providers = [\"cargo:macos-keychain\"]` \
                 (`cargo:wincred` on Windows, `cargo:libsecret` on Linux) in ~/.cargo/config.toml, then `cargo logout` and `cargo login` again. \
                 Create the token with only the publish-update scope, limited to your crates.",
            )
            .at(at(&path)),
        );
        return;
    }
    out.passing
        .push("Cargo: no registry token in plain text".to_string());
}

fn npmrc(home: &Path, out: &mut Out) {
    let path = env_path("NPM_CONFIG_USERCONFIG", home.join(".npmrc"));
    let Some(src) = read(&path) else {
        out.passing.push(format!("npm: no {} file", tilde(&path)));
        return;
    };
    let registries: BTreeSet<String> = src
        .lines()
        .filter_map(|l| l.split_once('='))
        // A commented-out token is still a token on disk; drop only the marker.
        .map(|(k, v)| (k.trim().trim_start_matches([';', '#']).trim(), v))
        .filter(|(k, v)| {
            (k.ends_with("_authToken") || k.ends_with("_auth") || k.ends_with("_password"))
                && literal(v)
        })
        .map(|(k, _)| {
            k.rsplit_once(':')
                .map_or("default registry", |(r, _)| r)
                .trim_start_matches("//")
                .to_string()
        })
        .collect();
    if registries.is_empty() {
        out.passing
            .push(format!("npm: no tokens in {}", tilde(&path)));
        return;
    }
    out.findings.push(
        Finding::new(format!("npm-token|{}", list(&registries, 20)), Severity::High, "secret", format!("npm token stored in {}", tilde(&path)))
            .detail(format!(
                "Registries: {}. With a publish token, malware can push poisoned versions of your packages, which is how \
                 the Shai-Hulud worm spread.",
                list(&registries, 5)
            ))
            .remedy("Log in only when publishing (`npm login`, then `npm logout`), use granular tokens limited to the packages you publish, and require 2FA for publishing.")
            .at(at(&path)),
    );
}

/// A file whose content alone means a plaintext credential.
struct TokenFile {
    path: PathBuf,
    key: &'static str,
    title: &'static str,
    remedy: &'static str,
    holds_credential: fn(&str) -> bool,
}

fn has_url_password(src: &str) -> bool {
    src.lines().any(|l| l.contains("://") && l.contains('@'))
}

/// Files whose mere content means a plaintext credential.
fn simple_token_files(home: &Path, out: &mut Out) {
    let gh = env_path("GH_CONFIG_DIR", home.join(".config").join("gh")).join("hosts.yml");
    let checks = [
        TokenFile {
            path: gh,
            key: "gh-token",
            title: "GitHub CLI token stored in plain text",
            remedy: "`gh auth logout` and `gh auth login` again: gh keeps the token in the system keychain unless told not to.",
            holds_credential: |s| {
                s.lines().any(|l| {
                    l.trim_start().starts_with("oauth_token:")
                        && literal(l.split_once(':').map_or("", |x| x.1))
                })
            },
        },
        TokenFile {
            path: home.join(".git-credentials"),
            key: "git-credentials",
            title: "Git passwords stored in ~/.git-credentials",
            remedy: "Use the platform credential helper (`git config --global credential.helper osxkeychain` / `manager`) and delete the file.",
            holds_credential: has_url_password,
        },
        TokenFile {
            path: home.join(".config").join("git").join("credentials"),
            key: "git-credentials-xdg",
            title: "Git passwords stored in ~/.config/git/credentials",
            remedy: "Use the platform credential helper and delete the file.",
            holds_credential: has_url_password,
        },
        TokenFile {
            path: home.join(if cfg!(windows) { "_netrc" } else { ".netrc" }),
            key: "netrc",
            title: "Passwords stored in ~/.netrc",
            remedy: "Remove the password entries; use a credential helper or the tool's own login.",
            holds_credential: |s| s.split_whitespace().any(|w| w == "password"),
        },
        TokenFile {
            path: home.join(".pypirc"),
            key: "pypirc",
            title: "PyPI password or token stored in ~/.pypirc",
            remedy: "Use trusted publishing from CI, or keyring, instead of a stored token.",
            holds_credential: |s| {
                ini_sections(s)
                    .iter()
                    .flat_map(|(_, kv)| kv)
                    .any(|(k, v)| k == "password" && literal(v))
            },
        },
        TokenFile {
            path: home.join(".terraform.d").join("credentials.tfrc.json"),
            key: "terraform-token",
            title: "Terraform Cloud token stored in plain text",
            remedy: "Use a credentials helper, or `terraform logout` when not needed.",
            holds_credential: |s| s.contains("\"token\""),
        },
    ];
    for t in checks {
        let Some(src) = read(&t.path) else { continue };
        if (t.holds_credential)(&src) {
            out.findings.push(
                Finding::new(t.key, Severity::High, "secret", t.title)
                    .remedy(t.remedy)
                    .at(at(&t.path)),
            );
        } else if t.key == "gh-token" && !src.contains("oauth_token:") {
            out.passing
                .push("GitHub CLI: token kept in the system keychain".to_string());
        }
    }
}

fn docker(home: &Path, out: &mut Out) {
    let path = env_path("DOCKER_CONFIG", home.join(".docker")).join("config.json");
    let Some(doc) = read(&path).and_then(|s| serde_json::from_str::<Value>(&s).ok()) else {
        out.passing
            .push(format!("Docker: no readable {}", tilde(&path)));
        return;
    };
    let inline: BTreeSet<String> = doc
        .get("auths")
        .and_then(Value::as_object)
        .map(|auths| {
            auths
                .iter()
                .filter(|(_, v)| {
                    ["auth", "identitytoken", "password"].iter().any(|k| {
                        v.get(k)
                            .and_then(Value::as_str)
                            .is_some_and(|s| !s.is_empty())
                    })
                })
                .map(|(registry, _)| registry.clone())
                .collect()
        })
        .unwrap_or_default();
    if inline.is_empty() {
        out.passing
            .push("Docker: registry logins use a credential helper".to_string());
        return;
    }
    out.findings.push(
        Finding::new(format!("docker-auth|{}", list(&inline, 20)), Severity::High, "secret", "Docker registry passwords stored in plain text")
            .detail(format!("Registries: {} (base64 user:password in config.json).", list(&inline, 5)))
            .remedy("Set `\"credsStore\": \"osxkeychain\"` (or desktop / wincred / pass), then `docker logout` and log in again.")
            .at(at(&path)),
    );
}

/// Every file in `KUBECONFIG` (kubectl merges them all), else `~/.kube/config`.
fn kubeconfigs(home: &Path) -> Vec<PathBuf> {
    let listed: Vec<PathBuf> = std::env::var_os("KUBECONFIG")
        .map(|v| {
            std::env::split_paths(&v)
                .filter(|p| !p.as_os_str().is_empty())
                .collect()
        })
        .unwrap_or_default();
    if listed.is_empty() {
        vec![home.join(".kube").join("config")]
    } else {
        listed
    }
}

fn kube(home: &Path, out: &mut Out) {
    let mut clean = Vec::new();
    for path in kubeconfigs(home) {
        let Some(src) = read(&path) else { continue };
        let kinds: BTreeSet<&str> = src
            .lines()
            .map(str::trim_start)
            .filter_map(|l| {
                ["token:", "client-key-data:", "password:"]
                    .into_iter()
                    .find(|k| l.strip_prefix(k).is_some_and(literal))
            })
            .collect();
        if kinds.is_empty() {
            clean.push(tilde(&path));
            continue;
        }
        out.findings.push(
            Finding::new(format!("kube-static|{}", tilde(&path)), Severity::High, "secret", "Static Kubernetes credentials in kubeconfig")
                .detail(format!(
                    "{} stores {} directly.",
                    tilde(&path),
                    kinds.iter().map(|k| k.trim_end_matches(':')).collect::<Vec<_>>().join(", ")
                ))
                .remedy("Use an `exec` credential plugin (aws eks get-token, gke-gcloud-auth-plugin, kubelogin) that issues short-lived tokens.")
                .at(at(&path)),
        );
    }
    if !clean.is_empty() {
        out.passing.push(format!(
            "Kubernetes: no static credentials in {}",
            clean.join(", ")
        ));
    }
}

// ---- SSH keys ---------------------------------------------------------------------

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for c in input
        .bytes()
        .filter(|c| !c.is_ascii_whitespace() && *c != b'=')
    {
        buf = (buf << 6) | ALPHABET.iter().position(|&a| a == c)? as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

/// `Some(true)` when the key needs a passphrase, `None` when it is not a private key.
fn key_is_encrypted(src: &str) -> Option<bool> {
    if !src.contains("PRIVATE KEY-----") {
        return None;
    }
    if src.contains("BEGIN OPENSSH PRIVATE KEY") {
        let body: String = src.lines().filter(|l| !l.starts_with("-----")).collect();
        let bytes = base64_decode(&body)?;
        let rest = bytes.strip_prefix(b"openssh-key-v1\0")?;
        let len = u32::from_be_bytes(rest.get(..4)?.try_into().ok()?) as usize;
        let cipher = rest.get(4..4 + len)?;
        return Some(cipher != b"none");
    }
    Some(src.contains("ENCRYPTED"))
}

fn ssh(home: &Path, out: &mut Out) {
    let dir = home.join(".ssh");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        out.passing.push("SSH: no ~/.ssh folder".to_string());
        return;
    };
    let mut bare = Vec::new();
    let mut protected = 0;
    for path in entries.flatten().map(|e| e.path()).filter(|p| p.is_file()) {
        let Some(src) = read(&path) else { continue };
        match key_is_encrypted(&src) {
            Some(false) => bare.push(path),
            Some(true) => protected += 1,
            None => {}
        }
    }
    for path in &bare {
        out.findings.push(
            Finding::new(format!("ssh-key|{}", tilde(path)), Severity::High, "secret", format!("SSH key without a passphrase: {}", tilde(path)))
                .detail("Anything running as you can copy it and use it anywhere until you remove it from every server and Git host.")
                .remedy(format!(
                    "Add a passphrase (`ssh-keygen -p -f {}`) and keep it in the agent/keychain, or move to a key that cannot leave the machine: \
                     a Secure Enclave key (e.g. Secretive) or a hardware key (`ssh-keygen -t ed25519-sk`).",
                    tilde(path)
                ))
                .at(at(path)),
        );
    }
    match (bare.is_empty(), protected) {
        (false, _) => {}
        (true, 0) => out
            .passing
            .push("SSH: no private keys in ~/.ssh".to_string()),
        (true, 1) => out
            .passing
            .push("SSH: 1 private key, passphrase-protected".to_string()),
        (true, n) => out
            .passing
            .push(format!("SSH: {n} private keys, all passphrase-protected")),
    }
}

fn gcloud(home: &Path, out: &mut Out) {
    let dir = env_path("CLOUDSDK_CONFIG", home.join(".config").join("gcloud"));
    let adc = dir.join("application_default_credentials.json");
    if let Some(doc) = read(&adc).and_then(|s| serde_json::from_str::<Value>(&s).ok()) {
        let held = match doc.get("type").and_then(Value::as_str) {
            Some("service_account") => Some((Severity::Critical, "a service-account private key")),
            Some("authorized_user") => {
                Some((Severity::High, "a refresh token for your Google account"))
            }
            Some("impersonated_service_account") => Some((
                Severity::High,
                "a refresh token used to impersonate a service account",
            )),
            Some("external_account_authorized_user") => {
                Some((Severity::High, "a refresh token for a federated account"))
            }
            // Workload identity federation and unknown types point to a token
            // source rather than holding a secret.
            _ => None,
        };
        match held {
            Some((severity, what)) => out.findings.push(
                Finding::new("gcloud-adc", severity, "secret", "Google Cloud application-default credentials on disk")
                    .detail(format!("{} holds {what}.", tilde(&adc)))
                    .remedy("Prefer service-account impersonation and `gcloud auth application-default revoke` when not needed; never keep service-account keys on a laptop.")
                    .at(at(&adc)),
            ),
            None => out.passing.push(format!(
                "Google Cloud: {} holds no stored secret",
                tilde(&adc)
            )),
        }
    }
    let db = dir.join("credentials.db");
    if db.exists() {
        out.findings.push(
            Finding::new(
                "gcloud-db",
                Severity::Medium,
                "secret",
                "gcloud refresh tokens in credentials.db",
            )
            .remedy("`gcloud auth revoke` accounts you no longer use.")
            .at(at(&db)),
        );
    }
}

// ---- shell startup files and history ---------------------------------------------------

/// `NAME=value`, `export NAME=value`, or fish's `set -x NAME value`.
fn assignment() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^\s*(?:(?:export\s+)?(?P<sh>[A-Za-z_][A-Za-z0-9_]*)=|set\s+-[a-zA-Z]*x[a-zA-Z]*\s+(?P<fish>[A-Za-z_][A-Za-z0-9_]*)\s+)(?P<value>.+)$",
        )
        .expect("valid pattern")
    })
}

/// What a startup-file line exposes: the variable it sets to a secret, or the
/// kind of token a command carries (`curl -H "Authorization: Bearer ghp_…"`).
fn startup_secret(line: &str) -> Option<String> {
    match assignment().captures(line) {
        Some(c) => {
            let name = c.name("sh").or_else(|| c.name("fish"))?.as_str();
            (name != "PWD" && is_secret(name, &c["value"])).then(|| name.to_string())
        }
        None => token_kind(line).map(|kind| format!("{kind} in a command")),
    }
}

fn shell_startup(home: &Path, out: &mut Out) {
    let files = [
        ".zshrc",
        ".zprofile",
        ".zshenv",
        ".bashrc",
        ".bash_profile",
        ".profile",
        ".config/fish/config.fish",
    ];
    for rel in files {
        let path = home.join(rel);
        let Some(src) = read(&path) else { continue };
        let names: BTreeSet<String> = src
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .filter_map(startup_secret)
            .collect();
        if names.is_empty() {
            continue;
        }
        out.findings.push(
            Finding::new(format!("shell-env|{rel}|{}", list(&names, 30)), Severity::High, "secret", format!("Secrets in ~/{rel}"))
                .detail(format!("{}. Every program you start, including package install scripts, inherits them.", list(&names, 8)))
                .remedy("Move them into a secret manager and load them only for the command that needs them (`op run`, aws-vault, direnv with a keychain lookup), then rotate them.")
                .at(at(&path)),
        );
    }
}

fn shell_history(home: &Path, out: &mut Out) {
    let files = [
        ".zsh_history",
        ".bash_history",
        ".local/share/fish/fish_history",
        ".python_history",
        ".node_repl_history",
        ".psql_history",
    ];
    for rel in files {
        let path = home.join(rel);
        let Some(src) = read(&path) else { continue };
        let mut kinds: BTreeMap<&str, usize> = BTreeMap::new();
        for (name, re) in token_patterns() {
            let n = re.find_iter(&src).count();
            if n > 0 {
                *kinds.entry(name).or_default() += n;
            }
        }
        if kinds.is_empty() {
            continue;
        }
        let total: usize = kinds.values().sum();
        let described: Vec<String> = kinds.iter().map(|(k, n)| format!("{k} ×{n}")).collect();
        out.findings.push(
            Finding::new(
                format!("history|{rel}|{}", kinds.keys().copied().collect::<Vec<_>>().join(",")),
                Severity::Medium,
                "secret",
                format!("{total} credentials in ~/{rel}"),
            )
            .detail(described.join(", "))
            .remedy("Rotate them, then delete those lines. Start commands that carry a secret with a space and enable HIST_IGNORE_SPACE (zsh) / HISTCONTROL=ignorespace (bash).")
            .at(at(&path)),
        );
    }
}

// ---- project files under the search roots (and every worktree) --------------------------

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

fn skip_dir(name: &str) -> bool {
    name.starts_with('.') || SKIP_DIRS.contains(&name)
}

fn env_file(name: &str) -> bool {
    (name == ".env" || name.starts_with(".env."))
        && ![
            ".example",
            ".sample",
            ".template",
            ".defaults",
            ".dist",
            ".schema",
        ]
        .iter()
        .any(|s| name.ends_with(s))
}

/// Secrets are small files; anything bigger is not one of these.
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// `name` ends with `suffix`, ignoring ASCII case (`KEY.PEM`).
fn ends_with_ci(name: &str, suffix: &str) -> bool {
    name.len()
        .checked_sub(suffix.len())
        .and_then(|start| name.get(start..))
        .is_some_and(|end| end.eq_ignore_ascii_case(suffix))
}

fn interesting(name: &str) -> bool {
    env_file(name)
        || (name.starts_with("appsettings") && ends_with_ci(name, ".json"))
        || name == "secrets.json"
        || [".tfstate", ".pem", ".key", ".p12", ".pfx"]
            .iter()
            .any(|ext| ends_with_ci(name, ext))
        || (ends_with_ci(name, ".json")
            && (name.contains("credential")
                || name.contains("service-account")
                || name.contains("serviceaccount")))
}

/// What a file exposes.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Found {
    /// The settings or variables holding secrets.
    Names(BTreeSet<String>),
    /// The file itself is the secret (a key, a certificate bundle, Terraform state).
    WholeFile(&'static str),
}

impl Found {
    fn describe(&self, max: usize) -> String {
        match self {
            Found::Names(names) => list(names, max),
            Found::WholeFile(what) => (*what).to_string(),
        }
    }
}

/// A variable name in a `.env` file, not a line that merely contains `=`
/// (a URL with `?token=` must never be shown as a name).
fn env_name(key: &str) -> bool {
    !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

fn file_secrets(name: &str, src: &str) -> Option<Found> {
    if env_file(name) {
        let mut found = BTreeSet::new();
        for line in src.lines().map(str::trim).filter(|l| !l.starts_with('#')) {
            let line = line.strip_prefix("export ").unwrap_or(line);
            if let Some((k, v)) = line.split_once('=')
                && let k = k.trim()
                && env_name(k)
                && is_secret(k, v)
            {
                found.insert(k.to_string());
            }
        }
        (!found.is_empty()).then_some(Found::Names(found))
    } else if ends_with_ci(name, ".json") {
        let mut found = BTreeSet::new();
        if let Ok(doc) = serde_json::from_str::<Value>(src) {
            json_secrets(&doc, "", &mut found);
        }
        (!found.is_empty()).then_some(Found::Names(found))
    } else if ends_with_ci(name, ".tfstate") {
        (src.contains("\"sensitive_attributes\"")
            || src.contains("\"password\"")
            || src.contains("\"secret"))
        .then_some(Found::WholeFile(
            "Terraform state (holds resource secrets in plain text)",
        ))
    } else if ends_with_ci(name, ".p12") || ends_with_ci(name, ".pfx") {
        Some(Found::WholeFile("certificate bundle with a private key"))
    } else if src.contains("PRIVATE KEY-----") {
        Some(Found::WholeFile("private key"))
    } else {
        None
    }
}

fn json_secrets(v: &Value, path: &str, found: &mut BTreeSet<String>) {
    match v {
        Value::Object(map) => {
            for (k, child) in map {
                let p = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                json_secrets(child, &p, found);
            }
        }
        Value::Array(items) => items.iter().for_each(|i| json_secrets(i, path, found)),
        Value::String(s) => {
            let leaf = path.rsplit('.').next().unwrap_or(path);
            let lower = s.to_ascii_lowercase();
            let connection = lower.contains("password=") && !lower.contains("password=;");
            if is_secret(leaf, s) || connection {
                found.insert(path.to_string());
            }
        }
        _ => {}
    }
}

/// Several key files in one folder (`certs/{a,b,c}.key`), or in sibling
/// folders (`vpn-users/<person>/<person>.key`), read better as one finding
/// about that folder.
fn collapse_siblings(
    groups: BTreeMap<(String, Found), Vec<PathBuf>>,
) -> BTreeMap<(String, Found), Vec<PathBuf>> {
    const MIN_FILES: usize = 3;
    // The folder and the one above it, nearest first.
    let folders = |p: &Path| -> Vec<PathBuf> {
        p.ancestors()
            .skip(1)
            .take(2)
            .map(Path::to_path_buf)
            .collect()
    };
    let single = |found: &Found, copies: &[PathBuf]| {
        matches!(found, Found::WholeFile(_)) && copies.len() == 1
    };
    let mut per_folder: BTreeMap<(PathBuf, Found), usize> = BTreeMap::new();
    for ((_, found), copies) in &groups {
        if single(found, copies) {
            for dir in folders(&copies[0]) {
                *per_folder.entry((dir, found.clone())).or_default() += 1;
            }
        }
    }
    let mut out: BTreeMap<(String, Found), Vec<PathBuf>> = BTreeMap::new();
    for ((rel, found), copies) in groups {
        let target = single(&found, &copies)
            .then(|| {
                folders(&copies[0]).into_iter().find(|dir| {
                    per_folder
                        .get(&(dir.clone(), found.clone()))
                        .is_some_and(|n| *n >= MIN_FILES)
                })
            })
            .flatten();
        let rel = target.map_or(rel, |dir| format!("{}/*", tilde(&dir)));
        out.entry((rel, found)).or_default().extend(copies);
    }
    out
}

/// The main checkout a worktree belongs to (its `.git` file points into
/// `<main>/.git/worktrees/<name>`), or `repo` itself.
fn main_checkout(repo: &Path) -> PathBuf {
    std::fs::read_to_string(repo.join(".git"))
        .ok()
        .and_then(|text| {
            let gitdir = repo.join(text.trim().strip_prefix("gitdir:")?.trim());
            let worktrees = gitdir.parent()?;
            (worktrees.file_name()? == "worktrees")
                .then(|| worktrees.parent()?.parent().map(Path::to_path_buf))
                .flatten()
        })
        .unwrap_or_else(|| repo.to_path_buf())
}

/// Whether a path names production (`.env.prod`, `deploy/production/`),
/// by whole words so `product-site` does not count.
fn production(path: &str) -> bool {
    path.split(['/', '\\', '.', '-', '_'])
        .any(|w| w.eq_ignore_ascii_case("prod") || w.eq_ignore_ascii_case("production"))
}

/// The repository root above `dir` (where `.git` is), to group copies of the
/// same file across worktrees.
fn repo_root(dir: &Path, cache: &mut HashMap<PathBuf, Option<PathBuf>>) -> Option<PathBuf> {
    if let Some(hit) = cache.get(dir) {
        return hit.clone();
    }
    let found = if dir.join(".git").exists() {
        Some(dir.to_path_buf())
    } else {
        dir.parent().and_then(|p| repo_root(p, cache))
    };
    cache.insert(dir.to_path_buf(), found.clone());
    found
}

fn project_files(roots: &[PathBuf], exclude: &Exclude, max_depth: usize, out: &mut Out) {
    let mut seen_files = BTreeSet::new();
    let mut repos = HashMap::new();
    // (path in the main checkout, what is exposed) -> every copy, across worktrees.
    let mut groups: BTreeMap<(String, Found), Vec<PathBuf>> = BTreeMap::new();
    let mut scanned = 0usize;
    for root in roots.iter().filter(|r| r.is_dir() && !exclude.skips(r)) {
        let walker = WalkDir::new(root)
            .max_depth(max_depth)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                e.depth() == 0
                    || !(e.file_type().is_dir()
                        && (skip_dir(&e.file_name().to_string_lossy()) || exclude.skips(e.path())))
            });
        for entry in walker.flatten().filter(|e| e.file_type().is_file()) {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !interesting(&name) || !seen_files.insert(entry.path().to_path_buf()) {
                continue;
            }
            if !entry.metadata().is_ok_and(|m| m.len() <= MAX_FILE_BYTES) {
                continue;
            }
            scanned += 1;
            let Some(src) = read(entry.path()) else {
                continue;
            };
            let Some(found) = file_secrets(&name, &src) else {
                continue;
            };
            let path = entry.path().to_path_buf();
            // Copies in worktrees of one repository group under its main checkout;
            // the same file name in an unrelated repository is a separate finding.
            let rel = path
                .parent()
                .and_then(|d| repo_root(d, &mut repos))
                .and_then(|r| {
                    let inside = path.strip_prefix(&r).ok()?;
                    Some(tilde(&main_checkout(&r).join(inside)))
                })
                .unwrap_or_else(|| tilde(&path));
            groups.entry((rel, found)).or_default().push(path);
        }
    }
    for ((rel, found), copies) in collapse_siblings(groups) {
        let whole_file = matches!(found, Found::WholeFile(_));
        let severity = if production(&rel) || whole_file {
            Severity::High
        } else {
            Severity::Medium
        };
        let collapsed = rel.ends_with("/*");
        let copies_text = match (copies.len(), collapsed) {
            (1, _) => String::new(),
            (n, true) => format!(" ({n} files)"),
            (n, false) => format!(" ({n} copies)"),
        };
        // One copy: its full path says which project it is; several: the path they share.
        let shown = if copies.len() == 1 {
            tilde(&copies[0])
        } else {
            rel.clone()
        };
        let title = match &found {
            Found::WholeFile(what) => format!("{shown}: {what}{copies_text}"),
            Found::Names(names) => format!(
                "{shown} holds {} {}{copies_text}",
                names.len(),
                if names.len() == 1 {
                    "secret"
                } else {
                    "secrets"
                }
            ),
        };
        let remedy = if collapsed {
            "Keys belong in a secret manager or on the machines that use them, not in a working directory. \
             Move or delete them, and revoke any that are no longer needed."
        } else if copies.len() > 1 {
            "Every copy is another file to steal: remove worktrees you no longer use, and load secrets at run time \
             (`op run --env-file`, aws-vault, Doppler) instead of copying them into each checkout."
        } else {
            "Load secrets at run time from a secret manager instead of keeping them in the file, and rotate any that were ever committed."
        };
        let mut f = Finding::new(
            format!("file|{rel}|{}", found.describe(100)),
            severity,
            "secret",
            title,
        )
        .detail(match &found {
            Found::WholeFile(what) => (*what).to_string(),
            Found::Names(names) => format!("Names: {}", list(names, 12)),
        })
        .remedy(remedy);
        for p in &copies {
            f = f.at(at(p));
        }
        out.findings.push(f);
    }
    out.passing.push(format!(
        "Looked at {scanned} .env, settings and key files under {} directories",
        roots.len()
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_values_without_keeping_them() {
        assert!(is_secret(
            "DATABASE_URL",
            "postgres://app:hunter2hunter2@db.internal:5432/app"
        ));
        assert!(is_secret(
            "GITHUB",
            "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"
        ));
        assert!(is_secret("STRIPE_SECRET_KEY", "sk_test_51abcdefghijklmnop"));
        assert!(!is_secret("API_KEY", ""));
        assert!(!is_secret("API_KEY", "${API_KEY}"));
        assert!(!is_secret(
            "OPENAI_API_KEY",
            "op://Private/openai/credential"
        ));
        assert!(!is_secret("LOG_LEVEL", "debug-verbose-mode"));
        assert!(!is_secret("AUTH_ENABLED", "true"));
        assert!(!is_secret(
            "Authority",
            "https://login.microsoftonline.com/tenant"
        ));
        assert!(!is_secret("TOKENIZER_PATH", "/models/tokenizer.json"));
        assert!(is_secret("ClientSecret", "abcDEF123456ghiJKL"));
        assert!(is_secret(
            "CONDUCTOR_JWT_SECRET_KEY",
            "abcdefghijklmnop1234"
        ));
        assert_eq!(
            words("CONDUCTOR_JWT_SecretKey"),
            vec!["conductor", "jwt", "secret", "key"]
        );
        assert_eq!(words("DBPassword"), vec!["db", "password"]);
        assert!(is_secret("JWTSecret", "abcdefghijklmnop1234"));
        assert!(!is_secret("AUTH_URL", "https://auth.example.com/login"));
        assert_eq!(
            token_kind("sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789"),
            Some("Anthropic API key")
        );
        assert_eq!(
            startup_secret("curl -H 'X: Bearer ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ'"),
            Some("GitHub token in a command".to_string())
        );
        assert_eq!(
            startup_secret("set -gx GITHUB_TOKEN ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"),
            Some("GITHUB_TOKEN".to_string())
        );
        assert!(production("~/deploy/prod/.env") && !production("~/code/product-site/.env"));
    }

    #[test]
    fn env_and_settings_files_report_names_only() {
        let env = "# comment\nexport AWS_SECRET_ACCESS_KEY=abcd1234efgh5678\nPORT=8080\nDATABASE_URL=postgres://u:pa55word99@h/db\nEMPTY_TOKEN=\n";
        let names = |found| match found {
            Some(Found::Names(n)) => n.into_iter().collect::<Vec<_>>(),
            other => panic!("{other:?}"),
        };
        assert_eq!(
            names(file_secrets(".env.production", env)),
            vec!["AWS_SECRET_ACCESS_KEY", "DATABASE_URL"]
        );
        // A line that is not an assignment never becomes a "name".
        let url = "https://deploy:S3cretPass@ci.example.com/hook?token=abc12345\n";
        assert_eq!(file_secrets(".env", url), None);
        let settings = r#"{"ConnectionStrings":{"Main":"Host=db;Username=app;Password=s3cretpass"},"Logging":{"Level":"Info"},"Jwt":{"Secret":"abcdefghijklmnopqrstuvwxyz"}}"#;
        assert_eq!(
            names(file_secrets("appsettings.Production.json", settings)),
            vec!["ConnectionStrings.Main", "Jwt.Secret"]
        );
        assert!(!env_file(".env.example") && env_file(".env.local"));
    }

    #[test]
    fn finds_cargo_tokens_by_registry() {
        let base = std::env::temp_dir().join(format!("lenstica-cargo-{}", std::process::id()));
        let cargo = base.join(".cargo");
        std::fs::create_dir_all(&cargo).unwrap();
        std::fs::write(
            cargo.join("credentials.toml"),
            "[registry]\ntoken = \"cio_abcdefghijklmnopqrstuvwxyz\"\n\n[registries.corp]\ntoken = \"corp-0123456789abcdef\"\n",
        )
        .unwrap();
        let mut out = Out::default();
        cargo_credentials(&cargo, &mut out);
        let f = &out.findings[0];
        assert_eq!(f.severity, Severity::High);
        assert!(f.detail.contains("corp, crates.io"), "{}", f.detail);
        assert!(!serde_json::to_string(f).unwrap().contains("cio_abcdef"));
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn detects_unencrypted_openssh_keys() {
        // Header of an ed25519 key with cipher "none" / "aes256-ctr" (key material omitted).
        let encode = |cipher: &str| {
            let mut bytes = b"openssh-key-v1\0".to_vec();
            bytes.extend((cipher.len() as u32).to_be_bytes());
            bytes.extend(cipher.as_bytes());
            const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut s = String::new();
            for chunk in bytes.chunks(3) {
                let n = chunk.iter().fold(0u32, |acc, &b| (acc << 8) | b as u32)
                    << (8 * (3 - chunk.len()));
                for i in 0..=chunk.len() {
                    s.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
                }
            }
            format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{s}\n-----END OPENSSH PRIVATE KEY-----\n")
        };
        assert_eq!(key_is_encrypted(&encode("none")), Some(false));
        assert_eq!(key_is_encrypted(&encode("aes256-ctr")), Some(true));
        assert_eq!(key_is_encrypted("ssh-ed25519 AAAA... user@host"), None);
        assert_eq!(
            key_is_encrypted("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n"),
            Some(true)
        );
    }

    #[test]
    fn copies_across_worktrees_group_into_one_finding() {
        let base = std::env::temp_dir().join(format!("lenstica-secrets-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        // A main checkout, two worktrees of it, and an unrelated repository.
        for wt in ["main", "wt-a", "wt-b", "other"] {
            let dir = base.join(wt);
            std::fs::create_dir_all(&dir).unwrap();
            match wt {
                "main" | "other" => std::fs::create_dir_all(dir.join(".git")).unwrap(),
                _ => {
                    let gitdir = base.join("main/.git/worktrees").join(wt);
                    std::fs::create_dir_all(&gitdir).unwrap();
                    std::fs::write(dir.join(".git"), format!("gitdir: {}\n", gitdir.display()))
                        .unwrap();
                }
            }
            std::fs::write(
                dir.join(".env.production"),
                "DB_PASSWORD=correcthorsebattery\n",
            )
            .unwrap();
        }
        let roots: Vec<PathBuf> = ["main", "wt-a", "wt-b", "other"]
            .iter()
            .map(|w| base.join(w))
            .collect();
        let mut out = Out::default();
        project_files(&roots, &Exclude::default(), 4, &mut out);
        let titles: Vec<&str> = out.findings.iter().map(|f| f.title.as_str()).collect();
        assert_eq!(out.findings.len(), 2, "{titles:?}");
        let f = out
            .findings
            .iter()
            .find(|f| f.locations.len() == 3)
            .expect("the worktrees grouped");
        assert!(
            f.title
                .ends_with("main/.env.production holds 1 secret (3 copies)"),
            "{}",
            f.title
        );
        assert_eq!(f.severity, Severity::High);
        assert!(
            titles
                .iter()
                .any(|t| t.ends_with("other/.env.production holds 1 secret"))
        );
        assert!(!serde_json::to_string(f).unwrap().contains("correcthorse"));

        // Sibling folders with one key each collapse into their parent.
        let keys = base.join("vpn-users");
        for person in ["ann", "bob", "cy"] {
            std::fs::create_dir_all(keys.join(person)).unwrap();
            std::fs::write(
                keys.join(person).join(format!("{person}.key")),
                "-----BEGIN PRIVATE KEY-----\nx\n",
            )
            .unwrap();
        }
        let mut out = Out::default();
        project_files(
            std::slice::from_ref(&keys),
            &Exclude::default(),
            4,
            &mut out,
        );
        assert_eq!(out.findings.len(), 1);
        assert!(
            out.findings[0]
                .title
                .ends_with("vpn-users/*: private key (3 files)"),
            "{}",
            out.findings[0].title
        );
        std::fs::remove_dir_all(&base).unwrap();
    }
}
