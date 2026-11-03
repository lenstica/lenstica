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
use lenstica_lens::{Context, Exclude, Finding, Lens, Location, Report, Result, Severity};
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
        let home = home();
        let mut out = Out::default();
        aws(&home, &mut out);
        aws_sign_in(&home, &mut out);
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
            format!(
                "{problems} exposures ({} critical, {} high, {} medium)",
                count(Severity::Critical),
                count(Severity::High),
                count(Severity::Medium)
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

fn home() -> PathBuf {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(var)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn tilde(path: &Path) -> String {
    match path.strip_prefix(home()) {
        Ok(rest) => format!("~{}{}", std::path::MAIN_SEPARATOR, rest.display()),
        Err(_) => path.display().to_string(),
    }
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
        .map(PathBuf::from)
        .unwrap_or(default)
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
            ("OpenAI API key", r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}"),
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

/// The words of an identifier: `CONDUCTOR_JWT_SecretKey` -> conductor, jwt, secret, key.
fn words(name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut word = String::new();
    let mut prev_lower = false;
    for c in name.chars() {
        if !c.is_ascii_alphanumeric() {
            if !word.is_empty() {
                out.push(std::mem::take(&mut word));
            }
            prev_lower = false;
            continue;
        }
        if c.is_ascii_uppercase() && prev_lower && !word.is_empty() {
            out.push(std::mem::take(&mut word));
        }
        prev_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
        word.push(c.to_ascii_lowercase());
    }
    if !word.is_empty() {
        out.push(word);
    }
    out
}

/// A name that says it holds a secret, by whole words: `DB_PASSWORD`,
/// `ClientSecret`, `API_KEY`, but not `Authority` or `TOKENIZER_PATH`.
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
    let w = words(name);
    w.iter().any(|x| WORDS.contains(&x.as_str()))
        || w.windows(2)
            .any(|p| PAIRS.contains(&(p[0].as_str(), p[1].as_str())))
}

/// A real-looking secret rather than an empty value, a placeholder or a reference
/// to a secret manager (`op://…`, `${VAR}`).
fn literal(value: &str) -> bool {
    let v = value.trim().trim_matches(|c| c == '"' || c == '\'');
    let lower = v.to_ascii_lowercase();
    v.len() >= 8
        && !v.starts_with('$')
        && !v.starts_with('`')
        && !v.starts_with('<')
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

fn token_kinds(text: &str) -> Vec<&'static str> {
    token_patterns()
        .iter()
        .filter(|(_, re)| re.is_match(text))
        .map(|(name, _)| *name)
        .collect()
}

/// Is this `name = value` pair a secret? By the shape of the value, or a
/// secret-sounding name with a literal value.
fn is_secret(name: &str, value: &str) -> bool {
    !token_kinds(value).is_empty() || (secret_name(name) && literal(value))
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
        if line.starts_with('[') && line.ends_with(']') {
            sections.push((line[1..line.len() - 1].trim().to_string(), Vec::new()));
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
        out.passing
            .push("AWS: no ~/.aws/credentials file".to_string());
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
            Finding::new("aws-temporary", Severity::Low, "secret", "Temporary AWS credentials stored in ~/.aws/credentials")
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
fn aws_sign_in(home: &Path, out: &mut Out) {
    let now = Utc::now();
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
    let roles = json_files(&home.join(".aws").join("cli").join("cache"))
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
        let mut section = String::new();
        let mut registries = BTreeSet::new();
        for line in src.lines().map(str::trim) {
            if line.starts_with('[') && line.ends_with(']') {
                section = line[1..line.len() - 1].trim().to_string();
            } else if let Some((k, v)) = line.split_once('=')
                && k.trim() == "token"
                && literal(v)
            {
                registries.insert(match section.strip_prefix("registries.") {
                    Some(r) => r.to_string(),
                    None => "crates.io".to_string(),
                });
            }
        }
        if registries.is_empty() {
            continue;
        }
        out.findings.push(
            Finding::new(
                format!("cargo-token|{name}|{}", list(&registries, 20)),
                Severity::High,
                "secret",
                format!("Cargo registry token stored in plain text in ~/.cargo/{name}"),
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
    let Some(src) = read(&path) else { return };
    let registries: BTreeSet<String> = src
        .lines()
        .filter_map(|l| l.split_once('='))
        .filter(|(k, v)| {
            let k = k.trim();
            (k.ends_with("_authToken") || k.ends_with("_auth") || k.ends_with("_password"))
                && literal(v)
        })
        .map(|(k, _)| {
            k.trim()
                .rsplit_once(':')
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
        Finding::new(format!("npm-token|{}", list(&registries, 20)), Severity::High, "secret", "npm token stored in ~/.npmrc")
            .detail(format!(
                "Registries: {}. With a publish token, malware can push poisoned versions of your packages, which is how \
                 the Shai-Hulud worm spread.",
                list(&registries, 5)
            ))
            .remedy("Log in only when publishing (`npm login`, then `npm logout`), use granular tokens limited to the packages you publish, and require 2FA for publishing.")
            .at(at(&path)),
    );
}

/// (file, finding key, title, remedy, "does its content hold a credential?")
type TokenFile<'a> = (PathBuf, &'a str, &'a str, &'a str, &'a dyn Fn(&str) -> bool);

/// Files whose mere content means a plaintext credential.
fn simple_token_files(home: &Path, out: &mut Out) {
    let gh = env_path("GH_CONFIG_DIR", home.join(".config").join("gh")).join("hosts.yml");
    let checks: [TokenFile; 6] = [
        (
            gh.clone(),
            "gh-token",
            "GitHub CLI token stored in plain text",
            "`gh auth logout` and `gh auth login` again: gh keeps the token in the system keychain unless told not to.",
            &|s: &str| {
                s.lines().any(|l| {
                    l.trim_start().starts_with("oauth_token:")
                        && literal(l.split_once(':').map_or("", |x| x.1))
                })
            },
        ),
        (
            home.join(".git-credentials"),
            "git-credentials",
            "Git passwords stored in ~/.git-credentials",
            "Use the platform credential helper (`git config --global credential.helper osxkeychain` / `manager`) and delete the file.",
            &|s: &str| s.lines().any(|l| l.contains("://") && l.contains('@')),
        ),
        (
            home.join(".config").join("git").join("credentials"),
            "git-credentials-xdg",
            "Git passwords stored in ~/.config/git/credentials",
            "Use the platform credential helper and delete the file.",
            &|s: &str| s.lines().any(|l| l.contains("://") && l.contains('@')),
        ),
        (
            home.join(if cfg!(windows) { "_netrc" } else { ".netrc" }),
            "netrc",
            "Passwords stored in ~/.netrc",
            "Remove the password entries; use a credential helper or the tool's own login.",
            &|s: &str| s.split_whitespace().any(|w| w == "password"),
        ),
        (
            home.join(".pypirc"),
            "pypirc",
            "PyPI password or token stored in ~/.pypirc",
            "Use trusted publishing from CI, or keyring, instead of a stored token.",
            &|s: &str| {
                ini_sections(s)
                    .iter()
                    .flat_map(|(_, kv)| kv)
                    .any(|(k, v)| k == "password" && literal(v))
            },
        ),
        (
            home.join(".terraform.d").join("credentials.tfrc.json"),
            "terraform-token",
            "Terraform Cloud token stored in plain text",
            "Use a credentials helper, or `terraform logout` when not needed.",
            &|s: &str| s.contains("\"token\""),
        ),
    ];
    for (path, key, title, remedy, hit) in checks {
        if let Some(src) = read(&path)
            && hit(&src)
        {
            out.findings.push(
                Finding::new(key, Severity::High, "secret", title)
                    .remedy(remedy)
                    .at(at(&path)),
            );
        }
    }
    if read(&gh).is_some_and(|s| !s.contains("oauth_token:")) {
        out.passing
            .push("GitHub CLI: token kept in the system keychain".to_string());
    }
}

fn docker(home: &Path, out: &mut Out) {
    let path = env_path("DOCKER_CONFIG", home.join(".docker")).join("config.json");
    let Some(doc) = read(&path).and_then(|s| serde_json::from_str::<Value>(&s).ok()) else {
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

fn kube(home: &Path, out: &mut Out) {
    let path = std::env::var_os("KUBECONFIG")
        .and_then(|v| std::env::split_paths(&v).next())
        .unwrap_or_else(|| home.join(".kube").join("config"));
    let Some(src) = read(&path) else { return };
    let kinds: BTreeSet<&str> = src
        .lines()
        .map(str::trim_start)
        .filter_map(|l| {
            ["token:", "client-key-data:", "password:"]
                .into_iter()
                .find(|k| l.starts_with(k) && literal(&l[k.len()..]))
        })
        .collect();
    if kinds.is_empty() {
        out.passing
            .push("Kubernetes: no static credentials in kubeconfig".to_string());
        return;
    }
    out.findings.push(
        Finding::new("kube-static", Severity::High, "secret", "Static Kubernetes credentials in kubeconfig")
            .detail(format!(
                "{} stores {} directly.",
                tilde(&path),
                kinds.iter().map(|k| k.trim_end_matches(':')).collect::<Vec<_>>().join(", ")
            ))
            .remedy("Use an `exec` credential plugin (aws eks get-token, gke-gcloud-auth-plugin, kubelogin) that issues short-lived tokens.")
            .at(at(&path)),
    );
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
    if bare.is_empty() {
        out.passing.push(format!(
            "SSH: {protected} private keys, all passphrase-protected"
        ));
    }
}

fn gcloud(home: &Path, out: &mut Out) {
    let dir = env_path("CLOUDSDK_CONFIG", home.join(".config").join("gcloud"));
    let adc = dir.join("application_default_credentials.json");
    if let Some(doc) = read(&adc).and_then(|s| serde_json::from_str::<Value>(&s).ok()) {
        let (severity, what) = match doc.get("type").and_then(Value::as_str) {
            Some("service_account") => (Severity::Critical, "a service-account private key"),
            _ => (Severity::High, "a refresh token for your Google account"),
        };
        out.findings.push(
            Finding::new("gcloud-adc", severity, "secret", "Google Cloud application-default credentials on disk")
                .detail(format!("{} holds {what}.", tilde(&adc)))
                .remedy("Prefer service-account impersonation and `gcloud auth application-default revoke` when not needed; never keep service-account keys on a laptop.")
                .at(at(&adc)),
        );
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

fn shell_startup(home: &Path, out: &mut Out) {
    let assignment = Regex::new(
        r"^\s*(?:export\s+|set\s+-[a-zA-Z]*x[a-zA-Z]*\s+)?([A-Za-z_][A-Za-z0-9_]*)(?:=|\s+)(.+)$",
    )
    .expect("valid pattern");
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
            .filter_map(|l| assignment.captures(l))
            .filter(|c| c[1] != *"PWD" && c[1] != *"OLDPWD" && is_secret(&c[1], &c[2]))
            .map(|c| c[1].to_string())
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

fn interesting(name: &str) -> bool {
    env_file(name)
        || (name.starts_with("appsettings") && name.ends_with(".json"))
        || name == "secrets.json"
        || name.ends_with(".tfstate")
        || name.ends_with(".pem")
        || name.ends_with(".key")
        || name.ends_with(".p12")
        || name.ends_with(".pfx")
        || (name.ends_with(".json")
            && (name.contains("credential")
                || name.contains("service-account")
                || name.contains("serviceaccount")))
}

/// Names of the secrets a file holds, or a description for whole-file secrets.
fn file_secrets(name: &str, src: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    if env_file(name) {
        for line in src.lines().map(str::trim).filter(|l| !l.starts_with('#')) {
            let line = line.strip_prefix("export ").unwrap_or(line);
            if let Some((k, v)) = line.split_once('=')
                && is_secret(k.trim(), v)
            {
                found.insert(k.trim().to_string());
            }
        }
    } else if name.ends_with(".json") {
        if let Ok(doc) = serde_json::from_str::<Value>(src) {
            json_secrets(&doc, "", &mut found);
        }
    } else if name.ends_with(".tfstate") {
        if src.contains("\"sensitive_attributes\"")
            || src.contains("\"password\"")
            || src.contains("\"secret")
        {
            found.insert("Terraform state (holds resource secrets in plain text)".to_string());
        }
    } else if name.ends_with(".p12") || name.ends_with(".pfx") {
        found.insert("certificate bundle with a private key".to_string());
    } else if src.contains("PRIVATE KEY-----") {
        found.insert("private key".to_string());
    }
    found
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
            let connection = s.to_ascii_lowercase().contains("password=")
                && !s.to_ascii_lowercase().contains("password=;");
            if is_secret(leaf, s) || connection {
                found.insert(path.to_string());
            }
        }
        _ => {}
    }
}

/// Several sibling folders each holding one key file (`vpn-users/<person>/<person>.key`)
/// read better as one finding about their parent folder.
fn collapse_siblings(
    groups: BTreeMap<(String, BTreeSet<String>), Vec<PathBuf>>,
) -> BTreeMap<(String, BTreeSet<String>), Vec<PathBuf>> {
    const MIN_SIBLINGS: usize = 3;
    let whole_file = |names: &BTreeSet<String>| names.iter().any(|n| n.contains(' '));
    let grandparent = |p: &Path| p.parent().and_then(Path::parent).map(Path::to_path_buf);
    let mut by_parent: BTreeMap<(PathBuf, BTreeSet<String>), usize> = BTreeMap::new();
    for ((_, names), copies) in &groups {
        if whole_file(names)
            && copies.len() == 1
            && let Some(gp) = grandparent(&copies[0])
        {
            *by_parent.entry((gp, names.clone())).or_default() += 1;
        }
    }
    let mut out: BTreeMap<(String, BTreeSet<String>), Vec<PathBuf>> = BTreeMap::new();
    for ((rel, names), copies) in groups {
        let collapse = whole_file(&names) && copies.len() == 1;
        let target = collapse
            .then(|| grandparent(&copies[0]))
            .flatten()
            .filter(|gp| {
                by_parent
                    .get(&(gp.clone(), names.clone()))
                    .is_some_and(|n| *n >= MIN_SIBLINGS)
            });
        match target {
            Some(gp) => out
                .entry((format!("{}/*", tilde(&gp)), names))
                .or_default()
                .extend(copies),
            None => out.entry((rel, names)).or_default().extend(copies),
        }
    }
    out
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
    // (path within its repository, secret names) -> every copy.
    let mut groups: BTreeMap<(String, BTreeSet<String>), Vec<PathBuf>> = BTreeMap::new();
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
            // Secrets are small files; anything big is not one of these.
            if entry
                .metadata()
                .map(|m| m.len() > 4 * 1024 * 1024)
                .unwrap_or(true)
            {
                continue;
            }
            scanned += 1;
            let Some(src) = read(entry.path()) else {
                continue;
            };
            let secrets = file_secrets(&name, &src);
            if secrets.is_empty() {
                continue;
            }
            let path = entry.path().to_path_buf();
            let rel = path
                .parent()
                .and_then(|d| repo_root(d, &mut repos))
                .and_then(|r| path.strip_prefix(r).ok().map(|p| p.display().to_string()))
                .unwrap_or_else(|| tilde(&path));
            groups.entry((rel, secrets)).or_default().push(path);
        }
    }
    for ((rel, names), copies) in collapse_siblings(groups) {
        let production = rel.to_ascii_lowercase().contains("prod");
        let whole_file = names.iter().any(|n| n.contains(' '));
        let severity = if production || whole_file {
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
        let title = if whole_file {
            format!("{shown}: {}{copies_text}", list(&names, 3))
        } else {
            format!(
                "{shown} holds {} {}{copies_text}",
                names.len(),
                if names.len() == 1 {
                    "secret"
                } else {
                    "secrets"
                }
            )
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
            format!("file|{rel}|{}", list(&names, 100)),
            severity,
            "secret",
            title,
        )
        .detail(if whole_file {
            list(&names, 5)
        } else {
            format!("Names: {}", list(&names, 12))
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
    }

    #[test]
    fn env_and_settings_files_report_names_only() {
        let env = "# comment\nexport AWS_SECRET_ACCESS_KEY=abcd1234efgh5678\nPORT=8080\nDATABASE_URL=postgres://u:pa55word99@h/db\nEMPTY_TOKEN=\n";
        let names = file_secrets(".env.production", env);
        assert_eq!(
            names.into_iter().collect::<Vec<_>>(),
            vec!["AWS_SECRET_ACCESS_KEY", "DATABASE_URL"]
        );
        let settings = r#"{"ConnectionStrings":{"Main":"Host=db;Username=app;Password=s3cretpass"},"Logging":{"Level":"Info"},"Jwt":{"Secret":"abcdefghijklmnopqrstuvwxyz"}}"#;
        let names = file_secrets("appsettings.Production.json", settings);
        assert_eq!(
            names.into_iter().collect::<Vec<_>>(),
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
        for wt in ["main", "wt-a", "wt-b"] {
            let dir = base.join(wt);
            std::fs::create_dir_all(dir.join(".git")).unwrap();
            std::fs::write(
                dir.join(".env.production"),
                "DB_PASSWORD=correcthorsebattery\n",
            )
            .unwrap();
        }
        let roots: Vec<PathBuf> = ["main", "wt-a", "wt-b"]
            .iter()
            .map(|w| base.join(w))
            .collect();
        let mut out = Out::default();
        project_files(&roots, &Exclude::default(), 4, &mut out);
        assert_eq!(
            out.findings.len(),
            1,
            "{:?}",
            out.findings.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
        let f = &out.findings[0];
        assert_eq!(
            (f.title.as_str(), f.severity, f.locations.len()),
            (
                ".env.production holds 1 secret (3 copies)",
                Severity::High,
                3
            )
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
