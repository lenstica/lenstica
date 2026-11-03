//! The accounts this machine can act as: git's author, SSH keys, and the
//! signed-in accounts of cloud, registry and AI tools. Only names are read:
//! a token, password or private key is never kept, only whether one is
//! stored in a file (where anything that can read the file can take it).

use std::path::{Path, PathBuf};

use serde_json::Value;

use super::{Asset, Ctx, Found, file_name, ini_sections, ini_value, without_credentials};
use crate::paths::{self, home};

pub(super) fn discover(ctx: &Ctx, found: &mut Found) {
    let h = home();
    git(ctx, found);
    ssh(&h.join(".ssh"), found);
    let gh = std::env::var_os("GH_CONFIG_DIR").map_or_else(
        || {
            if cfg!(windows) {
                paths::appdata().join("GitHub CLI")
            } else {
                paths::config_root().join("gh")
            }
        },
        PathBuf::from,
    );
    read(&gh.join("hosts.yml"), found, github);
    aws(found);
    let gcloud = std::env::var_os("CLOUDSDK_CONFIG").map_or_else(
        || {
            if cfg!(windows) {
                paths::appdata().join("gcloud")
            } else {
                paths::config_root().join("gcloud")
            }
        },
        PathBuf::from,
    );
    google_cloud(&gcloud, found);
    read(&h.join(".azure/azureProfile.json"), found, azure);
    read(&h.join(".kube/config"), found, kubernetes);
    read(&h.join(".docker/config.json"), found, docker);
    read(&h.join(".npmrc"), found, npm);
    read(&h.join(".pypirc"), found, pypi);
    let cargo = std::env::var_os("CARGO_HOME").map_or_else(|| h.join(".cargo"), PathBuf::from);
    for name in ["credentials.toml", "credentials"] {
        read(&cargo.join(name), found, crates);
    }
    read(&h.join(".netrc"), found, netrc);
    let claude = std::env::var_os("CLAUDE_CONFIG_DIR").map_or_else(
        || h.join(".claude.json"),
        |d| PathBuf::from(d).join(".claude.json"),
    );
    read(&claude, found, claude_code);
    read(&h.join(".codex/auth.json"), found, codex);
}

/// Parse a file that may not exist; its parser gets the text and the path.
fn read(path: &Path, found: &mut Found, parse: fn(&str, &Path) -> Vec<Asset>) {
    if let Ok(text) = std::fs::read_to_string(path) {
        for a in parse(&text, path) {
            found.add(a);
        }
    }
}

// ---- git and SSH -----------------------------------------------------------------

fn git(ctx: &Ctx, found: &mut Found) {
    let Some(git) = ctx.find("git") else { return };
    let Ok(out) = ctx.run(
        &git,
        &[
            "config",
            "--global",
            "--includes",
            "--get-regexp",
            r"^(user\.|commit\.gpgsign|gpg\.format)",
        ],
    ) else {
        return;
    };
    let path = home().join(".gitconfig");
    if let Some(a) = git_identity(&out.stdout, &path) {
        found.add(a);
    }
}

fn git_identity(listing: &str, path: &Path) -> Option<Asset> {
    let get = |key: &str| {
        listing
            .lines()
            .filter_map(|l| l.split_once(' '))
            .filter(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.trim().to_string())
            .next_back()
    };
    let name = get("user.name");
    let email = get("user.email");
    if name.is_none() && email.is_none() {
        return None;
    }
    let signs = get("commit.gpgsign").is_some_and(|v| v == "true");
    let signing = match (signs, get("gpg.format").as_deref()) {
        (false, _) => "off",
        (true, Some("ssh")) => "SSH key",
        (true, Some("x509")) => "X.509 certificate",
        (true, _) => "GPG key",
    };
    let shown = name.or_else(|| email.clone()).unwrap_or_default();
    Some(
        Asset::new("git", shown, "Git")
            .path(path)
            .fact_opt("email", email)
            .fact("signing", signing),
    )
}

/// Every key pair in `~/.ssh`: public keys, and private keys without one.
fn ssh(dir: &Path, found: &mut Found) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .collect();
    files.sort();
    for path in &files {
        let name = file_name(path);
        if let Some(stem) = name.strip_suffix(".pub") {
            let Ok(text) = std::fs::read_to_string(path) else {
                continue;
            };
            let private = dir.join(stem);
            let mut words = text.split_whitespace();
            let kind = words.next().unwrap_or_default();
            let _key = words.next();
            let comment: Vec<&str> = words.collect();
            found.add(
                Asset::new(format!("ssh:{stem}"), stem, "SSH")
                    .path(if private.is_file() {
                        private
                    } else {
                        path.clone()
                    })
                    .fact("keyType", key_type(kind))
                    .fact("comment", comment.join(" ")),
            );
        } else if !files.iter().any(|p| file_name(p) == format!("{name}.pub"))
            && is_private_key(path)
        {
            found.add(Asset::new(format!("ssh:{name}"), name.clone(), "SSH").path(path.clone()));
        }
    }
}

/// `ssh-ed25519` -> `Ed25519`; a security key (`sk-…`) says so.
fn key_type(kind: &str) -> String {
    let hardware = kind.starts_with("sk-");
    let base = match kind.trim_start_matches("sk-") {
        k if k.starts_with("ssh-ed25519") => "Ed25519",
        k if k.starts_with("ssh-rsa") => "RSA",
        k if k.starts_with("ecdsa-") => "ECDSA",
        k if k.starts_with("ssh-dss") => "DSA",
        other => other,
    };
    if hardware {
        format!("{base} (security key)")
    } else {
        base.to_string()
    }
}

/// Only the start of the file is read: `-----BEGIN … PRIVATE KEY-----`.
fn is_private_key(path: &Path) -> bool {
    use std::io::Read;
    let mut head = [0u8; 100];
    let Ok(n) = std::fs::File::open(path).and_then(|mut f| f.read(&mut head)) else {
        return false;
    };
    let first = String::from_utf8_lossy(&head[..n]);
    let first = first.lines().next().unwrap_or_default();
    first.starts_with("-----BEGIN") && first.contains("PRIVATE KEY")
}

// ---- GitHub CLI --------------------------------------------------------------------

/// `hosts.yml`: each host, its accounts (`users:`), the active one (`user:`),
/// and an `oauth_token:` when the token is in the file rather than the keychain.
fn github(text: &str, path: &Path) -> Vec<Asset> {
    struct Host {
        name: String,
        active: Option<String>,
        users: Vec<(String, bool)>,
        token_in_file: bool,
    }
    let mut hosts: Vec<Host> = Vec::new();
    let mut in_users = false;
    for raw in text.lines() {
        let line = raw.trim_end();
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        let content = line.trim();
        if indent == 0 {
            if let Some(name) = content.strip_suffix(':') {
                hosts.push(Host {
                    name: name.trim_matches(|c| c == '"' || c == '\'').to_string(),
                    active: None,
                    users: Vec::new(),
                    token_in_file: false,
                });
            }
            in_users = false;
            continue;
        }
        let Some(host) = hosts.last_mut() else {
            continue;
        };
        let (key, value) = content
            .split_once(':')
            .map_or((content, ""), |(k, v)| (k.trim(), v.trim()));
        if in_users && indent > 4 {
            if indent <= 8 && value.is_empty() {
                host.users.push((key.to_string(), false));
            } else if key == "oauth_token"
                && !value.is_empty()
                && let Some(u) = host.users.last_mut()
            {
                u.1 = true;
            }
            continue;
        }
        in_users = key == "users" && value.is_empty();
        match key {
            "user" if !value.is_empty() => host.active = Some(value.to_string()),
            "oauth_token" if !value.is_empty() => host.token_in_file = true,
            _ => {}
        }
    }
    let mut out = Vec::new();
    for host in hosts {
        let mut users = host.users.clone();
        if let Some(active) = &host.active
            && !users.iter().any(|(u, _)| u == active)
        {
            users.push((active.clone(), false));
        }
        for (user, own_token) in users {
            let current = host.active.as_deref() == Some(user.as_str());
            out.push(
                Asset::new(
                    format!("gh:{}:{user}", host.name),
                    user.clone(),
                    "GitHub CLI",
                )
                .path(path)
                .fact("host", &host.name)
                .tag_if(current, "current")
                .tag_if(
                    own_token || (current && host.token_in_file),
                    "credentialsInFile",
                ),
            );
        }
    }
    out
}

// ---- cloud providers ---------------------------------------------------------------

fn aws(found: &mut Found) {
    let config = std::env::var_os("AWS_CONFIG_FILE")
        .map_or_else(|| home().join(".aws/config"), PathBuf::from);
    let credentials = std::env::var_os("AWS_SHARED_CREDENTIALS_FILE")
        .map_or_else(|| home().join(".aws/credentials"), PathBuf::from);
    let config_text = std::fs::read_to_string(&config).unwrap_or_default();
    let credentials_text = std::fs::read_to_string(&credentials).unwrap_or_default();
    for a in aws_profiles(&config_text, &config, &credentials_text, &credentials) {
        found.add(a);
    }
}

/// One asset per profile in either file. Keys are noticed, never kept.
fn aws_profiles(
    config: &str,
    config_path: &Path,
    credentials: &str,
    credentials_path: &Path,
) -> Vec<Asset> {
    struct Profile {
        name: String,
        settings: Vec<(String, String)>,
        key_in_credentials: bool,
        in_config: bool,
    }
    let mut profiles: Vec<Profile> = Vec::new();
    for (section, settings) in ini_sections(config) {
        let name = match section.strip_prefix("profile ") {
            Some(n) => n.trim().to_string(),
            None if section == "default" => section,
            None => continue, // `sso-session …`, `services …`
        };
        profiles.push(Profile {
            name,
            settings,
            key_in_credentials: false,
            in_config: true,
        });
    }
    for (section, pairs) in ini_sections(credentials) {
        if section.is_empty() {
            continue;
        }
        let has_key = ini_value(&pairs, "aws_access_key_id").is_some()
            || ini_value(&pairs, "aws_secret_access_key").is_some();
        match profiles.iter_mut().find(|p| p.name == section) {
            Some(p) => {
                p.settings.extend(pairs);
                p.key_in_credentials |= has_key;
            }
            None => profiles.push(Profile {
                name: section,
                settings: pairs,
                key_in_credentials: has_key,
                in_config: false,
            }),
        }
    }
    profiles
        .into_iter()
        .map(|p| {
            let Profile {
                name,
                settings,
                key_in_credentials,
                in_config,
            } = p;
            let get = |k: &str| ini_value(&settings, k).map(str::to_string);
            let role = get("role_arn");
            let account = get("sso_account_id").or_else(|| {
                role.as_deref()
                    .and_then(|arn| arn.split(':').nth(4))
                    .map(str::to_string)
            });
            // A key in either file (settings hold both files' lines).
            let key_in_file = key_in_credentials || get("aws_access_key_id").is_some();
            let sign_in = if get("sso_session").is_some() || get("sso_start_url").is_some() {
                "SSO"
            } else if role.is_some() {
                "Assumed role"
            } else if get("credential_process").is_some() {
                "Command"
            } else if key_in_file {
                "Access key"
            } else {
                ""
            };
            let path = if key_in_credentials || !in_config {
                credentials_path
            } else {
                config_path
            };
            Asset::new(format!("aws:{name}"), name.clone(), "AWS")
                .path(path)
                .fact_opt("account", account)
                .fact("signIn", sign_in)
                .fact_opt(
                    "role",
                    get("sso_role_name")
                        .or_else(|| role.and_then(|r| r.rsplit('/').next().map(str::to_string))),
                )
                .fact_opt("region", get("region"))
                .tag_if(key_in_file, "credentialsInFile")
        })
        .collect()
}

fn google_cloud(dir: &Path, found: &mut Found) {
    let active = std::fs::read_to_string(dir.join("active_config"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "default".to_string());
    let configs = dir.join("configurations");
    if let Ok(entries) = std::fs::read_dir(&configs) {
        let mut files: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
        files.sort();
        for path in files {
            let Some(name) = file_name(&path).strip_prefix("config_").map(str::to_string) else {
                continue;
            };
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            if let Some(a) = gcloud_configuration(&name, &text, name == active, &path) {
                found.add(a);
            }
        }
    }
    let adc = dir.join("application_default_credentials.json");
    if let Some(doc) = crate::files::read_json::<Value>(&adc) {
        let kind = doc.get("type").and_then(Value::as_str).unwrap_or_default();
        let who = doc
            .get("client_email")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| "Application Default Credentials".to_string());
        found.add(
            Asset::new("gcloud:adc", who, "Google Cloud")
                .path(&adc)
                .fact(
                    "signIn",
                    match kind {
                        "service_account" => "Service account key",
                        "authorized_user" => "Application Default Credentials",
                        "external_account" => "Workload identity",
                        other => other,
                    },
                )
                .tag_if(
                    kind == "service_account" || kind == "authorized_user",
                    "credentialsInFile",
                ),
        );
    }
}

fn gcloud_configuration(name: &str, text: &str, active: bool, path: &Path) -> Option<Asset> {
    let sections = ini_sections(text);
    let get = |section: &str, key: &str| {
        sections
            .iter()
            .filter(|(s, _)| s == section)
            .find_map(|(_, p)| ini_value(p, key).map(str::to_string))
    };
    let account = get("core", "account")?;
    Some(
        Asset::new(format!("gcloud:{name}"), account, "Google Cloud")
            .path(path)
            .fact("profile", name)
            .fact_opt("project", get("core", "project"))
            .fact_opt("region", get("compute", "region"))
            .tag_if(active, "current"),
    )
}

/// `azureProfile.json`: subscriptions, each with the user signed in to it.
fn azure(text: &str, path: &Path) -> Vec<Asset> {
    let Ok(doc) = serde_json::from_str::<Value>(text.trim_start_matches('\u{feff}')) else {
        return Vec::new();
    };
    let subs = doc
        .get("subscriptions")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut users: Vec<(String, Vec<String>, bool)> = Vec::new();
    for s in &subs {
        let user = s
            .pointer("/user/name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let name = s
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let default = s.get("isDefault").and_then(Value::as_bool).unwrap_or(false);
        match users.iter_mut().find(|(u, _, _)| *u == user) {
            Some(u) => {
                u.1.push(name);
                u.2 |= default;
            }
            None => users.push((user, vec![name], default)),
        }
    }
    users
        .into_iter()
        .filter(|(u, _, _)| !u.is_empty())
        .map(|(user, subs, default)| {
            Asset::new(format!("azure:{user}"), user, "Azure")
                .path(path)
                .fact("subscriptions", subs.join(", "))
                .tag_if(default, "current")
        })
        .collect()
}

/// `~/.kube/config`: one asset per context, noting a user whose token, key
/// or password is written into the file.
fn kubernetes(text: &str, path: &Path) -> Vec<Asset> {
    let current = crate::files::yaml_get_top(text, "current-context");
    let contexts = yaml_list(text, "contexts");
    let users = yaml_list(text, "users");
    let embedded = |user: &str| {
        users.iter().any(|u| {
            u.iter().any(|(k, v)| k == "name" && v == user)
                && u.iter()
                    .any(|(k, _)| ["token", "client-key-data", "password"].contains(&k.as_str()))
        })
    };
    contexts
        .iter()
        .filter_map(|c| {
            let get = |key: &str| c.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone());
            let name = get("name")?;
            let user = get("user");
            Some(
                Asset::new(format!("kube:{name}"), name.clone(), "Kubernetes")
                    .path(path)
                    .fact_opt("cluster", get("cluster"))
                    .fact_opt("user", user.clone())
                    .fact_opt("namespace", get("namespace"))
                    .tag_if(current.as_deref() == Some(name.as_str()), "current")
                    .tag_if(user.as_deref().is_some_and(embedded), "credentialsInFile"),
            )
        })
        .collect()
}

/// The items of a top-level YAML list of mappings (`contexts:`), each as its
/// `key: value` scalars at any depth. Enough for kubeconfig, which tools write
/// in one shape.
fn yaml_list(text: &str, key: &str) -> Vec<Vec<(String, String)>> {
    let mut out: Vec<Vec<(String, String)>> = Vec::new();
    let mut inside = false;
    for raw in text.lines() {
        if raw.trim().is_empty() || raw.trim_start().starts_with('#') {
            continue;
        }
        let indent = raw.len() - raw.trim_start().len();
        if indent == 0 && !raw.starts_with('-') {
            inside = raw.trim_end() == format!("{key}:");
            continue;
        }
        if !inside {
            continue;
        }
        let mut content = raw.trim();
        if let Some(rest) = content
            .strip_prefix("- ")
            .or_else(|| (content == "-").then_some(""))
        {
            if indent <= 2 {
                out.push(Vec::new());
            }
            content = rest.trim();
        }
        if let (Some(item), Some((k, v))) = (out.last_mut(), content.split_once(':')) {
            let v = v.trim().trim_matches(|c| c == '"' || c == '\'');
            if !v.is_empty() {
                item.push((k.trim().to_string(), v.to_string()));
            }
        }
    }
    out
}

// ---- registries ----------------------------------------------------------------------

/// `~/.docker/config.json`: the registries signed in to, and where each keeps
/// its credentials (a helper such as the keychain, or the file itself).
fn docker(text: &str, path: &Path) -> Vec<Asset> {
    let Ok(doc) = serde_json::from_str::<Value>(text) else {
        return Vec::new();
    };
    let store = doc
        .get("credsStore")
        .and_then(Value::as_str)
        .map(str::to_string);
    let helpers = doc.get("credHelpers").and_then(Value::as_object);
    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let auths = doc.get("auths").and_then(Value::as_object);
    let names = auths
        .into_iter()
        .flat_map(|a| a.keys().cloned())
        .chain(helpers.into_iter().flat_map(|h| h.keys().cloned()));
    for registry in names {
        let host = registry_host(&registry);
        if !seen.insert(host.clone()) {
            continue;
        }
        let in_file = auths
            .and_then(|a| a.get(&registry))
            .and_then(|e| e.get("auth").or_else(|| e.get("identitytoken")))
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty());
        let helper = helpers
            .and_then(|h| h.get(&registry))
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| store.clone());
        out.push(
            Asset::new(format!("docker:{host}"), docker_name(&host), "Docker")
                .path(path)
                .fact("host", &host)
                .fact(
                    "keptIn",
                    if in_file {
                        "this file".to_string()
                    } else {
                        helper.unwrap_or_default()
                    },
                )
                .tag_if(in_file, "credentialsInFile"),
        );
    }
    out
}

fn registry_host(registry: &str) -> String {
    let r = registry
        .split_once("://")
        .map_or(registry, |(_, rest)| rest);
    r.split('/').next().unwrap_or(r).to_string()
}

fn docker_name(host: &str) -> String {
    match host {
        "index.docker.io" | "registry-1.docker.io" | "docker.io" => "Docker Hub".to_string(),
        other => other.to_string(),
    }
}

/// `~/.npmrc`: registries with a token, password or user. A value read from an
/// environment variable (`${NPM_TOKEN}`) is not in the file.
fn npm(text: &str, path: &Path) -> Vec<Asset> {
    let mut out: Vec<Asset> = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        let Some(rest) = line.strip_prefix("//") else {
            continue;
        };
        let Some((left, value)) = rest.split_once('=') else {
            continue;
        };
        let Some((host, key)) = left.rsplit_once(":") else {
            continue;
        };
        if !["_authToken", "_auth", "_password", "username"].contains(&key.trim()) {
            continue;
        }
        let host = host.trim_end_matches('/').to_string();
        let in_file = key.trim() != "username" && !value.trim().starts_with("${");
        let id = format!("npm:{host}");
        if let Some(a) = out.iter_mut().find(|a| a.id == id) {
            *a = a.clone().tag_if(in_file, "credentialsInFile");
            continue;
        }
        let name = host.split('/').next().unwrap_or(&host).to_string();
        out.push(
            Asset::new(id, name, "npm")
                .path(path)
                .fact("host", &host)
                .tag_if(in_file, "credentialsInFile"),
        );
    }
    out
}

/// `~/.pypirc`: each index with a user or password.
fn pypi(text: &str, path: &Path) -> Vec<Asset> {
    ini_sections(text)
        .into_iter()
        .filter(|(s, _)| !s.is_empty() && s != "distutils")
        .filter_map(|(section, pairs)| {
            let user = ini_value(&pairs, "username").map(str::to_string);
            let password = ini_value(&pairs, "password").is_some();
            (user.is_some() || password).then(|| {
                let shown = match user.as_deref() {
                    Some("__token__") => "API token".to_string(),
                    Some(u) => u.to_string(),
                    None => String::new(),
                };
                Asset::new(format!("pypi:{section}"), section.clone(), "PyPI")
                    .path(path)
                    .fact("user", shown)
                    .fact_opt(
                        "host",
                        ini_value(&pairs, "repository").map(without_credentials),
                    )
                    .tag_if(password, "credentialsInFile")
            })
        })
        .collect()
}

/// `~/.cargo/credentials.toml`: crates.io and other registries with a token.
fn crates(text: &str, path: &Path) -> Vec<Asset> {
    let Ok(doc) = text.parse::<toml::Table>() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if doc.get("registry").and_then(|r| r.get("token")).is_some() {
        out.push(
            Asset::new("cargo:crates.io", "crates.io", "Cargo")
                .path(path)
                .tag_if(true, "credentialsInFile"),
        );
    }
    if let Some(regs) = doc.get("registries").and_then(toml::Value::as_table) {
        for (name, r) in regs {
            if r.get("token").is_some() {
                out.push(
                    Asset::new(format!("cargo:{name}"), name.clone(), "Cargo")
                        .path(path)
                        .tag_if(true, "credentialsInFile"),
                );
            }
        }
    }
    out
}

/// `~/.netrc`: `machine host login user password …` entries.
fn netrc(text: &str, path: &Path) -> Vec<Asset> {
    let words: Vec<&str> = text
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .flat_map(str::split_whitespace)
        .collect();
    let mut out: Vec<Asset> = Vec::new();
    let mut i = 0;
    while i < words.len() {
        match words[i] {
            "machine" | "default" => {
                let host = if words[i] == "machine" {
                    i += 1;
                    words.get(i).copied().unwrap_or_default().to_string()
                } else {
                    "default".to_string()
                };
                out.push(
                    Asset::new(format!("netrc:{host}"), host.clone(), "netrc")
                        .path(path)
                        .fact("host", &host),
                );
            }
            "login" => {
                i += 1;
                if let (Some(a), Some(user)) = (out.pop(), words.get(i)) {
                    out.push(a.fact("user", *user));
                }
            }
            "password" | "account" => {
                i += 1;
                if let Some(a) = out.pop() {
                    out.push(a.tag_if(true, "credentialsInFile"));
                }
            }
            _ => {}
        }
        i += 1;
    }
    out
}

// ---- AI tools ---------------------------------------------------------------------

/// `~/.claude.json`: the account Claude Code is signed in with.
fn claude_code(text: &str, path: &Path) -> Vec<Asset> {
    let Ok(doc) = serde_json::from_str::<Value>(text) else {
        return Vec::new();
    };
    let Some(account) = doc.get("oauthAccount") else {
        return Vec::new();
    };
    let email = account
        .get("emailAddress")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if email.is_empty() {
        return Vec::new();
    }
    vec![
        Asset::new("claude:account", email, "Claude Code")
            .path(path)
            .fact_opt(
                "organization",
                account.get("organizationName").and_then(Value::as_str),
            ),
    ]
}

/// `~/.codex/auth.json`: signed in with a ChatGPT account, or an API key in the file.
fn codex(text: &str, path: &Path) -> Vec<Asset> {
    let Ok(doc) = serde_json::from_str::<Value>(text) else {
        return Vec::new();
    };
    let key = doc
        .get("OPENAI_API_KEY")
        .and_then(Value::as_str)
        .is_some_and(|k| !k.is_empty());
    let tokens = doc.get("tokens").is_some_and(|t| !t.is_null());
    if !key && !tokens {
        return Vec::new();
    }
    vec![
        Asset::new(
            "codex:account",
            if tokens {
                "ChatGPT account"
            } else {
                "OpenAI API key"
            },
            "Codex",
        )
        .path(path)
        .fact("signIn", if tokens { "ChatGPT" } else { "API key" })
        .tag_if(true, "credentialsInFile"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p() -> PathBuf {
        PathBuf::from("/x")
    }

    fn facts(a: &Asset) -> Vec<(String, String)> {
        a.facts
            .iter()
            .map(|f| (f.key.to_string(), f.value.clone()))
            .collect()
    }

    fn tags(a: &Asset) -> Vec<&str> {
        a.tags.iter().map(|t| t.key).collect()
    }

    #[test]
    fn git_author_and_signing() {
        let a = git_identity(
            "user.name Ada\nuser.email ada@example.com\ncommit.gpgsign true\ngpg.format ssh\n",
            &p(),
        )
        .unwrap();
        assert_eq!(a.name, "Ada");
        assert_eq!(a.get("email"), Some("ada@example.com"));
        assert_eq!(a.get("signing"), Some("SSH key"));
        assert!(git_identity("", &p()).is_none());
    }

    #[test]
    fn github_accounts_and_tokens_in_the_file() {
        let text = "github.com:\n    users:\n        ada:\n            oauth_token: gho_secret\n        bob:\n    git_protocol: https\n    user: bob\nghe.example.com:\n    user: carol\n    oauth_token: x\n";
        let list = github(text, &p());
        let names: Vec<&str> = list.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["ada", "bob", "carol"]);
        assert_eq!(tags(&list[0]), ["credentialsInFile"]);
        assert_eq!(tags(&list[1]), ["current"]);
        assert_eq!(tags(&list[2]), ["current", "credentialsInFile"]);
        for a in &list {
            assert!(!format!("{a:?}").contains("gho_secret"));
        }
    }

    #[test]
    fn aws_profiles_from_both_files_without_keys() {
        let config = "[default]\nregion = us-east-1\n[profile prod]\nsso_session = corp\nsso_account_id = 123456789012\nsso_role_name = Admin\n[sso-session corp]\nsso_region = us-east-1\n[profile ci]\nrole_arn = arn:aws:iam::210987654321:role/deploy\nsource_profile = default\n";
        let credentials = "[default]\naws_access_key_id = AKIAEXAMPLE\naws_secret_access_key = SECRETEXAMPLE\n[legacy]\naws_access_key_id = AKIA2\naws_secret_access_key = S2\n";
        let list = aws_profiles(config, Path::new("/c"), credentials, Path::new("/k"));
        let names: Vec<&str> = list.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["default", "prod", "ci", "legacy"]);
        assert_eq!(list[0].get("signIn"), Some("Access key"));
        assert_eq!(tags(&list[0]), ["credentialsInFile"]);
        assert_eq!(list[0].path.as_deref(), Some(Path::new("/k")));
        assert_eq!(list[1].get("signIn"), Some("SSO"));
        assert_eq!(list[1].get("account"), Some("123456789012"));
        assert_eq!(list[1].get("role"), Some("Admin"));
        assert_eq!(list[2].get("account"), Some("210987654321"));
        assert_eq!(list[2].get("role"), Some("deploy"));
        assert_eq!(list[3].path.as_deref(), Some(Path::new("/k")));
        for a in &list {
            let all = format!("{a:?}");
            assert!(!all.contains("SECRET") && !all.contains("AKIA"));
        }
    }

    #[test]
    fn gcloud_configuration_needs_an_account() {
        let a = gcloud_configuration(
            "work",
            "[core]\naccount = ada@corp.com\nproject = p1\n[compute]\nregion = europe-west1\n",
            true,
            &p(),
        )
        .unwrap();
        assert_eq!(a.name, "ada@corp.com");
        assert_eq!(facts(&a)[1], ("project".into(), "p1".into()));
        assert_eq!(tags(&a), ["current"]);
        assert!(gcloud_configuration("x", "[core]\nproject = p\n", false, &p()).is_none());
    }

    #[test]
    fn azure_users_with_their_subscriptions() {
        let text = "\u{feff}{\"subscriptions\":[{\"name\":\"Dev\",\"isDefault\":true,\"user\":{\"name\":\"ada@corp.com\"}},{\"name\":\"Prod\",\"isDefault\":false,\"user\":{\"name\":\"ada@corp.com\"}}]}";
        let list = azure(text, &p());
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].get("subscriptions"), Some("Dev, Prod"));
        assert_eq!(tags(&list[0]), ["current"]);
    }

    #[test]
    fn kube_contexts_and_embedded_credentials() {
        let text = "apiVersion: v1\nclusters:\n- cluster:\n    server: https://x\n  name: kind-kind\ncontexts:\n- context:\n    cluster: kind-kind\n    user: kind-kind\n  name: kind-kind\n- context:\n    cluster: eks\n    namespace: web\n    user: eks-user\n  name: prod\ncurrent-context: prod\nkind: Config\nusers:\n- name: kind-kind\n  user:\n    client-certificate-data: AAA\n    client-key-data: BBB\n- name: eks-user\n  user:\n    exec:\n      command: aws\n";
        let list = kubernetes(text, &p());
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].name, "kind-kind");
        assert_eq!(tags(&list[0]), ["credentialsInFile"]);
        assert_eq!(list[1].get("namespace"), Some("web"));
        assert_eq!(tags(&list[1]), ["current"]);
    }

    #[test]
    fn docker_registries_and_where_their_keys_are() {
        let text = r#"{"auths":{"https://index.docker.io/v1/":{},"ghcr.io":{"auth":"dXNlcjpwYXNz"}},"credsStore":"desktop","credHelpers":{"gcr.io":"gcloud"}}"#;
        let list = docker(text, &p());
        let names: Vec<&str> = list.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["ghcr.io", "Docker Hub", "gcr.io"]);
        assert_eq!(list[0].get("keptIn"), Some("this file"));
        assert_eq!(tags(&list[0]), ["credentialsInFile"]);
        assert_eq!(list[1].get("keptIn"), Some("desktop"));
        assert_eq!(list[2].get("keptIn"), Some("gcloud"));
        assert!(!format!("{list:?}").contains("dXNlcjpwYXNz"));
    }

    #[test]
    fn npm_registries_with_tokens() {
        let text = "registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=npm_secret\n//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}\n";
        let list = npm(text, &p());
        assert_eq!(list.len(), 2);
        assert_eq!(tags(&list[0]), ["credentialsInFile"]);
        assert!(list[1].tags.is_empty());
        assert!(!format!("{list:?}").contains("npm_secret"));
    }

    #[test]
    fn pypi_cargo_and_netrc() {
        let pypirc = "[distutils]\nindex-servers = pypi\n[pypi]\nusername = __token__\npassword = pypi-secret\n";
        let list = pypi(pypirc, &p());
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].get("user"), Some("API token"));
        assert!(!format!("{list:?}").contains("pypi-secret"));

        let list = crates(
            "[registry]\ntoken = \"cio_secret\"\n[registries.corp]\ntoken = \"x\"\n",
            &p(),
        );
        assert_eq!(list.len(), 2);
        assert!(!format!("{list:?}").contains("cio_secret"));

        let list = netrc(
            "machine api.heroku.com\n  login ada@example.com\n  password hsecret\nmachine github.com login ada\n",
            &p(),
        );
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].get("user"), Some("ada@example.com"));
        assert_eq!(tags(&list[0]), ["credentialsInFile"]);
        assert!(list[1].tags.is_empty());
        assert!(!format!("{list:?}").contains("hsecret"));
    }

    #[test]
    fn ai_tool_accounts() {
        let list = claude_code(
            r#"{"oauthAccount":{"emailAddress":"ada@example.com","organizationName":"Ada's"}}"#,
            &p(),
        );
        assert_eq!(list[0].name, "ada@example.com");
        assert!(claude_code("{}", &p()).is_empty());
        let list = codex(r#"{"OPENAI_API_KEY":"sk-secret","tokens":null}"#, &p());
        assert_eq!(list[0].get("signIn"), Some("API key"));
        assert!(!format!("{list:?}").contains("sk-secret"));
    }

    #[test]
    fn ssh_key_types() {
        assert_eq!(key_type("ssh-ed25519"), "Ed25519");
        assert_eq!(
            key_type("sk-ssh-ed25519@openssh.com"),
            "Ed25519 (security key)"
        );
        assert_eq!(key_type("ecdsa-sha2-nistp256"), "ECDSA");
    }
}
