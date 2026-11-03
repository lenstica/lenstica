//! HTTP through the system `curl`: present on macOS, Windows 10+ and nearly
//! every Linux, and it keeps TLS out of this binary (which also keeps
//! cross-compiling trivial). Batches run eight transfers in parallel.

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::exec;

const BATCH_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const USER_AGENT: &str = concat!("lenstica/", env!("CARGO_PKG_VERSION"));

pub fn curl(search: &OsStr) -> Result<PathBuf> {
    exec::find("curl", search).context("`curl` is needed to reach package registries and OSV.dev")
}

fn quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// GET every URL, writing response `i` to `dir/i`. A URL that fails (404 for
/// an unpublished name, say) simply has no file; an error is returned only
/// when nothing at all came back, which means the network is down.
pub fn get_batch(urls: &[String], dir: &Path, search: &OsStr) -> Result<()> {
    get_batch_with(urls, dir, search, &[])
}

/// [`get_batch`] with extra curl options for every URL: `["--head"]`, or
/// `["--header", "Accept: ..."]`.
pub fn get_batch_with(urls: &[String], dir: &Path, search: &OsStr, extra: &[&str]) -> Result<()> {
    let curl = curl(search)?;
    let mut config = String::new();
    for (i, url) in urls.iter().enumerate() {
        config.push_str(&format!(
            "url = {}\noutput = {}\n",
            quote(url),
            quote(&dir.join(i.to_string()).to_string_lossy())
        ));
    }
    let config_path = dir.join("batch.curlrc");
    fs::write(&config_path, config)
        .with_context(|| format!("cannot write {}", config_path.display()))?;
    let config_arg = config_path.to_string_lossy().into_owned();
    let mut args = vec![
        "--parallel",
        "--parallel-max",
        "8",
        "--compressed",
        "--silent",
        "--show-error",
        "--fail",
        "--location",
        "--retry",
        "2",
        "--connect-timeout",
        "15",
        "--max-time",
        "120",
        "--user-agent",
        USER_AGENT,
        "--config",
        &config_arg,
    ];
    args.extend_from_slice(extra);
    let out = exec::run_timeout(&curl, &args, search, BATCH_TIMEOUT)?;
    let _ = fs::remove_file(&config_path);
    let any_output = (0..urls.len()).any(|i| dir.join(i.to_string()).exists());
    // curl's exit 22 is an HTTP error status: the server answered (a 404 for
    // an unknown name), so the network is fine even when nothing came back.
    let answered = out.error_text().contains("(22)");
    if !out.success && !any_output && !answered && !urls.is_empty() {
        bail!("requests failed: {}", out.error_text());
    }
    Ok(())
}

/// POST a JSON body and return the response body.
pub fn post_json(url: &str, body: &str, dir: &Path, search: &OsStr) -> Result<String> {
    let curl = curl(search)?;
    fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    let body_path = dir.join(format!("post-{}.json", std::process::id()));
    fs::write(&body_path, body).with_context(|| format!("cannot write {}", body_path.display()))?;
    let data_arg = format!("@{}", body_path.to_string_lossy());
    let out = exec::run_timeout(
        &curl,
        &[
            "--silent",
            "--show-error",
            "--fail",
            "--compressed",
            "--retry",
            "2",
            "--connect-timeout",
            "15",
            "--max-time",
            "300",
            "--user-agent",
            USER_AGENT,
            "--header",
            "Content-Type: application/json",
            "--data-binary",
            &data_arg,
            url,
        ],
        search,
        BATCH_TIMEOUT,
    );
    let _ = fs::remove_file(&body_path);
    let out = out?;
    if !out.success {
        bail!("POST {url} failed: {}", out.error_text());
    }
    Ok(out.stdout)
}

/// A scratch directory for one batch, removed when dropped.
pub struct Scratch(pub PathBuf);

impl Scratch {
    pub fn new(parent: &Path, name: &str) -> Result<Self> {
        let dir = parent.join(format!("{name}-{}", std::process::id()));
        fs::create_dir_all(&dir).with_context(|| format!("cannot create {}", dir.display()))?;
        Ok(Self(dir))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
