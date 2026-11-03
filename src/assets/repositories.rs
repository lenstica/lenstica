//! The repositories under the folders Lenstica searches (Settings →
//! Projects), the same ones the project picker lists: each main checkout with
//! its remote, branch and worktrees, read from `.git` without running git.

use std::path::Path;

use super::{Asset, Ctx, Found, file_name, ini_sections, ini_value, without_credentials};

pub(super) fn discover(ctx: &Ctx, found: &mut Found) {
    let cfg = ctx.cfg;
    let exclude = cfg.exclude();
    let repos = crate::scan::repositories(&cfg.scan_roots(), cfg.scan.max_depth, &ctx.search);
    for repo in repos.iter().filter(|r| r.worktree_of.is_none()) {
        let worktrees = repos
            .iter()
            .filter(|r| r.worktree_of.as_deref() == Some(repo.path.as_path()))
            .count();
        let git = repo.path.join(".git");
        let config = std::fs::read_to_string(git.join("config")).unwrap_or_default();
        let remote = origin(&config);
        let head = std::fs::read_to_string(git.join("HEAD")).unwrap_or_default();
        found.add(
            Asset::new(
                repo.path.to_string_lossy(),
                file_name(&repo.path),
                remote.as_deref().map(host_name).unwrap_or_default(),
            )
            .path(&repo.path)
            .fact_opt("remote", remote)
            .fact_opt("branch", branch(&head))
            .fact(
                "worktrees",
                if worktrees > 0 {
                    worktrees.to_string()
                } else {
                    String::new()
                },
            )
            .tag_if(exclude.skips(&repo.path), "excluded"),
        );
    }
}

/// The `origin` remote's URL, else the first remote's, without credentials.
fn origin(config: &str) -> Option<String> {
    let remotes: Vec<(String, String)> = ini_sections(config)
        .into_iter()
        .filter_map(|(section, pairs)| {
            let name = section
                .strip_prefix("remote ")?
                .trim()
                .trim_matches('"')
                .to_string();
            Some((name, ini_value(&pairs, "url")?.to_string()))
        })
        .collect();
    remotes
        .iter()
        .find(|(n, _)| n == "origin")
        .or_else(|| remotes.first())
        .map(|(_, url)| without_credentials(url))
}

/// `main`, or `detached at 1a2b3c4`.
fn branch(head: &str) -> Option<String> {
    let head = head.trim();
    if let Some(r) = head.strip_prefix("ref: ") {
        return Some(r.trim_start_matches("refs/heads/").to_string());
    }
    (head.len() >= 7).then(|| format!("detached at {}", &head[..7]))
}

/// Where a remote is hosted, as the group the window shows it under.
fn host_name(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let rest = rest.rsplit_once('@').map_or(rest, |(_, r)| r);
    let host = rest
        .split([':', '/'])
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    match host.as_str() {
        "github.com" | "ssh.github.com" => "GitHub".to_string(),
        "gitlab.com" => "GitLab".to_string(),
        "bitbucket.org" => "Bitbucket".to_string(),
        "dev.azure.com" | "ssh.dev.azure.com" | "vs-ssh.visualstudio.com" => {
            "Azure DevOps".to_string()
        }
        "codeberg.org" => "Codeberg".to_string(),
        "" => String::new(),
        _ if Path::new(rest).is_absolute() => String::new(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_first_and_without_credentials() {
        let config = "[core]\n\tbare = false\n[remote \"upstream\"]\n\turl = git@github.com:a/b.git\n[remote \"origin\"]\n\turl = https://tok@gitlab.com/me/b.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n";
        assert_eq!(
            origin(config).as_deref(),
            Some("https://gitlab.com/me/b.git")
        );
        assert_eq!(origin("[core]\n").as_deref(), None);
    }

    #[test]
    fn hosts_and_branches() {
        assert_eq!(host_name("git@github.com:a/b.git"), "GitHub");
        assert_eq!(host_name("https://gitlab.com/a/b"), "GitLab");
        assert_eq!(
            host_name("ssh://git@git.corp.example:2222/a/b"),
            "git.corp.example"
        );
        assert_eq!(host_name("/srv/git/b.git"), "");
        assert_eq!(
            branch("ref: refs/heads/feature/x\n").as_deref(),
            Some("feature/x")
        );
        assert_eq!(
            branch("1a2b3c4d5e6f\n").as_deref(),
            Some("detached at 1a2b3c4")
        );
    }
}
