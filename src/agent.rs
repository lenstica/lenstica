//! Letting AI coding agents use lenstica: a skill that teaches the CLI, and
//! the command that registers the MCP server (`lenstica mcp`).

use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::files;
use crate::paths;

/// The skill, in the SKILL.md format Claude Code and other agents read.
pub const SKILL: &str = include_str!("../skills/lenstica/SKILL.md");

/// Where Claude Code looks for personal skills.
pub fn default_skill_dir() -> PathBuf {
    paths::home()
        .join(".claude")
        .join("skills")
        .join("lenstica")
}

/// Write SKILL.md into `dir` (default: `~/.claude/skills/lenstica`).
pub fn install_skill(dir: Option<PathBuf>) -> Result<PathBuf> {
    let dir = dir.unwrap_or_else(default_skill_dir);
    std::fs::create_dir_all(&dir).with_context(|| format!("cannot create {}", dir.display()))?;
    let path = dir.join("SKILL.md");
    files::write_atomic(&path, SKILL)?;
    Ok(path)
}

/// Whether the installed skill is this version's.
#[cfg_attr(not(feature = "tray"), allow(dead_code))]
pub fn skill_installed() -> bool {
    files::read_optional(&default_skill_dir().join("SKILL.md"))
        .ok()
        .flatten()
        .is_some_and(|s| s == SKILL)
}

/// The binary agents should start: this one, wherever it is installed.
fn executable() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.canonicalize().ok())
        .map_or_else(|| "lenstica".to_string(), |p| p.display().to_string())
}

/// `claude mcp add ...` for Claude Code.
pub fn mcp_command() -> String {
    let exe = executable();
    let exe = if exe.contains(' ') {
        format!("\"{exe}\"")
    } else {
        exe
    };
    format!("claude mcp add --scope user lenstica -- {exe} mcp")
}

/// The `mcpServers` entry most other MCP clients take.
pub fn mcp_json() -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "mcpServers": { "lenstica": { "command": executable(), "args": ["mcp"] } }
    }))
    .unwrap_or_default()
}
