//! `lenstica mcp`: a Model Context Protocol server on stdin/stdout, so an AI
//! agent can read Lenstica's results, get a brief for a finding, re-run
//! lenses and apply Lenstica's own fixes.
//!
//! Messages are JSON-RPC 2.0, one per line. Only JSON-RPC goes to stdout;
//! anything else Lenstica prints goes to stderr.

use std::io::{BufRead, Write};

use anyhow::{Context, Result, bail};
use lenstica_lens::{Category, Finding, Severity};
use serde_json::{Value, json};

use crate::config::Config;
use crate::lenses::{self, store::RunResult};
use crate::prompt;

const PROTOCOL_VERSIONS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];

const INSTRUCTIONS: &str = "Lenstica is the security monitor on this machine. \
Start with lenstica_status, list findings with lenstica_findings, and get the brief for one with lenstica_finding. \
Never print or copy secret values; findings hold names and paths only. \
For malware, stop and tell the user: the machine should be treated as compromised. \
Ask the user before rotating credentials, deleting files or accepting (ignoring) a finding.";

pub fn serve() -> Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line.context("cannot read stdin")?;
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Value>(&line) {
            Ok(Value::Array(batch)) if batch.is_empty() => {
                Some(error(Value::Null, -32600, "invalid request: empty batch"))
            }
            Ok(Value::Array(batch)) => {
                let replies: Vec<Value> = batch.iter().filter_map(handle).collect();
                (!replies.is_empty()).then_some(Value::Array(replies))
            }
            Ok(msg) => handle(&msg),
            Err(e) => Some(error(Value::Null, -32700, &format!("parse error: {e}"))),
        };
        if let Some(reply) = reply {
            writeln!(stdout, "{reply}")?;
            stdout.flush()?;
        }
    }
    Ok(())
}

fn error(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// The reply to one message; `None` for notifications and for replies to
/// requests (this server sends none, so they are ignored).
fn handle(msg: &Value) -> Option<Value> {
    if !msg.is_object() {
        return Some(error(Value::Null, -32600, "invalid request: not an object"));
    }
    let Some(method) = msg.get("method").and_then(Value::as_str) else {
        if msg.get("result").is_some() || msg.get("error").is_some() {
            return None;
        }
        let id = msg.get("id").cloned().unwrap_or(Value::Null);
        return Some(error(id, -32600, "invalid request: no method"));
    };
    let id = msg.get("id").cloned()?;
    let params = msg.get("params").cloned().unwrap_or(Value::Null);
    let result = match method {
        "initialize" => {
            let asked = params.get("protocolVersion").and_then(Value::as_str);
            let version = asked
                .filter(|v| PROTOCOL_VERSIONS.contains(v))
                .unwrap_or(PROTOCOL_VERSIONS[0]);
            json!({
                "protocolVersion": version,
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "lenstica", "version": env!("CARGO_PKG_VERSION") },
                "instructions": INSTRUCTIONS,
            })
        }
        "ping" => json!({}),
        "tools/list" => json!({ "tools": tools() }),
        "tools/call" => {
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            if !tools()
                .as_array()
                .is_some_and(|t| t.iter().any(|tool| tool["name"] == name))
            {
                return Some(error(id, -32602, &format!("unknown tool: {name}")));
            }
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            match call(name, &args) {
                Ok(text) => json!({ "content": [{ "type": "text", "text": text }] }),
                Err(e) => {
                    json!({ "content": [{ "type": "text", "text": format!("{e:#}") }], "isError": true })
                }
            }
        }
        "resources/list" => json!({ "resources": [] }),
        "prompts/list" => json!({ "prompts": [] }),
        other => return Some(error(id, -32601, &format!("method not found: {other}"))),
    };
    Some(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}

fn tools() -> Value {
    let read_only = json!({ "readOnlyHint": true, "openWorldHint": false });
    json!([
        {
            "name": "lenstica_status",
            "description": "Overview of every Lenstica lens: when it last ran, its summary, any error, and how many findings need attention. Reads stored results; runs nothing.",
            "inputSchema": { "type": "object", "properties": {} },
            "annotations": read_only,
        },
        {
            "name": "lenstica_findings",
            "description": "List current findings, most severe first. Each has lens, key, severity, category, topic, title, where it is, and whether Lenstica can fix it.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "severity": { "type": "string", "enum": ["info", "low", "medium", "high", "critical"], "description": "Lowest severity to include (default low)" },
                    "lens": { "type": "string", "description": "Only this lens id, e.g. secrets, vulnerabilities, package-age" },
                    "category": { "type": "string", "enum": Category::ALL.map(Category::id) },
                    "query": { "type": "string", "description": "Only findings whose title, detail or locations contain this text" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 500, "description": "Default 50" }
                }
            },
            "annotations": read_only,
        },
        {
            "name": "lenstica_finding",
            "description": "One finding in full (detail, every location, remedy, references) plus a brief for fixing it.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "lens": { "type": "string" },
                    "key": { "type": "string", "description": "The finding's key from lenstica_findings" }
                },
                "required": ["lens", "key"]
            },
            "annotations": read_only,
        },
        {
            "name": "lenstica_prompt",
            "description": "A brief for an agent covering every finding that needs attention, optionally for one lens only.",
            "inputSchema": { "type": "object", "properties": { "lens": { "type": "string" } } },
            "annotations": read_only,
        },
        {
            "name": "lenstica_assets",
            "description": "What is on this machine: identities (accounts signed in to git, SSH, GitHub, AWS, Google Cloud, Azure, Kubernetes, registries and AI tools; names only, never keys), repositories, applications, containers, virtual machines, and editor and browser extensions. Runs local listing commands such as `docker ps`; sends nothing anywhere.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "kind": { "type": "string", "enum": crate::assets::Kind::ALL.map(crate::assets::Kind::id), "description": "Only this kind; all when omitted" }
                }
            },
            "annotations": read_only,
        },
        {
            "name": "lenstica_run",
            "description": "Run lenses now and return their summaries, e.g. to confirm a fix. Dependency lenses can take a minute on a large machine.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "lenses": { "type": "array", "items": { "type": "string" }, "description": "Lens ids; all enabled ones when omitted" },
                    "offline": { "type": "boolean", "description": "Use cached registry data only" }
                }
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": false, "idempotentHint": true, "openWorldHint": true },
        },
        {
            "name": "lenstica_fix",
            "description": "Apply Lenstica's own fix for a finding marked fixable (writes a package manager's minimum-age setting, for example). Ask the user first.",
            "inputSchema": {
                "type": "object",
                "properties": { "lens": { "type": "string" }, "key": { "type": "string" } },
                "required": ["lens", "key"]
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": false, "openWorldHint": false },
        },
    ])
}

fn str_arg<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_default()
}

fn brief(f: &Finding) -> Value {
    json!({
        "lens": f.lens,
        "key": f.key,
        "severity": f.severity.label(),
        "category": f.category,
        "topic": f.topic,
        "title": f.title,
        "where": f.locations.iter().take(3).map(|l| l.label.clone()).collect::<Vec<_>>(),
        "locations": f.locations.len(),
        "fixable": f.fixable,
    })
}

fn find<'a>(
    results: &'a std::collections::BTreeMap<String, RunResult>,
    lens: &str,
    key: &str,
) -> Result<(&'a Finding, &'a RunResult)> {
    let result = results
        .get(lens)
        .with_context(|| format!("no results from `{lens}`; see lenstica_status for lens ids"))?;
    let f = result
        .findings
        .iter()
        .find(|f| f.key == key)
        .with_context(|| format!("`{lens}` no longer reports `{key}`"))?;
    Ok((f, result))
}

fn call(name: &str, args: &Value) -> Result<String> {
    let cfg = Config::load()?;
    let results = lenses::store::load();
    match name {
        "lenstica_status" => {
            let mut alerts = 0;
            let lenses: Vec<Value> = lenses::registry(&cfg)
                .iter()
                .map(|r| {
                    let res = results.get(r.id());
                    let enabled = lenses::enabled(&cfg, r);
                    let need_attention = res.map_or(0, |x| {
                        x.findings
                            .iter()
                            .filter(|f| lenses::is_alert(&cfg, f))
                            .count()
                    });
                    if enabled {
                        alerts += need_attention;
                    }
                    json!({
                        "id": r.id(),
                        "title": r.lens.title(),
                        "enabled": enabled,
                        "ran_at": res.map(|x| x.ran_at),
                        "summary": res.map(|x| x.summary.clone()),
                        "error": res.and_then(|x| x.error.clone()),
                        "findings": res.map_or(0, |x| x.findings.len()),
                        "need_attention": need_attention,
                    })
                })
                .collect();
            Ok(pretty(&json!({
                "min_days": cfg.min_days,
                "alert_severity": lenses::threshold(&cfg).label(),
                "need_attention": alerts,
                "lenses": lenses,
            })))
        }
        "lenstica_findings" => {
            let min = match str_arg(args, "severity") {
                Some(s) => {
                    lenses::parse_severity(s).with_context(|| format!("unknown severity `{s}`"))?
                }
                None => Severity::Low,
            };
            let lens = str_arg(args, "lens");
            let category = str_arg(args, "category")
                .map(str::parse::<Category>)
                .transpose()
                .map_err(anyhow::Error::msg)?;
            let query = str_arg(args, "query").map(str::to_lowercase);
            let limit = args
                .get("limit")
                .and_then(Value::as_u64)
                .unwrap_or(50)
                .clamp(1, 500) as usize;
            let mut list: Vec<&Finding> = lenses::live_results(&cfg, &results)
                .filter(|r| lens.is_none_or(|c| r.id == c))
                .flat_map(|r| &r.findings)
                .filter(|f| f.severity >= min)
                .filter(|f| category.is_none_or(|c| f.category == c))
                .filter(|f| {
                    query.as_ref().is_none_or(|q| {
                        let text = format!(
                            "{}\n{}\n{}",
                            f.title,
                            f.detail,
                            f.locations
                                .iter()
                                .map(|l| l.label.as_str())
                                .collect::<Vec<_>>()
                                .join("\n")
                        );
                        text.to_lowercase().contains(q)
                    })
                })
                .collect();
            list.sort_by(|a, b| lenses::by_severity(a, b));
            let total = list.len();
            let shown: Vec<Value> = list.into_iter().take(limit).map(brief).collect();
            Ok(pretty(
                &json!({ "total": total, "shown": shown.len(), "findings": shown }),
            ))
        }
        "lenstica_finding" => {
            let (lens, key) = (
                str_arg(args, "lens").context("`lens` is required")?,
                str_arg(args, "key").context("`key` is required")?,
            );
            let (f, result) = find(&results, lens, key)?;
            let mut value = serde_json::to_value(f)?;
            value["brief"] = Value::String(prompt::for_finding(&cfg, f, &result.title));
            Ok(pretty(&value))
        }
        "lenstica_prompt" => {
            let list = prompt::collect(&cfg, &results, &[(str_arg(args, "lens"), None)]);
            Ok(prompt::for_findings(&cfg, &list))
        }
        "lenstica_run" => {
            let only: Vec<String> = args
                .get("lenses")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            for id in &only {
                lenses::find(&cfg, id)?;
            }
            let offline = args
                .get("offline")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let ran = lenses::run_due(&cfg, true, &only, offline);
            let out: Vec<Value> = ran
                .iter()
                .map(|r| {
                    json!({
                        "id": r.id,
                        "summary": r.summary,
                        "error": r.error,
                        "need_attention": r.findings.iter().filter(|f| lenses::is_alert(&cfg, f)).count(),
                        "seconds": (r.seconds * 10.0).round() / 10.0,
                    })
                })
                .collect();
            Ok(pretty(&json!({ "ran": out })))
        }
        "lenstica_fix" => {
            let (lens, key) = (
                str_arg(args, "lens").context("`lens` is required")?,
                str_arg(args, "key").context("`key` is required")?,
            );
            lenses::fix(&cfg, lens, key).map(|(done, _)| done)
        }
        "lenstica_assets" => {
            use crate::assets::{self, Kind};
            let kinds = match str_arg(args, "kind") {
                Some(k) => vec![Kind::from_id(k).with_context(|| format!("unknown kind `{k}`"))?],
                None => Kind::ALL.to_vec(),
            };
            let found = assets::discover(&cfg, &kinds);
            Ok(pretty(&Value::Array(
                found.iter().map(assets::Discovery::brief).collect(),
            )))
        }
        other => bail!("unknown tool `{other}`"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_the_handshake_and_lists_tools() {
        let init = handle(&json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}})).unwrap();
        assert_eq!(init["result"]["protocolVersion"], "2025-03-26");
        assert_eq!(init["result"]["serverInfo"]["name"], "lenstica");
        assert!(handle(&json!({"jsonrpc":"2.0","method":"notifications/initialized"})).is_none());
        let list = handle(&json!({"jsonrpc":"2.0","id":"a","method":"tools/list"})).unwrap();
        let names: Vec<&str> = list["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "lenstica_status",
                "lenstica_findings",
                "lenstica_finding",
                "lenstica_prompt",
                "lenstica_assets",
                "lenstica_run",
                "lenstica_fix"
            ]
        );
        let unknown = handle(&json!({"jsonrpc":"2.0","id":2,"method":"nope"})).unwrap();
        assert_eq!(unknown["error"]["code"], -32601);
        let tool =
            handle(&json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"nope"}}));
        assert_eq!(tool.unwrap()["error"]["code"], -32602);
        let no_method = handle(&json!({"jsonrpc":"2.0","id":4})).unwrap();
        assert_eq!(no_method["error"]["code"], -32600);
        assert!(handle(&json!({"jsonrpc":"2.0","id":5,"result":{}})).is_none());
        assert_eq!(handle(&json!(7)).unwrap()["error"]["code"], -32600);
    }
}
