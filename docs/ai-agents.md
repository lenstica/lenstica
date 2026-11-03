# AI agents

There are three ways to hand Lenstica's findings to a coding agent such as
Claude Code. Findings hold secret names and paths, never values, and every
prompt tells the agent not to print any.

## Copy a prompt

Every finding, in the menu and the window, has **Copy Prompt for AI Agent**: a
short brief with what was found, where, the suggested fix, and how to confirm
it is gone (`lenstica check <lens>`). From the CLI:

```sh
lenstica prompt                  # everything needing attention
lenstica prompt <lens>           # one lens
lenstica prompt <lens> '<key>'   # one finding
```

## The skill

`lenstica skill --install` (or Settings → AI agents) writes
[`skills/lenstica/SKILL.md`](../skills/lenstica/SKILL.md) to
`~/.claude/skills/lenstica/`. It teaches the agent the CLI
(`lenstica status --no-run --json`, `lenstica findings --json`,
`lenstica fix`, `lenstica check`) and how to treat each lens's findings.
`lenstica skill` prints it, for agents that load skills from elsewhere
(`--install --dir DIR`).

## The MCP server

`lenstica mcp` speaks the Model Context Protocol on stdin/stdout. Register it
with Claude Code:

```sh
claude mcp add --scope user lenstica -- lenstica mcp
```

or use the `mcpServers` entry that `lenstica mcp --setup` prints.

| Tool | What it does |
|------|--------------|
| `lenstica_status` | every lens's summary |
| `lenstica_findings` | findings, filtered by severity, lens, category or text |
| `lenstica_finding` | one finding in full, with its brief |
| `lenstica_prompt` | a brief for an AI agent |
| `lenstica_run` | re-run lenses, to confirm a fix |
| `lenstica_fix` | apply one of Lenstica's own fixes |

It reads the same stored results as the menu bar app.
