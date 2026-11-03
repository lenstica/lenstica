# AI agents

There are three ways to hand Lenstica's findings to a coding agent such as
Claude Code. Findings hold secret names and paths, never values, and the
default prompts tell the agent not to print any.

## Copy a prompt

Every finding, in the menu and the window, has **Copy Prompt for AI Agent**: a
short brief with what was found, where, the suggested fix, and how to confirm
it is gone (`lenstica check <lens>`). In the window it first shows the prompt,
exactly as it will be copied, with Copy prompt (⌘↩) and a link to edit the
templates; a category's **Copy prompt for all** does the same for every
finding shown. The menu bar copies straight away. From the CLI:

```sh
lenstica prompt                  # everything needing attention
lenstica prompt <lens>           # one lens
lenstica prompt <lens> '<key>'   # one finding
```

## Prompt templates

The prompts are written from three templates you can change in **Settings →
AI prompts**, which shows Lenstica's own and a live preview from your current
findings. They are saved under `[prompts]` in the settings file and used
everywhere: Copy Prompt for AI Agent, `lenstica prompt`, and the MCP server's
`lenstica_prompt` and `lenstica_finding`.

| Template | Writes |
|----------|--------|
| `finding` | The prompt for one finding |
| `findings` | The prompt for several; `{{findings}}` is each one written with `item` |
| `item` | One finding in that list |

An empty template means Lenstica's own, so it keeps any later improvements.
`{{name}}` inserts a value; `{{#name}}…{{/name}}` keeps its text only when the
value is not empty, and `{{^name}}…{{/name}}` only when it is. Blank lines left
behind by empty values are collapsed. A template with an unknown value or an
unclosed section is refused, with the reason.

```toml
[prompts]
finding = """
[{{severity}} · {{category}} / {{topic}}] {{title}}
{{#remedy}}Do this: {{remedy}}{{/remedy}}{{^remedy}}No remedy given.{{/remedy}}
{{#fix_command}}Or run: {{fix_command}}{{/fix_command}}
Confirm with `{{check_command}}`.
"""
```

In `finding` and `item`:

| Value | Is |
|-------|----|
| `severity` | info, low, medium, high or critical |
| `title` | what was found |
| `lens`, `lens_id` | the lens's name (Package ages) and id (`package-age`) |
| `category`, `topic` | AI agents, Packages… and Cooldown, Prompt injection, Exposed… |
| `detail` | the details, up to 6 lines |
| `locations` | where it is, one `- ` line each, up to 10 |
| `remedy` | what to do about it |
| `links` | references, space-separated |
| `fix_command` | `lenstica fix …`, when Lenstica can fix it itself |
| `check_command` | `lenstica check <lens>`, to confirm it is gone |
| `untrusted_warning` | for AI-agent findings, a warning to treat the flagged file as untrusted |
| `number` | (`item` only) its position in the list |

In `findings`: `count`, `findings`, `check_command` (every lens involved) and
`untrusted_warning` (when any finding is about agent instructions).

Removing `untrusted_warning` from a template drops the warning that keeps an
agent from following instructions planted in the file it is asked to fix.

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
| `lenstica_assets` | what is on this machine: accounts (names only), repositories, apps, containers, virtual machines, extensions |
| `lenstica_run` | re-run lenses, to confirm a fix |
| `lenstica_fix` | apply one of Lenstica's own fixes |

It reads the same stored results as the menu bar app.
