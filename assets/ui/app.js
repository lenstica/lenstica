"use strict";
const SEV = ["info", "low", "medium", "high", "critical"];
const rank = s => SEV.indexOf(s);
const CATEGORIES = {
  malware: "Malware", vulnerability: "Vulnerabilities", secret: "Exposed secrets",
  cooldown: "Cooldown", deprecated: "Deprecated", agent: "AI agent instructions", settings: "Settings",
  telemetry: "Telemetry",
};
const DEP_KINDS = ["vuln", "malware", "telemetry", "too-new", "locked-young", "deprecated", "yanked"];
const PAGES = ["overview", "findings", "lenses", "settings"];
const ui = { state: null, page: "overview", q: "", sev: "low", cat: "", lens: "", selected: null, repos: null, reposError: null };
// The app opens the window on a page with `index.html#settings`, or on one
// finding with `index.html#findings/<lens|key, percent-encoded>`.
function route(target) {
  const [page, ...rest] = String(target).split("/");
  if (!PAGES.includes(page)) return false;
  ui.page = page;
  if (page === "findings" && rest.length) {
    Object.assign(ui, { q: "", sev: "info", cat: "", lens: "" });
    ui.selected = decodeURIComponent(rest.join("/"));
    ui.scrollToSelected = true;
  }
  return true;
}
route(location.hash.slice(1));

const tauri = window.__TAURI__;
const post = msg => tauri.core.invoke("action", { msg }).catch(e => window.lenstica.toast(String(e), false));
function icon(name) {
  // Template contents are not part of the document, so query the template itself.
  const el = document.getElementById("icons").content.querySelector(`[data-icon="${name}"] svg`);
  return el ? el.cloneNode(true) : document.createTextNode("");
}
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "class") el.className = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}
function ago(iso) {
  if (!iso) return "never";
  const s = Math.max(0, (Date.now() - Date.parse(iso)) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} days ago`;
}
const SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
// Severity as a coloured icon: octagon critical, triangle high, circle medium, i low, dot info.
const badge = sev => h("span", { class: `sev ${sev}`, title: SEV_LABEL[sev] }, icon(`sev-${sev}`));
const sevLabel = sev => h("span", { class: `sev ${sev}` }, icon(`sev-${sev}`), SEV_LABEL[sev]);
const findingId = f => f.lens + "|" + f.key;
const isAlert = f => rank(f.severity) >= rank(ui.state.alertSeverity);

function allFindings() {
  const out = [];
  for (const c of ui.state.lenses) {
    if (!c.enabled || !c.result) continue;
    for (const f of c.result.findings) out.push({ ...f, lensTitle: c.title });
  }
  return out.sort((a, b) => rank(b.severity) - rank(a.severity) || a.title.localeCompare(b.title));
}

function lensState(c) {
  if (c.running) return "run";
  if (!c.enabled || !c.result) return "idle";
  if (c.result.error) return "err";
  const alerts = c.result.findings.filter(isAlert);
  if (!alerts.length) return "ok";
  // A problem dot takes the colour of the worst severity, as in the menu bar.
  return `bad worst-${SEV[Math.max(...alerts.map(f => rank(f.severity)))]}`;
}

// ---- pages ------------------------------------------------------------------

function overview() {
  const findings = allFindings();
  const alerts = findings.filter(isAlert);
  const running = ui.state.lenses.filter(c => c.running).length;
  const ok = alerts.length === 0;
  const hero = h("div", { class: `card hero ${ok ? "ok" : "bad"}` },
    h("div", { class: "icon" }, icon(ok ? "check" : "alert")),
    h("div", {},
      h("div", { class: "title" }, ok ? "Nothing needs attention" : `${alerts.length} need attention`),
      h("div", { class: "muted" }, `Packages newer than ${ui.state.settings.min_days} days are held back · findings at ${ui.state.alertSeverity} or above count`)),
    h("div", { class: "spacer" }),
    h("button", { class: "btn primary", onclick: () => post({ type: "run" }), disabled: running > 0 },
      icon("refresh"), running ? `Checking (${running})…` : "Check everything"));

  const counts = SEV.slice().reverse().map(s => {
    const n = findings.filter(f => f.severity === s).length;
    return h("span", { class: "chip", onclick: () => go("findings", { sev: s, cat: "", lens: "" }) },
      sevLabel(s), h("b", {}, n));
  });

  const cats = Object.entries(CATEGORIES).map(([id, label]) => {
    const list = findings.filter(f => f.category === id);
    const worst = list.reduce((m, f) => Math.max(m, rank(f.severity)), -1);
    const alertsHere = list.filter(isAlert).length;
    return h("div", { class: "card tile", onclick: () => go("findings", { cat: id, sev: "info", lens: "" }) },
      h("div", { class: "head" }, icon(id === "secret" ? "key" : id === "malware" ? "shield" : id === "agent" ? "bot" : "package"), label,
        h("span", { class: "spacer" }), worst >= 0 ? sevLabel(SEV[worst]) : h("span", { class: "tag" }, "clear")),
      h("div", { class: "summary" }, list.length ? `${list.length} ${list.length === 1 ? "finding" : "findings"}, ${alertsHere} needing attention` : "Nothing found"));
  });

  const lenses = ui.state.lenses.map(c => {
    const st = lensState(c);
    const r = c.result;
    return h("div", { class: "card tile", onclick: () => go("findings", { lens: c.id, cat: "", sev: "info" }) },
      h("div", { class: "head" }, h("span", { class: `state ${st}` }), c.title, h("span", { class: "spacer" }),
        h("button", { class: "btn small", disabled: c.running || !c.enabled,
          onclick: e => { e.stopPropagation(); post({ type: "run", lens: c.id }); } }, icon("refresh"), c.running ? "Running" : "Run")),
      h("div", { class: "summary" }, !c.enabled ? "Turned off" : r ? (r.error ? `Failed: ${r.error}` : r.summary) : "Not run yet"),
      h("div", { class: "meta" }, r ? `${ago(r.ran_at)} · ${r.seconds.toFixed(1)} s` : "", h("span", {}, c.origin)));
  });

  return [
    h("h1", {}, "Overview"),
    h("p", { class: "sub" }, `Settings: ${ui.state.configPath}`),
    hero, h("div", { class: "chips" }, counts),
    h("h2", {}, "By category"), h("div", { class: "grid" }, cats),
    h("h2", {}, "Lenses"), h("div", { class: "grid" }, lenses),
  ];
}

function filtered() {
  const q = ui.q.trim().toLowerCase();
  return allFindings().filter(f =>
    rank(f.severity) >= rank(ui.sev) &&
    (!ui.cat || f.category === ui.cat) &&
    (!ui.lens || f.lens === ui.lens) &&
    (!q || [f.title, f.detail, f.remedy, ...f.locations.map(l => l.label)].join("\n").toLowerCase().includes(q)));
}

function findingsPage() {
  const list = filtered();
  if (ui.selected && !list.some(f => f.lens + "|" + f.key === ui.selected)) ui.selected = null;
  if (!ui.selected && list.length) ui.selected = list[0].lens + "|" + list[0].key;
  const select = (value, options, onchange) => h("select", { onchange: e => onchange(e.target.value) },
    options.map(([v, label]) => h("option", { value: v, selected: v === value }, label)));
  const toolbar = h("div", { class: "toolbar" },
    h("div", { class: "search" }, icon("search"),
      h("input", { placeholder: "Search titles, details, files…", value: ui.q,
        oninput: e => { ui.q = e.target.value; renderKeepFocus(); } })),
    select(ui.sev, SEV.map(s => [s, `${s} and above`]), v => { ui.sev = v; render(); }),
    select(ui.cat, [["", "All categories"], ...Object.entries(CATEGORIES)], v => { ui.cat = v; render(); }),
    select(ui.lens, [["", "All lenses"], ...ui.state.lenses.map(c => [c.id, c.title])], v => { ui.lens = v; render(); }),
    h("span", { class: "spacer" }),
    list.length ? h("button", { class: "btn", title: "One brief for an AI coding agent covering every finding shown", onclick: () => post({ type: "copyPrompt", items: list.slice(0, 50).map(f => ({ lens: f.lens, key: f.key })) }) },
      icon("copy"), list.length > 50 ? "Copy prompt for the first 50" : `Copy prompt for ${list.length === 1 ? "it" : "all " + list.length}`) : null);
  const rows = list.map(f => {
    const id = f.lens + "|" + f.key;
    const where = f.locations.length ? f.locations[0].label + (f.locations.length > 1 ? ` (+${f.locations.length - 1})` : "") : "";
    return h("div", { class: `item ${id === ui.selected ? "sel" : ""}`, onclick: () => { ui.selected = id; render(); } },
      badge(f.severity), h("div", { class: "t" }, f.title), h("div", { class: "m" }, `${f.lensTitle} · ${where}`));
  });
  const current = list.find(f => f.lens + "|" + f.key === ui.selected);
  return [
    h("h1", {}, "Findings"),
    h("p", { class: "sub" }, `${list.length} shown`),
    toolbar,
    h("div", { class: "split" },
      h("div", { class: "card list" }, rows.length ? rows : h("div", { class: "empty" }, "No findings match.")),
      h("div", { class: "card detail" }, current ? detail(current) : h("div", { class: "empty" }, "Select a finding."))),
  ];
}

function detail(f) {
  const parts = f.key.split("|");
  const actions = [];
  if (f.fixable) actions.push(h("button", { class: "btn primary", onclick: () => post({ type: "fix", lens: f.lens, key: f.key }) }, icon("wrench"), "Fix it"));
  actions.push(h("button", { class: "btn", title: "Copies a short brief an AI coding agent can act on", onclick: () => post({ type: "copyPrompt", items: [{ lens: f.lens, key: f.key }] }) }, icon("copy"), "Copy prompt for AI agent"));
  if (DEP_KINDS.includes(parts[0]) && parts.length >= 4) {
    const [, , name, version] = parts;
    actions.push(h("button", { class: "btn", onclick: () => post({ type: "ignorePackage", entry: `${name}@${version}`, lens: f.lens }) }, icon("eye-off"), `Ignore ${name}@${version}`));
    actions.push(h("button", { class: "btn", onclick: () => post({ type: "ignorePackage", entry: name, lens: f.lens }) }, icon("eye-off"), `Ignore all of ${name}`));
  }
  if (parts[0] === "vuln" && parts[4]) {
    for (const id of parts[4].split(",").slice(0, 3)) {
      actions.push(h("button", { class: "btn", onclick: () => post({ type: "ignoreAdvisory", id }) }, icon("eye-off"), `Ignore ${id}`));
    }
  }
  const locs = f.locations.map(l => h("li", {},
    h("span", { title: l.label }, l.label + (l.line ? `:${l.line}` : "")),
    l.path ? h("button", { class: "btn small", onclick: () => post({ type: "open", path: l.path }) }, icon("file"), "Open") : null,
    l.path ? h("button", { class: "btn small", onclick: () => post({ type: "open", path: l.path, reveal: true }) }, icon("folder"), "Reveal") : null));
  return [
    h("div", { class: "row" }, sevLabel(f.severity), h("span", { class: "tag" }, CATEGORIES[f.category] || f.category),
      f.lensTitle !== (CATEGORIES[f.category] || f.category) ? h("span", { class: "tag" }, f.lensTitle) : null),
    h("h3", {}, f.title),
    f.detail ? h("pre", {}, f.detail) : null,
    f.remedy ? h("div", { class: "remedy" }, f.remedy) : null,
    actions.length ? h("div", { class: "row" }, actions) : null,
    f.locations.length ? h("h2", {}, `Where (${f.locations.length})`) : null,
    f.locations.length ? h("ul", { class: "locs" }, locs) : null,
    f.links.length ? h("h2", {}, "References") : null,
    ...f.links.map(url => h("div", {}, h("span", { class: "link", onclick: () => post({ type: "openUrl", url }) }, url))),
    h("p", { class: "meta" }, `Key: ${f.key}`),
  ];
}

function lensesPage() {
  const cards = ui.state.lenses.map(c => {
    const r = c.result;
    return h("div", { class: "card lens" },
      h("div", { class: "head" },
        h("span", { class: `state ${lensState(c)}` }), h("span", { class: "name" }, c.title),
        h("span", { class: "tag" }, c.id), h("span", { class: "tag" }, c.origin), h("span", { class: "tag" }, `every ${c.intervalMinutes} min`),
        h("span", { class: "spacer" }),
        h("button", { class: "btn small", disabled: c.running || !c.enabled, onclick: () => post({ type: "run", lens: c.id }) }, icon("refresh"), "Run now"),
        h("label", { class: "switch", title: c.enabled ? "Turn off" : "Turn on" },
          h("input", { type: "checkbox", checked: c.enabled, onchange: e => post({ type: "toggleLens", id: c.id, enabled: e.target.checked }) }), h("span"))),
      h("div", { class: "desc" }, c.description),
      h("div", { class: "muted" }, r ? `${r.error ? "Failed: " + r.error : r.summary} · ${ago(r.ran_at)} · ${r.seconds.toFixed(1)} s` : "Not run yet"),
      r && r.passing.length ? h("details", {}, h("summary", {}, `What was checked (${r.passing.length})`), h("ul", {}, r.passing.map(p => h("li", {}, p)))) : null);
  });
  return [
    h("h1", {}, "Lenses"),
    h("p", { class: "sub" }, "Built-in lenses, plugin crates and external tools. Add tools under [[external]] in the settings file."),
    ...cards,
  ];
}

const SETTINGS = [
  ["Lenstica", [
    { path: ["min_days"], label: "Minimum release age, in days", type: "number", min: 1, max: 365, recommended: 7,
      why: "7 days would have kept out 8 of the 10 best-known supply-chain attacks of 2024-2025; most are caught and pulled within a week." },
    { path: ["monitor", "auto_apply"], label: "Re-apply automatically when a package manager drifts or is newly installed", type: "bool" },
    { path: ["monitor", "interval_minutes"], label: "Re-check package-manager settings every (minutes)", type: "number", min: 1 },
  ]],
  ["Alerts", [
    { path: ["monitor", "alert_severity"], label: "Lowest severity that needs attention (menu bar icon, counts, lenstica check)", type: "select", options: ["low", "medium", "high", "critical"] },
  ]],
  "notifications",
  "checks",
  "managers",
  ["Where to look", [
    { path: ["scan", "roots"], label: "Include: project folders to search, one per line. List single repositories here to search only those.", type: "list" },
    { path: ["scan", "exclude"], label: "Exclude: folders to leave out, one per line. A path skips that folder and everything in it; a bare name (fixtures) skips every folder called that.", type: "list" },
    { path: ["scan", "worktrees"], label: "Also every git worktree of the repositories found there", type: "bool" },
    { path: ["scan", "max_depth"], label: "Folder depth", type: "number", min: 1, max: 20 },
  ]],
  "repos",
  ["Installed packages", [
    { path: ["audit", "enabled"], label: "Check locked and installed packages", type: "bool" },
    { path: ["audit", "global"], label: "Include global installs (npm -g, pnpm -g, uv tools, pip --user, cargo install)", type: "bool" },
    { path: ["audit", "interval_minutes"], label: "Re-check every (minutes)", type: "number", min: 1 },
    { path: ["audit", "ignore"], label: "Packages never to flag: name or name@version, one per line", type: "list" },
  ]],
  ["Installed software", [
    { path: ["software", "package_managers"], label: "The package managers themselves (npm, pnpm, Yarn, Bun, Deno, uv, pip, Poetry, Cargo)", type: "bool" },
    { path: ["software", "homebrew"], label: "Homebrew formulae (sqlite, node, git…), dated by their published bottle", type: "bool" },
    { path: ["software", "casks"], label: "Homebrew casks (apps), dated by their download; apps that update themselves are skipped", type: "bool" },
    { path: ["software", "rust_toolchains"], label: "Rust toolchains installed with rustup", type: "bool" },
    { path: ["software", "node"], label: "Node.js, when it is not from Homebrew", type: "bool" },
    { path: ["software", "ignore"], label: "Software never to flag: name or name@version, one per line", type: "list" },
  ]],
  ["Install scripts", [
    { path: ["install_scripts", "block"], label: "Block dependencies' install scripts (npm ignore-scripts, Yarn enableScripts: false)", type: "bool" },
  ]],
  ["Homebrew", [
    { path: ["homebrew", "no_auto_update"], label: "Stop Homebrew updating itself before every install (HOMEBREW_NO_AUTO_UPDATE=1 in ~/.homebrew/brew.env). New versions then arrive only with brew update.", type: "bool" },
  ]],
  "agents",
];

const toggle = (checked, onchange, title) => h("label", { class: "switch", title },
  h("input", { type: "checkbox", checked: !!checked, onchange: e => onchange(e.target.checked) }), h("span"));
const labelled = (text, note) => h("label", {}, text, note ? h("div", { class: "note" }, note) : null);

function notificationsGroup() {
  const m = ui.state.settings.monitor;
  const on = !!m.notify;
  const save = (key, value) => post({ type: "setting", path: ["monitor", key], value });
  const levels = [["", `Same as above (${m.alert_severity})`], ["low", "low"], ["medium", "medium"], ["high", "high"], ["critical", "critical"]];
  return [
    h("h2", {}, "Notifications"),
    h("p", { class: "sub" }, "Desktop notifications for new findings. Each finding is notified once; everything is still listed here and in the menu."),
    h("div", { class: "card form" },
      h("div", { class: "field" }, labelled("Show desktop notifications"), toggle(on, v => save("notify", v)),
        h("button", { class: "btn small", disabled: !on, onclick: () => post({ type: "testNotification" }) }, "Send a test")),
      h("div", { class: `field ${on ? "" : "off"}` }, labelled("Notify from this severity up"),
        h("select", { disabled: !on, onchange: e => save("notify_severity", e.target.value) },
          levels.map(([v, label]) => h("option", { value: v, selected: v === (m.notify_severity || "") }, label)))),
      h("div", { class: `field ${on ? "" : "off"}` }, labelled("Also when Lenstica restores a package manager's setting by itself"),
        toggle(m.notify_fixes, v => save("notify_fixes", v))),
      ui.state.lenses.filter(c => c.enabled).map(c => h("div", { class: `field indent ${on ? "" : "off"}` },
        labelled(`Notify about ${c.title}`),
        toggle(c.notify, v => post({ type: "setting", path: ["lenses", c.id, "notify"], value: v }))))),
  ];
}

function agentsGroup() {
  const a = ui.state.agent;
  return [
    h("h2", {}, "AI agents"),
    h("p", { class: "sub" }, "Let a coding agent read Lenstica's findings and fix them. Every finding also has Copy prompt for AI agent, here and in the menu bar."),
    h("div", { class: "card form" },
      h("div", { class: "field" },
        labelled("Skill for Claude Code", a.skillInstalled ? `Installed at ${a.skillPath}. Teaches the agent the Lenstica CLI.` : `Teaches the agent the Lenstica CLI. Installs to ${a.skillPath}.`),
        h("button", { class: "btn", onclick: () => post({ type: "installSkill" }) }, icon("bot"), a.skillInstalled ? "Reinstall" : "Install")),
      h("div", { class: "field" },
        labelled("MCP server for Claude Code", h("code", {}, a.mcpCommand)),
        h("button", { class: "btn", onclick: () => post({ type: "copyText", text: a.mcpCommand }) }, icon("copy"), "Copy command")),
      h("div", { class: "field" },
        labelled("MCP server for other agents (Claude Desktop, Cursor…)", "Their mcpServers setting"),
        h("button", { class: "btn", onclick: () => post({ type: "copyText", text: a.mcpJson }) }, icon("copy"), "Copy JSON"))),
  ];
}

function checksGroup() {
  return [
    h("h2", {}, "Checks"),
    h("p", { class: "sub" }, "Turn each check on or off. How often each runs and its own options are on the Lenses page and in the settings file."),
    h("div", { class: "card form" }, ui.state.lenses.map(c => h("div", { class: "field" },
      labelled(c.title, c.description),
      toggle(c.enabled, on => post({ type: "toggleLens", id: c.id, enabled: on }), c.enabled ? "Turn off" : "Turn on")))),
  ];
}

function managersGroup() {
  return [
    h("div", { class: "row heading" }, h("h2", {}, "Package managers"), h("span", { class: "spacer" }),
      h("button", { class: "btn small", title: "Write the minimum age into every package manager that is on", onclick: () => post({ type: "apply" }) }, icon("wrench"), "Apply now")),
    h("p", { class: "sub" }, "Which package managers Lenstica sets the minimum age in and keeps an eye on. One that is off is left exactly as it is."),
    h("div", { class: "card form" }, ui.state.managers.map(m => h("div", { class: "field" },
      labelled(m.name, m.enabled ? null : "Left alone"),
      toggle(m.enabled, on => post({ type: "toggleManager", id: m.id, enabled: on }))))),
  ];
}

function loadRepos() {
  ui.repos = "loading";
  ui.reposError = null;
  tauri.core.invoke("list_repos")
    .then(list => { ui.repos = list; })
    .catch(e => { ui.repos = []; ui.reposError = String(e); })
    .finally(() => { if (ui.page === "settings") render(); });
}

function reposGroup() {
  if (ui.repos === null) loadRepos();
  const body = ui.repos === "loading" ? [h("div", { class: "field" }, labelled("Looking for repositories…"))]
    : ui.reposError ? [h("div", { class: "field" }, labelled("Could not list repositories", ui.reposError))]
    : !ui.repos.length ? [h("div", { class: "field" }, labelled("No git repositories under the folders above"))]
    : ui.repos.map(r => h("div", { class: `field ${r.worktreeOf ? "indent" : ""}` },
        labelled(r.label, r.worktreeOf ? `worktree of ${r.worktreeOf}` : null),
        r.inherited ? h("span", { class: "tag", title: "Left out by a parent folder, its main checkout, or a folder name in Exclude" }, "excluded") : null,
        toggle(!r.excluded, on => post({ type: "toggleExclude", path: r.path, excluded: !on }).then(loadRepos),
          r.excluded ? "Search it again" : "Leave it out")));
  return [
    h("div", { class: "row heading" }, h("h2", {}, "Repositories"), h("span", { class: "spacer" }),
      h("button", { class: "btn small", onclick: loadRepos }, icon("refresh"), "Look again")),
    h("p", { class: "sub" }, "Every repository and worktree found under the folders above. Turning one off adds it to Exclude; leaving out a repository leaves out its worktrees too."),
    h("div", { class: "card form" }, body),
  ];
}

// "Recommended" beside a setting at its recommended value, or a button to go back to it.
function recommendation(s, value, save) {
  if (s.recommended === undefined) return null;
  if (value === s.recommended) return h("span", { class: "tag rec", title: s.why || "" }, icon("check"), "Recommended");
  return h("button", { class: "btn small", title: s.why || "", onclick: () => save(s.path, s.recommended) }, `Use recommended (${s.recommended})`);
}

function settingsPage() {
  const get = path => path.reduce((v, k) => (v == null ? v : v[k]), ui.state.settings);
  const save = (path, value) => post({ type: "setting", path, value }).then(() => {
    if (path[0] === "scan") loadRepos();
  });
  const control = s => {
    const v = get(s.path);
    if (s.type === "bool") return toggle(v, on => save(s.path, on));
    if (s.type === "number") return h("input", { type: "number", value: v, min: s.min, max: s.max, onchange: e => save(s.path, parseInt(e.target.value, 10)) });
    if (s.type === "select") return h("select", { onchange: e => save(s.path, e.target.value) }, s.options.map(o => h("option", { value: o, selected: o === v }, o)));
    return h("textarea", { onchange: e => save(s.path, e.target.value.split("\n").map(x => x.trim()).filter(Boolean)) }, (v || []).join("\n"));
  };
  const special = { notifications: notificationsGroup, checks: checksGroup, managers: managersGroup, repos: reposGroup, agents: agentsGroup };
  const groups = SETTINGS.map(g => typeof g === "string" ? special[g]() : [
    h("h2", {}, g[0]),
    h("div", { class: "card form" }, g[1].map(s => h("div", { class: "field" }, labelled(s.label, s.why), recommendation(s, get(s.path), save), control(s)))),
  ]);
  return [
    h("div", { class: "row" }, h("h1", {}, "Settings"), h("span", { class: "spacer" }),
      h("button", { class: "btn", onclick: () => post({ type: "openConfig" }) }, icon("file"), "Edit settings file…")),
    h("p", { class: "sub" }, `Saved straight to ${ui.state.configPath}, comments kept. External tools and per-lens options live in the file.`),
    ...groups.flat(),
    h("h2", {}, "App"),
    h("div", { class: "card form" }, h("div", { class: "field" }, h("label", {}, "Start the menu bar app at login"),
      toggle(ui.state.autostart, on => post({ type: "autostart", enabled: on })))),
  ];
}

// ---- shell ----------------------------------------------------------------------

function report() {
  post({ type: "rendered", page: ui.page, elements: document.querySelectorAll(".tile, .item, .lens, .field").length });
}

function go(page, filters) {
  ui.page = page;
  // Look for repositories afresh each time Settings opens.
  if (page === "settings") ui.repos = null;
  if (filters) Object.assign(ui, filters);
  ui.selected = null;
  render();
  report();
}

function render() {
  if (!ui.state) return;
  document.querySelectorAll(".nav-item").forEach(b => b.classList.toggle("active", b.dataset.page === ui.page));
  const alerts = allFindings().filter(isAlert).length;
  const count = document.getElementById("nav-count");
  count.hidden = alerts === 0;
  count.textContent = alerts;
  document.getElementById("foot").textContent = `v${ui.state.version}`;
  const main = document.getElementById("main");
  const scroll = main.scrollTop;
  const pages = { overview, findings: findingsPage, lenses: lensesPage, settings: settingsPage };
  // A broken settings file is shown on every page: Lenstica runs on its last good settings meanwhile.
  const banner = ui.state.configError && h("div", { class: "banner" },
    `The settings file has an error, so Lenstica is using its defaults or last good settings: ${ui.state.configError}`,
    h("button", { class: "btn small", onclick: () => post({ type: "openConfig" }) }, "Open settings file"));
  // Pages return elements, possibly nested in arrays; never let an array reach the DOM as text.
  main.replaceChildren(...[banner, pages[ui.page]()].flat(Infinity).filter(Boolean));
  main.scrollTop = scroll;
  if (ui.scrollToSelected) {
    ui.scrollToSelected = false;
    const sel = document.querySelector(".item.sel");
    if (sel) sel.scrollIntoView({ block: "center" });
  }
}

function renderKeepFocus() {
  const el = document.activeElement, pos = el && el.selectionStart;
  render();
  const input = document.querySelector(".search input");
  if (input && el && el.tagName === "INPUT") { input.focus(); input.setSelectionRange(pos, pos); }
}

let reported = false;
window.lenstica = {
  render(state) {
    ui.state = state;
    if (!reported) {
      reported = true;
      // Lets `LENSTICA_DEBUG=1` confirm the native window really rendered.
      setTimeout(report, 0);
    }
    // Don't redraw a form field the user is typing in.
    const active = document.activeElement;
    if (ui.page === "settings" && active && ["INPUT", "TEXTAREA", "SELECT"].includes(active.tagName)) return;
    if (ui.page === "findings" && active && active.closest(".search")) return renderKeepFocus();
    render();
  },
  toast(text, ok) {
    const t = h("div", { class: `toast ${ok ? "" : "bad"}` }, text);
    document.getElementById("toasts").append(t);
    setTimeout(() => t.remove(), ok ? 3500 : 7000);
  },
};

document.querySelectorAll(".nav-item").forEach(b => b.addEventListener("click", () => go(b.dataset.page)));
setInterval(() => ui.state && ui.page === "overview" && render(), 30000);
function fatal(message) {
  document.getElementById("main").replaceChildren(
    h("div", { class: "empty" }, h("b", {}, "The window could not load."), h("pre", {}, message)));
}
window.addEventListener("error", e => { if (!ui.state) fatal(String(e.message || e)); });
window.addEventListener("unhandledrejection", e => { if (!ui.state) fatal(String(e.reason)); });

// Subscribe first, then pull the current state: an event sent before the
// subscription is in place would be lost, and the page would wait forever.
(async () => {
  try {
    await tauri.event.listen("state", e => window.lenstica.render(e.payload));
    await tauri.event.listen("navigate", e => { if (route(e.payload)) { if (ui.page === "settings") ui.repos = null; render(); report(); } });
    await tauri.event.listen("toast", e => window.lenstica.toast(e.payload.text, e.payload.ok));
    window.lenstica.render(await tauri.core.invoke("get_state"));
  } catch (e) {
    fatal(String(e));
  }
})();
