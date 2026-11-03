// The window's state: what Rust sent, the repositories and assets found, the
// selected project, the page, and everything derived from them.
import { getState, listAssets, listRepos, listen, post, reportErrorsTo } from "./api";
import { isKind, KINDS } from "./assets";
import { t, tOr } from "./i18n/index.svelte";
import type { Asset, AssetKind, Category, Discovery, Item, Lens, Location, Repo, Severity, State } from "./types";

export const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];
export const rank = (s: Severity) => SEVERITIES.indexOf(s);

/** `#overview`, `#<category>`, `#<category>/<lens|key>` for one finding,
 * `#assets/<kind>`, `#settings` or `#settings/<section>`. */
export interface Route {
  page: string;
  /** The finding on a category page, the kind of asset, or the section of Settings. */
  sub: string | null;
}

export function parseRoute(hash: string): Route {
  const [page, ...rest] = hash.replace(/^#/, "").split("/");
  // `findings` and `lenses` were pages before there were categories.
  if (!page || page === "findings" || page === "lenses") return { page: "overview", sub: null };
  return { page, sub: rest.length ? decodeURIComponent(rest.join("/")) : null };
}

/** The selected project: "all", "mac" (findings in no repository), or a main checkout's path. */
export const ALL = "all";
export const MAC = "mac";
const SCOPE_KEY = "lenstica.scope";

/** A path with forward slashes and no trailing slash, to compare. */
export const norm = (p: string) => p.replace(/\\/g, "/").replace(/\/+$/, "");
const basename = (p: string) => norm(p).split("/").pop() || p;

/** How a lens is doing, as one word the UI styles. */
export type LensState = "off" | "running" | "failed" | "never" | "clear" | Severity;

export interface Toast {
  id: number;
  text: string;
  ok: boolean;
}

export interface Project {
  path: string;
  name: string;
  label: string;
  worktrees: number;
}

class Model {
  state = $state<State | null>(null);
  repos = $state<Repo[]>([]);
  reposStatus = $state<"idle" | "loading" | "done" | "error">("idle");
  reposError = $state<string | null>(null);
  scope = $state<string>(localStorage.getItem(SCOPE_KEY) ?? ALL);
  route = $state<Route>(parseRoute(location.hash));
  toasts = $state<Toast[]>([]);
  loadError = $state<string | null>(null);
  /** The clock "5 min ago" is measured against, ticking every 30 seconds. */
  now = $state(Date.now());
  /** The prompt being shown before it is copied: for which findings, described. */
  prompt = $state<{ items: { lens: string; key: string }[]; about: string } | null>(null);
  /** Where Back and Forward go. */
  past = $state<Route[]>([]);
  future = $state<Route[]>([]);
  /** What is on this machine, by kind, as last looked for. */
  assets = $state<Partial<Record<AssetKind, Discovery>>>({});
  /** When each kind was last looked for, and which are being looked for now. */
  assetsAt = $state<Partial<Record<AssetKind, number>>>({});
  assetsLoading = $state<AssetKind[]>([]);
  assetsError = $state<string | null>(null);

  threshold = $derived(rank(this.state?.alertSeverity ?? "medium"));

  /** Every repository root, deepest first, with the project it belongs to. */
  roots = $derived(
    this.repos
      .map((r) => ({ path: norm(r.path), main: norm(r.mainPath) }))
      .sort((a, b) => b.path.length - a.path.length),
  );

  /** The projects in the picker: main checkouts that are searched, by name. */
  projects = $derived.by<Project[]>(() => {
    const worktrees = new Map<string, number>();
    for (const r of this.repos) {
      if (r.worktreeOf) worktrees.set(norm(r.mainPath), (worktrees.get(norm(r.mainPath)) ?? 0) + 1);
    }
    return this.repos
      .filter((r) => !r.worktreeOf && !r.excluded)
      .map((r) => ({ path: norm(r.path), name: basename(r.path), label: r.label, worktrees: worktrees.get(norm(r.path)) ?? 0 }))
      .sort((a, b) => a.name.localeCompare(b.name));
  });

  /** Categories some lens covers, on or off, in order. */
  categories = $derived<Category[]>(
    (this.state?.categories ?? []).filter((c) => this.state!.lenses.some((l) => l.categories.includes(c.id))),
  );

  /** Every finding of every lens that is on. */
  items = $derived.by<Item[]>(() => {
    const out: Item[] = [];
    for (const lens of this.state?.lenses ?? []) {
      if (!lens.enabled || !lens.result) continue;
      for (const f of lens.result.findings) {
        const scopes = new Set(f.locations.length ? f.locations.map((l) => this.scopeOf(l)) : [MAC]);
        out.push({ ...f, id: `${f.lens}|${f.key}`, lensTitle: lens.title, scopes });
      }
    }
    return out.sort((a, b) => rank(b.severity) - rank(a.severity) || a.title.localeCompare(b.title));
  });

  /** The findings in the selected project, with only that project's locations. */
  scoped = $derived.by<Item[]>(() => {
    const scope = this.scope;
    if (scope === ALL) return this.items;
    return this.items
      .filter((i) => i.scopes.has(scope))
      .map((i) => ({ ...i, locations: i.locations.filter((l) => this.scopeOf(l) === scope) }));
  });

  /** Findings needing attention per project, "mac" and "all". */
  alertCounts = $derived.by(() => {
    const counts = new Map<string, number>([[ALL, 0], [MAC, 0]]);
    for (const i of this.items) {
      if (!this.isAlert(i)) continue;
      counts.set(ALL, counts.get(ALL)! + 1);
      for (const s of i.scopes) counts.set(s, (counts.get(s) ?? 0) + 1);
    }
    return counts;
  });

  scopeTitle = $derived(
    this.scope === ALL
      ? t("project.all")
      : this.scope === MAC
        ? t("project.mac")
        : (this.projects.find((p) => p.path === this.scope)?.name ?? basename(this.scope)),
  );

  /** The project a location is in: its deepest repository's main checkout, or "mac". */
  scopeOf(l: Location): string {
    if (!l.path) return MAC;
    const p = norm(l.path);
    for (const r of this.roots) if (p === r.path || p.startsWith(r.path + "/")) return r.main;
    return MAC;
  }

  isAlert = (i: { severity: Severity }) => rank(i.severity) >= this.threshold;

  lensesIn = (category: string): Lens[] => (this.state?.lenses ?? []).filter((l) => l.categories.includes(category));
  itemsIn = (category: string): Item[] => this.scoped.filter((i) => i.category === category);
  alertsIn = (category: string): Item[] => this.itemsIn(category).filter(this.isAlert);

  /** The findings about an asset: a repository's are its project's; anything
   * else's are those with a location in its file or folder. */
  findingsAbout(kind: AssetKind, a: Asset): Item[] {
    if (!a.path) return [];
    const p = norm(a.path);
    if (kind === "repositories") return this.items.filter((i) => i.scopes.has(p));
    return this.items.filter((i) => i.locations.some((l) => l.path && (norm(l.path) === p || norm(l.path).startsWith(p + "/"))));
  }

  lensState(lens: Lens): LensState {
    if (!lens.enabled) return "off";
    if (lens.running) return "running";
    if (!lens.result) return "never";
    if (lens.result.error) return "failed";
    const worst = this.scoped
      .filter((i) => i.lens === lens.id && this.isAlert(i))
      .reduce((m, i) => Math.max(m, rank(i.severity)), -1);
    return worst < 0 ? "clear" : SEVERITIES[worst];
  }

  categoryState(category: string): LensState {
    const on = this.lensesIn(category).filter((l) => l.enabled);
    if (!on.length) return "off";
    if (on.some((l) => l.running)) return "running";
    const worst = this.alertsIn(category).reduce((m, i) => Math.max(m, rank(i.severity)), -1);
    if (worst >= 0) return SEVERITIES[worst];
    if (on.some((l) => l.result?.error)) return "failed";
    if (on.some((l) => !l.result)) return "never";
    return "clear";
  }

  setScope(scope: string) {
    this.scope = scope;
    localStorage.setItem(SCOPE_KEY, scope);
  }

  /** Go to a page, remembering the one left for Back. */
  go(page: string, sub: string | null = null) {
    // Asked again for the page already shown (the menu's Show in Lenstica for
    // the same finding): show it afresh, but it is not a step to go back to.
    if (page !== this.route.page || sub !== this.route.sub) {
      this.past.push(this.route);
      this.future = [];
    }
    this.show({ page, sub });
  }

  back() {
    const to = this.past.pop();
    if (!to) return;
    this.future.push(this.route);
    this.show(to);
  }

  forward() {
    const to = this.future.pop();
    if (!to) return;
    this.past.push(this.route);
    this.show(to);
  }

  private show({ page, sub }: Route) {
    const wasSettings = this.route.page === "settings";
    this.route = { page, sub };
    const hash = sub ? `${page}/${encodeURIComponent(sub)}` : page;
    history.replaceState(null, "", `#${hash}`);
    post({ type: "rendered", page });
    // Look for repositories afresh each time Settings opens, and for a kind of asset when its page does.
    if (page === "settings" && !wasSettings) this.loadRepos();
    if (page === "assets" && isKind(sub)) this.loadAssets([sub]);
  }

  /** Show the prompt for these findings, to read before copying it. */
  showPrompt(items: { lens: string; key: string }[], about: string) {
    this.prompt = { items, about };
  }

  toast(text: string, ok: boolean) {
    const id = Date.now() + Math.random();
    this.toasts.push({ id, text, ok });
    setTimeout(() => (this.toasts = this.toasts.filter((t) => t.id !== id)), ok ? 3500 : 7000);
  }

  loadRepos() {
    this.reposStatus = "loading";
    listRepos()
      .then((repos) => {
        // One entry per path, whatever reached it twice.
        this.repos = [...new Map(repos.map((r) => [norm(r.path), r])).values()];
        this.reposStatus = "done";
        this.reposError = null;
        const known = this.scope === ALL || this.scope === MAC || this.projects.some((p) => p.path === this.scope);
        if (!known) this.setScope(ALL);
      })
      .catch((e) => {
        this.reposStatus = "error";
        this.reposError = String(e);
      });
  }

  /** Look for these kinds of asset (every kind by default). A kind looked for
   * in the last 15 seconds, or being looked for now, is left alone unless `again`. */
  loadAssets(kinds: AssetKind[] = KINDS, again = false) {
    const now = Date.now();
    const asking = kinds.filter(
      (k) => !this.assetsLoading.includes(k) && (again || now - (this.assetsAt[k] ?? 0) > 15_000),
    );
    if (!asking.length) return;
    this.assetsLoading = [...this.assetsLoading, ...asking];
    listAssets(asking)
      .then((list) => {
        for (const d of list) {
          this.assets[d.kind] = d;
          this.assetsAt[d.kind] = Date.now();
        }
        this.assetsError = null;
      })
      .catch((e) => (this.assetsError = String(e)))
      .finally(() => (this.assetsLoading = this.assetsLoading.filter((k) => !asking.includes(k))));
  }

  /** Subscribe first, then pull the state: an event sent before the
   * subscription is in place would be lost, and the page would wait forever. */
  async start() {
    reportErrorsTo((m) => this.toast(m, false));
    setInterval(() => (this.now = Date.now()), 30_000);
    try {
      await listen<State>("state", (s) => (this.state = s));
      await listen<string>("navigate", (target) => {
        const r = parseRoute(target);
        this.go(r.page, r.sub);
      });
      await listen<{ text: string; ok: boolean }>("toast", (t) => this.toast(t.text, t.ok));
      this.state = await getState();
      this.loadRepos();
      this.loadAssets();
      post({ type: "rendered", page: this.route.page });
    } catch (e) {
      this.loadError = String(e);
    }
  }
}

export const model = new Model();

/** A category's name and description in the window's language (Rust's English if a translation lacks it). */
export const categoryTitle = (c: Category) => tOr(`categories.${c.id}.title`, c.title);
export const categoryDescription = (c: Category) => tOr(`categories.${c.id}.description`, c.description);
/** A topic's name: its translation, the category's own title for it, or its id. */
export const topicTitle = (c: Category | undefined, id: string) =>
  tOr(`topics.${id}`, c?.topics.find((x) => x.id === id)?.title ?? id);
