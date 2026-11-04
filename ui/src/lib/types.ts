// What the Rust side sends (src/gui/mod.rs `state`, src/gui/commands.rs).

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface Location {
  label: string;
  path?: string;
  line?: number;
}

export interface Finding {
  key: string;
  severity: Severity;
  category: string;
  topic?: string;
  title: string;
  detail: string;
  locations: Location[];
  remedy: string;
  links: string[];
  fixable: boolean;
  lens: string;
}

export interface RunResult {
  id: string;
  title: string;
  summary: string;
  passing: string[];
  findings: Finding[];
  ran_at: string;
  seconds: number;
  error: string | null;
}

export interface Lens {
  id: string;
  title: string;
  description: string;
  origin: string;
  categories: string[];
  thirdParty: string | null;
  enabled: boolean;
  notify: boolean;
  intervalMinutes: number;
  running: boolean;
  result: RunResult | null;
}

export interface Topic {
  id: string;
  title: string;
}

export interface Category {
  id: string;
  title: string;
  description: string;
  topics: Topic[];
}

export interface Manager {
  id: string;
  name: string;
  enabled: boolean;
}

export type PromptKind = "finding" | "findings" | "item";

export interface State {
  version: string;
  /** The project's GitHub address. */
  repository: string;
  /** `macos`, `windows`, `linux`: macOS draws its window buttons over the top bar. */
  platform: string;
  /** The system's preferred languages, most preferred first: `["uk-UA", "en-US"]`. */
  systemLanguages: string[];
  categories: Category[];
  /** Lenstica's own prompt templates, and the values each can insert. */
  prompts: {
    defaults: Record<PromptKind, string>;
    values: Record<PromptKind, { name: string; about: string }[]>;
  };
  managers: Manager[];
  agent: { skillInstalled: boolean; skillPath: string; mcpCommand: string; mcpJson: string };
  configPath: string;
  configError: string | null;
  alertSeverity: Severity;
  settings: Record<string, any>;
  /** The editors, terminals and file managers installed, for Settings to offer. */
  apps: { editors: string[]; terminals: string[]; files: string[] };
  lenses: Lens[];
  autostart: boolean;
  now: string;
}

export interface Repo {
  path: string;
  label: string;
  worktreeOf: string | null;
  mainPath: string;
  excluded: boolean;
  inherited: boolean;
}

/** A finding as the window shows it: with its lens's title and the projects it is in. */
export interface Item extends Finding {
  id: string;
  lensTitle: string;
  /** Main checkout paths, or "mac" for a location in no project. */
  scopes: Set<string>;
}

/** One program listening on one TCP port (src/network.rs). */
export interface Listening {
  process: string;
  path: string;
  pids: number[];
  port: number;
  /** `0.0.0.0:5432, [::]:5432`. */
  sockets: string;
  /** `network`: other devices can connect; `local`: only this machine. */
  reach: "network" | "local";
  allInterfaces: boolean;
  /** The listening-ports finding that covers it, when other devices can reach it. */
  findingKey: string | null;
}

/** A kind of asset: a page under Assets in the sidebar (src/assets/mod.rs). */
export type AssetKind = "identities" | "repositories" | "applications" | "containers" | "virtual-machines" | "extensions";

/** What an app may do beyond its own files, or was refused (src/assets/mod.rs `PERMISSIONS`). */
export interface Permission {
  key: string;
  /** Rust's English, for a key the window has no translation for. */
  label: string;
  /** Reaches beyond the app: every file, the screen, the keyboard, other apps, the system. */
  elevated: boolean;
  allowed: boolean;
  by?: "user" | "organization" | "system";
  /** What it applies to: the app Automation controls, a Flatpak's folders. */
  detail?: string;
  /** System Settings has a pane for it. */
  settings: boolean;
}

/** One thing on this machine: an account, a repository, an app, a container… */
export interface Asset {
  /** Unique within its kind. */
  id: string;
  name: string;
  /** What it comes from or runs on (`AWS`, `Docker Desktop`); empty for none. */
  source: string;
  status?: "running" | "paused" | "stopped";
  path?: string;
  /** `label` is Rust's English, for a key the window has no translation for. */
  facts: { key: string; label: string; value: string }[];
  tags: { key: string; label: string }[];
  /** Applications only, allowed first. */
  permissions?: Permission[];
}

/** What one look for a kind of asset found. */
export interface Discovery {
  kind: AssetKind;
  supported: boolean;
  assets: Asset[];
  /** Tools installed but not running, so what they hold is missing. */
  notRunning: string[];
  /** Sources that could not be read. */
  errors: string[];
  /** Sources macOS keeps from apps without Full Disk Access. */
  blocked: string[];
  /** What a look could not include, by key (`assets.notes`). */
  notes: string[];
  seconds: number;
}
