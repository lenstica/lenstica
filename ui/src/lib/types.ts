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
