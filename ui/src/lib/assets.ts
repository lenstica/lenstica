// The kinds of asset (`#assets/<kind>`), for the sidebar, the top bar and their pages.
import {
  Apple,
  AppWindow,
  Beer,
  Blocks,
  Bot,
  Box,
  Cloud,
  Code,
  Container,
  GitBranch,
  Globe,
  IdCard,
  KeyRound,
  MonitorCog,
  Package,
  Puzzle,
  ShipWheel,
  ShoppingBag,
  Sparkles,
  Terminal,
} from "@lucide/svelte";
import { tOr } from "./i18n/index.svelte";
import type { Asset, AssetKind, Permission } from "./types";

export const KINDS: AssetKind[] = ["identities", "repositories", "applications", "containers", "virtual-machines", "extensions"];

const ICONS = {
  identities: IdCard,
  repositories: GitBranch,
  applications: Blocks,
  containers: Container,
  "virtual-machines": MonitorCog,
  extensions: Puzzle,
};

export const isKind = (id: string | null): id is AssetKind => KINDS.includes(id as AssetKind);
export const kindIcon = (kind: AssetKind) => ICONS[kind];
export const kindTitle = (kind: AssetKind) => tOr(`assets.kinds.${kind}.title`, kind);
export const kindDescription = (kind: AssetKind) => tOr(`assets.kinds.${kind}.description`, "");
/**
 * Each source's icon and tint, so a list reads at a glance: a cloud for a
 * cloud account, a key for SSH, a package for a registry. Not brand logos;
 * a source not named here gets its kind's icon, untinted.
 */
const SOURCES: Record<string, [typeof Cloud, string]> = {
  // Identities
  Git: [GitBranch, "#f05033"],
  SSH: [KeyRound, "#30c47e"],
  "GitHub CLI": [Terminal, "#8b8b94"],
  AWS: [Cloud, "#ff9900"],
  "Google Cloud": [Cloud, "#4f8ff7"],
  Azure: [Cloud, "#0ea5e9"],
  Kubernetes: [ShipWheel, "#5b7fea"],
  Docker: [Container, "#2496ed"],
  npm: [Package, "#e5484d"],
  PyPI: [Package, "#e0b030"],
  Cargo: [Package, "#c98a4b"],
  netrc: [KeyRound, "#8b8b94"],
  "Claude Code": [Sparkles, "#d97757"],
  Codex: [Bot, "#10a37f"],
  // Repositories
  GitHub: [GitBranch, "#8b8b94"],
  GitLab: [GitBranch, "#fc6d26"],
  Bitbucket: [GitBranch, "#2684ff"],
  Codeberg: [GitBranch, "#2185d0"],
  // Applications
  "App Store": [ShoppingBag, "#0a84ff"],
  Homebrew: [Beer, "#f0a030"],
  Apple: [Apple, "#8b8b94"],
  Flatpak: [Package, "#4a90d9"],
  AppImage: [Box, "#8b8b94"],
  // Containers
  "Docker Desktop": [Container, "#2496ed"],
  OrbStack: [Container, "#8b5cf6"],
  Colima: [Container, "#e0a030"],
  "Rancher Desktop": [Container, "#2a9fd6"],
  Podman: [Container, "#892ca0"],
  // Extensions
  "VS Code": [Code, "#23a9f2"],
  Cursor: [Code, "#8b8b94"],
  Windsurf: [Code, "#34c99a"],
  VSCodium: [Code, "#2f80ed"],
  Zed: [Code, "#a78bfa"],
  Chrome: [Globe, "#4285f4"],
  Brave: [Globe, "#fb542b"],
  Edge: [Globe, "#0ea5e9"],
  Arc: [Globe, "#f43f5e"],
  Vivaldi: [Globe, "#ef3939"],
  Firefox: [Globe, "#ff7139"],
};
const NO_SOURCE = { applications: AppWindow } as Partial<Record<AssetKind, typeof Cloud>>;
export function sourceIcon(kind: AssetKind, source: string): { icon: typeof Cloud; tint: string | null } {
  const known = SOURCES[source];
  return known ? { icon: known[0], tint: known[1] } : { icon: (!source && NO_SOURCE[kind]) || ICONS[kind], tint: null };
}
/** The heading for assets without a source: "No remote", "Other". */
export const sourceTitle = (kind: AssetKind, source: string) => source || tOr(`assets.kinds.${kind}.noSource`, tOr("assets.noSource", "Other"));
export const factLabel = (f: Asset["facts"][number]) => tOr(`assets.facts.${f.key}`, f.label);
export const tagLabel = (tag: Asset["tags"][number]) => tOr(`assets.tags.${tag.key}`, tag.label);
export const permissionTitle = (p: Permission) => tOr(`assets.permissions.${p.key}.title`, p.label);
export const permissionAbout = (p: Permission) => tOr(`assets.permissions.${p.key}.about`, "");
/** "Full Disk Access, Accessibility, Screen Recording +2": each permission once, elevated first. */
export function permissionSummary(list: Permission[]) {
  const names = [...new Set(list.map(permissionTitle))];
  return names.slice(0, 3).join(", ") + (names.length > 3 ? ` +${names.length - 3}` : "");
}
