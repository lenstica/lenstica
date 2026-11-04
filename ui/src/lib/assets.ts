// The kinds of asset (`#assets/<kind>`), for the sidebar, the top bar and their pages.
import { Blocks, Container, GitBranch, IdCard, MonitorCog, Puzzle } from "@lucide/svelte";
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
