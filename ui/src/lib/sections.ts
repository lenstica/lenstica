// The sections of Settings (`#settings/<id>`), for its section list and the top bar.
import { Bell, Bot, Boxes, FolderGit2, ListChecks, SlidersHorizontal } from "@lucide/svelte";
import { t } from "./i18n/index.svelte";

const IDS = ["general", "notifications", "managers", "projects", "checks", "agents"] as const;
export type SectionId = (typeof IDS)[number];
const ICONS = { general: SlidersHorizontal, notifications: Bell, managers: Boxes, projects: FolderGit2, checks: ListChecks, agents: Bot };

/** Each section, named in the window's language. */
export const sections = () =>
  IDS.map((id) => ({ id, icon: ICONS[id], title: t(`settings.sections.${id}.title`), about: t(`settings.sections.${id}.about`) }));

/** The section an address names, or the first. */
export const sectionOf = (id: string | null) => sections().find((x) => x.id === id) ?? sections()[0];
