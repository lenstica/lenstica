// The apps that open a path (Settings → General, `[apps]`): what each button
// is called, and what Settings offers. `system` is the platform's own.
import { t } from "./i18n/index.svelte";
import { model } from "./model.svelte";

export type Role = "editor" | "files" | "terminal";

/** Shorter names for buttons; the rest fit as they are. */
const SHORT: Record<string, string> = {
  "Visual Studio Code": "VS Code",
  "IntelliJ IDEA CE": "IntelliJ IDEA",
  "PyCharm CE": "PyCharm",
  "Nimble Commander": "Nimble",
  "Commander One": "Commander One",
  "gnome-terminal": "Terminal",
  "gnome-text-editor": "Text Editor",
  "xfce4-terminal": "Terminal",
  wt: "Windows Terminal",
};

const picked = (role: Role): string | null => {
  const v = String(model.state?.settings?.apps?.[role] ?? "system").trim();
  return v && v !== "system" ? v : null;
};

/** The system's own, by name where the platform has one. */
export function systemName(role: Role): string | null {
  const p = model.state?.platform;
  if (role === "files") return p === "macos" ? "Finder" : p === "windows" ? "File Explorer" : null;
  if (role === "terminal") return p === "macos" ? "Terminal" : null;
  return null;
}

/** A button's name: the picked app, the system's by name, or what it is. */
export function appName(role: Role): string {
  const app = picked(role);
  if (app) return SHORT[app] ?? app;
  return systemName(role) ?? t(`open.${role}`);
}

/** What the button does, for its tooltip and screen readers: "Show in Finder". */
export function appAction(role: Role): string {
  return t(`open.${role}Title`, { app: appName(role) });
}

/** Settings' choices: the system's own first, then each installed one (and the one set, if it is not found). */
export function appOptions(role: Role): { value: string; label: string }[] {
  const found: string[] = model.state?.apps?.[role === "editor" ? "editors" : role === "files" ? "files" : "terminals"] ?? [];
  const own = systemName(role);
  const set = picked(role);
  const list = found.filter((a) => a !== own);
  if (set && !list.includes(set) && set !== own) list.push(set);
  return [{ value: "system", label: own ?? t("settings.fields.systemDefault") }, ...list.map((a) => ({ value: a, label: a }))];
}
