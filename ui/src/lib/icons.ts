import { AppWindow, Bot, Bug, Circle, CircleAlert, EyeOff, Info, KeyRound, Network, OctagonAlert, Package, Shapes, TriangleAlert } from "@lucide/svelte";
import type { Severity } from "./types";

/** Each severity's icon (octagon critical, triangle high, circle medium, i low, ring info, as in the menu) and colour. */
export const severityIcon = (s: Severity) => ({ critical: OctagonAlert, high: TriangleAlert, medium: CircleAlert, low: Info, info: Circle })[s];
export const severityTint = (s: Severity) => `var(--t-${s})`;

/** Each category's icon; a category the window does not know gets a generic one. */
export function categoryIcon(id: string) {
  return (
    { agents: Bot, packages: Package, software: AppWindow, secrets: KeyRound, malware: Bug, network: Network, privacy: EyeOff }[id] ?? Shapes
  );
}
