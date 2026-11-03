import { AppWindow, Bot, Bug, EyeOff, KeyRound, Network, Package, Shapes } from "@lucide/svelte";

/** Each category's icon; a category the window does not know gets a generic one. */
export function categoryIcon(id: string) {
  return (
    { agents: Bot, packages: Package, software: AppWindow, secrets: KeyRound, malware: Bug, network: Network, privacy: EyeOff }[id] ?? Shapes
  );
}
