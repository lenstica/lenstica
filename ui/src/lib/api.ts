// The bridge to Rust: one `action` command for everything the window asks
// for, `get_state`, `list_repos`, `list_listening` and `list_assets`, and the
// `state`, `navigate` and `toast` events.
import type { AssetKind, Discovery, Listening, PromptKind, Repo, State } from "./types";

declare global {
  interface Window {
    __TAURI__: {
      core: { invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> };
      event: { listen<T>(event: string, handler: (e: { payload: T }) => void): Promise<() => void> };
    };
  }
}

const tauri = () => window.__TAURI__;

let onError: (message: string) => void = () => {};
export function reportErrorsTo(handler: (message: string) => void) {
  onError = handler;
}

/** Ask the app to do something; a failure is shown as a toast. */
export function post(msg: Record<string, unknown>): Promise<void> {
  return tauri()
    .core.invoke<void>("action", { msg })
    .catch((e) => onError(String(e)));
}

export const getState = () => tauri().core.invoke<State>("get_state");
export const listRepos = () => tauri().core.invoke<Repo[]>("list_repos");
/** Every program accepting TCP connections now, for the Network page. */
export const listListening = () => tauri().core.invoke<Listening[]>("list_listening");
/** What is on this machine: every kind of asset, or only these. */
export const listAssets = (kinds?: AssetKind[]) => tauri().core.invoke<Discovery[]>("list_assets", { kinds: kinds ?? null });
/** The prompt Copy Prompt for AI Agent would copy for these findings (no key: all of a lens's alerts). */
export const promptText = (items: { lens: string; key?: string }[]) =>
  tauri().core.invoke<{ text: string; count: number }>("prompt_text", { items });
/** What these prompt templates would write, for one finding and for several; rejects with what is wrong. */
export const previewPrompt = (templates: Record<PromptKind, string>) =>
  tauri().core.invoke<{ one: string; many: string; real: boolean }>("preview_prompt", templates);
export const listen = <T>(event: string, handler: (payload: T) => void) =>
  tauri().event.listen<T>(event, (e) => handler(e.payload));
