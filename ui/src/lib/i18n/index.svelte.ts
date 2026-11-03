// The window's languages. Every word the app shows comes from a message file
// in the repository's `i18n/` (one per language, shared with the menu bar and
// notifications) through `t("page.key", { values })`; English (`en.json`) is
// the source and the fallback for anything a translation leaves out.
//
// To add a language, add `i18n/<code>.json` (see docs/translating.md): the
// window finds it, and Settings → General → Language offers it.
import en from "../../../../i18n/en.json";

export type Messages = typeof en;

/** A message that depends on a count, in the plural forms Intl.PluralRules names. */
type Plural = { zero?: string; one?: string; two?: string; few?: string; many?: string; other: string };

/** A translation: any part of the English messages, with the same shape. */
export type Translation = { [K in keyof Messages]?: Partial<DeepPartial<Messages[K]>> };
type DeepPartial<T> = { [K in keyof T]?: T[K] extends string ? string : T[K] extends Plural ? Plural : DeepPartial<T[K]> };

/** Every message's key, "settings.title", so a mistyped key fails the type check. */
type Paths<T, P extends string = ""> = {
  [K in keyof T & string]: T[K] extends string | { other: string } ? `${P}${K}` : Paths<T[K], `${P}${K}.`>;
}[keyof T & string];
export type Key = Paths<Messages>;

const files = import.meta.glob<Translation & { language?: { name?: string } }>("../../../../i18n/*.json", {
  eager: true,
  import: "default",
});

/** The languages the window speaks, English first: code, name in that language, messages. */
export const LANGUAGES: { code: string; name: string; messages: Translation }[] = Object.entries(files)
  .map(([path, messages]) => {
    const code = path.split("/").pop()!.replace(/\.json$/, "");
    return { code, name: messages.language?.name ?? code, messages };
  })
  .sort((a, b) => (a.code === "en" ? -1 : b.code === "en" ? 1 : a.name.localeCompare(b.name)));

/** The best language for a list of preferred ones: an exact match, then the base language. */
function pick(preferred: readonly string[]): string {
  for (const tag of preferred) {
    const lower = tag.toLowerCase();
    const hit =
      LANGUAGES.find((l) => l.code.toLowerCase() === lower) ??
      LANGUAGES.find((l) => l.code.toLowerCase() === lower.split("-")[0]);
    if (hit) return hit.code;
  }
  return "en";
}

class I18n {
  /** "system", or a language code: Settings → General → Language (`window.language`). */
  choice = $state("system");
  /** The system's preferred languages: the app reads them (the web view may only report English). */
  system = $state<readonly string[]>(navigator.languages ?? [navigator.language]);
  /** The language "system" means: the first of the system's the window speaks. */
  systemLocale = $derived(pick(this.system));
  locale = $derived(this.choice === "system" ? this.systemLocale : pick([this.choice]));
  messages = $derived(LANGUAGES.find((l) => l.code === this.locale)?.messages ?? en);
  plurals = $derived(new Intl.PluralRules(this.locale));
  numbers = $derived(new Intl.NumberFormat(this.locale));
  relative = $derived(new Intl.RelativeTimeFormat(this.locale, { numeric: "auto" }));
}

export const i18n = new I18n();

function lookup(messages: unknown, key: string): string | Plural | undefined {
  let at: any = messages;
  for (const part of key.split(".")) {
    if (at == null || typeof at !== "object") return undefined;
    at = at[part];
  }
  return typeof at === "string" || (at && typeof at === "object" && "other" in at) ? at : undefined;
}

function fill(message: string | Plural, values: Record<string, string | number>): string {
  const count = values.count;
  const text =
    typeof message === "string"
      ? message
      : (message[i18n.plurals.select(typeof count === "number" ? count : Number(count ?? 0)) as keyof Plural] ?? message.other);
  return text.replace(/\{(\w+)\}/g, (whole, name) => {
    const v = values[name];
    if (v === undefined) return whole;
    return typeof v === "number" ? i18n.numbers.format(v) : v;
  });
}

/** A message in the window's language, with its {placeholders} filled in. */
export function t(key: Key, values: Record<string, string | number> = {}): string {
  const message = lookup(i18n.messages, key) ?? lookup(en, key);
  return message === undefined ? key : fill(message, values);
}

/** A message whose key is only known at run time (a category's id), or `fallback`. */
export function tOr(key: string, fallback: string, values: Record<string, string | number> = {}): string {
  const message = lookup(i18n.messages, key) ?? lookup(en, key);
  return message === undefined ? fallback : fill(message, values);
}

/** "5 minutes ago", "yesterday", in the window's language; `now` is the clock it is measured against. */
export function ago(iso: string | null | undefined, now: number): string {
  if (!iso) return t("time.never");
  const seconds = Math.max(0, (now - Date.parse(iso)) / 1000);
  if (seconds < 60) return t("time.justNow");
  const [value, unit]: [number, Intl.RelativeTimeFormatUnit] =
    seconds < 3600 ? [seconds / 60, "minute"] : seconds < 86400 ? [seconds / 3600, "hour"] : [seconds / 86400, "day"];
  return i18n.relative.format(-Math.floor(value), unit);
}
