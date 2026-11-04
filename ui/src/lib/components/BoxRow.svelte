<script lang="ts">
  // One row in a list group: a tinted icon tile (a source's, a severity's) with
  // an optional badge on its corner, a title over a subtitle, and what follows.
  import type { Snippet } from "svelte";
  import type { Settings } from "@lucide/svelte";
  import type { HTMLButtonAttributes } from "svelte/elements";

  type Props = HTMLButtonAttributes & {
    title: string;
    subtitle?: string;
    selected?: boolean;
    icon: typeof Settings;
    /** A colour for the tile; none is neutral glass. */
    tint?: string | null;
    /** A tooltip for the whole row (where it is, what a click does). */
    hint?: string;
    /** What the icon means, for screen readers ("High"), when it says something. */
    iconLabel?: string;
    badge?: Snippet;
    before?: Snippet;
    trailing?: Snippet;
  };
  let { title, subtitle, selected = false, icon: Icon, tint = null, hint, iconLabel, badge, before, trailing, ...rest }: Props = $props();
</script>

<!-- A row that does nothing when clicked (a program only listening) is not a button. -->
<svelte:element
  this={rest.onclick ? "button" : "div"}
  type={rest.onclick ? "button" : undefined}
  title={hint}
  class="flex w-full items-center gap-3 border-b border-line px-3 py-2 text-left transition-colors last:border-0 focus-visible:outline-offset-[-2px] {selected
    ? 'bg-glass-strong'
    : rest.onclick
      ? 'hover:bg-glass'
      : ''}"
  {...rest}
>
  <span
    class="relative grid size-[30px] shrink-0 place-items-center rounded-md {tint ? '' : 'bg-glass text-muted'}"
    style={tint ? `color: color-mix(in srgb, ${tint} 82%, var(--fg)); background: color-mix(in srgb, ${tint} 16%, transparent)` : undefined}
  >
    <Icon size={16} strokeWidth={2} aria-hidden="true" />
    {#if iconLabel}<span class="sr-only">{iconLabel}:</span>{/if}
    {#if badge}<span class="absolute -bottom-1 -right-1 grid size-[17px] place-items-center rounded-full bg-panel">{@render badge()}</span>{/if}
  </span>
  <span class="min-w-0 flex-1">
    <span class="flex items-center gap-2">{#if before}{@render before()}{/if}<span class="truncate text-base font-medium">{title}</span></span>
    {#if subtitle}<span class="mt-px block truncate text-xs text-muted">{subtitle}</span>{/if}
  </span>
  {#if trailing}<span class="flex shrink-0 items-center gap-1.5">{@render trailing()}</span>{/if}
</svelte:element>
