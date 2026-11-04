<script lang="ts">
  // A navigation row (h-nav): the sidebar's pages, Settings' sections. Takes
  // the props of whatever it stands in for, such as a tab.
  import type { Component, Snippet } from "svelte";
  import type { HTMLButtonAttributes } from "svelte/elements";

  // A Lucide icon, or anything drawn at the same size (the GitHub mark).
  type NavIcon = Component<{ size?: number; strokeWidth?: number; class?: string }>;
  type Props = HTMLButtonAttributes & { icon: NavIcon; label: string; active?: boolean; trailing?: Snippet };
  let { icon: Icon, label, active = false, trailing, ...rest }: Props = $props();
</script>

<button
  type="button"
  class="flex h-nav w-full shrink-0 items-center gap-[11px] rounded-md border px-[11px] text-left text-md transition-colors {active
    ? 'border-rim bg-glass-strong font-medium text-fg'
    : 'border-transparent text-muted hover:bg-glass hover:text-fg'}"
  {...rest}
>
  <Icon size={19} strokeWidth={1.8} class="shrink-0" />
  <span class="min-w-0 flex-1 truncate">{label}</span>
  {#if trailing}{@render trailing()}{/if}
</button>
