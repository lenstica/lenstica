<script lang="ts">
  // A pill that filters or inserts, one height (h-control); pressed when selected.
  import type { Snippet } from "svelte";
  import type { HTMLButtonAttributes } from "svelte/elements";

  type Props = HTMLButtonAttributes & { selected?: boolean; count?: number; mono?: boolean; children: Snippet };
  let { selected = false, count, mono = false, children, ...rest }: Props = $props();
</script>

<button
  type="button"
  aria-pressed={selected}
  class="inline-flex h-control shrink-0 items-center gap-1.5 rounded-full border px-3 text-sm font-medium transition-colors {mono
    ? 'font-mono text-xs'
    : ''} {selected ? 'border-rim bg-glass-strong text-fg' : 'border-line bg-panel text-muted hover:border-line-strong hover:text-fg'}"
  {...rest}
>
  {@render children()}
  {#if count !== undefined}<span class="tabular {selected ? 'text-muted' : 'text-faint'}">{count}</span>{/if}
</button>
