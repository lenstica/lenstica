<script lang="ts">
  // A group in a list you pick from (assets by source, findings by topic): its
  // heading and count over a rounded box of rows. Without a heading, just the box.
  import type { Snippet } from "svelte";

  let { heading, count, note, children }: { heading?: string; count?: number; note?: string; children: Snippet } = $props();
</script>

<div role="group" aria-label={heading} class="mt-4 first:mt-0">
  {#if heading}
    <div class="mb-1.5 flex items-center gap-1.5 px-1 text-xs font-semibold text-muted" aria-hidden="true">
      {heading}{#if count !== undefined}<span class="font-medium tabular text-faint">{count}</span>{/if}
    </div>
  {/if}
  {#if note}<p class="-mt-1 mb-1.5 px-1 text-xs text-muted">{note}</p>{/if}
  <div class="overflow-hidden rounded-lg border border-line bg-panel shadow-card">{@render children()}</div>
</div>
