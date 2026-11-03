<script lang="ts">
  // One setting in a card: what it is, a note, and its control at the end.
  import type { Snippet } from "svelte";

  type Props = { label: string; note?: string | null; extra?: Snippet; children: Snippet; indent?: boolean; dim?: boolean };
  let { label, note, extra, children, indent = false, dim = false }: Props = $props();
</script>

<div class="flex items-center gap-4 border-b border-line px-4 py-3 last:border-0 {indent ? 'pl-9' : ''} {dim ? 'opacity-50' : ''}">
  <div class="min-w-0 flex-1">
    <div class="text-base">{label}</div>
    {#if note}<div class="mt-0.5 text-xs text-muted">{note}</div>{/if}
  </div>
  {#if extra}{@render extra()}{/if}
  {@render children()}
</div>
