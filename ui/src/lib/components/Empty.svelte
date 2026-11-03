<script lang="ts">
  import type { Snippet } from "svelte";

  let { title, children }: { title: string; children?: Snippet } = $props();
</script>

<div class="flex flex-col items-center justify-center gap-1.5 px-6 py-12 text-center">
  <div class="text-md font-medium">{title}</div>
  {#if children}<div class="max-w-md text-sm text-muted">{@render children()}</div>{/if}
</div>
