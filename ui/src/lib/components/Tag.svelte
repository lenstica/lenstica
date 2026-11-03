<script lang="ts">
  import type { Snippet } from "svelte";

  let { children, title }: { children: Snippet; title?: string } = $props();
</script>

<span class="inline-flex h-5 items-center whitespace-nowrap rounded-full border border-line px-2 text-2xs font-medium text-muted" {title}>
  {@render children()}
</span>
