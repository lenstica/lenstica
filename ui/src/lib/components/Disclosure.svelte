<script lang="ts">
  // More detail, folded away until asked for.
  import type { Snippet } from "svelte";

  let { summary, children }: { summary: string; children: Snippet } = $props();
</script>

<details class="text-xs text-muted">
  <summary class="cursor-pointer select-none rounded-sm text-faint hover:text-muted">{summary}</summary>
  {@render children()}
</details>
