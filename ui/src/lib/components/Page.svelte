<script lang="ts">
  // The frame every page sits in: centred, never wider than --container-page.
  import type { Snippet } from "svelte";

  let { children }: { children: Snippet } = $props();
</script>

<div class="mx-auto w-full max-w-page px-8 pb-14 pt-7">
  {@render children()}
</div>
