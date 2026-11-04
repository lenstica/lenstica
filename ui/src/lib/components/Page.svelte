<script lang="ts">
  // The frame every page sits in: centred, never wider than --container-page.
  // A page that fills the window (a list beside details) is exactly as tall as
  // it, so the page itself does not scroll; its parts do.
  import type { Snippet } from "svelte";

  let { children, fill = false }: { children: Snippet; fill?: boolean } = $props();
</script>

<div class="mx-auto w-full max-w-page px-8 pt-7 {fill ? 'flex h-full flex-col pb-6' : 'pb-14'}">
  {@render children()}
</div>
