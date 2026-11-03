<script lang="ts">
  // A card you click to open something: a category on the Overview.
  import type { Snippet } from "svelte";
  import type { HTMLButtonAttributes } from "svelte/elements";

  let { children, ...rest }: HTMLButtonAttributes & { children: Snippet } = $props();
</script>

<button
  type="button"
  class="flex flex-col gap-2 rounded-lg border border-line bg-panel p-4 text-left shadow-card transition-colors hover:border-line-strong"
  {...rest}
>
  {@render children()}
</button>
