<script lang="ts">
  import type { Snippet } from "svelte";
  import type { HTMLAttributes } from "svelte/elements";

  let { class: cls = "", children, ...rest }: HTMLAttributes<HTMLDivElement> & { children: Snippet } = $props();
</script>

<div class="rounded-lg border border-line bg-panel shadow-card {cls}" {...rest}>
  {@render children()}
</div>
