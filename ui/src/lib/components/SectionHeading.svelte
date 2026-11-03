<script lang="ts">
  // A heading within a page (h2) or a section (h3): a title, a count or
  // aside after it, a note under it, and an action at its end.
  import type { Snippet } from "svelte";

  type Props = {
    title: string;
    level?: 2 | 3 | 4;
    size?: "sm" | "md" | "lg";
    aside?: string;
    note?: string | null;
    action?: Snippet;
    class?: string;
  };
  let { title, level = 2, size = "md", aside, note, action, class: cls = "" }: Props = $props();
  const sizes = { sm: "text-sm", md: "text-md", lg: "text-lg" };
</script>

<div class="mb-2.5 flex items-center gap-2 {cls}">
  <svelte:element this={`h${level}`} class="m-0 font-semibold {sizes[size]}">{title}</svelte:element>
  {#if aside}<span class="text-sm text-faint">{aside}</span>{/if}
  <span class="flex-1"></span>
  {#if action}{@render action()}{/if}
</div>
{#if note}<p class="-mt-1.5 mb-2.5 text-sm text-muted">{note}</p>{/if}
