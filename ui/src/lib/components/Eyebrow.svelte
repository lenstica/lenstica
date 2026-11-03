<script lang="ts">
  // A small label over a group: "Categories", "Template", "What to do". On a
  // highlighted surface (a callout) it is muted, as faint would fall below AA.
  import type { Snippet } from "svelte";

  type Props = { children: Snippet; tone?: "faint" | "muted"; class?: string };
  let { children, tone = "faint", class: cls = "" }: Props = $props();
</script>

<div class="text-2xs font-semibold uppercase tracking-wide {tone === 'muted' ? 'text-muted' : 'text-faint'} {cls}">{@render children()}</div>
