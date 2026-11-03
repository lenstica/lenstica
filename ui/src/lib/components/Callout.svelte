<script lang="ts">
  // A note set apart: what to do (neutral), a problem with the settings
  // (attention), or what is wrong (critical, announced to screen readers).
  import type { Snippet } from "svelte";
  import Eyebrow from "./Eyebrow.svelte";

  type Props = { tone?: "neutral" | "attention" | "critical"; title?: string; class?: string; children: Snippet };
  let { tone = "neutral", title, class: cls = "", children }: Props = $props();
  const tones = {
    neutral: "border-rim bg-glass-strong",
    attention: "border-high/60 bg-high/10",
    critical: "border-critical/50 bg-critical/5 text-t-critical",
  };
</script>

<div role={tone === "critical" ? "alert" : undefined} class="rounded-md border px-3 py-2.5 text-sm {tones[tone]} {cls}">
  {#if title}<Eyebrow tone="muted" class="mb-0.5">{title}</Eyebrow>{/if}
  {@render children()}
</div>
