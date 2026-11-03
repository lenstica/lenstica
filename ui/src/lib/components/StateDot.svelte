<script lang="ts">
  // A lens's or category's state as a coloured dot, named for screen readers.
  import { t } from "../i18n/index.svelte";
  import type { LensState } from "../model.svelte";

  let { state, class: cls = "" }: { state: LensState; class?: string } = $props();

  const fill: Record<LensState, string> = {
    critical: "bg-critical",
    high: "bg-high",
    medium: "bg-medium",
    low: "bg-low",
    info: "bg-info",
    clear: "bg-clear",
    running: "bg-running animate-running",
    failed: "bg-failed",
    never: "border-[1.5px] border-faint",
    // Too small for a dashed ring to read as one: the hollow ring, dimmer.
    off: "border-[1.5px] border-faint opacity-50",
  };
  const name = $derived(t(`state.${state}`));
</script>

<span class="inline-block size-[8px] shrink-0 rounded-full {fill[state]} {cls}" title={name} role="img" aria-label={name}></span>
