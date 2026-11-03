<script lang="ts">
  // A severity as its icon (octagon critical, triangle high, circle medium,
  // i low, ring info, as in the menu), with its name for screen readers.
  import { Circle, CircleAlert, Info, OctagonAlert, TriangleAlert } from "@lucide/svelte";
  import { t } from "../i18n/index.svelte";
  import type { Severity } from "../types";

  let { severity, label = false, size = 15 }: { severity: Severity; label?: boolean; size?: number } = $props();

  const icons = { critical: OctagonAlert, high: TriangleAlert, medium: CircleAlert, low: Info, info: Circle };
  const color = { critical: "text-t-critical", high: "text-t-high", medium: "text-t-medium", low: "text-t-low", info: "text-t-info" };
  const Icon = $derived(icons[severity]);
  const name = $derived(t(`severity.${severity}`));
</script>

<span
  class="inline-flex shrink-0 items-center gap-1.5 text-xs font-semibold {color[severity]}"
  title={name}
  role={label ? undefined : "img"}
  aria-label={label ? undefined : name}
>
  <Icon {size} strokeWidth={2.1} />
  {#if label}{name}{/if}
</span>
