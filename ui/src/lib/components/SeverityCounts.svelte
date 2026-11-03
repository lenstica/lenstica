<script lang="ts">
  // How many findings there are at each severity, most severe first.
  import { SEVERITIES } from "../model.svelte";
  import type { Item } from "../types";
  import SeverityIcon from "./SeverityIcon.svelte";

  let { items }: { items: Item[] } = $props();
</script>

<span class="flex flex-wrap gap-3">
  {#each SEVERITIES.toReversed() as severity (severity)}
    <span class="inline-flex items-center gap-1.5 text-sm">
      <SeverityIcon {severity} label />
      <b class="tabular font-semibold">{items.filter((i) => i.severity === severity).length}</b>
    </span>
  {/each}
</span>
