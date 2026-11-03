<script lang="ts">
  // A one-line field (text, search, number), one height (h-control), with an
  // optional icon in front. Its label is the `aria-label`, or a visible label beside it.
  import type { Settings } from "@lucide/svelte";
  import type { HTMLInputAttributes } from "svelte/elements";

  type Props = Omit<HTMLInputAttributes, "value"> & { value?: string | number | null; icon?: typeof Settings };
  let { value = $bindable(), icon: Icon, class: cls = "", ...rest }: Props = $props();
</script>

<span
  class="flex h-control items-center gap-2 rounded-md border border-line bg-panel px-2.5 shadow-card focus-within:border-line-strong focus-within:outline-2 focus-within:outline-offset-2 focus-within:outline-focus {cls}"
>
  {#if Icon}<Icon size={15} class="shrink-0 text-faint" />{/if}
  <input bind:value class="tabular min-w-0 flex-1 border-0 bg-transparent text-base text-fg outline-none placeholder:text-faint" {...rest} />
</span>
