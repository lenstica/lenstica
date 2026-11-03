<script lang="ts">
  // A choice from a short list, one height (h-control).
  import { Select } from "bits-ui";
  import { Check, ChevronsUpDown } from "@lucide/svelte";
  import { option, popover } from "../styles";

  type Option = { value: string; label: string };
  type Props = { value: string; options: Option[]; onchange: (value: string) => void; label: string; disabled?: boolean; class?: string };
  let { value, options, onchange, label, disabled = false, class: cls = "" }: Props = $props();

  const shown = $derived(options.find((o) => o.value === value)?.label ?? value);
</script>

<Select.Root type="single" {value} onValueChange={(v) => v !== value && onchange(v)} items={options} {disabled}>
  <Select.Trigger
    aria-label={label}
    class="inline-flex h-control min-w-28 shrink-0 items-center justify-between gap-2 rounded-md border border-line bg-panel px-2.5 text-base shadow-card hover:border-line-strong data-[disabled]:opacity-45 {cls}"
  >
    <span class="truncate">{shown}</span>
    <ChevronsUpDown size={14} class="shrink-0 text-faint" />
  </Select.Trigger>
  <Select.Portal>
    <Select.Content sideOffset={4} class="{popover} max-h-72 min-w-[var(--bits-select-anchor-width)] p-1">
      <Select.Viewport>
        {#each options as o (o.value)}
          <Select.Item value={o.value} label={o.label} class="{option} justify-between gap-4">
            {#snippet children({ selected })}
              {o.label}
              {#if selected}<Check size={14} />{/if}
            {/snippet}
          </Select.Item>
        {/each}
      </Select.Viewport>
    </Select.Content>
  </Select.Portal>
</Select.Root>
