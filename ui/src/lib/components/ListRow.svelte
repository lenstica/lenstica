<script lang="ts">
  // One row of a list you pick from: a finding, a finding needing attention.
  import type { Snippet } from "svelte";
  import type { HTMLButtonAttributes } from "svelte/elements";

  type Props = HTMLButtonAttributes & {
    title: string;
    subtitle?: string;
    selected?: boolean;
    leading?: Snippet;
    trailing?: Snippet;
    ref?: HTMLButtonElement;
  };
  let { title, subtitle, selected = false, leading, trailing, ref = $bindable(), ...rest }: Props = $props();
</script>

<button
  bind:this={ref}
  type="button"
  class="grid w-full grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-x-3 gap-y-0.5 border-b border-line px-4 py-2.5 text-left last:border-0 {selected
    ? 'bg-glass-strong'
    : 'hover:bg-glass'}"
  {...rest}
>
  <span class="row-span-2 self-start pt-px">{#if leading}{@render leading()}{/if}</span>
  <span class="truncate text-base font-medium">{title}</span>
  <span class="row-span-2 text-xs text-muted">{#if trailing}{@render trailing()}{/if}</span>
  <!-- On the highlighted (selected) row, faint text would fall below AA: muted. -->
  {#if subtitle}<span class="col-start-2 row-start-2 truncate text-xs {selected ? 'text-muted' : 'text-faint'}">{subtitle}</span>{/if}
</button>
