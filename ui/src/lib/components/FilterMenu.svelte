<script lang="ts" module>
  import type { Settings } from "@lucide/svelte";

  export type FilterOption = { value: string; label: string; count?: number; icon?: typeof Settings; tint?: string | null };
  /** One choice in the menu: where they come from, how severe. */
  export type FilterGroup = { heading: string; value: string; options: FilterOption[]; onchange: (value: string) => void };
</script>

<script lang="ts">
  // The Filter button at the end of a search, and its menu: one choice per
  // group, each option with how many it leaves. The button names what it
  // filters by, highlighted, or just says Filter.
  import { DropdownMenu } from "bits-ui";
  import { Check, ListFilter, X } from "@lucide/svelte";
  import { t } from "../i18n/index.svelte";
  import { option, popover } from "../styles";

  type Props = { groups: FilterGroup[]; active: string[]; onclear: () => void };
  let { groups, active, onclear }: Props = $props();

  const heading = "px-2.5 pb-1 pt-1.5 text-2xs font-semibold uppercase tracking-wide text-faint";
</script>

<DropdownMenu.Root>
  <DropdownMenu.Trigger
    class="inline-flex h-control max-w-72 shrink-0 items-center gap-1.5 rounded-md border px-3 text-base font-medium text-fg shadow-card transition-colors {active.length
      ? 'border-rim bg-glass-strong'
      : 'border-line bg-panel hover:border-line-strong hover:bg-raised'}"
  >
    <ListFilter size={15} class="shrink-0" aria-hidden="true" />
    {#if active.length}<span class="sr-only">{t("filter.button")}:</span>{/if}
    <span class="truncate">{active.length ? active.join(" · ") : t("filter.button")}</span>
  </DropdownMenu.Trigger>
  <DropdownMenu.Portal>
    <DropdownMenu.Content align="end" sideOffset={4} class="{popover} max-h-[26rem] w-72 overflow-auto p-1">
      {#each groups as g, n (g.heading)}
        {#if n}<DropdownMenu.Separator class="my-1 h-px bg-line" />{/if}
        <DropdownMenu.RadioGroup value={g.value} onValueChange={g.onchange}>
          <DropdownMenu.GroupHeading class={heading}>{g.heading}</DropdownMenu.GroupHeading>
          {#each g.options as o (o.value)}
            <DropdownMenu.RadioItem value={o.value} class="{option} justify-between gap-3">
              {#snippet children({ checked })}
                <span class="flex min-w-0 items-center gap-2">
                  {#if o.icon}
                    <o.icon size={14} class="shrink-0 {o.tint ? '' : 'text-muted'}" style={o.tint ? `color: ${o.tint}` : undefined} aria-hidden="true" />
                  {/if}
                  <span class="truncate">{o.label}</span>
                </span>
                <span class="flex shrink-0 items-center gap-2">
                  {#if o.count !== undefined}<span class="text-xs tabular text-faint">{o.count}</span>{/if}
                  <span class="grid w-3.5 place-items-center">{#if checked}<Check size={14} aria-hidden="true" />{/if}</span>
                </span>
              {/snippet}
            </DropdownMenu.RadioItem>
          {/each}
        </DropdownMenu.RadioGroup>
      {/each}
      {#if active.length}
        <DropdownMenu.Separator class="my-1 h-px bg-line" />
        <DropdownMenu.Item class={option} onSelect={onclear}>
          <X size={14} class="text-muted" aria-hidden="true" />{t("filter.clear")}
        </DropdownMenu.Item>
      {/if}
    </DropdownMenu.Content>
  </DropdownMenu.Portal>
</DropdownMenu.Root>
