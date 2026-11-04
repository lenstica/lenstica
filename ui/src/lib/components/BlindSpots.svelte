<script lang="ts" module>
  /** One thing a page could not include, why, and what to do about it. */
  export type BlindSpot = {
    title: string;
    body?: string;
    /** Lines shown as they are, such as the sources that could not be read. */
    lines?: string[];
    action?: { label: string; onclick: () => void };
  };
</script>

<script lang="ts">
  // What a page could not include (an app not running, a folder macOS keeps
  // from Lenstica), behind one button beside its main action instead of a
  // stack of notes above the list.
  import { Popover } from "bits-ui";
  import { EyeOff } from "@lucide/svelte";
  import { t } from "../i18n/index.svelte";
  import { popover } from "../styles";
  import Button from "./Button.svelte";
  import CountBadge from "./CountBadge.svelte";

  let { spots }: { spots: BlindSpot[] } = $props();
</script>

{#if spots.length}
  <Popover.Root>
    <Popover.Trigger>
      {#snippet child({ props })}
        <Button {...props} class="data-[state=open]:border-rim data-[state=open]:bg-glass-strong">
          <EyeOff size={14} aria-hidden="true" />{t("blindSpots.button")}
          <CountBadge count={spots.length} tone="neutral" /><span class="sr-only">({spots.length})</span>
        </Button>
      {/snippet}
    </Popover.Trigger>
    <Popover.Portal>
      <Popover.Content
        side="bottom"
        align="end"
        sideOffset={6}
        aria-label={t("blindSpots.heading")}
        class="{popover} max-h-[calc(100vh-120px)] w-[min(420px,calc(100vw-32px))] overflow-auto"
      >
        <p class="m-0 border-b border-line px-4 py-2.5 text-xs font-semibold text-muted">{t("blindSpots.heading")}</p>
        <ul class="m-0 list-none p-0">
          {#each spots as spot (spot.title)}
            <li class="border-b border-line px-4 py-3 last:border-0">
              <div class="text-sm font-semibold">{spot.title}</div>
              {#if spot.body}<p class="m-0 mt-0.5 text-sm text-muted">{spot.body}</p>{/if}
              {#if spot.lines?.length}
                <ul class="m-0 mt-1 list-none p-0 font-mono text-xs text-muted">
                  {#each spot.lines as line (line)}<li class="break-words py-0.5">{line}</li>{/each}
                </ul>
              {/if}
              {#if spot.action}
                <Button class="mt-2" onclick={spot.action.onclick}>{spot.action.label}</Button>
              {/if}
            </li>
          {/each}
        </ul>
      </Popover.Content>
    </Popover.Portal>
  </Popover.Root>
{/if}
