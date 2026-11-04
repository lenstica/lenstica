<script lang="ts">
  // The top of every page: its title (the page's only h1) with an "i" that
  // says what the page is, a line of state, and its actions.
  import { Tooltip } from "bits-ui";
  import { Info } from "@lucide/svelte";
  import type { Settings } from "@lucide/svelte";
  import type { Snippet } from "svelte";
  import { t } from "../i18n/index.svelte";
  import { popover } from "../styles";

  type Props = { title: string; description?: string; icon?: typeof Settings; meta?: Snippet; actions?: Snippet };
  let { title, description, icon: Icon, meta, actions }: Props = $props();
</script>

<header class="flex items-start gap-4">
  {#if Icon}
    <div class="grid size-[44px] shrink-0 place-items-center rounded-xl border border-rim bg-glass-strong">
      <Icon size={21} strokeWidth={1.8} />
    </div>
  {/if}
  <div class="min-w-0 flex-1">
    <div class="flex items-center gap-1.5">
      <h1 class="m-0 text-xl font-semibold tracking-tight">{title}</h1>
      {#if description}
        <!-- What the page is, on hover or focus, rather than a paragraph under every title. -->
        <Tooltip.Provider delayDuration={120}>
          <Tooltip.Root disableCloseOnTriggerClick>
            <Tooltip.Trigger
              class="grid size-6 place-items-center rounded-full text-faint transition-colors hover:bg-glass hover:text-fg"
              aria-label={t("app.about", { page: title })}
            >
              <Info size={15} aria-hidden="true" />
            </Tooltip.Trigger>
            <Tooltip.Portal>
              <Tooltip.Content side="bottom" align="start" sideOffset={6} class="{popover} max-w-sm px-3 py-2 text-sm text-fg">
                {description}
              </Tooltip.Content>
            </Tooltip.Portal>
          </Tooltip.Root>
        </Tooltip.Provider>
      {/if}
    </div>
    {#if meta}<div class="mt-1.5 flex flex-wrap items-center gap-2 text-sm">{@render meta()}</div>{/if}
  </div>
  {#if actions}<div class="flex shrink-0 items-center gap-2">{@render actions()}</div>{/if}
</header>
