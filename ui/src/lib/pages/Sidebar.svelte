<script lang="ts">
  import { LayoutGrid, Settings } from "@lucide/svelte";
  import { post } from "../api";
  import CountBadge from "../components/CountBadge.svelte";
  import Eyebrow from "../components/Eyebrow.svelte";
  import LensGlyph from "../components/LensGlyph.svelte";
  import LinkButton from "../components/LinkButton.svelte";
  import NavItem from "../components/NavItem.svelte";
  import ProjectPicker from "../components/ProjectPicker.svelte";
  import StateDot from "../components/StateDot.svelte";
  import { t } from "../i18n/index.svelte";
  import { categoryIcon } from "../icons";
  import { categoryTitle, model, type LensState } from "../model.svelte";

  const total = $derived(model.scoped.filter(model.isAlert).length);
  // macOS draws the window buttons at the top left, over this bar.
  const buttons = $derived(model.state?.platform === "macos");
</script>

<!-- What a row shows at its end: how many need attention, Off, or the state. The
     count is read out with the name ("Packages, 6 findings need attention"). -->
{#snippet status(count: number, state: LensState | null)}
  {#if count}
    <CountBadge {count} />
    <span class="sr-only">, {t("nav.needAttention", { count })}</span>
  {:else if state === "off"}
    <span class="text-xs text-muted" title={t("nav.offTitle")}>{t("nav.off")}</span>
  {:else if state && state !== "clear"}
    <StateDot {state} />
  {/if}
{/snippet}

<nav class="flex h-full w-[236px] shrink-0 flex-col border-r border-line bg-sidebar" aria-label={t("nav.label")}>
  <!-- The top bar's sidebar end: the window buttons, then the logo. Drag it to move the window. -->
  <div data-tauri-drag-region="deep" class="flex h-[40px] shrink-0 select-none items-center gap-2 px-3 {buttons ? 'pl-[84px]' : ''}">
    <LensGlyph class="size-[18px]" />
    <span class="text-md font-semibold tracking-tight">{t("app.name")}</span>
  </div>

  <div class="flex min-h-0 flex-1 flex-col gap-[4px] overflow-y-auto px-3 pb-3 pt-2">
    {#snippet overviewEnd()}{@render status(total, null)}{/snippet}
    <NavItem
      icon={LayoutGrid}
      label={t("nav.overview")}
      active={model.route.page === "overview"}
      aria-current={model.route.page === "overview" ? "page" : undefined}
      onclick={() => model.go("overview")}
      trailing={overviewEnd}
    />
    <Eyebrow class="px-[11px] pb-[4px] pt-[18px]">{t("nav.categories")}</Eyebrow>
    {#each model.categories as c (c.id)}
      {#snippet end()}{@render status(model.alertsIn(c.id).length, model.categoryState(c.id))}{/snippet}
      <NavItem
        icon={categoryIcon(c.id)}
        label={categoryTitle(c)}
        active={model.route.page === c.id}
        aria-current={model.route.page === c.id ? "page" : undefined}
        onclick={() => model.go(c.id)}
        trailing={end}
      />
    {/each}
    <div class="flex-1"></div>
    <div class="mb-[6px]"><ProjectPicker /></div>
    <NavItem
      icon={Settings}
      label={t("nav.settings")}
      active={model.route.page === "settings"}
      aria-current={model.route.page === "settings" ? "page" : undefined}
      onclick={() => model.go("settings")}
    />
    <div class="flex items-center gap-2 px-[11px] pt-[8px] text-xs">
      {#if model.state?.repository}
        <LinkButton tone="muted" title={model.state.repository} onclick={() => post({ type: "openUrl", url: model.state!.repository })}>
          <!-- The GitHub mark (Octicons, MIT). -->
          <svg viewBox="0 0 16 16" class="size-3.5 fill-current" aria-hidden="true">
            <path d="M8 0c4.42 0 8 3.58 8 8a8.013 8.013 0 0 1-5.45 7.59c-.4.08-.55-.17-.55-.38 0-.27.01-1.13.01-2.2 0-.75-.25-1.23-.54-1.48 1.78-.2 3.65-.88 3.65-3.95 0-.88-.31-1.59-.82-2.15.08-.2.36-1.02-.08-2.12 0 0-.67-.22-2.2.82-.64-.18-1.32-.27-2-.27-.68 0-1.36.09-2 .27-1.53-1.03-2.2-.82-2.2-.82-.44 1.1-.16 1.92-.08 2.12-.51.56-.82 1.28-.82 2.15 0 3.06 1.86 3.75 3.64 3.95-.23.2-.44.55-.51 1.07-.46.21-1.61.55-2.33-.66-.15-.24-.6-.83-1.23-.82-.67.01-.27.38.01.53.34.19.73.9.82 1.13.16.45.68 1.31 2.69.94 0 .67.01 1.3.01 1.49 0 .21-.15.45-.55.38A7.995 7.995 0 0 1 0 8c0-4.42 3.58-8 8-8Z" />
          </svg>
          {t("nav.github")}
        </LinkButton>
      {/if}
      <span class="flex-1"></span>
      <span class="tabular text-faint">{model.state?.version ? t("nav.version", { version: model.state.version }) : ""}</span>
    </div>
  </div>
</nav>
