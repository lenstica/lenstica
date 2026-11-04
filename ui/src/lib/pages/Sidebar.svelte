<script lang="ts">
  import { CircleDot, LayoutGrid, Settings } from "@lucide/svelte";
  import { post } from "../api";
  import { KINDS, kindIcon, kindTitle } from "../assets";
  import CountBadge from "../components/CountBadge.svelte";
  import Eyebrow from "../components/Eyebrow.svelte";
  import LensGlyph from "../components/LensGlyph.svelte";
  import GitHubMark from "../components/GitHubMark.svelte";
  import NavItem from "../components/NavItem.svelte";
  import ProjectPicker from "../components/ProjectPicker.svelte";
  import StateDot from "../components/StateDot.svelte";
  import { t } from "../i18n/index.svelte";
  import { categoryIcon } from "../icons";
  import { categoryTitle, model, type LensState } from "../model.svelte";

  const SYSTEMS: Record<string, string> = { macos: "macOS", windows: "Windows", linux: "Linux" };
  // GitHub's choice of issue forms (.github/ISSUE_TEMPLATE), with the one
  // thing anyone answering asks first, which version on what, filled in for
  // whichever form is picked. Nothing is sent until the issue is.
  function issueUrl(repo: string, version: string) {
    const platform = model.state?.platform ?? "";
    const running = `${version} (alpha) on ${SYSTEMS[platform] ?? platform}`;
    return `${repo}/issues/new/choose?version=${encodeURIComponent(running)}`;
  }
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
    <Eyebrow class="px-[11px] pb-[4px] pt-[18px]">{t("nav.assets")}</Eyebrow>
    {#each KINDS as kind (kind)}
      {@const found = model.assets[kind]}
      {@const here = model.route.page === "assets" && model.route.sub === kind}
      <!-- How many there are: a plain number, not a badge, since nothing here needs attention by being counted. -->
      {#snippet end()}{#if found?.supported}<span class="tabular text-xs text-faint">{found.assets.length}</span>{/if}{/snippet}
      <NavItem
        icon={kindIcon(kind)}
        label={kindTitle(kind)}
        active={here}
        aria-current={here ? "page" : undefined}
        onclick={() => model.go("assets", kind)}
        trailing={end}
      />
    {/each}
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
    {#if model.state?.repository}
      {@const repo = model.state.repository}
      {@const version = model.state.version}
      <!-- The version as the asset rows show their counts: plain, faint, at the end. -->
      {#snippet versionEnd()}
        <span class="tabular shrink-0 text-xs text-faint" title={t("nav.versionTitle", { version })}>{t("nav.version", { version })}</span>
      {/snippet}
      <NavItem icon={GitHubMark} label={t("nav.github")} title={repo} onclick={() => post({ type: "openUrl", url: repo })} trailing={versionEnd} />
      <NavItem icon={CircleDot} label={t("nav.report")} title={t("nav.reportTitle")} onclick={() => post({ type: "openUrl", url: issueUrl(repo, version) })} />
    {/if}
  </div>
</nav>
