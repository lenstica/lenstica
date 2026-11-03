<script lang="ts">
  // The bar along the top of the content: Back, Forward and where you are. It
  // is also the window's title bar: drag it to move the window.
  import { ChevronLeft, ChevronRight, LayoutGrid, Settings } from "@lucide/svelte";
  import { isKind, kindIcon, kindTitle } from "../assets";
  import IconButton from "../components/IconButton.svelte";
  import LinkButton from "../components/LinkButton.svelte";
  import { t } from "../i18n/index.svelte";
  import { categoryIcon } from "../icons";
  import { categoryTitle, model } from "../model.svelte";
  import { sectionOf } from "../sections";

  const page = $derived(model.route.page);
  const category = $derived(model.state?.categories.find((c) => c.id === page));
  const kind = $derived(page === "assets" && isKind(model.route.sub) ? model.route.sub : null);
  const trail = $derived(
    page === "settings"
      ? { icon: Settings, title: t("nav.settings"), sub: sectionOf(model.route.sub).title }
      : kind
        ? { icon: kindIcon(kind), title: kindTitle(kind), sub: null }
        : category
          ? { icon: categoryIcon(category.id), title: categoryTitle(category), sub: null }
          : { icon: LayoutGrid, title: t("nav.overview"), sub: null },
  );
</script>

<header data-tauri-drag-region="deep" class="flex h-[40px] shrink-0 select-none items-center gap-1 border-b border-line px-3">
  <IconButton icon={ChevronLeft} label={t("nav.backKeys")} disabled={!model.past.length} onclick={() => model.back()} />
  <IconButton icon={ChevronRight} label={t("nav.forwardKeys")} disabled={!model.future.length} onclick={() => model.forward()} />
  <div class="ml-2 flex min-w-0 items-center gap-2 text-sm">
    <trail.icon size={15} strokeWidth={1.9} class="shrink-0 text-muted" />
    {#if trail.sub}
      <LinkButton tone="muted" onclick={() => model.go("settings")}>{trail.title}</LinkButton>
      <ChevronRight size={13} class="shrink-0 text-faint" />
      <span class="truncate font-medium" aria-current="page">{trail.sub}</span>
    {:else}
      <span class="truncate font-medium" aria-current="page">{trail.title}</span>
    {/if}
  </div>
</header>
