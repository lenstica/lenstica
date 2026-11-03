<script lang="ts">
  import { post } from "./lib/api";
  import Button from "./lib/components/Button.svelte";
  import Callout from "./lib/components/Callout.svelte";
  import CodeBlock from "./lib/components/CodeBlock.svelte";
  import Empty from "./lib/components/Empty.svelte";
  import PromptDialog from "./lib/components/PromptDialog.svelte";
  import Toasts from "./lib/components/Toasts.svelte";
  import { i18n, t } from "./lib/i18n/index.svelte";
  import { model } from "./lib/model.svelte";
  import CategoryPage from "./lib/pages/CategoryPage.svelte";
  import Overview from "./lib/pages/Overview.svelte";
  import Settings from "./lib/pages/Settings.svelte";
  import Sidebar from "./lib/pages/Sidebar.svelte";
  import TopBar from "./lib/pages/TopBar.svelte";

  const category = $derived(model.state?.categories.find((c) => c.id === model.route.page));
  let main: HTMLElement | undefined = $state();

  // The language: the one picked in Settings, else the system's; the page says which.
  $effect(() => {
    i18n.choice = model.state?.settings.window?.language ?? "system";
    if (model.state?.systemLanguages?.length) i18n.system = model.state.systemLanguages;
  });
  $effect(() => {
    document.documentElement.lang = i18n.locale;
  });

  // ⌘[ and ⌘] (Ctrl elsewhere) go back and forward, as in a browser.
  function keys(e: KeyboardEvent) {
    if (!(e.metaKey || e.ctrlKey) || e.altKey || e.shiftKey) return;
    if (e.key === "[") model.back();
    else if (e.key === "]") model.forward();
    else return;
    e.preventDefault();
  }

  // A new page, or a new section of Settings, starts at the top.
  $effect(() => {
    if (model.route.page === "settings") model.route.sub;
    else model.route.page;
    main?.scrollTo({ top: 0 });
  });
</script>

{#if model.loadError}
  <Empty title={t("app.loadError")}><CodeBlock text={model.loadError} class="text-left" /></Empty>
{:else if !model.state}
  <Empty title={t("app.loading")} />
{:else}
  <div class="flex h-full">
    <Sidebar />
    <div class="flex min-w-0 flex-1 flex-col">
      <TopBar />
      <main bind:this={main} class="min-h-0 min-w-0 flex-1 overflow-y-auto [scrollbar-gutter:stable]">
        {#if model.state.configError}
          <div class="mx-auto mt-5 max-w-page px-8">
            <Callout tone="attention" class="flex items-center justify-between gap-3">
              <span>{t("app.configError", { error: model.state.configError })}</span>
              <Button onclick={() => post({ type: "openConfig" })}>{t("app.openConfig")}</Button>
            </Callout>
          </div>
        {/if}
        {#if model.route.page === "settings"}
          <Settings />
        {:else if category}
          {#key category.id}<CategoryPage {category} />{/key}
        {:else}
          <Overview />
        {/if}
      </main>
    </div>
  </div>
{/if}
<PromptDialog />
<Toasts />
<svelte:window onkeydown={keys} />
