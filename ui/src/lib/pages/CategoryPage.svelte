<script lang="ts">
  // One category: what it covers, its lenses (run, turn on or off), and its
  // findings in the selected project, filtered by topic, severity and text.
  import { tick } from "svelte";
  import { ClipboardCopy, RefreshCw, Search } from "@lucide/svelte";
  import { post } from "../api";
  import Button from "../components/Button.svelte";
  import Card from "../components/Card.svelte";
  import Chip from "../components/Chip.svelte";
  import Empty from "../components/Empty.svelte";
  import ListRow from "../components/ListRow.svelte";
  import Page from "../components/Page.svelte";
  import PageHeader from "../components/PageHeader.svelte";
  import SectionHeading from "../components/SectionHeading.svelte";
  import Select from "../components/Select.svelte";
  import SeverityCounts from "../components/SeverityCounts.svelte";
  import SeverityIcon from "../components/SeverityIcon.svelte";
  import StateDot from "../components/StateDot.svelte";
  import TextField from "../components/TextField.svelte";
  import { t } from "../i18n/index.svelte";
  import { categoryIcon } from "../icons";
  import { ALL, categoryDescription, categoryTitle, model, rank, SEVERITIES, topicTitle } from "../model.svelte";
  import type { Category, Severity } from "../types";
  import FindingDetail from "./FindingDetail.svelte";
  import LensCard from "./LensCard.svelte";

  let { category }: { category: Category } = $props();

  let topic = $state("");
  let query = $state("");
  let minimum = $state<Severity>("low");
  let selected = $state<string | null>(null);
  let list: HTMLDivElement | undefined = $state();

  const title = $derived(categoryTitle(category));
  const lenses = $derived(model.lensesIn(category.id));
  const on = $derived(lenses.filter((l) => l.enabled));
  const items = $derived(model.itemsIn(category.id));
  const alerts = $derived(items.filter(model.isAlert));
  const bySeverity = $derived(items.filter((i) => rank(i.severity) >= rank(minimum)));
  // The category's topics, and any other a lens used.
  const topics = $derived([
    ...category.topics.map((k) => k.id),
    ...[...new Set(items.map((i) => i.topic ?? ""))].filter((id) => id && !category.topics.some((k) => k.id === id)),
  ]);
  const shown = $derived.by(() => {
    const q = query.trim().toLowerCase();
    return bySeverity.filter(
      (i) =>
        (!topic || i.topic === topic) &&
        (!q || [i.title, i.detail, i.remedy, ...i.locations.map((l) => l.label)].join("\n").toLowerCase().includes(q)),
    );
  });
  const current = $derived(shown.find((i) => i.id === selected) ?? shown[0] ?? null);
  const status = $derived(model.categoryState(category.id));
  const headline = $derived(
    !on.length
      ? t("category.headlineNoLens")
      : alerts.length
        ? t("category.headlineNeed", { count: alerts.length })
        : status === "never"
          ? t("category.headlineNotChecked")
          : t("category.headlineNothing"),
  );

  function show(id: string) {
    selected = id;
    tick().then(() => list?.querySelector<HTMLElement>('[aria-selected="true"]')?.scrollIntoView({ block: "nearest" }));
  }

  // The list moves with the arrow keys, Home and End; only the selected row is in the Tab order.
  function keys(e: KeyboardEvent) {
    const at = shown.findIndex((i) => i.id === current?.id);
    const to =
      e.key === "ArrowDown" ? at + 1 : e.key === "ArrowUp" ? at - 1 : e.key === "Home" ? 0 : e.key === "End" ? shown.length - 1 : null;
    if (to === null || !shown.length) return;
    e.preventDefault();
    show(shown[Math.max(0, Math.min(shown.length - 1, to))].id);
    tick().then(() => list?.querySelector<HTMLElement>('[aria-selected="true"]')?.focus());
  }

  // Opened on one finding (from the menu bar): show it whatever the filters and project.
  $effect(() => {
    const target = model.route.page === category.id ? model.route.sub : null;
    if (!target) return;
    topic = "";
    query = "";
    minimum = "info";
    if (!model.scoped.some((i) => i.id === target) && model.items.some((i) => i.id === target)) model.setScope(ALL);
    tick().then(() => {
      show(target);
      list?.querySelector<HTMLElement>('[aria-selected="true"]')?.scrollIntoView({ block: "center" });
    });
  });

  function copyShown() {
    const first = shown.slice(0, 50);
    model.showPrompt(
      first.map((i) => ({ lens: i.lens, key: i.key })),
      shown.length > 50
        ? t("category.aboutFirst", { count: 50, total: shown.length, category: title })
        : t("category.about", { count: shown.length, category: title }),
    );
  }
</script>

{#snippet meta()}
  <StateDot state={status} />
  <span class="font-medium">{headline}</span>
  <span class="text-faint">· {model.scopeTitle}</span>
  {#if on.length}<span class="ml-2"><SeverityCounts {items} /></span>{/if}
{/snippet}
{#snippet actions()}
  <Button variant="primary" disabled={!on.length || on.every((l) => l.running)} onclick={() => post({ type: "run", lenses: on.map((l) => l.id) })}>
    <RefreshCw size={14} />{t("category.check", { category: title })}
  </Button>
{/snippet}

<Page>
  <PageHeader {title} description={categoryDescription(category)} icon={categoryIcon(category.id)} {meta} {actions} />

  <section class="mt-7">
    <SectionHeading title={t("category.lenses")} aside={t("category.lensesOn", { on: on.length, count: lenses.length })} />
    <div class="grid grid-cols-[repeat(auto-fill,minmax(330px,1fr))] gap-3">
      {#each lenses as lens (lens.id)}<LensCard {lens} />{/each}
    </div>
  </section>

  <section class="mt-8">
    <SectionHeading title={t("category.findings")} aside={t("category.shown", { count: shown.length })} />
    {#if topics.length}
      <div class="mb-3 flex flex-wrap items-center gap-2">
        <Chip selected={!topic} count={bySeverity.length} onclick={() => (topic = "")}>{t("category.all")}</Chip>
        {#each topics as id (id)}
          <Chip selected={topic === id} count={bySeverity.filter((i) => i.topic === id).length} onclick={() => (topic = topic === id ? "" : id)}>
            {topicTitle(category, id)}
          </Chip>
        {/each}
      </div>
    {/if}
    <div class="mb-3 flex flex-wrap items-center gap-2">
      <TextField icon={Search} bind:value={query} type="search" aria-label={t("category.searchLabel")} placeholder={t("category.search")} class="min-w-60 flex-1" />
      <Select
        label={t("category.minimum")}
        value={minimum}
        options={SEVERITIES.map((s) => ({ value: s, label: t("severity.andAbove", { severity: t(`severity.${s}`) }) }))}
        onchange={(v) => (minimum = v as Severity)}
      />
      {#if shown.length}
        <Button title={t("category.copyTitle")} onclick={copyShown}>
          <ClipboardCopy size={14} />
          {shown.length > 50
            ? t("category.copyFirst", { count: 50 })
            : shown.length === 1
              ? t("category.copyOne")
              : t("category.copyAll", { count: shown.length })}
        </Button>
      {/if}
    </div>

    {#if !shown.length}
      <Card>
        {#if !on.length}
          <Empty title={t("category.noLensTitle")}>{t("category.noLensBody", { category: title.toLowerCase() })}</Empty>
        {:else if items.length}
          <Empty title={t("category.noMatchTitle")}>{t("category.noMatchBody")}</Empty>
        {:else}
          <Empty title={t("category.nothingTitle")}>{t("category.nothingBody", { scope: model.scopeTitle })}</Empty>
        {/if}
      </Card>
    {:else}
      <div class="grid h-[max(460px,calc(100vh-190px))] grid-cols-[minmax(320px,42%)_1fr] gap-3">
        <Card class="overflow-auto">
          <div bind:this={list} role="listbox" aria-label={t("category.listLabel")} tabindex="-1" onkeydown={keys}>
            {#each shown as i (i.id)}
              {@const where = i.locations.length ? i.locations[0].label + (i.locations.length > 1 ? ` (+${i.locations.length - 1})` : "") : ""}
              {#snippet icon()}<SeverityIcon severity={i.severity} />{/snippet}
              <ListRow
                role="option"
                aria-selected={current?.id === i.id}
                tabindex={current?.id === i.id ? 0 : -1}
                selected={current?.id === i.id}
                title={i.title}
                subtitle={i.lensTitle + (where ? ` · ${where}` : "")}
                leading={icon}
                onclick={() => show(i.id)}
              />
            {/each}
          </div>
        </Card>
        <Card class="overflow-auto p-5" aria-live="polite">
          {#if current}<FindingDetail item={current} {category} />{/if}
        </Card>
      </div>
    {/if}
  </section>
</Page>
