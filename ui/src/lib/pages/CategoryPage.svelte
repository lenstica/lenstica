<script lang="ts">
  // One category: what it covers, its lenses (run, turn on or off), and its
  // findings in the selected project, grouped by topic, filtered by topic,
  // severity and text. Like an asset page, it fits the window: the lenses are
  // a line of names, each opening its card, and only the list scrolls.
  import { tick } from "svelte";
  import { Popover } from "bits-ui";
  import { ClipboardCopy, RefreshCw, Search } from "@lucide/svelte";
  import { post } from "../api";
  import BoxRow from "../components/BoxRow.svelte";
  import Button from "../components/Button.svelte";
  import Card from "../components/Card.svelte";
  import Empty from "../components/Empty.svelte";
  import FilterMenu, { type FilterGroup } from "../components/FilterMenu.svelte";
  import ListGroup from "../components/ListGroup.svelte";
  import Page from "../components/Page.svelte";
  import PageHeader from "../components/PageHeader.svelte";
  import SeverityCounts from "../components/SeverityCounts.svelte";
  import StateDot from "../components/StateDot.svelte";
  import TextField from "../components/TextField.svelte";
  import { ago, t } from "../i18n/index.svelte";
  import { categoryIcon, severityIcon, severityTint } from "../icons";
  import { ALL, categoryDescription, categoryTitle, model, rank, SEVERITIES, topicTitle } from "../model.svelte";
  import type { Category, Item, Lens, Severity } from "../types";
  import FindingDetail from "./FindingDetail.svelte";
  import LensCard from "./LensCard.svelte";
  import ListeningPanel from "./ListeningPanel.svelte";

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
  // By topic, the group with the most severe finding first; each group keeps the
  // severity order. The arrow keys follow `ordered`, the list as drawn.
  const groups = $derived.by(() => {
    const by = new Map<string, Item[]>();
    for (const i of shown) {
      const k = i.topic ?? "";
      by.set(k, [...(by.get(k) ?? []), i]);
    }
    const at = (k: string) => (topics.includes(k) ? topics.indexOf(k) : topics.length);
    return [...by]
      .map(([topic, items]) => ({ topic, items }))
      .sort((a, b) => rank(b.items[0].severity) - rank(a.items[0].severity) || at(a.topic) - at(b.topic));
  });
  const ordered = $derived(groups.flatMap((g) => g.items));
  const current = $derived(shown.find((i) => i.id === selected) ?? ordered[0] ?? null);
  const filters = $derived.by(() => {
    const out: FilterGroup[] = [];
    if (topics.length)
      out.push({
        heading: t("category.filterTopic"),
        value: topic || "all",
        onchange: (v) => (topic = v === "all" ? "" : v),
        options: [
          { value: "all", label: t("category.all"), count: bySeverity.length },
          ...topics.map((id) => ({ value: id, label: topicTitle(category, id), count: bySeverity.filter((i) => i.topic === id).length })),
        ],
      });
    out.push({
      heading: t("category.filterSeverity"),
      value: minimum,
      onchange: (v) => (minimum = v as Severity),
      options: [...SEVERITIES].reverse().map((s) => ({
        value: s,
        label: t("severity.andAbove", { severity: t(`severity.${s}`) }),
        count: items.filter((i) => rank(i.severity) >= rank(s)).length,
        icon: severityIcon(s),
        tint: severityTint(s),
      })),
    });
    return out;
  });
  /** Low and above is where a page starts, so it is not called a filter. */
  const active = $derived(
    [topic ? topicTitle(category, topic) : "", minimum === "low" ? "" : t("severity.andAbove", { severity: t(`severity.${minimum}`) })].filter(Boolean),
  );
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
    const at = ordered.findIndex((i) => i.id === current?.id);
    const to =
      e.key === "ArrowDown" ? at + 1 : e.key === "ArrowUp" ? at - 1 : e.key === "Home" ? 0 : e.key === "End" ? ordered.length - 1 : null;
    if (to === null || !ordered.length) return;
    e.preventDefault();
    show(ordered[Math.max(0, Math.min(ordered.length - 1, to))].id);
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

  /** A lens's line under its name: off, running, never run, or its last summary. */
  function lensStatus(lens: Lens) {
    const r = lens.result;
    if (!lens.enabled) return t("lens.off");
    if (lens.running) return t("lens.runningStatus");
    if (!r) return t("lens.notRun");
    return t("lens.status", { summary: r.error ? t("lens.failed", { error: r.error }) : r.summary, when: ago(r.ran_at, model.now), seconds: r.seconds.toFixed(1) });
  }

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

<Page fill>
  <PageHeader {title} description={categoryDescription(category)} icon={categoryIcon(category.id)} {meta} {actions} />

  <!-- The lenses as a line of names with their state; each opens its card to run it or turn it on or off. -->
  <section class="mt-5 flex flex-wrap items-center gap-1.5" aria-label={t("category.lenses")}>
    <span class="mr-1 text-sm font-semibold">{t("category.lenses")}</span>
    <span class="mr-2 text-sm text-faint">{t("category.lensesOn", { on: on.length, count: lenses.length })}</span>
    {#each lenses as lens (lens.id)}
      <Popover.Root>
        <Popover.Trigger
          class="inline-flex h-7 max-w-64 items-center gap-1.5 rounded-full border border-line bg-panel px-2.5 text-xs font-medium shadow-card transition-colors hover:border-line-strong data-[state=open]:border-rim data-[state=open]:bg-glass-strong {lens.enabled
            ? 'text-fg'
            : 'text-muted'}"
          title={lensStatus(lens)}
        >
          <StateDot state={model.lensState(lens)} /><span class="truncate">{lens.title}</span>
        </Popover.Trigger>
        <Popover.Portal>
          <Popover.Content sideOffset={6} align="start" class="z-50 w-[min(460px,calc(100vw-32px))] rounded-lg shadow-[0_16px_40px_-12px_rgb(0_0_0/0.45)] outline-none">
            <LensCard {lens} />
          </Popover.Content>
        </Popover.Portal>
      </Popover.Root>
    {/each}
  </section>

  {#if category.id === "network"}<ListeningPanel />{/if}

  <section class="mt-5 flex min-h-0 flex-1 flex-col" aria-label={t("category.findings")}>
    <div class="mb-3 flex gap-2">
      <TextField icon={Search} bind:value={query} type="search" aria-label={t("category.searchLabel")} placeholder={t("category.search")} class="min-w-60 flex-1" />
      <FilterMenu groups={filters} {active} onclear={() => ((topic = ""), (minimum = "low"))} />
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
      <div class="grid min-h-[240px] flex-1 grid-cols-[minmax(320px,42%)_1fr] gap-3">
        <div class="min-h-0 overflow-auto pr-1.5">
          <div bind:this={list} role="listbox" aria-label={t("category.listLabel")} tabindex="-1" onkeydown={keys} class="pb-1">
            {#each groups as g (g.topic)}
              <ListGroup heading={g.topic ? topicTitle(category, g.topic) : groups.length > 1 ? t("category.otherTopic") : undefined} count={g.items.length}>
                {#each g.items as i (i.id)}
                  {@const where = i.locations.length ? i.locations[0].label + (i.locations.length > 1 ? ` (+${i.locations.length - 1})` : "") : ""}
                  {@const on = current?.id === i.id}
                  <BoxRow
                    role="option"
                    aria-selected={on}
                    tabindex={on ? 0 : -1}
                    selected={on}
                    title={i.title}
                    subtitle={i.lensTitle + (where ? ` · ${where}` : "")}
                    icon={severityIcon(i.severity)}
                    tint={severityTint(i.severity)}
                    iconLabel={t(`severity.${i.severity}`)}
                    onclick={() => show(i.id)}
                  />
                {/each}
              </ListGroup>
            {/each}
          </div>
        </div>
        <Card class="overflow-auto p-5" aria-live="polite">
          {#if current}<FindingDetail item={current} {category} />{/if}
        </Card>
      </div>
    {/if}
  </section>
</Page>
