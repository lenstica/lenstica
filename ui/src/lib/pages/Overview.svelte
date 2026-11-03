<script lang="ts">
  // Every category at a glance, in the selected project, and what needs attention most.
  import { RefreshCw } from "@lucide/svelte";
  import { post } from "../api";
  import Button from "../components/Button.svelte";
  import Card from "../components/Card.svelte";
  import Empty from "../components/Empty.svelte";
  import LensGlyph from "../components/LensGlyph.svelte";
  import ListRow from "../components/ListRow.svelte";
  import Page from "../components/Page.svelte";
  import PageHeader from "../components/PageHeader.svelte";
  import SectionHeading from "../components/SectionHeading.svelte";
  import SeverityCounts from "../components/SeverityCounts.svelte";
  import SeverityIcon from "../components/SeverityIcon.svelte";
  import StateDot from "../components/StateDot.svelte";
  import Tag from "../components/Tag.svelte";
  import Tile from "../components/Tile.svelte";
  import { ago, t } from "../i18n/index.svelte";
  import { categoryIcon } from "../icons";
  import { categoryTitle, model, topicTitle } from "../model.svelte";

  const s = $derived(model.state!);
  const alerts = $derived(model.scoped.filter(model.isAlert));
  const running = $derived(s.lenses.filter((l) => l.running).length);
  const lastRun = $derived(
    s.lenses
      .filter((l) => l.enabled && l.result)
      .map((l) => l.result!.ran_at)
      .sort()
      .pop(),
  );
  const ok = $derived(alerts.length === 0);
  const severity = $derived(t(`severity.${s.alertSeverity}`).toLowerCase());
</script>

<Page>
  <PageHeader title={t("overview.title")} description={t("overview.checked", { scope: model.scopeTitle, when: ago(lastRun, model.now) })} />

  <Card class="mt-5 flex items-center gap-5 p-5">
    <div class="grid size-[56px] shrink-0 place-items-center rounded-2xl border border-rim {ok ? 'bg-glass-strong text-fg' : 'bg-attention/15 text-attention'}">
      <LensGlyph class="size-8" />
    </div>
    <div class="min-w-0 flex-1">
      <div class="text-lg font-semibold">{ok ? t("overview.nothing") : t("overview.needAttention", { count: alerts.length })}</div>
      <div class="text-sm text-muted">{t("overview.policy", { days: s.settings.min_days, severity })}</div>
      <div class="mt-2.5"><SeverityCounts items={model.scoped} /></div>
    </div>
    <Button variant="primary" disabled={running > 0} onclick={() => post({ type: "run" })}>
      <RefreshCw size={14} class={running ? "animate-spin motion-reduce:animate-none" : ""} />
      {running ? t("overview.checking", { count: running }) : t("overview.checkEverything")}
    </Button>
  </Card>

  <SectionHeading title={t("overview.categories")} class="mt-8" />
  <div class="grid grid-cols-[repeat(auto-fill,minmax(270px,1fr))] gap-3">
    {#each model.categories as c (c.id)}
      {@const Icon = categoryIcon(c.id)}
      {@const lenses = model.lensesIn(c.id)}
      {@const on = lenses.filter((l) => l.enabled).length}
      {@const found = model.itemsIn(c.id)}
      {@const needs = found.filter(model.isAlert).length}
      {@const status = model.categoryState(c.id)}
      <Tile onclick={() => model.go(c.id)}>
        <span class="flex items-center gap-2.5">
          <Icon size={18} strokeWidth={1.9} class="text-muted" />
          <span class="flex-1 text-md font-semibold">{categoryTitle(c)}</span>
          <StateDot state={status} />
        </span>
        <span class="text-sm {needs ? 'font-medium text-fg' : 'text-muted'}">
          {status === "off"
            ? t("overview.tileNoLens")
            : needs
              ? t("overview.tileNeed", { count: needs })
              : found.length
                ? t("overview.tileFindings", { count: found.length })
                : t("overview.tileNothing")}
        </span>
        {#if c.topics.length}
          <span class="flex flex-wrap gap-1.5">
            {#each c.topics as topic (topic.id)}
              <Tag>{topicTitle(c, topic.id)}&nbsp;<span class="tabular">{found.filter((i) => i.topic === topic.id).length}</span></Tag>
            {/each}
          </span>
        {/if}
        <span class="text-xs text-faint">{t("overview.lensesOn", { on, count: lenses.length })}</span>
      </Tile>
    {/each}
  </div>

  <SectionHeading title={t("overview.needsAttention")} class="mt-8" />
  <Card>
    {#each alerts.slice(0, 10) as i (i.id)}
      {@const c = model.categories.find((k) => k.id === i.category)}
      {#snippet icon()}<SeverityIcon severity={i.severity} />{/snippet}
      {#snippet where()}{c ? categoryTitle(c) : i.category}{/snippet}
      <ListRow
        title={i.title}
        subtitle={i.lensTitle + (i.locations[0] ? ` · ${i.locations[0].label}` : "")}
        leading={icon}
        trailing={where}
        onclick={() => model.go(i.category, i.id)}
      />
    {:else}
      <Empty title={t("overview.nothing")}>{t("overview.noneBody", { severity, scope: model.scopeTitle })}</Empty>
    {/each}
    {#if alerts.length > 10}
      <div class="px-4 py-2.5 text-xs text-faint">{t("overview.more", { count: alerts.length - 10 })}</div>
    {/if}
  </Card>
</Page>
