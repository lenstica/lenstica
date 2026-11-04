<script lang="ts">
  // One kind of asset: everything of that kind on this machine, grouped by
  // where it comes from and searchable, with each one's details and the
  // findings about it. Looked for afresh each time the page opens.
  import { tick } from "svelte";
  import { RefreshCw, Search, Settings2, Shield, ShieldAlert } from "@lucide/svelte";
  import { post } from "../api";
  import {
    factLabel,
    kindDescription,
    kindIcon,
    kindTitle,
    permissionAbout,
    permissionSummary,
    permissionTitle,
    sourceIcon,
    sourceTitle,
    tagLabel,
  } from "../assets";
  import BoxRow from "../components/BoxRow.svelte";
  import Button from "../components/Button.svelte";
  import BlindSpots, { type BlindSpot } from "../components/BlindSpots.svelte";
  import Callout from "../components/Callout.svelte";
  import Card from "../components/Card.svelte";
  import Disclosure from "../components/Disclosure.svelte";
  import Empty from "../components/Empty.svelte";
  import FilterMenu, { type FilterGroup } from "../components/FilterMenu.svelte";
  import IconButton from "../components/IconButton.svelte";
  import ListGroup from "../components/ListGroup.svelte";
  import ListRow from "../components/ListRow.svelte";
  import Page from "../components/Page.svelte";
  import PageHeader from "../components/PageHeader.svelte";
  import PathActions from "../components/PathActions.svelte";
  import SectionHeading from "../components/SectionHeading.svelte";
  import SeverityIcon from "../components/SeverityIcon.svelte";
  import Tag from "../components/Tag.svelte";
  import TextField from "../components/TextField.svelte";
  import { ago, t, tOr } from "../i18n/index.svelte";
  import { model, norm, rank, SEVERITIES } from "../model.svelte";
  import type { Asset, AssetKind, Item, Permission } from "../types";

  let { kind }: { kind: AssetKind } = $props();

  /** The facts a row shows under the name; the rest are in its details. */
  const SUMMARY: Record<AssetKind, string[]> = {
    identities: ["account", "email", "host", "signIn", "cluster", "keyType", "project", "subscriptions", "user", "comment"],
    repositories: ["branch", "remote"],
    applications: ["version", "bundleId"],
    containers: ["image", "state"],
    "virtual-machines": ["system", "arch", "type"],
    extensions: ["version", "profile", "publisher"],
  };
  /** Opening an app in an editor launches it, and an extension's folder says little: those are only shown and, for extensions, opened in a terminal. */
  const opens = $derived(kind === "identities" || kind === "repositories" || kind === "virtual-machines");

  let source = $state<string | null>(null);
  /** Only apps with an elevated permission, or with any. */
  let holding = $state<"elevated" | "any" | null>(null);
  let query = $state("");
  let selected = $state<string | null>(null);
  let list: HTMLDivElement | undefined = $state();

  const title = $derived(kindTitle(kind));
  const found = $derived(model.assets[kind]);
  const looking = $derived(model.assetsLoading.includes(kind));
  const all = $derived(found?.assets ?? []);
  // Rust sorts by source, those without one last.
  const sources = $derived([...new Set(all.map((a) => a.source))]);
  const allowed = (a: Asset) => (a.permissions ?? []).filter((p) => p.allowed);
  const holds = (a: Asset, which: "elevated" | "any") => allowed(a).some((p) => which === "any" || p.elevated);
  const elevatedCount = $derived(all.filter((a) => holds(a, "elevated")).length);
  const anyCount = $derived(all.filter((a) => holds(a, "any")).length);
  const shown = $derived.by(() => {
    const q = query.trim().toLowerCase();
    return all.filter(
      (a) =>
        (source === null || a.source === source) &&
        (holding === null || holds(a, holding)) &&
        (!q ||
          [a.name, a.source, ...a.facts.map((f) => f.value), ...a.tags.map(tagLabel), ...allowed(a).map(permissionTitle)]
            .join("\n")
            .toLowerCase()
            .includes(q)),
    );
  });
  const groups = $derived(
    sources.map((s) => ({ source: s, assets: shown.filter((a) => a.source === s) })).filter((g) => g.assets.length),
  );
  const current = $derived(shown.find((a) => a.id === selected) ?? shown[0] ?? null);
  // Where they come from and, for apps, what they may do.
  const filters = $derived.by(() => {
    const out: FilterGroup[] = [];
    if (sources.length > 1)
      out.push({
        heading: t("assets.filterSource"),
        value: source === null ? "all" : `s:${source}`,
        onchange: (v) => (source = v === "all" ? null : v.slice(2)),
        options: [
          { value: "all", label: t("assets.all"), count: all.length },
          ...sources.map((s) => ({ value: `s:${s}`, label: sourceTitle(kind, s), count: all.filter((a) => a.source === s).length, ...sourceIcon(kind, s) })),
        ],
      });
    if (anyCount)
      out.push({
        heading: t("assets.filterPermissions"),
        value: holding ?? "all",
        onchange: (v) => (holding = v === "all" ? null : (v as "elevated" | "any")),
        options: [
          { value: "all", label: t("assets.all"), count: all.length },
          ...(elevatedCount ? [{ value: "elevated", label: t("assets.filterElevated"), count: elevatedCount, icon: ShieldAlert, tint: "var(--t-high)" }] : []),
          { value: "any", label: t("assets.filterAny"), count: anyCount, icon: Shield },
        ],
      });
    return out;
  });
  const active = $derived(
    [source === null ? "" : sourceTitle(kind, source), holding ? t(holding === "elevated" ? "assets.filterElevated" : "assets.filterAny") : ""].filter(Boolean),
  );
  const running = $derived(all.filter((a) => a.status === "running").length);
  const about = $derived(new Map(all.map((a) => [a.id, model.findingsAbout(kind, a)])));
  const alertsOf = (a: Asset) => (about.get(a.id) ?? []).filter(model.isAlert);
  // Rust sorts by source, and groups keep that order, so the arrow keys (which follow `shown`) move down the list as drawn.
  const worst = (items: Item[]) => SEVERITIES[items.reduce((m, i) => Math.max(m, rank(i.severity)), 0)];

  function summary(a: Asset) {
    const keys = SUMMARY[kind];
    const picked = a.facts.filter((f) => keys.includes(f.key)).sort((x, y) => keys.indexOf(x.key) - keys.indexOf(y.key));
    return (picked.length ? picked : a.facts).slice(0, 2).map((f) => f.value).join(" · ");
  }

  function show(id: string) {
    selected = id;
    tick().then(() => list?.querySelector<HTMLElement>('[aria-selected="true"]')?.scrollIntoView({ block: "nearest" }));
  }

  // The list moves with the arrow keys, Home and End; only the selected row is in the Tab order.
  function keys(e: KeyboardEvent) {
    const at = shown.findIndex((a) => a.id === current?.id);
    const to =
      e.key === "ArrowDown" ? at + 1 : e.key === "ArrowUp" ? at - 1 : e.key === "Home" ? 0 : e.key === "End" ? shown.length - 1 : null;
    if (to === null || !shown.length) return;
    e.preventDefault();
    show(shown[Math.max(0, Math.min(shown.length - 1, to))].id);
    tick().then(() => list?.querySelector<HTMLElement>('[aria-selected="true"]')?.focus());
  }

  // What this look could not include, behind the button beside Check now.
  const spots = $derived.by(() => {
    const out: BlindSpot[] = [];
    const macos = model.state?.platform === "macos";
    if (found?.blocked.length)
      out.push({
        title: t("blindSpots.blocked"),
        body: t("assets.blocked", { names: found.blocked.join(", ") }),
        action: { label: t("assets.openFullDiskAccess"), onclick: () => post({ type: "openPermissionSettings", key: "fullDiskAccess" }) },
      });
    for (const note of found?.notes ?? [])
      out.push({
        title: tOr(`blindSpots.notes.${note}`, t("blindSpots.note")),
        body: tOr(`assets.notes.${note}`, ""),
        action: macos ? { label: t("assets.openPrivacy"), onclick: () => post({ type: "openPermissionSettings", key: "privacy" }) } : undefined,
      });
    if (found?.notRunning.length)
      out.push({ title: t("blindSpots.notRunning"), body: t("assets.notRunning", { names: found.notRunning.join(", ") }) });
    if (found?.errors.length) out.push({ title: t("assets.errors", { count: found.errors.length }), lines: found.errors });
    return out;
  });

  // A repository the project picker offers (one left out of checks is not).
  const project = $derived(kind === "repositories" && current?.path ? model.projects.find((p) => p.path === norm(current.path!)) : undefined);
</script>

<!-- Running, paused or stopped, as a dot named for screen readers. -->
{#snippet status(a: Asset)}
  {#if a.status}
    {@const name = t(`assets.status.${a.status}`)}
    <span
      class="inline-block size-[8px] shrink-0 rounded-full {a.status === 'running'
        ? 'bg-clear'
        : a.status === 'paused'
          ? 'bg-medium'
          : 'border-[1.5px] border-faint'}"
      title={name}
      role="img"
      aria-label={name}
    ></span>
  {/if}
{/snippet}

<!-- One permission an app holds: what it is, what it allows, who set it, and where to change it. -->
{#snippet permission(p: Permission)}
  <div class="flex items-start gap-3 border-b border-line px-4 py-2.5 last:border-0">
    <span class="pt-0.5 {p.elevated ? 'text-t-high' : 'text-faint'}">
      {#if p.elevated}<ShieldAlert size={15} aria-hidden="true" />{:else}<Shield size={15} aria-hidden="true" />{/if}
    </span>
    <div class="min-w-0 flex-1">
      <div class="text-base font-medium">
        {permissionTitle(p)}{#if p.detail}<span class="font-normal text-muted"> · {p.detail}</span>{/if}
        {#if p.elevated}<span class="sr-only">, {t("assets.tags.elevated")}</span>{/if}
      </div>
      <div class="text-xs text-muted">{permissionAbout(p)}</div>
      {#if p.by === "organization" || p.by === "system"}<div class="mt-0.5 text-xs text-faint">{t(`assets.by.${p.by}`)}</div>{/if}
    </div>
    {#if p.settings && model.state?.platform === "macos"}
      <IconButton icon={Settings2} label={t("assets.changeInSettings")} onclick={() => post({ type: "openPermissionSettings", key: p.key })} />
    {/if}
  </div>
{/snippet}

{#snippet meta()}
  <span class="font-medium">{found ? t("assets.count", { count: all.length }) : t("assets.looking")}</span>
  {#if running}<span class="text-faint">· {t("assets.running", { count: running })}</span>{/if}
  {#if found}
    <span class="text-faint">· {looking ? t("assets.looking") : t("assets.looked", { ago: ago(new Date(model.assetsAt[kind] ?? model.now).toISOString(), model.now) })}</span>
  {/if}
{/snippet}
{#snippet actions()}
  <BlindSpots {spots} />
  <Button variant="primary" disabled={looking} onclick={() => model.loadAssets([kind], true)}>
    <RefreshCw size={14} class={looking ? "animate-spin" : ""} />{t("assets.checkNow")}
  </Button>
{/snippet}

<Page fill>
  <PageHeader {title} description={kindDescription(kind)} icon={kindIcon(kind)} {meta} {actions} />

  <section class="mt-6 flex min-h-0 flex-1 flex-col">
    {#if !found}
      <Card>
        {#if model.assetsError && !looking}
          <Empty title={t("assets.loadError")}>{model.assetsError}</Empty>
        {:else}
          <Empty title={t("assets.looking")} />
        {/if}
      </Card>
    {:else if !found.supported}
      <Card><Empty title={t("assets.unsupported")} /></Card>
    {:else if !all.length}
      <Card><Empty title={tOr(`assets.kinds.${kind}.empty`, t("assets.noMatchTitle"))} /></Card>
    {:else}
      <div class="mb-3 flex gap-2">
        <TextField
          icon={Search}
          bind:value={query}
          type="search"
          aria-label={t("assets.searchLabel", { kind: title })}
          placeholder={t("assets.search")}
          class="min-w-60 flex-1"
        />
        {#if filters.length}
          <FilterMenu groups={filters} {active} onclear={() => ((source = null), (holding = null))} />
        {/if}
      </div>

      {#if !shown.length}
        <Card><Empty title={t("assets.noMatchTitle")}>{t("assets.noMatchBody")}</Empty></Card>
      {:else}
        <div class="grid min-h-[240px] flex-1 grid-cols-[minmax(300px,42%)_1fr] gap-3">
          <!-- A rounded box of rows per source, each row led by its source's icon. -->
          <div class="@container min-h-0 overflow-auto pr-1.5">
            <div bind:this={list} role="listbox" aria-label={t("assets.listLabel", { kind: title })} tabindex="-1" onkeydown={keys} class="pb-1">
              {#each groups as g (g.source)}
                {@const from = sourceIcon(kind, g.source)}
                <ListGroup heading={sourceTitle(kind, g.source)} count={g.assets.length}>
                  {#each g.assets as a (a.id)}
                    {@const alerts = alertsOf(a)}
                    {@const granted = allowed(a)}
                    {@const elevated = granted.filter((p) => p.elevated).length}
                    {@const tags = a.tags.filter((tag) => tag.key !== "elevated")}
                    {@const on = current?.id === a.id}
                    <!-- The worst finding about it that needs attention, on the icon's corner. -->
                    {#snippet badge()}<SeverityIcon severity={worst(alerts)} size={13} />{/snippet}
                    {#snippet before()}{@render status(a)}{/snippet}
                    {#snippet trailing()}
                      <!-- Tags only where the name still fits beside them; the details show them all. -->
                      {#if tags.length}
                        <span class="hidden items-center gap-1.5 @[25rem]:flex">
                          {#each tags.slice(0, 2) as tag (tag.key)}<Tag>{tagLabel(tag)}</Tag>{/each}
                        </span>
                      {/if}
                      <!-- How many permissions it holds; in the high colour when one is elevated. -->
                      {#if granted.length}
                        <span
                          class="inline-flex items-center gap-1 text-xs font-medium tabular {elevated ? 'text-t-high' : 'text-muted'}"
                          title={t("assets.permissionsTitle", { count: granted.length })}
                        >
                          {#if elevated}<ShieldAlert size={13} aria-hidden="true" />{:else}<Shield size={13} aria-hidden="true" />{/if}
                          <span aria-hidden="true">{granted.length}</span><span class="sr-only">{t("assets.permissionsTitle", { count: granted.length })}</span>
                        </span>
                      {/if}
                    {/snippet}
                    <BoxRow
                      role="option"
                      aria-selected={on}
                      tabindex={on ? 0 : -1}
                      selected={on}
                      title={a.name}
                      subtitle={granted.length ? permissionSummary(granted) : summary(a)}
                      icon={from.icon}
                      tint={from.tint}
                      badge={alerts.length ? badge : undefined}
                      before={a.status ? before : undefined}
                      trailing={tags.length || granted.length ? trailing : undefined}
                      onclick={() => show(a.id)}
                    />
                  {/each}
                </ListGroup>
              {/each}
            </div>
          </div>

          <Card class="overflow-auto p-5" aria-live="polite">
            {#if current}
              {@const findings = about.get(current.id) ?? []}
              {@const alerts = findings.filter(model.isAlert)}
              <div class="flex flex-wrap items-center gap-2">
                {#if current.status}
                  <span class="inline-flex items-center gap-1.5 text-xs font-medium text-muted">
                    {@render status(current)}{t(`assets.status.${current.status}`)}
                  </span>
                {/if}
                <Tag>{sourceTitle(kind, current.source)}</Tag>
                {#each current.tags as tag (tag.key)}<Tag>{tagLabel(tag)}</Tag>{/each}
              </div>
              <SectionHeading level={3} size="lg" title={current.name} class="mt-2.5" />

              {#each current.tags as tag (tag.key)}
                {@const note = tOr(`assets.tagNotes.${tag.key}`, "")}
                {#if note}
                  <Callout tone={tag.key === "credentialsInFile" || tag.key === "allSites" ? "attention" : "neutral"} class="mt-3">{note}</Callout>
                {/if}
              {/each}

              {#if current.facts.length}
                <dl class="m-0 mt-4 grid grid-cols-[max-content_minmax(0,1fr)] gap-x-5 gap-y-2 text-sm">
                  {#each current.facts as f (f.key)}
                    <dt class="text-muted">{factLabel(f)}</dt>
                    <dd class="m-0 break-words">{f.value}</dd>
                  {/each}
                </dl>
              {/if}

              {#if current.permissions?.length}
                {@const on = current.permissions.filter((p) => p.allowed)}
                {@const off = current.permissions.filter((p) => !p.allowed)}
                <SectionHeading
                  level={4}
                  size="sm"
                  title={t("assets.permissionsTitle", { count: on.length })}
                  note={t("assets.permissionsNote")}
                  class="mb-1 mt-6"
                />
                {#if on.length}
                  <Card>{#each on as p (p.key + (p.detail ?? ""))}{@render permission(p)}{/each}</Card>
                {/if}
                {#if off.length}
                  <div class="mt-2">
                    <Disclosure summary={t("assets.turnedOff", { count: off.length })}>
                      <ul class="m-0 mt-1.5 list-none p-0">
                        {#each off as p (p.key + (p.detail ?? ""))}
                          <li class="py-0.5">{permissionTitle(p)}{p.detail ? ` · ${p.detail}` : ""}</li>
                        {/each}
                      </ul>
                    </Disclosure>
                  </div>
                {/if}
              {/if}

              {#if current.path}
                <div class="@container mt-4 flex items-center gap-2 border-t border-line pt-3 font-mono text-xs">
                  <span class="min-w-0 flex-1 truncate" title={current.path}>{current.path}</span>
                  <span class="flex shrink-0 font-sans">
                    <PathActions path={current.path} edit={opens} terminal={kind !== "applications"} />
                  </span>
                </div>
              {/if}

              {#if project}
                <div class="mt-4">
                  <Button
                    onclick={() => {
                      model.setScope(project.path);
                      model.go("overview");
                    }}
                  >
                    {t("assets.showProject")}
                  </Button>
                </div>
              {/if}

              {#if findings.length}
                <SectionHeading
                  level={4}
                  size="sm"
                  title={t("assets.findings", { count: findings.length })}
                  aside={alerts.length ? t("assets.needAttention", { count: alerts.length }) : undefined}
                  note={kind === "repositories" ? null : t("assets.findingsNote")}
                  class="mb-1 mt-6"
                />
                <Card>
                  {#each findings.slice(0, 25) as i (i.id)}
                    {#snippet icon()}<SeverityIcon severity={i.severity} />{/snippet}
                    <ListRow title={i.title} subtitle={i.lensTitle} leading={icon} onclick={() => model.go(i.category, i.id)} />
                  {/each}
                </Card>
              {/if}
            {/if}
          </Card>
        </div>
      {/if}
    {/if}
  </section>
</Page>
