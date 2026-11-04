<script lang="ts">
  // One kind of asset: everything of that kind on this machine, grouped by
  // where it comes from and searchable, with each one's details and the
  // findings about it. Looked for afresh each time the page opens.
  import { tick } from "svelte";
  import { File, FolderOpen, ListFilter, RefreshCw, Search, Settings2, Shield, ShieldAlert } from "@lucide/svelte";
  import { post } from "../api";
  import {
    factLabel,
    kindDescription,
    kindIcon,
    kindTitle,
    permissionAbout,
    permissionSummary,
    permissionTitle,
    sourceTitle,
    tagLabel,
  } from "../assets";
  import Button from "../components/Button.svelte";
  import Callout from "../components/Callout.svelte";
  import Card from "../components/Card.svelte";
  import Chip from "../components/Chip.svelte";
  import Disclosure from "../components/Disclosure.svelte";
  import Empty from "../components/Empty.svelte";
  import Eyebrow from "../components/Eyebrow.svelte";
  import IconButton from "../components/IconButton.svelte";
  import ListRow from "../components/ListRow.svelte";
  import Page from "../components/Page.svelte";
  import PageHeader from "../components/PageHeader.svelte";
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
  /** Opening an app launches it, and an extension's folder says little: those are only revealed. */
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
  <Button variant="primary" disabled={looking} onclick={() => model.loadAssets([kind], true)}>
    <RefreshCw size={14} class={looking ? "animate-spin" : ""} />{t("assets.lookAgain")}
  </Button>
{/snippet}

<Page>
  <PageHeader {title} description={kindDescription(kind)} icon={kindIcon(kind)} {meta} {actions} />

  {#if found?.notRunning.length}
    <Callout class="mt-5">{t("assets.notRunning", { names: found.notRunning.join(", ") })}</Callout>
  {/if}
  {#if found?.blocked.length}
    <Callout class="mt-3 flex items-center justify-between gap-3">
      <span>{t("assets.blocked", { names: found.blocked.join(", ") })}</span>
      <Button onclick={() => post({ type: "openPermissionSettings", key: "fullDiskAccess" })}>{t("assets.openFullDiskAccess")}</Button>
    </Callout>
  {/if}
  {#if found?.errors.length}
    <div class="mt-3">
      <Disclosure summary={t("assets.errors", { count: found.errors.length })}>
        <ul class="m-0 mt-1.5 list-none p-0 font-mono">
          {#each found.errors as e (e)}<li class="py-0.5">{e}</li>{/each}
        </ul>
      </Disclosure>
    </div>
  {/if}

  <section class="mt-6">
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
      {#if sources.length > 1 || anyCount}
        <div class="mb-3 flex flex-wrap items-center gap-2">
          <ListFilter size={15} class="text-faint" aria-hidden="true" />
          <Chip selected={source === null} count={all.length} onclick={() => (source = null)}>{t("assets.all")}</Chip>
          {#if sources.length > 1}
            {#each sources as s (s)}
              <Chip selected={source === s} count={all.filter((a) => a.source === s).length} onclick={() => (source = source === s ? null : s)}>
                {sourceTitle(kind, s)}
              </Chip>
            {/each}
          {/if}
          {#if anyCount}
            <span class="mx-1 h-5 w-px bg-line" aria-hidden="true"></span>
            {#if elevatedCount}
              <Chip selected={holding === "elevated"} count={elevatedCount} onclick={() => (holding = holding === "elevated" ? null : "elevated")}>
                <ShieldAlert size={14} class="text-t-high" aria-hidden="true" />{t("assets.filterElevated")}
              </Chip>
            {/if}
            <Chip selected={holding === "any"} count={anyCount} onclick={() => (holding = holding === "any" ? null : "any")}>
              <Shield size={14} aria-hidden="true" />{t("assets.filterAny")}
            </Chip>
          {/if}
        </div>
      {/if}
      <div class="mb-3 flex">
        <TextField
          icon={Search}
          bind:value={query}
          type="search"
          aria-label={t("assets.searchLabel", { kind: title })}
          placeholder={t("assets.search")}
          class="min-w-60 flex-1"
        />
      </div>

      {#if !shown.length}
        <Card><Empty title={t("assets.noMatchTitle")}>{t("assets.noMatchBody")}</Empty></Card>
      {:else}
        <div class="grid h-[max(420px,calc(100vh-280px))] grid-cols-[minmax(300px,42%)_1fr] gap-3">
          <Card class="overflow-auto">
            <div bind:this={list} role="listbox" aria-label={t("assets.listLabel", { kind: title })} tabindex="-1" onkeydown={keys}>
              {#each groups as g (g.source)}
                {@const heading = sourceTitle(kind, g.source)}
                <div role="group" aria-label={heading}>
                  <div class="sticky top-0 z-10 border-b border-line bg-panel px-4 pb-1 pt-2.5" aria-hidden="true">
                    <Eyebrow tone="muted">{heading} <span class="tabular text-faint">{g.assets.length}</span></Eyebrow>
                  </div>
                  {#each g.assets as a (a.id)}
                    {@const alerts = alertsOf(a)}
                    {@const granted = allowed(a)}
                    {@const elevated = granted.filter((p) => p.elevated).length}
                    {@const tags = a.tags.filter((tag) => tag.key !== "elevated")}
                    {#snippet lead()}
                      <span class="grid w-4 place-items-center pt-0.5">
                        {#if alerts.length}<SeverityIcon severity={worst(alerts)} />{:else}{@render status(a)}{/if}
                      </span>
                    {/snippet}
                    {#snippet end()}
                      <span class="flex flex-wrap items-center justify-end gap-1.5">
                        {#each tags.slice(0, 2) as tag (tag.key)}<Tag>{tagLabel(tag)}</Tag>{/each}
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
                      </span>
                    {/snippet}
                    <ListRow
                      role="option"
                      aria-selected={current?.id === a.id}
                      tabindex={current?.id === a.id ? 0 : -1}
                      selected={current?.id === a.id}
                      title={a.name}
                      subtitle={granted.length ? permissionSummary(granted) : summary(a)}
                      leading={lead}
                      trailing={end}
                      onclick={() => show(a.id)}
                    />
                  {/each}
                </div>
              {/each}
            </div>
          </Card>

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
                <div class="mt-4 flex items-center gap-2 border-t border-line pt-3 font-mono text-xs">
                  <span class="min-w-0 flex-1 truncate" title={current.path}>{current.path}</span>
                  {#if opens}
                    <Button variant="quiet" onclick={() => post({ type: "open", path: current.path })}><File size={14} />{t("finding.open")}</Button>
                  {/if}
                  <Button variant="quiet" onclick={() => post({ type: "open", path: current.path, reveal: true })}>
                    <FolderOpen size={14} />{t("finding.reveal")}
                  </Button>
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
