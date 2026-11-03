<script lang="ts">
  // The Network page's live view: every program accepting TCP connections,
  // split into what other devices can reach and what only this machine can,
  // each with the severity of the listening-ports finding that covers it.
  import { onDestroy } from "svelte";
  import { RefreshCw } from "@lucide/svelte";
  import { listListening, post } from "../api";
  import Card from "../components/Card.svelte";
  import Disclosure from "../components/Disclosure.svelte";
  import Empty from "../components/Empty.svelte";
  import IconButton from "../components/IconButton.svelte";
  import SectionHeading from "../components/SectionHeading.svelte";
  import SeverityIcon from "../components/SeverityIcon.svelte";
  import { t } from "../i18n/index.svelte";
  import { model, rank } from "../model.svelte";
  import type { Finding, Listening } from "../types";

  const LENS = "listening-ports";
  const ROW =
    "grid w-full grid-cols-[20px_minmax(140px,1.2fr)_64px_minmax(160px,2fr)] items-center gap-3 border-b border-line px-4 py-2 text-left last:border-0";

  let list = $state<Listening[] | null>(null);
  let error = $state<string | null>(null);

  function load() {
    listListening()
      .then((l) => {
        list = l;
        error = null;
      })
      .catch((e) => (error = String(e)));
  }
  load();
  // Programs start and stop all the time: keep the list current while the page is open.
  const timer = setInterval(() => document.hidden || load(), 10_000);
  onDestroy(() => clearInterval(timer));

  const lens = $derived(model.state?.lenses.find((l) => l.id === LENS));
  const findings = $derived(new Map((lens?.enabled ? (lens.result?.findings ?? []) : []).map((f) => [f.key, f])));
  const findingOf = (l: Listening) => (l.findingKey ? findings.get(l.findingKey) : undefined);
  const severityOf = (l: Listening) => {
    const f = findingOf(l);
    return f ? rank(f.severity) : -1;
  };
  // Riskiest first, then by program and port.
  const reachable = $derived(
    (list ?? [])
      .filter((l) => l.reach === "network")
      .sort((a, b) => severityOf(b) - severityOf(a) || a.process.localeCompare(b.process) || a.port - b.port),
  );
  const local = $derived((list ?? []).filter((l) => l.reach === "local"));

  function refresh() {
    load();
    if (lens?.enabled) post({ type: "run", lenses: [LENS] });
  }
</script>

{#snippet cells(l: Listening, f: Finding | undefined)}
  <span>{#if f}<SeverityIcon severity={f.severity} />{/if}</span>
  <span class="min-w-0">
    <span class="block truncate text-base font-medium">{l.process}</span>
    <span class="block truncate text-xs text-faint">{t("network.pids", { pids: l.pids.join(", ") })}</span>
  </span>
  <span class="font-semibold tabular-nums">{l.port}</span>
  <span class="min-w-0">
    <span class="block truncate font-mono text-xs">{l.sockets}</span>
    {#if l.allInterfaces}<span class="block text-xs text-faint">{t("network.everyInterface")}</span>{/if}
  </span>
{/snippet}

{#snippet row(l: Listening)}
  {@const f = findingOf(l)}
  {#if f}
    <button type="button" class="{ROW} hover:bg-glass" title={t("network.showFinding")} onclick={() => model.go("network", `${f.lens}|${f.key}`)}>
      {@render cells(l, f)}
    </button>
  {:else}
    <div class={ROW} title={l.path}>{@render cells(l, f)}</div>
  {/if}
{/snippet}

{#snippet action()}<IconButton icon={RefreshCw} label={t("network.refresh")} onclick={refresh} />{/snippet}

<section class="mt-8">
  <SectionHeading
    title={t("network.listening")}
    aside={list ? t("network.count", { count: list.length }) : undefined}
    note={t("network.visibility")}
    {action}
  />
  {#if error}
    <Card><Empty title={t("network.error")}>{error}</Empty></Card>
  {:else if !list}
    <Card><Empty title={t("network.loading")} /></Card>
  {:else}
    <SectionHeading level={3} size="sm" title={t("network.reachable")} aside={String(reachable.length)} note={t("network.reachableNote")} />
    <Card>
      {#each reachable as l (`${l.process}|${l.port}`)}{@render row(l)}{:else}<Empty title={t("network.noneReachable")} />{/each}
    </Card>
    <div class="mt-3">
      <Disclosure summary={t("network.local", { count: local.length })}>
        <p class="mb-2 mt-1.5">{t("network.localNote")}</p>
        <Card>
          {#each local as l (`${l.process}|${l.port}`)}{@render row(l)}{:else}<Empty title={t("network.noneLocal")} />{/each}
        </Card>
      </Disclosure>
    </div>
  {/if}
</section>
