<script lang="ts">
  // The Network page's live view: every program accepting TCP connections,
  // split into what other devices can reach and what only this machine can,
  // each with the severity of the listening-ports finding that covers it.
  import { onDestroy } from "svelte";
  import { Network, RefreshCw } from "@lucide/svelte";
  import { listListening, post } from "../api";
  import BoxRow from "../components/BoxRow.svelte";
  import Card from "../components/Card.svelte";
  import Disclosure from "../components/Disclosure.svelte";
  import Empty from "../components/Empty.svelte";
  import IconButton from "../components/IconButton.svelte";
  import ListGroup from "../components/ListGroup.svelte";
  import { t } from "../i18n/index.svelte";
  import { severityIcon, severityTint } from "../icons";
  import { model, rank } from "../model.svelte";
  import type { Listening } from "../types";

  const LENS = "listening-ports";

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

<!-- A program and port: the severity of the finding about it (a click shows the finding), or a plain network icon. -->
{#snippet row(l: Listening)}
  {@const f = findingOf(l)}
  {@const where = [t("network.port", { port: String(l.port) }), l.sockets, l.allInterfaces ? t("network.everyInterface") : "", t("network.pids", { pids: l.pids.join(", ") })]}
  <BoxRow
    title={l.process}
    subtitle={where.filter(Boolean).join(" · ")}
    icon={f ? severityIcon(f.severity) : Network}
    tint={f ? severityTint(f.severity) : null}
    iconLabel={f ? t(`severity.${f.severity}`) : undefined}
    hint={f ? t("network.showFinding") : l.path}
    onclick={f ? () => model.go("network", `${f.lens}|${f.key}`) : undefined}
  />
{/snippet}

<!-- At most a little under half the page, scrolling inside, so the findings below keep their room. -->
<section class="mt-5 flex max-h-[42%] min-h-0 shrink flex-col" aria-label={t("network.listening")}>
  <div class="flex items-center gap-2">
    <h2 class="m-0 text-sm font-semibold">{t("network.listening")}</h2>
    {#if list}<span class="text-sm text-faint">{t("network.count", { count: list.length })}</span>{/if}
    <span class="flex-1"></span>
    <IconButton icon={RefreshCw} label={t("network.refresh")} onclick={refresh} />
  </div>
  <p class="mb-2.5 mt-0 text-xs text-muted">{t("network.visibility")}</p>
  <div class="min-h-0 overflow-auto pr-1.5">
    {#if error}
      <Card><Empty title={t("network.error")}>{error}</Empty></Card>
    {:else if !list}
      <Card><Empty title={t("network.loading")} /></Card>
    {:else}
      <ListGroup heading={t("network.reachable")} count={reachable.length} note={t("network.reachableNote")}>
        {#each reachable as l (`${l.process}|${l.port}`)}{@render row(l)}{:else}<Empty title={t("network.noneReachable")} />{/each}
      </ListGroup>
      <div class="mt-3">
        <Disclosure summary={t("network.local", { count: local.length })}>
          <p class="mb-2 mt-1.5">{t("network.localNote")}</p>
          <ListGroup>
            {#each local as l (`${l.process}|${l.port}`)}{@render row(l)}{:else}<Empty title={t("network.noneLocal")} />{/each}
          </ListGroup>
        </Disclosure>
      </div>
    {/if}
  </div>
</section>
