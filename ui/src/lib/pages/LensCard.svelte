<script lang="ts">
  import { RefreshCw } from "@lucide/svelte";
  import { post } from "../api";
  import Button from "../components/Button.svelte";
  import Callout from "../components/Callout.svelte";
  import Card from "../components/Card.svelte";
  import Disclosure from "../components/Disclosure.svelte";
  import StateDot from "../components/StateDot.svelte";
  import Switch from "../components/Switch.svelte";
  import Tag from "../components/Tag.svelte";
  import { ago, t } from "../i18n/index.svelte";
  import { model } from "../model.svelte";
  import type { Lens } from "../types";

  let { lens }: { lens: Lens } = $props();

  const r = $derived(lens.result);
  const status = $derived(
    !lens.enabled
      ? t("lens.off")
      : lens.running
        ? t("lens.runningStatus")
        : !r
          ? t("lens.notRun")
          : t("lens.status", {
              summary: r.error ? t("lens.failed", { error: r.error }) : r.summary,
              when: ago(r.ran_at, model.now),
              seconds: r.seconds.toFixed(1),
            }),
  );
</script>

<Card class="flex flex-col gap-2 p-4">
  <div class="flex items-center gap-2.5">
    <StateDot state={model.lensState(lens)} />
    <h3 class="m-0 min-w-0 truncate text-base font-semibold">{lens.title}</h3>
    {#if lens.thirdParty}<Tag title={lens.thirdParty}>{t("lens.thirdParty")}</Tag>{/if}
    {#if lens.origin !== "built-in"}<Tag>{lens.origin}</Tag>{/if}
    <span class="flex-1"></span>
    <Button variant="quiet" disabled={lens.running || !lens.enabled} onclick={() => post({ type: "run", lens: lens.id })} title={t("lens.runTitle", { lens: lens.title })}>
      <RefreshCw size={14} class={lens.running ? "animate-spin motion-reduce:animate-none" : ""} />
      {lens.running ? t("lens.running") : t("lens.run")}
    </Button>
    <Switch
      checked={lens.enabled}
      label={lens.enabled ? t("lens.turnOff", { lens: lens.title }) : t("lens.turnOn", { lens: lens.title })}
      onchange={(on) => post({ type: "toggleLens", id: lens.id, enabled: on })}
    />
  </div>
  <p class="m-0 line-clamp-2 text-sm text-muted" title={lens.description}>{lens.description}</p>
  {#if lens.thirdParty && !lens.enabled}
    <Callout class="text-xs text-muted"><span class="font-semibold text-fg">{t("lens.offUntil")}</span> {lens.thirdParty}</Callout>
  {/if}
  <div class="flex items-center gap-2 text-xs text-faint">
    <span class="min-w-0 truncate" title={status}>{status}</span>
    <span class="flex-1"></span>
    <span class="shrink-0">{t("lens.every", { minutes: lens.intervalMinutes })}</span>
  </div>
  {#if lens.enabled && r?.passing.length}
    <Disclosure summary={t("lens.checked", { count: r.passing.length })}>
      <ul class="mb-0 mt-1.5 space-y-0.5 pl-4">
        {#each r.passing as p, i (i)}<li>{p}</li>{/each}
      </ul>
    </Disclosure>
  {/if}
</Card>
