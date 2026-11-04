<script lang="ts">
  import { ClipboardCopy, EyeOff, Wrench } from "@lucide/svelte";
  import { post } from "../api";
  import Button from "../components/Button.svelte";
  import Callout from "../components/Callout.svelte";
  import CodeBlock from "../components/CodeBlock.svelte";
  import LinkButton from "../components/LinkButton.svelte";
  import PathActions from "../components/PathActions.svelte";
  import SectionHeading from "../components/SectionHeading.svelte";
  import SeverityIcon from "../components/SeverityIcon.svelte";
  import Tag from "../components/Tag.svelte";
  import { t } from "../i18n/index.svelte";
  import { model, topicTitle } from "../model.svelte";
  import type { Category, Item } from "../types";

  let { item, category }: { item: Item; category: Category } = $props();

  // Dependency findings' keys are `<kind>|<ecosystem>|<name>|<version>[|<advisories>]`.
  const DEP_KINDS = ["vuln", "malware", "telemetry", "too-new", "locked-young", "deprecated", "yanked"];
  const parts = $derived(item.key.split("|"));
  const pkg = $derived(DEP_KINDS.includes(parts[0]) && parts.length >= 4 ? { name: parts[2], version: parts[3] } : null);
  const advisories = $derived(parts[0] === "vuln" && parts[4] ? parts[4].split(",").slice(0, 3) : []);
  // Listening-ports keys: `listen|<program>` or `listen|<program>|<port>`.
  const listener = $derived(item.lens === "listening-ports" && parts[0] === "listen" ? { program: parts[1], port: parts[2] } : null);
</script>

<div class="flex flex-wrap items-center gap-2">
  <SeverityIcon severity={item.severity} label />
  {#if item.topic}<Tag>{topicTitle(category, item.topic)}</Tag>{/if}
  <Tag>{item.lensTitle}</Tag>
</div>
<SectionHeading level={3} size="lg" title={item.title} class="mt-2.5" />

{#if item.detail}<CodeBlock text={item.detail} class="mt-3" />{/if}
{#if item.remedy}<Callout title={t("finding.whatToDo")} class="mt-3">{item.remedy}</Callout>{/if}

<div class="mt-4 flex flex-wrap gap-2">
  {#if item.fixable}
    <Button variant="primary" onclick={() => post({ type: "fix", lens: item.lens, key: item.key })}><Wrench size={14} />{t("finding.fix")}</Button>
  {/if}
  <Button title={t("finding.copyPromptTitle")} onclick={() => model.showPrompt([{ lens: item.lens, key: item.key }], item.title)}>
    <ClipboardCopy size={14} />{t("finding.copyPrompt")}
  </Button>
  {#if pkg}
    <Button onclick={() => post({ type: "ignorePackage", entry: `${pkg.name}@${pkg.version}`, lens: item.lens })}>
      <EyeOff size={14} />{t("finding.ignoreVersion", { name: pkg.name, version: pkg.version })}
    </Button>
    <Button onclick={() => post({ type: "ignorePackage", entry: pkg.name, lens: item.lens })}>
      <EyeOff size={14} />{t("finding.ignoreAll", { name: pkg.name })}
    </Button>
  {/if}
  {#if listener}
    {#if listener.port}
      <Button onclick={() => post({ type: "ignoreListener", entry: `${listener.program}:${listener.port}` })}>
        <EyeOff size={14} />{t("finding.ignoreListenerPort", { program: listener.program, port: listener.port })}
      </Button>
    {/if}
    <Button onclick={() => post({ type: "ignoreListener", entry: listener.program })}>
      <EyeOff size={14} />{t("finding.ignoreAll", { name: listener.program })}
    </Button>
  {/if}
  {#each advisories as id (id)}
    <Button onclick={() => post({ type: "ignoreAdvisory", id })}><EyeOff size={14} />{t("finding.ignoreAdvisory", { id })}</Button>
  {/each}
</div>

{#if item.locations.length}
  <SectionHeading level={4} size="sm" title={t("finding.where", { count: item.locations.length })} class="mb-1 mt-5" />
  <ul class="@container m-0 list-none p-0">
    {#each item.locations as l, i (i)}
      <li class="flex items-center gap-2 border-b border-dashed border-line py-1 font-mono text-xs last:border-0">
        <span class="min-w-0 flex-1 truncate" title={l.label}>{l.label}{l.line ? `:${l.line}` : ""}</span>
        {#if l.path}
          <span class="flex shrink-0 font-sans">
            <PathActions path={l.path} />
          </span>
        {/if}
      </li>
    {/each}
  </ul>
{/if}

{#if item.links.length}
  <SectionHeading level={4} size="sm" title={t("finding.references")} class="mb-1 mt-5" />
  {#each item.links as url (url)}
    <div class="py-0.5 text-sm"><LinkButton onclick={() => post({ type: "openUrl", url })}>{url}</LinkButton></div>
  {/each}
{/if}

<p class="mb-0 mt-5 break-all font-mono text-2xs text-faint">{t("finding.key", { key: item.key })}</p>
