<script lang="ts">
  // Settings → AI agents → AI prompts: edit the templates Copy Prompt for AI
  // Agent, `lenstica prompt` and the MCP server write with, with a live preview.
  import { tick } from "svelte";
  import { RotateCcw, Save } from "@lucide/svelte";
  import { post, previewPrompt } from "../api";
  import Button from "../components/Button.svelte";
  import Callout from "../components/Callout.svelte";
  import Card from "../components/Card.svelte";
  import Chip from "../components/Chip.svelte";
  import CodeBlock from "../components/CodeBlock.svelte";
  import Eyebrow from "../components/Eyebrow.svelte";
  import Select from "../components/Select.svelte";
  import Tag from "../components/Tag.svelte";
  import TextArea from "../components/TextArea.svelte";
  import { t } from "../i18n/index.svelte";
  import { model } from "../model.svelte";
  import type { PromptKind } from "../types";

  const KINDS = $derived<{ value: PromptKind; label: string; note: string }[]>([
    { value: "finding", label: t("templates.finding"), note: t("templates.findingNote") },
    { value: "findings", label: t("templates.findings"), note: t("templates.findingsNote") },
    { value: "item", label: t("templates.item"), note: t("templates.itemNote") },
  ]);

  const s = $derived(model.state!);
  const defaults = $derived(s.prompts.defaults);
  const saved = (k: PromptKind): string => model.state!.settings.prompts?.[k] || model.state!.prompts.defaults[k];

  let kind = $state<PromptKind>("finding");
  // What is being edited, per template; starts from what is saved, or Lenstica's own.
  let drafts = $state<Record<PromptKind, string>>({ finding: saved("finding"), findings: saved("findings"), item: saved("item") });
  let preview = $state<{ one: string; many: string; real: boolean } | null>(null);
  let problem = $state<string | null>(null);
  let area: HTMLTextAreaElement | undefined = $state();

  const dirty = $derived(drafts[kind] !== saved(kind));
  const isDefault = $derived(drafts[kind] === defaults[kind]);
  const note = $derived(KINDS.find((k) => k.value === kind)!.note);

  // The preview follows the drafts as you type.
  $effect(() => {
    const now = { finding: drafts.finding, findings: drafts.findings, item: drafts.item };
    const timer = setTimeout(() => {
      previewPrompt(now)
        .then((p) => {
          preview = p;
          problem = null;
        })
        .catch((e) => (problem = String(e)));
    }, 250);
    return () => clearTimeout(timer);
  });

  // Saving Lenstica's own text stores nothing, so later improvements to it still apply.
  const save = () => post({ type: "setting", path: ["prompts", kind], value: isDefault ? "" : drafts[kind] });

  function reset() {
    drafts[kind] = defaults[kind];
    post({ type: "setting", path: ["prompts", kind], value: "" });
  }

  function insert(name: string) {
    const text = `{{${name}}}`;
    const at = area?.selectionStart ?? drafts[kind].length;
    const end = area?.selectionEnd ?? at;
    drafts[kind] = drafts[kind].slice(0, at) + text + drafts[kind].slice(end);
    tick().then(() => {
      area?.focus();
      area?.setSelectionRange(at + text.length, at + text.length);
    });
  }
</script>

<Card class="p-4">
  <div class="flex flex-wrap items-center gap-2">
    <Select label={t("templates.which")} value={kind} options={KINDS} onchange={(v) => (kind = v as PromptKind)} class="min-w-52" />
    <Tag>{isDefault ? t("templates.own") : t("templates.custom")}</Tag>
    {#if dirty}<span class="text-xs text-t-medium" role="status">{t("templates.unsaved")}</span>{/if}
    <span class="flex-1"></span>
    <Button disabled={isDefault && !dirty} onclick={reset} title={t("templates.resetTitle")}><RotateCcw size={14} />{t("templates.reset")}</Button>
    <Button variant="primary" disabled={!dirty || !!problem} onclick={save}><Save size={14} />{t("templates.save")}</Button>
  </div>
  <p class="mb-3 mt-2 text-xs text-muted">{note}</p>

  <div class="grid gap-3">
    <label class="flex min-w-0 flex-col gap-1.5">
      <Eyebrow>{t("templates.template")}</Eyebrow>
      <TextArea mono bind:ref={area} bind:value={drafts[kind]} invalid={!!problem} class="h-64" />
    </label>
    <div class="flex min-w-0 flex-col gap-1.5">
      <Eyebrow>{preview?.real === false ? t("templates.previewSample") : t("templates.previewReal")}</Eyebrow>
      {#if problem}
        <Callout tone="critical" class="h-64 overflow-auto">{problem}</Callout>
      {:else}
        <CodeBlock text={preview ? (kind === "finding" ? preview.one : preview.many) : ""} class="h-64 overflow-auto" />
      {/if}
    </div>
  </div>

  <p class="mb-0 mt-3 text-xs text-muted">
    {t("templates.help", { shown: "{{#remedy}}…{{/remedy}}", hidden: "{{^remedy}}…{{/remedy}}" })}
  </p>
  <div class="mt-2 flex flex-wrap gap-1.5">
    {#each s.prompts.values[kind] as v (v.name)}
      <Chip mono title={v.about} onclick={() => insert(v.name)}>{`{{${v.name}}}`}</Chip>
    {/each}
  </div>
</Card>
