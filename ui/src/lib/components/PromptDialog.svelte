<script lang="ts">
  // The prompt for an AI agent, shown before it is copied: written by the
  // app with the user's templates, so what you read is exactly what is copied.
  import { tick } from "svelte";
  import { Dialog } from "bits-ui";
  import { ClipboardCopy, Pencil, X } from "@lucide/svelte";
  import { post, promptText } from "../api";
  import { t } from "../i18n/index.svelte";
  import { model } from "../model.svelte";
  import Button from "./Button.svelte";
  import Callout from "./Callout.svelte";
  import CodeBlock from "./CodeBlock.svelte";
  import IconButton from "./IconButton.svelte";

  let text = $state<string | null>(null);
  let count = $state(0);
  let problem = $state<string | null>(null);

  $effect(() => {
    const asked = model.prompt;
    text = null;
    problem = null;
    if (!asked) return;
    let current = true;
    promptText(asked.items)
      .then((p) => {
        if (!current) return;
        text = p.text;
        count = p.count;
        // Ready to copy: Return copies.
        tick().then(() => document.querySelector<HTMLElement>("[data-prompt-copy]")?.focus());
      })
      .catch((e) => current && (problem = String(e)));
    return () => (current = false);
  });

  const lines = $derived(text ? text.trimEnd().split("\n").length : 0);

  function copy() {
    if (!text) return;
    post({ type: "copyText", text, toast: count === 1 ? t("toast.copiedOne") : t("toast.copiedMany", { count }) });
    model.prompt = null;
  }

  function editTemplates() {
    model.prompt = null;
    model.go("settings", "agents");
  }

  function keys(e: KeyboardEvent) {
    // ⌘↩ copies, as the button says.
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
      e.preventDefault();
      copy();
    }
  }
</script>

<Dialog.Root open={!!model.prompt} onOpenChange={(open) => !open && (model.prompt = null)}>
  <Dialog.Portal>
    <Dialog.Overlay class="fixed inset-0 z-40 bg-scrim backdrop-blur-[2px]" />
    <Dialog.Content
      onkeydown={keys}
      onOpenAutoFocus={(e) => e.preventDefault()}
      class="fixed left-1/2 top-1/2 z-50 flex max-h-[82vh] w-[min(760px,calc(100vw-48px))] -translate-x-1/2 -translate-y-1/2 flex-col rounded-xl border border-rim bg-panel shadow-card outline-none"
    >
      <div class="flex items-start gap-3 border-b border-line px-5 py-4">
        <div class="min-w-0 flex-1">
          <Dialog.Title class="m-0 text-md font-semibold">{t("prompt.title")}</Dialog.Title>
          <Dialog.Description class="m-0 mt-0.5 truncate text-sm text-muted">{model.prompt?.about}</Dialog.Description>
        </div>
        <Dialog.Close>
          {#snippet child({ props })}<IconButton {...props} icon={X} label={t("prompt.close")} />{/snippet}
        </Dialog.Close>
      </div>

      <div class="min-h-0 flex-1 overflow-auto px-5 py-4">
        {#if problem}
          <Callout tone="critical">{problem}</Callout>
        {:else if text === null}
          <p class="m-0 text-sm text-muted" role="status">{t("prompt.writing")}</p>
        {:else}
          <CodeBlock {text} class="p-4" />
        {/if}
      </div>

      <div class="flex items-center gap-2 border-t border-line px-5 py-3">
        <Button variant="quiet" onclick={editTemplates} title={t("prompt.editTitle")}><Pencil size={14} />{t("prompt.editTemplates")}</Button>
        {#if text}
          <span class="text-xs text-faint">{t("prompt.findings", { count })} · {t("prompt.lines", { count: lines })}</span>
        {/if}
        <span class="flex-1"></span>
        <Button onclick={() => (model.prompt = null)}>{t("prompt.cancel")}</Button>
        <Button variant="primary" disabled={!text} onclick={copy} title={t("prompt.copyTitle")} data-prompt-copy>
          <ClipboardCopy size={14} />{t("prompt.copy")}
        </Button>
      </div>
    </Dialog.Content>
  </Dialog.Portal>
</Dialog.Root>
