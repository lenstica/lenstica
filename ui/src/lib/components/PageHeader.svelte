<script lang="ts">
  // The top of every page: its title (the page's only h1), what it is, a line
  // of state, and its actions.
  import type { Settings } from "@lucide/svelte";
  import type { Snippet } from "svelte";

  type Props = { title: string; description?: string; icon?: typeof Settings; meta?: Snippet; actions?: Snippet };
  let { title, description, icon: Icon, meta, actions }: Props = $props();
</script>

<header class="flex items-start gap-4">
  {#if Icon}
    <div class="grid size-[44px] shrink-0 place-items-center rounded-xl border border-rim bg-glass-strong">
      <Icon size={21} strokeWidth={1.8} />
    </div>
  {/if}
  <div class="min-w-0 flex-1">
    <h1 class="m-0 text-xl font-semibold tracking-tight">{title}</h1>
    {#if description}<p class="m-0 mt-0.5 max-w-3xl text-sm text-muted">{description}</p>{/if}
    {#if meta}<div class="mt-2 flex flex-wrap items-center gap-2 text-sm">{@render meta()}</div>{/if}
  </div>
  {#if actions}<div class="flex shrink-0 items-center gap-2">{@render actions()}</div>{/if}
</header>
