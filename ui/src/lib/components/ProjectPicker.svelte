<script lang="ts">
  // Bottom left, above Settings: which project the window shows. All
  // projects, This Mac (findings in no repository), or one repository with
  // its worktrees. It only changes what is shown; checks cover everything.
  import { Command, Popover } from "bits-ui";
  import { Check, ChevronsUpDown, FolderGit2, Laptop, Layers } from "@lucide/svelte";
  import { t } from "../i18n/index.svelte";
  import { ALL, MAC, model } from "../model.svelte";
  import { listSearch, option, popover } from "../styles";
  import CountBadge from "./CountBadge.svelte";
  import Eyebrow from "./Eyebrow.svelte";

  let open = $state(false);

  // Projects with something needing attention first, then by name.
  const projects = $derived(
    [...model.projects].sort(
      (a, b) => (model.alertCounts.get(b.path) ?? 0) - (model.alertCounts.get(a.path) ?? 0) || a.name.localeCompare(b.name),
    ),
  );
  const scopeIcon = $derived(model.scope === ALL ? Layers : model.scope === MAC ? Laptop : FolderGit2);

  function pick(scope: string) {
    model.setScope(scope);
    open = false;
  }
</script>

{#snippet row(scope: string, Icon: typeof Laptop, name: string, note: string | null)}
  {@const count = model.alertCounts.get(scope) ?? 0}
  <Command.Item value={scope} keywords={[name, note ?? ""]} onSelect={() => pick(scope)} class="{option} py-1.5">
    <Icon size={16} class="shrink-0 text-muted" />
    <span class="min-w-0 flex-1">
      <span class="block truncate">{name}</span>
      {#if note}<span class="block truncate text-2xs text-faint">{note}</span>{/if}
    </span>
    {#if count}
      <CountBadge {count} tone="neutral" />
      <span class="sr-only">, {t("nav.needAttention", { count })}</span>
    {/if}
    <Check size={15} class="shrink-0 {model.scope === scope ? 'opacity-100' : 'opacity-0'}" />
  </Command.Item>
{/snippet}

<Popover.Root bind:open>
  <Popover.Trigger
    class="flex h-nav w-full items-center gap-[11px] rounded-md border border-line bg-panel px-[11px] text-left shadow-card hover:border-line-strong"
    aria-label={t("project.label", { name: model.scopeTitle })}
    title={t("project.title")}
  >
    {@const Icon = scopeIcon}
    <Icon size={18} strokeWidth={1.8} class="shrink-0 text-muted" />
    <span class="min-w-0 flex-1 truncate text-md font-medium">{model.scopeTitle}</span>
    <ChevronsUpDown size={15} class="shrink-0 text-faint" />
  </Popover.Trigger>
  <Popover.Portal>
    <Popover.Content side="top" align="start" sideOffset={6} class="{popover} w-80 overflow-hidden">
      <Command.Root label={t("project.title")}>
        <Command.Input placeholder={t("project.find")} class={listSearch} />
        <Command.List class="max-h-96 overflow-y-auto p-1">
          <Command.Viewport>
            <Command.Empty class="px-3 py-6 text-center text-sm text-muted">{t("project.noMatch")}</Command.Empty>
            <Command.Group>
              <Command.GroupItems>
                {@render row(ALL, Layers, t("project.all"), t("project.allNote"))}
                {@render row(MAC, Laptop, t("project.mac"), t("project.macNote"))}
              </Command.GroupItems>
            </Command.Group>
            {#if projects.length}
              <Command.Group>
                <Command.GroupHeading class="px-2.5 pb-1 pt-2.5"><Eyebrow>{t("project.projects")}</Eyebrow></Command.GroupHeading>
                <Command.GroupItems>
                  {#each projects as p (p.path)}
                    {@render row(p.path, FolderGit2, p.name, p.worktrees ? t("project.worktrees", { path: p.label, count: p.worktrees }) : p.label)}
                  {/each}
                </Command.GroupItems>
              </Command.Group>
            {:else if model.reposStatus === "loading"}
              <div class="px-3 py-3 text-sm text-muted">{t("project.looking")}</div>
            {/if}
          </Command.Viewport>
        </Command.List>
      </Command.Root>
    </Popover.Content>
  </Popover.Portal>
</Popover.Root>
