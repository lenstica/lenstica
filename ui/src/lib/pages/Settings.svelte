<script lang="ts">
  // Everything otherwise edited by hand, saved straight into the settings
  // file with its comments kept, in sections (`#settings/<section>`). Lenses
  // are turned on and off in their category.
  import { Tabs } from "bits-ui";
  import { Bot, Check, ClipboardCopy, FileText, RefreshCw, Wrench } from "@lucide/svelte";
  import { post } from "../api";
  import Button from "../components/Button.svelte";
  import Card from "../components/Card.svelte";
  import FieldRow from "../components/FieldRow.svelte";
  import NavItem from "../components/NavItem.svelte";
  import Page from "../components/Page.svelte";
  import PageHeader from "../components/PageHeader.svelte";
  import SectionHeading from "../components/SectionHeading.svelte";
  import Select from "../components/Select.svelte";
  import Switch from "../components/Switch.svelte";
  import Tag from "../components/Tag.svelte";
  import TextArea from "../components/TextArea.svelte";
  import TextField from "../components/TextField.svelte";
  import { i18n, LANGUAGES, t, type Key } from "../i18n/index.svelte";
  import { model } from "../model.svelte";
  import { appOptions, type Role } from "../openers";
  import { sectionOf, sections } from "../sections";
  import PromptTemplates from "./PromptTemplates.svelte";

  type Setting = {
    path: string[];
    label: Key;
    type: "number" | "bool" | "select" | "list";
    min?: number;
    max?: number;
    options?: string[];
    recommended?: number;
    why?: Key;
  };

  const s = $derived(model.state!);
  const get = (path: string[]) => path.reduce<any>((v, k) => (v == null ? v : v[k]), s.settings);
  const save = (path: string[], value: unknown) =>
    post({ type: "setting", path, value }).then(() => {
      if (path[0] === "scan") model.loadRepos();
    });
  const severities = ["low", "medium", "high", "critical"];
  const severityOptions = (values: string[]) => values.map((v) => ({ value: v, label: t(`severity.${v}` as Key) }));

  const section = $derived(sectionOf(model.route.sub));

  // Each group: its heading, an optional note, and its settings.
  const GROUPS: Record<string, [Key, Key | null, Setting[]]> = {
    cooldown: ["settings.groups.cooldown", null, [
      { path: ["min_days"], label: "settings.fields.minDays", type: "number", min: 1, max: 365, recommended: 7, why: "settings.fields.minDaysWhy" },
      { path: ["monitor", "auto_apply"], label: "settings.fields.autoApply", type: "bool" },
      { path: ["monitor", "interval_minutes"], label: "settings.fields.interval", type: "number", min: 1 },
    ]],
    alerts: ["settings.groups.alerts", null, [
      { path: ["monitor", "alert_severity"], label: "settings.fields.alertSeverity", type: "select", options: severities },
    ]],
    look: ["settings.groups.look", "settings.groups.lookNote", [
      { path: ["scan", "roots"], label: "settings.fields.roots", type: "list" },
      { path: ["scan", "exclude"], label: "settings.fields.exclude", type: "list" },
      { path: ["scan", "worktrees"], label: "settings.fields.worktrees", type: "bool" },
      { path: ["scan", "max_depth"], label: "settings.fields.maxDepth", type: "number", min: 1, max: 20 },
    ]],
    packages: ["settings.groups.packages", null, [
      { path: ["audit", "enabled"], label: "settings.fields.auditEnabled", type: "bool" },
      { path: ["audit", "global"], label: "settings.fields.auditGlobal", type: "bool" },
      { path: ["audit", "interval_minutes"], label: "settings.fields.auditInterval", type: "number", min: 1 },
      { path: ["audit", "ignore"], label: "settings.fields.auditIgnore", type: "list" },
    ]],
    software: ["settings.groups.software", null, [
      { path: ["software", "package_managers"], label: "settings.fields.softwareManagers", type: "bool" },
      { path: ["software", "homebrew"], label: "settings.fields.softwareHomebrew", type: "bool" },
      { path: ["software", "casks"], label: "settings.fields.softwareCasks", type: "bool" },
      { path: ["software", "rust_toolchains"], label: "settings.fields.softwareRust", type: "bool" },
      { path: ["software", "node"], label: "settings.fields.softwareNode", type: "bool" },
      { path: ["software", "ignore"], label: "settings.fields.softwareIgnore", type: "list" },
    ]],
    scripts: ["settings.groups.scripts", null, [
      { path: ["install_scripts", "block"], label: "settings.fields.blockScripts", type: "bool" },
    ]],
    homebrew: ["settings.groups.homebrew", null, [
      { path: ["homebrew", "no_auto_update"], label: "settings.fields.noAutoUpdate", type: "bool" },
    ]],
  };

  const m = $derived(s.settings.monitor);
  const notifyLevels = $derived([
    { value: "", label: t("settings.fields.sameAsAlerts", { severity: t(`severity.${m.alert_severity}` as Key) }) },
    ...severityOptions(severities),
  ]);
  // What "System" means here: the language the window would pick from the system's.
  const systemLanguage = $derived(LANGUAGES.find((l) => l.code === i18n.systemLocale)?.name ?? "English");

  // What opens a file, shows it, or opens a terminal in its folder (`[apps]`).
  const APPS: { role: Role; label: Key; note: Key }[] = [
    { role: "editor", label: "settings.fields.editor", note: "settings.fields.editorNote" },
    { role: "terminal", label: "settings.fields.terminal", note: "settings.fields.terminalNote" },
    { role: "files", label: "settings.fields.files", note: "settings.fields.filesNote" },
  ];
</script>

<!-- One setting's control, by its type. -->
{#snippet control(set: Setting)}
  {@const v = get(set.path)}
  {@const label = t(set.label)}
  {#if set.type === "bool"}
    <Switch checked={!!v} {label} onchange={(on) => save(set.path, on)} />
  {:else if set.type === "number"}
    <TextField
      type="number"
      value={v}
      min={set.min}
      max={set.max}
      aria-label={label}
      onchange={(e) => save(set.path, parseInt(e.currentTarget.value, 10))}
      class="w-24"
    />
  {:else if set.type === "select"}
    <Select {label} value={v} options={severityOptions(set.options!)} onchange={(value) => save(set.path, value)} />
  {:else}
    <TextArea
      mono
      value={(v ?? []).join("\n")}
      aria-label={label}
      onchange={(e) => save(set.path, e.currentTarget.value.split("\n").map((x) => x.trim()).filter(Boolean))}
      class="min-h-16 w-80"
    />
  {/if}
{/snippet}

<!-- A group of settings: its heading and a card with a row per setting. -->
{#snippet group(id: string)}
  {@const [title, note, settings] = GROUPS[id]}
  <SectionHeading level={3} title={t(title)} note={note ? t(note) : null} class="mt-7 first:mt-0" />
  <Card>
    {#each settings as set (set.path.join("."))}
      {#snippet recommendation()}
        {#if set.recommended !== undefined}
          {#if get(set.path) === set.recommended}
            <span title={set.why ? t(set.why) : undefined}><Tag><Check size={11} class="mr-1 text-t-clear" />{t("settings.recommended")}</Tag></span>
          {:else}
            <Button title={set.why ? t(set.why) : undefined} onclick={() => save(set.path, set.recommended)}>
              {t("settings.useRecommended", { value: set.recommended })}
            </Button>
          {/if}
        {/if}
      {/snippet}
      <FieldRow label={t(set.label)} note={set.why ? t(set.why) : null} extra={recommendation}>
        {@render control(set)}
      </FieldRow>
    {/each}
  </Card>
{/snippet}

<Page>
  <div class="max-w-[calc(210px+2rem+var(--container-form))]">
    {#snippet actions()}
      <Button onclick={() => post({ type: "openConfig" })}><FileText size={14} />{t("settings.editFile")}</Button>
    {/snippet}
    <PageHeader title={t("settings.title")} description={t("settings.savedTo", { path: s.configPath })} {actions} />

    <Tabs.Root
      value={section.id}
      onValueChange={(id) => model.go("settings", id)}
      orientation="vertical"
      class="mt-6 grid grid-cols-[210px_minmax(0,1fr)] items-start gap-8"
    >
      <Tabs.List aria-label={t("settings.sectionsLabel")} class="sticky top-6 flex flex-col gap-[4px]">
        {#each sections() as sec (sec.id)}
          <Tabs.Trigger value={sec.id}>
            {#snippet child({ props })}<NavItem {...props} icon={sec.icon} label={sec.title} active={section.id === sec.id} />{/snippet}
          </Tabs.Trigger>
        {/each}
      </Tabs.List>

      <Tabs.Content value={section.id} class="min-w-0 outline-none">
        <div>
          <SectionHeading size="lg" title={section.title} note={section.about} class="mb-1" />
          <div class="mt-5">
            {#if section.id === "general"}
              <div>
                {@render group("cooldown")}
                {@render group("alerts")}
                <SectionHeading level={3} title={t("settings.groups.app")} class="mt-7" />
                <Card>
                  <FieldRow label={t("settings.fields.appearance")} note={t("settings.fields.appearanceNote")}>
                    <Select
                      label={t("settings.fields.appearance")}
                      value={s.settings.window?.appearance ?? "system"}
                      options={[
                        { value: "system", label: t("settings.fields.system") },
                        { value: "light", label: t("settings.fields.light") },
                        { value: "dark", label: t("settings.fields.dark") },
                      ]}
                      onchange={(v) => save(["window", "appearance"], v)}
                    />
                  </FieldRow>
                  <FieldRow label={t("settings.fields.language")} note={t("settings.fields.languageNote")}>
                    <Select
                      label={t("settings.fields.language")}
                      value={s.settings.window?.language ?? "system"}
                      options={[
                        { value: "system", label: t("settings.fields.systemLanguage", { language: systemLanguage }) },
                        ...LANGUAGES.map((l) => ({ value: l.code, label: l.name })),
                      ]}
                      onchange={(v) => save(["window", "language"], v)}
                    />
                  </FieldRow>
                  {#each APPS as app (app.role)}
                    <FieldRow label={t(app.label)} note={t(app.note)}>
                      <Select
                        label={t(app.label)}
                        value={s.settings.apps?.[app.role] ?? "system"}
                        options={appOptions(app.role)}
                        onchange={(v) => save(["apps", app.role], v)}
                      />
                    </FieldRow>
                  {/each}
                  <FieldRow label={t("settings.fields.autostart")}>
                    <Switch checked={s.autostart} label={t("settings.fields.autostart")} onchange={(on) => post({ type: "autostart", enabled: on })} />
                  </FieldRow>
                </Card>
              </div>
            {:else if section.id === "notifications"}
              <div>
                <Card>
                  <FieldRow label={t("settings.fields.notify")}>
                    <Button disabled={!m.notify} onclick={() => post({ type: "testNotification" })}>{t("settings.fields.sendTest")}</Button>
                    <Switch checked={m.notify} label={t("settings.fields.notify")} onchange={(on) => save(["monitor", "notify"], on)} />
                  </FieldRow>
                  <FieldRow label={t("settings.fields.notifySeverity")} dim={!m.notify}>
                    <Select
                      label={t("settings.fields.notifySeverity")}
                      value={m.notify_severity || ""}
                      options={notifyLevels}
                      disabled={!m.notify}
                      onchange={(v) => save(["monitor", "notify_severity"], v)}
                    />
                  </FieldRow>
                  <FieldRow label={t("settings.fields.notifyFixes")} dim={!m.notify}>
                    <Switch
                      checked={m.notify_fixes}
                      label={t("settings.fields.notifyFixesLabel")}
                      disabled={!m.notify}
                      onchange={(on) => save(["monitor", "notify_fixes"], on)}
                    />
                  </FieldRow>
                </Card>
                <SectionHeading level={3} title={t("settings.groups.perLens")} note={t("settings.groups.perLensNote")} class="mt-7" />
                <Card>
                  {#each s.lenses.filter((l) => l.enabled) as lens (lens.id)}
                    <FieldRow label={lens.title} dim={!m.notify}>
                      <Switch
                        checked={lens.notify}
                        label={t("settings.fields.notifyLens", { lens: lens.title })}
                        disabled={!m.notify}
                        onchange={(on) => post({ type: "setting", path: ["lenses", lens.id, "notify"], value: on })}
                      />
                    </FieldRow>
                  {/each}
                </Card>
              </div>
            {:else if section.id === "managers"}
              <div>
                {#snippet applyNow()}
                  <Button title={t("settings.fields.applyTitle")} onclick={() => post({ type: "apply" })}><Wrench size={14} />{t("settings.fields.applyNow")}</Button>
                {/snippet}
                <SectionHeading level={3} title={t("settings.groups.managed")} note={t("settings.groups.managedNote")} action={applyNow} />
                <Card>
                  {#each s.managers as mgr (mgr.id)}
                    <FieldRow label={mgr.name} note={mgr.enabled ? null : t("settings.fields.leftAlone")}>
                      <Switch
                        checked={mgr.enabled}
                        label={mgr.enabled ? t("settings.fields.leave", { name: mgr.name }) : t("settings.fields.manage", { name: mgr.name })}
                        onchange={(on) => post({ type: "toggleManager", id: mgr.id, enabled: on })}
                      />
                    </FieldRow>
                  {/each}
                </Card>
                {@render group("scripts")}
                {@render group("homebrew")}
              </div>
            {:else if section.id === "projects"}
              <div>
                {@render group("look")}
                {#snippet checkNow()}
                  <Button onclick={() => model.loadRepos()}><RefreshCw size={14} />{t("settings.fields.checkNow")}</Button>
                {/snippet}
                <SectionHeading level={3} title={t("settings.groups.repositories")} note={t("settings.groups.repositoriesNote")} action={checkNow} class="mt-7" />
                <Card>
                  {#if model.reposStatus === "loading" && !model.repos.length}
                    <div class="px-4 py-3 text-sm text-muted" role="status">{t("settings.fields.looking")}</div>
                  {:else if model.reposStatus === "error"}
                    <div class="px-4 py-3 text-sm">{t("settings.fields.couldNotList")}<div class="text-xs text-muted">{model.reposError}</div></div>
                  {:else if !model.repos.length}
                    <div class="px-4 py-3 text-sm text-muted">{t("settings.fields.noRepos")}</div>
                  {:else}
                    {#each model.repos as r (r.path)}
                      {#snippet inherited()}
                        {#if r.inherited}<Tag title={t("settings.fields.excludedTitle")}>{t("settings.fields.excluded")}</Tag>{/if}
                      {/snippet}
                      <FieldRow
                        label={r.label}
                        note={r.worktreeOf ? t("settings.fields.worktreeOf", { path: r.worktreeOf }) : null}
                        extra={inherited}
                        indent={!!r.worktreeOf}
                      >
                        <Switch
                          checked={!r.excluded}
                          label={r.excluded ? t("settings.fields.searchAgain") : t("settings.fields.leaveOut")}
                          onchange={(on) => post({ type: "toggleExclude", path: r.path, excluded: !on }).then(() => model.loadRepos())}
                        />
                      </FieldRow>
                    {/each}
                  {/if}
                </Card>
              </div>
            {:else if section.id === "checks"}
              <div>
                {@render group("packages")}
                {@render group("software")}
              </div>
            {:else if section.id === "agents"}
              <div>
                <SectionHeading level={3} title={t("settings.groups.agentTools")} note={t("settings.groups.agentToolsNote")} />
                <Card>
                  <FieldRow
                    label={t("settings.fields.skill")}
                    note={s.agent.skillInstalled
                      ? t("settings.fields.skillInstalled", { path: s.agent.skillPath })
                      : t("settings.fields.skillNotInstalled", { path: s.agent.skillPath })}
                  >
                    <Button onclick={() => post({ type: "installSkill" })}>
                      <Bot size={14} />{s.agent.skillInstalled ? t("settings.fields.reinstall") : t("settings.fields.install")}
                    </Button>
                  </FieldRow>
                  <FieldRow label={t("settings.fields.mcpClaude")} note={s.agent.mcpCommand}>
                    <Button onclick={() => post({ type: "copyText", text: s.agent.mcpCommand })}><ClipboardCopy size={14} />{t("settings.fields.copyCommand")}</Button>
                  </FieldRow>
                  <FieldRow label={t("settings.fields.mcpOther")} note={t("settings.fields.mcpOtherNote")}>
                    <Button onclick={() => post({ type: "copyText", text: s.agent.mcpJson })}><ClipboardCopy size={14} />{t("settings.fields.copyJson")}</Button>
                  </FieldRow>
                </Card>
                <SectionHeading level={3} title={t("settings.groups.prompts")} note={t("settings.groups.promptsNote")} class="mt-7" />
                <PromptTemplates />
              </div>
            {/if}
          </div>
        </div>
      </Tabs.Content>
    </Tabs.Root>
  </div>
</Page>
