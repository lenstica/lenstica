<script lang="ts">
  // What can be done with a file or folder, each button named for the app
  // that does it: open it in the editor, show it in the file manager, open a
  // terminal in its folder. The apps are picked in Settings → General. Where
  // the pane is narrow (a container under 30rem), only the icons show.
  import { FilePen, FolderOpen, SquareTerminal } from "@lucide/svelte";
  import { post } from "../api";
  import { appAction, appName, type Role } from "../openers";
  import Button from "./Button.svelte";

  type Props = { path: string; edit?: boolean; terminal?: boolean };
  let { path, edit = true, terminal = true }: Props = $props();

  const icons = { editor: FilePen, files: FolderOpen, terminal: SquareTerminal };
  const roles = $derived((["editor", "files", "terminal"] as Role[]).filter((r) => (r === "editor" ? edit : r === "terminal" ? terminal : true)));
</script>

{#each roles as role (role)}
  {@const Icon = icons[role]}
  <Button variant="quiet" class="px-2" title={appAction(role)} aria-label={appAction(role)} onclick={() => post({ type: "open", path, with: role })}>
    <Icon size={14} aria-hidden="true" /><span class="hidden @[30rem]:inline">{appName(role)}</span>
  </Button>
{/each}
