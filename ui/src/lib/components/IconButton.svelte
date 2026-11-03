<script lang="ts">
  // A button that is only an icon: square, one height (h-control), named for
  // screen readers and in its tooltip.
  import type { Settings } from "@lucide/svelte";
  import type { HTMLButtonAttributes } from "svelte/elements";

  type Props = HTMLButtonAttributes & { icon: typeof Settings; label: string };
  let { icon: Icon, label, class: cls = "", ...rest }: Props = $props();
</script>

<button
  type="button"
  aria-label={label}
  title={label}
  class="grid size-control shrink-0 place-items-center rounded-md text-muted transition-colors enabled:hover:bg-glass enabled:hover:text-fg disabled:opacity-35 {cls}"
  {...rest}
>
  <Icon size={17} />
</button>
