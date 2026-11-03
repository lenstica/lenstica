<script lang="ts">
  // Text that goes somewhere: a reference, GitHub, a step back in the top bar.
  import type { Snippet } from "svelte";
  import type { HTMLButtonAttributes } from "svelte/elements";

  type Props = HTMLButtonAttributes & { tone?: "link" | "muted"; children: Snippet };
  let { tone = "link", class: cls = "", children, ...rest }: Props = $props();
</script>

<button
  type="button"
  class="inline-flex max-w-full items-center gap-1.5 truncate rounded-sm text-left underline-offset-2 {tone === 'link'
    ? 'text-t-low hover:underline'
    : 'text-muted hover:text-fg'} {cls}"
  {...rest}
>
  {@render children()}
</button>
