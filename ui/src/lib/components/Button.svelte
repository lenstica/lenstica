<script lang="ts">
  // Every text button, one height (h-control): primary for a page's main
  // action, secondary for the rest, quiet inside cards and rows.
  import type { Snippet } from "svelte";
  import type { HTMLButtonAttributes } from "svelte/elements";

  type Props = HTMLButtonAttributes & { variant?: "primary" | "secondary" | "quiet"; children: Snippet };
  let { variant = "secondary", class: cls = "", children, ...rest }: Props = $props();

  const variants = {
    primary: "bg-primary text-on-primary shadow-card enabled:hover:opacity-90",
    secondary: "border border-line bg-panel text-fg shadow-card enabled:hover:border-line-strong enabled:hover:bg-raised",
    quiet: "text-muted enabled:hover:bg-glass enabled:hover:text-fg",
  };
</script>

<button
  type="button"
  class="inline-flex h-control shrink-0 items-center justify-center gap-1.5 whitespace-nowrap rounded-md px-3 text-base font-medium transition-colors disabled:cursor-default disabled:opacity-45 [&_svg]:shrink-0 {variants[variant]} {cls}"
  {...rest}
>
  {@render children()}
</button>
