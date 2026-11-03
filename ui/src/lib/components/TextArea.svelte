<script lang="ts">
  // A multi-line field: lists in Settings, the prompt template editor.
  import type { HTMLTextareaAttributes } from "svelte/elements";

  type Props = Omit<HTMLTextareaAttributes, "value"> & {
    value?: string;
    /** Code-like text: monospace, no spell check. */
    mono?: boolean;
    /** Shows that what it holds cannot be used. */
    invalid?: boolean;
    ref?: HTMLTextAreaElement;
  };
  let { value = $bindable(""), mono = false, invalid = false, ref = $bindable(), class: cls = "", ...rest }: Props = $props();
</script>

<textarea
  bind:this={ref}
  bind:value
  spellcheck={mono ? false : undefined}
  aria-invalid={invalid || undefined}
  class="w-full resize-y rounded-md border bg-panel px-2.5 py-2 shadow-card outline-none focus:outline-2 focus:outline-offset-2 focus:outline-focus {mono
    ? 'font-mono text-xs leading-relaxed'
    : 'text-base'} {invalid ? 'border-critical/70' : 'border-line focus:border-line-strong'} {cls}"
  {...rest}
></textarea>
