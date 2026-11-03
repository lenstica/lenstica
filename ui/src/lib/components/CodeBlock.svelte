<script lang="ts">
  // Text shown as it is: a finding's details, a prompt.
  let { text, class: cls = "" }: { text: string; class?: string } = $props();
</script>

<pre class="m-0 select-text whitespace-pre-wrap break-words rounded-md bg-glass p-3.5 font-mono text-xs leading-relaxed {cls}">{text}</pre>
