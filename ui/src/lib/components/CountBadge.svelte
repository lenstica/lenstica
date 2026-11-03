<script lang="ts">
  // A count beside a name: how many need attention (attention), or how many there are (neutral).
  let { count, tone = "attention" }: { count: number; tone?: "attention" | "neutral" } = $props();
</script>

<span
  aria-hidden="true"
  class="tabular min-w-[22px] shrink-0 rounded-full px-[7px] text-center text-xs font-semibold leading-[20px] {tone === 'attention'
    ? 'bg-attention text-on-attention'
    : 'bg-glass-strong text-muted'}">{count}</span
>
